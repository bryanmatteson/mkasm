package arm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mkasm/pkg/ir"
	"mkasm/pkg/parse"
)

// ARMParser orchestrates the 3-pass parsing pipeline
type ARMParser struct {
	parser     *parse.Parser
	registry   *InstructionRegistry
	iformCache *ParsedIFormCache
	corpus     XMLCorpus
	config     ARMParserConfig
}

// ARMParserConfig configures the ARM parser
type ARMParserConfig struct {
	// Paths
	EncodingIndexPath string
	IFormDirectory    string
	OutputDirectory   string
	// Corpus replaces EncodingIndexPath/IFormDirectory reads with a logical XML
	// source, such as TarXMLCorpus. Entry names remain ARM's relative filenames.
	Corpus XMLCorpus

	// Performance
	IFormWorkers int
	// IFormCacheSize bounds retained parsed forms. Zero keeps every form for
	// the parser's lifetime, which is the efficient default for code generation:
	// Pass 3 consumes the same forms Pass 2 just parsed.
	IFormCacheSize int

	// Features
	EnabledFeatures map[string]bool
	GenerateTests   bool
	SkipCodegen     bool // when true, stop after Pass 2
	MaxIForms       int  // if >0, resolve at most this many iforms
	// Languages selects Pass 3 targets (default: go). Use go, rust, or both.
	Languages []CodegenLang
	// Arch is the target architecture. It names the generated artifact — the
	// Rust crate and Go module are both named after it.
	Arch Arch
	// Progress receives human-readable pipeline diagnostics. Nil keeps the
	// library silent.
	Progress io.Writer
}

// NewARMParser creates a new ARM parser with the given configuration
func NewARMParser(config ARMParserConfig) *ARMParser {
	// Set defaults
	if config.IFormWorkers == 0 {
		config.IFormWorkers = 10
	}
	if config.Arch == "" {
		config.Arch = ArchAArch64
	}
	if config.Progress == nil {
		config.Progress = io.Discard
	}

	// Create parse options
	parseOpts := parse.DefaultParseOptions()
	parseOpts.EnableMetrics = true
	parseOpts.StopOnError = false // encodingindex has irregular rows; keep going

	// Create parser
	parser := parse.NewParser(parseOpts)

	// Create components
	registry := NewInstructionRegistry()
	iformCache := NewParsedIFormCache(config.IFormCacheSize)
	ap := &ARMParser{
		parser:     parser,
		registry:   registry,
		iformCache: iformCache,
		corpus:     config.Corpus,
		config:     config,
	}

	// Register handlers for Pass 1
	ap.registerEncodingHandlers()

	return ap
}

// Parse executes the 3-pass parsing pipeline
func (ap *ARMParser) Parse(ctx context.Context) error {
	// Pass 1: Parse encoding index
	if err := ap.pass1EncodingIndex(ctx); err != nil {
		return fmt.Errorf("pass 1 failed: %w", err)
	}

	// Pass 2: Resolve IForms asynchronously
	if err := ap.pass2IFormResolution(ctx); err != nil {
		return fmt.Errorf("pass 2 failed: %w", err)
	}

	if ap.config.SkipCodegen {
		return nil
	}

	// Pass 3: Generate code
	if err := ap.pass3CodeGeneration(ctx); err != nil {
		return fmt.Errorf("pass 3 failed: %w", err)
	}

	return nil
}

// pass1EncodingIndex parses the encoding index XML
func (ap *ARMParser) pass1EncodingIndex(ctx context.Context) error {
	var (
		result *parse.ParseResult
		err    error
	)
	if ap.corpus != nil {
		r, openErr := ap.corpus.OpenXML(ap.config.EncodingIndexPath)
		if openErr != nil {
			return fmt.Errorf("open encoding index: %w", openErr)
		}
		result, err = ap.parser.Parse(ctx, r)
		closeErr := r.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	} else {
		result, err = ap.parser.ParseFile(ctx, ap.config.EncodingIndexPath)
	}
	if err != nil {
		return fmt.Errorf("parse encoding index: %w", err)
	}
	if releaser, ok := ap.corpus.(interface{ releaseXML(string) }); ok {
		releaser.releaseXML(ap.config.EncodingIndexPath)
	}

	// Extract partial instructions from results
	instructions := parse.GetResults[*ir.InstructionIR](result.Results(), "instruction")

	// Store in registry
	for _, instr := range instructions {
		ap.registry.Add(instr)
	}

	aliases, err := ap.discoverAliases()
	if err != nil {
		return fmt.Errorf("discover aliases: %w", err)
	}

	fmt.Fprintf(ap.config.Progress, "Pass 1 complete: %d instructions parsed (%d canonical + %d alias)\n",
		len(instructions)+aliases, len(instructions), aliases)

	return nil
}

// discoverAliases adds the alias encodings that encodingindex.xml omits.
func (ap *ARMParser) discoverAliases() (int, error) {
	canonical := make(map[string]struct{})
	classByFile := make(map[string]string)
	for _, instr := range ap.registry.GetAll() {
		if instr.IFormFile == "" {
			continue
		}
		canonical[instr.IFormFile] = struct{}{}
		if _, ok := classByFile[instr.IFormFile]; !ok {
			classByFile[instr.IFormFile] = instr.IClass
		}
	}

	classOf := func(f string) string { return classByFile[f] }
	var aliases []*ir.InstructionIR
	var err error
	if ap.corpus != nil {
		aliases, err = DiscoverAliasEncodingsCorpus(ap.corpus, canonical, classOf)
	} else {
		specDir := filepath.Dir(ap.config.EncodingIndexPath)
		aliases, err = DiscoverAliasEncodings(specDir, canonical, classOf)
	}
	if err != nil {
		return 0, err
	}

	added := 0
	for _, instr := range aliases {
		if err := ap.registry.Add(instr); err == nil {
			added++
		}
	}
	return added, nil
}

// pass2IFormResolution loads and resolves IForm files asynchronously
func (ap *ARMParser) pass2IFormResolution(ctx context.Context) error {
	// Get all instructions that need IForm resolution
	instructions := ap.registry.GetAll()

	// Create channels for work distribution
	workCh := make(chan *ir.InstructionIR, len(instructions))
	errCh := make(chan error, len(instructions))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < ap.config.IFormWorkers; i++ {
		wg.Add(1)
		go ap.iformWorker(ctx, &wg, workCh, errCh)
	}

	// Queue work
	queued := 0
	for _, instr := range instructions {
		if ap.config.MaxIForms > 0 && queued >= ap.config.MaxIForms {
			break
		}
		select {
		case workCh <- instr:
			queued++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	close(workCh)

	// Wait for completion
	wg.Wait()
	close(errCh)

	// Read-only parsing reports individual misses as warnings. Code generation
	// must fail: silently omitting an encoding would make a partial artifact
	// look complete.
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		fmt.Fprintf(ap.config.Progress, "Pass 2 warnings: %d IForm resolution errors (first: %v)\n", len(errs), errs[0])
		if !ap.config.SkipCodegen {
			return fmt.Errorf("%d IForm resolution errors; refusing incomplete codegen (first: %w)",
				len(errs), errs[0])
		}
	}

	fmt.Fprintf(ap.config.Progress, "Pass 2 complete: %d IForm jobs queued (registry size %d)\n", queued, len(instructions))
	return nil
}

// iformWorker processes IForm resolution work
func (ap *ARMParser) iformWorker(ctx context.Context, wg *sync.WaitGroup, workCh <-chan *ir.InstructionIR, errCh chan<- error) {
	defer wg.Done()

	for instr := range workCh {
		select {
		case <-ctx.Done():
			return
		default:
			if err := ap.resolveIForm(ctx, instr); err != nil {
				errCh <- fmt.Errorf("resolve iform %s: %w", instr.EncodingID, err)
			}
		}
	}
}

// resolveIForm loads and merges IForm data into an instruction
func (ap *ARMParser) resolveIForm(ctx context.Context, instr *ir.InstructionIR) error {
	if instr.IFormFile == "" {
		return nil
	}
	_ = ctx

	parsed, err := ap.loadCachedIForm(instr)
	if err != nil {
		return err
	}
	ApplyParsedIForm(instr, parsed)
	return nil
}

// loadIForm returns the parsed iform backing one encoding, reusing the Pass 2
// cache so no file is parsed twice.
func (ap *ARMParser) loadIForm(instr *ir.InstructionIR) *ParsedIForm {
	if instr.IFormFile == "" {
		return nil
	}
	p, err := ap.loadCachedIForm(instr)
	if err != nil {
		return nil
	}
	return p
}

func (ap *ARMParser) loadCachedIForm(instr *ir.InstructionIR) (*ParsedIForm, error) {
	if ap.corpus != nil {
		return ap.iformCache.GetOrLoadCorpus(ap.corpus, instr.IFormFile, instr.EncodingID)
	}
	return ap.iformCache.GetOrLoad(
		filepath.Join(ap.config.IFormDirectory, instr.IFormFile), instr.EncodingID)
}

// buildAsmSurface projects resolved IR into the typed assembler API.
func (ap *ARMParser) buildAsmSurface(resolved []*ir.InstructionIR) *AsmSurface {
	return BuildAsmSurface(resolved, ap.loadIForm)
}

// AsmSurface projects the resolved corpus into the typed assembler model.
// It is valid after Parse and is exposed for conformance tooling that must call
// the exact same overloads Pass 3 emitted.
func (ap *ARMParser) AsmSurface() *AsmSurface {
	return ap.buildAsmSurface(ap.ResolvedInstructions())
}

// DisasmSurface projects resolved IR into the print model. Valid after Parse.
func (ap *ARMParser) DisasmSurface() *DisasmSurface {
	return BuildDisasmSurface(ap.ResolvedInstructions(), ap.loadIForm)
}

// ResolvedInstructions returns the registry entries Pass 2 gave authoritative
// encoding data, which is the set Pass 3 generates from.
func (ap *ARMParser) ResolvedInstructions() []*ir.InstructionIR {
	all := ap.registry.GetAll()
	out := make([]*ir.InstructionIR, 0, len(all))
	for _, instr := range all {
		if hasPass2Encoding(instr) {
			out = append(out, instr)
		}
	}
	return out
}

// pass3CodeGeneration generates Go code from the complete IR
func (ap *ARMParser) pass3CodeGeneration(ctx context.Context) error {
	instructions := ap.registry.GetAll()
	resolved := make([]*ir.InstructionIR, 0, len(instructions))
	for _, instr := range instructions {
		if hasPass2Encoding(instr) {
			resolved = append(resolved, instr)
		}
	}
	if len(resolved) == 0 {
		return fmt.Errorf("pass 3: no Pass-2-resolved instructions (use a local -iform dir and raise -max-iforms)")
	}
	if ap.config.MaxIForms == 0 && len(resolved) != len(instructions) {
		return fmt.Errorf("pass 3: only %d/%d instructions resolved; refusing incomplete full generation",
			len(resolved), len(instructions))
	}

	byClass := map[string][]*ir.InstructionIR{}
	for _, instr := range resolved {
		byClass[instr.IClass] = append(byClass[instr.IClass], instr)
	}

	langs := ap.config.Languages
	if len(langs) == 0 {
		langs = []CodegenLang{LangGo}
	}
	catalog := BuildCatalog(resolved)

	for _, lang := range langs {
		outDir, err := codegenOutDir(ap.config.OutputDirectory, langs, lang)
		if err != nil {
			return err
		}
		cg := NewCodeGenerator(outDir, ap.config.Arch)
		cg.SetDisasmSurface(ap.DisasmSurface())
		switch lang {
		case LangGo:
			if err := cg.GenerateEncoders(ctx, byClass); err != nil {
				return fmt.Errorf("generate go encoders: %w", err)
			}
			if err := cg.GenerateDecoders(ctx, byClass); err != nil {
				return fmt.Errorf("generate go decoders: %w", err)
			}
			if err := cg.GenerateRegistry(ctx, resolved); err != nil {
				return fmt.Errorf("generate go registry: %w", err)
			}
		case LangRust:
			cg.SetAsmSurface(ap.buildAsmSurface(resolved))
			if err := cg.GenerateRust(catalog); err != nil {
				return fmt.Errorf("generate rust: %w", err)
			}
		default:
			return fmt.Errorf("unsupported codegen language %q", lang)
		}
		fmt.Fprintf(ap.config.Progress, "Pass 3 (%s): wrote %s\n", lang, outDir)
	}

	// Golden decoder tests are always written by GenerateDecoders (Go).
	_ = ap.config.GenerateTests
	fmt.Fprintf(ap.config.Progress, "Pass 3 complete: Generated code for %d/%d resolved instructions (%v)\n",
		len(resolved), len(instructions), langs)
	return nil
}

func codegenOutDir(root string, langs []CodegenLang, lang CodegenLang) (string, error) {
	if len(langs) == 1 {
		return root, nil
	}
	sub := filepath.Join(root, string(lang))
	if err := os.MkdirAll(sub, 0755); err != nil {
		return "", err
	}
	return sub, nil
}

// registerEncodingHandlers registers handlers for Pass 1
func (ap *ARMParser) registerEncodingHandlers() {
	ap.parser.RegisterHandler(NewInstructionTableHandler())
	ap.parser.RegisterHandler(NewInstructionRowHandler())
	ap.parser.RegisterHandler(NewMnemonicHandler())
	ap.parser.RegisterHandler(NewBitfieldHandler())
	ap.parser.RegisterHandler(NewFeatureHandler())
}

// GetMetrics returns parsing metrics
func (ap *ARMParser) GetMetrics() map[string]interface{} {
	metrics := ap.parser.Metrics()
	metrics["registry.size"] = ap.registry.Size()
	metrics["iform.cache_hits"] = ap.iformCache.Hits()
	metrics["iform.cache_misses"] = ap.iformCache.Misses()
	if corpus, ok := ap.corpus.(*TarXMLCorpus); ok {
		stats := corpus.Stats()
		metrics["corpus.expanded_xml_bytes"] = stats.ExpandedXMLBytes
		metrics["corpus.peak_inflight_bytes"] = stats.PeakInflightBytes
		metrics["corpus.retained_raw_xml_bytes"] = stats.RetainedRawXMLBytes
		metrics["corpus.prepared_iforms"] = stats.PreparedIForms
	}
	return metrics
}

// GetRegistry returns the instruction registry
func (ap *ARMParser) GetRegistry() *InstructionRegistry {
	return ap.registry
}

// Close cleans up resources
func (ap *ARMParser) Close(timeout time.Duration) error {
	if err := ap.parser.Close(timeout); err != nil {
		return err
	}

	ap.iformCache.Clear()
	if closer, ok := ap.corpus.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

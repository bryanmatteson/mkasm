package arm

import (
	"bytes"
	"context"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/decoder"
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/templates"
)

// CodeGenerator generates Go code from the instruction IR
type CodeGenerator struct {
	outputDir string
	templates *template.Template
	decoder   *decoder.DecoderTreeBuilder
	arch      Arch
	// surface is the typed assembler API model, set before Rust codegen.
	surface *AsmSurface
	disasm  *DisasmSurface
}

// SetAsmSurface supplies the typed assembler model for Rust codegen.
func (cg *CodeGenerator) SetAsmSurface(s *AsmSurface) { cg.surface = s }

// SetDisasmSurface supplies the print model used to choose legal exhaustive
// conformance representatives for every generated language.
func (cg *CodeGenerator) SetDisasmSurface(s *DisasmSurface) { cg.disasm = s }

// NewCodeGenerator creates a new code generator
func NewCodeGenerator(outputDir string, arch Arch) *CodeGenerator {
	if arch == "" {
		arch = ArchAArch64
	}
	return &CodeGenerator{
		outputDir: outputDir,
		arch:      arch,
		templates: loadTemplates(),
		decoder:   &decoder.DecoderTreeBuilder{},
	}
}

// GenerateEncoders generates encoder functions grouped by class
func (cg *CodeGenerator) GenerateEncoders(ctx context.Context, byClass map[string][]*ir.InstructionIR) error {
	encoderDir := filepath.Join(cg.outputDir, "encoders")
	if err := os.MkdirAll(encoderDir, 0755); err != nil {
		return fmt.Errorf("create encoder dir: %w", err)
	}

	if err := cg.writeOutputModule(); err != nil {
		return err
	}

	resolved := filterResolvedByClass(byClass)
	if len(resolved) == 0 {
		return fmt.Errorf("no Pass-2-resolved instructions to encode (run with a local -iform directory)")
	}

	for class, instructions := range resolved {
		if err := cg.generateClassEncoder(ctx, class, instructions, encoderDir); err != nil {
			return fmt.Errorf("generate class %s: %w", class, err)
		}
	}

	if err := cg.generateMasterEncoder(ctx, resolved, encoderDir); err != nil {
		return err
	}
	var all []*ir.InstructionIR
	for _, instructions := range resolved {
		all = append(all, instructions...)
	}
	return writeGoConformanceTest(cg.outputDir, cg.arch.ArtifactName(), BuildCatalog(all), cg.disasm)
}

// writeOutputModule ensures the generated tree is a buildable Go module.
func (cg *CodeGenerator) writeOutputModule() error {
	mod := fmt.Sprintf("module %s\n\ngo 1.22\n", cg.arch.ArtifactName())
	if err := os.WriteFile(filepath.Join(cg.outputDir, "go.mod"), []byte(mod), 0644); err != nil {
		return err
	}
	return writeLicense(cg.outputDir)
}

// hasPass2Encoding reports whether Pass 2 applied authoritative iform data.
func hasPass2Encoding(instr *ir.InstructionIR) bool {
	if instr == nil {
		return false
	}
	if instr.Asm.Raw != "" {
		return true
	}
	if strings.ContainsAny(instr.BitPattern, "01") {
		return true
	}
	for _, f := range instr.Encoding.Fields {
		if f.Fixed != nil {
			return true
		}
	}
	return false
}

func filterResolvedByClass(byClass map[string][]*ir.InstructionIR) map[string][]*ir.InstructionIR {
	out := make(map[string][]*ir.InstructionIR)
	for class, instrs := range byClass {
		kept := make([]*ir.InstructionIR, 0, len(instrs))
		for _, instr := range instrs {
			if hasPass2Encoding(instr) {
				kept = append(kept, instr)
			}
		}
		if len(kept) > 0 {
			out[class] = kept
		}
	}
	return out
}

// generateClassEncoder generates encoder for a single instruction class
func (cg *CodeGenerator) generateClassEncoder(ctx context.Context, class string, instructions []*ir.InstructionIR, outputDir string) error {
	// Prepare template data
	data := ClassEncoderData{
		Package:      "encoders",
		ClassName:    formatClassName(class),
		Instructions: cg.prepareInstructionData(instructions),
		Imports:      cg.determineImports(instructions),
	}

	// Generate code
	var buf bytes.Buffer
	if err := cg.templates.ExecuteTemplate(&buf, "class_encoder.tmpl", data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	// Format code
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		// Save unformatted for debugging
		debugPath := filepath.Join(outputDir, fmt.Sprintf("%s_encoder_debug.go", strings.ToLower(class)))
		os.WriteFile(debugPath, buf.Bytes(), 0644)
		return fmt.Errorf("format code: %w", err)
	}

	// Write file
	filename := fmt.Sprintf("%s_encoder.go", strings.ToLower(class))
	outputPath := filepath.Join(outputDir, filename)

	return os.WriteFile(outputPath, formatted, 0644)
}

// generateMasterEncoder generates the main encoder file
func (cg *CodeGenerator) generateMasterEncoder(ctx context.Context, byClass map[string][]*ir.InstructionIR, outputDir string) error {
	classes := cg.extractClasses(byClass)
	classRefs := make([]ClassEncoderRef, 0, len(classes))
	for _, class := range classes {
		typeName := formatClassName(class)
		field := cleanIdentifier(class)
		if field == "" {
			field = "cls"
		}
		fieldName := strings.ToLower(field[:1]) + field[1:]
		classRefs = append(classRefs, ClassEncoderRef{
			Class:     class,
			FieldName: fieldName,
			TypeName:  typeName,
		})
	}

	var all []*ir.InstructionIR
	dispatches := make([]MasterDispatchEntry, 0)
	for class, instrs := range byClass {
		field := cleanIdentifier(class)
		if field == "" {
			continue
		}
		fieldName := strings.ToLower(field[:1]) + field[1:]
		for _, instr := range instrs {
			all = append(all, instr)
			if instr.EncodingID == "" {
				continue
			}
			dispatches = append(dispatches, MasterDispatchEntry{
				EncodingID: instr.EncodingID,
				Class:      class,
				FieldName:  fieldName,
				FuncName:   cg.generateEncoderFuncName(instr),
			})
		}
	}
	sort.Slice(dispatches, func(i, j int) bool {
		return dispatches[i].EncodingID < dispatches[j].EncodingID
	})

	src := emitMasterEncoderSource(classRefs, dispatches, all)
	formatted, err := format.Source([]byte(src))
	if err != nil {
		debugPath := filepath.Join(outputDir, "encoder_debug.go")
		_ = os.WriteFile(debugPath, []byte(src), 0644)
		return fmt.Errorf("format master encoder: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "encoder.go"), formatted, 0644); err != nil {
		return err
	}
	// Always emit fixed-bit round-trip tests next to encoders
	if err := writeFixedRoundTripTest(outputDir, all); err != nil {
		return err
	}
	return nil
}

func writeEncodeDecodeCorpusTest(decoderDir, modPath string, instrs []*ir.InstructionIR) error {
	type sample struct {
		id      string
		word    uint32
		field   string
		fval    uint64
		packed  uint32
		pattern string
		// fixedLegal is false when the encoding's own constraints reject the
		// zeroed base: SVE's FNMLA requires size != 00, so EncodeFixed's word
		// is a well-defined fixed-bit base but not a legal instruction. The
		// decode round-trip is only asserted on legal words.
		fixedLegal  bool
		packedLegal bool
	}
	var samples []sample
	for _, instr := range instrs {
		if instr == nil || instr.EncodingID == "" {
			continue
		}
		w, ok := ir.FixedWord(instr)
		if !ok {
			continue
		}
		fixedMask, _ := ir.FixedBitsFromPattern(instr.BitPattern)
		s := sample{
			id: instr.EncodingID, word: w, pattern: instr.BitPattern,
			fixedLegal: ir.MatchWord(instr, w),
		}
		for _, f := range instr.Encoding.Fields {
			if f.Name == "" || f.Fixed != nil || f.Start < 0 || f.End < f.Start {
				continue
			}
			width := f.End - f.Start + 1
			if width <= 0 || width > 16 {
				continue
			}
			// Only vary the bits this encoding actually leaves free. A partly
			// pinned field (SMSTOP's CRm<0>=0) would otherwise be handed a value
			// that encodes a different instruction entirely.
			free := (fieldRangeMask(f.Start, f.End) &^ fixedMask) >> uint(f.Start)
			if free == 0 {
				continue
			}
			max := uint64(1)<<uint(width) - 1
			variable := max
			if max > 1 {
				variable = max / 2
				if variable == 0 {
					variable = 1
				}
			}
			variable &= uint64(free)
			if variable == 0 {
				// Lowest free bit keeps the case non-trivial.
				variable = uint64(free & (^free + 1))
			}
			// EncodeWithFields accepts the complete logical field value. Retain
			// any bits the encoding pins inside a partly variable field and vary
			// only the free portion.
			fieldMask := fieldRangeMask(f.Start, f.End)
			fixedValue := uint64((w & fieldMask) >> uint(f.Start))
			val := fixedValue | variable
			packed, err := ir.InsertField(w, f, val)
			if err != nil {
				continue
			}
			s.field = f.Name
			s.fval = val
			s.packed = packed
			s.packedLegal = ir.MatchWord(instr, packed)
			break
		}
		samples = append(samples, s)
		if len(samples) >= 128 {
			break
		}
	}
	if len(samples) == 0 {
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, `// Code generated by mkasm. DO NOT EDIT.

package decoders_test

import (
	"testing"

	%q
	%q
)
`, modPath+"/decoders", modPath+"/encoders")
	b.WriteString(`

func TestEncodeDecode_corpus(t *testing.T) {
	type row struct {
		id          string
		fixed       uint32
		field       string
		fval        uint64
		packed      uint32
		pattern     string
		fixedLegal  bool
		packedLegal bool
	}
	cases := []row{
`)
	for _, s := range samples {
		fmt.Fprintf(&b, "\t\t{%q, 0x%08X, %q, %d, 0x%08X, %q, %t, %t},\n",
			s.id, s.word, s.field, s.fval, s.packed, s.pattern, s.fixedLegal, s.packedLegal)
	}
	b.WriteString(`	}
	for _, c := range cases {
		c := c
		t.Run(c.id+"/fixed", func(t *testing.T) {
			got, err := encoders.EncodeFixed(c.id)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.fixed {
				t.Fatalf("EncodeFixed=0x%08X want 0x%08X", got, c.fixed)
			}
			if !c.fixedLegal {
				// The encoding constrains a variable field away from zero, so
				// its zeroed base is not a legal instruction and must not
				// decode. Assert exactly that.
				if d, err := decoders.Decode(got); err == nil && d.EncodingID == c.id {
					t.Fatalf("0x%08X violates %s's own constraints but decoded as it", got, c.id)
				}
				return
			}
			d, err := decoders.Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			if d.EncodingID != c.id && !containsID(d.Ambiguous, c.id) {
				// The zeroed base of a generic encoding can be a different
				// instruction outright: MSR with op1/CRm/op2 all zero *is*
				// CFINV, and the fully pinned encoding rightly wins. Require
				// only that the word genuinely belongs to the expected
				// encoding; which match ranks first is a specificity policy.
				if !matchesPattern(c.pattern, got) {
					t.Fatalf("Decode fixed → %s ambig=%v want %s (word 0x%08X does not match %s)",
						d.EncodingID, d.Ambiguous, c.id, got, c.pattern)
				}
				t.Logf("specialization wins: primary=%s, %s also matches", d.EncodingID, c.id)
			}
		})
		if c.field == "" {
			continue
		}
		t.Run(c.id+"/fields", func(t *testing.T) {
			got, err := encoders.EncodeWithFields(c.id, map[string]uint64{c.field: c.fval})
			if err != nil {
				t.Fatal(err)
			}
			if got != c.packed {
				t.Fatalf("EncodeWithFields=0x%08X want 0x%08X", got, c.packed)
			}
			if !c.packedLegal {
				return // constrained field still unsatisfied; see /fixed above
			}
			d, err := decoders.Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			if d.EncodingID != c.id && !containsID(d.Ambiguous, c.id) {
				if !matchesPattern(c.pattern, got) {
					t.Fatalf("Decode packed → %s ambig=%v want %s (word 0x%08X does not match %s)",
						d.EncodingID, d.Ambiguous, c.id, got, c.pattern)
				}
				t.Logf("specialization wins: primary=%s, %s also matches", d.EncodingID, c.id)
			}
			if v, ok := d.Field(c.field); ok && v != c.fval && d.EncodingID == c.id {
				t.Fatalf("field %s=%d want %d", c.field, v, c.fval)
			}
		})
	}
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// matchesPattern reports whether word satisfies a 32-char 0/1/x bit pattern.
func matchesPattern(pattern string, word uint32) bool {
	if len(pattern) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		bit := (word >> uint(31-i)) & 1
		switch pattern[i] {
		case '0':
			if bit != 0 {
				return false
			}
		case '1':
			if bit != 1 {
				return false
			}
		}
	}
	return true
}
`)
	formatted, err := format.Source([]byte(b.String()))
	if err != nil {
		formatted = []byte(b.String())
	}
	return os.WriteFile(filepath.Join(decoderDir, "roundtrip_corpus_test.go"), formatted, 0644)
}

// GenerateDecoders generates decoder functions
func (cg *CodeGenerator) GenerateDecoders(ctx context.Context, byClass map[string][]*ir.InstructionIR) error {
	decoderDir := filepath.Join(cg.outputDir, "decoders")
	if err := os.MkdirAll(decoderDir, 0755); err != nil {
		return fmt.Errorf("create decoder dir: %w", err)
	}

	var allInstructions []*ir.InstructionIR
	for _, instrs := range byClass {
		allInstructions = append(allInstructions, instrs...)
	}

	features := make(decoder.FeatureMap)
	tree := cg.decoder.BuildTree(allInstructions, features)
	leaves, nodes := countDecoderTree(tree)

	// Prefer programmatically emitted decoder (table + real Match walk)
	// over the stub decoder.tmpl. Tree stats still come from BuildTree.
	src := emitDecoderSource(allInstructions, tree, leaves, nodes)
	formatted, err := format.Source([]byte(src))
	if err != nil {
		debugPath := filepath.Join(decoderDir, "decoder_debug.go")
		_ = os.WriteFile(debugPath, []byte(src), 0644)
		return fmt.Errorf("format decoder: %w", err)
	}

	outputPath := filepath.Join(decoderDir, "decoder.go")
	if err := os.WriteFile(outputPath, formatted, 0644); err != nil {
		return err
	}
	if err := writeEncodeDecodeCorpusTest(decoderDir, cg.arch.ArtifactName(), allInstructions); err != nil {
		return err
	}
	// Always emit golden decoder tests for known fixed words present in this set
	return cg.GenerateTests(ctx, allInstructions)
}

func countDecoderTree(tree *ir.DecoderTree) (leaves, nodes int) {
	if tree == nil || tree.Root == nil {
		return 0, 0
	}
	var walk func(n *ir.DecoderNode)
	walk = func(n *ir.DecoderNode) {
		if n == nil {
			return
		}
		nodes++
		if n.Instruction != nil || len(n.Ambiguous) > 0 {
			leaves++
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)
	return leaves, nodes
}

// GenerateRegistry generates the instruction registry
func (cg *CodeGenerator) GenerateRegistry(ctx context.Context, instructions []*ir.InstructionIR) error {
	registryDir := filepath.Join(cg.outputDir, "registry")
	if err := os.MkdirAll(registryDir, 0755); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	src := emitRegistrySource(instructions)
	formatted, err := format.Source([]byte(src))
	if err != nil {
		_ = os.WriteFile(filepath.Join(registryDir, "registry_debug.go"), []byte(src), 0644)
		return fmt.Errorf("format registry: %w", err)
	}
	return os.WriteFile(filepath.Join(registryDir, "registry.go"), formatted, 0644)
}

// GenerateTests generates decoder golden tests under decoders/ (package-level).
func (cg *CodeGenerator) GenerateTests(ctx context.Context, instructions []*ir.InstructionIR) error {
	decoderDir := filepath.Join(cg.outputDir, "decoders")
	if err := os.MkdirAll(decoderDir, 0755); err != nil {
		return err
	}
	return writeGoldenDecoderTest(decoderDir, instructions)
}

// Helper methods

func (cg *CodeGenerator) prepareInstructionData(instructions []*ir.InstructionIR) []InstructionEncoderData {
	data := make([]InstructionEncoderData, 0, len(instructions))

	for _, instr := range instructions {
		data = append(data, InstructionEncoderData{
			Instruction: instr,
			FuncName:    cg.generateEncoderFuncName(instr),
			Operands:    cg.prepareOperandData(instr.Operands),
			FixedBits:   cg.extractFixedBits(instr.Encoding),
			Constraints: cg.extractConstraints(instr),
		})
	}

	return data
}

func (cg *CodeGenerator) generateEncoderFuncName(instr *ir.InstructionIR) string {
	mnem := cleanIdentifier(instr.Mnemonic)
	if mnem == "" {
		mnem = "Unknown"
	}
	base := "encode" + strings.ToUpper(mnem[:1]) + mnem[1:]

	if instr.EncodingID != "" {
		base += "_" + cleanIdentifier(instr.EncodingID)
	}

	return base
}

func (cg *CodeGenerator) prepareOperandData(operands []ir.OperandIR) []OperandEncoderData {
	data := make([]OperandEncoderData, 0, len(operands))
	used := map[string]int{}

	for _, op := range operands {
		base := safeParamName(op.Name)
		name := base
		if n := used[base]; n > 0 {
			name = fmt.Sprintf("%s%d", base, n+1)
		}
		used[base]++
		data = append(data, OperandEncoderData{
			Operand:   op,
			ParamName: name,
			ParamType: cg.getOperandGoType(op),
		})
	}

	return data
}

// getOperandGoType picks the parameter type for a class encoder operand. The
// emitted encoders package declares no operand types of its own, so registers,
// conditions and enums are all plain uint32; only immediates narrow, to make an
// out-of-range literal a compile error at the call site.
func (cg *CodeGenerator) getOperandGoType(op ir.OperandIR) string {
	if op.Type != ir.Imm {
		return "uint32"
	}
	switch width := op.BitRange.End - op.BitRange.Start + 1; {
	case width <= 0:
		return "uint32"
	case width <= 8:
		return "uint8"
	case width <= 16:
		return "uint16"
	case width <= 32:
		return "uint32"
	default:
		return "uint64"
	}
}

func (cg *CodeGenerator) extractFixedBits(encoding ir.EncodingMask) []FixedBitData {
	fixed := make([]FixedBitData, 0)

	for _, field := range encoding.Fields {
		if field.Fixed == nil || field.Start < 0 || field.End < field.Start {
			continue
		}
		fixed = append(fixed, FixedBitData{
			Start: field.Start,
			End:   field.End,
			Value: *field.Fixed,
		})
	}

	sort.Slice(fixed, func(i, j int) bool {
		return fixed[i].Start < fixed[j].Start
	})

	return fixed
}

func (cg *CodeGenerator) extractConstraints(instr *ir.InstructionIR) []ConstraintData {
	constraints := make([]ConstraintData, 0)

	for _, op := range instr.Operands {
		if hasConstraints(op.Constraint) {
			constraints = append(constraints, ConstraintData{
				OperandName: op.Name,
				Constraint:  op.Constraint,
			})
		}
	}

	return constraints
}

func (cg *CodeGenerator) determineImports(instructions []*ir.InstructionIR) []string {
	// Class encoder bodies are self-contained; no imports required.
	_ = instructions
	return nil
}

func (cg *CodeGenerator) extractClasses(byClass map[string][]*ir.InstructionIR) []string {
	classes := make([]string, 0, len(byClass))
	for class := range byClass {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	return classes
}

// Helper functions

func formatClassName(class string) string {
	// Convert class name to Go identifier
	parts := strings.Split(class, "_")
	for i := range parts {
		parts[i] = strings.ToTitle(strings.ToLower(parts[i]))
	}
	return strings.Join(parts, "")
}

func cleanIdentifier(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if b.Len() == 0 {
				b.WriteByte('n')
			}
			b.WriteRune(r)
		case r == '-' || r == '.' || r == ' ' || r == '/' || r == '(' || r == ')':
			if b.Len() > 0 && (i+1 < len(s)) {
				b.WriteByte('_')
			}
		default:
			// drop other punctuation
		}
	}
	out := b.String()
	// Collapse repeated underscores
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	return strings.Trim(out, "_")
}

// safeParamName produces a non-keyword Go parameter identifier.
// Avoids colliding with the encoder receiver name "enc".
func safeParamName(raw string) string {
	name := cleanIdentifier(raw)
	if name == "" {
		name = "op"
	}
	// Lowercase first letter for param style when whole field is short (a,b,c,e…)
	// keep as-is otherwise.
	switch name {
	case "enc", "encoding", "type", "func", "var", "const", "package", "range",
		"map", "chan", "go", "select", "interface", "struct", "return", "if",
		"else", "for", "switch", "case", "default", "break", "continue",
		"fallthrough", "defer", "import", "error", "byte", "string", "bool",
		"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
		"uint32", "uint64", "float32", "float64", "any", "true", "false", "nil",
		"len", "cap", "make", "new", "append", "copy", "delete", "panic", "recover":
		name = name + "Val"
	}
	return name
}

func hasConstraints(c ir.Constraint) bool {
	return c.MustBeZero || c.MustBeOne ||
		c.Mask != 0 || c.Min != 0 || c.Max != 0 ||
		len(c.AllowedVals) > 0 || len(c.DisallowedVals) > 0
}

// Template data structures

type ClassEncoderData struct {
	Package      string
	ClassName    string
	Instructions []InstructionEncoderData
	Imports      []string
}

type InstructionEncoderData struct {
	Instruction *ir.InstructionIR
	FuncName    string
	Operands    []OperandEncoderData
	FixedBits   []FixedBitData
	Constraints []ConstraintData
}

type OperandEncoderData struct {
	Operand   ir.OperandIR
	ParamName string
	ParamType string
}

type FixedBitData struct {
	Start int
	End   int
	Value uint64
}

type ConstraintData struct {
	OperandName string
	Constraint  ir.Constraint
}

type MasterEncoderData struct {
	Package    string
	Classes    []ClassEncoderRef
	Dispatches []MasterDispatchEntry
}

type ClassEncoderRef struct {
	Class     string
	FieldName string
	TypeName  string
}

type MasterDispatchEntry struct {
	EncodingID string
	Class      string
	FieldName  string
	FuncName   string
}

type DecoderData struct {
	Package    string
	Tree       *ir.DecoderTree
	Classes    []string
	LeafCount  int
	NodeCount  int
	InstrCount int
}

// loadTemplates loads Go Pass 3 templates from templates/go/*.tmpl.
func loadTemplates() *template.Template {
	tmpl := template.New("codegen")
	tmpl.Funcs(template.FuncMap{
		"lower":      strings.ToLower,
		"upper":      strings.ToUpper,
		"title":      strings.ToTitle,
		"cleanIdent": cleanIdentifier,
		"hasPrefix":  strings.HasPrefix,
		"hasSuffix":  strings.HasSuffix,
		"printf":     fmt.Sprintf,
		"ge":         func(a, b int) bool { return a >= b },
	})
	return template.Must(tmpl.ParseFS(templates.FS, "go/*.tmpl"))
}

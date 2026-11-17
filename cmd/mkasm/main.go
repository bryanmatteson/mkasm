package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"github.com/bryanmatteson/mkasm/pkg/object"
)

const commandName = "mkasm"

const helpText = `mkasm generates standalone instruction codec projects or exports resolved IR.

Usage:
  mkasm [--arch <target>] --codegen <rust|go> --output <dir> <input>
  mkasm [--arch <target>] --json <input>
  mkasm --arch cil --inspect --json [--verify] [--native] <assembly>
  mkasm --arch cil --rewrite <manifest.json> --output <assembly> <input>
  mkasm --assemble-object --assembler <tool> --target-triple <triple> --output <file> <input>

Modes:
  --codegen <rust|go>  Generate a standalone codec project.
  --json               Write resolved instruction IR as JSON to stdout.

Arguments:
  <input>  Architecture specification file, URL, or - for stdin.
           Arm: ISA XML directory/archive. x86: opcodesDB v3 JSON.
           RISC-V: riscv-opcodes directory or tar archive.
           LLVM targets: resolved TableGen JSON (--dump-json).
           Other native, bytecode and module sources: see docs/architecture-codecs.md.
           Use --list-architectures for all target names.

Options:
  --arch <arch>  Target architecture (default: aarch64).
  --output <dir>  Destination directory. Required with --codegen.
  --cpu <name>    Select a source-defined CPU profile (where available).
  --strict-corpus Reject unsupported source records.
  --inspect       Inspect a .NET PE/CLI image or Portable PDB (with --arch cil --json).
  --verify        Check CIL stack heights, variable bounds and maxstack during inspection.
  --native        Include ReadyToRun native function bytes and MethodDef mappings.
  --type-verifier <tool> Run ILVerify with an explicitly selected executable.
  --references <paths> Reference assembly paths/globs for metadata and ILVerify.
  --system-module <name> Core library name (default: System.Private.CoreLib).
  --rewrite <json> Replace methods using token-to-complete-hex-body JSON.
  --drop-native   Remove ReadyToRun code when all required IL bodies remain.
  --strip-signatures Remove invalidated strong-name and Authenticode signatures.
  --assemble-object Assemble complete programs, retaining symbols and relocations.
  --assembler <path> Explicit target assembler executable.
  --assembler-kind <kind> llvm (default), gnu, or command.
  --target-triple <triple> LLVM target triple.
  --assembler-args <json> Literal argument array; command uses {input}/{output}.
  --features <list> Comma-separated LLVM feature names.
  --list-architectures List all supported target names.
  --version       Show the mkasm version.
  -h, --help      Show this help.

Examples:
  mkasm --codegen rust --output ./aarch64-rs ./ISA_A64_xml.tar.gz
  xz -dc x86_64.json.xz | mkasm --arch x86_64 --codegen rust --output ./x86_64-rs -
  mkasm --codegen go --output ./aarch64-go https://example.com/ISA_A64_xml.tar.gz
  curl -fsSL https://example.com/ISA_A64_xml.tar.gz | mkasm --json - > arm-ir.json

Status and statistics are written to stderr. JSON is written only to stdout.

Learn more:
  https://github.com/bryanmatteson/mkasm
`

// version is replaced by the release build using -ldflags=-X.
var version = "dev"

type usageError struct {
	message string
}

func (e *usageError) Error() string { return e.message }

func main() {
	err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", commandName, err)
	var badUsage *usageError
	if errors.As(err, &badUsage) {
		fmt.Fprintf(os.Stderr, "\n%s", helpText)
		os.Exit(2)
	}
	os.Exit(1)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (err error) {
	if len(args) == 0 {
		_, err := io.WriteString(stdout, helpText)
		return err
	}

	flags := flag.NewFlagSet(commandName, flag.ContinueOnError)
	// The flag package otherwise writes its own error and usage before returning
	// an error, causing main to print both a second time. All diagnostics have
	// one owner here so stdout and stderr remain predictable.
	flags.SetOutput(io.Discard)

	codegen := flags.String("codegen", "", "generate a rust or go project")
	archName := flags.String("arch", "aarch64", "target architecture")
	jsonIR := flags.Bool("json", false, "write resolved instruction IR as JSON to stdout")
	output := flags.String("output", "", "generated project directory")
	cpu := flags.String("cpu", "", "source-defined CPU profile")
	strictCorpus := flags.Bool("strict-corpus", false, "reject unsupported source records")
	inspect := flags.Bool("inspect", false, "inspect a .NET managed image or metadata file")
	verify := flags.Bool("verify", false, "verify managed evaluation stacks during inspection")
	native := flags.Bool("native", false, "include ReadyToRun headers, functions and native code during inspection")
	rewrite := flags.String("rewrite", "", "MethodDef token to complete hex body JSON manifest")
	dropNative := flags.Bool("drop-native", false, "discard ReadyToRun code when rewriting")
	stripSignatures := flags.Bool("strip-signatures", false, "remove invalidated PE signatures when rewriting")
	typeVerifier := flags.String("type-verifier", "", "ILVerify executable for full managed type verification")
	references := flags.String("references", "", "comma-separated explicit reference assembly paths/globs")
	systemModule := flags.String("system-module", "System.Private.CoreLib", "managed core library name")
	assembleProgram := flags.Bool("assemble-object", false, "assemble a complete program with an explicit toolchain")
	assembler := flags.String("assembler", "", "target assembler executable")
	assemblerKind := flags.String("assembler-kind", "llvm", "llvm, gnu, or command")
	assemblerArgs := flags.String("assembler-args", "", "JSON array of literal assembler arguments")
	targetTriple := flags.String("target-triple", "", "explicit LLVM target triple")
	features := flags.String("features", "", "comma-separated assembler feature names")
	listArchitectures := flags.Bool("list-architectures", false, "list supported targets")
	showVersion := flags.Bool("version", false, "show the mkasm version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := io.WriteString(stdout, helpText)
			return err
		}
		return &usageError{message: err.Error()}
	}
	if *listArchitectures {
		if *assembleProgram || *assembler != "" || *assemblerKind != "llvm" || *assemblerArgs != "" || *targetTriple != "" || *features != "" {
			return &usageError{message: "--list-architectures must be used alone"}
		}
		if flags.NArg() != 0 || *showVersion || *codegen != "" || *jsonIR || *output != "" || *cpu != "" || *strictCorpus || *inspect || *archName != "aarch64" || *verify || *native || *rewrite != "" || *dropNative || *stripSignatures || *typeVerifier != "" || *references != "" || *systemModule != "System.Private.CoreLib" {
			return &usageError{message: "--list-architectures must be used alone"}
		}
		_, err := fmt.Fprintln(stdout, strings.Join(architectureNames(), "\n"))
		return err
	}
	if *showVersion {
		if *assembleProgram || *assembler != "" || *assemblerKind != "llvm" || *assemblerArgs != "" || *targetTriple != "" || *features != "" {
			return &usageError{message: "--version must be used alone"}
		}
		if flags.NArg() != 0 || *codegen != "" || *jsonIR || *output != "" || *archName != "aarch64" || *cpu != "" || *strictCorpus || *inspect || *verify || *native || *rewrite != "" || *dropNative || *stripSignatures || *typeVerifier != "" || *references != "" || *systemModule != "System.Private.CoreLib" {
			return &usageError{message: "--version cannot be combined with a mode, output, or input"}
		}
		_, err := fmt.Fprintf(stdout, "%s %s\n", commandName, resolvedVersion())
		return err
	}

	if flags.NArg() != 1 {
		return &usageError{message: "exactly one INPUT is required"}
	}
	if *assembleProgram {
		if *assembler == "" || (*output == "") == !*jsonIR || *codegen != "" || *inspect || *strictCorpus || *verify || *native || *rewrite != "" || *dropNative || *stripSignatures || *typeVerifier != "" || *references != "" || *systemModule != "System.Private.CoreLib" {
			return &usageError{message: "--assemble-object requires --assembler and exactly one of --output FILE or --json, without other modes"}
		}
		opts := object.Options{Executable: *assembler, Kind: *assemblerKind, Triple: *targetTriple, CPU: *cpu}
		if *features != "" {
			opts.Features = strings.Split(*features, ",")
		}
		if *assemblerArgs != "" {
			if e := json.Unmarshal([]byte(*assemblerArgs), &opts.Arguments); e != nil {
				return &usageError{message: "--assembler-args must be a JSON string array"}
			}
		}
		return assembleObject(ctx, flags.Arg(0), *output, *jsonIR, stdin, stdout, opts)
	}
	if *assembler != "" || *assemblerKind != "llvm" || *assemblerArgs != "" || *targetTriple != "" || *features != "" {
		return &usageError{message: "assembler options require --assemble-object"}
	}
	if *rewrite != "" {
		if canonicalArchitecture(*archName) != "cil" || *output == "" || *jsonIR || *codegen != "" || *cpu != "" || *strictCorpus || *inspect || *verify || *native || *showVersion || *listArchitectures || *typeVerifier != "" || *references != "" || *systemModule != "System.Private.CoreLib" {
			return &usageError{message: "--rewrite requires --arch cil --output FILE and no other mode"}
		}
		return rewriteManaged(ctx, flags.Arg(0), *rewrite, *output, stdin, dotnet.RewriteOptions{DropNative: *dropNative, StripStrongName: *stripSignatures, StripAuthenticode: *stripSignatures})
	}
	if *dropNative || *stripSignatures {
		return &usageError{message: "--drop-native and --strip-signatures require --rewrite"}
	}
	if (*verify || *native) && !*inspect {
		return &usageError{message: "--verify and --native require --inspect"}
	}
	if (*typeVerifier != "" || *references != "" || *systemModule != "System.Private.CoreLib") && !*inspect {
		return &usageError{message: "type verification options require --inspect"}
	}
	if *typeVerifier == "" && *systemModule != "System.Private.CoreLib" {
		return &usageError{message: "a custom system module requires --type-verifier"}
	}
	if (*codegen == "") == !*jsonIR {
		return &usageError{message: "choose exactly one of --codegen or --json"}
	}
	architecture := canonicalArchitecture(*archName)
	if architecture != "aarch64" && architecture != "arm32" && architecture != "x86_64" && architecture != "x86_32" && backendLoaders[architecture] == nil {
		return &usageError{message: "--arch must be one of: " + strings.Join(architectureNames(), ", ")}
	}
	if *inspect {
		if architecture != "cil" || !*jsonIR || *codegen != "" || *output != "" || *cpu != "" || *strictCorpus {
			return &usageError{message: "--inspect requires --arch cil --json and no generation or CPU options"}
		}
		var refs []string
		if *references != "" {
			refs = strings.Split(*references, ",")
		}
		return inspectManagedDetailed(ctx, flags.Arg(0), stdin, stdout, *verify, *typeVerifier, refs, *systemModule, *native)
	}
	if (*cpu != "" || *strictCorpus) && backendLoaders[architecture] == nil {
		return &usageError{message: "--cpu and --strict-corpus require a specification backend"}
	}

	var languages []arm.CodegenLang
	if *codegen != "" {
		switch strings.ToLower(strings.TrimSpace(*codegen)) {
		case "rust":
			languages = []arm.CodegenLang{arm.LangRust}
		case "go":
			languages = []arm.CodegenLang{arm.LangGo}
		default:
			return &usageError{message: "--codegen must be rust or go"}
		}
		if strings.TrimSpace(*output) == "" {
			return &usageError{message: "--output is required with --codegen"}
		}
		if architecture != "aarch64" && languages[0] != arm.LangRust {
			return &usageError{message: architecture + " code generation currently supports rust"}
		}
	} else if *output != "" {
		return &usageError{message: "--output is only valid with --codegen"}
	}

	input := flags.Arg(0)
	if architecture == "x86_64" || architecture == "x86_32" {
		return runX86(ctx, input, stdin, stdout, stderr, *output, *jsonIR, architecture)
	}
	if backendLoaders[architecture] != nil {
		return runBackend(ctx, architecture, input, stdin, stdout, stderr, *output, *jsonIR, *cpu, *strictCorpus)
	}
	source, err := openInput(ctx, input, stdin)
	if err != nil {
		return err
	}
	arch := arm.Arch(architecture)
	source.encodingIndex = filepath.Join(filepath.Dir(source.encodingIndex), arch.SpecIndexFile())

	if *codegen != "" {
		if err := os.MkdirAll(*output, 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	started := time.Now()
	parser := arm.NewARMParser(arm.ARMParserConfig{
		EncodingIndexPath: source.encodingIndex,
		IFormDirectory:    source.iformDirectory,
		OutputDirectory:   *output,
		Corpus:            source.corpus,
		IFormWorkers:      runtime.GOMAXPROCS(0),
		SkipCodegen:       *codegen == "",
		Languages:         languages,
		Arch:              arch,
		Progress:          stderr,
	})
	defer func() {
		if closeErr := parser.Close(5 * time.Second); err == nil && closeErr != nil {
			err = fmt.Errorf("close parser: %w", closeErr)
		}
	}()

	if err := parser.Parse(ctx); err != nil {
		return fmt.Errorf("parse %s: %w", source.description, err)
	}

	registry := parser.GetRegistry()
	validator := arm.NewInstructionValidator()
	if bad := validator.ValidateAll(registry.GetAll()); bad != 0 {
		errs := validator.GetErrors()
		if len(errs) != 0 {
			return fmt.Errorf("validate IR: %d instructions have issues (first: %s)", bad, errs[0])
		}
		return fmt.Errorf("validate IR: %d instructions have issues", bad)
	}

	printStats(stderr, source.description, registry, parser.GetMetrics(), time.Since(started))
	if *jsonIR {
		return writeArchitectureIRJSON(stdout, registry, arch)
	}
	return nil
}

func printStats(w io.Writer, source string, registry *arm.InstructionRegistry, metrics map[string]any, elapsed time.Duration) {
	stats := registry.Statistics()
	fmt.Fprintf(w, "Input: %s\n", source)
	fmt.Fprintf(w, "Instructions: %d total, %d resolved\n", stats.TotalInstructions, registry.ResolvedCount())
	fmt.Fprintf(w, "Mnemonics: %d; classes: %d; features: %d\n",
		stats.UniqueMnemonics, stats.UniqueClasses, stats.UniqueFeatures)
	if expanded, ok := metrics["corpus.expanded_xml_bytes"]; ok {
		fmt.Fprintf(w, "Corpus XML: %v bytes expanded", expanded)
		if peak, exists := metrics["corpus.peak_inflight_bytes"]; exists {
			fmt.Fprintf(w, "; %v bytes peak in flight", peak)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Elapsed: %s\n", elapsed.Round(time.Millisecond))
}

func resolvedVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

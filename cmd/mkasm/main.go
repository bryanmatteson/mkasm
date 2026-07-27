package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

const commandName = "mkasm"

const helpText = `mkasm generates AArch64 assembler projects or exports the resolved IR.

Usage:
  mkasm --codegen <rust|go> --output <dir> <input>
  mkasm --json <input>

Modes:
  --codegen <rust|go>  Generate a standalone assembler project.
  --json               Write resolved instruction IR as JSON to stdout.

Arguments:
  <input>  ARM ISA XML directory, .tar or .tar.gz archive, HTTP(S) URL,
           or - to read a tar stream from stdin.

Options:
  --output <dir>  Destination directory. Required with --codegen.
  --version       Show the mkasm version.
  -h, --help      Show this help.

Examples:
  mkasm --codegen rust --output ./aarch64-rs ./ISA_A64_xml.tar.gz
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
	jsonIR := flags.Bool("json", false, "write resolved instruction IR as JSON to stdout")
	output := flags.String("output", "", "generated project directory")
	showVersion := flags.Bool("version", false, "show the mkasm version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := io.WriteString(stdout, helpText)
			return err
		}
		return &usageError{message: err.Error()}
	}
	if *showVersion {
		if flags.NArg() != 0 || *codegen != "" || *jsonIR || *output != "" {
			return &usageError{message: "--version cannot be combined with a mode, output, or input"}
		}
		_, err := fmt.Fprintf(stdout, "%s %s\n", commandName, resolvedVersion())
		return err
	}

	if flags.NArg() != 1 {
		return &usageError{message: "exactly one INPUT is required"}
	}
	if (*codegen == "") == !*jsonIR {
		return &usageError{message: "choose exactly one of --codegen or --json"}
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
	} else if *output != "" {
		return &usageError{message: "--output is only valid with --codegen"}
	}

	input := flags.Arg(0)
	source, err := openInput(ctx, input, stdin)
	if err != nil {
		return err
	}

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
		Arch:              arm.ArchAArch64,
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
		return writeIRJSON(stdout, registry)
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

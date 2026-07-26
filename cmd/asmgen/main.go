package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"mkasm/pkg/arm"
)

const usage = `usage:
  asmgen --codegen rust --output DIR INPUT
  asmgen --codegen go   --output DIR INPUT
  asmgen --json INPUT

INPUT is an ISA XML directory, a .tar/.tar.gz file, an HTTP(S) URL, or -
for a tar stream on stdin.
`

type usageError struct {
	message string
}

func (e *usageError) Error() string { return e.message }

func main() {
	err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "asmgen: %v\n", err)
	var badUsage *usageError
	if errors.As(err, &badUsage) {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	os.Exit(1)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (err error) {
	flags := flag.NewFlagSet("asmgen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usage) }

	codegen := flags.String("codegen", "", "generate a rust or go project")
	jsonIR := flags.Bool("json", false, "write resolved instruction IR as JSON to stdout")
	output := flags.String("output", "", "generated project directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return &usageError{message: err.Error()}
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

package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

const corpusEnv = "MKASM_CORPUS"

type parserOptions struct {
	codegen arm.CodegenLang
}

// loadCorpusParser makes every external proof consume the same explicit
// compressed corpus used by the CLI. Ordinary `go test ./...` skips these
// expensive suites; the mise conformance tasks always set MKASM_CORPUS, so a
// missing or invalid corpus is a hard failure rather than a misleading skip.
func loadCorpusParser(t *testing.T, options parserOptions) (*arm.ARMParser, string) {
	t.Helper()
	location := os.Getenv(corpusEnv)
	if location == "" {
		t.Skipf("set %s or run a mise conformance task", corpusEnv)
	}

	corpus, err := arm.OpenTarXMLCorpus(context.Background(), location)
	if err != nil {
		t.Fatalf("open %s=%q: %v", corpusEnv, location, err)
	}

	outDir := filepath.Join(t.TempDir(), "aarch64")
	config := arm.ARMParserConfig{
		Corpus:            corpus,
		EncodingIndexPath: arm.ArchAArch64.SpecIndexFile(),
		OutputDirectory:   outDir,
		SkipCodegen:       options.codegen == "",
		IFormWorkers:      8,
		Arch:              arm.ArchAArch64,
	}
	if options.codegen != "" {
		config.Languages = []arm.CodegenLang{options.codegen}
	}

	parser := arm.NewARMParser(config)
	t.Cleanup(func() {
		if err := parser.Close(2 * time.Second); err != nil {
			t.Errorf("close parser: %v", err)
		}
	})
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatalf("parse %s=%q: %v", corpusEnv, location, err)
	}
	t.Logf("corpus=%s resolved-instructions=%d", location, len(parser.ResolvedInstructions()))
	return parser, outDir
}

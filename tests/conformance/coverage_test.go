package conformance_test

import (
	"os"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/arm"
	encodingcoverage "github.com/bryanmatteson/mkasm/pkg/coverage"
)

func TestGeneratedLedgerEncodingCoverage(t *testing.T) {
	if os.Getenv("MKASM_LEDGER_COVERAGE") != "1" {
		t.Skip("set MKASM_LEDGER_COVERAGE=1 or run mise run coverage:encodings")
	}
	p, _ := loadCorpusParser(t, parserOptions{})
	resolved := p.ResolvedInstructions()
	expected := make([]string, len(resolved))
	for i := range resolved {
		expected[i] = resolved[i].EncodingID
	}

	goCases := arm.GoConformanceCases(arm.BuildCatalog(resolved))
	goIDs := goCaseIDs(goCases)
	requireCompleteLedger(t, "go-exact", expected, goIDs)

	_, rustCases := arm.EmitRustExactConformanceTest("aarch64", p.AsmSurface())
	rustIDs := rustCaseIDs(rustCases)
	requireCompleteLedger(t, "rust-exact", expected, rustIDs)
}

func requireCompleteLedger(t *testing.T, name string, expected, observed []string) {
	t.Helper()
	report := encodingcoverage.Analyze(expected, observed)
	t.Logf("%s encoding coverage: %.2f%% (%d/%d)",
		name, report.Percent(), report.Covered, report.Expected)
	if err := report.Error(); err != nil {
		t.Fatal(err)
	}
}

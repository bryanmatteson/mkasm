package coverage

import (
	"strings"
	"testing"
)

func TestAnalyzeComplete(t *testing.T) {
	report := Analyze([]string{"b", "a"}, []string{"a", "b"})
	if !report.Complete() || report.Percent() != 100 || report.Error() != nil {
		t.Fatalf("complete report = %#v, error=%v", report, report.Error())
	}
}

func TestAnalyzeIncomplete(t *testing.T) {
	report := Analyze(
		[]string{"missing", "duplicate", "covered"},
		[]string{"duplicate", "covered", "duplicate", "unknown"},
	)
	if report.Complete() {
		t.Fatal("incomplete report is complete")
	}
	if report.Expected != 3 || report.Covered != 2 || report.Percent() != 200.0/3.0 {
		t.Fatalf("counts = %#v", report)
	}
	if got := report.Missing; len(got) != 1 || got[0] != "missing" {
		t.Fatalf("missing = %v", got)
	}
	if got := report.Duplicates; len(got) != 1 || got[0] != "duplicate" {
		t.Fatalf("duplicates = %v", got)
	}
	if got := report.Unknown; len(got) != 1 || got[0] != "unknown" {
		t.Fatalf("unknown = %v", got)
	}
	if err := report.Error(); err == nil || !strings.Contains(err.Error(), "66.67%") {
		t.Fatalf("error = %v", err)
	}
}

func TestEmptyExpectationIsComplete(t *testing.T) {
	report := Analyze(nil, nil)
	if !report.Complete() || report.Percent() != 100 {
		t.Fatalf("empty report = %#v", report)
	}
}

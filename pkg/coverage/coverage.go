// Package coverage proves that a generated conformance ledger accounts for an
// expected corpus exactly once.
package coverage

import (
	"fmt"
	"sort"
)

// Report is an exact set comparison between expected and observed IDs.
type Report struct {
	Expected   int
	Covered    int
	Missing    []string
	Duplicates []string
	Unknown    []string
}

// Percent returns the fraction of expected IDs covered exactly once.
func (r Report) Percent() float64 {
	if r.Expected == 0 {
		return 100
	}
	return 100 * float64(r.Covered) / float64(r.Expected)
}

// Complete reports whether every expected ID appears exactly once and no
// unknown IDs appear.
func (r Report) Complete() bool {
	return len(r.Missing) == 0 && len(r.Duplicates) == 0 && len(r.Unknown) == 0
}

// Error explains an incomplete report and returns nil for complete coverage.
func (r Report) Error() error {
	if r.Complete() {
		return nil
	}
	return fmt.Errorf("encoding coverage %.2f%% (%d/%d): missing=%v duplicates=%v unknown=%v",
		r.Percent(), r.Covered, r.Expected, r.Missing, r.Duplicates, r.Unknown)
}

// Analyze compares expected and observed encoding IDs as sets while retaining
// duplicate observations as a separate error class.
func Analyze(expected, observed []string) Report {
	want := make(map[string]struct{}, len(expected))
	for _, id := range expected {
		want[id] = struct{}{}
	}
	counts := make(map[string]int, len(observed))
	for _, id := range observed {
		counts[id]++
	}

	report := Report{Expected: len(want)}
	for id := range want {
		switch counts[id] {
		case 0:
			report.Missing = append(report.Missing, id)
		case 1:
			report.Covered++
		default:
			report.Covered++
			report.Duplicates = append(report.Duplicates, id)
		}
	}
	for id := range counts {
		if _, ok := want[id]; !ok {
			report.Unknown = append(report.Unknown, id)
		}
	}
	sort.Strings(report.Missing)
	sort.Strings(report.Duplicates)
	sort.Strings(report.Unknown)
	return report
}

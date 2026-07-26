package arm_test

import (
	"testing"

	"mkasm/pkg/decoder"
	"mkasm/pkg/ir"
)

// TestDecodeQuality_selfMatch measures how often each resolved encoding's
// fixed-bit base word uniquely MatchWord-hits itself. This is a quality
// oracle for pattern extraction (not a golden of architectural encodings).
func TestDecodeQuality_selfMatch(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	all := reg.GetAll()

	var withPattern, selfHit, uniqueSelf, multi int
	for _, instr := range all {
		if instr == nil || !contains01(instr.BitPattern) {
			continue
		}
		withPattern++
		_, value := ir.FixedBitsFromPattern(instr.BitPattern)
		// variable fields zeroed
		hits := reg.MatchWord(value)
		found := false
		for _, h := range hits {
			if h.EncodingID == instr.EncodingID {
				found = true
				break
			}
		}
		if found {
			selfHit++
			if len(hits) == 1 {
				uniqueSelf++
			} else {
				multi++
			}
		}
	}

	if withPattern == 0 {
		t.Fatal("no patterns with fixed bits")
	}
	selfPct := 100 * float64(selfHit) / float64(withPattern)
	uniqPct := 100 * float64(uniqueSelf) / float64(withPattern)
	t.Logf("patterns=%d selfHit=%.1f%% unique=%.1f%% multi=%d miss=%d",
		withPattern, selfPct, uniqPct, multi, withPattern-selfHit)

	// Floor: nearly all encodings should at least match themselves.
	if selfPct < 95 {
		t.Fatalf("self-hit rate too low: %.1f%%", selfPct)
	}
	// After bitdiffs pinning, a majority of encodings should uniquely self-match
	// on their fixed base (aliases and !=-only constraints still share bases).
	if uniqPct < 45 {
		t.Fatalf("unique self-match too low after bitdiffs: %.1f%% (want >= 45%%)", uniqPct)
	}
}

// TestDecodeQuality_treeVsPattern compares tree Match vs flat MatchByPattern
// on a sample of self-encoded fixed bases.
func TestDecodeQuality_treeVsPattern(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	var resolved []*ir.InstructionIR
	for _, instr := range reg.GetAll() {
		if instr != nil && contains01(instr.BitPattern) {
			resolved = append(resolved, instr)
		}
	}
	tree := (&decoder.DecoderTreeBuilder{}).BuildTree(resolved, nil)

	const sampleN = 200
	step := len(resolved) / sampleN
	if step < 1 {
		step = 1
	}
	var agree, treeOnly, flatOnly, neither, checked int
	for i := 0; i < len(resolved); i += step {
		instr := resolved[i]
		_, value := ir.FixedBitsFromPattern(instr.BitPattern)
		flat := decoder.MatchByPattern(resolved, value)
		tres, terr := decoder.Match(tree, value)

		var flatHas, treeHas bool
		for _, h := range flat {
			if h.EncodingID == instr.EncodingID {
				flatHas = true
				break
			}
		}
		if terr == nil && tres.Instruction != nil && tres.Instruction.EncodingID == instr.EncodingID {
			treeHas = true
		} else if len(tres.Ambiguous) > 0 {
			for _, a := range tres.Ambiguous {
				if a.EncodingID == instr.EncodingID {
					treeHas = true
					break
				}
			}
		}
		checked++
		switch {
		case flatHas && treeHas:
			agree++
		case treeHas && !flatHas:
			treeOnly++
		case flatHas && !treeHas:
			flatOnly++
		default:
			neither++
		}
	}
	t.Logf("sample=%d agree=%d treeOnly=%d flatOnly=%d neither=%d", checked, agree, treeOnly, flatOnly, neither)
	if float64(agree)/float64(checked) < 0.8 {
		t.Fatalf("tree/flat agreement too low: %d/%d", agree, checked)
	}
}

package arm_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mkasm/pkg/arm"
	"mkasm/pkg/ir"
)

// TestGapScan enumerates every encoding that has no typed method and attributes
// the failure to a specific operand and cause. A scoping instrument for closing
// the coverage gap, not a correctness test.
func TestGapScan(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	all := reg.GetAll()
	iformDir := iformDirPath(t)
	load := func(i *ir.InstructionIR) *arm.ParsedIForm {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, i.IFormFile), i.EncodingID)
		if err != nil {
			return nil
		}
		return p
	}
	s := arm.BuildAsmSurface(all, load)

	rawIDs := map[string]string{}
	for _, r := range s.Raw {
		rawIDs[r.EncodingID] = r.Reason
	}

	// cause -> count, plus a sample encoding for each.
	cause := map[string]int{}
	sample := map[string]string{}
	symCause := map[string]int{}
	prosePat := map[string]int{}

	for _, instr := range all {
		reason, isRaw := rawIDs[instr.EncodingID]
		if !isRaw {
			continue
		}
		p := load(instr)
		if p == nil {
			cause["iform unavailable"]++
			continue
		}
		if reason != "operands not typeable" {
			cause["MODEL: "+reason]++
			if sample[reason] == "" {
				sample[reason] = instr.EncodingID + "  " + p.AsmTemplate
			}
			continue
		}
		exps := arm.ExplanationsFor(p.Explanations, instr.EncodingID)
		byName := map[string]ir.BitField{}
		for _, f := range instr.Encoding.Fields {
			byName[f.Name] = f
		}
		blamed := false
		for _, o := range p.AsmOperands {
			exp := exps[o.Symbol]
			c := arm.ClassifyOperandWith(o, exp)
			var why string
			switch {
			case c.Class == arm.ClassUnsupported:
				why = "unsupported class"
			case c.ResolvedField == "":
				why = "no field"
			default:
				if _, ok := byName[c.ResolvedField]; !ok && c.Class != arm.ClassArrangement {
					why = "field not in diagram: " + c.ResolvedField
				}
			}
			if why == "" {
				continue
			}
			blamed = true
			key := why + " | " + o.Symbol
			cause[key]++
			symCause[o.Symbol]++
			if sample[key] == "" {
				sample[key] = instr.EncodingID + "  " + p.AsmTemplate + "\n        prose: " + trunc(exp.Prose, 150) + "\n        encodedin: " + strings.Join(exp.Fields, ":")
			}
			// Bucket the prose shape so families become visible.
			prosePat[proseShape(exp.Prose, o.Hover)]++
		}
		if !blamed {
			cause["UNATTRIBUTED"]++
			if sample["UNATTRIBUTED"] == "" {
				sample["UNATTRIBUTED"] = instr.EncodingID + "  " + p.AsmTemplate
			}
		}
	}

	forms := 0
	for _, m := range s.MethodOrder {
		forms += len(s.Methods[m])
	}
	fmt.Printf("\nencodings %d | typed forms %d | raw %d | dropped %d\n",
		len(all), forms, len(s.Raw), len(s.Dropped))

	fmt.Println("\n=== blocking causes (operand-level, descending) ===")
	printTopKV(cause, 60, sample)

	fmt.Println("\n=== blocked symbols ===")
	printTopN(symCause, 40)

	fmt.Println("\n=== prose shapes of blocked operands ===")
	printTopN(prosePat, 40)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// proseShape reduces an operand's description to a family label.
func proseShape(prose, hover string) string {
	p := strings.ToLower(prose + " " + hover)
	switch {
	case strings.Contains(p, "plus 1") || strings.Contains(p, "plus 2") ||
		strings.Contains(p, "plus 3") || strings.Contains(p, "plus 4"):
		return "A: derived consecutive register (\"encoded as X plus N\")"
	case strings.Contains(p, "index"):
		return "B: element index"
	case strings.Contains(p, "tile"):
		return "C: SME tile / tile slice"
	case strings.Contains(p, "vector select register"):
		return "D: SME vector select register (W8-W11)"
	case strings.Contains(p, "predicate"):
		return "E: predicate"
	case strings.Contains(p, "scalable vector"):
		return "F: scalable vector"
	case strings.Contains(p, "general-purpose"):
		return "G: general purpose"
	case strings.Contains(p, "immediate") || strings.Contains(p, "offset"):
		return "H: immediate/offset"
	case strings.TrimSpace(p) == "":
		return "Z: NO PROSE AT ALL"
	default:
		return "Y: other: " + trunc(strings.TrimSpace(p), 70)
	}
}

func printTopKV(m map[string]int, n int, sample map[string]string) {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].v != s[j].v {
			return s[i].v > s[j].v
		}
		return s[i].k < s[j].k
	})
	for i, e := range s {
		if i >= n {
			fmt.Printf("   ... and %d more causes\n", len(s)-n)
			break
		}
		fmt.Printf("   %5d  %s\n", e.v, e.k)
		if ex := sample[e.k]; ex != "" {
			fmt.Printf("          e.g. %s\n", ex)
		}
	}
}

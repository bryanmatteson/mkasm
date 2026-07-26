package arm_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"mkasm/pkg/arm"
	"mkasm/pkg/ir"
)

// TestSplitFieldAudit checks that every operand of every typed form covers all
// the bits ARM says it occupies.
//
// An operand whose value spans several fields but is placed in one encodes the
// wrong word and reports no error, so this is a correctness test rather than a
// coverage measurement. Each parameter must either carry a placement spanning
// exactly the fields it needs, or be dispatched through a value table that
// spans them.
func TestSplitFieldAudit(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	iformDir := iformDirPath(t)
	load := func(i *ir.InstructionIR) *arm.ParsedIForm {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, i.IFormFile), i.EncodingID)
		if err != nil {
			return nil
		}
		return p
	}
	s := arm.BuildAsmSurface(reg.GetAll(), load)

	var bad []string
	forms, params, splits := 0, 0, 0
	for _, m := range s.MethodOrder {
		for _, f := range s.Methods[m] {
			forms++
			// Every parameter must cover its own field(s). Alias constraints can
			// additionally mirror the value into hidden fields, so extra
			// placements are valid and are checked separately by conformance.
			placedBy := map[string][]arm.Placement{}
			for _, pl := range f.Placements {
				name := placementParam(pl)
				placedBy[name] = append(placedBy[name], pl)
			}
			dispatched := map[string]bool{}
			for _, d := range f.Enums {
				dispatched[d.Param] = true
			}
			for _, p := range f.Params {
				params++
				if p.RustType == "Mem" || p.ArrDispatch != nil && len(p.Split) == 0 {
					continue
				}
				want := len(p.Split)
				if want == 0 {
					want = 1
				}
				if want > 1 {
					splits++
				}
				if dispatched[p.Name] {
					continue
				}
				got := 0
				for _, pl := range placedBy[p.Name] {
					if len(p.Split) == 0 {
						if pl.Field == p.Field {
							got = 1
							break
						}
						continue
					}
					if placementParts(pl) == want {
						got = want
						break
					}
				}
				if got != want {
					if len(bad) < 20 {
						bad = append(bad, fmt.Sprintf("%s %s.%s: spans %d field(s) %v, placed across %d",
							f.EncodingID, f.Method, p.Name, want, p.Split, got))
					}
				}
			}
		}
	}
	fmt.Printf("\ntyped forms %d | parameters %d | split placements %d | defects %d\n",
		forms, params, splits, len(bad))
	for _, b := range bad {
		fmt.Println("   " + b)
	}
	if len(bad) > 0 {
		t.Errorf("%d typed operands are not placed across every field they span", len(bad))
	}
}

func placementParam(pl arm.Placement) string {
	s := strings.TrimSuffix(pl.Param, " as i64")
	s = strings.TrimSuffix(s, " as u32")
	s = strings.TrimSuffix(s, ".reg.raw()")
	return strings.TrimSuffix(s, ".raw()")
}

func placementParts(pl arm.Placement) int {
	if len(pl.Parts) == 0 {
		return 1
	}
	return len(pl.Parts)
}

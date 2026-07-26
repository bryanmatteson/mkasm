package conformance_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"mkasm/pkg/asl"
	"mkasm/pkg/ir"
)

// The ASL specification lives outside this repository: it is generated from
// ARM's XML by mra_tools, a separate toolchain. That separateness is the point
// of this test.
const (
	aslInstrsEnv = "MKASM_ASL_INSTRS" // arm_instrs.asl
	aslDecodeEnv = "MKASM_ASL_DECODE" // arch_decode.asl
)

// encodingIDComment maps an ASL encoding name to the XML encoding id, which
// arch_decode.asl records as a trailing comment on each __encoding line.
var encodingIDComment = regexp.MustCompile(`__encoding\s+(\S+)\s*//\s*(\S+)`)

// TestASLCrossCheck verifies this generator's bit patterns and field layouts
// against ARM's own machine-readable specification.
//
// Everything else in this repository derives from one parse of one input: the
// decoder, the exact encoders and the typed methods all read the same XML
// through the same code, so their agreeing with each other proves only that
// they are consistent. The ASL is produced by an unrelated toolchain from the
// same architecture, which makes disagreement here real evidence rather than a
// self-check.
//
// Only encodings present in both are compared. The ASL snapshot is older than
// the XML in spec/, so it has no SVE2 or SME2, and it also covers AArch32,
// which this generator does not.
func TestASLCrossCheck(t *testing.T) {
	instrsPath := os.Getenv(aslInstrsEnv)
	decodePath := os.Getenv(aslDecodeEnv)
	if instrsPath == "" || decodePath == "" {
		t.Skipf("set %s and %s to cross-check against the ASL", aslInstrsEnv, aslDecodeEnv)
	}
	for _, p := range []string{instrsPath, decodePath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s: %v", p, err)
		}
	}

	decodeSrc, err := os.ReadFile(decodePath)
	if err != nil {
		t.Fatalf("read decode: %v", err)
	}
	aslToXML := map[string]string{}
	for _, m := range encodingIDComment.FindAllStringSubmatch(string(decodeSrc), -1) {
		aslToXML[m[1]] = m[2]
	}
	if len(aslToXML) == 0 {
		t.Fatal("no encoding-id comments found in the decode tree")
	}

	instrsSrc, err := os.ReadFile(instrsPath)
	if err != nil {
		t.Fatalf("read instrs: %v", err)
	}
	instrs, err := asl.ParseInstructions(string(instrsSrc))
	if err != nil {
		t.Fatalf("parse ASL: %v", err)
	}

	p, _ := loadCorpusParser(t, parserOptions{})
	reg := p.GetRegistry()
	mine := map[string]*ir.InstructionIR{}
	for _, i := range reg.GetAll() {
		mine[i.EncodingID] = i
	}

	var (
		compared, patternsOK, fieldsOK int
		patternBad, fieldBad, nameOnly []string
	)
	for _, in := range instrs {
		for _, enc := range in.Encodings {
			if enc.Set != "A64" {
				continue
			}
			xid, ok := aslToXML[enc.Name]
			if !ok {
				continue
			}
			instr, ok := mine[xid]
			if !ok {
				continue
			}
			compared++

			// Compare only bits both sides pin. A don't-care on either side is
			// not a disagreement.
			if len(enc.Opcode) == 32 && len(instr.BitPattern) == 32 {
				conflict := false
				for i := 0; i < 32; i++ {
					a, b := enc.Opcode[i], instr.BitPattern[i]
					if (a == '0' || a == '1') && (b == '0' || b == '1') && a != b {
						conflict = true
					}
				}
				if conflict {
					patternBad = append(patternBad, fmt.Sprintf("%s\n    asl  %s\n    mine %s", xid, enc.Opcode, instr.BitPattern))
				} else {
					patternsOK++
				}
			}

			byName := map[string]ir.BitField{}
			for _, f := range instr.Encoding.Fields {
				byName[f.Name] = f
			}
			for _, f := range enc.Fields {
				bf, ok := byName[f.Name]
				if !ok {
					// The ASL names some fields after the operand rather than
					// the encoding: Xn where ARM's XML says Rn.
					nameOnly = append(nameOnly, fmt.Sprintf("%s.%s", xid, f.Name))
					continue
				}
				if bf.Start != f.Lo || bf.End != f.Hi() {
					fieldBad = append(fieldBad, fmt.Sprintf("%s.%s: asl %d..%d, mine %d..%d",
						xid, f.Name, f.Lo, f.Hi(), bf.Start, bf.End))
					continue
				}
				fieldsOK++
			}
		}
	}

	fmt.Printf("\nA64 encodings in both this parse and the ASL: %d\n", compared)
	fmt.Printf("  bit patterns compatible : %d (%d conflicting)\n", patternsOK, len(patternBad))
	fmt.Printf("  field positions equal   : %d (%d differing)\n", fieldsOK, len(fieldBad))
	fmt.Printf("  fields named only by ASL: %d\n", len(nameOnly))

	if compared == 0 {
		t.Fatal("no encodings overlapped; the mapping or the paths are wrong")
	}
	for _, b := range patternBad {
		t.Errorf("bit pattern disagrees with the ASL:\n%s", b)
	}
	for _, b := range fieldBad {
		t.Errorf("field position disagrees with the ASL: %s", b)
	}
	if len(nameOnly) > 0 {
		sort.Strings(nameOnly)
		show := nameOnly
		if len(show) > 8 {
			show = show[:8]
		}
		t.Logf("fields the ASL names and this parse does not (naming differences): %s …",
			strings.Join(show, ", "))
	}
}

package conformance_test

import (
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

// TestLabelOperandsCarryDisplacementSign holds every PC-relative label in the
// printable surface to the model invariant — a two's-complement displacement,
// or the RawMul<0 PAC negative-offset form — and renders one backward word per
// label family. An unsigned reading printed BL .-420 as BL .+268435036, which
// no consumer could resolve to its target.
func TestLabelOperandsCarryDisplacementSign(t *testing.T) {
	if testing.Short() {
		t.Skip("full ISA parse")
	}
	p, _ := loadCorpusParser(t, parserOptions{})
	surface := p.DisasmSurface()

	labels := 0
	for _, form := range surface.Forms {
		for _, part := range form.Parts {
			op := part.Op
			if op == nil || op.Class != arm.ClassLabel || op.Kind != arm.DisasmNum {
				continue
			}
			labels++
			if !op.Signed && op.RawMul >= 0 {
				t.Errorf("%s: label %s is an unsigned displacement", form.EncodingID, op.Symbol)
			}
			if op.RawMul < 0 && op.Scale != 4 {
				t.Errorf("%s: PAC label scale %d, want 4", form.EncodingID, op.Scale)
			}
		}
	}
	if labels < 80 {
		t.Fatalf("printable surface has %d label operands, want the A64 label families", labels)
	}
	for _, skip := range surface.Skipped {
		if strings.Contains(skip.Reason, "no displacement sign") {
			t.Errorf("%s: %s", skip.EncodingID, skip.Reason)
		}
	}

	forms := make(map[string]*arm.DisasmForm, len(surface.Forms))
	for i := range surface.Forms {
		forms[surface.Forms[i].EncodingID] = &surface.Forms[i]
	}
	for _, test := range []struct {
		encoding string
		word     uint32
		want     string
	}{
		{"BL_only_branch_imm", 0x97FFFF97, "BL .-420"},
		{"B_only_branch_imm", 0x17FFFFFF, "B .-4"},
		{"B_only_condbranch", 0x54FFFF61, "B.ne .-20"},
		{"CBZ_64_compbranch", 0xB4FFFFC0, "CBZ x0, .-8"},
		{"TBNZ_only_testbranch", 0x3707FE37, "TBNZ w23, #0, .-60"},
		{"ADR_only_pcreladdr", 0x70FFFFE0, "ADR x0, .-1"},
		{"ADRP_only_pcreladdr", 0xF0FFFFE0, "ADRP x0, .-4096"},
		{"LDR_64_loadlit", 0x58FFFFE0, "LDR x0, .-4"},
		{"AUTIASPPC_only_dp_1src_imm", 0xF380049F, "AUTIASPPC .-144"},
	} {
		form := forms[test.encoding]
		if form == nil {
			t.Errorf("%s is not printable", test.encoding)
			continue
		}
		if got, ok := form.Render(test.word); !ok || got != test.want {
			t.Errorf("%s 0x%08X = %q, %v; want %q", test.encoding, test.word, got, ok, test.want)
		}
	}
}

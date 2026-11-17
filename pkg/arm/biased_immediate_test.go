package arm

import (
	"strconv"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestBiasedSignedImmediateUsesUnsignedEncodedField(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<imms1>", Link: "imms1_cbr", Field: "imm6", Prefix: "#",
		Hover: `Is a signed immediate, in the range -1 to 62, encoded as "imm6" minus 1.`,
	})
	fields := map[string]ir.BitField{"imm6": {Name: "imm6", Start: 15, End: 20}}
	op, err := disasmOperand(c, fields, 0)
	if err != nil {
		t.Fatal(err)
	}
	if op.Signed || op.Bias != -1 {
		t.Fatalf("encoded field: signed=%v bias=%d", op.Signed, op.Bias)
	}
	for raw := uint32(0); raw < 64; raw++ {
		got, ok := op.Render(raw << 15)
		want := strconv.Itoa(int(raw) - 1)
		if !ok || got != want {
			t.Fatalf("raw=%d: render=%q,%v want=%q", raw, got, ok, want)
		}
	}
	prm := Param{Name: "imms1", Class: ClassImm, Field: "imm6", Bias: -1, Lo: -1, Hi: 62, HasRange: true, Scale: 1}
	pl, err := placementFor(&prm, "imms1", fields, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pl.Signed || pl.Bias != -1 {
		t.Fatalf("assembly placement: signed=%v bias=%d", pl.Signed, pl.Bias)
	}
	for _, tc := range []struct {
		lo, bias, scale int64
		want            bool
	}{
		{-1, -1, 1, false}, {-4, -1, 4, false}, {-128, -1, 1, true}, {-1024, 0, 4, true}, {0, 0, 1, false},
	} {
		if got := numericFieldSigned(tc.lo, tc.bias, tc.scale); got != tc.want {
			t.Errorf("signed(%d,%d,%d)=%v want=%v", tc.lo, tc.bias, tc.scale, got, tc.want)
		}
	}
}

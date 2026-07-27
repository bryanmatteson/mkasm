package arm

import (
	"os"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestParseBitDiffs_basic(t *testing.T) {
	tree, err := ParseBitDiffs("cc == 110")
	if err != nil {
		t.Fatal(err)
	}
	if tree == nil || tree.Atom == nil || tree.Atom.Field != "cc" || tree.Atom.Bits != "110" {
		t.Fatalf("%+v", tree)
	}
}

func TestParseBitDiffs_andPartial(t *testing.T) {
	tree, err := ParseBitDiffs("Q == 1 && imm5 == x1000")
	if err != nil {
		t.Fatal(err)
	}
	if tree.Kind != ir.BitDiffAnd || len(tree.Kids) != 2 {
		t.Fatalf("%+v", tree)
	}
}

func TestParseBitDiffs_neAndIn(t *testing.T) {
	tree, err := ParseBitDiffs("Rm != 11111 && opcode == 000")
	if err != nil {
		t.Fatal(err)
	}
	if tree.Kind != ir.BitDiffAnd {
		t.Fatalf("kind=%v", tree.Kind)
	}
	tree2, err := ParseBitDiffs("!(op1 == '000' && op2 IN {'00x', '010'})")
	if err != nil {
		t.Fatal(err)
	}
	if tree2.Kind != ir.BitDiffNot {
		t.Fatalf("kind=%v", tree2.Kind)
	}
}

func TestApplyBitDiffs_CBBEQ(t *testing.T) {
	path := filepathJoinISA(t, "cbbcc_regs.xml")
	parsed, err := ParseIFormFile(path, "CBBEQ_8_regs")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.BitDiffs != "cc == 110" {
		t.Fatalf("bitdiffs=%q", parsed.BitDiffs)
	}
	instr := &ir.InstructionIR{EncodingID: "CBBEQ_8_regs", Mnemonic: "CBBEQ"}
	ApplyParsedIForm(instr, parsed)
	if instr.BitDiffsTree == nil {
		t.Fatal("missing BitDiffsTree")
	}
	mask, value := ir.FixedBitsFromPattern(instr.BitPattern)
	if mask&(7<<21) != 7<<21 {
		t.Fatalf("cc not pinned in pattern %s mask=%08x", instr.BitPattern, mask)
	}
	if (value>>21)&7 != 0b110 {
		t.Fatalf("cc value=%03b pat=%s", (value>>21)&7, instr.BitPattern)
	}
	w, ok := ir.FixedWord(instr)
	if !ok {
		t.Fatal("no FixedWord")
	}
	ge, err := ParseIFormFile(path, "CBBGE_8_regs")
	if err != nil {
		t.Fatal(err)
	}
	geInstr := &ir.InstructionIR{EncodingID: "CBBGE_8_regs"}
	ApplyParsedIForm(geInstr, ge)
	gw, _ := ir.FixedWord(geInstr)
	if w == gw {
		t.Fatalf("CBBEQ and CBBGE share FixedWord 0x%08X after bitdiffs", w)
	}
	if !ir.MatchWord(instr, w) {
		t.Fatal("self mismatch")
	}
	if ir.MatchWord(geInstr, w) {
		t.Fatal("CBBGE should not match CBBEQ fixed word")
	}
}

func TestApplyBitDiffs_SF(t *testing.T) {
	path := filepathJoinISA(t, "smin_reg.xml")
	p0, err := ParseIFormFile(path, "SMIN_32_dp_2src")
	if err != nil {
		t.Fatal(err)
	}
	p1, err := ParseIFormFile(path, "SMIN_64_dp_2src")
	if err != nil {
		t.Fatal(err)
	}
	i0 := &ir.InstructionIR{EncodingID: "SMIN_32_dp_2src"}
	i1 := &ir.InstructionIR{EncodingID: "SMIN_64_dp_2src"}
	ApplyParsedIForm(i0, p0)
	ApplyParsedIForm(i1, p1)
	w0, _ := ir.FixedWord(i0)
	w1, _ := ir.FixedWord(i1)
	if w0 == w1 {
		t.Fatalf("sf bitdiffs not applied: both 0x%08X", w0)
	}
	if (w0>>31)&1 != 0 || (w1>>31)&1 != 1 {
		t.Fatalf("sf pins: 32=0x%08X 64=0x%08X", w0, w1)
	}
}

func TestAlias_NGC(t *testing.T) {
	path := filepathJoinISA(t, "ngc_sbc.xml")
	p, err := ParseIFormFile(path, "NGC_SBC_32_addsub_carry")
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAlias {
		t.Fatal("expected alias section")
	}
	if p.AliasOf != "SBC_32_addsub_carry" {
		t.Fatalf("AliasOf=%q", p.AliasOf)
	}
	instr := &ir.InstructionIR{EncodingID: "NGC_SBC_32_addsub_carry"}
	ApplyParsedIForm(instr, p)
	if instr.AliasOf != "SBC_32_addsub_carry" {
		t.Fatalf("instr.AliasOf=%q", instr.AliasOf)
	}
}

func filepathJoinISA(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{
		"spec/ISA/" + name,
		"../spec/ISA/" + name,
		"../../spec/ISA/" + name,
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 100 {
			return p
		}
	}
	t.Skip(name + " not available")
	return ""
}

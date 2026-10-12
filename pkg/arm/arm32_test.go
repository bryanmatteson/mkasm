package arm

import (
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestARM32InstructionStateAndStatelessThumbSpelling(t *testing.T) {
	page := `<instructionsection><classes><iclass isa="T32"><regdiagram form="16"><box hibit="15" width="5"><c colspan="5">00110</c></box><box name="Rdn" hibit="10" width="3"><c colspan="3"/></box><box name="imm8" hibit="7" width="8"><c colspan="8"/></box></regdiagram><encoding name="ADD_i_T2"><asmtemplate comment="InITBlock()"><text>ADD</text><a link="c">&lt;c&gt;</a><text> </text><a hover="encoded in the &quot;Rdn&quot; field">&lt;Rdn&gt;</a><text>, #</text><a>&lt;imm8&gt;</a></asmtemplate><asmtemplate comment="Outside IT block, and representable"><text>ADDS </text><a hover="encoded in the &quot;Rdn&quot; field">&lt;Rdn&gt;</a><text>, #</text><a>&lt;imm8&gt;</a></asmtemplate></encoding></iclass></classes></instructionsection>`
	p, err := parseIForm(strings.NewReader(page), "ADD_i_T2")
	if err != nil {
		t.Fatal(err)
	}
	instr := &ir.InstructionIR{EncodingID: "ADD_i_T2"}
	ApplyParsedIForm(instr, p)
	if instr.InstructionSet != "T32" || instr.Encoding.Width != 16 || instr.Asm.Raw != "ADDS <Rdn>, #<imm8>" {
		t.Fatalf("wrong instruction state or syntax: %#v", instr)
	}
	if got := BuildCatalog([]*ir.InstructionIR{instr}).Entries[0]; got.Mask != 0xf800 || got.Value != 0x3000 {
		t.Fatalf("16-bit word moved into wrong halfword: %#v", got)
	}
}

func TestARM32SplitOperandsAndScaling(t *testing.T) {
	fields := []CatalogField{{Name: "D", Start: 22, End: 22}, {Name: "Vd", Start: 12, End: 15}}
	bits, width, ok := arm32Slices([]string{"D", "Vd"}, fields)
	if !ok || width != 5 || !strings.Contains(bits, "lo: 22, width: 1") || !strings.Contains(bits, "lo: 12, width: 4") {
		t.Fatalf("incorrect split SIMD register: %s %d %v", bits, width, ok)
	}
	if _, _, ok := arm32Slices([]string{"Vd[4]"}, fields); ok {
		t.Fatal("accepted out-of-range selector")
	}
	p := &ParsedIForm{InstructionSet: "T32", Width: 16, AsmOperands: []AsmOperand{{Symbol: "<imm>", Prefix: ", #"}}, Explanations: []AsmExplanation{{Symbol: "<imm>", Fields: []string{"imm5"}, Prose: `encoded as <imm>/4.`}}}
	f, err := arm32PrintForm(CatalogEntry{EncodingID: "LDR_i_T1", Fields: []CatalogField{{Name: "imm5", Start: 6, End: 10}}}, p)
	if err != nil || !strings.Contains(f, "scale: 4") {
		t.Fatalf("scaled load displacement: %s %v", f, err)
	}
}

func TestARM32ArchitectureAliases(t *testing.T) {
	for _, name := range []string{"arm32", "arm", "a32", "aarch32", "thumb", "thumb2", "t32"} {
		a, err := ParseArch(name)
		if err != nil || a != ArchARM32 {
			t.Fatalf("%s: %s %v", name, a, err)
		}
	}
	if !isEncodingIndex("a32_encindex.xml") || !isEncodingIndex("t32_encindex.xml") {
		t.Fatal("AArch32 indexes are not retained by the archive loader")
	}
}

func TestARM32AllocationConstraintsUseOnlyPresentOperands(t *testing.T) {
	p := &ParsedIForm{EncodingName: "VMOV", InstructionSet: "A32", Width: 32,
		Boxes:        []RegBox{{HiBit: 31, Width: 1, Bits: "0"}, {Name: "size", HiBit: 1, Width: 2, Bits: "--"}},
		AsmOperands:  []AsmOperand{{Symbol: "<imm>"}},
		Explanations: []AsmExplanation{{Symbol: "<dt>", Fields: []string{"size"}, Values: []SymbolValue{{Bits: []string{"10"}, Symbol: "i32"}}}},
	}
	apply := func() *ir.InstructionIR {
		i := &ir.InstructionIR{EncodingID: "VMOV"}
		ApplyParsedIForm(i, p)
		return i
	}
	if i := apply(); !ir.MatchWord(i, 0) {
		t.Fatal("an unused explanation from another variant constrained the encoding")
	}
	p.AsmOperands = append(p.AsmOperands, AsmOperand{Symbol: "<dt>"})
	if i := apply(); ir.MatchWord(i, 0) || !ir.MatchWord(i, 2) {
		t.Fatal("datatype allocation table did not constrain its actual operand")
	}
	p.Pseudocode = []string{"if size == '10' || size == '11' then Undefined(); end;"}
	if ir.MatchWord(apply(), 2) {
		t.Fatal("undefined encoding passed a disjunctive decode guard")
	}
}

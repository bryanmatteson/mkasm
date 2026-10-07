package arm

import (
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestDisasmOperandInfersRestrictedRegisterBias(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<Ws>",
		Link:   "Ws__3",
		Hover:  `Is the 32-bit name of the slice index register W12-W15, encoded in the "Rs" field.`,
		Field:  "Rs",
	})
	if c.Class != ClassGpr32 || !c.HasRegRange || c.RegLo != 12 || c.RegHi != 15 {
		t.Fatalf("classification = class %s range %d..%d present=%v", c.Class, c.RegLo, c.RegHi, c.HasRegRange)
	}
	op, err := disasmOperand(c, map[string]ir.BitField{
		"Rs": {Name: "Rs", Start: 13, End: 14},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if op.Bias != 12 {
		t.Fatalf("bias = %d, want 12", op.Bias)
	}
	if got, ok := op.Render(0); !ok || got != "w12" {
		t.Fatalf("render = %q, %v; want w12, true", got, ok)
	}
}

func TestClassifyScaledFieldDivision(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<shift>",
		Link:   "shift",
		Hover:  `Is the shift amount, encoded in the "hw" field as <shift>/16.`,
		Field:  "hw",
	})
	if c.Scale != 16 {
		t.Fatalf("scale = %d, want 16", c.Scale)
	}
}

func TestClassifyCryptoVaAsRegister(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<Va>",
		Link:   "Va",
		Hover:  `Is the name of the third SIMD&FP source register, encoded in the "Ra" field.`,
		Field:  "Ra",
	})
	if c.Class != ClassSimdVec {
		t.Fatalf("class = %s, want %s", c.Class, ClassSimdVec)
	}
}

func TestClassifyRegisterFieldSlice(t *testing.T) {
	c := ClassifyOperandWith(AsmOperand{
		Symbol: "<Vm>",
		Hover:  `Is the second SIMD&FP source register V0-V7, encoded in the "Rm<2:0>" field.`,
	}, AsmExplanation{Fields: []string{"Rm"}})
	if c.ResolvedField != "Rm<2:0>" || len(c.Fields) != 1 || c.Fields[0] != "Rm<2:0>" {
		t.Fatalf("field slice = resolved %q fields %v", c.ResolvedField, c.Fields)
	}
	if !c.HasRegRange || c.RegLo != 0 || c.RegHi != 7 {
		t.Fatalf("register range = %d..%d present=%v", c.RegLo, c.RegHi, c.HasRegRange)
	}
}

func TestClassifyNamedImmFieldWithoutImmediateNoun(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<imm6>",
		Link:   "imm6",
		Hover:  `Is a rotation right, encoded in "imm6".`,
		Field:  "imm6",
	})
	if c.Class != ClassImm {
		t.Fatalf("class = %s, want %s", c.Class, ClassImm)
	}
}

func TestDisasmImmediateCarriesDocumentedHashPrefix(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<amount>",
		Link:   "amount",
		Prefix: " ",
		Hover:  `Is the index shift amount, it must be #0, encoded in "S" as 0 if omitted, or as 1 if present.`,
		Field:  "S",
	})
	op, err := disasmOperand(c, map[string]ir.BitField{
		"S": {Name: "S", Start: 12, End: 12},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := op.Render(0); !ok || got != "#0" {
		t.Fatalf("render = %q, %v; want #0, true", got, ok)
	}
	if got, ok := op.Render(1 << 12); !ok || got != "#0" {
		t.Fatalf("present render = %q, %v; want #0, true", got, ok)
	}
}

func TestDisasmFormEnforcesAliasEquality(t *testing.T) {
	f := DisasmForm{
		EqualFields: []DisasmFieldEquality{{
			LeftStart: 5, LeftEnd: 9, RightStart: 16, RightEnd: 20,
		}},
	}
	if _, ok := f.Render(1 << 5); ok {
		t.Fatal("rendered a word that violates the alias equality")
	}
	got, ok := f.SatisfyConstraints(3 << 5)
	if !ok || fieldValue(got, 16, 20) != 3 {
		t.Fatalf("satisfied word = 0x%08X, %v", got, ok)
	}
}

func TestDisasmFormEnforcesOneHotAlias(t *testing.T) {
	form := DisasmForm{OneHotMasks: []uint32{0x0f}}
	if _, ok := form.Render(0x03); ok {
		t.Fatal("rendered a word that violates one-hot alias selection")
	}
	word, ok := form.SatisfyConstraints(0x03)
	if !ok || word&0x0f != 1 {
		t.Fatalf("satisfied word = 0x%08X, %v; want low nibble 1", word, ok)
	}
}

func TestSingleFieldBitCountAliasConstraint(t *testing.T) {
	form := DisasmForm{}
	fields := map[string]ir.BitField{"immh": {Name: "immh", Start: 19, End: 22}}
	if err := addDisasmAliasConstraints(&form, "BitCount(immh) == 1", fields); err != nil {
		t.Fatal(err)
	}
	if len(form.OneHotMasks) != 1 || form.OneHotMasks[0] != 0x00780000 {
		t.Fatalf("one-hot masks = %#v", form.OneHotMasks)
	}
}

func TestParentOptionalGroupKeepsNonDefaultChild(t *testing.T) {
	form := DisasmForm{
		GroupParent: map[int]int{2: 1},
		Parts: []DisasmPart{
			{Group: 1, Op: &DisasmOperand{
				Kind: DisasmTable, HasDefault: true, Default: 0,
				Cols: []BitPart{{Start: 1, End: 1, Width: 1}},
				Rows: bitTable(1, "LSL", "UXTW"),
			}},
			{Group: 2, Op: &DisasmOperand{
				Kind: DisasmNum, HasDefault: true, Default: 0,
				Parts: []BitPart{{Start: 0, End: 0, Width: 1}},
			}},
		},
	}
	if form.groupOmitted(1, 1) {
		t.Fatal("parent group omitted despite non-default nested amount")
	}
}

func TestDisasmFormulaRows(t *testing.T) {
	fields := map[string]ir.BitField{
		"immh": {Name: "immh", Start: 19, End: 22},
		"immb": {Name: "immb", Start: 16, End: 18},
	}
	formula, err := compileDisasmFormula("32 - UInt(immh :: immb)", fields)
	if err != nil {
		t.Fatal(err)
	}
	op := DisasmOperand{
		Kind:     DisasmFormula,
		Cols:     []BitPart{{Field: "immh", Start: 19, End: 22, Width: 4}},
		Rows:     []DisasmRow{{Bits: []string{"001x"}}},
		Formulas: []DisasmFormulaExpr{formula},
	}
	// immh:immb = 0010:101 = 21, so the architectural shift is 32-21.
	word := uint32(0b0010)<<19 | uint32(0b101)<<16
	if got, ok := op.Render(word); !ok || got != "11" {
		t.Fatalf("formula render = %q, %v; want 11, true", got, ok)
	}
}

func TestDisasmFormulaSlice(t *testing.T) {
	fields := map[string]ir.BitField{
		"imm5": {Name: "imm5", Start: 16, End: 20},
	}
	formula, err := compileDisasmFormula("UInt(imm5[4:2])", fields)
	if err != nil {
		t.Fatal(err)
	}
	op := DisasmOperand{
		Kind:     DisasmFormula,
		Cols:     []BitPart{{Field: "imm5", Start: 16, End: 20, Width: 5}},
		Rows:     []DisasmRow{{Bits: []string{"xxxxx"}}},
		Formulas: []DisasmFormulaExpr{formula},
	}
	word := uint32(0b10110) << 16
	if got, ok := op.Render(word); !ok || got != "5" {
		t.Fatalf("slice formula render = %q, %v; want 5, true", got, ok)
	}
}

func TestElementSizeShiftFormula(t *testing.T) {
	fields := map[string]ir.BitField{
		"tszh": {Name: "tszh", Start: 22, End: 22},
		"tszl": {Name: "tszl", Start: 19, End: 21},
		"imm3": {Name: "imm3", Start: 16, End: 18},
	}
	formula, ok := compileElementSizeFormula(
		[]string{"tszh", "tszl", "imm3"},
		[]string{`let shift : integer = (2 * esize) - UInt(tsize::imm3);`},
		fields,
	)
	if !ok {
		t.Fatal("element-size formula was not recognized")
	}
	op := DisasmOperand{
		Kind:     DisasmFormula,
		Rows:     []DisasmRow{{}},
		Formulas: []DisasmFormulaExpr{formula},
	}
	word := uint32(0b0)<<22 | uint32(0b010)<<19 | uint32(0b101)<<16
	if got, ok := op.Render(word); !ok || got != "11" {
		t.Fatalf("element-size render = %q, %v; want 11, true", got, ok)
	}
}

func TestLogicalImmediateDecode(t *testing.T) {
	op := DisasmOperand{
		Kind: DisasmLogicalImm,
		Parts: []BitPart{
			{Start: 22, End: 22, Width: 1},
			{Start: 16, End: 21, Width: 6},
			{Start: 10, End: 15, Width: 6},
			{Start: 31, End: 31, Width: 1},
		},
	}
	word := uint32(1)<<31 | uint32(1)<<22 | uint32(7)<<10
	if got, ok := op.Render(word); !ok || got != "0xff" {
		t.Fatalf("logical immediate = %q, %v; want 0xff, true", got, ok)
	}
}

func TestPackedLogicalImmediateDecode(t *testing.T) {
	op := DisasmOperand{
		Kind:  DisasmLogicalImm,
		Parts: []BitPart{{Start: 5, End: 17, Width: 13}},
	}
	// N=1, immr=0, imms=7 is the 64-bit logical mask 0xff.
	word := uint32(1<<12|7) << 5
	if got, ok := op.Render(word); !ok || got != "0xff" {
		t.Fatalf("packed logical immediate = %q, %v; want 0xff, true", got, ok)
	}
	// N=0, immr=0, imms=111000 encodes the 8-bit element mask 0x1.
	word = uint32(0b111000) << 5
	if got, ok := op.Render(word); !ok || got != "0x1" {
		t.Fatalf("packed byte logical immediate = %q, %v; want 0x1, true", got, ok)
	}
}

func TestEquivalentLogicalInverseRelation(t *testing.T) {
	visible := AsmOperand{Symbol: "<const>", Link: "const"}
	equivalent := []AsmOperand{{
		Symbol: "<const>",
		Link:   "const",
		Prefix: ", #(-",
	}}
	if !equivalentOperandInverts(visible, equivalent, " - 1)") {
		t.Fatal("did not recognize #(-<const> - 1) as a logical inverse")
	}
}

func TestFixedSpecifierLiteral(t *testing.T) {
	got, ok := fixedSpecifierLiteral("is the destination width specifier, h.")
	if !ok || got != "h" {
		t.Fatalf("fixed specifier = %q, %v; want h, true", got, ok)
	}
}

func TestPackedElementIndexDecode(t *testing.T) {
	op := DisasmOperand{
		Kind: DisasmElementIndex,
		Parts: []BitPart{
			{Start: 5, End: 6, Width: 2},
			{Start: 0, End: 4, Width: 5},
		},
		IndexSizeParts: 1,
	}
	// imm2:tsz = 10:00100. The unary size marker has lsb=2, leaving
	// index 1000 (8) above it.
	word := uint32(2)<<5 | 4
	if got, ok := op.Render(word); !ok || got != "8" {
		t.Fatalf("element index = %q, %v; want 8, true", got, ok)
	}
}

func TestTileMaskDecode(t *testing.T) {
	op := DisasmOperand{
		Kind:  DisasmTileMask,
		Parts: []BitPart{{Start: 0, End: 7, Width: 8}},
	}
	if got, ok := op.Render(0b10000101); !ok || got != "za0.d, za2.d, za7.d" {
		t.Fatalf("tile mask = %q, %v", got, ok)
	}
}

func TestSingletonEnumFromProse(t *testing.T) {
	c := ClassifiedOperand{
		Fields: []string{"CRm"},
		Explanation: AsmExplanation{
			Fields: []string{"CRm"},
		},
	}
	rows, cols, ok := proseSingletonTable(c, map[string]ir.BitField{
		"CRm": {Name: "CRm", Start: 8, End: 11},
	}, "specifies values are: sy full system, encoded as crm = 0b1111. can be omitted")
	if !ok || len(rows) != 1 || rows[0].Symbol != "sy" ||
		len(cols) != 1 || cols[0].Width != 4 {
		t.Fatalf("singleton table = %#v, %#v, %v", rows, cols, ok)
	}
}

func TestCanonicalBareAlternative(t *testing.T) {
	if got := canonicalAsmAlternatives("ISB sy|#15"); got != "ISB sy" {
		t.Fatalf("bare alternative = %q, want ISB sy", got)
	}
}

// labelOperandFixtures are ARM's own <label> explanations, one per wording
// the A64 corpus uses, with the fields they are encoded in.
var labelOperandFixtures = []struct {
	name   string
	link   string
	fields []string
	bits   map[string]ir.BitField
	prose  string
}{
	{
		name: "B/BL imm26", link: "imm26_offset", fields: []string{"imm26"},
		bits:  map[string]ir.BitField{"imm26": {Name: "imm26", Start: 0, End: 25}},
		prose: `Is the program label to be unconditionally branched to. Its offset from the address of this instruction, in the range +/-128MB, is encoded as "imm26" times 4.`,
	},
	{
		name: "B.cond/CBZ imm19", link: "imm19_offset", fields: []string{"imm19"},
		bits:  map[string]ir.BitField{"imm19": {Name: "imm19", Start: 5, End: 23}},
		prose: `Is the program label to be conditionally branched to. Its offset from the address of this instruction, in the range +/-1MB, is encoded as "imm19" times 4.`,
	},
	{
		name: "LDR literal imm19", link: "imm19_offset", fields: []string{"imm19"},
		bits:  map[string]ir.BitField{"imm19": {Name: "imm19", Start: 5, End: 23}},
		prose: `Is the program label from which the data is to be loaded. Its offset from the address of this instruction, in the range +/-1MB, is encoded as "imm19" times 4.`,
	},
	{
		name: "TBZ imm14", link: "imm14_offset", fields: []string{"imm14"},
		bits:  map[string]ir.BitField{"imm14": {Name: "imm14", Start: 5, End: 18}},
		prose: `Is the program label to be conditionally branched to. Its offset from the address of this instruction, in the range +/-32KB, is encoded as "imm14" times 4.`,
	},
	{
		name: "CB<cc> imm9", link: "imm9_offset", fields: []string{"imm9"},
		bits:  map[string]ir.BitField{"imm9": {Name: "imm9", Start: 5, End: 13}},
		prose: `Is the program label to be conditionally branched to. Its offset from the address of this instruction, in the range -1024 to 1020, is encoded as "imm9" times 4.`,
	},
	{
		name: "ADR immhi:immlo", link: "immhiimmlo_offset", fields: []string{"immhi", "immlo"},
		bits: map[string]ir.BitField{
			"immhi": {Name: "immhi", Start: 5, End: 23},
			"immlo": {Name: "immlo", Start: 29, End: 30},
		},
		prose: `Is the program label whose address is to be calculated. Its offset from the address of this instruction, in the range +/-1MB, is encoded in "immhi:immlo".`,
	},
	{
		name: "ADRP immhi:immlo", link: "immhiimmlo_offset", fields: []string{"immhi", "immlo"},
		bits: map[string]ir.BitField{
			"immhi": {Name: "immhi", Start: 5, End: 23},
			"immlo": {Name: "immlo", Start: 29, End: 30},
		},
		prose: `Is the program label whose 4KB page address is to be calculated. Its offset from the page address of this instruction, in the range +/-4GB, is encoded as "immhi:immlo" times 4096.`,
	},
	{
		name: "AUTIASPPC imm16", link: "imm16_offset", fields: []string{"imm16"},
		bits:  map[string]ir.BitField{"imm16": {Name: "imm16", Start: 5, End: 20}},
		prose: `Is the program label whose address is to be calculated. Its negative offset from the address of this instruction, a multiple of 4 in the range -262140 to 0, is encoded as an unsigned value in the "imm16" field as <label>/4.`,
	},
}

func modelLabelOperand(t *testing.T, name string) *DisasmOperand {
	t.Helper()
	for _, fixture := range labelOperandFixtures {
		if fixture.name != name {
			continue
		}
		c := ClassifyOperandWith(AsmOperand{
			Symbol: "<label>", Link: fixture.link, Hover: fixture.prose,
		}, AsmExplanation{
			Symbol: "<label>", Link: fixture.link, Fields: fixture.fields, Prose: fixture.prose,
		})
		if c.Class != ClassLabel {
			t.Fatalf("%s classified as %s, want label", name, c.Class)
		}
		op, err := disasmOperandWithContext(c, fixture.bits, 0, 0, nil, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := checkLabelDisplacement(op); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return op
	}
	t.Fatalf("no label fixture %q", name)
	return nil
}

// TestPCRelativeLabelDecodeRelations renders the model-built operand for every
// A64 label wording, in both directions. A backward branch is the case an
// unsigned reading gets wrong: BL .-420 used to print as .+268435036.
func TestPCRelativeLabelDecodeRelations(t *testing.T) {
	for _, test := range []struct {
		fixture string
		word    uint32
		want    string
	}{
		{"B/BL imm26", 0x03FFFF97, ".-420"},
		{"B/BL imm26", 0x02000000, ".-134217728"},
		{"B/BL imm26", 0x00000001, ".+4"},
		{"B/BL imm26", 0x01FFFFFF, ".+134217724"},
		{"B.cond/CBZ imm19", 0x7FFFB << 5, ".-20"},
		{"B.cond/CBZ imm19", 0x7FFFE << 5, ".-8"},
		{"B.cond/CBZ imm19", 0x00005 << 5, ".+20"},
		{"LDR literal imm19", 0x7FFFF << 5, ".-4"},
		{"LDR literal imm19", 0x40000 << 5, ".-1048576"},
		{"TBZ imm14", 0x3FF1 << 5, ".-60"},
		{"TBZ imm14", 0x1FFF << 5, ".+32764"},
		{"CB<cc> imm9", 0x100 << 5, ".-1024"},
		{"CB<cc> imm9", 0x0FF << 5, ".+1020"},
		{"ADR immhi:immlo", 0x7FFFF<<5 | 3<<29, ".-1"},
		{"ADR immhi:immlo", 0x40000 << 5, ".-1048576"},
		{"ADR immhi:immlo", 1 << 29, ".+1"},
		{"ADRP immhi:immlo", 1 << 29, ".+4096"},
		{"ADRP immhi:immlo", 0x7FFFF<<5 | 3<<29, ".-4096"},
		{"AUTIASPPC imm16", 36 << 5, ".-144"},
		{"AUTIASPPC imm16", 3 << 5, ".-12"},
		{"AUTIASPPC imm16", 0xFFFF << 5, ".-262140"},
		{"AUTIASPPC imm16", 0, ".+0"},
	} {
		op := modelLabelOperand(t, test.fixture)
		if got, ok := op.Render(test.word); !ok || got != test.want {
			t.Errorf("%s label of 0x%08X = %q, %v; want %q, true",
				test.fixture, test.word, got, ok, test.want)
		}
	}
}

// TestLabelOperandsCarryDisplacementSign is the model invariant: every
// PC-relative label is Signed or the RawMul<0 PAC form, and a label read as a
// plain unsigned field is refused rather than printed as a forward offset.
func TestLabelOperandsCarryDisplacementSign(t *testing.T) {
	for _, fixture := range labelOperandFixtures {
		op := modelLabelOperand(t, fixture.name)
		if !op.Signed && op.RawMul >= 0 {
			t.Errorf("%s: label is neither signed nor negated: %#v", fixture.name, op)
		}
		if op.RawMul < 0 && (op.Signed || op.Scale != 4) {
			t.Errorf("%s: PAC label signed=%v scale=%d, want unsigned field times 4",
				fixture.name, op.Signed, op.Scale)
		}
	}
	unsigned := &DisasmOperand{Symbol: "<label>", Class: ClassLabel, Kind: DisasmNum, Scale: 4}
	if err := checkLabelDisplacement(unsigned); err == nil {
		t.Fatal("an unsigned PC-relative label passed the displacement invariant")
	}
}

func TestLabelSignSampleSetsEveryLabelSignBit(t *testing.T) {
	label := modelLabelOperand(t, "B/BL imm26")
	form := DisasmForm{Parts: []DisasmPart{{Literal: "BL "}, {Op: label}}}
	entry := CatalogEntry{Mask: 0xFC000000, Value: 0x94000000}
	sample, ok := labelSignSample(&form, entry, 0x94000001)
	if !ok || sample != 0x96000001 {
		t.Fatalf("sign sample = 0x%08X, %v; want 0x96000001, true", sample, ok)
	}
	if got, ok := form.Render(sample); !ok || got != "BL .-134217724" {
		t.Fatalf("sign sample renders %q, %v; want BL .-134217724", got, ok)
	}
	if _, ok := labelSignSample(&form, entry, sample); ok {
		t.Fatal("a probe that already sets the sign bit produced a duplicate sample")
	}
}

func TestBitfieldAliasWidthDecode(t *testing.T) {
	op := DisasmOperand{
		Kind: DisasmBitfieldWidth,
		Parts: []BitPart{
			{Start: 10, End: 15, Width: 6},
			{Start: 16, End: 21, Width: 6},
		},
	}
	word := uint32(12)<<10 | uint32(8)<<16
	if got, ok := op.Render(word); !ok || got != "5" {
		t.Fatalf("extract width = %q, %v; want 5, true", got, ok)
	}
	op.Add = 1
	insertWord := uint32(7)<<10 | uint32(8)<<16
	if got, ok := op.Render(insertWord); !ok || got != "8" {
		t.Fatalf("insert width = %q, %v; want 8, true", got, ok)
	}
	if got, ok := op.Render(uint32(8)<<10 | uint32(8)<<16); ok {
		t.Fatalf("insert alias rendered non-wrapping fields as %q", got)
	}
	op.Add = 0
	op.DataSize = 32
	if got, ok := op.Render(uint32(36)<<10 | uint32(29)<<16); ok {
		t.Fatalf("32-bit extract rendered out-of-range imms as %q", got)
	}
}

func TestByteMaskImmediateDecode(t *testing.T) {
	op := DisasmOperand{Kind: DisasmByteMaskImm}
	for bit := 0; bit < 8; bit++ {
		op.Parts = append(op.Parts, BitPart{Start: 7 - bit, End: 7 - bit, Width: 1})
	}
	if got, ok := op.Render(0b10100001); !ok || got != "0xff00ff00000000ff" {
		t.Fatalf("byte mask = %q, %v; want 0xff00ff00000000ff, true", got, ok)
	}
}

func TestTableNumericFallbackRendersSelectorValue(t *testing.T) {
	op := DisasmOperand{
		Kind: DisasmTable,
		Cols: []BitPart{{Start: 0, End: 3, Width: 4}},
		Rows: []DisasmRow{{Bits: []string{"x11x"}, Symbol: "#uimm4"}},
	}
	if got, ok := op.Render(0b0110); !ok || got != "#6" {
		t.Fatalf("numeric table fallback = %q, %v; want #6, true", got, ok)
	}
}

func TestMoveWideAliasImmediateDecode(t *testing.T) {
	op := DisasmOperand{
		Kind: DisasmMoveWideImm,
		Parts: []BitPart{
			{Start: 5, End: 20, Width: 16},
			{Start: 21, End: 22, Width: 2},
			{Start: 31, End: 31, Width: 1},
		},
	}
	word := uint32(1)<<31 | uint32(1)<<21 | uint32(0x1d)<<5
	if got, ok := op.Render(word); !ok || got != "0x1d0000" {
		t.Fatalf("MOVZ alias immediate = %q, %v; want 0x1d0000, true", got, ok)
	}
	op.MoveWideInvert = true
	if got, ok := op.Render(word); !ok || got != "0xffffffffffe2ffff" {
		t.Fatalf("MOVN alias immediate = %q, %v; want 0xffffffffffe2ffff, true", got, ok)
	}
}

func TestPredicateCounterUsesFieldBias(t *testing.T) {
	c := ClassifyOperandWith(AsmOperand{
		Symbol: "<PNd>",
		Link:   "PNd",
	}, AsmExplanation{
		Symbol: "<PNd>",
		Fields: []string{"PNd"},
		Prose: `Is the name of the destination scalable predicate register PN8-PN15,
			with predicate-as-counter encoding, encoded as "PNd" plus 8.`,
	})
	if c.Class != ClassSvePN || c.Class == ClassDerived || c.Bias != 8 {
		t.Fatalf("classification = class %s bias %d, want pn bias 8", c.Class, c.Bias)
	}
}

func TestSVEMoveMaskPreferredConstraint(t *testing.T) {
	form := DisasmForm{
		SVEMoveMaskField: &BitPart{Field: "imm13", Start: 5, End: 17, Width: 13},
	}
	// imm13=1 decodes to the replicated value 3, which a single DUP can
	// express and therefore is not the preferred MOV<-DUPM alias.
	if form.matchesConstraints(1 << 5) {
		t.Fatal("replicated immediate 3 unexpectedly selected the MOV alias")
	}
	word, ok := form.SatisfyConstraints(1 << 5)
	if !ok || !sveMoveMaskPreferred(fieldValue(word, 5, 17)) {
		t.Fatalf("constraint solver returned 0x%08X, %v", word, ok)
	}
}

func TestSemanticRegisterPartsRetainPinnedLowBit(t *testing.T) {
	parts := semanticFieldParts(
		ir.BitField{Name: "Rt", Start: 0, End: 4},
		1, 0,
	)
	op := DisasmOperand{Parts: parts}
	if got := op.rawValue(8); got != 8 {
		t.Fatalf("decoded register = %d, want architectural register 8", got)
	}
	if len(parts) != 2 || parts[0].Start != 1 || !parts[1].IsLit || parts[1].Literal != "0" {
		t.Fatalf("semantic parts = %#v, want free bits followed by pinned zero", parts)
	}
}

func TestEquivalentDefaultsDoNotConstrainVisibleOperands(t *testing.T) {
	operand := AsmOperand{
		Symbol: "<amount>",
		Hover:  `Is an unsigned immediate, defaulting to 0 and encoded in the "imm6" field.`,
	}
	fields := map[string]ir.BitField{
		"imm6": {Name: "imm6", Start: 10, End: 15},
	}
	var form DisasmForm
	if err := addEquivalentOperandDefaults(
		&form, []AsmOperand{operand}, fields, map[string]bool{"imm6": true},
	); err != nil {
		t.Fatal(err)
	}
	if form.ConstraintMask != 0 {
		t.Fatalf("visible optional operand became fixed: mask=%08x", form.ConstraintMask)
	}
}

func TestMoveAliasPreferredPredicates(t *testing.T) {
	moveWide := DisasmForm{MoveWideZeroGuard: &DisasmMoveWideZeroGuard{
		Imm16: BitPart{Start: 5, End: 20, Width: 16},
		HW:    BitPart{Start: 21, End: 22, Width: 2},
	}}
	word := uint32(1) << 21
	if moveWide.matchesConstraints(word) {
		t.Fatal("MOVZ with zero imm16 and nonzero hw selected the MOV alias")
	}
	if got, ok := moveWide.SatisfyConstraints(word); !ok || fieldValue(got, 21, 22) != 0 {
		t.Fatalf("move-wide solver = 0x%08X, %v", got, ok)
	}

	logical := DisasmForm{LogicalMoveGuard: &DisasmLogicalMoveGuard{
		SF: BitPart{Start: 31, End: 31, Width: 1}, N: BitPart{Start: 22, End: 22, Width: 1},
		Imms: BitPart{Start: 10, End: 15, Width: 6}, Immr: BitPart{Start: 16, End: 21, Width: 6},
	}}
	const movzPreferred = uint32(0x320617E4)
	if logical.matchesConstraints(movzPreferred) {
		t.Fatal("logical immediate encodable by MOVZ selected MOV<-ORR")
	}
	if got, ok := logical.SatisfyConstraints(movzPreferred); !ok || !logical.matchesConstraints(got) {
		t.Fatalf("logical MOV solver = 0x%08X, %v", got, ok)
	}
}

func TestBitfieldAliasPredicates(t *testing.T) {
	fields := map[string]ir.BitField{
		"sf":   {Name: "sf", Start: 31, End: 31},
		"opc":  {Name: "opc", Start: 29, End: 30},
		"N":    {Name: "N", Start: 22, End: 22},
		"immr": {Name: "immr", Start: 16, End: 21},
		"imms": {Name: "imms", Start: 10, End: 15},
	}
	form := func(cond string) DisasmForm {
		t.Helper()
		var f DisasmForm
		if err := addDisasmAliasConstraints(&f, cond, fields); err != nil {
			t.Fatal(err)
		}
		if f.BitfieldGuard == nil {
			t.Fatalf("%q compiled no bitfield guard", cond)
		}
		return f
	}
	ubfx := form("BFXPreferred(sf, opc[1], imms, immr)")
	ubfiz := form("UInt(imms) < UInt(immr)")
	bfxil := form("UInt(imms) >= UInt(immr)")
	for _, test := range []struct {
		word               uint32
		ubfx, ubfiz, bfxil bool
	}{
		// UBFM w0, w8, #8, #15 is UBFX w0, w8, #8, #8.
		{0x53083D00, true, false, true},
		// UBFM w0, w8, #8, #7 is UBFIZ w0, w8, #24, #8.
		{0x53081D00, false, true, false},
		// UBFM w0, w8, #0, #15 is UXTH, not UBFX.
		{0x53003D00, false, false, true},
		// UBFM w0, w8, #8, #31 is LSR, not UBFX.
		{0x53087D00, false, false, true},
		// SBFM x0, x8, #0, #31 is SXTW, not SBFX.
		{0x93407D00, false, false, true},
		// UBFM x0, x8, #0, #31 is UBFX: zero extension of a word is not an alias.
		{0xD3407D00, true, false, true},
	} {
		if got := ubfx.matchesConstraints(test.word); got != test.ubfx {
			t.Errorf("0x%08X BFXPreferred = %t, want %t", test.word, got, test.ubfx)
		}
		if got := ubfiz.matchesConstraints(test.word); got != test.ubfiz {
			t.Errorf("0x%08X imms < immr = %t, want %t", test.word, got, test.ubfiz)
		}
		if got := bfxil.matchesConstraints(test.word); got != test.bfxil {
			t.Errorf("0x%08X imms >= immr = %t, want %t", test.word, got, test.bfxil)
		}
	}
	for _, f := range []DisasmForm{ubfx, ubfiz, bfxil} {
		if got, ok := f.SatisfyConstraints(0x53003D00); !ok || !f.matchesConstraints(got) {
			t.Fatalf("bitfield solver = 0x%08X, %t", got, ok)
		}
	}
	var none DisasmForm
	if err := addDisasmAliasConstraints(&none, "imms == '011111'", fields); err != nil || none.BitfieldGuard != nil {
		t.Fatalf("a field literal compiled a bitfield guard: %v", err)
	}
}

func TestAbsentTableRowBecomesOptionalDefault(t *testing.T) {
	c := ClassifiedOperand{
		AsmOperand: AsmOperand{Symbol: "<option>"},
		Class:      ClassEnum,
		Fields:     []string{"CRm"},
		Explanation: AsmExplanation{
			Fields: []string{"CRm"}, ValueFields: []string{"CRm[2:1]"},
			Values: []SymbolValue{
				{Bits: []string{"01"}, Symbol: "SM"},
				{Bits: []string{"10"}, Symbol: "ZA"},
				{Bits: []string{"11"}, Symbol: "[absent]"},
			},
		},
	}
	op, err := disasmOperand(c, map[string]ir.BitField{
		"CRm": {Name: "CRm", Start: 8, End: 11},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !op.HasDefault || op.Default != 3 {
		t.Fatalf("table default = %d present=%v, want encoded absent row 3", op.Default, op.HasDefault)
	}
}

func TestPNgIsOrdinaryGoverningPredicate(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<PNg>",
		Hover:  "Is the name of the governing scalable predicate register P0-P7.",
	})
	if c.Class != ClassSveP {
		t.Fatalf("class = %s, want %s", c.Class, ClassSveP)
	}
}

func TestDecodeEqualityBehindFeatureGuard(t *testing.T) {
	got := decodeEqualityConstraints([]string{
		`if !IsFeatureImplemented(FEAT_MOPS) || sz != '00' then EndOfDecode(Decode_UNDEF);`,
	})
	if len(got) != 1 || got[0] != "sz == 00" {
		t.Fatalf("constraints = %v, want [sz == 00]", got)
	}
}

func TestDecodeBitPinConstraint(t *testing.T) {
	got := decodeBitPinConstraints([]string{
		`if size[0] == '0' then EndOfDecode(Decode_UNDEF);`,
	}, []RegBox{{Name: "size", Width: 2}})
	if len(got) != 1 || got[0] != "size == x1" {
		t.Fatalf("constraints = %v, want [size == x1]", got)
	}
	nested := decodeBitPinConstraints([]string{
		"case scale of\n    when '01' =>\n        if size[0] == '1' then EndOfDecode(Decode_UNDEF); end;",
	}, []RegBox{{Name: "size", Width: 2}})
	if len(nested) != 0 {
		t.Fatalf("nested branch was promoted to global constraint: %v", nested)
	}
}

func TestDecodeSquareBracketRegisterRestrictions(t *testing.T) {
	got := decodeRegisterRestrictions([]string{
		`if Rt[4:3] == '11' || Rt[0] == '1' then EndOfDecode(Decode_UNDEF);`,
		`if Rs[0] == '1' then EndOfDecode(Decode_UNDEF);`,
	})
	rt := got["Rt"]
	if rt.Multiple != 2 || !rt.HasRange || rt.Lo != 0 || rt.Hi != 22 {
		t.Fatalf("Rt restriction = %#v, want even 0..22", rt)
	}
	if rs := got["Rs"]; rs.Multiple != 2 {
		t.Fatalf("Rs restriction = %#v, want even", rs)
	}
}

func TestDecodeRegisterSuccessorRelation(t *testing.T) {
	got := decodeRegisterSuccessors([]string{
		"let d0 : integer = UInt(Pd);\nlet d1 : integer = (UInt(Pd) + 1) MOD 16;",
	})
	rel, ok := got["Pd"]
	if !ok || rel.Field != "Pd" || rel.Mul != 1 || rel.Add != 1 || rel.Mod != 16 {
		t.Fatalf("successor = %+v present=%v", rel, ok)
	}
}

func TestSystemOperationRegisterArity(t *testing.T) {
	if got := systemOperationRegisterArity("SysOp(op1, CRn, CRm, op2) == Sys_GIC"); got != 1 {
		t.Fatalf("GIC arity = %d, want 1", got)
	}
	if got := systemOperationRegisterArity("SysOp128(op1, CRn, CRm, op2) == Sys_TLBIP"); got != 2 {
		t.Fatalf("TLBIP arity = %d, want 2", got)
	}
	if got := systemOperationRegisterArity("SysOp(op1, CRn, CRm, op2) == Sys_TLBI"); got != 0 {
		t.Fatalf("value-dependent TLBI arity = %d, want optional", got)
	}
}

func TestDecodeCompoundForbiddenConstraints(t *testing.T) {
	fields := map[string]ir.BitField{
		"size":  {Name: "size", Start: 22, End: 23},
		"L":     {Name: "L", Start: 21, End: 21},
		"H":     {Name: "H", Start: 11, End: 11},
		"Q":     {Name: "Q", Start: 30, End: 30},
		"cmode": {Name: "cmode", Start: 12, End: 15},
		"op":    {Name: "op", Start: 29, End: 29},
	}
	got := decodeForbiddenConstraints([]string{
		"if size == '10' && (L == '1' || Q == '0') then EndOfDecode(Decode_UNDEF); end;",
		"if size == '01' && H == '1' && Q == '0' then EndOfDecode(Decode_UNDEF); end;",
	}, fields, 0)
	if len(got) != 3 {
		t.Fatalf("forbidden clauses = %#v, want 3", got)
	}
	form := DisasmForm{Forbidden: got}
	word := uint32(1)<<22 | uint32(1)<<11 // size=01, H=1, Q=0
	if form.matchesConstraints(word) {
		t.Fatal("undefined size/H/Q combination was accepted")
	}
	legal, ok := form.SatisfyConstraints(word)
	if !ok || !form.matchesConstraints(legal) {
		t.Fatalf("constraint solver = 0x%08X, %v", legal, ok)
	}

	nested := decodeForbiddenConstraints([]string{`if cmode::op == '11111' then
    if Q == '0' then EndOfDecode(Decode_UNDEF); end;
end;`}, fields, uint32(1)<<29)
	if len(nested) != 1 {
		t.Fatalf("nested forbidden clauses = %#v, want 1", nested)
	}
	wantMask := uint32(0xf)<<12 | uint32(1)<<29 | uint32(1)<<30
	wantValue := uint32(0xf)<<12 | uint32(1)<<29
	if nested[0].Mask != wantMask || nested[0].Value != wantValue {
		t.Fatalf("nested forbidden = %#v, want mask=%08x value=%08x",
			nested[0], wantMask, wantValue)
	}

	unsupportedOuter := decodeForbiddenConstraints([]string{`if ComplexPredicate(x) then
    if Q == '0' then EndOfDecode(Decode_UNDEF); end;
end;`}, fields, 0)
	if len(unsupportedOuter) != 0 {
		t.Fatalf("inner condition escaped unsupported outer context: %#v", unsupportedOuter)
	}
}

func TestDecodeMemoryOperationRegisterConstraints(t *testing.T) {
	fields := map[string]ir.BitField{
		"Rd": {Name: "Rd", Start: 0, End: 4},
		"Rn": {Name: "Rn", Start: 5, End: 9},
		"Rs": {Name: "Rs", Start: 16, End: 20},
	}
	forbidden, unequal := decodeMemoryOperationRegisterConstraints(
		[]string{`var memcpy : CPYParams;`}, fields, 0,
	)
	if len(forbidden) != 3 || len(unequal) != 3 {
		t.Fatalf("CPY constraints = forbidden %v unequal %v", forbidden, unequal)
	}
	form := DisasmForm{Forbidden: forbidden, UnequalFields: unequal}
	if form.matchesConstraints(0) {
		t.Fatal("overlapping CPY roles were accepted")
	}
	word := uint32(31) | uint32(2)<<5 | uint32(3)<<16
	if form.matchesConstraints(word) {
		t.Fatal("CPY register 31 was accepted")
	}
	legal, ok := form.SatisfyConstraints(word)
	if !ok || !form.matchesConstraints(legal) {
		t.Fatalf("CPY constraint solver = 0x%08X, %v", legal, ok)
	}
	legal, ok = form.SatisfyConstraints(0)
	if !ok || !form.matchesConstraints(legal) {
		t.Fatalf("overlapping CPY constraint solver = 0x%08X, %v", legal, ok)
	}

	forbidden, unequal = decodeMemoryOperationRegisterConstraints(
		[]string{`var memset : SETParams;`}, fields, 0,
	)
	if len(forbidden) != 3 || len(unequal) != 3 {
		t.Fatalf("SET constraints = forbidden %v unequal %v", forbidden, unequal)
	}
}

func TestWritebackRegisterConstraintsAreSampleOnly(t *testing.T) {
	fields := map[string]ir.BitField{
		"Rt": {Name: "Rt", Start: 0, End: 4},
		"Rn": {Name: "Rn", Start: 5, End: 9},
	}
	got := decodeWritebackSampleRegisterConstraints(
		[]string{"var wback : boolean = TRUE;"}, fields, 0,
	)
	if len(got) != 1 || got[0].RightMutable != 0x1f {
		t.Fatalf("writeback constraints = %#v", got)
	}
	form := DisasmForm{SampleUnequalFields: got}
	word, ok := form.SatisfyConstraints(uint32(8) | uint32(8)<<5)
	if !ok || fieldValue(word, 0, 4) == fieldValue(word, 5, 9) {
		t.Fatalf("sample word = 0x%08X, %v", word, ok)
	}
	if !form.matchesConstraints(uint32(8) | uint32(8)<<5) {
		t.Fatal("sample-only inequality became a decoder validity rule")
	}
}

func TestDecodeEnumeratedPinConstraint(t *testing.T) {
	got := decodeEnumeratedPinConstraints([]string{
		`if size == '10' || size == '11' then EndOfDecode(Decode_UNDEF);`,
		`if opc IN {'0x'} then EndOfDecode(Decode_UNDEF);`,
	})
	if len(got) != 2 || got[0] != "size == 0x" || got[1] != "opc == 1x" {
		t.Fatalf("constraints = %v, want [size == 0x opc == 1x]", got)
	}
}

func TestDecodeFieldNegate(t *testing.T) {
	got := decodeFieldNegates([]string{
		`constant integer esize = 16;
constant integer shift = esize - UInt(imm4);`,
	})
	if got["imm4"] != 16 {
		t.Fatalf("negates = %v, want imm4:16", got)
	}
}

func TestDecodeRegisterRestriction(t *testing.T) {
	got := decodeRegisterRestrictions([]string{
		`if Rt<4:3> == '11' || Rt<0> == '1' then EndOfDecode(Decode_UNDEF);`,
	})["Rt"]
	if got.Multiple != 2 || !got.HasRange || got.Lo != 0 || got.Hi != 22 {
		t.Fatalf("restriction = %+v, want even 0..22", got)
	}
}

func TestOperandAlternativeSelector(t *testing.T) {
	prose := `When <field>option<0></field> is set to 0, is the 32-bit name`
	m := operandSelectorRE.FindStringSubmatch(prose)
	if m == nil || m[1] != "option" || m[2] != "0" || m[3] != "0" {
		t.Fatalf("selector match = %v", m)
	}
}

func TestShiftAmountIsImmediate(t *testing.T) {
	c := ClassifyOperand(AsmOperand{
		Symbol: "<shift>",
		Link:   "shift",
		Hover:  `Is the shift amount, in the range 0 to 31, encoded in the "immr" field.`,
		Field:  "immr",
	})
	if c.Class != ClassImm {
		t.Fatalf("class = %s, want immediate", c.Class)
	}
}

func TestParsedRORShiftIsImmediate(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "ror_extr.xml"), "ROR_EXTR_32_extract")
	if err != nil {
		t.Fatal(err)
	}
	exps := ExplanationsFor(p.Explanations, p.EncodingName)
	for _, operand := range p.AsmOperands {
		if operand.Symbol != "<shift>" {
			continue
		}
		c := ClassifyOperandWith(operand, exps[operand.Symbol])
		if c.Class != ClassImm {
			t.Fatalf("class = %s; prose=%q hover=%q", c.Class, exps[operand.Symbol].Prose, operand.Hover)
		}
		return
	}
	t.Fatal("shift operand absent")
}

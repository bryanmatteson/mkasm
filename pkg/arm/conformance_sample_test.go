package arm

import "testing"

func TestCanonicalizeOptionalGroupDefault(t *testing.T) {
	form := &DisasmForm{
		RequiredGroups: map[int]bool{},
		Parts: []DisasmPart{{Group: 1, Op: &DisasmOperand{
			Kind: DisasmReg, HasDefault: true, Default: 31,
			Parts: []BitPart{{Start: 0, End: 4, Width: 5}},
		}}},
	}
	if got := canonicalizeOptionalGroupDefaults(form, 1, 0, 0); got != 31 {
		t.Fatalf("optional default = %d, want 31", got)
	}
	form.RequiredGroups[1] = true
	if got := canonicalizeOptionalGroupDefaults(form, 2, 0, 0); got != 2 {
		t.Fatalf("required group changed to %d", got)
	}
}

func TestLegalConformanceWordSolvesSemanticOperandRange(t *testing.T) {
	op := &DisasmOperand{
		Symbol:   "<index>",
		Class:    ClassImm,
		Kind:     DisasmNum,
		Parts:    []BitPart{{Start: 10, End: 13, Width: 4}},
		Scale:    1,
		Lo:       0,
		Hi:       3,
		HasRange: true,
	}
	form := &DisasmForm{
		Mnemonic: "EXT",
		Parts: []DisasmPart{
			{Literal: "EXT #"},
			{Op: op},
		},
		GroupParent: map[int]int{},
	}
	const fixedMask = uint32(0xff000000)
	const fixedValue = uint32(0x5a000000)
	initial := fixedValue | 15<<10
	got := legalConformanceWord(initial, fixedMask, fixedValue, form)
	if got&fixedMask != fixedValue {
		t.Fatalf("fixed bits changed: got %#08x", got)
	}
	if _, ok := form.Render(got); !ok {
		t.Fatalf("semantic range was not solved: got %#08x", got)
	}
}

func TestLegalConformanceWordSolvesBitfieldAliasRelation(t *testing.T) {
	op := &DisasmOperand{
		Symbol: "<width>",
		Class:  ClassImm,
		Kind:   DisasmBitfieldWidth,
		Parts: []BitPart{
			{Start: 10, End: 15, Width: 6},
			{Start: 16, End: 21, Width: 6},
		},
		Scale: 1,
		Add:   1,
	}
	form := &DisasmForm{
		Mnemonic: "BFI",
		Parts: []DisasmPart{
			{Literal: "BFI #"},
			{Op: op},
		},
		GroupParent: map[int]int{},
	}
	initial := uint32(29)<<10 | uint32(29)<<16
	got := legalConformanceWord(initial, 0, 0, form)
	imms := fieldValue(got, 10, 15)
	immr := fieldValue(got, 16, 21)
	if imms >= immr {
		t.Fatalf("alias relation was not solved: imms=%d immr=%d", imms, immr)
	}
	if _, ok := form.Render(got); !ok {
		t.Fatalf("solved word did not render: %#08x", got)
	}
}

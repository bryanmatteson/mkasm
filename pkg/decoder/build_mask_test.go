package decoder

import (
	"slices"
	"strings"
	"testing"

	"mkasm/pkg/ir"
)

func TestCollectFieldMasksSkipsInvalidRanges(t *testing.T) {
	b := &DecoderTreeBuilder{}
	instrs := []*ir.InstructionIR{
		{
			Mnemonic: "bad",
			Encoding: ir.EncodingMask{
				Width: 32,
				Fields: []ir.BitField{
					{Name: "neg", Start: 5, End: 2, Fixed: uint64Ptr(1)},   // End < Start
					{Name: "wide", Start: 0, End: 40, Fixed: uint64Ptr(1)}, // overflows
					{Name: "ok", Start: 28, End: 31, Fixed: uint64Ptr(0xf)},
				},
			},
		},
	}

	masks := b.collectFieldMasks(instrs)
	if len(masks) != 1 {
		t.Fatalf("expected 1 valid mask, got %d: %#v", len(masks), masks)
	}
	if masks[0].Mask != 0xf0000000 {
		t.Fatalf("unexpected mask %#x", masks[0].Mask)
	}
}

func TestBuildTreeDoesNotPanicOnSparseFields(t *testing.T) {
	b := &DecoderTreeBuilder{}
	zero := uint64(0)
	one := uint64(1)
	instrs := []*ir.InstructionIR{
		{
			Mnemonic:   "A",
			EncodingID: "A",
			BitPattern: "00000000000000000000000000000000",
			Encoding: ir.EncodingMask{
				Width: 32,
				Fields: []ir.BitField{
					{Name: "op", Start: 25, End: 28, Fixed: &zero},
				},
			},
		},
		{
			Mnemonic:   "B",
			EncodingID: "B",
			BitPattern: "00010000000000000000000000000000",
			Encoding: ir.EncodingMask{
				Width: 32,
				Fields: []ir.BitField{
					{Name: "op", Start: 25, End: 28, Fixed: &one},
					{Name: "bad", Start: 10, End: 5, Fixed: &one},
				},
			},
		},
	}

	tree := b.BuildTree(instrs, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("expected non-nil decoder tree")
	}
}

func uint64Ptr(v uint64) *uint64 { return &v }

// wildcardTrio models the shape that used to misroute: two encodings pin the
// field the split is taken on, a third leaves it free. SYS/DC/IC are the real
// instance — DC is SYS with op1/CRn pinned, so every word that decodes as DC
// also matches SYS.
func wildcardTrio() []*ir.InstructionIR {
	field := func(name string, start, end int, fixed *uint64) ir.BitField {
		return ir.BitField{Name: name, Start: start, End: end, Fixed: fixed}
	}
	return []*ir.InstructionIR{
		{
			Mnemonic: "A", EncodingID: "A",
			BitPattern: "11" + strings.Repeat("x", 26) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("top", 30, 31, uint64Ptr(0b11)),
				field("mid", 4, 29, nil),
				field("tag", 0, 3, uint64Ptr(1)),
			}},
		},
		{
			Mnemonic: "B", EncodingID: "B",
			BitPattern: "10" + strings.Repeat("x", 26) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("top", 30, 31, uint64Ptr(0b10)),
				field("mid", 4, 29, nil),
				field("tag", 0, 3, uint64Ptr(1)),
			}},
		},
		{
			Mnemonic: "C", EncodingID: "C",
			BitPattern: strings.Repeat("x", 28) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("mid", 4, 29, nil),
				field("tag", 0, 3, uint64Ptr(1)),
			}},
		},
	}
}

func TestTreeRoutesEncodingsWildcardUnderTheSplit(t *testing.T) {
	instrs := wildcardTrio()
	tree := (&DecoderTreeBuilder{}).BuildTree(instrs, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("expected non-nil decoder tree")
	}
	if tree.Root.Mask == 0 {
		t.Fatalf("expected a mask split at the root, got %+v", tree.Root)
	}

	for top := uint32(0); top < 4; top++ {
		word := top<<30 | 1
		res, _ := Match(tree, word)
		got := hitIDs(resultHits(res))
		want := hitIDs(MatchByPattern(instrs, word))
		if len(want) == 0 {
			t.Fatalf("0x%08X matches nothing; the fixture is wrong", word)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("0x%08X: tree found %v, flat matcher found %v", word, got, want)
		}
	}
}

func TestTreeReportsPeersOfAWildcardEncoding(t *testing.T) {
	instrs := wildcardTrio()
	tree := (&DecoderTreeBuilder{}).BuildTree(instrs, nil)

	// C is wildcard over the split, so it must show up beside B rather than
	// leaving B's leaf looking unique.
	res, _ := Match(tree, 0b10<<30|1)
	if got, want := hitIDs(resultHits(res)), []string{"B", "C"}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	// Nothing pins top=01, so C is alone there and the claim of uniqueness holds.
	res, err := Match(tree, 0b01<<30|1)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if res.Instruction == nil || res.Instruction.EncodingID != "C" || len(res.Ambiguous) != 0 {
		t.Fatalf("got %+v", res)
	}
}

func resultHits(res MatchResult) []*ir.InstructionIR {
	if res.Instruction != nil {
		return []*ir.InstructionIR{res.Instruction}
	}
	return res.Ambiguous
}

func hitIDs(hits []*ir.InstructionIR) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.EncodingID)
	}
	slices.Sort(out)
	return out
}

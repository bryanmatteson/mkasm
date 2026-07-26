package decoder

import (
	"testing"

	"mkasm/pkg/ir"
)

func fixed(v uint64) *uint64 { return &v }

func TestMatchTree_CLREXLike(t *testing.T) {
	// Build a tiny artificial tree: mask top 8 bits, then leaf
	clrex := &ir.InstructionIR{
		Mnemonic:   "CLREX",
		EncodingID: "CLREX_BN_barriers",
		BitPattern: "11010101000000110011xxxxxxxxxxxx",
		Encoding: ir.EncodingMask{
			Width: 32,
			Fields: []ir.BitField{
				{Name: "fixed_hi", Start: 24, End: 31, Fixed: fixed(0xD5)},
			},
		},
	}
	// pad pattern
	for len(clrex.BitPattern) < 32 {
		clrex.BitPattern += "x"
	}
	clrex.BitPattern = clrex.BitPattern[:32]

	builder := &DecoderTreeBuilder{}
	tree := builder.BuildTree([]*ir.InstructionIR{clrex}, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("empty tree")
	}

	// word matching fixed bits of pattern
	_, value := ir.FixedBitsFromPattern(clrex.BitPattern)
	res, err := Match(tree, value)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if res.Instruction == nil || res.Instruction.EncodingID != clrex.EncodingID {
		t.Fatalf("got %+v", res)
	}
}

func TestMatchByPattern(t *testing.T) {
	a := &ir.InstructionIR{EncodingID: "A", BitPattern: "1111xxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
	b := &ir.InstructionIR{EncodingID: "B", BitPattern: "0000xxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
	hits := MatchByPattern([]*ir.InstructionIR{a, b}, 0xF0000000)
	if len(hits) != 1 || hits[0].EncodingID != "A" {
		t.Fatalf("hits=%v", hits)
	}
}

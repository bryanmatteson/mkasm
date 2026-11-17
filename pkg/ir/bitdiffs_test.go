package ir

import (
	"fmt"
	"strings"
	"testing"
)

func TestEvalBitDiffPatterns(t *testing.T) {
	for _, bounds := range [][2]int{{0, 0}, {3, 7}, {0, 31}, {31, 31}} {
		start, end := bounds[0], bounds[1]
		width := end - start + 1
		for _, pattern := range []string{"", "1", "0", "x", "X1x0", "'10 xX 01'", "000000000000000000000000000000001", "((10invalid01))"} {
			for _, word := range []uint32{0, 1, 0xffffffff, 0x12345678, 0x80000000} {
				gotBits := fmt.Sprintf("%032b", word)[31-end : 32-start]
				want := true
				for i, bit := range normalizeBitString(pattern, width) {
					if bit != 'x' && bit != 'X' && byte(bit) != gotBits[i] {
						want = false
					}
				}
				for _, op := range []BitDiffOp{BitDiffEq, BitDiffNe, BitDiffIn} {
					a := &BitDiffAtom{Start: start, End: end, Op: op, Bits: pattern, Alts: []string{pattern}}
					expected := want
					if op == BitDiffNe {
						expected = !want
					}
					if got := EvalBitDiffs(&BitDiffNode{Atom: a}, word); got != expected {
						t.Fatalf("word=%08x field=%d:%d pattern=%q op=%d: %t, want %t", word, start, end, pattern, op, got, expected)
					}
				}
			}
		}
	}
	for _, bounds := range [][2]int{{-1, -1}, {1, 0}, {0, 32}} {
		if !EvalBitDiffs(&BitDiffNode{Atom: &BitDiffAtom{Start: bounds[0], End: bounds[1], Bits: "1"}}, 0) {
			t.Fatal("unresolved field rejected")
		}
	}
	n := &BitDiffNode{Atom: &BitDiffAtom{Start: 0, End: 4, Op: BitDiffIn, Alts: []string{"11111", "00001"}}}
	if !EvalBitDiffs(n, 1) || EvalBitDiffs(n, 2) {
		t.Fatal("IN alternatives changed")
	}
}

func BenchmarkEvalBitDiffs(b *testing.B) {
	for _, width := range []int{5, 32} {
		b.Run(fmt.Sprint(width), func(b *testing.B) {
			n := &BitDiffNode{Atom: &BitDiffAtom{Start: 0, End: width - 1, Op: BitDiffNe, Bits: strings.Repeat("1", width)}}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !EvalBitDiffs(n, uint32(i)&0x7ffffffe) {
					b.Fatal("unexpected mismatch")
				}
			}
		})
	}
}

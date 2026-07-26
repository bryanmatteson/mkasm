package decoder

import (
	"fmt"

	"mkasm/pkg/ir"
)

// MatchResult is the outcome of walking a decoder tree for one instruction word.
type MatchResult struct {
	Instruction *ir.InstructionIR
	Ambiguous   []*ir.InstructionIR
	Depth       int
}

// Match walks tree for word using mask/value child edges.
// Leaves with a single Instruction or Ambiguous set terminate the walk.
func Match(tree *ir.DecoderTree, word uint32) (MatchResult, error) {
	if tree == nil || tree.Root == nil {
		return MatchResult{}, fmt.Errorf("empty decoder tree")
	}
	return matchNode(tree.Root, word, 0)
}

// matchNode follows key edges only. groupByMask files every encoding under all
// the keys it can match, so a node with no edge for the word's key holds no
// candidate for it either. The linear rescue scan this used to fall back on
// only masked misrouting — and the emitted walker never had one, so any word it
// rescued was a word the generated decoder silently dropped to its O(n) table.
func matchNode(node *ir.DecoderNode, word uint32, depth int) (MatchResult, error) {
	if node == nil {
		return MatchResult{}, fmt.Errorf("nil decoder node at depth %d", depth)
	}

	if node.Instruction != nil || len(node.Ambiguous) > 0 {
		return matchLeaf(node, word, depth)
	}

	if len(node.Children) == 0 {
		return MatchResult{}, fmt.Errorf("dead-end decoder node at depth %d", depth)
	}

	key := nodeKey(node, word)
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		if child.Value == key {
			return matchNode(child, word, depth+1)
		}
	}

	return MatchResult{}, fmt.Errorf("no decoder match for 0x%08X at depth %d (key=0x%X mask=0x%X)", word, depth, key, node.Mask)
}

// matchLeaf resolves a terminal node. Its candidate list is complete for every
// word routed here, so the peers reported in Ambiguous are exactly the ones
// MatchByPattern would report over the whole instruction set.
func matchLeaf(node *ir.DecoderNode, word uint32, depth int) (MatchResult, error) {
	var hits []*ir.InstructionIR
	if node.Instruction != nil && ir.MatchWord(node.Instruction, word) {
		hits = append(hits, node.Instruction)
	}
	for _, a := range node.Ambiguous {
		if ir.MatchWord(a, word) {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 0:
		return MatchResult{Depth: depth}, fmt.Errorf("no leaf candidate matches 0x%08X at depth %d", word, depth)
	case 1:
		return MatchResult{Instruction: hits[0], Depth: depth}, nil
	default:
		return MatchResult{Ambiguous: hits, Depth: depth}, fmt.Errorf("ambiguous decode: %d candidates", len(hits))
	}
}

func nodeKey(node *ir.DecoderNode, word uint32) uint32 {
	if node.Mask != 0 {
		return word & node.Mask
	}
	if node.BitRange.End >= node.BitRange.Start && node.BitRange.Start >= 0 {
		width := node.BitRange.End - node.BitRange.Start + 1
		m := uint32((uint64(1) << uint(width)) - 1)
		return (word >> uint(node.BitRange.Start)) & m
	}
	return 0
}

// MatchByPattern scans a flat instruction list using BitPattern + bitdiffs (O(n)).
// Useful when a tree is not available or as a correctness oracle.
func MatchByPattern(instructions []*ir.InstructionIR, word uint32) []*ir.InstructionIR {
	var hits []*ir.InstructionIR
	for _, instr := range instructions {
		if instr == nil {
			continue
		}
		if ir.MatchWord(instr, word) {
			hits = append(hits, instr)
		}
	}
	return hits
}

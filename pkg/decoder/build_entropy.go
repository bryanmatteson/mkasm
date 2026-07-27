package decoder

import (
	"fmt"
	"maps"
	"slices"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// buildNodeWithEntropy constructs the decoder tree using the hybrid entropy strategy
func (b *DecoderTreeBuilder) buildNodeWithEntropy(instructions []*ir.InstructionIR, depth int, maxDepth int) *ir.DecoderNode {
	if len(instructions) == 0 {
		return nil
	}

	if len(instructions) == 1 || depth >= maxDepth {
		if len(instructions) == 1 {
			return &ir.DecoderNode{
				Instruction: instructions[0],
				Comment:     fmt.Sprintf("Leaf: %s", instructions[0].Mnemonic),
			}
		}
		return &ir.DecoderNode{
			Comment:   fmt.Sprintf("Ambiguous at depth %d: %d candidates", depth, len(instructions)),
			Ambiguous: instructions,
		}
	}

	best := b.findBestSplit(instructions)
	if best == nil {
		return &ir.DecoderNode{
			Comment:   fmt.Sprintf("Ambiguous fallback: %d candidates", len(instructions)),
			Ambiguous: instructions,
		}
	}

	mask := calculateMask(best)
	groups := b.groupByBitPattern(instructions, mask)

	node := &ir.DecoderNode{
		BitRange: *best,
		Mask:     mask,
		Comment:  fmt.Sprintf("Split: bits [%d:%d]", best.End, best.Start),
		Children: []*ir.DecoderNode{},
	}

	// Stable group order
	keys := slices.Sorted(maps.Keys(groups))
	for _, val := range keys {
		child := b.buildNodeWithEntropy(groups[val], depth+1, maxDepth)
		if child != nil {
			child.Value = val
			node.Children = append(node.Children, child)
		}
	}

	return node
}

// findBestSplit chooses the best bit range to split on (entropy + fixed-bit bonus),
// avoiding operand-overlapping fields. Ranges are held to the same replication
// budget and same shrink requirement as mask splits; see findBestMaskSplit.
func (b *DecoderTreeBuilder) findBestSplit(instructions []*ir.InstructionIR) *ir.BitRange {
	var best *ir.BitRange
	bestScore := 0.0
	operandBits := determineOperandBitSet(instructions)
	budget := maskSplitBudget * len(instructions)

	for start := 0; start <= 31; start++ {
		for width := 1; width <= 8 && start+width <= 32; width++ {
			skip := false
			for b := start; b < start+width; b++ {
				if operandBits[b] {
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			br := &ir.BitRange{Start: start, End: start + width - 1}
			mask := calculateMask(br)
			if mask == 0 || b.replicationCost(instructions, mask, budget) > budget {
				continue
			}
			counts, total, largest := b.splitCounts(instructions, mask)
			if len(counts) <= 1 || largest >= len(instructions) {
				continue
			}
			score := normalizedEntropy(counts, total)*float64(len(instructions))/float64(total) +
				countFixedBits(instructions, br)*0.1
			if score > bestScore {
				best = br
				bestScore = score
			}
		}
	}
	return best
}

// determineOperandBitSet finds bits used for operands to exclude from tree splits
func determineOperandBitSet(instructions []*ir.InstructionIR) map[int]bool {
	bitset := make(map[int]bool)
	for _, instr := range instructions {
		for _, f := range instr.Encoding.Fields {
			if f.Start < 0 || f.End < f.Start {
				continue
			}
			for b := f.Start; b <= f.End && b < 32; b++ {
				bitset[b] = true
			}
		}
	}
	return bitset
}

// groupByBitPattern files an instruction under every key in the split range it
// can match; see groupByMask for why replication and not a wildcard bucket.
//
// Keys are the masked word (not the range shifted down to bit 0) because the
// node carries a non-zero Mask, and both walkers take the masked-word branch
// whenever Mask is set — a shifted child Value could never be reached.
func (b *DecoderTreeBuilder) groupByBitPattern(instructions []*ir.InstructionIR, mask uint32) map[uint32][]*ir.InstructionIR {
	groups := make(map[uint32][]*ir.InstructionIR)
	for _, instr := range instructions {
		b.eachMaskKey(instr, mask, func(key uint32) {
			groups[key] = append(groups[key], instr)
		})
	}
	return groups
}

// rangesOverlap checks if two bit ranges overlap
func rangesOverlap(field ir.BitField, bitRange *ir.BitRange) bool {
	if bitRange == nil || field.Start < 0 || field.End < field.Start {
		return false
	}
	if bitRange.Start < 0 || bitRange.End < bitRange.Start {
		return false
	}
	return field.Start <= bitRange.End && field.End >= bitRange.Start
}

// countFixedBits counts how many instructions have fixed bits in the range
func countFixedBits(instructions []*ir.InstructionIR, bitRange *ir.BitRange) float64 {
	count := 0
	fixedOverlap := func(f ir.BitField) bool { return f.Fixed != nil && rangesOverlap(f, bitRange) }

	for _, instr := range instructions {
		if slices.ContainsFunc(instr.Encoding.Fields, fixedOverlap) {
			count++
		}
	}

	return float64(count) / float64(len(instructions))
}

// calculateMask calculates the bit mask for a range
func calculateMask(bitRange *ir.BitRange) uint32 {
	if bitRange == nil || bitRange.Start < 0 || bitRange.End < bitRange.Start {
		return 0
	}
	width := bitRange.End - bitRange.Start + 1
	if width <= 0 || width > 32 || bitRange.Start+width > 32 {
		return 0
	}
	return uint32((uint64(1)<<uint(width))-1) << uint(bitRange.Start)
}

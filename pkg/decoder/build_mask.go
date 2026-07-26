package decoder

import (
	"fmt"
	"maps"
	"math"
	"math/bits"
	"slices"

	"mkasm/pkg/ir"
)

// maskSplitBudget bounds how far a single split may duplicate the candidate set.
// A field that is fixed for one encoding is a register or immediate field for
// most of its neighbours, so filing those neighbours under every key they can
// reach multiplies the set by 2^(free bits under the mask). Rd[4:0] is fixed in
// RET and free in nearly everything else, so splitting on it would copy most of
// A64 thirty-two times; the cap keeps such fields out of the tree and leaves the
// wide opcode fields the A64 decode hierarchy is actually built from.
const maskSplitBudget = 4

// buildNodeWithMask uses field-derived bitmask splits to construct the decoder tree
func (b *DecoderTreeBuilder) buildNodeWithMask(instructions []*ir.InstructionIR, depth int, maxDepth int) *ir.DecoderNode {
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
		// Preserve all remaining candidates instead of silently dropping them.
		return &ir.DecoderNode{
			Comment:   fmt.Sprintf("Ambiguous at depth %d: %d candidates", depth, len(instructions)),
			Ambiguous: instructions,
		}
	}

	bestMask := b.findBestMaskSplit(instructions)
	if bestMask == nil {
		return &ir.DecoderNode{
			Comment:   fmt.Sprintf("Ambiguous fallback: %d candidates", len(instructions)),
			Ambiguous: instructions,
		}
	}

	groups := b.groupByMask(instructions, bestMask)

	node := &ir.DecoderNode{
		Mask:     bestMask.Mask,
		Comment:  fmt.Sprintf("Switch on mask 0x%08X", bestMask.Mask),
		Children: []*ir.DecoderNode{},
	}

	keys := slices.Sorted(maps.Keys(groups))
	for _, key := range keys {
		if child := b.buildNodeWithMask(groups[key], depth+1, maxDepth); child != nil {
			child.Value = key
			node.Children = append(node.Children, child)
		}
	}

	return node
}

// findBestMaskSplit scores each admissible mask by information gain per unit of
// duplication. A mask that leaves the largest group at full size is rejected:
// under replication such a mask rebuilds the whole candidate set beneath every
// key, so the recursion would fan out 2^width wide at every remaining depth.
func (b *DecoderTreeBuilder) findBestMaskSplit(instructions []*ir.InstructionIR) *ir.BitMask {
	var best *ir.BitMask
	bestScore := 0.0

	for _, bm := range b.collectFieldMasks(instructions) {
		counts, total, largest := b.splitCounts(instructions, bm.Mask)
		if len(counts) <= 1 || largest >= len(instructions) {
			continue
		}
		score := normalizedEntropy(counts, total) * float64(len(instructions)) / float64(total)
		if score > bestScore {
			best = bm
			bestScore = score
		}
	}
	return best
}

// collectFieldMasks creates masks from fields that are fixed in some candidate,
// dropping any whose replication would exceed maskSplitBudget.
func (b *DecoderTreeBuilder) collectFieldMasks(instructions []*ir.InstructionIR) []*ir.BitMask {
	budget := maskSplitBudget * len(instructions)
	seen := map[uint32]bool{}
	masks := []*ir.BitMask{}

	for _, instr := range instructions {
		for _, f := range instr.Encoding.Fields {
			if f.Fixed == nil {
				continue
			}
			if f.Start < 0 || f.End < f.Start || f.Start > 31 {
				continue
			}
			width := f.End - f.Start + 1
			if width <= 0 || width > 32 || f.Start+width > 32 {
				continue
			}
			mask := uint32((uint64(1)<<uint(width))-1) << uint(f.Start)
			if mask == 0 || seen[mask] {
				continue
			}
			seen[mask] = true
			if b.replicationCost(instructions, mask, budget) > budget {
				continue
			}
			masks = append(masks, &ir.BitMask{Mask: mask})
		}
	}
	return masks
}

// replicationCost is the size the candidate set grows to once every instruction
// is filed under each key it can match. It stops counting past limit so a mask
// over a wide free field costs a scan, not 2^32 additions.
func (b *DecoderTreeBuilder) replicationCost(instructions []*ir.InstructionIR, mask uint32, limit int) int {
	total := 0
	for _, instr := range instructions {
		pinned, _ := b.pinnedBits(instr)
		free := bits.OnesCount32(mask &^ pinned)
		if free > 30 {
			return limit + 1
		}
		total += 1 << uint(free)
		if total > limit {
			return total
		}
	}
	return total
}

// splitCounts reports the group sizes a mask produces without materializing the
// groups, so scoring every candidate mask stays allocation-free.
func (b *DecoderTreeBuilder) splitCounts(instructions []*ir.InstructionIR, mask uint32) (counts map[uint32]int, total, largest int) {
	counts = map[uint32]int{}
	for _, instr := range instructions {
		b.eachMaskKey(instr, mask, func(key uint32) {
			counts[key]++
			total++
			if counts[key] > largest {
				largest = counts[key]
			}
		})
	}
	return counts, total, largest
}

// normalizedEntropy is Shannon entropy over group sizes, scaled to [0,1].
func normalizedEntropy(counts map[uint32]int, total int) float64 {
	if len(counts) <= 1 || total == 0 {
		return 0
	}
	entropy := 0.0
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	if maxEntropy := math.Log2(float64(len(counts))); maxEntropy > 0 {
		return entropy / maxEntropy
	}
	return entropy
}

// groupByMask files an instruction under every key it can match, not only the
// one obtained by zeroing its variable bits. A mask is chosen because it is a
// fixed field of *some* candidate; the rest usually have 'x' bits under it, and
// filing those under the single zeroed key is what made the walker dead-end on
// every word that set them.
//
// Replication is preferred over a per-node wildcard bucket because it is what
// makes a leaf's candidate list complete: a bucket the walker only consults on
// key miss would leave a leaf looking unique while a wildcard peer also matched,
// and Decoded.Ambiguous would understate the flat matcher again.
func (b *DecoderTreeBuilder) groupByMask(instructions []*ir.InstructionIR, bm *ir.BitMask) map[uint32][]*ir.InstructionIR {
	out := map[uint32][]*ir.InstructionIR{}
	for _, instr := range instructions {
		b.eachMaskKey(instr, bm.Mask, func(key uint32) {
			out[key] = append(out[key], instr)
		})
	}
	return out
}

// eachMaskKey visits every value of (word & mask) that instr's pinned bits allow.
func (b *DecoderTreeBuilder) eachMaskKey(instr *ir.InstructionIR, mask uint32, visit func(uint32)) {
	pinned, value := b.pinnedBits(instr)
	base := value & pinned & mask
	free := mask &^ pinned
	if free == 0 {
		visit(base)
		return
	}
	// Submask enumeration: sub runs over every subset of the free bits.
	for sub := free; ; sub = (sub - 1) & free {
		visit(base | sub)
		if sub == 0 {
			return
		}
	}
}

// pinnedBits returns the (mask, value) a word must satisfy to match instr,
// following the same fallback chain emitDecoderSource uses for the flat table
// entry so the tree and the flat matcher never disagree on what an encoding
// pins. Results are cached: scoring re-derives them once per mask per node
// otherwise, and each derivation scans a 32-byte pattern string.
func (b *DecoderTreeBuilder) pinnedBits(instr *ir.InstructionIR) (mask, value uint32) {
	if v, ok := b.pins[instr]; ok {
		return v[0], v[1]
	}
	pat := instr.BitPattern
	if !hasFixedBit(pat) {
		pat = ir.PatternFromEncoding(instr.Encoding)
	}
	mask, value = ir.FixedBitsFromPattern(pat)
	if mask == 0 {
		mask, value = ir.FixedBitsFromEncoding(instr.Encoding)
	}
	if b.pins == nil {
		b.pins = map[*ir.InstructionIR][2]uint32{}
	}
	b.pins[instr] = [2]uint32{mask, value}
	return mask, value
}

func hasFixedBit(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '0' || pattern[i] == '1' {
			return true
		}
	}
	return false
}

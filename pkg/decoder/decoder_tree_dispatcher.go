package decoder

import (
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"slices"
)

const (
	// DefaultMaxDepth is the maximum depth for the decoder tree
	DefaultMaxDepth = 31

	BitMaskStrategy = "mask"    // Use bitmask-based splitting
	EntropyStrategy = "entropy" // Use entropy-based splitting
)

// FeatureMap defines which features are enabled.
type FeatureMap map[string]bool

type DecoderTreeBuilder struct {
	// pins caches pinnedBits per candidate for the duration of one BuildTree.
	// Keyed by pointer, so it is dropped on entry: callers mutate instructions
	// between passes and a stale pin would misfile the encoding.
	pins map[*ir.InstructionIR][2]uint32
}

// BuildTree constructs a decoder tree for all instructions
func (b *DecoderTreeBuilder) BuildTree(instructions []*ir.InstructionIR, enabled FeatureMap) *ir.DecoderTree {
	b.pins = nil
	insts, strategy := b.filterAndDetermineStrategy(instructions, enabled)
	tree := &ir.DecoderTree{}
	switch strategy {
	case BitMaskStrategy:
		tree.Root = b.buildNodeWithMask(insts, 0, DefaultMaxDepth)
	case EntropyStrategy:
		tree.Root = b.buildNodeWithEntropy(insts, 0, DefaultMaxDepth)
	}
	return tree
}

func (b *DecoderTreeBuilder) filterAndDetermineStrategy(instructions []*ir.InstructionIR, enabled FeatureMap) ([]*ir.InstructionIR, string) {
	var total, fixed int
	out := make([]*ir.InstructionIR, 0, len(instructions))
	for _, instr := range instructions {
		if !featureSetSatisfied(instr.Features.Tags, enabled) {
			continue // skip if features not supported
		}
		if instr.Encoding.Width <= 0 || len(instr.Encoding.Fields) == 0 {
			continue // skip if no valid encoding
		}
		total += len(instr.Encoding.Fields)
		fixed += sliceCount(instr.Encoding.Fields, func(f ir.BitField) bool { return f.Fixed != nil })
		out = append(out, instr)
	}

	if total == 0 || float64(fixed)/float64(total) < 0.6 {
		return out, EntropyStrategy
	}
	return out, BitMaskStrategy
}

func sliceCount[T any](s []T, pred func(T) bool) int {
	count := 0
	for _, v := range s {
		if pred(v) {
			count++
		}
	}
	return count
}

// FeatureSetSatisfied checks if all required features are present.
func featureSetSatisfied(features []ir.FeatureTag, enabled FeatureMap) bool {
	// Does not contain any features that are required but not enabled
	return len(enabled) == 0 || !slices.ContainsFunc(features, func(f ir.FeatureTag) bool {
		return f.Required && !enabled[f.Name]
	})
}

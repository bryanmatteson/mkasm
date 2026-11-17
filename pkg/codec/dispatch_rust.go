package codec

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Each branch tests a fixed instruction bit. Wildcard encodings occur in both
// children; splitting only when both children shrink bounds redundant work.
// Leaves retain specificity order, including the original order of ties.
// A short buffer uses the full ordered list, so a late discriminator cannot
// hide a valid shorter instruction or change Unknown versus Truncated.
type rustDecodeNode struct{ bit, zero, one uint32 }
type rustDecodeTree struct {
	nodes             []rustDecodeNode
	candidates, order []int
}

func buildRustDecodeTree(encodings []Encoding) rustDecodeTree {
	var tree rustDecodeTree
	maxBits := 0
	for i, e := range encodings {
		if e.AssemblyOnly {
			continue
		}
		tree.order = append(tree.order, i)
		if len(e.Mask)*8 > maxBits {
			maxBits = len(e.Mask) * 8
		}
	}
	sort.SliceStable(tree.order, func(i, j int) bool {
		return specificity(&encodings[tree.order[i]]) > specificity(&encodings[tree.order[j]])
	})
	seen := make(map[string]uint32)
	limit := max(64, len(tree.order)*4)
	var build func([]int, int) uint32
	build = func(ids []int, depth int) uint32 {
		key := make([]byte, len(ids)*4)
		for i, id := range ids {
			binary.LittleEndian.PutUint32(key[i*4:], uint32(id))
		}
		if index, ok := seen[string(key)]; ok {
			return index
		}
		index := uint32(len(tree.nodes))
		seen[string(key)] = index
		tree.nodes = append(tree.nodes, rustDecodeNode{})
		bit, bestMax, bestTotal := -1, len(ids), len(ids)*2
		if len(ids) > 8 && depth < 20 && len(tree.nodes) < limit {
			// Never inspect beyond the shortest candidate. Otherwise decoding a
			// complete short instruction could fall back to the entire catalog.
			availableBits := maxBits
			for _, id := range ids {
				availableBits = min(availableBits, len(encodings[id].Mask)*8)
			}
			for p := 0; p < availableBits; p++ {
				zero, one := 0, 0
				for _, id := range ids {
					e := &encodings[id]
					if p/8 >= len(e.Mask) || e.Mask[p/8]&(1<<uint(p%8)) == 0 {
						zero++
						one++
					} else if e.Value[p/8]&(1<<uint(p%8)) == 0 {
						zero++
					} else {
						one++
					}
				}
				maximum := max(zero, one)
				if maximum < bestMax || maximum == bestMax && maximum < len(ids) && zero+one < bestTotal {
					bit, bestMax, bestTotal = p, maximum, zero+one
				}
			}
		}
		if bit < 0 {
			start := len(tree.candidates)
			tree.candidates = append(tree.candidates, ids...)
			tree.nodes[index] = rustDecodeNode{^uint32(0), uint32(start), uint32(len(ids))}
		} else {
			zero, one := make([]int, 0, bestMax), make([]int, 0, bestMax)
			for _, id := range ids {
				e := &encodings[id]
				if bit/8 >= len(e.Mask) || e.Mask[bit/8]&(1<<uint(bit%8)) == 0 {
					zero = append(zero, id)
					one = append(one, id)
				} else if e.Value[bit/8]&(1<<uint(bit%8)) == 0 {
					zero = append(zero, id)
				} else {
					one = append(one, id)
				}
			}
			left := build(zero, depth+1)
			right := build(one, depth+1)
			tree.nodes[index] = rustDecodeNode{uint32(bit), left, right}
		}
		return index
	}
	build(tree.order, 0)
	return tree
}

func writeRustDecodeTree(b *strings.Builder, encodings []Encoding) {
	tree := buildRustDecodeTree(encodings)
	b.WriteString("// (instruction bit, zero child/start, one child/count); u32::MAX marks a leaf.\nstatic DECODE_TREE:&[(u32,u32,u32)]=&[\n")
	for _, n := range tree.nodes {
		fmt.Fprintf(b, "(%d,%d,%d),\n", n.bit, n.zero, n.one)
	}
	b.WriteString("];\nstatic DECODE_CANDIDATES:&[u32]=&[")
	for _, id := range tree.candidates {
		fmt.Fprintf(b, "%d,", id)
	}
	b.WriteString("];\nstatic DECODE_ORDER:&[u32]=&[")
	for _, id := range tree.order {
		fmt.Fprintf(b, "%d,", id)
	}
	b.WriteString("];\n")
}

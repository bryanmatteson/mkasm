package arm

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Dispatch only rejects impossible fixed masks. Full allocation/alias predicates
// remain with their consumers, and leaves retain the supplied preference order.
type rustMaskValue struct{ mask, value uint32 }
type rustMaskedNode struct{ bit, zero, one uint32 }
type rustMaskedDispatch struct {
	entries    []rustMaskValue
	nodes      []rustMaskedNode
	candidates []uint16
	seen       map[string]uint32
}

func newRustMaskedDispatch(entries []rustMaskValue) *rustMaskedDispatch {
	return &rustMaskedDispatch{entries: entries, seen: make(map[string]uint32)}
}
func (d *rustMaskedDispatch) add(ids []uint16) uint32 { return d.build(ids, 4*len(ids), 0) }
func (d *rustMaskedDispatch) build(ids []uint16, budget, depth int) uint32 {
	key := make([]byte, 2*len(ids))
	for i, id := range ids {
		binary.LittleEndian.PutUint16(key[2*i:], id)
	}
	if index, ok := d.seen[string(key)]; ok {
		return index
	}
	index := uint32(len(d.nodes))
	d.seen[string(key)] = index
	d.nodes = append(d.nodes, rustMaskedNode{})
	bit, bestMax, bestTotal := -1, len(ids), 2*len(ids)
	if len(ids) > 8 && depth < 20 {
		for p := 0; p < 32; p++ {
			var zero, one int
			mask := uint32(1) << p
			for _, id := range ids {
				e := d.entries[id]
				if e.mask&mask == 0 {
					zero++
					one++
				} else if e.value&mask == 0 {
					zero++
				} else {
					one++
				}
			}
			maximum := max(zero, one)
			if zero+one <= budget && (maximum < bestMax || maximum == bestMax && maximum < len(ids) && zero+one < bestTotal) {
				bit, bestMax, bestTotal = p, maximum, zero+one
			}
		}
	}
	if bit < 0 {
		start := len(d.candidates)
		d.candidates = append(d.candidates, ids...)
		d.nodes[index] = rustMaskedNode{0, uint32(start), uint32(len(ids))}
	} else {
		zero, one := make([]uint16, 0, bestMax), make([]uint16, 0, bestMax)
		mask := uint32(1) << bit
		for _, id := range ids {
			e := d.entries[id]
			if e.mask&mask == 0 {
				zero = append(zero, id)
				one = append(one, id)
			} else if e.value&mask == 0 {
				zero = append(zero, id)
			} else {
				one = append(one, id)
			}
		}
		// Reserve both children's unsplit lists before distributing extra capacity.
		// Thus a root uses at most four candidate references per source candidate.
		extra := budget - len(zero) - len(one)
		left := d.build(zero, len(zero)+extra/2, depth+1)
		right := d.build(one, len(one)+extra-extra/2, depth+1)
		d.nodes[index] = rustMaskedNode{mask, left, right}
	}
	return index
}
func (d *rustMaskedDispatch) emit(prefix string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "static %s_TREE:&[(u32,u32,u32)]=&[\n", prefix)
	for _, n := range d.nodes {
		fmt.Fprintf(&b, "(%d,%d,%d),\n", n.bit, n.zero, n.one)
	}
	fmt.Fprintf(&b, "];\nstatic %s_CANDIDATES:&[u16]=&[", prefix)
	for _, id := range d.candidates {
		fmt.Fprintf(&b, "%d,", id)
	}
	b.WriteString("];\n")
	return b.String()
}

package arm

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestRustMaskedDispatchPreservesWildcardsOrderAndBudget(t *testing.T) {
	rng := rand.New(rand.NewSource(9183))
	masks := make([]rustMaskValue, 64)
	order := make([]uint16, len(masks))
	for i := range masks {
		mask := uint32(rng.Uint32()&rng.Uint32()) & 65535
		masks[i] = rustMaskValue{mask, uint32(rng.Uint32()) & mask}
		order[i] = uint16(len(masks) - 1 - i)
	}
	// Include a full wildcard, zero-width masks and overlapping fixed rows.
	masks[0] = rustMaskValue{}
	masks[1] = rustMaskValue{65535, 0x1234}
	masks[2] = masks[1]
	d := newRustMaskedDispatch(masks)
	root := d.add(order)
	if len(d.nodes) <= 1 {
		t.Fatal("fixture did not split")
	}
	if len(d.candidates) > 4*len(order) {
		t.Fatalf("candidate budget exceeded: %d", len(d.candidates))
	}
	candidates := func(word uint32) []uint16 {
		node := root
		for steps := 0; steps <= 20; steps++ {
			n := d.nodes[node]
			if n.bit == 0 {
				return d.candidates[n.zero : n.zero+n.one]
			}
			if word&n.bit == 0 {
				node = n.zero
			} else {
				node = n.one
			}
		}
		t.Fatal("dispatch exceeded depth bound")
		return nil
	}
	filter := func(ids []uint16, word uint32) []uint16 {
		var out []uint16
		for _, id := range ids {
			e := masks[id]
			if word&e.mask == e.value {
				out = append(out, id)
			}
		}
		return out
	}
	for word := uint32(0); word < 65536; word++ {
		got, want := filter(candidates(word), word), filter(order, word)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%x: %v != %v", word, got, want)
		}
	}
	nodes, refs := len(d.nodes), len(d.candidates)
	if d.add(order) != root || len(d.nodes) != nodes || len(d.candidates) != refs {
		t.Fatal("identical roots did not share their immutable tables")
	}
	// A root with a different preference order must retain that order.
	reversed := append([]uint16(nil), order...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	other := d.add(reversed)
	if other == root {
		t.Fatal("different preference orders were conflated")
	}
}
func TestRustMaskedDispatchUsesHighInstructionBits(t *testing.T) {
	masks := make([]rustMaskValue, 32)
	ids := make([]uint16, 32)
	for i := range masks {
		masks[i] = rustMaskValue{0xf8000000, uint32(i) << 27}
		ids[i] = uint16(i)
	}
	d := newRustMaskedDispatch(masks)
	root := d.add(ids)
	for i := range masks {
		word := uint32(i) << 27
		node := root
		for d.nodes[node].bit != 0 {
			n := d.nodes[node]
			if word&n.bit == 0 {
				node = n.zero
			} else {
				node = n.one
			}
		}
		n := d.nodes[node]
		found := false
		for _, id := range d.candidates[n.zero : n.zero+n.one] {
			if id == uint16(i) {
				found = true
			}
		}
		if !found {
			t.Fatalf("lost high-bit row %d", i)
		}
	}
	empty := newRustMaskedDispatch(nil)
	index := empty.add(nil)
	if empty.nodes[index] != (rustMaskedNode{}) {
		t.Fatal(empty.nodes)
	}
}

// Narrow trees should keep their direct slices; adding another selector to them
// increases the cost of the common path instead of pruning a large source leaf.
func TestRustDecoderOnlyRefinesLargeSourceLeaves(t *testing.T) {
	for _, count := range []int{1, 64, 65, 128} {
		catalog := &Catalog{}
		for i := 0; i < count; i++ {
			catalog.Entries = append(catalog.Entries, CatalogEntry{
				EncodingID: fmt.Sprintf("E%d", i), Mnemonic: "OP", Pattern: "1010" + strings.Repeat("x", 28), Mask: 0xf0000000, Value: 0xa0000000,
				Fields: []CatalogField{{Name: "opcode", Start: 28, End: 31, Fixed: true}, {Name: "payload", Start: 0, End: 27, Free: 0x0fffffff}},
			})
		}
		data, err := buildRustDecoderData(catalog)
		if err != nil {
			t.Fatal(err)
		}
		if data.Adaptive != (count > 64) {
			t.Fatalf("%d entries: adaptive=%v", count, data.Adaptive)
		}
		if strings.Contains(data.Preferred, "SELECT_TREE") != data.Adaptive {
			t.Fatalf("%d entries: missing selected dispatch representation", count)
		}
		if strings.Contains(data.Preferred, "PREFERRED_ALL") == data.Adaptive {
			t.Fatalf("%d entries: redundant flat preference data", count)
		}
	}
}

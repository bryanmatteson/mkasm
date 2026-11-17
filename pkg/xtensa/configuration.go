package xtensa

import (
	"bytes"
	"fmt"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// ValidateConfiguration admits a resolved processor description, including TIE
// scalar opcodes and arbitrary FLIX lengths/slot placements. Byte order is part
// of the physical description; it is never inferred by reversing instructions.
func (c *Catalog) ValidateConfiguration() error {
	if c.Schema != "mkasm.xtensa.v1" || (c.Architecture != "xtensa" && c.Architecture != "xtensaeb") || c.Core == nil || c.Slots == nil {
		return fmt.Errorf("invalid Xtensa configuration header")
	}
	if c.Core.Architecture != c.Architecture || c.Slots.Architecture != c.Architecture {
		return fmt.Errorf("Xtensa configuration byte order mismatch")
	}
	if e := c.Core.Validate(); e != nil {
		return e
	}
	if len(c.Slots.Encodings) > 0 {
		if e := c.Slots.Validate(); e != nil {
			return e
		}
	}
	ids := map[string]bool{}
	slotIDs := map[string]bool{}
	for _, table := range []*codec.Catalog{c.Core, c.Slots} {
		for _, e := range table.Encodings {
			if ids[e.ID] {
				return fmt.Errorf("duplicate Xtensa encoding %s", e.ID)
			}
			ids[e.ID] = true
		}
	}
	for _, e := range c.Slots.Encodings {
		slotIDs[e.ID] = true
		if _, ok := c.Metadata[e.ID]; !ok {
			return fmt.Errorf("missing slot metadata for %s", e.ID)
		}
	}
	for id := range c.Metadata {
		if !slotIDs[id] {
			return fmt.Errorf("slot metadata without encoding %s", id)
		}
	}
	names := map[string]bool{}
	for fi, f := range c.Formats {
		if f.Name == "" || names[f.Name] || f.Length < 1 || f.Length > 256 {
			return fmt.Errorf("invalid Xtensa format %s", f.Name)
		}
		names[f.Name] = true
		if f.Scalar && len(f.Mask) == 0 {
			continue
		}
		if !f.Scalar && len(f.Mask) == 0 {
			present := false
			for _, m := range c.Metadata {
				present = present || m.Format == fi
			}
			if !present {
				continue
			}
		}
		if len(f.Mask) != f.Length || len(f.Value) != f.Length {
			return fmt.Errorf("format %s requires a physical mask/value", f.Name)
		}
		fixed := byte(0)
		for _, b := range f.Mask {
			fixed |= b
		}
		if fixed == 0 {
			return fmt.Errorf("format %s has no framing bits", f.Name)
		}
		for j := 0; j < fi; j++ {
			g := c.Formats[j]
			if len(g.Mask) == 0 {
				continue
			}
			disjoint := false
			for k := 0; k < len(g.Mask) && k < len(f.Mask); k++ {
				disjoint = disjoint || (g.Value[k]^f.Value[k])&g.Mask[k]&f.Mask[k] != 0
			}
			if !disjoint {
				return fmt.Errorf("ambiguous framing for %s and %s", g.Name, f.Name)
			}
		}
		for j := range f.Mask {
			if f.Value[j]&^f.Mask[j] != 0 {
				return fmt.Errorf("format %s value outside mask", f.Name)
			}
		}
		if f.Scalar {
			continue
		}
		if len(f.Slots) == 0 {
			return fmt.Errorf("empty FLIX format %s", f.Name)
		}
		used := append([]byte(nil), f.Mask...)
		seen := map[int]bool{}
		for _, slot := range f.Slots {
			if seen[slot] {
				return fmt.Errorf("duplicate format slot %d", slot)
			}
			seen[slot] = true
			var owned []byte
			count := 0
			for _, e := range c.Slots.Encodings {
				m, ok := c.Metadata[e.ID]
				if !ok || m.Format != fi || m.Slot != slot {
					continue
				}
				count++
				if len(e.Mask) != f.Length || len(m.Mask) != f.Length {
					return fmt.Errorf("slot %s length mismatch", e.ID)
				}
				if owned == nil {
					owned = append([]byte(nil), m.Mask...)
				} else if !bytes.Equal(owned, m.Mask) {
					return fmt.Errorf("slot %d has inconsistent physical ownership", slot)
				}
				for j := range m.Mask {
					if e.Value[j]&^m.Mask[j] != 0 || e.Mask[j]&f.Mask[j]&m.Mask[j] != f.Mask[j]&m.Mask[j] || (e.Value[j]^f.Value[j])&f.Mask[j]&m.Mask[j] != 0 {
						return fmt.Errorf("slot %s conflicts with format bits", e.ID)
					}
				}
				for _, o := range e.Operands {
					for _, s := range o.Bits {
						for bit := s.InstructionBit; bit < s.InstructionBit+s.Width; bit++ {
							if m.Mask[bit/8]&(1<<uint(bit%8)) == 0 {
								return fmt.Errorf("slot %s operand outside its slot", e.ID)
							}
						}
					}
				}
			}
			if count == 0 {
				return fmt.Errorf("format %s has no definitions for slot %d", f.Name, slot)
			}
			for j, b := range owned {
				if used[j]&b&^f.Mask[j] != 0 {
					return fmt.Errorf("overlapping FLIX slots in %s", f.Name)
				}
				used[j] |= b
			}
		}
		for _, b := range used {
			if b != 255 {
				return fmt.Errorf("format %s has unspecified bits", f.Name)
			}
		}
	}
	for id, m := range c.Metadata {
		if m.Format < 0 || m.Format >= len(c.Formats) || c.Formats[m.Format].Scalar {
			return fmt.Errorf("invalid slot format for %s", id)
		}
		found := false
		for _, s := range c.Formats[m.Format].Slots {
			found = found || s == m.Slot
		}
		if !found {
			return fmt.Errorf("undeclared slot for %s", id)
		}
	}
	return nil
}

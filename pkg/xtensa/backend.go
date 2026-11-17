package xtensa

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type Catalog struct {
	Schema       string              `json:"schema"`
	Architecture string              `json:"architecture"`
	Core         *codec.Catalog      `json:"instructions"`
	Slots        *codec.Catalog      `json:"slots"`
	Formats      []Format            `json:"formats"`
	Metadata     map[string]SlotMeta `json:"slot_metadata"`
}

func newBackend(core *codec.Catalog) *Catalog {
	c := &Catalog{Schema: "mkasm.xtensa.v1", Architecture: core.Architecture, Core: core, Slots: &codec.Catalog{Schema: codec.Schema, Architecture: core.Architecture}, Metadata: map[string]SlotMeta{}}
	return c
}
func (c *Catalog) InstructionCatalog() *codec.Catalog { return c.Core }
func (c *Catalog) WriteJSON(w io.Writer) error        { return json.NewEncoder(w).Encode(c) }

type Instruction struct {
	ID     string           `json:"id"`
	Values map[string]int64 `json:"values"`
}
type Decoded struct {
	Format       string        `json:"format"`
	Instructions []Instruction `json:"instructions"`
	Length       int           `json:"length"`
}

func (c *Catalog) Length(src []byte) (int, error) {
	if len(src) == 0 {
		return 0, codec.ErrTruncated
	}
	for _, f := range c.Formats {
		if len(f.Mask) == 0 {
			continue
		}
		match := true
		for i := 0; i < min(len(src), f.Length); i++ {
			if src[i]&f.Mask[i] != f.Value[i] {
				match = false
				break
			}
		}
		if match {
			if len(src) < f.Length {
				return 0, codec.ErrTruncated
			}
			return f.Length, nil
		}
	}
	op := src[0] & 15
	if c.Architecture == "xtensaeb" {
		op = src[0] >> 4
	}
	length := 3
	if op >= 8 && op < 14 {
		length = 2
	} else if op >= 14 {
		length = 8
	}
	if len(src) < length {
		return 0, codec.ErrTruncated
	}
	return length, nil
}
func (c *Catalog) Decode(src []byte) (*Decoded, error) { return c.DecodeWithFeatures(src, nil) }
func (c *Catalog) DecodeWithFeatures(src []byte, features []string) (*Decoded, error) {
	length, err := c.Length(src)
	if err != nil {
		return nil, err
	}
	fi := -1
	scalar := length < 8
	for _, f := range c.Formats {
		if f.Scalar && len(f.Mask) == length {
			match := true
			for j := range f.Mask {
				match = match && src[j]&f.Mask[j] == f.Value[j]
			}
			if match {
				scalar = true
				break
			}
		}
	}
	for i, f := range c.Formats {
		if !f.Scalar && len(f.Mask) == length && length == f.Length {
			ok := true
			for j := range f.Mask {
				if src[j]&f.Mask[j] != f.Value[j] {
					ok = false
					break
				}
			}
			if ok {
				fi = i
				break
			}
		}
	}
	if fi < 0 && scalar {
		d, err := c.Core.DecodeWithFeatures(src[:length], features)
		if err != nil {
			return nil, err
		}
		return &Decoded{Format: "scalar", Instructions: []Instruction{{ID: d.Encoding.ID, Values: d.Values}}, Length: length}, nil
	}
	if fi < 0 {
		return nil, codec.ErrUnknown
	}
	out := &Decoded{Format: c.Formats[fi].Name, Length: length}
	for _, slot := range c.Formats[fi].Slots {
		var found *codec.Decoded
		for i := range c.Slots.Encodings {
			e := &c.Slots.Encodings[i]
			m := c.Metadata[e.ID]
			if m.Slot != slot || m.Format != fi {
				continue
			}
			b := make([]byte, length)
			for j := range b {
				b[j] = src[j] & m.Mask[j]
			}
			single := codec.Catalog{Architecture: c.Architecture, Encodings: []codec.Encoding{*e}}
			d, err := single.DecodeWithFeatures(b, features)
			if err == nil {
				found = d
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("Xtensa: unknown FLIX slot %d", slot)
		}
		out.Instructions = append(out.Instructions, Instruction{ID: found.Encoding.ID, Values: found.Values})
	}
	return out, nil
}
func (c *Catalog) entry(id string) (*codec.Encoding, error) {
	for _, table := range []*codec.Catalog{c.Core, c.Slots} {
		for i := range table.Encodings {
			if table.Encodings[i].ID == id {
				return &table.Encodings[i], nil
			}
		}
	}
	return nil, fmt.Errorf("Xtensa: unknown encoding %s", id)
}
func (c *Catalog) Encode(d Decoded) ([]byte, error) {
	if d.Format == "scalar" || d.Format == "" {
		if len(d.Instructions) != 1 {
			return nil, fmt.Errorf("Xtensa scalar requires one instruction")
		}
		i := d.Instructions[0]
		return c.Core.Encode(i.ID, i.Values)
	}
	fi := -1
	for n, f := range c.Formats {
		if f.Name == d.Format && !f.Scalar && len(f.Mask) == f.Length {
			fi = n
		}
	}
	if fi < 0 {
		return nil, fmt.Errorf("Xtensa: unknown format %q", d.Format)
	}
	format := c.Formats[fi]
	if len(d.Instructions) != len(format.Slots) {
		return nil, fmt.Errorf("Xtensa %s requires %d slots", d.Format, len(format.Slots))
	}
	out := append([]byte(nil), format.Value...)
	for n, i := range d.Instructions {
		m, ok := c.Metadata[i.ID]
		if !ok || m.Format != fi || m.Slot != format.Slots[n] {
			return nil, fmt.Errorf("Xtensa: %s is illegal in slot %d", i.ID, n)
		}
		b, err := c.Slots.Encode(i.ID, i.Values)
		if err != nil {
			return nil, err
		}
		for j := range b {
			out[j] |= b[j] & m.Mask[j]
		}
	}
	return out, nil
}
func (c *Catalog) Format(d *Decoded, address uint64) string {
	var text []string
	for _, i := range d.Instructions {
		e, err := c.entry(i.ID)
		if err != nil {
			return "<unknown>"
		}
		x := codec.Decoded{Encoding: e, Values: i.Values, Length: len(e.Mask)}
		text = append(text, x.Format(address))
	}
	if d.Format != "scalar" && d.Format != "" {
		return "{ " + strings.Join(text, "; ") + " }"
	}
	return strings.Join(text, "; ")
}
func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.AssembleWithFeatures(text, address, nil)
}
func (c *Catalog) AssembleWithFeatures(text string, address uint64, features []string) ([][]byte, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "{") {
		return c.Core.AssembleWithFeatures(text, address, features)
	}
	if !strings.HasSuffix(text, "}") {
		return nil, fmt.Errorf("Xtensa: unterminated FLIX bundle")
	}
	parts := strings.Split(strings.TrimSpace(text[1:len(text)-1]), ";")
	var result [][]byte
	for fi, f := range c.Formats {
		if f.Scalar || len(f.Mask) == 0 || len(f.Slots) != len(parts) {
			continue
		}
		partial := [][]Instruction{{}}
		for n, p := range parts {
			var next [][]Instruction
			for _, e := range c.Slots.Encodings {
				m := c.Metadata[e.ID]
				if m.Format != fi || m.Slot != f.Slots[n] {
					continue
				}
				single := codec.Catalog{Architecture: c.Architecture, Encodings: []codec.Encoding{e}}
				bb, err := single.AssembleWithFeatures(strings.TrimSpace(p), address, features)
				if err != nil {
					continue
				}
				for _, b := range bb {
					d, err := single.Decode(b)
					if err != nil {
						continue
					}
					for _, prev := range partial {
						v := append(append([]Instruction{}, prev...), Instruction{ID: e.ID, Values: d.Values})
						next = append(next, v)
					}
				}
			}
			partial = next
		}
		for _, v := range partial {
			b, err := c.Encode(Decoded{Format: f.Name, Instructions: v})
			if err == nil {
				result = append(result, b)
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("Xtensa: no legal FLIX format matches assembly")
	}
	return result, nil
}

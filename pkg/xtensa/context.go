package xtensa

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// ExecutionContext supplies runtime state that cannot be recovered from L32R's
// instruction bits. LITBASE bit zero enables extended literal addressing; the
// address base is LITBASE[31:12]<<12, plus the negative scaled displacement.
type ExecutionContext struct {
	PC      uint32 `json:"pc"`
	LITBASE uint32 `json:"litbase"`
}

func (c *Catalog) inContext(ctx ExecutionContext) *Catalog {
	if ctx.LITBASE&1 == 0 {
		return c
	}
	view := *c
	clone := func(source *codec.Catalog) *codec.Catalog {
		out := *source
		out.Encodings = append([]codec.Encoding(nil), source.Encodings...)
		for i := range out.Encodings {
			e := &out.Encodings[i]
			if e.Mnemonic != "l32r" {
				continue
			}
			e.Operands = append([]codec.Operand(nil), e.Operands...)
			for j := range e.Operands {
				o := &e.Operands[j]
				if o.Relative {
					o.PCBias = int64(ctx.LITBASE&0xfffff000) - int64(ctx.PC)
					o.PCPreAlignBias = 0
					o.PCAlignBits = 0
				}
			}
		}
		return &out
	}
	view.Core = clone(c.Core)
	view.Slots = clone(c.Slots)
	return &view
}

func (c *Catalog) FormatWithContext(d *Decoded, ctx ExecutionContext) string {
	return c.inContext(ctx).Format(d, uint64(ctx.PC))
}
func (c *Catalog) AssembleWithContext(text string, ctx ExecutionContext, features []string) ([][]byte, error) {
	return c.inContext(ctx).AssembleWithFeatures(text, uint64(ctx.PC), features)
}

// RelocateWithContext preserves all encoded address operands across changes in
// PC and literal-base state. Out-of-range replacements fail without mutation.
func (c *Catalog) RelocateWithContext(d *Decoded, from, to ExecutionContext) (*Decoded, error) {
	old, next := c.inContext(from), c.inContext(to)
	out := *d
	out.Instructions = make([]Instruction, len(d.Instructions))
	for i, in := range d.Instructions {
		a, e := old.entry(in.ID)
		if e != nil {
			return nil, e
		}
		b, e := next.entry(in.ID)
		if e != nil {
			return nil, e
		}
		values := map[string]int64{}
		for k, v := range in.Values {
			values[k] = v
		}
		for j, o := range a.Operands {
			if !o.Relative {
				continue
			}
			target, ok := o.Position().Target(uint64(from.PC), values[o.Name])
			if !ok {
				return nil, fmt.Errorf("Xtensa: cannot resolve operand %s", o.Name)
			}
			v, ok := b.Operands[j].Position().ValueForTarget(uint64(to.PC), target)
			if !ok {
				return nil, fmt.Errorf("Xtensa: operand %s leaves literal/PC region", o.Name)
			}
			values[o.Name] = v
		}
		out.Instructions[i] = Instruction{ID: in.ID, Values: values}
	}
	if _, e := c.Encode(out); e != nil {
		return nil, e
	}
	return &out, nil
}

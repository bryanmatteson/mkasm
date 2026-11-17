package cil

import (
	"slices"
	"strings"
)

// InstructionTemplate is reusable across streams and positions. Its fixed
// operand, when present, uses typed encoding values (branch displacements and
// complete switch displacement lists). A nil fixed operand captures the operand.
type InstructionTemplate struct {
	catalog *Catalog
	opcode  uint16
	fixed   *Operand
}

func cloneOperand(o *Operand) *Operand {
	if o == nil {
		return nil
	}
	x := *o
	if o.Targets != nil {
		x.Targets = append([]int32{}, o.Targets...)
	}
	return &x
}
func (c *Catalog) Template(mnemonic string) (*InstructionTemplate, error) {
	d := c.Lookup(strings.ToLower(mnemonic))
	if d == nil {
		return nil, malformed("unknown template mnemonic")
	}
	return &InstructionTemplate{catalog: c, opcode: d.Opcode}, nil
}
func (t *InstructionTemplate) Bind(o *Operand) error {
	if err := validateOperand(t.catalog.Definition(t.opcode), o); err != nil {
		return err
	}
	t.fixed = cloneOperand(o)
	return nil
}
func (t *InstructionTemplate) Encode(o *Operand, offset uint32) ([]byte, error) {
	if t.fixed != nil {
		if o != nil && !sameOperand(o, t.fixed) {
			return nil, malformed("template operand disagrees with fixed binding")
		}
		o = t.fixed
	}
	return t.catalog.Encode(&Instruction{Opcode: t.opcode, Operand: cloneOperand(o)}, offset)
}
func (t *InstructionTemplate) Match(src []byte, offset uint32) (*Instruction, bool) {
	in, err := t.catalog.Decode(src, offset)
	if err != nil || in.Opcode != t.opcode || t.fixed != nil && !sameOperand(t.fixed, in.Operand) {
		return nil, false
	}
	return in, true
}
func (c *Catalog) ParseTemplate(text string, offset uint32) (*InstructionTemplate, error) {
	name, operand := splitInstruction(text)
	t, err := c.Template(name)
	if err != nil {
		return nil, err
	}
	if operand == "_" || strings.HasPrefix(operand, "$") {
		if c.Definition(t.opcode).OperandKind == "none" {
			return nil, malformed("operand-free capture")
		}
		if strings.ContainsAny(operand, " \t(),") {
			return nil, malformed("invalid capture")
		}
		if operand != "_" {
			name := strings.TrimPrefix(operand, "$")
			if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
				name = name[1 : len(name)-1]
			}
			if name == "" {
				return nil, malformed("invalid capture")
			}
			for _, ch := range []byte(name) {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
					return nil, malformed("invalid capture")
				}
			}
		}
		return t, nil
	}
	b, err := c.Assemble(text, offset)
	if err != nil {
		return nil, err
	}
	in, err := c.Decode(b, offset)
	if err != nil {
		return nil, err
	}
	if err = t.Bind(in.Operand); err != nil {
		return nil, err
	}
	return t, nil
}

func sameOperand(a, b *Operand) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Kind == b.Kind && a.Value == b.Value && a.Bits == b.Bits && slices.Equal(a.Targets, b.Targets)
}

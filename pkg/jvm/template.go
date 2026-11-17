package jvm

import "fmt"

// InstructionTemplate fixes selected named operands and captures the remaining
// structured instruction when matching. Values use the encoding model, so branch
// operands are displacements and switch targets are opcode-relative offsets.
type InstructionTemplate struct {
	catalog     *Catalog
	definition  *Definition
	wide        bool
	fixed       map[string]int64
	switchValue *Switch
}

func (c *Catalog) Template(mnemonic string, wide bool) (*InstructionTemplate, error) {
	for i := range c.Instructions {
		d := &c.Instructions[i]
		if d.Mnemonic != mnemonic {
			continue
		}
		if d.Reserved || d.Opcode == 0xc4 || wide && !wideAllowed(d.Opcode) {
			return nil, malformed("invalid template opcode/mode")
		}
		return &InstructionTemplate{catalog: c, definition: d, wide: wide, fixed: map[string]int64{}}, nil
	}
	return nil, malformed("unknown template mnemonic " + mnemonic)
}

func (t *InstructionTemplate) Set(name string, value int64) error {
	in := representativeInstruction(*t.definition, t.wide)
	for i := range in.Operands {
		if in.Operands[i].Name != name {
			continue
		}
		in.Operands[i].Value = value
		if _, err := t.catalog.Encode(in, 0); err != nil {
			return err
		}
		t.fixed[name] = value
		return nil
	}
	return fmt.Errorf("JVM template: unknown operand %q", name)
}

func cloneSwitch(value *Switch) *Switch {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Targets = append([]int32(nil), value.Targets...)
	copy.Pairs = append([]LookupPair(nil), value.Pairs...)
	return &copy
}

func (t *InstructionTemplate) SetSwitch(value *Switch) error {
	if t.definition.Opcode != 0xaa && t.definition.Opcode != 0xab {
		return malformed("template opcode has no switch")
	}
	in := representativeInstruction(*t.definition, t.wide)
	in.Switch = cloneSwitch(value)
	if _, err := t.catalog.Encode(in, 0); err != nil {
		return err
	}
	t.switchValue = in.Switch
	return nil
}

func (t *InstructionTemplate) Encode(offset uint32) ([]byte, error) {
	in := representativeInstruction(*t.definition, t.wide)
	for i := range in.Operands {
		value, ok := t.fixed[in.Operands[i].Name]
		if !ok {
			return nil, malformed("missing template operand " + in.Operands[i].Name)
		}
		in.Operands[i].Value = value
	}
	if in.Switch != nil && t.switchValue == nil {
		return nil, malformed("missing template switch")
	}
	in.Switch = cloneSwitch(t.switchValue)
	return t.catalog.Encode(in, offset)
}

func (t *InstructionTemplate) Match(src []byte, offset uint32) (*Instruction, bool) {
	in, err := t.catalog.Decode(src, offset)
	if err != nil || in.Opcode != t.definition.Opcode || in.Wide != t.wide {
		return nil, false
	}
	for _, o := range in.Operands {
		if fixed, ok := t.fixed[o.Name]; ok && fixed != o.Value {
			return nil, false
		}
	}
	if t.switchValue != nil {
		a, b := t.switchValue, in.Switch
		if b == nil || a.Default != b.Default || a.Low != b.Low || len(a.Targets) != len(b.Targets) || len(a.Pairs) != len(b.Pairs) {
			return nil, false
		}
		for i, v := range a.Targets {
			if v != b.Targets[i] {
				return nil, false
			}
		}
		for i, v := range a.Pairs {
			if v != b.Pairs[i] {
				return nil, false
			}
		}
	}
	return in, true
}

package dex

import (
	"bytes"
	"slices"
)

// InstructionTemplate fixes selected operands and captures the complete decoded
// instruction on a match. Branch operands retain opcode-relative code units.
// Invoke registers and payloads are bound as complete structured values.
type InstructionTemplate struct {
	catalog    *Catalog
	definition *Definition
	version    int
	fixed      map[string]int64
	registers  []uint16
	listSet    bool
	rangeValue *RegisterRange
	payload    *Payload
}

func (c *Catalog) Template(mnemonic string) (*InstructionTemplate, error) {
	return c.TemplateVersion(mnemonic, LatestVersion)
}

func (c *Catalog) TemplateVersion(mnemonic string, version int) (*InstructionTemplate, error) {
	if !validVersion(version) {
		return nil, ErrVersion
	}
	for i := range c.Instructions {
		d := &c.Instructions[i]
		if d.Mnemonic == mnemonic && !d.Reserved {
			if version < d.MinVersion {
				return nil, ErrVersion
			}
			return &InstructionTemplate{catalog: c, definition: d, version: version, fixed: map[string]int64{}}, nil
		}
	}
	return nil, malformed("unknown template mnemonic " + mnemonic)
}

func templateInstruction(d *Definition) *Instruction {
	in := &Instruction{Opcode: d.Opcode, Values: map[string]int64{}}
	for _, f := range d.Fields {
		if f.Kind == "target" {
			in.Values[f.Name] = 1
		} else {
			in.Values[f.Name] = 0
		}
	}
	switch d.Format {
	case "35c", "45cc":
		in.Registers = []uint16{0}
	case "3rc", "4rcc":
		in.Range = &RegisterRange{Count: 1}
	}
	if d.Opcode >= 256 {
		in.Payload = &Payload{}
		if d.Opcode == 0x300 {
			in.Payload.ElementWidth = 1
		}
	}
	return in
}

func clonePayload(p *Payload) *Payload {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Keys = slices.Clone(p.Keys)
	copy.Targets = slices.Clone(p.Targets)
	copy.Data = bytes.Clone(p.Data)
	return &copy
}

func payloadEqual(a, b *Payload) bool {
	return a == nil && b == nil || a != nil && b != nil &&
		a.FirstKey == b.FirstKey && a.ElementWidth == b.ElementWidth &&
		slices.Equal(a.Keys, b.Keys) && slices.Equal(a.Targets, b.Targets) && bytes.Equal(a.Data, b.Data)
}

func (t *InstructionTemplate) Set(name string, value int64) error {
	in := templateInstruction(t.definition)
	if _, ok := in.Values[name]; !ok {
		return malformed("unknown template operand " + name)
	}
	in.Values[name] = value
	if _, err := t.catalog.EncodeVersion(in, 0, t.version); err != nil {
		return err
	}
	t.fixed[name] = value
	return nil
}

func (t *InstructionTemplate) SetRegisters(registers []uint16) error {
	if t.definition.Format != "35c" && t.definition.Format != "45cc" {
		return malformed("template has no invoke register list")
	}
	in := templateInstruction(t.definition)
	in.Registers = slices.Clone(registers)
	if _, err := t.catalog.EncodeVersion(in, 0, t.version); err != nil {
		return err
	}
	t.registers, t.listSet = in.Registers, true
	return nil
}

func (t *InstructionTemplate) SetRange(value RegisterRange) error {
	if t.definition.Format != "3rc" && t.definition.Format != "4rcc" {
		return malformed("template has no invoke register range")
	}
	in := templateInstruction(t.definition)
	in.Range = &value
	if _, err := t.catalog.EncodeVersion(in, 0, t.version); err != nil {
		return err
	}
	t.rangeValue = &value
	return nil
}

func (t *InstructionTemplate) SetPayload(value *Payload) error {
	if t.definition.Opcode < 256 || value == nil {
		return malformed("template requires a payload opcode and value")
	}
	in := templateInstruction(t.definition)
	in.Payload = clonePayload(value)
	if _, err := t.catalog.EncodeVersion(in, 0, t.version); err != nil {
		return err
	}
	t.payload = in.Payload
	return nil
}

func (t *InstructionTemplate) Encode(offset uint32) ([]byte, error) {
	in := templateInstruction(t.definition)
	for _, f := range t.definition.Fields {
		value, ok := t.fixed[f.Name]
		if !ok {
			return nil, malformed("missing template operand " + f.Name)
		}
		in.Values[f.Name] = value
	}
	if in.Registers != nil {
		if !t.listSet {
			return nil, malformed("missing template invoke registers")
		}
		in.Registers = slices.Clone(t.registers)
	}
	if in.Range != nil {
		if t.rangeValue == nil {
			return nil, malformed("missing template invoke range")
		}
		value := *t.rangeValue
		in.Range = &value
	}
	if in.Payload != nil {
		if t.payload == nil {
			return nil, malformed("missing template payload")
		}
		in.Payload = clonePayload(t.payload)
	}
	return t.catalog.EncodeVersion(in, offset, t.version)
}

func (t *InstructionTemplate) Match(src []byte, offset uint32) (*Instruction, bool) {
	in, err := t.catalog.DecodeVersion(src, offset, t.version)
	if err != nil || in.Opcode != t.definition.Opcode {
		return nil, false
	}
	for name, value := range t.fixed {
		if in.Values[name] != value {
			return nil, false
		}
	}
	if t.listSet && !slices.Equal(t.registers, in.Registers) ||
		t.rangeValue != nil && (in.Range == nil || *t.rangeValue != *in.Range) ||
		t.payload != nil && !payloadEqual(t.payload, in.Payload) {
		return nil, false
	}
	return in, true
}

package spirv

import "fmt"

// InstructionTemplate binds entire structured operands from a prototype. This
// preserves composite/enum parameters, strings and wide constants as typed data.
// Repeated names require equal operands; optional/variadic shape comes from the
// prototype. Encode validates substitutions in the supplied module context.
type InstructionTemplate struct {
	catalog   *Catalog
	prototype Instruction
	holes     map[int]string
}

func cloneOperand(o Operand) Operand {
	o.Words = append([]uint32(nil), o.Words...)
	parameters := make([]Operand, len(o.Parameters))
	for i, p := range o.Parameters {
		parameters[i] = cloneOperand(p)
	}
	o.Parameters = parameters
	return o
}

func (c *Catalog) Template(prototype Instruction, holes map[int]string) (*InstructionTemplate, error) {
	if c.ops[prototype.Opcode] == nil {
		return nil, fmt.Errorf("unknown template opcode %d", prototype.Opcode)
	}
	copy := Instruction{Opcode: prototype.Opcode, Operands: make([]Operand, len(prototype.Operands))}
	for i, o := range prototype.Operands {
		copy.Operands[i] = cloneOperand(o)
	}
	bindings := map[int]string{}
	for index, name := range holes {
		if index < 0 || index >= len(copy.Operands) || name == "" {
			return nil, fmt.Errorf("invalid template hole %d %q", index, name)
		}
		bindings[index] = name
	}
	return &InstructionTemplate{c, copy, bindings}, nil
}

func (t *InstructionTemplate) Match(instruction Instruction) (map[string]Operand, bool) {
	if instruction.Opcode != t.prototype.Opcode || len(instruction.Operands) != len(t.prototype.Operands) {
		return nil, false
	}
	captures := map[string]Operand{}
	for index, value := range instruction.Operands {
		if name, ok := t.holes[index]; ok {
			if previous, exists := captures[name]; exists && !equalOperands([]Operand{previous}, []Operand{value}) {
				return nil, false
			}
			captures[name] = cloneOperand(value)
		} else if !equalOperands([]Operand{t.prototype.Operands[index]}, []Operand{value}) {
			return nil, false
		}
	}
	return captures, true
}

func (t *InstructionTemplate) MatchBytes(data []byte, ctx *Context, env *Environment) (map[string]Operand, int, error) {
	in, n, err := t.catalog.Decode(data, ctx, env)
	if err != nil {
		return nil, 0, err
	}
	captures, ok := t.Match(in)
	if !ok {
		return nil, 0, fmt.Errorf("SPIR-V instruction does not match template")
	}
	return captures, n, nil
}

func (t *InstructionTemplate) Encode(bindings map[string]Operand, ctx *Context, env *Environment) ([]byte, error) {
	in := Instruction{Opcode: t.prototype.Opcode, Operands: make([]Operand, len(t.prototype.Operands))}
	used := map[string]bool{}
	for i, o := range t.prototype.Operands {
		if name, ok := t.holes[i]; ok {
			value, exists := bindings[name]
			if !exists {
				return nil, fmt.Errorf("missing template binding %q", name)
			}
			used[name] = true
			in.Operands[i] = cloneOperand(value)
		} else {
			in.Operands[i] = cloneOperand(o)
		}
	}
	if len(used) != len(bindings) {
		return nil, fmt.Errorf("unknown template binding")
	}
	return t.catalog.Encode(in, ctx, env)
}

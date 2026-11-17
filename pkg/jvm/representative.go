package jvm

// Legal instruction shapes for generated corpus smoke tests.
func representativeInstruction(d Definition, wide bool) *Instruction {
	in := &Instruction{Opcode: d.Opcode, Mnemonic: d.Mnemonic, Wide: wide}
	for _, o := range d.Operands {
		v := int64(1)
		if o.Signed {
			v = -3
		}
		if o.Kind == "array_type" {
			v = 10
		}
		if wide && o.Kind == "local" {
			v = 300
		}
		in.Operands = append(in.Operands, Operand{o.Name, o.Kind, v})
	}
	if d.Opcode == 0xaa {
		in.Switch = &Switch{Default: -12, Low: -2, Targets: []int32{4, -8, 16}}
	}
	if d.Opcode == 0xab {
		in.Switch = &Switch{Default: 16, Pairs: []LookupPair{{-100, -8}, {10000, 4}}}
	}
	return in
}

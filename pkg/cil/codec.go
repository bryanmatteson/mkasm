package cil

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

func malformed(s string) error { return fmt.Errorf("%w: %s", ErrMalformed, s) }
func operandBytes(d *Definition) int {
	switch d.Operand {
	case "InlineNone":
		return 0
	case "ShortInlineI", "ShortInlineVar", "ShortInlineBrTarget":
		return 1
	case "InlineVar":
		return 2
	case "InlineI8", "InlineR":
		return 8
	case "InlineSwitch":
		return -1
	default:
		return 4
	}
}
func validToken(class string, v uint32) bool {
	if v&0xffffff == 0 {
		return false
	}
	tag := v >> 24
	switch class {
	case "InlineMethod":
		return tag == 6 || tag == 10 || tag == 43
	case "InlineField":
		return tag == 4 || tag == 10
	case "InlineType":
		return tag == 1 || tag == 2 || tag == 27
	case "InlineSig":
		return tag == 17
	case "InlineString":
		return tag == 112
	case "InlineTok":
		return tag == 1 || tag == 2 || tag == 4 || tag == 6 || tag == 10 || tag == 27 || tag == 43
	}
	return false
}
func (c *Catalog) Decode(src []byte, offset uint32) (*Instruction, error) {
	if len(src) == 0 {
		return nil, ErrTruncated
	}
	op := uint16(src[0])
	size := 1
	if op == 0xfe {
		if len(src) < 2 {
			return nil, ErrTruncated
		}
		op = 0xfe00 | uint16(src[1])
		size = 2
	}
	d := c.Definition(op)
	if d == nil {
		return nil, fmt.Errorf("%w: 0x%04x", ErrReserved, op)
	}
	in := &Instruction{Opcode: op, Mnemonic: d.Mnemonic, Offset: offset, Length: size}
	n := operandBytes(d)
	if n < 0 {
		if len(src) < size+4 {
			return nil, ErrTruncated
		}
		count := uint64(binary.LittleEndian.Uint32(src[size:]))
		if count > uint64((len(src)-size-4)/4) {
			return nil, ErrTruncated
		}
		if count > uint64(math.MaxInt32/4) {
			return nil, malformed("switch table too large")
		}
		in.Length += 4 + int(count)*4
		in.Operand = &Operand{Kind: "switch", Targets: make([]int32, int(count))}
		for i := range in.Operand.Targets {
			in.Operand.Targets[i] = int32(binary.LittleEndian.Uint32(src[size+4+i*4:]))
		}
	} else {
		if len(src) < size+n {
			return nil, ErrTruncated
		}
		in.Length += n
		if n > 0 {
			o := &Operand{Kind: d.OperandKind}
			var raw uint64
			switch n {
			case 1:
				raw = uint64(src[size])
			case 2:
				raw = uint64(binary.LittleEndian.Uint16(src[size:]))
			case 4:
				raw = uint64(binary.LittleEndian.Uint32(src[size:]))
			case 8:
				raw = binary.LittleEndian.Uint64(src[size:])
			}
			switch d.OperandKind {
			case "float32", "float64":
				o.Bits = raw
			case "integer", "branch":
				switch n {
				case 1:
					o.Value = int64(int8(raw))
				case 4:
					o.Value = int64(int32(raw))
				case 8:
					o.Value = int64(raw)
				}
				if d.Mnemonic == "unaligned." {
					o.Value = int64(raw)
				}
			default:
				o.Value = int64(raw)
			}
			in.Operand = o
		}
	}
	if uint64(offset)+uint64(in.Length) > math.MaxUint32 {
		return nil, malformed("instruction offset overflow")
	}
	if err := validateOperand(d, in.Operand); err != nil {
		return nil, err
	}
	return in, nil
}
func validateOperand(d *Definition, o *Operand) error {
	if d.OperandKind == "none" {
		if o != nil {
			return malformed("operand supplied for operand-free opcode")
		}
		return nil
	}
	if o == nil || o.Kind != d.OperandKind {
		return malformed("operand kind for " + d.Mnemonic)
	}
	if o.Kind != "switch" && o.Targets != nil {
		return malformed("unexpected switch targets")
	}
	if !strings.HasPrefix(o.Kind, "float") && o.Bits != 0 {
		return malformed("unexpected float bits")
	}
	if (strings.HasPrefix(o.Kind, "float") || o.Kind == "switch") && o.Value != 0 {
		return malformed("unexpected integer value")
	}
	switch d.OperandKind {
	case "integer":
		n := operandBytes(d)
		if d.Mnemonic == "unaligned." {
			if o.Value != 1 && o.Value != 2 && o.Value != 4 {
				return malformed("unaligned. alignment must be 1, 2 or 4")
			}
		} else if n == 1 && (o.Value < math.MinInt8 || o.Value > math.MaxInt8) || n == 4 && (o.Value < math.MinInt32 || o.Value > math.MaxInt32) {
			return malformed("integer out of range")
		}
	case "variable":
		max := int64(math.MaxUint16)
		if operandBytes(d) == 1 {
			max = math.MaxUint8
		}
		if o.Value < 0 || o.Value > max {
			return malformed("variable index out of range")
		}
	case "token":
		if o.Value < 0 || o.Value > math.MaxUint32 || !validToken(d.Operand, uint32(o.Value)) {
			return malformed("invalid " + d.Operand + " token")
		}
	case "float32":
		if o.Bits > math.MaxUint32 {
			return malformed("float32 bits out of range")
		}
	case "branch":
		if o.Value < math.MinInt32 || o.Value > math.MaxInt32 || operandBytes(d) == 1 && (o.Value < math.MinInt8 || o.Value > math.MaxInt8) {
			return malformed("branch displacement out of range")
		}
	case "switch":
		if uint64(len(o.Targets)) > math.MaxInt32/4 {
			return malformed("switch table too large")
		}
	}
	return nil
}
func (c *Catalog) resolve(in *Instruction) (*Definition, error) {
	if in == nil {
		return nil, malformed("nil instruction")
	}
	d := c.Definition(in.Opcode)
	if in.Mnemonic != "" {
		n := c.Lookup(strings.ToLower(in.Mnemonic))
		if n == nil {
			return nil, malformed("unknown instruction " + in.Mnemonic)
		}
		if in.Opcode != 0 && in.Opcode != n.Opcode {
			return nil, malformed("opcode/mnemonic disagreement")
		}
		d = n
	}
	if d == nil {
		return nil, ErrReserved
	}
	return d, nil
}
func (c *Catalog) Encode(in *Instruction, offset uint32) ([]byte, error) {
	d, err := c.resolve(in)
	if err != nil {
		return nil, err
	}
	if err := validateOperand(d, in.Operand); err != nil {
		return nil, err
	}
	n := operandBytes(d)
	if n < 0 {
		n = 4 + 4*len(in.Operand.Targets)
	}
	if uint64(offset)+uint64(d.Size+n) > math.MaxUint32 {
		return nil, malformed("instruction offset overflow")
	}
	out := make([]byte, d.Size+n)
	if d.Size == 2 {
		out[0] = 0xfe
		out[1] = byte(d.Opcode)
	} else {
		out[0] = byte(d.Opcode)
	}
	if n == 0 {
		return out, nil
	}
	o := in.Operand
	if o.Kind == "switch" {
		binary.LittleEndian.PutUint32(out[d.Size:], uint32(len(o.Targets)))
		for i, v := range o.Targets {
			binary.LittleEndian.PutUint32(out[d.Size+4+i*4:], uint32(v))
		}
		return out, nil
	}
	raw := uint64(o.Value)
	if strings.HasPrefix(o.Kind, "float") {
		raw = o.Bits
	}
	switch n {
	case 1:
		out[d.Size] = byte(raw)
	case 2:
		binary.LittleEndian.PutUint16(out[d.Size:], uint16(raw))
	case 4:
		binary.LittleEndian.PutUint32(out[d.Size:], uint32(raw))
	case 8:
		binary.LittleEndian.PutUint64(out[d.Size:], raw)
	}
	return out, nil
}
func (in Instruction) BranchTargets() []int64 {
	if in.Operand == nil {
		return nil
	}
	base := int64(in.Offset) + int64(in.Length)
	if in.Operand.Kind == "branch" {
		return []int64{base + in.Operand.Value}
	}
	if in.Operand.Kind == "switch" {
		out := make([]int64, len(in.Operand.Targets))
		for i, v := range in.Operand.Targets {
			out[i] = base + int64(v)
		}
		return out
	}
	return nil
}
func (c *Catalog) DecodeMethod(code []byte) ([]Instruction, error) {
	if uint64(len(code)) > math.MaxInt32 {
		return nil, malformed("method code too large")
	}
	out := make([]Instruction, 0)
	for at := 0; at < len(code); {
		in, err := c.Decode(code[at:], uint32(at))
		if err != nil {
			return nil, fmt.Errorf("CIL offset 0x%x: %w", at, err)
		}
		out = append(out, *in)
		at += in.Length
	}
	if err := c.validateMethod(out, uint32(len(code))); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Catalog) EncodeMethod(instructions []Instruction) ([]byte, error) {
	var out []byte
	var normalized []Instruction
	for _, in := range instructions {
		b, err := c.Encode(&in, uint32(len(out)))
		if err != nil {
			return nil, err
		}
		in.Offset = uint32(len(out))
		in.Length = len(b)
		d, _ := c.resolve(&in)
		in.Opcode = d.Opcode
		in.Mnemonic = d.Mnemonic
		normalized = append(normalized, in)
		out = append(out, b...)
		if len(out) > math.MaxInt32 {
			return nil, malformed("method code too large")
		}
	}
	if err := c.validateMethod(normalized, uint32(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Catalog) validateMethod(in []Instruction, size uint32) error {
	starts := map[uint32]bool{}
	var prefixes []string
	for i, x := range in {
		d := c.Definition(x.Opcode)
		if len(prefixes) == 0 {
			starts[x.Offset] = true
		}
		if d.Prefix {
			for _, p := range prefixes {
				if p == d.Mnemonic {
					return malformed("duplicate prefix")
				}
			}
			prefixes = append(prefixes, d.Mnemonic)
			continue
		}
		for _, p := range prefixes {
			if !prefixAllowed(p, d.Mnemonic) {
				return malformed("prefix " + p + " cannot modify " + d.Mnemonic)
			}
			if p == "tail." && (i+1 >= len(in) || in[i+1].Mnemonic != "ret") {
				return malformed("tail call must be followed by ret")
			}
		}
		prefixes = nil
	}
	if len(prefixes) > 0 {
		return malformed("dangling prefix")
	}
	for _, x := range in {
		for _, target := range x.BranchTargets() {
			if target < 0 || target >= int64(size) || !starts[uint32(target)] {
				return malformed("branch target is not an instruction-group boundary")
			}
		}
	}
	return nil
}
func prefixAllowed(p, n string) bool {
	switch p {
	case "tail.":
		return n == "call" || n == "calli" || n == "callvirt"
	case "constrained.":
		return n == "call" || n == "callvirt" || n == "ldftn"
	case "readonly.":
		return n == "ldelema"
	case "unaligned.":
		return strings.HasPrefix(n, "ldind.") || strings.HasPrefix(n, "stind.") || n == "ldfld" || n == "stfld" || n == "ldobj" || n == "stobj" || n == "cpblk" || n == "initblk"
	case "volatile.":
		return strings.HasPrefix(n, "ldind.") || strings.HasPrefix(n, "stind.") || n == "ldfld" || n == "stfld" || n == "ldsfld" || n == "stsfld" || n == "ldobj" || n == "stobj" || n == "cpblk" || n == "initblk"
	}
	return false
}

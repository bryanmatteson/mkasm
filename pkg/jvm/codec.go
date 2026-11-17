package jvm

import (
	"encoding/binary"
	"fmt"
	"math"
)

func malformed(s string) error { return fmt.Errorf("%w: %s", ErrMalformed, s) }
func wideAllowed(op byte) bool {
	return op >= 0x15 && op <= 0x19 || op >= 0x36 && op <= 0x3a || op == 0x84 || op == 0xa9
}
func (c *Catalog) Decode(src []byte, offset uint32) (*Instruction, error) {
	if len(src) == 0 {
		return nil, ErrTruncated
	}
	op := src[0]
	pos := 1
	wide := false
	if op == 0xc4 {
		if len(src) < 2 {
			return nil, ErrTruncated
		}
		op = src[1]
		if !wideAllowed(op) {
			return nil, malformed("wide prefix on invalid opcode")
		}
		wide = true
		pos = 2
	}
	d := c.definition(op)
	if d == nil || d.Reserved {
		return nil, fmt.Errorf("%w: 0x%02x", ErrReserved, op)
	}
	inst := &Instruction{Opcode: op, Mnemonic: d.Mnemonic, Offset: offset, Wide: wide}
	if op == 0xaa || op == 0xab {
		return decodeSwitch(src, offset, inst)
	}
	for _, o := range d.Operands {
		n := o.Bytes
		if wide {
			n = 2
		}
		if len(src)-pos < n {
			return nil, ErrTruncated
		}
		var v int64
		for _, b := range src[pos : pos+n] {
			v = v<<8 | int64(b)
		}
		if o.Signed {
			v = v << uint(64-n*8) >> uint(64-n*8)
		}
		pos += n
		if err := validateOperand(o, v); err != nil {
			return nil, err
		}
		inst.Operands = append(inst.Operands, Operand{o.Name, o.Kind, v})
	}
	zeros := 0
	if op == 0xb9 {
		zeros = 1
	}
	if op == 0xba {
		zeros = 2
	}
	if len(src)-pos < zeros {
		return nil, ErrTruncated
	}
	for _, b := range src[pos : pos+zeros] {
		if b != 0 {
			return nil, malformed("nonzero invoke reserved byte")
		}
	}
	pos += zeros
	inst.Length = pos
	return inst, nil
}
func decodeSwitch(src []byte, offset uint32, in *Instruction) (*Instruction, error) {
	pad := int((4 - (offset+1)%4) % 4)
	pos := 1 + pad
	if len(src) < pos {
		return nil, ErrTruncated
	}
	for _, b := range src[1:pos] {
		if b != 0 {
			return nil, malformed("nonzero switch padding")
		}
	}
	header := 8
	if in.Opcode == 0xaa {
		header = 12
	}
	if len(src)-pos < header {
		return nil, ErrTruncated
	}
	word := func(p int) int32 { return int32(binary.BigEndian.Uint32(src[p : p+4])) }
	s := &Switch{Default: word(pos)}
	pos += 4
	if in.Opcode == 0xaa {
		low, high := word(pos), word(pos+4)
		pos += 8
		n := int64(high) - int64(low) + 1
		if n <= 0 {
			return nil, malformed("tableswitch high is below low")
		}
		if n > int64((65535-pos)/4) {
			return nil, malformed("tableswitch exceeds maximum method size")
		}
		if n > int64((len(src)-pos)/4) {
			return nil, ErrTruncated
		}
		s.Low = low
		s.Targets = make([]int32, int(n))
		for i := range s.Targets {
			s.Targets[i] = word(pos)
			pos += 4
		}
	} else {
		n := int64(word(pos))
		pos += 4
		if n < 0 {
			return nil, malformed("negative lookupswitch pair count")
		}
		if n > int64((65535-pos)/8) {
			return nil, malformed("lookupswitch exceeds maximum method size")
		}
		if n > int64((len(src)-pos)/8) {
			return nil, ErrTruncated
		}
		s.Pairs = make([]LookupPair, int(n))
		for i := range s.Pairs {
			key, target := word(pos), word(pos+4)
			pos += 8
			if i > 0 && key <= s.Pairs[i-1].Match {
				return nil, malformed("lookupswitch keys are not strictly increasing")
			}
			s.Pairs[i] = LookupPair{key, target}
		}
	}
	in.Switch = s
	in.Length = pos
	return in, nil
}
func validateOperand(o OperandDefinition, v int64) error {
	switch o.Kind {
	case "constant_pool":
		if v == 0 {
			return malformed("constant-pool index zero")
		}
	case "count", "dimensions":
		if v == 0 {
			return malformed("zero " + o.Kind)
		}
	case "array_type":
		if v < 4 || v > 11 {
			return malformed("invalid newarray primitive type")
		}
	}
	return nil
}
func (c *Catalog) Encode(in *Instruction, offset uint32) ([]byte, error) {
	d := c.definition(in.Opcode)
	if d == nil || d.Reserved {
		return nil, ErrReserved
	}
	if in.Mnemonic != "" && in.Mnemonic != d.Mnemonic {
		return nil, malformed("opcode/mnemonic mismatch")
	}
	if in.Wide && !wideAllowed(in.Opcode) {
		return nil, malformed("wide prefix on invalid opcode")
	}
	if in.Opcode == 0xaa || in.Opcode == 0xab {
		if in.Wide || len(in.Operands) != 0 {
			return nil, malformed("invalid switch operands")
		}
		return encodeSwitch(in, offset)
	}
	if in.Opcode == 0xc4 {
		return nil, malformed("wide requires a modified instruction")
	}
	if in.Switch != nil {
		return nil, malformed("switch data on fixed instruction")
	}
	if len(in.Operands) != len(d.Operands) {
		return nil, malformed("operand count")
	}
	out := []byte{in.Opcode}
	if in.Wide {
		out = []byte{0xc4, in.Opcode}
	}
	for i, o := range d.Operands {
		v := in.Operands[i].Value
		if in.Operands[i].Name != "" && in.Operands[i].Name != o.Name {
			return nil, malformed("operand name")
		}
		n := o.Bytes
		if in.Wide {
			n = 2
		}
		lo, hi := int64(0), int64(1)<<uint(n*8)-1
		if o.Signed {
			lo = -(int64(1) << uint(n*8-1))
			hi = (int64(1) << uint(n*8-1)) - 1
		}
		if v < lo || v > hi {
			return nil, malformed("operand out of range")
		}
		if err := validateOperand(o, v); err != nil {
			return nil, err
		}
		for b := n - 1; b >= 0; b-- {
			out = append(out, byte(uint64(v)>>uint(b*8)))
		}
	}
	if in.Opcode == 0xb9 {
		out = append(out, 0)
	}
	if in.Opcode == 0xba {
		out = append(out, 0, 0)
	}
	return out, nil
}
func encodeSwitch(in *Instruction, offset uint32) ([]byte, error) {
	s := in.Switch
	if s == nil {
		return nil, malformed("missing switch data")
	}
	out := []byte{in.Opcode}
	pad := int((4 - (offset+1)%4) % 4)
	out = append(out, make([]byte, pad)...)
	add := func(v int32) { out = binary.BigEndian.AppendUint32(out, uint32(v)) }
	add(s.Default)
	if in.Opcode == 0xaa {
		if len(s.Pairs) != 0 || len(s.Targets) == 0 || int64(s.Low)+int64(len(s.Targets))-1 > math.MaxInt32 {
			return nil, malformed("invalid tableswitch range")
		}
		if len(s.Targets) > 16384 {
			return nil, malformed("tableswitch exceeds maximum method size")
		}
		add(s.Low)
		add(int32(int64(s.Low) + int64(len(s.Targets)) - 1))
		for _, v := range s.Targets {
			add(v)
		}
	} else {
		if len(s.Targets) != 0 || s.Low != 0 || len(s.Pairs) > 8192 {
			return nil, malformed("invalid lookupswitch data")
		}
		add(int32(len(s.Pairs)))
		for i, p := range s.Pairs {
			if i > 0 && p.Match <= s.Pairs[i-1].Match {
				return nil, malformed("lookupswitch keys are not strictly increasing")
			}
			add(p.Match)
			add(p.Target)
		}
	}
	if len(out) > 65535 {
		return nil, malformed("switch exceeds maximum method size")
	}
	return out, nil
}

// DecodeMethod additionally checks the JVMS code-size limit and that every
// branch/switch target points to an instruction opcode in this method.
func (c *Catalog) DecodeMethod(code []byte) ([]Instruction, error) {
	if len(code) == 0 || len(code) > 65535 {
		return nil, malformed("method code length must be 1..65535")
	}
	var out []Instruction
	starts := map[int64]bool{}
	for pos := 0; pos < len(code); {
		in, err := c.Decode(code[pos:], uint32(pos))
		if err != nil {
			return nil, fmt.Errorf("JVM at %d: %w", pos, err)
		}
		starts[int64(pos)] = true
		out = append(out, *in)
		pos += in.Length
	}
	for _, in := range out {
		for _, target := range instructionTargets(&in) {
			if !starts[int64(in.Offset)+int64(target)] {
				return nil, malformed(fmt.Sprintf("branch from %d targets noninstruction %d", in.Offset, int64(in.Offset)+int64(target)))
			}
		}
	}
	return out, nil
}
func instructionTargets(in *Instruction) []int32 {
	var out []int32
	for _, o := range in.Operands {
		if o.Kind == "branch" {
			out = append(out, int32(o.Value))
		}
	}
	if in.Switch != nil {
		out = append(out, in.Switch.Default)
		out = append(out, in.Switch.Targets...)
		for _, p := range in.Switch.Pairs {
			out = append(out, p.Target)
		}
	}
	return out
}
func (c *Catalog) EncodeMethod(instructions []Instruction) ([]byte, error) {
	var out []byte
	for i := range instructions {
		b, err := c.Encode(&instructions[i], uint32(len(out)))
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	if _, err := c.DecodeMethod(out); err != nil {
		return nil, err
	}
	return out, nil
}

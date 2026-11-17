package m68k

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var constants = map[byte]string{'C': "ccr", 'S': "sr", 'U': "usp", 'E': "acc", 'G': "macsr", 'H': "mask", 'V': "val"}
var widths = map[byte]int{'D': 3, 'A': 3, 'a': 3, '+': 3, '-': 3, 'F': 3, 'R': 4, 'r': 4, 'u': 5, 'O': 6, 'J': 12, 'c': 2, 'e': 2, 'g': 1, 'i': 2, 'K': 9, 's': 3, 't': 3, 'T': 4, 'X': 5, 'Y': 5, 'Z': 5, 'W': 5, '0': 5, '1': 5, '2': 5, '3': 5, 'f': 5}

type stream struct {
	b      []byte
	p      int
	encode bool
}

func (s *stream) field(v Value, place byte, bits int) (Value, error) {
	if s.encode {
		n, e := v.unsigned(bits)
		if e != nil {
			return Value{}, e
		}
		e = fieldWrite(s.b, place, bits, n)
		return v, e
	}
	n, e := fieldRead(s.b, place, bits)
	return U(n), e
}
func (s *stream) immediate(v Value, pos, bits int, consume bool) (Value, error) {
	if bits == 8 {
		if s.encode {
			data, e := byteImmediate(v)
			if e != nil {
				return Value{}, e
			}
			if len(s.b) < pos+2 {
				s.b = append(s.b, make([]byte, pos+2-len(s.b))...)
			}
			copy(s.b[pos:pos+2], data)
			if consume {
				s.p = pos + 2
			}
			return v, nil
		}
		if pos+2 > len(s.b) {
			return Value{}, ErrTruncated
		}
		if consume {
			s.p = pos + 2
		}
		return decodeByteImmediate(s.b[pos : pos+2]), nil
	}

	nbytes := bits / 8
	if bits == 8 {
		nbytes = 2
	}
	if s.encode {
		n, e := number(v)
		if e != nil {
			return Value{}, e
		}
		if bits < 64 && (n < -(int64(1)<<(bits-1)) || n >= (int64(1)<<bits)) {
			return Value{}, errors.New("immediate out of range")
		}
		if len(s.b) < pos+nbytes {
			s.b = append(s.b, make([]byte, pos+nbytes-len(s.b))...)
		}
		if bits == 8 {
			s.b[pos] = 0
			s.b[pos+1] = byte(n)
		} else {
			for i := 0; i < nbytes; i++ {
				s.b[pos+i] = byte(uint64(n) >> uint((nbytes-1-i)*8))
			}
		}
		if consume {
			s.p = pos + nbytes
		}
		return v, nil
	}
	p := pos
	n, e := readInt(s.b, &p, bits)
	if consume {
		s.p = p
	}
	return S(n), e
}
func (c *Catalog) operand(s *stream, o *Opcode, pair string, v Value) (Value, error) {
	k, p := pair[0], pair[1]
	if s.encode {
		v = registerValue(k, p, v)
	}
	if name, ok := constants[k]; ok {
		if s.encode && v.Text != name {
			return Value{}, fmt.Errorf("expected %s", name)
		}
		return T(name), nil
	}
	if isEA(k) {
		if s.encode {
			address := v
			mask := U(0)
			if p == '/' {
				a, e := getList(v, 2)
				if e != nil {
					return Value{}, e
				}
				address = a[0]
				mask = a[1]
			}
			b, code, e := c.writeEA(s.b, address, k, p)
			if e != nil {
				return Value{}, e
			}
			s.b = b
			s.p = len(b)
			if p == 'd' {
				code = (code&7)<<3 | (code>>3)&7
				return v, fieldWrite(s.b, 'x', 6, uint64(code))
			}
			if p == '/' {
				if _, e := s.field(mask, '/', 1); e != nil {
					return Value{}, e
				}
			}
			return v, fieldWrite(s.b, 's', 6, uint64(code))
		}
		place := byte('s')
		if p == 'd' {
			place = 'x'
		}
		n, e := fieldRead(s.b, place, 6)
		if e != nil {
			return Value{}, e
		}
		code := int(n)
		if p == 'd' {
			code = (code&7)<<3 | code>>3&7
		}
		if !validEA(k, code) {
			return Value{}, errors.New("invalid effective address class")
		}
		address, e := c.readEA(s.b, &s.p, code, p)
		if e != nil {
			return Value{}, e
		}
		if p == '/' {
			mask, e := s.field(Value{}, '/', 1)
			return L(address, mask), e
		}
		return address, nil
	}
	if k == '#' || k == '^' {
		if p == 'j' {
			return s.field(v, 'j', 12)
		}
		if p == 'B' {
			if s.encode {
				n, e := number(v)
				if e != nil || n < -128 || n > 127 {
					return Value{}, errors.New("moveq immediate out of range")
				}
				return v, fieldWrite(s.b, 's', 8, uint64(uint8(n)))
			}
			n, e := fieldRead(s.b, 's', 8)
			return S(sign(n, 8)), e
		}
		if strings.ContainsRune("sC83", rune(p)) {
			bits := map[byte]int{'s': 4, 'C': 7, '8': 3, '3': 8}[p]
			return s.field(v, p, bits)
		}
		pos := 2
		if k == '^' {
			pos = 4
		}
		if o.Mask&65535 == 65535 || strings.HasPrefix(o.Mnemonic, "ptrap") {
			pos = 4
		}
		bits := map[byte]int{'b': 8, 'w': 16, 'W': 16, 'l': 32}[p]
		if bits == 0 {
			return Value{}, errors.New("unknown immediate location")
		}
		result, e := s.immediate(v, pos, bits, false)
		s.p = max(s.p, pos+max(2, bits/8))
		return result, e
	}
	if k == 'B' {
		if p == 'b' || p == 's' {
			p = 'g'
		}
		bits := 16
		switch p {
		case 'B':
			if s.encode {
				n, e := number(v)
				if e != nil {
					return Value{}, e
				}
				if n == 0 || n == -1 && (hasFull(c) || Profiles[c.CPU]&(65536|131072) != 0) {
					return Value{}, errors.New("reserved short branch displacement")
				}
				if n < -128 || n > 127 {
					return Value{}, errors.New("short branch out of range")
				}
				return v, fieldWrite(s.b, 's', 8, uint64(uint8(n)))
			}
			n, e := fieldRead(s.b, 's', 8)
			d := sign(n, 8)
			if e == nil && (d == 0 || d == -1 && (hasFull(c) || Profiles[c.CPU]&(65536|131072) != 0)) {
				e = errors.New("reserved short branch displacement")
			}
			return S(d), e
		case 'b':
			bits = 8
		case 'l', 'L', 'C':
			bits = 32
		case 'g':
			if s.encode {
				n, e := number(v)
				if e != nil {
					return Value{}, e
				}
				if n >= -128 && n <= 127 && n != 0 && !(n == -1 && (hasFull(c) || Profiles[c.CPU]&(65536|131072) != 0)) {
					return v, fieldWrite(s.b, 's', 8, uint64(uint8(n)))
				}
				if n >= -32768 && n <= 32767 {
					if e := fieldWrite(s.b, 's', 8, 0); e != nil {
						return Value{}, e
					}
					bits = 16
				} else {
					if !hasFull(c) && Profiles[c.CPU]&(65536|131072) == 0 {
						return Value{}, errors.New("long branch requires 68020 or ColdFire ISA B/C")
					}
					if e := fieldWrite(s.b, 's', 8, 255); e != nil {
						return Value{}, e
					}
					bits = 32
				}
			} else {
				n, e := fieldRead(s.b, 's', 8)
				if e != nil {
					return Value{}, e
				}
				if n != 0 && n != 255 {
					return S(sign(n, 8)), nil
				}
				if n == 255 {
					if !hasFull(c) && Profiles[c.CPU]&(65536|131072) == 0 {
						return S(-1), nil
					}
					bits = 32
				}
			}
		case 'c':
			if s.encode {
				n, e := number(v)
				if e != nil {
					return Value{}, e
				}
				flag := uint64(0)
				if n < -32768 || n > 32767 {
					flag = 1
				}
				if e = fieldWrite(s.b, 'e', 1, flag); e != nil {
					return Value{}, e
				}
			}
			n, e := fieldRead(s.b, 's', 8)
			if e != nil {
				return Value{}, e
			}
			if n&64 != 0 {
				bits = 32
			}
		}
		if s.encode {
			if _, e := v.signed(bits); e != nil {
				return Value{}, e
			}
		}
		return s.immediate(v, s.p, bits, true)
	}
	if k == '_' {
		return s.immediate(v, s.p, 32, true)
	}
	if k == 'd' {
		if s.encode {
			a, e := getList(v, 2)
			if e != nil {
				return Value{}, e
			}
			if _, e = s.field(a[0], p, 3); e != nil {
				return Value{}, e
			}
			if _, e = a[1].signed(16); e != nil {
				return Value{}, e
			}
			_, e = s.immediate(a[1], s.p, 16, true)
			return v, e
		}
		reg, e := s.field(Value{}, p, 3)
		if e != nil {
			return Value{}, e
		}
		disp, e := s.immediate(Value{}, s.p, 16, true)
		return L(reg, disp), e
	}
	if k == 'I' {
		if s.encode && Profiles[c.CPU]&(16|32|4096) != 0 && v.U != 1 {
			return Value{}, errors.New("integrated FPU requires coprocessor ID 1")
		}
		if !s.encode && Profiles[c.CPU]&(16|32|4096) != 0 {
			n, e := fieldRead(s.b, 'd', 3)
			if e != nil || n != 1 {
				return Value{}, errors.New("integrated FPU requires coprocessor ID 1")
			}
		}
		return s.field(v, 'd', 3)
	}
	if k == 'L' || k == 'l' {
		bits := 8
		place := p
		if p == 'w' {
			bits = 16
			place = '3'
		} else if p == '8' {
			bits = 3
		}
		if s.encode && k == 'l' {
			n, e := v.unsigned(bits)
			if e != nil {
				return Value{}, e
			}
			var rev uint64
			for i := 0; i < bits; i++ {
				rev |= (n >> uint(i) & 1) << uint(bits-1-i)
			}
			_, e = s.field(U(rev), place, bits)
			return v, e
		}
		result, e := s.field(v, place, bits)
		if !s.encode && k == 'l' && e == nil {
			var rev uint64
			for i := 0; i < bits; i++ {
				rev |= (result.U >> uint(i) & 1) << uint(bits-1-i)
			}
			result = U(rev)
		}
		return result, e
	}
	if k == 'Q' || k == 'x' || k == 'j' || k == 'M' || k == 'k' {
		bits := 3
		if k == 'M' {
			bits = 8
			if p == 'h' {
				bits = 1
			}
		}
		if k == 'k' && p == 'C' {
			bits = 7
		}
		if s.encode {
			n, e := number(v)
			if e != nil {
				return Value{}, e
			}
			switch k {
			case 'Q':
				if p != 's' {
					if n < 1 || n > 8 {
						return Value{}, errors.New("quick count must be 1..8")
					}
					n &= 7
				}
			case 'x':
				if n == -1 {
					n = 0
				} else if n < 1 || n > 7 {
					return Value{}, errors.New("mov3q count must be -1 or 1..7")
				}
			case 'j':
				n--
			case 'M':
				if p != 'h' {
					if n < -128 || n > 127 {
						return Value{}, errors.New("moveq immediate out of range")
					}
					n = int64(uint8(n))
				}
			case 'k':
				if p == 'C' {
					if n < -64 || n > 63 {
						return Value{}, errors.New("K factor out of range")
					}
					n &= 127
				}
			}
			_, e = s.field(U(uint64(n)), p, bits)
			return v, e
		}
		raw, e := s.field(Value{}, p, bits)
		n := int64(raw.U)
		if e != nil {
			return Value{}, e
		}
		switch k {
		case 'Q':
			if n == 0 && p != 's' {
				n = 8
			}
		case 'x':
			if n == 0 {
				n = -1
			}
		case 'j':
			n++
		case 'M':
			if p != 'h' {
				n = sign(raw.U, 8)
			}
		case 'k':
			if p == 'C' {
				n = sign(raw.U, 7)
			}
		}
		return S(n), nil
	}
	if k == 's' {
		if s.encode {
			n, e := v.unsigned(3)
			if e != nil || n != 1 && n != 2 && n != 4 {
				return Value{}, errors.New("single FPU control register required")
			}
		} else {
			n, e := fieldRead(s.b, p, 3)
			if e != nil || n != 1 && n != 2 && n != 4 {
				return Value{}, errors.New("single FPU control register required")
			}
		}
	}
	bits, ok := widths[k]
	if !ok {
		return Value{}, fmt.Errorf("unimplemented operand kind %c", k)
	}
	if k == 'X' || k == 'Y' || k == 'Z' || k == 'W' || k >= '0' && k <= '3' {
		if k == 'X' {
			p = '8'
		}
		bank := U(0)
		hasBank := false
		selector := v
		if s.encode && v.Kind == "list" {
			a, e := getList(v, 2)
			if e != nil {
				return Value{}, e
			}
			selector = a[0]
			bank = a[1]
			hasBank = true
		}
		out, e := s.field(selector, p, 5)
		if e != nil {
			return Value{}, e
		}
		n := out.U
		if _, known := mmuRegistersByValue(n); !known && n != 28 && n != 29 {
			return Value{}, errors.New("reserved MMU register selector")
		}
		if n == 28 || n == 29 {
			b, e := s.field(bank, ':', 3)
			if e != nil {
				return Value{}, e
			}
			return L(out, b), nil
		}
		if hasBank {
			return Value{}, errors.New("bank number only applies to BAD/BAC registers")
		}
		return out, nil
	}

	out, e := s.field(v, p, bits)
	if e != nil {
		return Value{}, e
	}
	if k == 'i' && out.U != 1 && out.U != 3 {
		return Value{}, errors.New("invalid MAC shift")
	}
	if k == 'O' && out.U&32 != 0 && out.U&24 != 0 {
		return Value{}, errors.New("reserved bitfield register bits")
	}
	return out, nil
}

type Instruction struct {
	Opcode         *Opcode
	Operands       []Value
	Length         int
	BranchBase     int
	OperandOffsets []int
}

func (i *Instruction) Format() string {
	b, _ := json.Marshal(i.Operands)
	if len(i.Operands) == 0 {
		return i.Opcode.ID
	}
	return i.Opcode.ID + " " + string(b)
}
func (i *Instruction) BranchTarget(pc uint64) (uint64, bool) {
	for n, p := range pairs(i.Opcode) {
		if p[0] == 'B' {
			d, e := number(i.Operands[n])
			if e == nil {
				return uint64(uint32(pc) + uint32(i.BranchBase) + uint32(d)), true
			}
		}
	}
	return 0, false
}
func (c *Catalog) Encode(id string, values []Value) ([]byte, error) {
	name := strings.ReplaceAll(id, ".", "")
	for depth := 0; depth < len(c.Aliases); depth++ {
		found := false
		for _, a := range c.Aliases {
			if a.Alias == name {
				name = a.Primary
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	var last error
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		if o.ID != id && o.Mnemonic != name || o.Features&Profiles[c.CPU] == 0 {
			continue
		}
		a := pairs(o)
		if len(a) != len(values) {
			last = errors.New("operand count mismatch")
			continue
		}
		s := stream{b: make([]byte, fixedSize(o)), p: fixedSize(o), encode: true}
		binary.BigEndian.PutUint16(s.b, uint16(o.Opcode>>16))
		if len(s.b) >= 4 {
			binary.BigEndian.PutUint16(s.b[2:], uint16(o.Opcode))
		}
		ok := true
		for k, p := range a {
			if _, e := c.operand(&s, o, p, values[k]); e != nil {
				last = fmt.Errorf("%s operand %d: %w", o.ID, k, e)
				ok = false
				break
			}
		}
		if ok {
			if e := validateControlOperands(o, values); e != nil {
				last = e
				continue
			}
			value := uint32(binary.BigEndian.Uint16(s.b)) << 16
			if len(s.b) >= 4 {
				value |= uint32(binary.BigEndian.Uint16(s.b[2:]))
			}
			if value&o.Mask != o.Opcode&o.Mask {
				last = errors.New("operand conflicts with fixed opcode bits")
				continue
			}
			return s.b[:max(s.p, len(s.b))], nil
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("m68k: unknown or disabled instruction %q", id)
}
func (c *Catalog) Decode(b []byte) (*Instruction, error) {
	return c.decodeSelected(b, "")
}

func (c *Catalog) decodeSelected(b []byte, id string) (*Instruction, error) {
	if len(b) < 2 {
		return nil, ErrTruncated
	}
	first := uint32(binary.BigEndian.Uint16(b)) << 16
	var best *Instruction
	bestScore := -1
	truncated := false
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		if id != "" && o.ID != id {
			continue
		}
		if o.Features&Profiles[c.CPU] == 0 || first&(o.Mask&0xffff0000) != o.Opcode&(o.Mask&0xffff0000) {
			continue
		}
		n := fixedSize(o)
		if len(b) < n {
			truncated = true
			continue
		}
		if o.Mask&65535 != 0 && uint32(binary.BigEndian.Uint16(b[2:]))&(o.Mask&65535) != o.Opcode&o.Mask&65535 {
			continue
		}
		s := stream{b: b, p: n}
		i := &Instruction{Opcode: o, BranchBase: n}
		ok := true
		for _, p := range pairs(o) {
			i.OperandOffsets = append(i.OperandOffsets, s.p)
			v, e := c.operand(&s, o, p, Value{})
			if e != nil {
				if errors.Is(e, ErrTruncated) {
					truncated = true
				}
				ok = false
				break
			}
			i.Operands = append(i.Operands, v)
		}
		if !ok {
			continue
		}
		check, e := c.Encode(o.ID, i.Operands)
		if e != nil || len(check) != s.p || !bytes.Equal(check, b[:s.p]) {
			continue
		}
		i.Length = s.p
		score := 0
		for mask := o.Mask; mask != 0; mask >>= 1 {
			score += int(mask & 1)
		}
		if score > bestScore {
			best = i
			bestScore = score
		}
	}
	if best != nil {
		return best, nil
	}
	if truncated {
		return nil, ErrTruncated
	}
	return nil, ErrUnknown
}
func (c *Catalog) Assemble(text string) ([]byte, error) {
	name, rest, _ := strings.Cut(strings.TrimSpace(text), " ")
	var a []Value
	if strings.TrimSpace(rest) != "" {
		if e := json.Unmarshal([]byte(rest), &a); e != nil {
			return nil, e
		}
	}
	return c.Encode(name, a)
}
func (c *Catalog) Disassemble(b []byte) ([]*Instruction, error) {
	var r []*Instruction
	for len(b) > 0 {
		i, e := c.Decode(b)
		if e != nil {
			return r, e
		}
		r = append(r, i)
		b = b[i.Length:]
	}
	return r, nil
}

// PCRelativeTarget returns the architectural 32-bit target for a d16(PC)
// operand. Indexed PC forms require the caller's index-register state.
func (i *Instruction) PCRelativeTarget(operand int, pc uint64) (uint64, bool) {
	if operand < 0 || operand >= len(i.Operands) || operand >= len(i.OperandOffsets) {
		return 0, false
	}
	a, e := getList(i.Operands[operand], 2)
	if e != nil || a[0].Kind != "number" || a[0].U != 58 {
		return 0, false
	}
	d, e := number(a[1])
	if e != nil {
		return 0, false
	}
	return uint64(uint32(pc) + uint32(i.OperandOffsets[operand]) + uint32(d)), true
}

func validateControlOperands(o *Opcode, values []Value) error {
	if o.Opcode&0xe000 != 0x8000 && o.Opcode&0xe000 != 0xa000 {
		return nil
	}
	a := pairs(o)
	mask := uint64(0)
	found := false
	for n, p := range a {
		if p == "s8" || p == "L8" {
			v := registerValue('s', '8', values[n])
			m, e := v.unsigned(3)
			if e != nil {
				return e
			}
			mask = m
			found = true
		}
	}
	if !found {
		return nil
	}
	single := mask == 1 || mask == 2 || mask == 4
	for n, p := range a {
		if isEA(p[0]) {
			ea, e := getList(values[n], -1)
			if e != nil || len(ea) == 0 {
				return errors.New("invalid FPU control transfer address")
			}
			code, e := ea[0].unsigned(6)
			if e != nil {
				return e
			}
			if code < 8 && !single || code >= 8 && code < 16 && mask != 1 || code == 60 && !single {
				return errors.New("FPU control transfer register/immediate addressing requires one register; address register requires FPIAR")
			}
		}
	}
	return nil
}

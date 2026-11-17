package dex

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

func malformed(s string) error { return fmt.Errorf("%w: %s", ErrMalformed, s) }
func getBits(b []byte, bit, width int) uint64 {
	var v uint64
	for i := 0; i < width; i++ {
		v |= uint64((b[(bit+i)/8]>>uint((bit+i)%8))&1) << uint(i)
	}
	return v
}
func putBits(b []byte, bit, width int, v uint64) {
	for i := 0; i < width; i++ {
		if v&(uint64(1)<<uint(i)) != 0 {
			b[(bit+i)/8] |= 1 << uint((bit+i)%8)
		}
	}
}
func signed(v uint64, width int) int64 {
	if width < 64 && v&(uint64(1)<<uint(width-1)) != 0 {
		v |= ^uint64(0) << uint(width)
	}
	return int64(v)
}
func (c *Catalog) Decode(data []byte, offset uint32) (*Instruction, error) {
	return c.DecodeVersion(data, offset, LatestVersion)
}
func (c *Catalog) DecodeVersion(data []byte, offset uint32, version int) (*Instruction, error) {
	if !validVersion(version) {
		return nil, malformed("unknown DEX version")
	}
	if len(data) < 2 {
		return nil, ErrTruncated
	}
	op := uint16(data[0])
	if op == 0 && data[1] != 0 {
		op = binary.LittleEndian.Uint16(data)
	}
	d := c.definition(op)
	if d == nil || d.Reserved {
		return nil, ErrReserved
	}
	if version < d.MinVersion {
		return nil, ErrVersion
	}
	in := &Instruction{Opcode: op, Mnemonic: d.Mnemonic, Offset: offset, Values: map[string]int64{}}
	if op >= 256 {
		if err := decodePayload(in, data); err != nil {
			return nil, err
		}
		return in, nil
	}
	n := int(d.Format[0]-'0') * 2
	if len(data) < n {
		return nil, ErrTruncated
	}
	in.Length = n
	mask := make([]byte, n)
	mask[0] = 255
	for _, f := range d.Fields {
		raw := getBits(data, f.Bit, f.Width)
		v := int64(raw)
		if f.Signed {
			v = signed(raw, f.Width)
		}
		in.Values[f.Name] = int64(uint64(v) << uint(f.Shift))
		putBits(mask, f.Bit, f.Width, ^uint64(0))
	}
	switch d.Format {
	case "35c", "45cc":
		count := int(data[1] >> 4)
		if count > 5 {
			return nil, malformed("invoke register count exceeds five")
		}
		mask[1] = 255
		mask[4] = 255
		mask[5] = 255
		positions := []int{32, 36, 40, 44, 8}
		for i, p := range positions {
			r := uint16(getBits(data, p, 4))
			if i < count {
				in.Registers = append(in.Registers, r)
			} else if r != 0 {
				return nil, malformed("nonzero unused invoke register")
			}
		}
	case "3rc", "4rcc":
		mask[1] = 255
		mask[4] = 255
		mask[5] = 255
		in.Range = &RegisterRange{binary.LittleEndian.Uint16(data[4:]), uint16(data[1])}
	}
	for i := range mask {
		if data[i]&^mask[i] != 0 {
			return nil, malformed("nonzero reserved format bits")
		}
	}
	if err := validateInstruction(d, in); err != nil {
		return nil, err
	}
	return in, nil
}
func (c *Catalog) Encode(in *Instruction, offset uint32) ([]byte, error) {
	return c.EncodeVersion(in, offset, LatestVersion)
}
func (c *Catalog) EncodeVersion(in *Instruction, offset uint32, version int) ([]byte, error) {
	if in == nil {
		return nil, malformed("nil instruction")
	}
	if !validVersion(version) {
		return nil, malformed("unknown DEX version")
	}
	d := c.definition(in.Opcode)
	if d == nil || d.Reserved {
		return nil, ErrReserved
	}
	if version < d.MinVersion {
		return nil, ErrVersion
	}
	if in.Mnemonic != "" && in.Mnemonic != d.Mnemonic {
		return nil, malformed("opcode and mnemonic disagree")
	}
	if in.Opcode >= 256 {
		return encodePayload(in, offset)
	}
	if err := validateInstruction(d, in); err != nil {
		return nil, err
	}
	n := int(d.Format[0]-'0') * 2
	b := make([]byte, n)
	b[0] = byte(in.Opcode)
	for _, f := range d.Fields {
		v := in.Values[f.Name]
		putBits(b, f.Bit, f.Width, uint64(v>>uint(f.Shift)))
	}
	switch d.Format {
	case "35c", "45cc":
		b[1] = byte(len(in.Registers)) << 4
		for i, r := range in.Registers {
			p := []int{32, 36, 40, 44, 8}[i]
			putBits(b, p, 4, uint64(r))
		}
	case "3rc", "4rcc":
		b[1] = byte(in.Range.Count)
		binary.LittleEndian.PutUint16(b[4:], in.Range.Start)
	}
	return b, nil
}
func validateInstruction(d *Definition, in *Instruction) error {
	if in.Payload != nil {
		return malformed("payload on ordinary opcode")
	}
	allowed := map[string]bool{}
	for _, f := range d.Fields {
		allowed[f.Name] = true
		v, ok := in.Values[f.Name]
		if !ok {
			return malformed("missing operand " + f.Name)
		}
		if f.Shift > 0 && uint64(v)&((uint64(1)<<uint(f.Shift))-1) != 0 {
			return malformed("nonzero low literal bits")
		}
		raw := v >> uint(f.Shift)
		if f.Signed {
			if f.Width < 64 && (raw < -(int64(1)<<uint(f.Width-1)) || raw >= (int64(1)<<uint(f.Width-1))) {
				return malformed("signed operand out of range: " + f.Name)
			}
		} else if raw < 0 || (f.Width < 63 && uint64(raw) >= (uint64(1)<<uint(f.Width))) {
			return malformed("unsigned operand out of range: " + f.Name)
		}
		if f.Kind == "target" && v == 0 && (in.Opcode == 0x28 || in.Opcode == 0x29 || in.Opcode >= 0x32 && in.Opcode <= 0x3d) {
			return malformed("zero branch offset")
		}
	}
	for k := range in.Values {
		if !allowed[k] {
			return malformed("unknown operand " + k)
		}
	}
	list := d.Format == "35c" || d.Format == "45cc"
	rng := d.Format == "3rc" || d.Format == "4rcc"
	if list {
		if in.Range != nil || len(in.Registers) > 5 {
			return malformed("invalid invoke register list")
		}
		for _, r := range in.Registers {
			if r > 15 {
				return malformed("invoke register exceeds v15")
			}
		}
		if strings.Contains(d.Verify, "kVerifyVarArgNonZero") && len(in.Registers) == 0 {
			return malformed("invoke requires receiver")
		}
	} else if len(in.Registers) > 0 {
		return malformed("unexpected register list")
	}
	if rng {
		if in.Range == nil || in.Range.Count > 255 || uint32(in.Range.Start)+uint32(in.Range.Count) > 65536 {
			return malformed("invalid register range")
		}
		if strings.Contains(d.Verify, "kVerifyVarArgRangeNonZero") && in.Range.Count == 0 {
			return malformed("invoke range requires receiver")
		}
	} else if in.Range != nil {
		return malformed("unexpected register range")
	}
	return nil
}
func decodePayload(in *Instruction, b []byte) error {
	if in.Offset%2 != 0 {
		return malformed("payload is not 4-byte aligned")
	}
	if len(b) < 4 {
		return ErrTruncated
	}
	p := &Payload{}
	in.Payload = p
	count := uint64(binary.LittleEndian.Uint16(b[2:]))
	var n uint64
	switch in.Opcode {
	case 0x100:
		n = 8 + count*4
	case 0x200:
		n = 4 + count*8
	case 0x300:
		if len(b) < 8 {
			return ErrTruncated
		}
		p.ElementWidth = uint16(count)
		if p.ElementWidth != 1 && p.ElementWidth != 2 && p.ElementWidth != 4 && p.ElementWidth != 8 {
			return malformed("invalid array element width")
		}
		count = uint64(binary.LittleEndian.Uint32(b[4:]))
		n = 8 + count*uint64(p.ElementWidth)
		n = (n + 1) &^ 1
	default:
		return ErrReserved
	}
	if n > uint64(len(b)) {
		return ErrTruncated
	}
	in.Length = int(n)
	switch in.Opcode {
	case 0x100:
		p.FirstKey = int32(binary.LittleEndian.Uint32(b[4:]))
		if count > 0 && int64(p.FirstKey)+int64(count)-1 > math.MaxInt32 {
			return malformed("packed key overflow")
		}
		for i := uint64(0); i < count; i++ {
			p.Targets = append(p.Targets, int32(binary.LittleEndian.Uint32(b[8+i*4:])))
		}
	case 0x200:
		for i := uint64(0); i < count; i++ {
			p.Keys = append(p.Keys, int32(binary.LittleEndian.Uint32(b[4+i*4:])))
			p.Targets = append(p.Targets, int32(binary.LittleEndian.Uint32(b[4+count*4+i*4:])))
			if i > 0 && p.Keys[i] <= p.Keys[i-1] {
				return malformed("sparse keys must increase")
			}
		}
	case 0x300:
		size := count * uint64(p.ElementWidth)
		p.Data = append([]byte(nil), b[8:8+size]...)
		if size%2 != 0 && b[n-1] != 0 {
			return malformed("nonzero array padding")
		}
	}
	return nil
}
func encodePayload(in *Instruction, offset uint32) ([]byte, error) {
	if offset%2 != 0 {
		return nil, malformed("payload is not 4-byte aligned")
	}
	p := in.Payload
	if p == nil || len(in.Values) != 0 || len(in.Registers) != 0 || in.Range != nil {
		return nil, malformed("invalid payload operands")
	}
	count := len(p.Targets)
	var n int
	switch in.Opcode {
	case 0x100:
		if count > 65535 || len(p.Keys) != 0 || p.ElementWidth != 0 || len(p.Data) != 0 || count > 0 && int64(p.FirstKey)+int64(count)-1 > math.MaxInt32 {
			return nil, malformed("invalid packed payload")
		}
		n = 8 + 4*count
	case 0x200:
		if count > 65535 || count != len(p.Keys) || p.FirstKey != 0 || p.ElementWidth != 0 || len(p.Data) != 0 {
			return nil, malformed("invalid sparse payload")
		}
		for i := 1; i < count; i++ {
			if p.Keys[i] <= p.Keys[i-1] {
				return nil, malformed("sparse keys must increase")
			}
		}
		n = 4 + 8*count
	case 0x300:
		w := int(p.ElementWidth)
		if w != 1 && w != 2 && w != 4 && w != 8 {
			return nil, malformed("invalid array element width")
		}
		if count != 0 || len(p.Keys) != 0 || p.FirstKey != 0 || len(p.Data)%w != 0 || uint64(len(p.Data)/w) > math.MaxUint32 {
			return nil, malformed("invalid array payload")
		}
		count = len(p.Data) / w
		n = (8 + len(p.Data) + 1) &^ 1
	default:
		return nil, ErrReserved
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b, in.Opcode)
	switch in.Opcode {
	case 0x100:
		binary.LittleEndian.PutUint16(b[2:], uint16(count))
		binary.LittleEndian.PutUint32(b[4:], uint32(p.FirstKey))
		for i, v := range p.Targets {
			binary.LittleEndian.PutUint32(b[8+i*4:], uint32(v))
		}
	case 0x200:
		binary.LittleEndian.PutUint16(b[2:], uint16(count))
		for i, v := range p.Keys {
			binary.LittleEndian.PutUint32(b[4+i*4:], uint32(v))
			binary.LittleEndian.PutUint32(b[4+count*4+i*4:], uint32(p.Targets[i]))
		}
	case 0x300:
		binary.LittleEndian.PutUint16(b[2:], p.ElementWidth)
		binary.LittleEndian.PutUint32(b[4:], uint32(count))
		copy(b[8:], p.Data)
	}
	return b, nil
}

package dex

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// DecodeMethod checks framing, branch boundaries, payload references and normal
// control flow through a complete code_item instruction array.
func (c *Catalog) DecodeMethod(data []byte, version int) ([]*Instruction, error) {
	if len(data)%2 != 0 {
		return nil, ErrTruncated
	}
	if uint64(len(data)/2) > math.MaxUint32 {
		return nil, malformed("method too large")
	}
	var out []*Instruction
	for pos := 0; pos < len(data); {
		in, err := c.DecodeVersion(data[pos:], uint32(pos/2), version)
		if err != nil {
			return nil, fmt.Errorf("code unit %d: %w", pos/2, err)
		}
		out = append(out, in)
		pos += in.Length
	}
	if err := c.ValidateMethod(out, uint32(len(data)/2)); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Catalog) ValidateMethod(ins []*Instruction, units uint32) error {
	return c.validateMethod(ins, units, []uint32{0})
}
func (c *Catalog) validateMethod(ins []*Instruction, units uint32, entries []uint32) error {
	if len(ins) == 0 {
		return malformed("empty method")
	}
	by := map[uint32]*Instruction{}
	next := uint32(0)
	for _, in := range ins {
		if in == nil || in.Offset != next || in.Length < 2 || in.Length%2 != 0 {
			return malformed("noncontiguous instruction array")
		}
		if uint64(next)+uint64(in.Length/2) > uint64(units) {
			return malformed("instruction exceeds method")
		}
		encoded, err := c.Encode(in, in.Offset)
		if err != nil {
			return err
		}
		if len(encoded) != in.Length {
			return malformed("instruction length disagrees with format")
		}
		by[next] = in
		next += uint32(in.Length / 2)
	}
	if next != units {
		return malformed("method size mismatch")
	}
	if ins[0].Payload != nil {
		return malformed("method begins with payload")
	}
	target := func(base uint32, delta int32, payload bool) (*Instruction, error) {
		v := int64(base) + int64(delta)
		if v < 0 || v >= int64(units) {
			return nil, malformed("target outside method")
		}
		t := by[uint32(v)]
		if t == nil {
			return nil, malformed("target is not an instruction boundary")
		}
		if !payload && t.Payload != nil {
			return nil, malformed("branch targets data payload")
		}
		return t, nil
	}
	edges := map[uint32][]uint32{}
	for _, in := range ins {
		if in.Payload != nil {
			continue
		}
		d := c.definition(in.Opcode)
		if d == nil {
			return ErrReserved
		}
		if v, ok := in.Values["target"]; ok {
			payload := d.Format == "31t"
			to, err := target(in.Offset, int32(v), payload)
			if err != nil {
				return fmt.Errorf("code unit %d: %w", in.Offset, err)
			}
			if payload {
				expected := uint16(0x300)
				if in.Opcode == 0x2b {
					expected = 0x100
				}
				if in.Opcode == 0x2c {
					expected = 0x200
				}
				if to.Opcode != expected || to.Payload == nil {
					return malformed("wrong payload kind")
				}
				for _, delta := range to.Payload.Targets {
					edges[in.Offset] = append(edges[in.Offset], uint32(int64(in.Offset)+int64(delta)))
					if _, err := target(in.Offset, delta, false); err != nil {
						return err
					}
				}
			} else {
				edges[in.Offset] = append(edges[in.Offset], to.Offset)
			}
		}
		if strings.Contains(d.Flags, "kContinue") {
			off := in.Offset + uint32(in.Length/2)
			edges[in.Offset] = append(edges[in.Offset], off)
		}
	}
	seen := map[uint32]bool{}
	stack := append([]uint32(nil), entries...)
	for len(stack) > 0 {
		off := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[off] {
			continue
		}
		seen[off] = true
		t := by[off]
		if t == nil || t.Payload != nil {
			return malformed("reachable control flow leaves code or enters payload")
		}
		stack = append(stack, edges[off]...)
	}
	return nil
}

// PoolSizes is optional resolution context. Missing pool names are unchecked.
// Keys match source index kinds: String, Type, Field, Method, Proto, CallSite,
// and MethodHandle. Index zero is legal in every DEX identifier pool.
type PoolSizes map[string]uint32

func (c *Catalog) ValidateRegisters(ins []*Instruction, registers uint16, outs uint16, pools PoolSizes) error {
	for _, in := range ins {
		if in == nil {
			return malformed("nil instruction")
		}
		if in.Payload != nil {
			continue
		}
		d := c.definition(in.Opcode)
		if d == nil || d.Reserved {
			return ErrReserved
		}
		if err := validateInstruction(d, in); err != nil {
			return err
		}
		for _, f := range d.Fields {
			v := in.Values[f.Name]
			if f.Kind == "register" {
				n := int64(1)
				if f.Wide {
					n = 2
				}
				if v < 0 || v+n > int64(registers) {
					return malformed("register exceeds code_item frame")
				}
			} else {
				kind := f.Kind
				if kind == "MethodAndProto" {
					kind = "Method"
				}
				if size, ok := pools[kind]; ok && (v < 0 || uint64(v) >= uint64(size)) {
					return malformed("identifier pool index out of range")
				}
			}
		}
		for _, r := range in.Registers {
			if r >= registers {
				return malformed("invoke register exceeds frame")
			}
		}
		count := len(in.Registers)
		if in.Range != nil {
			count = int(in.Range.Count)
			if uint32(in.Range.Start)+uint32(in.Range.Count) > uint32(registers) {
				return malformed("invoke range exceeds frame")
			}
		}
		if strings.Contains(d.Flags, "kInvoke") || in.Opcode == 0xfc || in.Opcode == 0xfd {
			if count > int(outs) {
				return malformed("invoke exceeds outs_size")
			}
		}
	}
	return nil
}

type CodeItem struct {
	RegistersSize   uint16         `json:"registers_size"`
	InsSize         uint16         `json:"ins_size"`
	OutsSize        uint16         `json:"outs_size"`
	DebugInfoOffset uint32         `json:"debug_info_offset"`
	Instructions    []*Instruction `json:"instructions"`
	Tries           []Try          `json:"tries,omitempty"`
	Handlers        []CatchHandler `json:"handlers,omitempty"`
	Length          int            `json:"length"`
}
type Try struct {
	Start   uint32 `json:"start"`
	Count   uint16 `json:"count"`
	Handler int    `json:"handler"`
}
type CatchHandler struct {
	Catches  []Catch `json:"catches,omitempty"`
	CatchAll *uint32 `json:"catch_all,omitempty"`
}
type Catch struct {
	Type    uint32 `json:"type"`
	Address uint32 `json:"address"`
}

func uleb(data []byte, pos *int) (uint32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		if *pos >= len(data) {
			return 0, ErrTruncated
		}
		b := data[*pos]
		*pos++
		if i == 4 && b > 15 {
			return 0, malformed("ULEB128 overflow")
		}
		v |= uint32(b&127) << uint(i*7)
		if b < 128 {
			return v, nil
		}
	}
	return 0, malformed("invalid ULEB128")
}
func sleb(data []byte, pos *int) (int32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		if *pos >= len(data) {
			return 0, ErrTruncated
		}
		b := data[*pos]
		*pos++
		if i == 4 && b&0x78 != 0 && b&0x78 != 0x78 {
			return 0, malformed("SLEB128 overflow")
		}
		v |= uint32(b&127) << uint(i*7)
		if b < 128 {
			bits := uint((i + 1) * 7)
			if bits < 32 && b&64 != 0 {
				v |= ^uint32(0) << bits
			}
			return int32(v), nil
		}
	}
	return 0, malformed("invalid SLEB128")
}
func appendULEB(b []byte, v uint32) []byte {
	for {
		n := byte(v & 127)
		v >>= 7
		if v != 0 {
			n |= 128
		}
		b = append(b, n)
		if v == 0 {
			return b
		}
	}
}
func appendSLEB(b []byte, v int32) []byte {
	for {
		n := byte(v) & 127
		v >>= 7
		done := v == 0 && n&64 == 0 || v == -1 && n&64 != 0
		if !done {
			n |= 128
		}
		b = append(b, n)
		if done {
			return b
		}
	}
}
func (c *Catalog) DecodeCodeItem(data []byte, version int) (*CodeItem, error) {
	if len(data) < 16 {
		return nil, ErrTruncated
	}
	ci := &CodeItem{RegistersSize: binary.LittleEndian.Uint16(data), InsSize: binary.LittleEndian.Uint16(data[2:]), OutsSize: binary.LittleEndian.Uint16(data[4:]), DebugInfoOffset: binary.LittleEndian.Uint32(data[8:])}
	tries := int(binary.LittleEndian.Uint16(data[6:]))
	units := binary.LittleEndian.Uint32(data[12:])
	end := uint64(16) + uint64(units)*2
	if end > uint64(len(data)) {
		return nil, ErrTruncated
	}
	var err error
	ci.Instructions, err = c.DecodeMethod(data[16:end], version)
	if err != nil {
		return nil, err
	}
	pos := int(end)
	if tries > 0 {
		if units%2 != 0 {
			if pos+2 > len(data) {
				return nil, ErrTruncated
			}
			if binary.LittleEndian.Uint16(data[pos:]) != 0 {
				return nil, malformed("nonzero code_item padding")
			}
			pos += 2
		}
		if uint64(pos)+uint64(tries)*8 > uint64(len(data)) {
			return nil, ErrTruncated
		}
		trystart := pos
		pos += tries * 8
		handlerstart := pos
		count, e := uleb(data, &pos)
		if e != nil {
			return nil, e
		}
		if uint64(count) > uint64(len(data)-pos) {
			return nil, ErrTruncated
		}
		offsets := map[int]int{}
		for i := uint32(0); i < count; i++ {
			offsets[pos-handlerstart] = int(i)
			size, e := sleb(data, &pos)
			if e != nil {
				return nil, e
			}
			n := int64(size)
			if n < 0 {
				n = -n
			}
			if n > int64((len(data)-pos)/2) {
				return nil, ErrTruncated
			}
			h := CatchHandler{}
			for j := int64(0); j < n; j++ {
				typ, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				addr, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				h.Catches = append(h.Catches, Catch{typ, addr})
			}
			if size <= 0 {
				a, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				h.CatchAll = &a
			}
			ci.Handlers = append(ci.Handlers, h)
		}
		for i := 0; i < tries; i++ {
			p := data[trystart+i*8:]
			idx, ok := offsets[int(binary.LittleEndian.Uint16(p[6:]))]
			if !ok {
				return nil, malformed("try handler offset is not a handler boundary")
			}
			ci.Tries = append(ci.Tries, Try{binary.LittleEndian.Uint32(p), binary.LittleEndian.Uint16(p[4:]), idx})
		}
	}
	ci.Length = pos
	if err := c.validateCodeItem(ci, units, nil); err != nil {
		return nil, err
	}
	return ci, nil
}
func (c *Catalog) validateCodeItem(ci *CodeItem, units uint32, pools PoolSizes) error {
	if ci.InsSize > ci.RegistersSize {
		return malformed("ins_size exceeds registers_size")
	}
	if err := c.ValidateRegisters(ci.Instructions, ci.RegistersSize, ci.OutsSize, pools); err != nil {
		return err
	}
	if len(ci.Tries) > 65535 {
		return malformed("too many try items")
	}
	by := map[uint32]*Instruction{}
	for _, in := range ci.Instructions {
		by[in.Offset] = in
	}
	valid := func(a uint32) bool { return by[a] != nil && by[a].Payload == nil }
	last := uint64(0)
	for _, t := range ci.Tries {
		end := uint64(t.Start) + uint64(t.Count)
		if t.Count == 0 || uint64(t.Start) < last || end > uint64(units) || !valid(t.Start) || end < uint64(units) && by[uint32(end)] == nil || t.Handler < 0 || t.Handler >= len(ci.Handlers) {
			return malformed("invalid try item")
		}
		last = end
	}
	if len(ci.Tries) == 0 && len(ci.Handlers) > 0 {
		return malformed("handlers without try items")
	}
	for _, h := range ci.Handlers {
		if len(h.Catches) == 0 && h.CatchAll == nil {
			return malformed("empty catch handler")
		}
		seen := map[uint32]bool{}
		for _, p := range h.Catches {
			if !valid(p.Address) || seen[p.Type] {
				return malformed("invalid catch handler")
			}
			if size, ok := pools["Type"]; ok && p.Type >= size {
				return malformed("catch type outside pool")
			}
			seen[p.Type] = true
		}
		if h.CatchAll != nil && !valid(*h.CatchAll) {
			return malformed("catch-all target outside code")
		}
	}
	entries := []uint32{0}
	for _, h := range ci.Handlers {
		for _, p := range h.Catches {
			entries = append(entries, p.Address)
		}
		if h.CatchAll != nil {
			entries = append(entries, *h.CatchAll)
		}
	}
	return c.validateMethod(ci.Instructions, units, entries)
}
func (c *Catalog) EncodeCodeItem(ci *CodeItem, version int) ([]byte, error) {
	if ci == nil {
		return nil, malformed("nil code_item")
	}
	var code []byte
	for _, in := range ci.Instructions {
		if uint64(len(code)/2) > math.MaxUint32 || in.Offset != uint32(len(code)/2) {
			return nil, malformed("noncontiguous code_item")
		}
		b, e := c.EncodeVersion(in, in.Offset, version)
		if e != nil {
			return nil, e
		}
		code = append(code, b...)
	}
	if uint64(len(code)/2) > math.MaxUint32 {
		return nil, malformed("method too large")
	}
	units := uint32(len(code) / 2)
	ins, e := c.DecodeMethod(code, version)
	if e != nil {
		return nil, e
	}
	copyCI := *ci
	copyCI.Instructions = ins
	if e = c.validateCodeItem(&copyCI, units, nil); e != nil {
		return nil, e
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b, ci.RegistersSize)
	binary.LittleEndian.PutUint16(b[2:], ci.InsSize)
	binary.LittleEndian.PutUint16(b[4:], ci.OutsSize)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(ci.Tries)))
	binary.LittleEndian.PutUint32(b[8:], ci.DebugInfoOffset)
	binary.LittleEndian.PutUint32(b[12:], units)
	b = append(b, code...)
	if len(ci.Tries) > 0 {
		if units%2 != 0 {
			b = append(b, 0, 0)
		}
		handlers := appendULEB(nil, uint32(len(ci.Handlers)))
		offsets := []int{}
		for _, h := range ci.Handlers {
			offsets = append(offsets, len(handlers))
			n := int32(len(h.Catches))
			if h.CatchAll != nil {
				n = -n
			}
			handlers = appendSLEB(handlers, n)
			for _, p := range h.Catches {
				handlers = appendULEB(handlers, p.Type)
				handlers = appendULEB(handlers, p.Address)
			}
			if h.CatchAll != nil {
				handlers = appendULEB(handlers, *h.CatchAll)
			}
		}
		for _, t := range ci.Tries {
			off := offsets[t.Handler]
			if off > 65535 {
				return nil, malformed("handler offset exceeds 16 bits")
			}
			p := make([]byte, 8)
			binary.LittleEndian.PutUint32(p, t.Start)
			binary.LittleEndian.PutUint16(p[4:], t.Count)
			binary.LittleEndian.PutUint16(p[6:], uint16(off))
			b = append(b, p...)
		}
		b = append(b, handlers...)
	}
	return b, nil
}

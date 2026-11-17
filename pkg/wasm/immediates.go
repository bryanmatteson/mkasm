package wasm

import (
	"errors"
	"fmt"
	"strings"
)

var valCodes = map[string]byte{"i32": 0x7f, "i64": 0x7e, "f32": 0x7d, "f64": 0x7c, "v128": 0x7b}
var heapCodes = map[string]byte{"func": 0x70, "extern": 0x6f, "any": 0x6e, "none": 0x71, "noextern": 0x72, "nofunc": 0x73, "eq": 0x6d, "struct": 0x6b, "array": 0x6a, "i31": 0x6c, "exn": 0x69, "noexn": 0x74, "cont": 0x68, "nocont": 0x75}

func list(v Value, n int) ([]Value, error) {
	if v.Kind != "list" || (n >= 0 && len(v.Items) != n) {
		return nil, fmt.Errorf("expected array of %d items", n)
	}
	return v.Items, nil
}
func laneLimit(o *Opcode) uint64 {
	s := o.Mnemonic
	for _, p := range []struct {
		s string
		n uint64
	}{{"i8x16", 16}, {"i16x8", 8}, {"i32x4", 4}, {"f32x4", 4}, {"i64x2", 2}, {"f64x2", 2}} {
		if strings.HasPrefix(s, p.s) {
			return p.n
		}
	}
	for _, p := range []struct {
		s string
		n uint64
	}{{"8_lane", 16}, {"16_lane", 8}, {"32_lane", 4}, {"64_lane", 2}} {
		if strings.Contains(s, p.s) {
			return p.n
		}
	}
	return 256
}
func (c *Catalog) offsetBits() int {
	if c.Architecture == "wasm64" {
		return 64
	}
	return 32
}
func count(r *reader) (int, error) {
	n, e := r.uleb(32)
	if e != nil {
		return 0, e
	}
	if n > uint64(len(r.b)-r.p) {
		return 0, ErrTruncated
	}
	return int(n), nil
}
func (c *Catalog) readValue(r *reader, kind string, o *Opcode) (Value, error) {
	switch kind {
	case "u32", "ordering":
		n, e := r.uleb(32)
		if kind == "ordering" && n > 1 {
			return Value{}, errors.New("invalid atomic ordering")
		}
		return U(n), e
	case "s32", "s64":
		bits := 32
		if kind == "s64" {
			bits = 64
		}
		n, e := r.sleb(bits)
		return S(n), e
	case "f32", "f64", "v128", "shuffle":
		n := 4
		if kind == "f64" {
			n = 8
		}
		if kind == "v128" || kind == "shuffle" {
			n = 16
		}
		if len(r.b)-r.p < n {
			return Value{}, ErrTruncated
		}
		if n <= 8 {
			var value uint64
			for i := 0; i < n; i++ {
				value |= uint64(r.b[r.p+i]) << uint(8*i)
			}
			r.p += n
			return U(value), nil
		}
		v := L()
		for i := 0; i < n; i++ {
			b := r.b[r.p+i]
			if kind == "shuffle" && b >= 32 {
				return Value{}, errors.New("invalid shuffle lane")
			}
			v.Items = append(v.Items, U(uint64(b)))
		}
		r.p += n
		return v, nil
	case "zero", "lane":
		b, e := r.byte()
		if e != nil {
			return Value{}, e
		}
		if (kind == "zero" && b != 0) || (kind == "lane" && uint64(b) >= laneLimit(o)) {
			return Value{}, errors.New("invalid reserved byte or SIMD lane")
		}
		return U(uint64(b)), nil
	case "memarg":
		flags, e := r.uleb(32)
		if e != nil {
			return Value{}, e
		}
		memory := uint64(0)
		if flags&64 != 0 {
			memory, e = r.uleb(32)
			if e != nil {
				return Value{}, e
			}
			flags ^= 64
		}
		if flags >= 64 {
			return Value{}, errors.New("invalid memarg alignment flags")
		}
		offset, e := r.uleb(c.offsetBits())
		return L(U(flags), U(offset), U(memory)), e
	case "heaptype":
		if r.p >= len(r.b) {
			return Value{}, ErrTruncated
		}
		b := r.b[r.p]
		if b == 0x65 || b == 0x62 {
			r.p++
			if b == 0x62 {
				n, e := r.uleb(32)
				return L(T("exact"), U(n)), e
			}
			code, e := r.byte()
			if e != nil {
				return Value{}, e
			}
			name, ok := abstractName(code)
			if !ok {
				return Value{}, errors.New("shared heap type must be abstract")
			}
			return L(T("shared"), T(name)), nil
		}
		n, e := r.sleb(33)
		if e != nil {
			return Value{}, e
		}
		if n >= 0 {
			return U(uint64(n)), nil
		}
		for name, b := range heapCodes {
			if n == int64(b)-128 {
				return T(name), nil
			}
		}
		return Value{}, errors.New("invalid abstract heap type")
	case "valtype", "reftype", "block":
		if r.p >= len(r.b) {
			return Value{}, ErrTruncated
		}
		b := r.b[r.p]
		if kind == "block" && b == 0x40 {
			r.p++
			return T("empty"), nil
		}
		if kind != "reftype" {
			for name, code := range valCodes {
				if b == code {
					r.p++
					return T(name), nil
				}
			}
		}
		if b == 0x63 || b == 0x64 {
			r.p++
			h, e := c.readValue(r, "heaptype", o)
			nullable := "ref"
			if b == 0x63 {
				nullable = "refnull"
			}
			return L(T(nullable), h), e
		}
		if _, ok := abstractName(b); ok || b == 0x65 {
			h, e := c.readValue(r, "heaptype", o)
			return L(T("refnull"), h), e
		}
		if kind == "block" {
			n, e := r.sleb(33)
			if e != nil {
				return Value{}, e
			}
			if n < 0 {
				return Value{}, errors.New("invalid block type")
			}
			return U(uint64(n)), nil
		}
		return Value{}, errors.New("invalid value type")
	case "br_table", "valtypes", "resume_table":
		n, e := count(r)
		if e != nil {
			return Value{}, e
		}
		if kind == "br_table" {
			n++
		}
		v := L()
		for i := 0; i < n; i++ {
			sub := "u32"
			if kind == "valtypes" {
				sub = "valtype"
			}
			var item Value
			if kind == "resume_table" {
				tag, e := r.byte()
				if e != nil {
					return Value{}, e
				}
				if tag > 1 {
					return Value{}, errors.New("invalid resume table tag")
				}
				x, e := r.uleb(32)
				if e != nil {
					return Value{}, e
				}
				item = L(U(uint64(tag)), U(x))
				if tag == 0 {
					label, e := r.uleb(32)
					if e != nil {
						return Value{}, e
					}
					item.Items = append(item.Items, U(label))
				}
			} else {
				item, e = c.readValue(r, sub, o)
				if e != nil {
					return Value{}, e
				}
			}
			v.Items = append(v.Items, item)
		}
		return v, nil
	case "try_table":
		bt, e := c.readValue(r, "block", o)
		if e != nil {
			return Value{}, e
		}
		n, e := count(r)
		if e != nil {
			return Value{}, e
		}
		catches := L()
		for i := 0; i < n; i++ {
			tag, e := r.byte()
			if e != nil {
				return Value{}, e
			}
			if tag > 3 {
				return Value{}, errors.New("invalid catch tag")
			}
			entry := L(U(uint64(tag)))
			if tag < 2 {
				x, e := r.uleb(32)
				if e != nil {
					return Value{}, e
				}
				entry.Items = append(entry.Items, U(x))
			}
			label, e := r.uleb(32)
			if e != nil {
				return Value{}, e
			}
			entry.Items = append(entry.Items, U(label))
			catches.Items = append(catches.Items, entry)
		}
		return L(bt, catches), nil
	case "cast":
		flags, e := r.byte()
		if e != nil {
			return Value{}, e
		}
		if flags > 3 {
			return Value{}, errors.New("invalid cast flags")
		}
		depth, e := r.uleb(32)
		if e != nil {
			return Value{}, e
		}
		from, e := c.readValue(r, "heaptype", o)
		if e != nil {
			return Value{}, e
		}
		to, e := c.readValue(r, "heaptype", o)
		return L(U(uint64(flags)), U(depth), from, to), e
	}
	return Value{}, fmt.Errorf("unknown immediate kind %s", kind)
}
func abstractName(b byte) (string, bool) {
	for n, c := range heapCodes {
		if b == c {
			return n, true
		}
	}
	return "", false
}
func (c *Catalog) writeValue(b []byte, v Value, kind string, o *Opcode) ([]byte, error) {
	switch kind {
	case "u32", "ordering":
		n, e := v.unsigned(32)
		if e != nil {
			return nil, e
		}
		if kind == "ordering" && n > 1 {
			return nil, errors.New("invalid atomic ordering")
		}
		return putU(b, n), nil
	case "s32", "s64":
		bits := 32
		if kind == "s64" {
			bits = 64
		}
		n, e := v.signed(bits)
		if e != nil {
			return nil, e
		}
		return putS(b, n), nil
	case "zero", "lane":
		n, e := v.unsigned(8)
		if e != nil {
			return nil, e
		}
		if (kind == "zero" && n != 0) || (kind == "lane" && n >= laneLimit(o)) {
			return nil, errors.New("invalid reserved byte or SIMD lane")
		}
		return append(b, byte(n)), nil
	case "f32", "f64":
		n := 4
		if kind == "f64" {
			n = 8
		}
		x, e := v.unsigned(n * 8)
		if e != nil {
			return nil, e
		}
		for i := 0; i < n; i++ {
			b = append(b, byte(x>>uint(8*i)))
		}
		return b, nil
	case "v128", "shuffle":
		items, e := list(v, 16)
		if e != nil {
			return nil, e
		}
		for _, item := range items {
			x, e := item.unsigned(8)
			if e != nil {
				return nil, e
			}
			if kind == "shuffle" && x >= 32 {
				return nil, errors.New("invalid shuffle lane")
			}
			b = append(b, byte(x))
		}
		return b, nil
	case "memarg":
		items, e := list(v, 3)
		if e != nil {
			return nil, e
		}
		align, e := items[0].unsigned(6)
		if e != nil {
			return nil, e
		}
		offset, e := items[1].unsigned(c.offsetBits())
		if e != nil {
			return nil, e
		}
		memory, e := items[2].unsigned(32)
		if e != nil {
			return nil, e
		}
		if memory != 0 {
			align |= 64
		}
		b = putU(b, align)
		if memory != 0 {
			b = putU(b, memory)
		}
		return putU(b, offset), nil
	case "heaptype":
		if v.Kind == "text" {
			code, ok := heapCodes[v.Text]
			if !ok {
				return nil, errors.New("unknown heap type")
			}
			return append(b, code), nil
		}
		if v.Kind == "number" {
			x, e := v.unsigned(32)
			if e != nil {
				return nil, e
			}
			return putS(b, int64(x)), nil
		}
		items, e := list(v, 2)
		if e != nil {
			return nil, e
		}
		if items[0].Text == "shared" {
			if items[1].Kind != "text" {
				return nil, errors.New("shared heap type must be abstract")
			}
			return c.writeValue(append(b, 0x65), items[1], "heaptype", o)
		}
		if items[0].Text == "exact" {
			n, e := items[1].unsigned(32)
			if e != nil {
				return nil, e
			}
			return putU(append(b, 0x62), n), nil
		}
		return nil, errors.New("invalid heap type")
	case "valtype", "reftype", "block":
		if v.Kind == "text" {
			if kind == "block" && v.Text == "empty" {
				return append(b, 0x40), nil
			}
			code, ok := valCodes[v.Text]
			if ok && kind != "reftype" {
				return append(b, code), nil
			}
			return nil, errors.New("invalid value type")
		}
		if v.Kind == "number" && kind == "block" {
			n, e := v.unsigned(32)
			if e != nil {
				return nil, e
			}
			return putS(b, int64(n)), nil
		}
		items, e := list(v, 2)
		if e != nil {
			return nil, e
		}
		if items[0].Text == "refnull" {
			if items[1].Kind == "text" || (items[1].Kind == "list" && len(items[1].Items) > 0 && items[1].Items[0].Text == "shared") {
				return c.writeValue(b, items[1], "heaptype", o)
			}
			return c.writeValue(append(b, 0x63), items[1], "heaptype", o)
		}
		if items[0].Text == "ref" {
			return c.writeValue(append(b, 0x64), items[1], "heaptype", o)
		}
		return nil, errors.New("invalid reference type")
	case "br_table", "valtypes", "resume_table":
		items, e := list(v, -1)
		if e != nil {
			return nil, e
		}
		n := len(items)
		if kind == "br_table" {
			if n == 0 {
				return nil, errors.New("br_table requires a default target")
			}
			n--
		}
		b = putU(b, uint64(n))
		for _, item := range items {
			if kind == "resume_table" {
				entry, e := list(item, -1)
				if e != nil || len(entry) < 2 {
					return nil, errors.New("invalid resume handle")
				}
				tag, e := entry[0].unsigned(1)
				if e != nil {
					return nil, e
				}
				length := 2
				if tag == 0 {
					length = 3
				}
				if len(entry) != length {
					return nil, errors.New("invalid resume handle length")
				}
				b = append(b, byte(tag))
				for _, x := range entry[1:] {
					b, e = c.writeValue(b, x, "u32", o)
					if e != nil {
						return nil, e
					}
				}
			} else {
				sub := "u32"
				if kind == "valtypes" {
					sub = "valtype"
				}
				b, e = c.writeValue(b, item, sub, o)
				if e != nil {
					return nil, e
				}
			}
		}
		return b, nil
	case "try_table":
		items, e := list(v, 2)
		if e != nil {
			return nil, e
		}
		b, e = c.writeValue(b, items[0], "block", o)
		if e != nil {
			return nil, e
		}
		entries, e := list(items[1], -1)
		if e != nil {
			return nil, e
		}
		b = putU(b, uint64(len(entries)))
		for _, item := range entries {
			entry, e := list(item, -1)
			if e != nil || len(entry) < 2 {
				return nil, errors.New("invalid catch")
			}
			tag, e := entry[0].unsigned(2)
			if e != nil {
				return nil, e
			}
			n := 2
			if tag < 2 {
				n = 3
			}
			if len(entry) != n {
				return nil, errors.New("invalid catch length")
			}
			b = append(b, byte(tag))
			for _, v := range entry[1:] {
				b, e = c.writeValue(b, v, "u32", o)
				if e != nil {
					return nil, e
				}
			}
		}
		return b, nil
	case "cast":
		items, e := list(v, 4)
		if e != nil {
			return nil, e
		}
		flags, e := items[0].unsigned(2)
		if e != nil {
			return nil, e
		}
		b = append(b, byte(flags))
		for i, sub := range []string{"u32", "heaptype", "heaptype"} {
			b, e = c.writeValue(b, items[i+1], sub, o)
			if e != nil {
				return nil, e
			}
		}
		return b, nil
	}
	return nil, fmt.Errorf("unknown immediate kind %s", kind)
}

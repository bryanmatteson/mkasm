package m68k

import (
	"errors"
	"fmt"
	"strings"
)

var eaMasks = map[byte]uint16{'*': 0xfff, '~': 0x1fc, '%': 0x1ff, ';': 0xffd, '@': 0x7fd, '!': 0x7e4, '&': 0x1e4, '$': 0x1fd, '?': 0x1e5, '/': 0x7e5, '|': 0x7e4, '>': 0x1f4, '<': 0x7ec, 'm': 0x1f, 'n': 0x220, 'o': 0xdc0, 'p': 0x3f, 'q': 0x3d, 'v': 0x1bd, 'b': 0x23d, 'w': 0x23c, 'y': 0x24, 'z': 0x224, '4': 0x3c}

func validEA(kind byte, code int) bool {
	mask, ok := eaMasks[kind]
	if !ok || code < 0 || code >= 61 {
		return false
	}
	mode := code >> 3
	if mode == 7 {
		mode = 7 + (code & 7)
	}
	return mask&(1<<uint(mode)) != 0
}
func isEA(k byte) bool { _, ok := eaMasks[k]; return ok }
func getList(v Value, n int) ([]Value, error) {
	if v.Kind != "list" || (n >= 0 && len(v.Items) != n) {
		return nil, fmt.Errorf("expected operand array of %d items", n)
	}
	return v.Items, nil
}
func number(v Value) (int64, error) {
	if v.Kind != "number" || v.U > uint64(1)<<63 {
		return 0, errors.New("expected integer operand")
	}
	if v.Negative {
		return -int64(v.U), nil
	}
	if v.U > uint64(^uint64(0)>>1) {
		return 0, errors.New("integer too large")
	}
	return int64(v.U), nil
}
func nums(v Value) ([]int64, error) {
	a, e := getList(v, -1)
	if e != nil {
		return nil, e
	}
	var r []int64
	for _, v := range a {
		x, e := number(v)
		if e != nil {
			return nil, e
		}
		r = append(r, x)
	}
	return r, nil
}
func hasFull(c *Catalog) bool {
	return c.Architecture == "m68k" && Profiles[c.CPU]&(4|8|16|32|256|512) != 0
}
func immBytes(place byte) int {
	switch place {
	case 'b', 'w':
		return 2
	case 'l', 'f', 's':
		return 4
	case 'F':
		return 8
	case 'x', 'p':
		return 12
	}
	return 0
}
func (c *Catalog) readEA(b []byte, p *int, code int, place byte) (Value, error) {
	v := L(U(uint64(code)))
	mode, reg := code>>3, code&7
	if mode == 5 || mode == 7 && (reg == 0 || reg == 2) {
		n, e := readInt(b, p, 16)
		if e != nil {
			return Value{}, e
		}
		v.Items = append(v.Items, S(n))
		return v, nil
	}
	if mode == 7 && reg == 1 {
		n, e := readInt(b, p, 32)
		if e != nil {
			return Value{}, e
		}
		v.Items = append(v.Items, U(uint64(uint32(n))))
		return v, nil
	}
	if mode == 6 || mode == 7 && reg == 3 {
		w, e := word(b, *p)
		if e != nil {
			return Value{}, e
		}
		*p += 2
		index := int64(w >> 12)
		long := int64((w >> 11) & 1)
		scale := int64(1) << ((w >> 9) & 3)
		if w&0x100 == 0 {
			if !hasFull(c) && c.Architecture == "m68k" && scale != 1 {
				return Value{}, errors.New("scaled index requires 68020")
			}
			if c.Architecture == "coldfire" && long == 0 {
				return Value{}, errors.New("ColdFire index must be long")
			}
			return L(U(uint64(code)), S(index), S(long), S(scale), S(0), S(sign(uint64(w&255), 8))), nil
		}
		if !hasFull(c) {
			return Value{}, errors.New("full index extension requires 68020")
		}
		if w&8 != 0 || w&0x30 == 0 || w&7 == 4 {
			return Value{}, errors.New("reserved full extension format")
		}
		bdSize := int((w >> 4) & 3)
		bd := int64(0)
		if bdSize >= 2 {
			bd, e = readInt(b, p, (bdSize-1)*16)
			if e != nil {
				return Value{}, e
			}
		}
		ind := int(w & 7)
		outerSize := 0
		if ind&3 >= 2 {
			outerSize = (ind&3 - 1) * 16
		}
		outer := int64(0)
		if outerSize > 0 {
			outer, e = readInt(b, p, outerSize)
			if e != nil {
				return Value{}, e
			}
		}
		return L(U(uint64(code)), S(index), S(long), S(scale), S(1), S(bd), S(int64((bdSize-1)*16)), S(int64((w>>7)&1)), S(int64((w>>6)&1)), S(int64(ind)), S(outer)), nil
	}
	if mode == 7 && reg == 4 {
		n := immBytes(place)
		if n == 0 {
			return Value{}, errors.New("immediate addressing forbidden for this size")
		}
		if *p+n > len(b) {
			return Value{}, ErrTruncated
		}
		if place == 'b' {
			v := decodeByteImmediate(b[*p : *p+2])
			*p += 2
			return L(U(60), v), nil
		}
		if place == 'w' || place == 'l' || place == 's' {
			bits := n * 8
			n1, e := readInt(b, p, bits)
			if e != nil {
				return Value{}, e
			}
			return L(U(uint64(code)), S(n1)), nil
		}
		data := L()
		for _, x := range b[*p : *p+n] {
			data.Items = append(data.Items, U(uint64(x)))
		}
		*p += n
		return L(U(uint64(code)), data), nil
	}
	if mode >= 7 {
		return Value{}, errors.New("reserved effective address")
	}
	return v, nil
}
func (c *Catalog) writeEA(b []byte, v Value, kind, place byte) ([]byte, int, error) {
	a, e := getList(v, -1)
	if e != nil || len(a) == 0 {
		return nil, 0, errors.New("invalid effective address")
	}
	n, e := a[0].unsigned(6)
	if e != nil {
		return nil, 0, e
	}
	code := int(n)
	if !validEA(kind, code) {
		return nil, 0, errors.New("addressing mode forbidden for operand")
	}
	mode, reg := code>>3, code&7
	if mode == 5 || mode == 7 && (reg == 0 || reg == 2) || mode == 7 && reg == 1 {
		if len(a) != 2 {
			return nil, 0, errors.New("address displacement required")
		}
		x, e := number(a[1])
		if e != nil {
			return nil, 0, e
		}
		bits := 16
		if mode == 7 && reg == 1 {
			bits = 32
		}
		if mode == 5 || mode == 7 && reg == 2 {
			if _, e = a[1].signed(bits); e != nil {
				return nil, 0, e
			}
		}
		b, e = appendInt(b, x, bits)
		return b, code, e
	}
	if mode == 6 || mode == 7 && reg == 3 {
		x, e := nums(v)
		if e != nil || len(x) < 6 {
			return nil, 0, errors.New("invalid indexed address")
		}
		if x[1] < 0 || x[1] > 15 || x[2] < 0 || x[2] > 1 {
			return nil, 0, errors.New("invalid index register")
		}
		scale := 0
		switch x[3] {
		case 1:
		case 2:
			scale = 1
		case 4:
			scale = 2
		case 8:
			scale = 3
		default:
			return nil, 0, errors.New("invalid index scale")
		}
		w := uint16(x[1]<<12 | x[2]<<11 | int64(scale)<<9)
		if x[4] == 0 {
			if len(x) != 6 || x[5] < -128 || x[5] > 127 {
				return nil, 0, errors.New("brief index displacement out of range")
			}
			if c.Architecture == "m68k" && !hasFull(c) && scale != 0 {
				return nil, 0, errors.New("scaled index requires 68020")
			}
			if c.Architecture == "coldfire" && x[2] == 0 {
				return nil, 0, errors.New("ColdFire index must be long")
			}
			w |= uint16(uint8(x[5]))
			return append(b, byte(w>>8), byte(w)), code, nil
		}
		if !hasFull(c) || len(x) != 11 || x[4] != 1 {
			return nil, 0, errors.New("invalid full index extension")
		}
		if (x[6] != 0 && x[6] != 16 && x[6] != 32) || x[7] < 0 || x[7] > 1 || x[8] < 0 || x[8] > 1 || x[9] < 0 || x[9] > 7 || x[9] == 4 {
			return nil, 0, errors.New("reserved full index fields")
		}
		w |= 0x100 | uint16((x[6]/16+1)<<4|x[7]<<7|x[8]<<6|x[9])
		b = append(b, byte(w>>8), byte(w))
		if x[6] != 0 {
			if _, e = S(x[5]).signed(int(x[6])); e != nil {
				return nil, 0, e
			}
			b, e = appendInt(b, x[5], int(x[6]))
			if e != nil {
				return nil, 0, e
			}
		} else if x[5] != 0 {
			return nil, 0, errors.New("null displacement must be zero")
		}
		outerBits := 0
		if x[9]&3 >= 2 {
			outerBits = int((x[9]&3)-1) * 16
		}
		if outerBits > 0 {
			if _, e = S(x[10]).signed(outerBits); e != nil {
				return nil, 0, e
			}
			b, e = appendInt(b, x[10], outerBits)
		} else if x[10] != 0 {
			return nil, 0, errors.New("unexpected outer displacement")
		}
		return b, code, e
	}
	if mode == 7 && reg == 4 {
		if len(a) != 2 {
			return nil, 0, errors.New("immediate value required")
		}
		n := immBytes(place)
		if n == 0 {
			return nil, 0, errors.New("invalid immediate size")
		}
		if place == 'b' {
			data, e := byteImmediate(a[1])
			return append(b, data...), code, e
		}
		if strings.ContainsRune("bwls", rune(place)) {
			x, e := number(a[1])
			if e != nil {
				return nil, 0, e
			}
			if place == 'b' && (x < -128 || x > 255) {
				return nil, 0, errors.New("byte immediate out of range")
			}
			if place == 'b' {
				return append(b, 0, byte(x)), code, nil
			}
			b, e = appendInt(b, x, n*8)
			return b, code, e
		}
		data, e := getList(a[1], n)
		if e != nil {
			return nil, 0, e
		}
		for _, v := range data {
			x, e := v.unsigned(8)
			if e != nil {
				return nil, 0, e
			}
			b = append(b, byte(x))
		}
		return b, code, nil
	}
	if len(a) != 1 {
		return nil, 0, errors.New("unexpected address extension")
	}
	return b, code, nil
}

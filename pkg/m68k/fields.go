package m68k

import (
	"fmt"
)

type segment struct {
	word, shift, value, width int
	invert                    bool
}

func segments(place byte, bits int) ([]segment, error) {
	s := func(w, shift int) []segment { return []segment{{w, shift, 0, bits, false}} }
	switch place {
	case 's', 'f':
		return s(0, 0), nil
	case 'd':
		return s(0, 9), nil
	case 'x':
		return s(0, 6), nil
	case '1', 'o':
		if place == 'o' {
			return []segment{{1, 12, 0, min(bits, 4), false}, {1, 7, 4, max(bits-4, 0), false}}, nil
		}
		return s(1, 12), nil
	case '2':
		return s(1, 6), nil
	case '3', 'j', 'C':
		return s(1, 0), nil
	case '4':
		return s(2, 12), nil
	case '5':
		return s(2, 6), nil
	case '6':
		return s(2, 0), nil
	case '7':
		return s(1, 7), nil
	case '8':
		return s(1, 10), nil
	case '9', '/':
		return s(1, 5), nil
	case 'k':
		return s(1, 4), nil
	case 'e':
		return s(0, 6), nil
	case 'E', 'I':
		return s(1, 9), nil
	case ']':
		return s(0, 10), nil
	case 'F':
		return s(0, 9), nil
	case 'G', 'H':
		return []segment{{0, 7, 0, 1, place == 'G'}, {1, 4, 1, 1, false}}, nil
	case 'm', 'n':
		a := []segment{{0, 9, 0, 3, false}, {0, 6, 3, 1, false}}
		if bits > 4 && place == 'm' {
			a = append(a, segment{1, 7, 4, 1, false})
		}
		return a, nil
	case 'M', 'N':
		w := 0
		if place == 'N' {
			w = 1
		}
		a := []segment{{w, 0, 0, min(bits, 4), false}}
		if bits > 4 {
			a = append(a, segment{1, 6, 4, 1, false})
		}
		return a, nil
	case ':':
		return s(1, 2), nil
	case 'h':
		return s(1, 10), nil
	case 'D':
		return []segment{{1, 12, 0, bits, false}, {1, 0, 0, bits, false}}, nil
	case 't':
		return []segment{{1, 7, 0, bits, false}, {1, 10, 0, bits, false}}, nil
	}
	return nil, fmt.Errorf("unsupported field placement %c", place)
}
func fieldRead(b []byte, place byte, bits int) (uint64, error) {
	s, e := segments(place, bits)
	if e != nil {
		return 0, e
	}
	var n uint64
	var known uint64
	for _, p := range s {
		if p.width == 0 {
			continue
		}
		w, e := word(b, p.word*2)
		if e != nil {
			return 0, e
		}
		mask := uint64(1)<<uint(p.width) - 1
		v := uint64(w>>uint(p.shift)) & mask
		if p.invert {
			v ^= mask
		}
		v <<= uint(p.value)
		m := mask << uint(p.value)
		if known&m != 0 && n&m != v&m {
			return 0, fmt.Errorf("duplicated operand fields differ")
		}
		n |= v
		known |= m
	}
	return n, nil
}
func fieldWrite(b []byte, place byte, bits int, n uint64) error {
	s, e := segments(place, bits)
	if e != nil {
		return e
	}
	if n >= uint64(1)<<uint(bits) {
		return fmt.Errorf("operand outside %d-bit range", bits)
	}
	for _, p := range s {
		if p.width == 0 {
			continue
		}
		w, e := word(b, p.word*2)
		if e != nil {
			return e
		}
		mask := uint16((1 << uint(p.width)) - 1)
		v := uint16(n>>uint(p.value)) & mask
		if p.invert {
			v ^= mask
		}
		w = w&^(mask<<uint(p.shift)) | v<<uint(p.shift)
		setWord(b, p.word*2, w)
	}
	return nil
}

package m68k

import "fmt"

func sampleEA(code int, place byte) Value {
	if code>>3 == 5 || code == 56 || code == 57 || code == 58 {
		return L(U(uint64(code)), S(2))
	}
	if code>>3 == 6 || code == 59 {
		return L(U(uint64(code)), U(0), U(1), U(1), U(0), S(2))
	}
	if code == 60 {
		if place == 'b' || place == 'w' || place == 'l' || place == 's' {
			return L(U(60), S(2))
		}
		data := L()
		for i := 0; i < immBytes(place); i++ {
			data.Items = append(data.Items, U(0))
		}
		return L(U(60), data)
	}
	return L(U(uint64(code)))
}
func sampleOpcode(c *Catalog, o *Opcode) ([]Value, error) {
	buf := make([]byte, max(8, fixedSize(o)))
	setWord(buf, 0, uint16(o.Opcode>>16))
	setWord(buf, 2, uint16(o.Opcode))
	values := make([]Value, 0)
	for _, pair := range pairs(o) {
		k, p := pair[0], pair[1]
		if isEA(k) {
			code := 0
			for !validEA(k, code) {
				code++
			}
			v := sampleEA(code, p)
			if p == '/' {
				v = L(v, U(0))
			}
			values = append(values, v)
			continue
		}
		if k == 'L' && p == '8' {
			values = append(values, U(1))
			continue
		}
		if k == 's' {
			values = append(values, U(1))
			continue
		}
		if k == 'I' {
			values = append(values, U(1))
			continue
		}
		if k == 'B' {
			values = append(values, S(2))
			continue
		}
		if k == 'd' {
			values = append(values, L(U(0), S(2)))
			continue
		}
		if k == '_' {
			values = append(values, U(2))
			continue
		}
		s := stream{b: buf, p: fixedSize(o)}
		v, e := c.operand(&s, o, pair, Value{})
		if e != nil {
			if k == 'i' {
				v = U(1)
			} else {
				return nil, fmt.Errorf("%s %s: %w", o.ID, pair, e)
			}
		}
		values = append(values, v)
	}
	return values, nil
}

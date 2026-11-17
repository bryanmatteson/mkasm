package m68k

import "strings"

var controlRegisters = map[string]uint64{"sfc": 0, "dfc": 1, "cacr": 2, "tc": 3, "itt0": 4, "itt1": 5, "dtt0": 6, "dtt1": 7, "buscr": 8, "rgpiobar": 9, "acr4": 12, "acr5": 13, "acr6": 14, "acr7": 15, "usp": 0x800, "vbr": 0x801, "caar": 0x802, "msp": 0x803, "isp": 0x804, "mmusr": 0x805, "urp": 0x806, "srp": 0x807, "pcr": 0x808, "pc": 0x80f, "rambar0": 0xc04, "rambar1": 0xc05, "mbar0": 0xc0e, "mbar1": 0xc0f, "cac": 0xffe, "mbo": 0xfff, "mbb": 0xfff, "asid": 3, "acr0": 4, "acr1": 5, "acr2": 6, "acr3": 7, "mmubar": 8, "cpucr": 0x802, "rombar": 0xc00, "rombar0": 0xc00, "rombar1": 0xc01, "flashbar": 0xc04, "rambar": 0xc05, "mpcr": 0xc0c, "edrambar": 0xc0d, "mbar2": 0xc0e, "secmbar": 0xc0e, "mbar": 0xc0f, "pcr1u0": 0xd02, "pcr1l0": 0xd03, "pcr2u0": 0xd04, "pcr2l0": 0xd05, "pcr3u0": 0xd06, "pcr3l0": 0xd07, "pcr1l1": 0xd0a, "pcr1u1": 0xd0b, "pcr2l1": 0xd0c, "pcr2u1": 0xd0d, "pcr3l1": 0xd0e, "pcr3u1": 0xd0f}

func registerValue(k, p byte, v Value) Value {
	if v.Kind != "text" {
		return v
	}
	s := strings.TrimPrefix(strings.ToLower(v.Text), "%")
	if name, ok := constants[k]; ok && s == name {
		return T(name)
	}
	if s == "sp" {
		s = "a7"
	} else if s == "fp" {
		s = "a6"
	}
	n := -1
	reg := func(prefix byte) int {
		if len(s) == 2 && s[0] == prefix && s[1] >= '0' && s[1] <= '7' {
			return int(s[1] - '0')
		}
		return -1
	}
	switch k {
	case 'D':
		n = reg('d')
	case 'A', 'a', '+', '-':
		n = reg('a')
	case 'R', 'r':
		n = reg('d')
		if n < 0 {
			n = reg('a')
			if n >= 0 {
				n += 8
			}
		}
	case 'F':
		if len(s) == 3 && strings.HasPrefix(s, "fp") && s[2] >= '0' && s[2] <= '7' {
			n = int(s[2] - '0')
		}
	case 'O':
		n = reg('d')
		if n >= 0 {
			n += 32
		}
	case 'X', 'Y', 'Z', 'W', '0', '1', '2', '3':
		if x, ok := mmuRegisters[s]; ok {
			return U(x)
		}
		if len(s) == 4 && (strings.HasPrefix(s, "bad") || strings.HasPrefix(s, "bac")) && s[3] >= '0' && s[3] <= '7' {
			selector := uint64(28)
			if s[2] == 'c' {
				selector = 29
			}
			return L(U(selector), U(uint64(s[3]-'0')))
		}
	case 'J':
		if x, ok := controlRegisters[s]; ok {
			return U(x)
		}
	case 'c':
		n = mapOrMinus(map[string]int{"nc": 0, "dc": 1, "ic": 2, "bc": 3}, s)
	case 'e':
		if len(s) == 4 && strings.HasPrefix(s, "acc") && s[3] >= '0' && s[3] <= '3' {
			n = int(s[3] - '0')
		}
	case 'g':
		n = mapOrMinus(map[string]int{"accext01": 0, "accext23": 1}, s)
	case 's':
		n = mapOrMinus(map[string]int{"fpiar": 1, "fpsr": 2, "fpcr": 4}, s)
	case 'f':
		n = mapOrMinus(map[string]int{"sfc": 0, "dfc": 1}, s)
	case 'k':
		if p == 'k' {
			n = reg('d')
		}
	case 'u':
		if len(s) == 3 && (s[2] == 'l' || s[2] == 'u') {
			half := s[2]
			s = s[:2]
			n = reg('d')
			if n < 0 {
				n = reg('a')
				if n >= 0 {
					n += 8
				}
			}
			if n >= 0 && half == 'u' {
				n += 16
			}
		}
	}
	if n >= 0 {
		return U(uint64(n))
	}
	return v
}
func mapOrMinus(m map[string]int, s string) int {
	if n, ok := m[s]; ok {
		return n
	}
	return -1
}

var mmuRegisters = map[string]uint64{"tt0": 2, "tt1": 3, "tc": 16, "drp": 17, "srp": 18, "crp": 19, "cal": 20, "val": 21, "scc": 22, "ac": 23, "psr": 24, "pcsr": 25}

func mmuRegistersByValue(n uint64) (string, bool) {
	for s, v := range mmuRegisters {
		if v == n {
			return s, true
		}
	}
	return "", false
}

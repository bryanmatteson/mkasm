package ir

import "fmt"

// MatchBitPattern reports whether word matches a 32-char bit pattern of 0/1/x
// (or other don't-care characters). Pattern index 0 is the MSB (bit 31).
//
// A pattern with no fixed 0/1 bits never matches (provisional all-x patterns
// from Pass 1 must not hit every word).
//
// Cherry-picked from improved-parser-design utilities (matchesPattern).
func MatchBitPattern(pattern string, word uint32) bool {
	if pattern == "" {
		return false
	}
	fixed := false
	for i := 0; i < 32 && i < len(pattern); i++ {
		bit := (word >> (31 - i)) & 1
		switch pattern[i] {
		case '0':
			fixed = true
			if bit != 0 {
				return false
			}
		case '1':
			fixed = true
			if bit != 1 {
				return false
			}
		case 'x', 'X', 'n', 'N', ' ':
			// don't care
		default:
			// variable field letters (Rd, imm, …) treated as don't care
		}
	}
	return fixed
}

// FixedBitsFromPattern returns (mask, value) for the fixed 0/1 bits in pattern.
// Pattern index 0 is MSB (bit 31).
func FixedBitsFromPattern(pattern string) (mask, value uint32) {
	for i := 0; i < 32 && i < len(pattern); i++ {
		shift := uint(31 - i)
		switch pattern[i] {
		case '0':
			mask |= 1 << shift
		case '1':
			mask |= 1 << shift
			value |= 1 << shift
		}
	}
	return mask, value
}

// FixedBitsFromEncoding derives (mask, value) from fixed bitfields.
// Field Start is the low bit index (LSB=0).
func FixedBitsFromEncoding(enc EncodingMask) (mask, value uint32) {
	for _, f := range enc.Fields {
		if f.Fixed == nil {
			continue
		}
		if f.Start < 0 || f.End < f.Start || f.Start > 31 {
			continue
		}
		width := f.End - f.Start + 1
		if width <= 0 || width > 32 || f.Start+width > 32 {
			continue
		}
		fieldMask := uint32((uint64(1)<<uint(width))-1) << uint(f.Start)
		fieldVal := uint32(*f.Fixed&((1<<uint(width))-1)) << uint(f.Start)
		mask |= fieldMask
		value |= fieldVal
	}
	return mask, value
}

// PatternFromEncoding builds a 32-char 0/1/x pattern from encoding fields.
// Index 0 is MSB. Variable fields become 'x'; fixed fields take their bits.
func PatternFromEncoding(enc EncodingMask) string {
	pat := make([]byte, 32)
	for i := range pat {
		pat[i] = 'x'
	}
	for _, f := range enc.Fields {
		if f.Fixed == nil {
			continue
		}
		if f.Start < 0 || f.End < f.Start || f.Start > 31 {
			continue
		}
		width := f.End - f.Start + 1
		for i := 0; i < width; i++ {
			bitPos := f.Start + i
			if bitPos < 0 || bitPos > 31 {
				continue
			}
			idx := 31 - bitPos
			if ((*f.Fixed) >> uint(i) & 1) == 1 {
				pat[idx] = '1'
			} else {
				pat[idx] = '0'
			}
		}
	}
	return string(pat)
}

// FixedWord returns the instruction word with only fixed bits set (variables zero).
// Prefers BitPattern; falls back to Encoding fixed fields.
func FixedWord(instr *InstructionIR) (word uint32, ok bool) {
	if instr == nil {
		return 0, false
	}
	pat := instr.BitPattern
	if pat == "" || !stringsContains01(pat) {
		pat = PatternFromEncoding(instr.Encoding)
	}
	mask, value := FixedBitsFromPattern(pat)
	if mask == 0 {
		mask, value = FixedBitsFromEncoding(instr.Encoding)
	}
	if mask == 0 {
		return 0, false
	}
	return value, true
}

func stringsContains01(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '0' || s[i] == '1' {
			return true
		}
	}
	return false
}

// ValidateBitFields checks field bounds and pairwise overlaps.
// Cherry-picked from improved-parser-design InstructionValidator.
func ValidateBitFields(fields []BitField) error {
	for i, f := range fields {
		if f.Start < 0 || f.End > 31 || f.Start > f.End {
			return fmt.Errorf("field %q invalid range [%d:%d]", f.Name, f.Start, f.End)
		}
		for j := i + 1; j < len(fields); j++ {
			g := fields[j]
			if f.Start <= g.End && g.Start <= f.End {
				return fmt.Errorf("fields %q and %q overlap", f.Name, g.Name)
			}
		}
	}
	return nil
}

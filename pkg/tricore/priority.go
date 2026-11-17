package tricore

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// SLEIGH gives a constructor precedence over a less-specific pattern it
// contains. COP's generic coprocessor opcodes, for example, contain the FPU
// instruction space. Subtract those regions so byte decoding, exact encoding,
// assembly and generated templates all observe the same source priority.
// Each result is a disjoint cube of the original source bit constraints; no
// opcode or operand value is invented to fill an unsupported source form.
func applyPriority(input []codec.Encoding) ([]codec.Encoding, error) {
	var out []codec.Encoding
	for i, e := range input {
		parts := []codec.Encoding{e}
		for j, narrow := range input {
			if i == j || !moreSpecific(narrow, e) {
				continue
			}
			var next []codec.Encoding
			for _, part := range parts {
				next = append(next, subtract(part, narrow)...)
			}
			parts = next
		}
		for n, part := range parts {
			if len(parts) != 1 || !sameMask(part.Mask, e.Mask) {
				part.ID = fmt.Sprintf("%s_p%d", e.ID, n)
			}
			var operands []codec.Operand
			var mask, value uint32
			for k := range part.Mask {
				mask |= uint32(part.Mask[k]) << uint(k*8)
				value |= uint32(part.Value[k]) << uint(k*8)
			}
			for _, o := range part.Operands {
				restricted, literal, err := restrictOperand(o, mask, value)
				if err != nil {
					return nil, fmt.Errorf("source priority %s: %w", e.ID, err)
				}
				if literal != "" {
					part.Syntax = strings.ReplaceAll(part.Syntax, "{"+o.Name+"}", literal)
				} else {
					operands = append(operands, restricted)
				}
			}
			part.Operands = operands
			out = append(out, part)
		}
	}
	return out, nil
}
func sameMask(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func moreSpecific(narrow, broad codec.Encoding) bool {
	if len(narrow.Mask) != len(broad.Mask) || len(narrow.Features) != len(broad.Features) {
		return false
	}
	for i, f := range narrow.Features {
		if f != broad.Features[i] {
			return false
		}
	}
	strict := false
	for i, m := range broad.Mask {
		if narrow.Mask[i]&m != m || narrow.Value[i]&m != broad.Value[i] {
			return false
		}
		strict = strict || narrow.Mask[i] != m
	}
	return strict
}
func subtract(broad, narrow codec.Encoding) []codec.Encoding {
	for i, m := range broad.Mask {
		if (m&narrow.Mask[i])&(broad.Value[i]^narrow.Value[i]) != 0 {
			return []codec.Encoding{broad}
		}
	}
	var out []codec.Encoding
	inside := broad
	inside.Mask = append([]byte(nil), broad.Mask...)
	inside.Value = append([]byte(nil), broad.Value...)
	for i := range inside.Mask {
		for bit := byte(1); bit != 0; bit <<= 1 {
			if narrow.Mask[i]&bit == 0 || inside.Mask[i]&bit != 0 {
				continue
			}
			inside.Mask[i] |= bit
			inside.Value[i] = (inside.Value[i] &^ bit) | (narrow.Value[i] & bit)
			outside := inside
			outside.Mask = append([]byte(nil), inside.Mask...)
			outside.Value = append([]byte(nil), inside.Value...)
			outside.Value[i] ^= bit
			out = append(out, outside)
		}
	}
	return out
}

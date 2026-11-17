package ir

import (
	"fmt"
	"strings"
	"unicode"
)

// BitDiffOp is a leaf comparison from an ARM encoding@bitdiffs expression.
type BitDiffOp int

const (
	BitDiffEq BitDiffOp = iota
	BitDiffNe
	BitDiffIn
)

// BitDiffAtom is one field comparison with bit patterns (MSB-first within the field).
// Start/End are absolute instruction bit indices (LSB = 0). End >= Start.
type BitDiffAtom struct {
	Field string
	Start int
	End   int
	Op    BitDiffOp
	// Bits is used for Eq/Ne; length must equal field width; 'x'/'X' = don't-care.
	Bits string
	// Alts is used for In; each entry same width rules as Bits.
	Alts []string
}

// BitDiffNode is a boolean tree over bitdiffs atoms.
// KindAnd: all Kids true. KindNot: !Kids[0]. KindAtom: Atom.
type BitDiffKind int

const (
	BitDiffAtomKind BitDiffKind = iota
	BitDiffAnd
	BitDiffNot
)

// BitDiffNode evaluates against an instruction word.
type BitDiffNode struct {
	Kind BitDiffKind
	Kids []*BitDiffNode
	Atom *BitDiffAtom
}

// MatchWord reports whether word matches BitPattern (or Encoding fixed bits)
// and satisfies BitDiffs constraints when present.
func MatchWord(instr *InstructionIR, word uint32) bool {
	if instr == nil {
		return false
	}
	pat := instr.BitPattern
	if pat == "" || !stringsContains01(pat) {
		pat = PatternFromEncoding(instr.Encoding)
	}
	if !MatchBitPattern(pat, word) {
		return false
	}
	if instr.BitDiffsTree != nil && !EvalBitDiffs(instr.BitDiffsTree, word) {
		return false
	}
	return true
}

// EvalBitDiffs evaluates a bitdiffs tree against word.
func EvalBitDiffs(n *BitDiffNode, word uint32) bool {
	if n == nil {
		return true
	}
	switch n.Kind {
	case BitDiffAnd:
		for _, k := range n.Kids {
			if !EvalBitDiffs(k, word) {
				return false
			}
		}
		return true
	case BitDiffNot:
		if len(n.Kids) == 0 {
			return true
		}
		return !EvalBitDiffs(n.Kids[0], word)
	default:
		if n.Atom == nil {
			return true
		}
		return evalAtom(n.Atom, word)
	}
}

func evalAtom(a *BitDiffAtom, word uint32) bool {
	if a.Start < 0 || a.End < a.Start || a.End > 31 {
		return true // unresolved field: do not reject
	}
	switch a.Op {
	case BitDiffEq:
		return matchFieldBits(word, a.Start, a.End, a.Bits)
	case BitDiffNe:
		return !matchFieldBits(word, a.Start, a.End, a.Bits)
	case BitDiffIn:
		for _, alt := range a.Alts {
			if matchFieldBits(word, a.Start, a.End, alt) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// matchFieldBits compares integer masks while preserving normalization's zero
// padding, truncation and ignored non-bit characters without building text.
func matchFieldBits(word uint32, start, end int, pattern string) bool {
	var mask, value uint32
	p := len(pattern)
	for bit := start; bit <= end; bit++ {
		c := byte('0')
		for p > 0 {
			p--
			if b := pattern[p]; b == '0' || b == '1' || b == 'x' || b == 'X' {
				c = b
				break
			}
		}
		if c == '0' || c == '1' {
			mask |= 1 << uint(bit)
			if c == '1' {
				value |= 1 << uint(bit)
			}
		}
	}
	return word&mask == value
}

// normalizeBitString pads/truncates to width. Shorter values are left-padded with '0'.
func normalizeBitString(s string, width int) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "'\"()")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '0' || r == '1' || r == 'x' || r == 'X':
			return r
		case unicode.IsSpace(r):
			return -1
		default:
			return -1
		}
	}, s)
	if len(s) == width {
		return s
	}
	if len(s) < width {
		return strings.Repeat("0", width-len(s)) + s
	}
	return s[len(s)-width:]
}

// ApplyBitDiffPins writes equality pins from tree into BitPattern and Encoding.Fixed.
// Inequality / IN / Not nodes are left for EvalBitDiffs at match time.
func ApplyBitDiffPins(instr *InstructionIR, tree *BitDiffNode) {
	if instr == nil || tree == nil {
		return
	}
	walkPins(tree, instr, false)
	// Drop operands that are now fully fixed.
	if len(instr.Operands) > 0 {
		fixed := map[string]bool{}
		for _, f := range instr.Encoding.Fields {
			if f.Fixed != nil && f.Name != "" {
				fixed[f.Name] = true
			}
		}
		kept := instr.Operands[:0]
		for _, op := range instr.Operands {
			if !fixed[op.Name] {
				kept = append(kept, op)
			}
		}
		instr.Operands = kept
	}
}

func walkPins(n *BitDiffNode, instr *InstructionIR, negated bool) {
	if n == nil {
		return
	}
	switch n.Kind {
	case BitDiffNot:
		if len(n.Kids) > 0 {
			walkPins(n.Kids[0], instr, !negated)
		}
	case BitDiffAnd:
		// A negated conjunction is a disjunction. No individual child is
		// required, even if a nested NOT would make its equality positive.
		if negated {
			return
		}
		for _, k := range n.Kids {
			walkPins(k, instr, negated)
		}
	default:
		if negated || n.Atom == nil || n.Atom.Op != BitDiffEq {
			return
		}
		pinEquality(instr, n.Atom)
	}
}

func pinEquality(instr *InstructionIR, a *BitDiffAtom) {
	if a.Start < 0 || a.End < a.Start || a.End > 31 {
		return
	}
	width := a.End - a.Start + 1
	bits := normalizeBitString(a.Bits, width)
	if len(bits) != width {
		return
	}

	pat := []byte(instr.BitPattern)
	if len(pat) != 32 {
		pat = []byte(PatternFromEncoding(instr.Encoding))
		if len(pat) != 32 {
			pat = bytesFilled(32, 'x')
		}
	}

	allFixed := true
	var val uint64
	for i := 0; i < width; i++ {
		bitPos := a.End - i
		idx := 31 - bitPos
		switch bits[i] {
		case '0':
			pat[idx] = '0'
		case '1':
			pat[idx] = '1'
			val |= 1 << uint(width-1-i)
		case 'x', 'X':
			allFixed = false
		default:
			allFixed = false
		}
	}
	instr.BitPattern = string(pat)

	idx := -1
	for i := range instr.Encoding.Fields {
		f := &instr.Encoding.Fields[i]
		if f.Start == a.Start && f.End == a.End {
			idx = i
			break
		}
		if a.Field != "" && f.Name == a.Field {
			idx = i
			break
		}
	}
	if idx >= 0 {
		f := &instr.Encoding.Fields[idx]
		f.Start = a.Start
		f.End = a.End
		if a.Field != "" {
			f.Name = a.Field
		}
		if allFixed {
			v := val
			f.Fixed = &v
			f.Source = "bitdiffs"
		}
		return
	}
	if allFixed {
		v := val
		instr.Encoding.Fields = append(instr.Encoding.Fields, BitField{
			Name:   a.Field,
			Start:  a.Start,
			End:    a.End,
			Fixed:  &v,
			Source: "bitdiffs",
		})
	}
}

func bytesFilled(n int, c byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

// ResolveBitDiffFields fills Start/End on atoms from Encoding field names.
func ResolveBitDiffFields(tree *BitDiffNode, enc EncodingMask) error {
	if tree == nil {
		return nil
	}
	byName := map[string]BitField{}
	for _, f := range enc.Fields {
		if f.Name != "" {
			byName[f.Name] = f
		}
	}
	var walk func(*BitDiffNode) error
	walk = func(n *BitDiffNode) error {
		if n == nil {
			return nil
		}
		if n.Kind == BitDiffAtomKind && n.Atom != nil {
			a := n.Atom
			if f, ok := byName[a.Field]; ok {
				a.Start = f.Start
				a.End = f.End
				width := a.End - a.Start + 1
				switch a.Op {
				case BitDiffEq, BitDiffNe:
					a.Bits = normalizeBitString(a.Bits, width)
				case BitDiffIn:
					for i := range a.Alts {
						a.Alts[i] = normalizeBitString(a.Alts[i], width)
					}
				}
				return nil
			}
			return fmt.Errorf("bitdiffs: unknown field %q", a.Field)
		}
		for _, k := range n.Kids {
			if err := walk(k); err != nil {
				// Keep going — some XML refs symbolic names not in regdiagram.
				_ = err
			}
		}
		return nil
	}
	return walk(tree)
}

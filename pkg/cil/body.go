package cil

import (
	"encoding/binary"
	"math"
)

func (c *Catalog) DecodeMethodBody(src []byte) (*MethodBody, error) {
	if len(src) == 0 {
		return nil, ErrTruncated
	}
	b := &MethodBody{}
	start := 0
	size := 0
	more := false
	switch src[0] & 3 {
	case 2:
		b.Tiny = true
		b.MaxStack = 8
		start = 1
		size = int(src[0] >> 2)
	case 3:
		if len(src) < 12 {
			return nil, ErrTruncated
		}
		flags := binary.LittleEndian.Uint16(src)
		if flags>>12 != 3 || flags&0x0fe4 != 0 {
			return nil, malformed("invalid fat method header")
		}
		b.MaxStack = binary.LittleEndian.Uint16(src[2:])
		n := binary.LittleEndian.Uint32(src[4:])
		if n > math.MaxInt32 {
			return nil, malformed("method code too large")
		}
		size = int(n)
		b.LocalSignatureToken = binary.LittleEndian.Uint32(src[8:])
		if b.LocalSignatureToken != 0 && !validToken("InlineSig", b.LocalSignatureToken) {
			return nil, malformed("invalid local signature token")
		}
		b.InitLocals = flags&16 != 0
		more = flags&8 != 0
		start = 12
	default:
		return nil, malformed("invalid method header format")
	}
	if size > len(src)-start {
		return nil, ErrTruncated
	}
	b.Code = append([]byte{}, src[start:start+size]...)
	in, err := c.DecodeMethod(b.Code)
	if err != nil {
		return nil, err
	}
	b.Instructions = in
	at := start + size
	if more {
		aligned := (at + 3) &^ 3
		if aligned > len(src) {
			return nil, ErrTruncated
		}
		b.Padding = append([]byte{}, src[at:aligned]...)
		at = aligned
	}
	for more {
		if len(src)-at < 4 {
			return nil, ErrTruncated
		}
		kind := src[at]
		if kind&0x3f != 1 {
			return nil, ErrUnsupported
		}
		fat := kind&0x40 != 0
		more = kind&0x80 != 0
		n := int(src[at+1])
		width := 12
		if fat {
			n |= int(src[at+2])<<8 | int(src[at+3])<<16
			width = 24
		} else if src[at+2] != 0 || src[at+3] != 0 {
			return nil, malformed("nonzero small EH reserved bytes")
		}
		if n < 4 || (n-4)%width != 0 {
			return nil, malformed("invalid EH section size")
		}
		if n > len(src)-at {
			return nil, ErrTruncated
		}
		section := ExceptionSection{Fat: fat, Clauses: make([]ExceptionClause, (n-4)/width)}
		for i := range section.Clauses {
			p := src[at+4+i*width:]
			e := &section.Clauses[i]
			if fat {
				e.Flags = binary.LittleEndian.Uint32(p)
				e.TryOffset = binary.LittleEndian.Uint32(p[4:])
				e.TryLength = binary.LittleEndian.Uint32(p[8:])
				e.HandlerOffset = binary.LittleEndian.Uint32(p[12:])
				e.HandlerLength = binary.LittleEndian.Uint32(p[16:])
				e.ClassTokenOrFilterOffset = binary.LittleEndian.Uint32(p[20:])
			} else {
				e.Flags = uint32(binary.LittleEndian.Uint16(p))
				e.TryOffset = uint32(binary.LittleEndian.Uint16(p[2:]))
				e.TryLength = uint32(p[4])
				e.HandlerOffset = uint32(binary.LittleEndian.Uint16(p[5:]))
				e.HandlerLength = uint32(p[7])
				e.ClassTokenOrFilterOffset = binary.LittleEndian.Uint32(p[8:])
			}
		}
		b.Sections = append(b.Sections, section)
		at += n
	}
	b.Length = at
	if err := validateEH(b.Sections, b.Instructions, uint32(size)); err != nil {
		return nil, err
	}
	return b, nil
}
func validateEH(sections []ExceptionSection, in []Instruction, size uint32) error {
	starts := map[uint32]bool{}
	pending := false
	for _, x := range in {
		if !pending {
			starts[x.Offset] = true
		}
		pending = stringsPrefix(x.Mnemonic)
	}
	ends := map[uint32]bool{size: true}
	for p := range starts {
		ends[p] = true
	}
	for _, s := range sections {
		for _, e := range s.Clauses {
			if e.Flags != 0 && e.Flags != 1 && e.Flags != 2 && e.Flags != 4 {
				return malformed("invalid EH clause flags")
			}
			if e.TryLength == 0 || e.HandlerLength == 0 || uint64(e.TryOffset)+uint64(e.TryLength) > uint64(size) || uint64(e.HandlerOffset)+uint64(e.HandlerLength) > uint64(size) {
				return malformed("EH region out of range")
			}
			if !starts[e.TryOffset] || !starts[e.HandlerOffset] || !ends[e.TryOffset+e.TryLength] || !ends[e.HandlerOffset+e.HandlerLength] {
				return malformed("EH boundary splits an instruction group")
			}
			switch e.Flags {
			case 0:
				if !validToken("InlineType", e.ClassTokenOrFilterOffset) {
					return malformed("invalid catch class token")
				}
			case 1:
				if !starts[e.ClassTokenOrFilterOffset] || e.ClassTokenOrFilterOffset >= e.HandlerOffset {
					return malformed("invalid filter offset")
				}
			case 2, 4:
				if e.ClassTokenOrFilterOffset != 0 {
					return malformed("nonzero finally/fault reserved value")
				}
			}
		}
	}
	return validateEHNesting(sections, in)
}
func stringsPrefix(name string) bool {
	return name == "unaligned." || name == "volatile." || name == "tail." || name == "constrained." || name == "readonly."
}
func (c *Catalog) EncodeMethodBody(b *MethodBody) ([]byte, error) {
	if b == nil {
		return nil, malformed("nil method body")
	}
	code := append([]byte{}, b.Code...)
	var in []Instruction
	var err error
	if b.Instructions != nil {
		code, err = c.EncodeMethod(b.Instructions)
		if err != nil {
			return nil, err
		}
	}
	in, err = c.DecodeMethod(code)
	if err != nil {
		return nil, err
	}
	if b.LocalSignatureToken != 0 && !validToken("InlineSig", b.LocalSignatureToken) {
		return nil, malformed("invalid local signature token")
	}
	if err := validateEH(b.Sections, in, uint32(len(code))); err != nil {
		return nil, err
	}
	if b.Tiny {
		if len(code) >= 64 || b.MaxStack != 8 || b.InitLocals || b.LocalSignatureToken != 0 || len(b.Sections) > 0 || len(b.Padding) > 0 {
			return nil, malformed("invalid tiny method attributes")
		}
		return append([]byte{byte(len(code)<<2) | 2}, code...), nil
	}
	out := make([]byte, 12)
	flags := uint16(0x3003)
	if b.InitLocals {
		flags |= 16
	}
	if len(b.Sections) > 0 {
		flags |= 8
	}
	binary.LittleEndian.PutUint16(out, flags)
	binary.LittleEndian.PutUint16(out[2:], b.MaxStack)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(code)))
	binary.LittleEndian.PutUint32(out[8:], b.LocalSignatureToken)
	out = append(out, code...)
	if len(b.Sections) > 0 {
		padding := (4 - len(out)%4) % 4
		if b.Padding != nil && len(b.Padding) != padding {
			return nil, malformed("invalid EH alignment padding")
		}
		if b.Padding == nil {
			out = append(out, make([]byte, padding)...)
		} else {
			out = append(out, b.Padding...)
		}
	} else if len(b.Padding) > 0 {
		return nil, malformed("padding without sections")
	}
	for i, s := range b.Sections {
		width := 12
		kind := byte(1)
		if s.Fat {
			width = 24
			kind |= 0x40
		}
		if i+1 < len(b.Sections) {
			kind |= 0x80
		}
		n := 4 + width*len(s.Clauses)
		if n > 0xffffff || !s.Fat && n > 255 {
			return nil, malformed("EH section too large")
		}
		start := len(out)
		out = append(out, make([]byte, n)...)
		out[start] = kind
		out[start+1] = byte(n)
		if s.Fat {
			out[start+2] = byte(n >> 8)
			out[start+3] = byte(n >> 16)
		}
		for j, e := range s.Clauses {
			p := out[start+4+j*width:]
			if s.Fat {
				binary.LittleEndian.PutUint32(p, e.Flags)
				binary.LittleEndian.PutUint32(p[4:], e.TryOffset)
				binary.LittleEndian.PutUint32(p[8:], e.TryLength)
				binary.LittleEndian.PutUint32(p[12:], e.HandlerOffset)
				binary.LittleEndian.PutUint32(p[16:], e.HandlerLength)
				binary.LittleEndian.PutUint32(p[20:], e.ClassTokenOrFilterOffset)
			} else {
				if e.TryOffset > math.MaxUint16 || e.HandlerOffset > math.MaxUint16 || e.TryLength > 255 || e.HandlerLength > 255 {
					return nil, malformed("EH clause does not fit small format")
				}
				binary.LittleEndian.PutUint16(p, uint16(e.Flags))
				binary.LittleEndian.PutUint16(p[2:], uint16(e.TryOffset))
				p[4] = byte(e.TryLength)
				binary.LittleEndian.PutUint16(p[5:], uint16(e.HandlerOffset))
				p[7] = byte(e.HandlerLength)
				binary.LittleEndian.PutUint32(p[8:], e.ClassTokenOrFilterOffset)
			}
		}
	}
	return out, nil
}

// EH regions are lexical intervals. ECMA-335 I.12.4.2.7 permits only nested,
// disjoint, or mutually protecting entries, in innermost-first table order.
type ehRegion struct {
	start, end uint32
	filter     bool
}

func ehRegions(e ExceptionClause) []ehRegion {
	r := []ehRegion{{e.TryOffset, e.TryOffset + e.TryLength, false}, {e.HandlerOffset, e.HandlerOffset + e.HandlerLength, false}}
	if e.Flags == 1 {
		r = append(r, ehRegion{e.ClassTokenOrFilterOffset, e.HandlerOffset, true})
	}
	return r
}
func ehOverlap(a, b ehRegion) bool  { return a.start < b.end && b.start < a.end }
func ehContains(a, b ehRegion) bool { return a.start <= b.start && b.end <= a.end }
func ehNested(a, b []ehRegion) bool {
	for _, outer := range b {
		if outer.filter {
			continue
		}
		all := true
		for _, inner := range a {
			all = all && ehContains(outer, inner)
		}
		if all {
			return true
		}
	}
	return false
}
func ehDisjoint(a, b []ehRegion) bool {
	for _, x := range a {
		for _, y := range b {
			if ehOverlap(x, y) {
				return false
			}
		}
	}
	return true
}
func validateEHNesting(sections []ExceptionSection, in []Instruction) error {
	var entries []ExceptionClause
	for _, s := range sections {
		entries = append(entries, s.Clauses...)
	}
	for i, a := range entries {
		ar := ehRegions(a)
		for x := range ar {
			for y := 0; y < x; y++ {
				if ehOverlap(ar[x], ar[y]) {
					return malformed("overlapping regions of one EH entry")
				}
			}
		}
		if a.Flags == 1 {
			last := ""
			for _, x := range in {
				if x.Offset < a.HandlerOffset && x.Offset >= a.ClassTokenOrFilterOffset {
					last = x.Mnemonic
				}
			}
			if last != "endfilter" {
				return malformed("filter must end with endfilter")
			}
		}
		for j := 0; j < i; j++ {
			b := entries[j]
			br := ehRegions(b)
			if ehNested(br, ar) || ehDisjoint(ar, br) {
				continue
			}
			if a.TryOffset == b.TryOffset && a.TryLength == b.TryLength && (a.Flags == 0 || a.Flags == 1) && (b.Flags == 0 || b.Flags == 1) && ehDisjoint(ar[1:], br[1:]) {
				continue
			}
			return malformed("EH entries must nest in innermost-first order, be disjoint, or mutually protect")
		}
	}
	return nil
}

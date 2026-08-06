package x86

import (
	"errors"
	"fmt"
	"sort"
)

var (
	ErrShortInstruction = errors.New("truncated x86 instruction")
	ErrInstructionLong  = errors.New("x86 instruction exceeds 15 bytes")
	ErrUnknownEncoding  = errors.New("unknown x86 encoding")
)

const dispatchTableSize = int(encodingKindCount) * int(opcodeMapCount) * 256

type decodeBucket struct {
	start uint32
	count uint16
}

// Decoder dispatches by normalized prefix family, opcode map, and opcode byte.
// Its Decode method allocates no memory.
type Decoder struct {
	catalog    *Catalog
	buckets    [dispatchTableSize]decodeBucket
	candidates []uint32
}

// Decoded identifies a catalog form and its byte length. Alternatives counts
// other syntax forms that match the same bytes without allocating a slice.
type Decoded struct {
	CatalogIndex uint32
	Length       uint8
	Alternatives uint16
}

func (d Decoded) Encoding(decoder *Decoder) *Encoding {
	if decoder == nil || decoder.catalog == nil || int(d.CatalogIndex) >= len(decoder.catalog.Encodings) {
		return nil
	}
	return &decoder.catalog.Encodings[d.CatalogIndex]
}

// NewDecoder compiles a catalog into a fixed-size direct dispatch table.
func NewDecoder(catalog *Catalog) (*Decoder, error) {
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	type keyedCandidate struct {
		index uint32
		key   int
	}
	keyed := make([]keyedCandidate, 0, len(catalog.Encodings))
	for i := range catalog.Encodings {
		e := &catalog.Encodings[i]
		count := 1
		if e.OpcodePlusReg {
			count = 8
		}
		for opcodeOffset := 0; opcodeOffset < count; opcodeOffset++ {
			keyed = append(keyed, keyedCandidate{
				index: uint32(i),
				key:   dispatchIndex(e.Kind, e.Map, e.Opcode+byte(opcodeOffset)),
			})
		}
	}
	sort.Slice(keyed, func(i, j int) bool {
		if keyed[i].key != keyed[j].key {
			return keyed[i].key < keyed[j].key
		}
		a := &catalog.Encodings[keyed[i].index]
		b := &catalog.Encodings[keyed[j].index]
		return a.FormID < b.FormID
	})

	d := &Decoder{catalog: catalog, candidates: make([]uint32, len(keyed))}
	for i := range keyed {
		d.candidates[i] = keyed[i].index
	}
	for start := 0; start < len(keyed); {
		key := keyed[start].key
		end := start + 1
		for end < len(keyed) && keyed[end].key == key {
			end++
		}
		if end-start > int(^uint16(0)) {
			return nil, fmt.Errorf("x86 dispatch bucket %d has %d candidates", key, end-start)
		}
		d.buckets[key] = decodeBucket{start: uint32(start), count: uint16(end - start)}
		start = end
	}
	return d, nil
}

type decodedHead struct {
	kind            EncodingKind
	opcodeMap       OpcodeMap
	opcode          byte
	prefixBits      byte
	w               byte
	vectorLength    uint16
	addressOverride bool
	modrmOffset     int
}

// Decode decodes one instruction from the start of src in the requested mode.
func (d *Decoder) Decode(src []byte, mode Mode) (Decoded, error) {
	if d == nil || d.catalog == nil || !modeAll.supports(mode) {
		return Decoded{}, ErrUnknownEncoding
	}
	head, err := parseHead(src, mode)
	if err != nil {
		return Decoded{}, err
	}
	bucket := d.buckets[dispatchIndex(head.kind, head.opcodeMap, head.opcode)]
	if bucket.count == 0 {
		return Decoded{}, ErrUnknownEncoding
	}

	var best Decoded
	matched := uint16(0)
	for i := uint32(0); i < uint32(bucket.count); i++ {
		catalogIndex := d.candidates[bucket.start+i]
		encoding := &d.catalog.Encodings[catalogIndex]
		length, ok, short := matchEncoding(src, mode, head, encoding)
		if short && matched == 0 {
			err = ErrShortInstruction
		}
		if !ok {
			continue
		}
		if matched == 0 {
			best = Decoded{CatalogIndex: catalogIndex, Length: uint8(length)}
		}
		matched++
	}
	if matched == 0 {
		if err != nil {
			return Decoded{}, err
		}
		return Decoded{}, ErrUnknownEncoding
	}
	best.Alternatives = matched - 1
	return best, nil
}

func matchEncoding(src []byte, mode Mode, head decodedHead, e *Encoding) (length int, matched, short bool) {
	if !e.Modes.supports(mode) || head.prefixBits&e.PrefixMask != e.PrefixValue {
		return 0, false, false
	}
	if e.W != BitAny && byte(e.W) != head.w {
		return 0, false, false
	}
	if e.VectorLength != 0 && e.VectorLength != head.vectorLength {
		return 0, false, false
	}
	end := head.modrmOffset
	if e.HasModRM {
		var ok bool
		end, ok, short = modRMLength(src, mode, head.addressOverride, head.modrmOffset, e)
		if !ok {
			return 0, false, short
		}
	}
	for _, tail := range e.Tail {
		end += tailBytes(tail, mode, head.prefixBits&1 != 0, head.w != 0, head.addressOverride)
	}
	if end > 15 {
		return 0, false, false
	}
	if end > len(src) {
		return 0, false, true
	}
	return end, true, false
}

func modRMLength(src []byte, mode Mode, addressOverride bool, offset int, e *Encoding) (int, bool, bool) {
	if offset >= len(src) {
		return 0, false, true
	}
	modrm := src[offset]
	mod, reg, rm := modrm>>6, (modrm>>3)&7, modrm&7
	if (e.Mod == ModMemory && mod == 3) || (e.Mod == ModRegister && mod != 3) || reg&e.RegMask != e.RegValue || rm&e.RMMask != e.RMValue {
		return 0, false, false
	}
	end := offset + 1
	if mod == 3 {
		return end, true, false
	}
	addressBits := effectiveAddressBits(mode, addressOverride)
	if addressBits == 16 {
		if mod == 0 && rm == 6 {
			end += 2
		} else if mod == 1 {
			end++
		} else if mod == 2 {
			end += 2
		}
	} else {
		if rm == 4 {
			if end >= len(src) {
				return 0, false, true
			}
			sib := src[end]
			end++
			if mod == 0 && sib&7 == 5 {
				end += 4
			}
		}
		if mod == 0 && rm == 5 {
			end += 4
		} else if mod == 1 {
			end++
		} else if mod == 2 {
			end += 4
		}
	}
	if end > len(src) {
		return 0, false, true
	}
	return end, true, false
}

func parseHead(src []byte, mode Mode) (decodedHead, error) {
	var h decodedHead
	if len(src) == 0 {
		return h, ErrShortInstruction
	}
	pos := 0
	for pos < len(src) && pos < 15 {
		switch src[pos] {
		case 0x66:
			h.prefixBits |= 1 << 0
		case 0xf3:
			h.prefixBits |= 1 << 1
		case 0xf2:
			h.prefixBits |= 1 << 2
		case 0x67:
			h.addressOverride = true
		case 0xf0, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65:
		default:
			goto prefixesDone
		}
		pos++
	}
prefixesDone:
	if pos >= 15 {
		return h, ErrInstructionLong
	}
	if pos >= len(src) {
		return h, ErrShortInstruction
	}
	if mode == Mode64 && src[pos] >= 0x40 && src[pos] <= 0x4f {
		h.w = (src[pos] >> 3) & 1
		pos++
		if pos >= len(src) {
			return h, ErrShortInstruction
		}
	}

	switch src[pos] {
	case 0xc5:
		if pos+2 >= len(src) {
			return h, ErrShortInstruction
		}
		h.kind, h.opcodeMap = EncodingVEX, Map0F
		p1 := src[pos+1]
		h.prefixBits = prefixBitsFromPP(p1 & 3)
		h.vectorLength = 128 << ((p1 >> 2) & 1)
		pos += 2
	case 0xc4:
		if pos+3 >= len(src) {
			return h, ErrShortInstruction
		}
		h.kind = EncodingVEX
		var ok bool
		h.opcodeMap, ok = mapFromMmmmm(src[pos+1] & 0x1f)
		if !ok {
			return h, ErrUnknownEncoding
		}
		p2 := src[pos+2]
		h.w, h.prefixBits = p2>>7, prefixBitsFromPP(p2&3)
		h.vectorLength = 128 << ((p2 >> 2) & 1)
		pos += 3
	case 0x62:
		if pos+4 >= len(src) {
			return h, ErrShortInstruction
		}
		h.kind = EncodingEVEX
		var ok bool
		h.opcodeMap, ok = mapFromMmmmm(src[pos+1] & 7)
		if !ok {
			return h, ErrUnknownEncoding
		}
		p1, p2 := src[pos+2], src[pos+3]
		h.w, h.prefixBits = p1>>7, prefixBitsFromPP(p1&3)
		switch (p2 >> 5) & 3 {
		case 0:
			h.vectorLength = 128
		case 1:
			h.vectorLength = 256
		case 2:
			h.vectorLength = 512
		default:
			return h, ErrUnknownEncoding
		}
		pos += 4
	case 0x8f:
		if pos+1 < len(src) && src[pos+1]&0x1f >= 8 {
			if pos+3 >= len(src) {
				return h, ErrShortInstruction
			}
			h.kind = EncodingXOP
			var ok bool
			h.opcodeMap, ok = mapFromMmmmm(src[pos+1] & 0x1f)
			if !ok {
				return h, ErrUnknownEncoding
			}
			p2 := src[pos+2]
			h.w, h.prefixBits = p2>>7, prefixBitsFromPP(p2&3)
			h.vectorLength = 128 << ((p2 >> 2) & 1)
			pos += 3
		}
	}

	if h.kind == EncodingLegacy {
		if src[pos] == 0x0f {
			pos++
			if pos >= len(src) {
				return h, ErrShortInstruction
			}
			switch src[pos] {
			case 0x38:
				h.opcodeMap = Map0F38
				pos++
			case 0x3a:
				h.opcodeMap = Map0F3A
				pos++
			case 0x0f:
				return h, ErrUnknownEncoding // 3DNow selector follows ModR/M.
			default:
				h.opcodeMap = Map0F
			}
		}
	}
	if pos >= len(src) {
		return h, ErrShortInstruction
	}
	h.opcode = src[pos]
	h.modrmOffset = pos + 1
	return h, nil
}

func dispatchIndex(kind EncodingKind, opcodeMap OpcodeMap, opcode byte) int {
	return (int(kind)*int(opcodeMapCount)+int(opcodeMap))*256 + int(opcode)
}

func prefixBitsFromPP(pp byte) byte {
	switch pp {
	case 1:
		return 1 << 0
	case 2:
		return 1 << 1
	case 3:
		return 1 << 2
	default:
		return 0
	}
}

func mapFromMmmmm(m byte) (OpcodeMap, bool) {
	switch m {
	case 1:
		return Map0F, true
	case 2:
		return Map0F38, true
	case 3:
		return Map0F3A, true
	case 8:
		return MapXOP8, true
	case 9:
		return MapXOP9, true
	case 10:
		return MapXOPA, true
	default:
		return 0, false
	}
}

func tailBytes(width TailWidth, mode Mode, operandOverride, w, addressOverride bool) int {
	switch width {
	case Tail8:
		return 1
	case Tail16:
		return 2
	case Tail32:
		return 4
	case Tail64:
		return 8
	case TailZ:
		if effectiveOperandBits(mode, operandOverride, w) == 16 {
			return 2
		}
		return 4
	case TailV:
		return effectiveOperandBits(mode, operandOverride, w) / 8
	case TailAddress:
		return effectiveAddressBits(mode, addressOverride) / 8
	case TailFarPointer:
		if effectiveOperandBits(mode, operandOverride, w) == 16 {
			return 4
		}
		return 6
	default:
		return 0
	}
}

func effectiveOperandBits(mode Mode, override, w bool) int {
	switch mode {
	case Mode16:
		if override {
			return 32
		}
		return 16
	case Mode64:
		if w {
			return 64
		}
		if override {
			return 16
		}
		return 32
	default:
		if override {
			return 16
		}
		return 32
	}
}

func effectiveAddressBits(mode Mode, override bool) int {
	switch mode {
	case Mode16:
		if override {
			return 32
		}
		return 16
	case Mode64:
		if override {
			return 32
		}
		return 64
	default:
		if override {
			return 16
		}
		return 32
	}
}

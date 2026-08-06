package x86

import "errors"

var (
	ErrBufferTooSmall     = errors.New("x86 encoding buffer is too small")
	ErrInvalidEncodeField = errors.New("invalid x86 encoding field")
	ErrUnsupportedFamily  = errors.New("x86 encoding family is not yet supported")
)

// EncodeFields contains physical encoding fields, not semantic operands. This
// is the stable boundary on which generated typed assembler methods are built.
type EncodeFields struct {
	Mode            Mode
	SegmentOverride byte
	AddressOverride bool
	Mod             byte
	Reg             byte
	RM              byte
	Scale           byte
	Index           byte
	Base            byte
	UseSIB          bool
	VVVV            byte
	Mask            byte
	Zeroing         bool
	Broadcast       bool
	OpcodeReg       byte
	Displacement    int64
	Immediate       [4]uint64
}

// Encode writes one exact encoding into dst and returns its length. It does not
// allocate. Callers normally provide a [15]byte buffer.
func Encode(dst []byte, e *Encoding, fields EncodeFields) (int, error) {
	if e == nil || len(dst) == 0 || !e.Modes.supports(fields.Mode) {
		return 0, ErrInvalidEncodeField
	}
	if fields.SegmentOverride != 0 && fields.SegmentOverride != 0x26 && fields.SegmentOverride != 0x2e && fields.SegmentOverride != 0x36 && fields.SegmentOverride != 0x3e && fields.SegmentOverride != 0x64 && fields.SegmentOverride != 0x65 {
		return 0, ErrInvalidEncodeField
	}
	if e.OperandSize == 64 && fields.Mode != Mode64 {
		return 0, ErrInvalidEncodeField
	}
	if fields.Reg > 31 || fields.RM > 31 || fields.Index > 31 || fields.Base > 31 || fields.VVVV > 31 || fields.Mask > 7 || fields.OpcodeReg > 15 || fields.Mod > 3 || fields.Scale > 3 {
		return 0, ErrInvalidEncodeField
	}
	if e.Kind != EncodingEVEX && (fields.Mask != 0 || fields.Zeroing || fields.Broadcast) {
		return 0, ErrInvalidEncodeField
	}
	if e.Kind != EncodingEVEX && (fields.Reg > 15 || fields.RM > 15 || fields.Index > 15 || fields.Base > 15 || fields.VVVV > 15) {
		return 0, ErrInvalidEncodeField
	}
	if e.RegMask != 0 && fields.Reg&e.RegMask != e.RegValue || e.RMMask != 0 && fields.RM&e.RMMask != e.RMValue {
		return 0, ErrInvalidEncodeField
	}
	if e.Mod == ModMemory && fields.Mod == 3 || e.Mod == ModRegister && fields.Mod != 3 {
		return 0, ErrInvalidEncodeField
	}

	pos := 0
	put := func(b byte) bool {
		if pos >= len(dst) || pos >= 15 {
			return false
		}
		dst[pos] = b
		pos++
		return true
	}
	if fields.SegmentOverride != 0 && !put(fields.SegmentOverride) {
		return 0, ErrBufferTooSmall
	}
	if fields.AddressOverride && !put(0x67) {
		return 0, ErrBufferTooSmall
	}
	if e.Kind == EncodingLegacy {
		operandOverride := operandSizeOverride(fields.Mode, e.OperandSize)
		if operandOverride && e.MandatoryPrefix != Prefix66 && !put(0x66) {
			return 0, ErrBufferTooSmall
		}
		if prefix := mandatoryPrefixByte(e.MandatoryPrefix); prefix != 0 && !put(prefix) {
			return 0, ErrBufferTooSmall
		}
		rex := byte(0)
		if fields.Mode == Mode64 {
			if e.W == BitOne || e.OperandSize == 64 {
				rex |= 1 << 3
			}
			rex |= (fields.Reg >> 3 & 1) << 2
			if e.OpcodePlusReg {
				rex |= fields.OpcodeReg >> 3 & 1
			} else if fields.UseSIB {
				rex |= (fields.Index >> 3 & 1) << 1
				rex |= fields.Base >> 3 & 1
			} else {
				rex |= fields.RM >> 3 & 1
			}
		}
		if rex != 0 && !put(0x40|rex) {
			return 0, ErrBufferTooSmall
		}
		opcode := e.Opcode
		if e.OpcodePlusReg {
			opcode |= fields.OpcodeReg & 7
		}
		if !putOpcodeMap(&pos, dst, e.Map) || !put(opcode) {
			return 0, ErrBufferTooSmall
		}
	} else {
		prefix, n, err := vectorPrefix(e, fields)
		if err != nil {
			return 0, err
		}
		for i := 0; i < n; i++ {
			if !put(prefix[i]) {
				return 0, ErrBufferTooSmall
			}
		}
		if !put(e.Opcode) {
			return 0, ErrBufferTooSmall
		}
	}

	if e.HasModRM {
		if !put((fields.Mod << 6) | ((fields.Reg & 7) << 3) | (fields.RM & 7)) {
			return 0, ErrBufferTooSmall
		}
		if fields.Mod != 3 {
			addressBits := effectiveAddressBits(fields.Mode, fields.AddressOverride)
			if fields.UseSIB {
				if addressBits == 16 || fields.RM&7 != 4 || !put((fields.Scale<<6)|((fields.Index&7)<<3)|(fields.Base&7)) {
					return 0, ErrInvalidEncodeField
				}
			}
			dispBase := fields.RM & 7
			if fields.UseSIB {
				dispBase = fields.Base & 7
			}
			dispBytes := displacementBytes(fields.Mod, dispBase, fields.UseSIB, addressBits)
			if pos+dispBytes > len(dst) || pos+dispBytes > 15 {
				return 0, ErrBufferTooSmall
			}
			writeLittleEndian(dst[pos:pos+dispBytes], uint64(fields.Displacement))
			pos += dispBytes
		}
	}
	for i, tail := range e.Tail {
		width := tailBytes(tail, fields.Mode, e.MandatoryPrefix == Prefix66 || operandSizeOverride(fields.Mode, e.OperandSize), e.W == BitOne || e.OperandSize == 64, fields.AddressOverride)
		if pos+width > len(dst) || pos+width > 15 {
			return 0, ErrBufferTooSmall
		}
		writeLittleEndian(dst[pos:pos+width], fields.Immediate[i])
		pos += width
	}
	return pos, nil
}

func operandSizeOverride(mode Mode, size uint8) bool {
	switch mode {
	case Mode16:
		return size == 32
	case Mode32, Mode64:
		return size == 16
	default:
		return false
	}
}

func mandatoryPrefixByte(prefix MandatoryPrefix) byte {
	switch prefix {
	case Prefix66:
		return 0x66
	case PrefixF3:
		return 0xf3
	case PrefixF2:
		return 0xf2
	default:
		return 0
	}
}

func putOpcodeMap(pos *int, dst []byte, opcodeMap OpcodeMap) bool {
	var bytes []byte
	switch opcodeMap {
	case MapPrimary:
		return true
	case Map0F:
		bytes = []byte{0x0f}
	case Map0F38:
		bytes = []byte{0x0f, 0x38}
	case Map0F3A:
		bytes = []byte{0x0f, 0x3a}
	default:
		return false
	}
	if *pos+len(bytes) > len(dst) || *pos+len(bytes) > 15 {
		return false
	}
	copy(dst[*pos:], bytes)
	*pos += len(bytes)
	return true
}

func vectorPrefix(e *Encoding, fields EncodeFields) ([4]byte, int, error) {
	var out [4]byte
	mapBits, ok := mmmmmFromMap(e.Map)
	if !ok {
		return out, 0, ErrInvalidEncodeField
	}
	pp := ppFromMandatoryPrefix(e.MandatoryPrefix)
	w := byte(0)
	if e.W == BitOne {
		w = 1
	}
	l := byte(0)
	if e.VectorLength == 256 {
		l = 1
	}
	r, x, b := fields.Reg>>3&1, fields.Index>>3&1, fields.RM>>3&1
	if e.Kind == EncodingEVEX && fields.Mod == 3 {
		x = fields.RM >> 4 & 1
	}
	if fields.UseSIB {
		b = fields.Base >> 3 & 1
	}
	switch e.Kind {
	case EncodingVEX:
		if e.Map == Map0F && e.W != BitOne && x == 0 && b == 0 {
			out[0] = 0xc5
			out[1] = (^r&1)<<7 | (^fields.VVVV&15)<<3 | l<<2 | pp
			return out, 2, nil
		}
		out[0] = 0xc4
		out[1] = (^r&1)<<7 | (^x&1)<<6 | (^b&1)<<5 | mapBits
		out[2] = w<<7 | (^fields.VVVV&15)<<3 | l<<2 | pp
		return out, 3, nil
	case EncodingXOP:
		out[0] = 0x8f
		out[1] = (^r&1)<<7 | (^x&1)<<6 | (^b&1)<<5 | mapBits
		out[2] = w<<7 | (^fields.VVVV&15)<<3 | l<<2 | pp
		return out, 3, nil
	case EncodingEVEX:
		ll := byte(0)
		if e.VectorLength == 256 {
			ll = 1
		} else if e.VectorLength == 512 {
			ll = 2
		}
		regHigh, vHigh := fields.Reg>>4&1, fields.VVVV>>4&1
		out[0] = 0x62
		out[1] = (^r&1)<<7 | (^x&1)<<6 | (^b&1)<<5 | (^regHigh&1)<<4 | (mapBits & 3)
		out[2] = w<<7 | (^fields.VVVV&15)<<3 | 1<<2 | pp
		out[3] = boolBit(fields.Zeroing)<<7 | ll<<5 | boolBit(fields.Broadcast)<<4 | (^vHigh&1)<<3 | fields.Mask
		return out, 4, nil
	case EncodingMVEX, Encoding3DNow:
		return out, 0, ErrUnsupportedFamily
	default:
		return out, 0, ErrInvalidEncodeField
	}
}

func boolBit(value bool) byte {
	if value {
		return 1
	}
	return 0
}

func ppFromMandatoryPrefix(prefix MandatoryPrefix) byte {
	switch prefix {
	case Prefix66:
		return 1
	case PrefixF3:
		return 2
	case PrefixF2:
		return 3
	default:
		return 0
	}
}

func mmmmmFromMap(opcodeMap OpcodeMap) (byte, bool) {
	switch opcodeMap {
	case Map0F:
		return 1, true
	case Map0F38:
		return 2, true
	case Map0F3A:
		return 3, true
	case MapXOP8:
		return 8, true
	case MapXOP9:
		return 9, true
	case MapXOPA:
		return 10, true
	default:
		return 0, false
	}
}

func displacementBytes(mod, base byte, sib bool, addressBits int) int {
	if addressBits == 16 {
		if mod == 0 && base == 6 {
			return 2
		}
		if mod == 1 {
			return 1
		}
		if mod == 2 {
			return 2
		}
		return 0
	}
	if mod == 0 && base == 5 {
		return 4
	}
	if mod == 1 {
		return 1
	}
	if mod == 2 {
		return 4
	}
	return 0
}

func writeLittleEndian(dst []byte, value uint64) {
	for i := range dst {
		dst[i] = byte(value >> (8 * i))
	}
}

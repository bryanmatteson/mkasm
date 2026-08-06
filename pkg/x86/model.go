// Package x86 models variable-length x86 instruction encodings independently
// from the fixed-width ARM IR.
package x86

import "fmt"

// Mode is the active x86 execution mode.
type Mode uint8

const (
	Mode16 Mode = 16
	Mode32 Mode = 32
	Mode64 Mode = 64
)

type ModeMask uint8

const (
	mode16 ModeMask = 1 << iota
	mode32
	mode64
	modeAll = mode16 | mode32 | mode64
)

func (m ModeMask) supports(mode Mode) bool {
	switch mode {
	case Mode16:
		return m&mode16 != 0
	case Mode32:
		return m&mode32 != 0
	case Mode64:
		return m&mode64 != 0
	default:
		return false
	}
}

// EncodingKind identifies the opcode-prefix family.
type EncodingKind uint8

const (
	EncodingLegacy EncodingKind = iota
	EncodingVEX
	EncodingEVEX
	EncodingMVEX
	EncodingXOP
	Encoding3DNow
	encodingKindCount
)

func (k EncodingKind) String() string {
	switch k {
	case EncodingLegacy:
		return "legacy"
	case EncodingVEX:
		return "vex"
	case EncodingEVEX:
		return "evex"
	case EncodingMVEX:
		return "mvex"
	case EncodingXOP:
		return "xop"
	case Encoding3DNow:
		return "3dnow"
	default:
		return fmt.Sprintf("encoding-kind(%d)", k)
	}
}

// OpcodeMap is the opcode byte's map after prefix normalization.
type OpcodeMap uint8

const (
	MapPrimary OpcodeMap = iota
	Map0F
	Map0F38
	Map0F3A
	Map0F0F
	MapXOP8
	MapXOP9
	MapXOPA
	opcodeMapCount
)

type MandatoryPrefix uint8

const (
	PrefixNone MandatoryPrefix = iota
	Prefix66
	PrefixF3
	PrefixF2
)

// ModConstraint limits the ModR/M mod field.
type ModConstraint uint8

const (
	ModAny ModConstraint = iota
	ModMemory
	ModRegister
)

// BitConstraint represents an unconstrained, zero, or one encoding bit.
type BitConstraint int8

const (
	BitAny  BitConstraint = -1
	BitZero BitConstraint = 0
	BitOne  BitConstraint = 1
)

// TailWidth describes bytes following the opcode and optional ModR/M payload.
type TailWidth uint8

const (
	Tail8 TailWidth = iota + 1
	Tail16
	Tail32
	Tail64
	// TailZ is 16 bits with an operand-size override and 32 bits otherwise.
	TailZ
	// TailV follows the effective integer operand size.
	TailV
	// TailAddress follows the effective address size (moffs operands).
	TailAddress
	// TailFarPointer is a 16:16 or 16:32 immediate far pointer.
	TailFarPointer
)

// Encoding is one independently decodable syntax form.
type Encoding struct {
	ID       string
	FormID   string
	Mnemonic string
	Syntax   string

	Kind            EncodingKind
	Map             OpcodeMap
	Opcode          byte
	OpcodePlusReg   bool
	MandatoryPrefix MandatoryPrefix
	// PrefixMask and PrefixValue use bits 0=66, 1=F3, 2=F2. Unlike
	// MandatoryPrefix, they preserve explicit zero constraints from the source.
	PrefixMask   byte
	PrefixValue  byte
	Modes        ModeMask
	W            BitConstraint
	VectorLength uint16

	HasModRM bool
	Mod      ModConstraint
	RegMask  byte
	RegValue byte
	RMMask   byte
	RMValue  byte
	Tail     []TailWidth
}

// Catalog is the normalized, source-independent x86 code-generation model.
type Catalog struct {
	Encodings []Encoding
}

// Validate checks invariants required by the allocation-free dispatcher.
func (c *Catalog) Validate() error {
	if c == nil || len(c.Encodings) == 0 {
		return fmt.Errorf("x86 catalog is empty")
	}
	seen := make(map[string]struct{}, len(c.Encodings))
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.FormID == "" {
			return fmt.Errorf("encoding %d has no form id", i)
		}
		if _, exists := seen[e.FormID]; exists {
			return fmt.Errorf("duplicate x86 form id %q", e.FormID)
		}
		seen[e.FormID] = struct{}{}
		if e.Mnemonic == "" {
			return fmt.Errorf("%s has no mnemonic", e.FormID)
		}
		if e.Kind >= encodingKindCount {
			return fmt.Errorf("%s has invalid encoding kind %d", e.FormID, e.Kind)
		}
		if e.Map >= opcodeMapCount {
			return fmt.Errorf("%s has invalid opcode map %d", e.FormID, e.Map)
		}
		if e.OpcodePlusReg && e.Opcode > 0xf8 {
			return fmt.Errorf("%s opcode+register base 0x%02x overflows", e.FormID, e.Opcode)
		}
		if e.Modes == 0 {
			return fmt.Errorf("%s is valid in no execution mode", e.FormID)
		}
		if !e.HasModRM && (e.Mod != ModAny || e.RegMask != 0 || e.RMMask != 0) {
			return fmt.Errorf("%s constrains ModR/M without encoding one", e.FormID)
		}
		if len(e.Tail) > 4 {
			return fmt.Errorf("%s has %d immediate tails; encoder capacity is 4", e.FormID, len(e.Tail))
		}
	}
	return nil
}

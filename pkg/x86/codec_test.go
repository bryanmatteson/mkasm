package x86

import (
	"bytes"
	"errors"
	"testing"
)

func codecCatalog() *Catalog {
	return &Catalog{Encodings: []Encoding{
		{ID: "NOP", FormID: "NOP/0", Mnemonic: "NOP", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x90, Modes: modeAll, W: BitAny},
		{ID: "ADD_rm64_r64", FormID: "ADD_rm64_r64/0", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x01, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModRegister, Operands: []Operand{
			{Type: "REG", Symbol: "GPR64", EncodedIn: "RM", Read: true, Write: true},
			{Type: "REG", Symbol: "GPR64", EncodedIn: "REG", Read: true},
		}},
		{ID: "ADD_rm64_r64", FormID: "ADD_rm64_r64/1", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x01, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModMemory, Operands: []Operand{
			{Type: "MEM", Symbol: "MEM", EncodedIn: "RM", Size: "64", Read: true, Write: true},
			{Type: "REG", Symbol: "GPR64", EncodedIn: "REG", Read: true},
		}},
		{ID: "ENDBR64", FormID: "ENDBR64/0", Mnemonic: "ENDBR64", Kind: EncodingLegacy, Map: Map0F, Opcode: 0x1e, MandatoryPrefix: PrefixF3, PrefixMask: 7, PrefixValue: 2, Modes: mode64, W: BitAny, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: 7, RMMask: 7, RMValue: 2},
		{ID: "VPADDD", FormID: "VPADDD/0", Mnemonic: "VPADDD", Kind: EncodingVEX, Map: Map0F, Opcode: 0xfe, MandatoryPrefix: Prefix66, PrefixMask: 7, PrefixValue: 1, Modes: modeAll, W: BitZero, VectorLength: 256, HasModRM: true, Mod: ModRegister, Operands: []Operand{
			{Type: "VREG", Symbol: "YMMREG", EncodedIn: "REG", Write: true},
			{Type: "VREG", Symbol: "YMMREG", EncodedIn: "VVVV", Read: true},
			{Type: "VREG", Symbol: "YMMREG", EncodedIn: "RM", Read: true},
		}},
		{ID: "VPXORD", FormID: "VPXORD/0", Mnemonic: "VPXORD", Kind: EncodingEVEX, Map: Map0F, Opcode: 0xef, MandatoryPrefix: Prefix66, PrefixMask: 7, PrefixValue: 1, Modes: mode64, W: BitZero, VectorLength: 512, HasModRM: true, Mod: ModRegister, Operands: []Operand{
			{Type: "VREG", Symbol: "ZMMREG", EncodedIn: "REG", Write: true},
			{Type: "VREG", Symbol: "ZMMREG", EncodedIn: "VVVV", Read: true},
			{Type: "VREG", Symbol: "ZMMREG", EncodedIn: "RM", Read: true},
		}},
		{ID: "ADD_imm", FormID: "ADD_imm/0", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x81, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: 0, Tail: []TailWidth{TailZ}, Operands: []Operand{
			{Type: "REG", Symbol: "GPR64", EncodedIn: "RM", Read: true, Write: true},
			{Type: "IMM", Symbol: "SIMM", EncodedIn: "IZ", DataType: "SX"},
		}},
		{ID: "PUSH_r64", FormID: "PUSH_r64/0", Mnemonic: "PUSH", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x50, OpcodePlusReg: true, Modes: mode64, W: BitAny, Operands: []Operand{
			{Type: "REG", Symbol: "GPR64", EncodedIn: "OPCODE", Read: true},
		}},
	}}
}

func TestDecodeAndEncodeRepresentativeFamilies(t *testing.T) {
	decoder, err := NewDecoder(codecCatalog())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		bytes  []byte
		id     string
		length uint8
	}{
		{"nop", []byte{0x90}, "NOP", 1},
		{"rex", []byte{0x48, 0x01, 0xc8}, "ADD_rm64_r64", 3},
		{"memory-sib-disp8", []byte{0x48, 0x01, 0x4c, 0x24, 0x08}, "ADD_rm64_r64", 5},
		{"endbr64", []byte{0xf3, 0x0f, 0x1e, 0xfa}, "ENDBR64", 4},
		{"vex", []byte{0xc5, 0xed, 0xfe, 0xcb}, "VPADDD", 4},
		{"evex", []byte{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0}, "VPXORD", 6},
		{"imm32", []byte{0x48, 0x81, 0xc0, 0x78, 0x56, 0x34, 0x12}, "ADD_imm", 7},
		{"opcode-register", []byte{0x41, 0x51}, "PUSH_r64", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decoder.Decode(tt.bytes, Mode64)
			if err != nil {
				t.Fatal(err)
			}
			if got.Length != tt.length || got.Encoding(decoder).ID != tt.id {
				t.Fatalf("got %+v (%+v), want %s length %d", got, got.Encoding(decoder), tt.id, tt.length)
			}
		})
	}

	encodeTests := []struct {
		index  int
		fields EncodeFields
		want   []byte
	}{
		{1, EncodeFields{Mode: Mode64, Mod: 3, Reg: 1, RM: 0}, []byte{0x48, 0x01, 0xc8}},
		{2, EncodeFields{Mode: Mode64, Mod: 1, Reg: 1, RM: 4, UseSIB: true, Scale: 0, Index: 4, Base: 4, Displacement: 8}, []byte{0x48, 0x01, 0x4c, 0x24, 0x08}},
		{2, EncodeFields{Mode: Mode64, SegmentOverride: 0x64, Mod: 1, Reg: 1, RM: 4, UseSIB: true, Scale: 0, Index: 4, Base: 4, Displacement: 8}, []byte{0x64, 0x48, 0x01, 0x4c, 0x24, 0x08}},
		{3, EncodeFields{Mode: Mode64, Mod: 3, Reg: 7, RM: 2}, []byte{0xf3, 0x0f, 0x1e, 0xfa}},
		{4, EncodeFields{Mode: Mode64, Mod: 3, Reg: 1, RM: 3, VVVV: 2}, []byte{0xc5, 0xed, 0xfe, 0xcb}},
		{5, EncodeFields{Mode: Mode64, Mod: 3, Reg: 0, RM: 0, VVVV: 0}, []byte{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0}},
		{5, EncodeFields{Mode: Mode64, Mod: 3, Reg: 16, RM: 18, VVVV: 17}, []byte{0x62, 0xa1, 0x75, 0x40, 0xef, 0xc2}},
		{5, EncodeFields{Mode: Mode64, Mod: 3, Reg: 16, RM: 18, VVVV: 17, Mask: 3, Zeroing: true, Broadcast: true}, []byte{0x62, 0xa1, 0x75, 0xd3, 0xef, 0xc2}},
		{6, EncodeFields{Mode: Mode64, Mod: 3, Reg: 0, RM: 0, Immediate: [4]uint64{0x12345678}}, []byte{0x48, 0x81, 0xc0, 0x78, 0x56, 0x34, 0x12}},
		{7, EncodeFields{Mode: Mode64, OpcodeReg: 9}, []byte{0x41, 0x51}},
	}
	for _, tt := range encodeTests {
		var dst [15]byte
		n, err := Encode(dst[:], &codecCatalog().Encodings[tt.index], tt.fields)
		if err != nil {
			t.Fatalf("encode %d: %v", tt.index, err)
		}
		if !bytes.Equal(dst[:n], tt.want) {
			t.Fatalf("encode %d = % x, want % x", tt.index, dst[:n], tt.want)
		}
	}
}

func TestParseHeadResolvesLegacyVectorPrefixCollisions(t *testing.T) {
	tests := []struct {
		name   string
		bytes  []byte
		mode   Mode
		kind   EncodingKind
		opcode byte
	}{
		{"bound-16", []byte{0x62, 0x00}, Mode16, EncodingLegacy, 0x62},
		{"bound-32", []byte{0x62, 0x00}, Mode32, EncodingLegacy, 0x62},
		{"lds-32", []byte{0xc5, 0x00}, Mode32, EncodingLegacy, 0xc5},
		{"les-32", []byte{0xc4, 0x00}, Mode32, EncodingLegacy, 0xc4},
		{"vex2-32", []byte{0xc5, 0xf8, 0x77}, Mode32, EncodingVEX, 0x77},
		{"vex3-32", []byte{0xc4, 0xe1, 0x78, 0x77}, Mode32, EncodingVEX, 0x77},
		{"evex-64", []byte{0x62, 0xf1, 0x7c, 0x08, 0x77}, Mode64, EncodingEVEX, 0x77},
		{"evex-32", []byte{0x62, 0xf1, 0x7c, 0x08, 0x77}, Mode32, EncodingEVEX, 0x77},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, err := parseHead(tt.bytes, tt.mode)
			if err != nil {
				t.Fatal(err)
			}
			if head.kind != tt.kind || head.opcode != tt.opcode {
				t.Fatalf("head = kind %v opcode %#x, want kind %v opcode %#x", head.kind, head.opcode, tt.kind, tt.opcode)
			}
		})
	}
}

func TestDecodePrefersMostSpecificOverlappingEncoding(t *testing.T) {
	catalog := &Catalog{Encodings: []Encoding{
		{ID: "BSR", FormID: "BSR/0", Mnemonic: "BSR", Kind: EncodingLegacy, Map: Map0F, Opcode: 0xbd, Modes: modeAll, W: BitAny, HasModRM: true, Mod: ModAny},
		{ID: "LZCNT", FormID: "LZCNT/0", Mnemonic: "LZCNT", Kind: EncodingLegacy, Map: Map0F, Opcode: 0xbd, PrefixMask: 7, PrefixValue: 2, Modes: modeAll, W: BitAny, HasModRM: true, Mod: ModAny},
	}}
	decoder, err := NewDecoder(catalog)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decoder.Decode([]byte{0xf3, 0x0f, 0xbd, 0xc0}, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Encoding(decoder).Mnemonic; got != "LZCNT" || decoded.Alternatives != 1 {
		t.Fatalf("decoded %s with %d alternatives, want LZCNT with 1", got, decoded.Alternatives)
	}
}

func TestDecodeErrorsAndAllocations(t *testing.T) {
	decoder, err := NewDecoder(codecCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode([]byte{0x48, 0x81, 0xc0}, Mode64); !errors.Is(err, ErrShortInstruction) {
		t.Fatalf("got %v, want ErrShortInstruction", err)
	}
	if _, err := decoder.Decode([]byte{0x0f, 0x0b}, Mode64); !errors.Is(err, ErrUnknownEncoding) {
		t.Fatalf("got %v, want ErrUnknownEncoding", err)
	}
	allocs := testing.AllocsPerRun(1_000, func() {
		got, decodeErr := decoder.Decode([]byte{0xc5, 0xed, 0xfe, 0xcb}, Mode64)
		if decodeErr != nil || got.Length != 4 {
			panic("decode failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("Decode allocated %.2f times", allocs)
	}
}

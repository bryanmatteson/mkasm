package x86

import (
	"bytes"
	"errors"
	"testing"
)

func codecCatalog() *Catalog {
	return &Catalog{Encodings: []Encoding{
		{ID: "NOP", FormID: "NOP/0", Mnemonic: "NOP", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x90, Modes: modeAll, W: BitAny},
		{ID: "ADD_rm64_r64", FormID: "ADD_rm64_r64/0", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x01, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModRegister},
		{ID: "ADD_rm64_r64", FormID: "ADD_rm64_r64/1", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x01, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModMemory},
		{ID: "ENDBR64", FormID: "ENDBR64/0", Mnemonic: "ENDBR64", Kind: EncodingLegacy, Map: Map0F, Opcode: 0x1e, MandatoryPrefix: PrefixF3, PrefixMask: 7, PrefixValue: 2, Modes: mode64, W: BitAny, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: 7, RMMask: 7, RMValue: 2},
		{ID: "VPADDD", FormID: "VPADDD/0", Mnemonic: "VPADDD", Kind: EncodingVEX, Map: Map0F, Opcode: 0xfe, MandatoryPrefix: Prefix66, PrefixMask: 7, PrefixValue: 1, Modes: modeAll, W: BitZero, VectorLength: 256, HasModRM: true, Mod: ModRegister},
		{ID: "VPXORD", FormID: "VPXORD/0", Mnemonic: "VPXORD", Kind: EncodingEVEX, Map: Map0F, Opcode: 0xef, MandatoryPrefix: Prefix66, PrefixMask: 7, PrefixValue: 1, Modes: mode64, W: BitZero, VectorLength: 512, HasModRM: true, Mod: ModRegister},
		{ID: "ADD_imm", FormID: "ADD_imm/0", Mnemonic: "ADD", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x81, Modes: mode64, W: BitOne, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: 0, Tail: []TailWidth{TailZ}},
		{ID: "PUSH_r64", FormID: "PUSH_r64/0", Mnemonic: "PUSH", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x50, OpcodePlusReg: true, Modes: mode64, W: BitAny},
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
		{3, EncodeFields{Mode: Mode64, Mod: 3, Reg: 7, RM: 2}, []byte{0xf3, 0x0f, 0x1e, 0xfa}},
		{4, EncodeFields{Mode: Mode64, Mod: 3, Reg: 1, RM: 3, VVVV: 2}, []byte{0xc5, 0xed, 0xfe, 0xcb}},
		{5, EncodeFields{Mode: Mode64, Mod: 3, Reg: 0, RM: 0, VVVV: 0}, []byte{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0}},
		{5, EncodeFields{Mode: Mode64, Mod: 3, Reg: 16, RM: 18, VVVV: 17}, []byte{0x62, 0x31, 0x75, 0x40, 0xef, 0xc2}},
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

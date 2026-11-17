package x86

import (
	"os"
	"strings"
	"testing"
)

func TestXEDFP16PhysicalSource(t *testing.T) {
	data, err := os.ReadFile("testdata/intel-xed-fp16/avx512-fp16-isa.xed.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, report, err := ParseXEDFP16(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("imported %d, explicit excluded %d", report.Imported, len(report.Excluded))
	if report.Imported+len(report.Excluded) != 590 {
		t.Fatalf("source blocks lost: %+v", report)
	}
	dec, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		bytes    []byte
		mnemonic string
	}{
		{[]byte{0x62, 0xf5, 0x6c, 0x08, 0x58, 0xc1}, "VADDPH"},
		{[]byte{0x62, 0xf5, 0x6e, 0x08, 0x58, 0xc1}, "VADDSH"},
		{[]byte{0x62, 0xf6, 0x6d, 0x08, 0x98, 0xc1}, "VFMADD132PH"},
		{[]byte{0x62, 0xf5, 0x6c, 0x48, 0x58, 0x40, 0x02}, "VADDPH"},
	} {
		d, err := dec.Decode(test.bytes, Mode64)
		if err != nil {
			t.Fatalf("%x: %v", test.bytes, err)
		}
		e := d.Encoding(dec)
		if e.Mnemonic != test.mnemonic {
			t.Fatalf("%x: %s", test.bytes, e.Mnemonic)
		}
		var dst [15]byte
		if e.Mod == ModRegister {
			if _, err := Encode(dst[:], e, EncodeFields{Mode: Mode64, Mod: 3, Reg: 0, RM: 1, VVVV: 2}); err != nil {
				t.Fatal(err)
			}
			if string(dst[:6]) != string(test.bytes) {
				t.Fatalf("map encode: %x != %x", dst[:6], test.bytes)
			}
		}
	}
	// Embedded rounding retains logical VL512 rather than interpreting RC as VL.
	er, err := dec.Decode([]byte{0x62, 0xf5, 0x6c, 0x78, 0x58, 0xc1}, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	if !er.Encoding(dec).EmbeddedRounding || er.Encoding(dec).VectorLength != 512 {
		t.Fatal("lost embedded RC context")
	}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		mode := Mode64
		if !e.Modes.supports(mode) {
			mode = Mode32
		}
		fields := EncodeFields{Mode: mode, Mod: 3, Reg: e.RegValue, RM: e.RMValue, Broadcast: e.EVEXValue&16 != 0}
		if e.Mod == ModMemory {
			fields.Mod = 0
		}
		if e.NoSourceDestMatch {
			fields.VVVV = 1
			if fields.Mod == 3 {
				fields.RM = 2
			}
		}
		for rc := byte(0); rc < 4; rc++ {
			if !e.EmbeddedRounding && !e.VectorLengthIgnored && rc != 0 {
				continue
			}
			fields.RoundingControl = rc
			var out [15]byte
			n, err := Encode(out[:], e, fields)
			if err != nil {
				t.Fatalf("%s: %v", e.FormID, err)
			}
			d, err := dec.Decode(out[:n], mode)
			if err != nil {
				t.Fatalf("%s %x: %v", e.FormID, out[:n], err)
			}
			if got := d.Encoding(dec); got.Mnemonic != e.Mnemonic || got.VectorLength != e.VectorLength || got.SuppressExceptions != e.SuppressExceptions {
				t.Fatalf("source form mismatch: %+v -> %+v", e, got)
			}
		}
	}
	if _, err := dec.Decode([]byte{0x62, 0xf5, 0x68, 0x08, 0x58, 0xc1}, Mode64); err == nil {
		t.Fatal("reserved U bit ignored")
	}
	scalar, err := dec.Decode([]byte{0x62, 0xf5, 0x6e, 0x68, 0x58, 0xc1}, Mode64)
	if err != nil || !scalar.Encoding(dec).VectorLengthIgnored || scalar.Encoding(dec).VectorLength != 128 {
		t.Fatalf("LLIG scalar: %v", err)
	}
	var invalid [15]byte
	if _, err := Encode(invalid[:], er.Encoding(dec), EncodeFields{Mode: Mode64, Mod: 3, Broadcast: true, RoundingControl: 4}); err == nil {
		t.Fatal("invalid rounding control accepted")
	}
	if _, err := dec.Decode([]byte{0x62, 0xe5, 0x7e, 0x08, 0x2d, 0xc1}, Mode64); err == nil {
		t.Fatal("GPR destination EVEX.R4 constraint ignored")
	}
	// XOP map 8 and EVEX map 5 retain distinct internal buckets.
	if MapXOP8 == MapEVEX5 {
		t.Fatal("map collision")
	}
}

func TestXEDFP16RejectsUnknownGrammar(t *testing.T) {
	bad := strings.Replace(xedFP16Source, "EVV 0x58 VNP MAP5", "EVV 0x58 VNP MAP5 UNKNOWN()", 1)
	if _, _, err := ParseXEDFP16(strings.NewReader(bad)); err == nil {
		t.Fatal("unrecognized constraints silently discarded")
	}
}

func TestXEDFP16ComplexSourceDestinationConstraints(t *testing.T) {
	c, _, err := ParseXEDFP16(strings.NewReader(xedFP16Source))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if !e.NoSourceDestMatch {
			continue
		}
		count++
		fields := EncodeFields{Mode: Mode64, Mod: 3, Reg: 17, VVVV: 1, RM: 18, Broadcast: e.EVEXValue&16 != 0}
		if e.Mod == ModMemory {
			fields.Mod = 0
			fields.RM = 0
		}
		var out [15]byte
		n, err := Encode(out[:], e, fields)
		if err != nil {
			t.Fatalf("%s: %v", e.FormID, err)
		}
		if _, err := dec.Decode(out[:n], Mode64); err != nil {
			t.Fatalf("%s high distinct sources: %v", e.FormID, err)
		}
		original := out
		// Mutate the encoded vvvv/V' source to the high destination register.
		out[2] = (out[2] &^ 0x78) | ((^fields.Reg & 15) << 3)
		out[3] = (out[3] &^ 8) | ((^fields.Reg >> 4 & 1) << 3)
		if _, err := dec.Decode(out[:n], Mode64); err == nil {
			t.Fatalf("%s accepted destination=vvvv", e.FormID)
		}
		bad := fields
		bad.VVVV = bad.Reg
		if _, err := Encode(out[:], e, bad); err == nil {
			t.Fatalf("%s encoded destination=vvvv", e.FormID)
		}
		if fields.Mod == 3 {
			out = original
			out[5] = (out[5] &^ 7) | (fields.Reg & 7)
			out[1] = (out[1] &^ 0x60) | ((^fields.Reg >> 3 & 1) << 5) | ((^fields.Reg >> 4 & 1) << 6)
			if _, err := dec.Decode(out[:n], Mode64); err == nil {
				t.Fatalf("%s accepted destination=rm", e.FormID)
			}
			bad = fields
			bad.RM = bad.Reg
			if _, err := Encode(out[:], e, bad); err == nil {
				t.Fatalf("%s encoded destination=rm", e.FormID)
			}
		}
	}
	if count != 40 {
		t.Fatalf("source constrained complex forms: got%d want40", count)
	}
}

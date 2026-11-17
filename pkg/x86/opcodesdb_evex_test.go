package x86

import (
	"os"
	"testing"
)

func TestOpcodesDBEVEXActualRoundingAndSAE(t *testing.T) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Skip("set MKASM_X86_OPCODESDB for actual source corpus")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	c, err := ParseOpcodesDB(file)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p2 := range []byte{0x18, 0x38, 0x58, 0x78} {
		d, err := dec.Decode([]byte{0x62, 0xf1, 0x74, p2, 0x58, 0xc2}, Mode64)
		if err != nil {
			t.Fatalf("VADDPS ER P2=%02x: %v", p2, err)
		}
		e := d.Encoding(dec)
		if e.Mnemonic != "VADDPS" || !e.EmbeddedRounding || !e.SuppressExceptions || e.VectorLength != 512 {
			t.Fatalf("lost ER physical/logical contract: %+v", e)
		}
	}
	for _, test := range []struct {
		p2  byte
		sae bool
	}{{0x08, false}, {0x68, false}, {0x18, true}, {0x78, true}} {
		d, err := dec.Decode([]byte{0x62, 0xf3, 0x7d, test.p2, 0x0a, 0xc1, 0xf3}, Mode64)
		if err != nil {
			t.Fatalf("RNDSCALESS P2=%02x: %v", test.p2, err)
		}
		e := d.Encoding(dec)
		if e.Mnemonic != "VRNDSCALESS" || e.SuppressExceptions != test.sae || e.EmbeddedRounding || e.VectorLength != 128 || !test.sae && !e.VectorLengthIgnored {
			t.Fatalf("lost SAE/LLIG contract: %+v", e)
		}
	}
}

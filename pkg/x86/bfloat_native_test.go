package x86

import (
	"bytes"
	"os"
	"testing"
)

func TestBF16NativePhysicalSource(t *testing.T) {
	input := os.Getenv("MKASM_X86_OPCODESDB")
	if input == "" {
		t.Skip("set MKASM_X86_OPCODESDB to pinned corpus")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseOpcodesDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decoder.Decode([]byte{0x62, 0xf2, 0x7e, 0x48, 0x72, 0xc1}, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	e := d.Encoding(decoder)
	t.Logf("physical BF16 source: %+v", e)
	if e.Mnemonic != "VCVTNEPS2BF16" || e.VectorLength != 512 {
		t.Fatal("wrong physical BF16 identity")
	}
}

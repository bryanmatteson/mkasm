package wasm

import (
	"bytes"
	"os"
	"testing"
)

func FuzzInstructionRoundtrip(f *testing.F) {
	source, err := os.ReadFile("testdata/wasm-opcodes.json")
	if err != nil {
		f.Fatal(err)
	}
	c, err := Parse(bytes.NewReader(source), "wasm64")
	if err != nil {
		f.Fatal(err)
	}
	for _, op := range c.Opcodes {
		b, err := c.Encode(op.ID, representativeValues(op))
		if err != nil {
			f.Fatal(op.ID, err)
		}
		f.Add(b)
	}
	f.Add([]byte{0xfc, 0x80, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := c.Decode(b)
		if err != nil {
			return
		}
		if in.Length < 1 || in.Length > len(b) {
			t.Fatal("invalid instruction length", in.Length)
		}
		canonical, err := c.Encode(in.Opcode.ID, in.Operands)
		if err != nil {
			t.Fatal("decoded instruction cannot encode", err)
		}
		text, err := c.Assemble(in.Format())
		if err != nil || !bytes.Equal(text, canonical) {
			t.Fatalf("canonical text roundtrip %x: %q -> %x (%v)", b, in.Format(), text, err)
		}
	})
}

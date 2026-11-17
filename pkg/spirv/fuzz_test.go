package spirv

import (
	"bytes"
	"os"
	"testing"
)

func FuzzInstructionRoundtrip(f *testing.F) {
	source, err := os.ReadFile("testdata/spirv.core.grammar.json")
	if err != nil {
		f.Fatal(err)
	}
	c, err := Parse(bytes.NewReader(source), "spirv")
	if err != nil {
		f.Fatal(err)
	}
	for _, definition := range c.Instructions {
		b, err := c.Encode(sampleInstruction(c, definition, true), nil, nil)
		if err != nil {
			f.Fatal(definition.Name, err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		in, length, err := c.Decode(b, nil, nil)
		if err != nil {
			return
		}
		if length < 4 || length > len(b) {
			t.Fatal("invalid instruction length", length)
		}
		encoded, err := c.Encode(in, nil, nil)
		if err != nil || !bytes.Equal(encoded, b[:length]) {
			t.Fatalf("binary roundtrip %x -> %x (%v)", b[:length], encoded, err)
		}
		text := c.Format(in)
		again, err := c.Assemble(text, nil, nil)
		if err != nil {
			t.Fatalf("decoded instruction cannot assemble %q: %v", text, err)
		}
		encoded, err = c.Encode(again, nil, nil)
		if err != nil || !bytes.Equal(encoded, b[:length]) {
			t.Fatalf("text roundtrip %x: %q -> %x (%v)", b[:length], text, encoded, err)
		}
	})
}

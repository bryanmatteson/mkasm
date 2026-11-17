package spirv

import (
	"bytes"
	"testing"
)

func TestStructuredInstructionTemplates(t *testing.T) {
	c := grammar(t)
	prototype, err := c.Assemble("%3 = OpIAdd %1 %4 %4", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := c.Template(prototype, map[int]string{2: "input", 3: "input"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode(prototype, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	captures, n, err := template.MatchBytes(b, nil, nil)
	if err != nil || n != len(b) || captures["input"].Words[0] != 4 {
		t.Fatalf("capture %+v %d %v", captures, n, err)
	}
	prototype.Operands[0].Words[0] = 99 // The template retains its own fixed fields.
	replacement := Operand{Kind: "IdRef", Words: []uint32{9}}
	encoded, err := template.Encode(map[string]Operand{"input": replacement}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := c.Assemble("%3 = OpIAdd %1 %9 %9", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.Encode(expected, nil, nil)
	if err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("encode %x %x %v", encoded, want, err)
	}
	expected.Operands[3].Words[0] = 10
	if _, ok := template.Match(expected); ok {
		t.Fatal("matched unequal repeated operands")
	}
	if _, err := template.Encode(map[string]Operand{"input": replacement, "unknown": replacement}, nil, nil); err == nil {
		t.Fatal("accepted extra binding")
	}
	if _, err := template.Encode(map[string]Operand{"input": {Kind: "IdRef", Words: []uint32{0}}}, nil, nil); err == nil {
		t.Fatal("accepted zero ID")
	}
}

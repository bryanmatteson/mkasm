package jvm

import (
	"bytes"
	"testing"
)

func TestInstructionTemplates(t *testing.T) {
	c := catalog(t)
	template, err := c.Template("iinc", true)
	if err != nil {
		t.Fatal(err)
	}
	if err = template.Set("index", 300); err != nil {
		t.Fatal(err)
	}
	if _, err = template.Encode(0); err == nil {
		t.Fatal("encoded unset operand")
	}
	want := []byte{0xc4, 0x84, 1, 44, 0xfe, 0xd4}
	in, ok := template.Match(want, 12)
	if !ok || in.Offset != 12 || in.Operands[1].Value != -300 {
		t.Fatalf("capture %+v %v", in, ok)
	}
	if err = template.Set("constant", -300); err != nil {
		t.Fatal(err)
	}
	if got, err := template.Encode(12); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encode %x %v", got, err)
	}
	if _, ok := template.Match([]byte{0xc4, 0x84, 1, 45, 0xfe, 0xd4}, 12); ok {
		t.Fatal("matched different fixed register")
	}
	for name, value := range map[string]int64{"index": 65536, "constant": -32769, "missing": 0} {
		if err := template.Set(name, value); err == nil {
			t.Fatalf("accepted %s=%d", name, value)
		}
	}
	if _, err := c.Template("nop", true); err == nil {
		t.Fatal("accepted wide nop template")
	}
	if _, err := c.Template("breakpoint", false); err == nil {
		t.Fatal("accepted reserved template")
	}
	switchTemplate, err := c.Template("lookupswitch", false)
	if err != nil {
		t.Fatal(err)
	}
	value := &Switch{Default: 16, Pairs: []LookupPair{{Match: -1, Target: -4}}}
	if err = switchTemplate.SetSwitch(value); err != nil {
		t.Fatal(err)
	}
	value.Pairs[0].Target = 8
	for offset := uint32(0); offset < 4; offset++ {
		b, err := switchTemplate.Encode(offset)
		if err != nil {
			t.Fatal(err)
		}
		in, ok := switchTemplate.Match(b, offset)
		if !ok || in.Switch.Pairs[0].Target != -4 {
			t.Fatalf("switch %+v %v", in, ok)
		}
		if got, err := c.Assemble(in.Format(), offset); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("switch text %x %v", got, err)
		}
	}
}

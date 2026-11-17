package m68k

import (
	"bytes"
	"fmt"
	"testing"
)

func TestTemplateMatchesSourceForms(t *testing.T) {
	c := corpus(t)
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		if o.Mnemonic == "swbeg" {
			continue
		}
		for _, profile := range []string{"68000", "68010", "68020", "68030", "68040", "68060", "68881", "68851", "cpu32", "fido", "coldfire-all"} {
			if o.Features&Profiles[profile] != 0 {
				c.CPU = profile
				break
			}
		}
		values, err := sampleOpcode(c, o)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := c.Encode(o.ID, values)
		if err != nil {
			t.Fatal(err)
		}
		template, err := c.Template(o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := template.Match(encoded); !ok {
			_, decodeErr := c.decodeSelected(encoded, o.ID)
			t.Fatalf("unbound template failed for %s (%s, %s, %x, %#v): %v", o.ID, c.CPU, o.Args, encoded, values, decodeErr)
		}
		for i, value := range values {
			if err := template.Set(fmt.Sprintf("op%d", i), value); err != nil {
				t.Fatal(err)
			}
		}
		if _, ok := template.Match(encoded); !ok {
			t.Fatalf("bound template failed for %s", o.ID)
		}
	}
}

func TestTemplateCopiesNestedBindingsAndChecksMeaning(t *testing.T) {
	c := corpus(t)
	c.CPU = "68000"
	encoded, err := c.Assemble("movel [[40,-8],[0]]")
	if err != nil {
		t.Fatal(err)
	}
	in, err := c.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	template, err := c.Template(in.Opcode.ID)
	if err != nil {
		t.Fatal(err)
	}
	value := L(U(40), S(-8))
	if err := template.Set("op0", value); err != nil {
		t.Fatal(err)
	}
	value.Items[1] = S(-10)
	if _, ok := template.Match(append(encoded, 0xff)); !ok {
		t.Fatal("bound template changed after caller mutation")
	}
	other, err := c.Assemble("movel [[40,-10],[0]]")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := template.Match(other); ok {
		t.Fatal("matched a different bound displacement")
	}
	if _, err := template.Encode(); err == nil {
		t.Fatal("encoded unbound destination")
	}
	if err := template.Set("op1", L(U(0))); err != nil {
		t.Fatal(err)
	}
	actual, err := template.Encode()
	if err != nil || !bytes.Equal(actual, encoded) {
		t.Fatalf("got %x, %v; want %x", actual, err, encoded)
	}
	for i := 0; i < len(encoded); i++ {
		if _, ok := template.Match(encoded[:i]); ok {
			t.Fatalf("matched truncated instruction at byte %d", i)
		}
	}
}

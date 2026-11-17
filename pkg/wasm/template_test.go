package wasm

import "testing"

func TestTemplateMatchingEveryOpcode(t *testing.T) {
	c := corpus(t, "wasm32")
	for _, o := range c.Opcodes {
		values := representativeValues(o)
		encoded, err := c.Encode(o.ID, values)
		if err != nil {
			t.Fatal(err)
		}
		template, err := c.Template(o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := template.Match(encoded); !ok {
			t.Fatal("unbound template failed", o.ID)
		}
		for i, f := range o.Fields {
			if err := template.Set(f.Name, values[i]); err != nil {
				t.Fatal(err)
			}
		}
		if _, ok := template.Match(encoded); !ok {
			t.Fatal("bound template failed", o.ID)
		}
	}
	template, _ := c.Template("I32Const")
	if err := template.Set("value", S(0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := template.Match([]byte{0x41, 1}); ok {
		t.Fatal("matched different fixed operand")
	}
	table, _ := c.Template("BrTable")
	value := L(U(1), U(2))
	if err := table.Set("targets", value); err != nil {
		t.Fatal(err)
	}
	value.Items[0] = U(99)
	encoded, err := table.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if in, ok := table.Match(encoded); !ok || in.Operands[0].Items[0].U != 1 {
		t.Fatal("template retained caller-owned operand storage")
	}
}

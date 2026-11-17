package dex

import (
	"bytes"
	"testing"
)

func TestStructuredInstructionTemplates(t *testing.T) {
	c := load(t)
	for _, definition := range c.Instructions {
		if definition.Reserved {
			continue
		}
		t.Run(definition.Mnemonic, func(t *testing.T) {
			in := sample(definition)
			want, err := c.Encode(in, 100)
			if err != nil {
				t.Fatal(err)
			}
			template, err := c.Template(definition.Mnemonic)
			if err != nil {
				t.Fatal(err)
			}
			capture, ok := template.Match(want, 100)
			if !ok || capture.Opcode != in.Opcode {
				t.Fatalf("capture %+v %v", capture, ok)
			}
			for name, value := range in.Values {
				if err = template.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			switch definition.Format {
			case "35c", "45cc":
				err = template.SetRegisters(in.Registers)
			case "3rc", "4rcc":
				err = template.SetRange(*in.Range)
			}
			if err != nil {
				t.Fatal(err)
			}
			if in.Payload != nil {
				if err = template.SetPayload(in.Payload); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := template.Encode(100); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("encode %x want %x: %v", got, want, err)
			}
		})
	}
	template, _ := c.Template("const/4")
	if _, err := template.Encode(0); err == nil {
		t.Fatal("encoded missing fields")
	}
	if err := template.Set("a", 16); err == nil {
		t.Fatal("accepted out-of-range register")
	}
	if err := template.Set("a", 3); err != nil {
		t.Fatal(err)
	}
	if _, ok := template.Match([]byte{0x12, 0x42}, 0); ok {
		t.Fatal("matched different fixed register")
	}
	if err := template.SetRegisters(nil); err == nil {
		t.Fatal("accepted invoke list on const")
	}
	if _, err := c.TemplateVersion("invoke-polymorphic", 35); err != ErrVersion {
		t.Fatalf("accepted newer opcode: %v", err)
	}
	payloadTemplate, _ := c.Template("array-data-payload")
	p := &Payload{ElementWidth: 1, Data: []byte{1, 2, 3}}
	if err := payloadTemplate.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	p.Data[0] = 99
	b, err := payloadTemplate.Encode(0)
	if err != nil || b[8] != 1 {
		t.Fatalf("payload was not copied: %x %v", b, err)
	}
	if _, err := payloadTemplate.Encode(1); err == nil {
		t.Fatal("encoded unaligned payload")
	}
}

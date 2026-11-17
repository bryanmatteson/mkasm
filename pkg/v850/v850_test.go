package v850

import (
	"bytes"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"testing"
)

func load(t *testing.T) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/v850-opc.c")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, "v850")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestCorpus(t *testing.T) {
	c := load(t)
	lengths := map[int]int{}
	for _, e := range c.Encodings {
		lengths[len(e.Mask)]++
	}
	t.Logf("%d forms, %v lengths, %d profiles", len(c.Encodings), lengths, len(c.FeatureSets))
}
func sample(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(4)
		if o.Signed {
			n = -4
		}
		if o.Relative {
			n = 8
			if o.Class == "D16_LOOP" {
				n = -8
			}
		}
		if o.Class == "LIST12" {
			n = 7
		}
		if o.Class == "IMM16HI" {
			n = 0x12340000
		}
		if o.Class == "IMM32" {
			n = 0x12345678
		}
		if o.Class == "POS_U" {
			n = 20
		}
		if o.Class == "POS_M" {
			n = 4
		}
		if o.Class == "POS_L" {
			n = 4
		}
		if o.Class == "WIDTH_M" {
			n = 17
		}
		if o.Class == "WIDTH_U" || o.Class == "WIDTH_L" {
			n = 4
		}
		if o.Class == "I5DIV1" || o.Class == "I5DIV2" || o.Class == "I5DIV3" {
			n = 8
		}
		if o.Width() < 3 {
			n = 1
		}
		v[o.Name] = n
	}
	return v
}
func TestEveryForm(t *testing.T) {
	c := load(t)
	for j := range c.Encodings {
		e := &c.Encodings[j]
		t.Run(e.ID, func(t *testing.T) {
			v := sample(e)
			b, err := c.Encode(e.ID, v)
			if err != nil {
				t.Fatal(err)
			}
			d := codec.Decoded{Encoding: e, Values: v, Length: len(b)}
			text := d.Format(0x1000)
			forms, err := c.Assemble(text, 0x1000)
			if err != nil {
				t.Fatal(text, err)
			}
			found := false
			for _, f := range forms {
				found = found || bytes.Equal(f, b)
			}
			if !found {
				t.Fatal("text lost bytes", text)
			}
			if e.AssemblyOnly {
				return
			}
			got, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			back, err := c.Encode(got.Encoding.ID, got.Values)
			if err != nil || !bytes.Equal(back, b) {
				t.Fatalf("%s -> %s got %x expected %x %v", fmt.Sprint(v), got.Encoding.ID, back, b, err)
			}
		})
	}
}

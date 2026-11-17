package z80

import (
	"bytes"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"testing"
)

func sample(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(1)
		if len(o.Names) > 0 {
			for i, s := range o.Names {
				if s != "" {
					n = int64(i)
					break
				}
			}
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		v[o.Name] = n*scale + o.Bias
	}
	return v
}
func TestCorpus(t *testing.T) {
	for _, arch := range []string{"z80", "z180"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]int{"z80": 1446, "z180": 732}[arch]
			if len(c.Encodings) != want {
				t.Fatalf("source forms %d want%d", len(c.Encodings), want)
			}
			t.Log(len(c.Encodings))
			for i := range c.Encodings {
				e := &c.Encodings[i]
				v := sample(e)
				b, err := codec.Encode(e, v)
				if err != nil {
					t.Fatalf("%s: %v", e.ID, err)
				}
				d, err := c.Decode(b)
				if err != nil {
					t.Fatalf("%s %x: %v", e.ID, b, err)
				}
				again, err := d.Reencode()
				if err != nil || !bytes.Equal(b, again) {
					t.Fatalf("%s exact %x %x %v", e.ID, b, again, err)
				}
				text := d.Format(0x1000)
				all, err := c.Assemble(text, 0x1000)
				if err != nil {
					t.Fatalf("%s %q: %v", e.ID, text, err)
				}
				if !bytes.Equal(all[0], b) {
					t.Fatalf("%s text %q %x !=%x", e.ID, text, b, all)
				}
			}
		})
	}
}

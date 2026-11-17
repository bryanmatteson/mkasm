package tricore

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func sample(e *codec.Encoding) map[string]int64 {
	values := map[string]int64{}
	for _, o := range e.Operands {
		raw := int64(1)
		lowest := 64
		for _, b := range o.Bits {
			if b.ValueBit < lowest {
				lowest = b.ValueBit
			}
		}
		raw <<= lowest
		if len(o.Names) > 0 {
			raw = 4
			if int(raw) >= len(o.Names) || o.Names[raw] == "" {
				for i, n := range o.Names {
					if n != "" {
						raw = int64(i)
						break
					}
				}
			}
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		values[o.Name] = raw*scale + o.Bias
	}
	return values
}

// corpusSamples exercises zero, highest legal indices and signed minima as
// well as an ordinary value. Sparse value bits are kept in their source slots.
func corpusSamples(e *codec.Encoding) []map[string]int64 {
	out := []map[string]int64{sample(e)}
	for mode := 0; mode < 3; mode++ {
		values := map[string]int64{}
		for _, o := range e.Operands {
			raw := uint64(0)
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					bit := b.ValueBit + k
					if mode == 1 || mode == 2 && bit == o.Width()-1 {
						raw |= uint64(1) << bit
					}
				}
			}
			if len(o.Names) > 0 {
				indices := []int{}
				for i, n := range o.Names {
					if n != "" {
						indices = append(indices, i)
					}
				}
				switch mode {
				case 0:
					raw = uint64(indices[0])
				case 1:
					raw = uint64(indices[len(indices)-1])
				case 2:
					raw = uint64(indices[len(indices)/2])
				}
			}
			value := int64(raw)
			if o.Signed && raw&(uint64(1)<<uint(o.Width()-1)) != 0 {
				value -= int64(uint64(1) << uint(o.Width()))
			}
			scale := o.Scale
			if scale == 0 {
				scale = 1
			}
			values[o.Name] = value*scale + o.Bias
		}
		out = append(out, values)
	}
	return out
}
func TestRuntimeCorpus(t *testing.T) {
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			for i := range c.Encodings {
				e := &c.Encodings[i]
				for _, v := range corpusSamples(e) {
					b, err := codec.Encode(e, v)
					if err != nil {
						t.Fatalf("%s: %v", e.ID, err)
					}
					if arch == "tricore" && int(b[0]&1) != (len(b)/2-1) {
						t.Fatalf("%s invalid16/32 framing %x", e.ID, b)
					}
					single := codec.Catalog{Architecture: arch, Encodings: []codec.Encoding{*e}}
					d, err := single.Decode(b)
					if err != nil {
						t.Fatalf("%s decode %x: %v", e.ID, b, err)
					}
					again, err := codec.Encode(e, d.Values)
					if err != nil || !bytes.Equal(b, again) {
						t.Fatalf("%s structured roundtrip %x !=%x %v", e.ID, b, again, err)
					}
					text := d.Format(0x1000)
					parsed, ok := codec.ParseOperands(e, text, 0x1000)
					if !ok {
						t.Fatalf("%s cannot parse %q", e.ID, text)
					}
					again, err = codec.Encode(e, parsed)
					if err != nil || !bytes.Equal(b, again) {
						t.Fatalf("%s text roundtrip %q %x !=%x %v", e.ID, text, b, again, err)
					}
					decoded, err := c.DecodeWithFeatures(b, e.Features)
					if err != nil {
						t.Fatal(err)
					}
					candidates, err := c.AssembleWithFeatures(decoded.Format(0x1000), 0x1000, e.Features)
					if err != nil {
						t.Fatalf("%s catalog text %q: %v", e.ID, decoded.Format(0x1000), err)
					}
					found := false
					for _, x := range candidates {
						found = found || bytes.Equal(x, b)
					}
					if !found {
						t.Fatalf("%s lost framing/fields through catalog %x -> %q -> %x", e.ID, b, decoded.Format(0x1000), candidates)
					}
				}
			}
		})
	}
}
func ExampleParse() {
	c, err := Parse(strings.NewReader(Source), "tricore")
	if err != nil {
		panic(err)
	}
	all, err := c.AssembleWithFeatures("add d0,d0,d0", 0x1000, c.FeatureSets["v2"])
	if err != nil {
		panic(err)
	}
	for _, b := range all {
		fmt.Printf("%x\n", b)
	}
	// Output:
	// 0b000000
}

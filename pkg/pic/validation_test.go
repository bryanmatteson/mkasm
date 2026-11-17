package pic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestTargetUnits(t *testing.T) {
	for _, v := range []struct{ arch, profile, hex, text string }{{"pic14", "pic14-enhanced", "ff33", "BRA 0x1000"}, {"pic18", "pic18", "ffd7", "BRA 0x1000"}, {"pic24", "pic24e", "ffff3700", "bra 0x1000"}, {"pic24", "pic24e", "0200020000000000", "call 0x4"}} {
		c, err := Parse(nil, v.arch)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := hex.DecodeString(v.hex)
		d, err := c.DecodeWithFeatures(b, c.FeatureSets[v.profile])
		if err != nil {
			t.Fatal(v.arch, err)
		}
		if d.Format(0x1000) != v.text {
			t.Fatalf("%s: %s != %s", v.arch, d.Format(0x1000), v.text)
		}
		a, err := c.AssembleWithFeatures(v.text, 0x1000, c.FeatureSets[v.profile])
		ok := false
		for _, x := range a {
			ok = ok || bytes.Equal(x, b)
		}
		if err != nil || !ok {
			t.Fatal(v.arch, err)
		}
	}
}
func TestStrictFraming(t *testing.T) {
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Encodings {
			one := &codec.Catalog{Encodings: []codec.Encoding{e}}
			b, err := codec.Encode(&e, sample(&e))
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < len(b); i++ {
				if _, err := one.Decode(b[:i]); !errors.Is(err, codec.ErrTruncated) {
					t.Fatalf("%s prefix%d: %v", e.ID, i, err)
				}
			}
			for _, o := range e.Operands {
				if !o.Optional {
					continue
				}
				v := sample(&e)
				v[o.Name] = (int64(1) << uint(o.Width())) - 1
				nonzero, err := codec.Encode(&e, v)
				if err != nil {
					t.Fatal(err)
				}
				d, err := one.Decode(nonzero)
				if err != nil {
					t.Fatal(err)
				}
				round, err := codec.Encode(d.Encoding, d.Values)
				if err != nil || !bytes.Equal(round, nonzero) {
					t.Fatal(e.ID, "padding", err)
				}
			}
		}
	}
	c, _ := Parse(nil, "pic18")
	for _, h := range []string{"00ec0000", "00ef0000", "00ee00ff"} {
		b, _ := hex.DecodeString(h)
		if _, err := c.Decode(b); err == nil {
			t.Fatal("accepted malformed PIC18 continuation", h)
		}
	}
}
func TestSourceCoverage(t *testing.T) {
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		var src corpus
		if err := json.Unmarshal(Source, &src); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, u := range c.Unsupported {
			if u.ID != "pic18_L1061" && u.ID != "pic18_L1815" && u.ID != "pic17_L520" {
				t.Fatal(u)
			}
			seen[u.ID] = true
		}
		for _, e := range c.Encodings {
			parts := strings.Split(e.ID, "_")
			seen[strings.Join(parts[:2], "_")] = true
		}
		for i, p := range src.Profiles {
			profile := profileNames[i]
			if !contains(aliases[arch], profile) {
				continue
			}
			for _, ct := range p.Tables["instruction"] {
				if ct.Length == 0 {
					continue
				}
				key := profile + "_L" + strconv.Itoa(ct.Line)
				if !seen[key] {
					t.Error("missing original constructor", key)
				}
			}
		}
	}
}

func TestEveryPhysicalField(t *testing.T) {
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Encodings {
			one := &codec.Catalog{Encodings: []codec.Encoding{e}}
			for trial := 0; trial < 10; trial++ {
				b := append([]byte(nil), e.Value...)
				for j := range b {
					b[j] |= byte((uint64(0x9e3779b97f4a7c15)*uint64(trial+1+j))>>uint(j*7)) &^ e.Mask[j]
				}
				d, err := one.Decode(b)
				if err != nil {
					continue
				}
				round, err := codec.Encode(d.Encoding, d.Values)
				if err != nil || !bytes.Equal(round, b) {
					t.Fatalf("%s %x: %v", e.ID, b, err)
				}
			}
		}
	}
}

func TestRealRoutine(t *testing.T) {
	c, err := Parse(nil, "pic18")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/pic18-routine.bin")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for at := 0; at < len(b); {
		d, err := c.DecodeWithFeatures(b[at:], c.FeatureSets["default"])
		if err != nil {
			t.Fatal(at, err)
		}
		forms, err := c.AssembleWithFeatures(d.Format(uint64(at)), uint64(at), c.FeatureSets["default"])
		found := false
		for _, x := range forms {
			found = found || bytes.Equal(x, b[at:at+d.Length])
		}
		if err != nil || !found {
			t.Fatal(at, d.Format(uint64(at)), err)
		}
		at += d.Length
		count++
	}
	if count != 7 {
		t.Fatal("routine frame count", count)
	}
}

func TestPageLatchesAndFeatures(t *testing.T) {
	for _, v := range []struct {
		arch, hex string
		latch     uint8
		want      uint64
	}{{"pic12", "0009", 2, 0x800}, {"pic14", "0020", 0x18, 0x3000}, {"pic17", "00b7", 0x12, 0x2400}} {
		c, err := Parse(nil, v.arch)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := hex.DecodeString(v.hex)
		d, err := c.DecodeWithFeatures(b, c.FeatureSets["default"])
		if err != nil {
			t.Fatal(err)
		}
		target, ok := TargetWithPage(d, 0x1000, v.latch)
		if !ok || target != v.want {
			t.Fatal(v.arch, target, ok)
		}
	}
	c, _ := Parse(nil, "pic18")
	b := []byte{0, 0xea}
	if _, err := c.DecodeWithFeatures(b, c.FeatureSets["default"]); err == nil {
		t.Fatal("PUSHL available without XINST")
	}
	d, err := c.DecodeWithFeatures(b, c.FeatureSets["pic18-extended"])
	if err != nil || d.Encoding.Mnemonic != "PUSHL" {
		t.Fatal(d, err)
	}
	c14, _ := Parse(nil, "pic14")
	d, err = c14.DecodeWithFeatures([]byte{0x20, 0}, c14.FeatureSets["pic14-enhanced"])
	if err != nil || d.Encoding.Mnemonic != "MOVLB" {
		t.Fatal(d, err)
	}
}

func TestTargetWrap(t *testing.T) {
	c, err := Parse(nil, "pic24")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.DecodeWithFeatures([]byte{0, 0, 0x37, 0}, c.FeatureSets["pic24e"])
	if err != nil {
		t.Fatal(err)
	}
	target, ok := d.BranchTarget(0xfffffc)
	if !ok || target != 0 {
		t.Fatal(target, ok)
	}
	c, err = Parse(nil, "pic12")
	if err != nil {
		t.Fatal(err)
	}
	d, err = c.DecodeWithFeatures([]byte{0, 9}, c.FeatureSets["default"])
	if err != nil {
		t.Fatal(err)
	}
	target, ok = d.BranchTarget(0x200)
	if !ok || target != 0 {
		t.Fatal("PIC12 CALL must clear bit8", target, ok)
	}
}

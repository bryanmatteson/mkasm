package mos6502

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func load(t testing.TB) *Catalog {
	t.Helper()
	f, err := os.Open("testdata/opcodes.c")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "mos6502")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func profileFor(c *Catalog, e *codec.Encoding) string {
	for _, name := range profiles {
		active := c.FeatureSets[name]
		ok := true
		for _, f := range e.Features {
			found := false
			for _, v := range active {
				found = found || v == f
			}
			ok = ok && found
		}
		if ok {
			return name
		}
	}
	panic("missing source profile")
}
func sample(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(0x44)
		if o.Width() == 16 {
			n = 0x1234
		}
		if o.Relative {
			n = 8
		}
		if o.Name == "signature" {
			n = 0
		}
		v[o.Name] = n
	}
	return v
}
func TestWholeCorpus(t *testing.T) {
	c := load(t)
	if len(c.Encodings) != 361 {
		t.Fatal(len(c.Encodings))
	}
	counts := map[string]int{}
	for _, e := range c.Encodings {
		v := sample(&e)
		b, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(e.ID, err)
		}
		profile := profileFor(c, &e)
		d, err := c.DecodeWithFeatures(b, c.FeatureSets[profile])
		if err != nil || d.Length != len(b) {
			t.Fatal(e.ID, d, err)
		}
		back, err := c.Encode(d.Encoding.ID, d.Values)
		if err != nil || !bytes.Equal(back, b) {
			t.Fatal(e.ID, err)
		}
		text := d.Format(0x1000)
		forms, err := c.AssembleWithFeatures(text, 0x1000, c.FeatureSets[profile])
		found := false
		for _, x := range forms {
			found = found || bytes.Equal(x, b)
		}
		if err != nil || !found {
			t.Fatal(e.ID, text, err)
		}
		for n := 0; n < len(b); n++ {
			if _, err := c.DecodeWithFeatures(b[:n], c.FeatureSets[profile]); !errors.Is(err, codec.ErrTruncated) {
				t.Fatal(e.ID, n, err)
			}
		}
	}
	for _, profile := range profiles {
		for op := 0; op < 256; op++ {
			if _, err := c.DecodeWithFeatures([]byte{byte(op), 0, 0}, c.FeatureSets[profile]); err == nil {
				counts[profile]++
			}
		}
	}
	t.Log(counts)
	for name, want := range map[string]int{"6502": 151, "6502x": 256, "65sc02": 178, "65c02": 210, "w65c02": 212, "w65c02+nops": 256} {
		if counts[name] != want {
			t.Fatal(name, counts[name], want)
		}
	}
}
func TestBoundaries(t *testing.T) {
	c := load(t)
	for _, e := range c.Encodings {
		for _, o := range e.Operands {
			ns := []int64{0, (1 << uint(o.Width())) - 1}
			if o.Signed {
				ns = []int64{-128, -1, 0, 127}
			}
			for _, n := range ns {
				v := sample(&e)
				v[o.Name] = n
				b, err := c.Encode(e.ID, v)
				if err != nil {
					t.Fatal(e.ID, n, err)
				}
				d, err := c.DecodeWithFeatures(b, c.FeatureSets[profileFor(c, &e)])
				if err != nil || d.Values[o.Name] != n {
					t.Fatal(e.ID, n, d, err)
				}
			}
			invalid := []int64{-1, 1 << uint(o.Width())}
			if o.Signed {
				invalid = []int64{-129, 128}
			}
			for _, n := range invalid {
				v := sample(&e)
				v[o.Name] = n
				if _, err := c.Encode(e.ID, v); err == nil {
					t.Fatal("invalid value admitted", e.ID, o.Name, n)
				}
			}
		}
	}
	for _, row := range []struct {
		text, profile, hex string
		address            uint64
	}{{"lda #$ff", "6502", "a9ff", 0}, {"lda #%10101010", "6502", "a9aa", 0}, {"asl", "6502", "0a", 0}, {"brk", "6502", "0000", 0}, {"bne $0002", "6502", "d002", 0xfffe}, {"bne $ffff", "6502", "d0fd", 0}, {"bbr0 $44,$0001", "65c02", "0f44fe", 0}} {
		forms, err := c.AssembleWithFeatures(row.text, row.address, c.FeatureSets[row.profile])
		want, _ := hex.DecodeString(row.hex)
		if err != nil || len(forms) == 0 || !bytes.Equal(forms[0], want) {
			t.Fatal(row, forms, err)
		}
	}
	for _, bad := range []string{"lda #256", "lda #-129", "lda #", "lda (0x100,x)", "sta #1", "jmp (65536)", "bne 0x2000", "brk #256", "bbr8 1,2"} {
		if _, err := c.Assemble(bad, 0x1000); err == nil {
			t.Fatal("invalid assembly admitted", bad)
		}
	}
	if _, err := Parse(strings.NewReader("const OpcDesc OpcTable_6502[256] = {};"), "mos6502"); err == nil {
		t.Fatal("partial source admitted")
	}
	if _, err := c.DecodeWithFeatures([]byte{0x02}, c.FeatureSets["6502"]); !errors.Is(err, codec.ErrUnknown) {
		t.Fatal(err)
	}
	if _, err := c.DecodeWithFeatures([]byte{0x02}, c.FeatureSets["w65c02+nops"]); !errors.Is(err, codec.ErrTruncated) {
		t.Fatal(err)
	}
	if _, err := c.Decode([]byte{0}); !errors.Is(err, codec.ErrTruncated) {
		t.Fatal("BRK must include signature", err)
	}
}
func TestTemplatesAndAddresses(t *testing.T) {
	c := load(t)
	nop, err := c.ParseTemplateWithFeatures("nop", 0, c.FeatureSets["6502"])
	if err != nil {
		t.Fatal(err)
	}
	nb, err := nop.Encode(nil)
	if err != nil || len(nb) != 1 || !bytes.Equal(nb[0], []byte{0xea}) {
		t.Fatal(nb, err)
	}
	for _, row := range []struct {
		profile string
		op      byte
		want    string
	}{{"6502", 2, "invalid"}, {"6502x", 2, "undocumented"}, {"65c02", 0xcb, "invalid"}, {"w65c02", 0xcb, "documented"}, {"w65c02+nops", 0x5c, "reserved-nop"}} {
		got, err := c.OpcodeStatus(row.profile, row.op)
		if err != nil || got != row.want {
			t.Fatal(row, got, err)
		}
	}
	for _, pair := range [][2]string{{"ane #$44", "xaa #$44"}, {"sha ($44),y", "ahx ($44),y"}} {
		a, err := c.AssembleWithFeatures(pair[0], 0, c.FeatureSets["6502x"])
		if err != nil {
			t.Fatal(err)
		}
		b, err := c.AssembleWithFeatures(pair[1], 0, c.FeatureSets["6502x"])
		if err != nil || !bytes.Equal(a[0], b[0]) {
			t.Fatal(pair, err)
		}
	}
	template, err := c.ParseTemplate("lda #${constant}", 0)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := template.Encode(map[string]int64{"constant": 255})
	if err != nil || len(bs) != 1 || !bytes.Equal(bs[0], []byte{0xa9, 255}) {
		t.Fatal(bs, err)
	}
	v, err := template.Match(bs[0])
	if err != nil || v["constant"] != 255 {
		t.Fatal(v, err)
	}
	memory := map[uint16]byte{0xff: 0x34, 0x00: 0x12, 0x10ff: 0x78, 0x1000: 0x56, 0x1100: 0x9a, 0xffff: 0x56}
	read := func(at uint16) byte { return memory[at] }
	for _, row := range []struct {
		code, profile string
		x, y          byte
		want          uint16
		cross         bool
	}{{"b5ff", "6502", 2, 0, 1, false}, {"bdffff", "6502", 2, 0, 1, true}, {"a1fe", "6502", 1, 0, 0x1234, false}, {"b1ff", "6502", 0, 255, 0x1333, true}, {"6cff10", "6502", 0, 0, 0x5678, false}, {"6cff10", "65c02", 0, 0, 0x9a78, false}, {"6cffff", "65c02", 0, 0, 0x1256, false}} {
		b, _ := hex.DecodeString(row.code)
		d, err := c.DecodeWithFeatures(b, c.FeatureSets[row.profile])
		if err != nil {
			t.Fatal(err)
		}
		r, ok, err := ResolveOperand(d, "address", 0, AddressContext{row.profile, row.x, row.y, read})
		if err != nil || !ok || r.Address != row.want || r.PageCrossed != row.cross {
			t.Fatal(row, r, err)
		}
	}
}
func FuzzDecode(f *testing.F) {
	c := load(f)
	for _, e := range c.Encodings {
		b, err := c.Encode(e.ID, sample(&e))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, byte(0))
	}
	f.Fuzz(func(t *testing.T, b []byte, p byte) {
		profile := profiles[int(p)%len(profiles)]
		d, err := c.DecodeWithFeatures(b, c.FeatureSets[profile])
		if err != nil {
			return
		}
		if d.Length <= 0 || d.Length > len(b) {
			t.Fatal("bad frame")
		}
		out, err := c.Encode(d.Encoding.ID, d.Values)
		if err != nil || !bytes.Equal(out, b[:d.Length]) {
			t.Fatal("not exact", err)
		}
	})
}

package z80

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPrefixFraming(t *testing.T) {
	c, err := Parse(nil, "z80")
	if err != nil {
		t.Fatal(err)
	}
	framed := []byte{0xdd, 0xfd, 0xdd, 0x21, 0x34, 0x12}
	for _, profile := range []string{"default", "z80", "z8401x"} {
		d, err := c.DecodeWithFeatures(framed, c.FeatureSets[profile])
		if err != nil || d.Length != len(framed) {
			t.Fatal(profile, d, err)
		}
		b, err := c.AssembleWithFeatures(d.Format(0), 0, c.FeatureSets[profile])
		if err != nil || !bytes.Equal(b[0], framed) {
			t.Fatal(profile, b, err)
		}
	}
	if _, err := c.DecodeWithFeatures(framed, []string{}); !errors.Is(err, ErrUnknown) {
		t.Fatal("inactive profile admitted framed encoding", err)
	}
	if _, err := c.AssembleWithFeatures("prefix[ddfd] enc[dd21] ld ix,4660", 0, []string{}); err == nil {
		t.Fatal("inactive profile admitted qualified encoding")
	}
	cases := []struct {
		b      []byte
		text   string
		length int
	}{{[]byte{0xdd, 0x76}, "halt", 2}, {[]byte{0xdd, 0xfd, 0xdd, 0x21, 0x34, 0x12}, "ld ix,4660", 6}, {[]byte{0xfd, 0xed, 0x44}, "neg", 3}, {[]byte{0xdd, 0xeb}, "ex de,hl", 2}, {[]byte{0xdd, 0x66, 0x80}, "ld h,(ix-128)", 3}, {[]byte{0xdd, 0xcb, 0x7f, 0}, "rlc (ix+127),b", 4}, {[]byte{0xdd, 0xcb, 0x80, 0x40}, "bit 0,(ix-128)", 4}, {[]byte{0xed, 0xed, 0x21, 0, 0}, "nop", 2}}
	for _, x := range cases {
		d, err := c.Decode(x.b)
		if err != nil {
			t.Fatalf("%x: %v", x.b, err)
		}
		if d.Length != x.length || d.CanonicalFormat(0x1000) != x.text {
			t.Errorf("%x: %q len%d", x.b, d.CanonicalFormat(0x1000), d.Length)
		}
		b, err := d.Reencode()
		if err != nil || !bytes.Equal(b, x.b[:d.Length]) {
			t.Fatal(b, err)
		}
		all, err := c.Assemble(d.Format(0x1000), 0x1000)
		if err != nil || !bytes.Equal(all[0], b) {
			t.Fatal(d.Format(0x1000), all, err)
		}
	}
	for _, length := range []int{1, 2, 255, 256, 4097, 65537} {
		raw := bytes.Repeat([]byte{0xdd}, length)
		raw = append(raw, 0xfd, 0x21, 0x34, 0x12)
		d, err := c.Decode(raw)
		if err != nil || d.Length != len(raw) {
			t.Fatal(length, d, err)
		}
		b, err := d.Reencode()
		if err != nil || !bytes.Equal(b, raw) {
			t.Fatal(length, err)
		}
		all, err := c.Assemble(d.Format(0), 0)
		if err != nil || !bytes.Equal(all[0], raw) {
			t.Fatal(length, err)
		}
	}
	for _, raw := range [][]byte{nil, {0xdd}, {0xdd, 0xfd}, {0xdd, 0xcb}, {0xdd, 0xcb, 0}, {0xdd, 0x21}, {0xdd, 0x21, 0}, {0xed}} {
		if _, err := c.Decode(raw); !errors.Is(err, ErrTruncated) {
			t.Errorf("truncated%x: %v", raw, err)
		}
	}
	d, err := c.Decode([]byte{0xdd, 0x18, 0xfd})
	if err != nil {
		t.Fatal(err)
	}
	target, ok := d.BranchTarget(65535)
	if !ok || target != 65535 {
		t.Fatal(target, ok)
	}
	for _, text := range []string{"ld a,256", "ld a,(ix-129)", "ld a,(iy+128)", "prefix[ed] nop", "prefix[dd] ld hl,1", "prefix[dd", "enc[invalid] nop", "jr 0x2000"} {
		if _, err := c.Assemble(text, 0x1000); err == nil {
			t.Errorf("invalid text accepted%q", text)
		}
	}
	var output bytes.Buffer
	if err = c.WriteJSON(&output); err != nil {
		t.Fatal(err)
	}
	copy, err := Parse(&output, "z80")
	if err != nil {
		t.Fatal(err)
	}
	if len(copy.Encodings) != len(c.Encodings) {
		t.Fatal("JSON catalog lost forms")
	}
	for _, input := range []string{"", Source[:100], strings.Replace(Source, "0000\t# NOP", "0001\t# NOP", 1), "{}"} {
		if _, err := Parse(strings.NewReader(input), "z80"); err == nil {
			t.Fatal("malformed source accepted")
		}
	}
	if _, err := Parse(nil, "ez80"); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
	if !json.Valid(output.Bytes()) && output.Len() != 0 {
		t.Fatal("invalid JSON")
	}
}
func TestTemplates(t *testing.T) {
	c, _ := Parse(nil, "z80")
	template, err := c.ParseTemplate("prefix[ddfd] ld $dst,$value", 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	all, err := template.Encode(map[string]int64{"dst": 2, "value": 0x1234})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte{0xdd, 0xfd, 0xdd, 0x21, 0x34, 0x12}
	found := false
	for _, b := range all {
		found = found || bytes.Equal(raw, b)
	}
	if !found {
		t.Fatalf("missing% x in%x", raw, all)
	}
	n, holes, ok := template.Matches(raw)
	if !ok || n != 6 || holes["value"] != 0x1234 {
		t.Fatal(n, holes, ok)
	}
	repeated, err := c.ParseTemplate("ld $same,$same", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := repeated.Matches([]byte{0x41}); ok {
		t.Fatal("repeated binding accepted different registers")
	}
	if _, _, ok := repeated.Matches([]byte{0x40}); !ok {
		t.Fatal("repeated register failed")
	}
	mode, err := c.ParseTemplate("im $mode", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, values, ok := mode.Matches([]byte{0xed, 0x6e}); !ok || values["mode"] != 0 {
		t.Fatal("duplicate IM selector lost semantic mode", values, ok)
	}
	all, err = mode.Encode(map[string]int64{"mode": 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("IM2 aliases: %x", all)
	}
}
func FuzzDecode(f *testing.F) {
	c, err := Parse(nil, "z80")
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range [][]byte{{}, {0xdd}, {0xdd, 0xfd, 0xed, 0x44}, {0xdd, 0xcb, 0x80, 0}, {0x18, 0xff}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := c.Decode(b)
		if err != nil {
			return
		}
		if d.Length <= 0 || d.Length > len(b) {
			t.Fatal(d.Length)
		}
		again, err := d.Reencode()
		if err != nil || !bytes.Equal(again, b[:d.Length]) {
			t.Fatalf("%x !=%x: %v", again, b[:d.Length], err)
		}
	})
}

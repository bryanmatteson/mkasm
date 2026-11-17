package xtensa

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvedConfigurationConsumer(t *testing.T) {
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		if e := c.ValidateConfiguration(); e != nil {
			t.Fatalf("%s %v", arch, e)
		}
		var b bytes.Buffer
		if e := c.WriteJSON(&b); e != nil {
			t.Fatal(e)
		}
		backend, e := Parse(&b, arch)
		if e != nil {
			t.Fatal(e)
		}
		copy := backend.(*Catalog)
		text := "add a2,a3,a4"
		if arch == "xtensa" {
			text = "{ add a2,a3,a4; add a5,a6,a7; nop }"
		}
		all, e := copy.Assemble(text, 0x1000)
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range all {
			d, e := copy.Decode(raw)
			if e != nil {
				t.Fatal(e)
			}
			got, e := copy.Encode(*d)
			if e != nil || !bytes.Equal(got, raw) {
				t.Fatal(got, e)
			}
		}
	}
}

func TestConfiguredPacketLength(t *testing.T) {
	c := fixture(t, "xtensa")
	// Extend the real GNU slot placement with a fixed four-byte format trailer.
	// This tests configuration framing, without claiming a new proprietary ISA.
	f := &c.Formats[3]
	f.Name, f.Length = "configured-96", 12
	f.Mask = append(f.Mask, 255, 255, 255, 255)
	f.Value = append(f.Value, 0, 0, 0, 0)
	for i := range c.Slots.Encodings {
		e := &c.Slots.Encodings[i]
		m := c.Metadata[e.ID]
		if m.Format != 3 {
			continue
		}
		e.Mask = append(e.Mask, 255, 255, 255, 255)
		e.Value = append(e.Value, 0, 0, 0, 0)
		m.Mask = append(m.Mask, 0, 0, 0, 0)
		c.Metadata[e.ID] = m
	}
	if err := c.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	all, err := c.Assemble("{ add a2,a3,a4; add a5,a6,a7; nop }", 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range all {
		if len(raw) != 12 {
			t.Fatalf("configured length %d", len(raw))
		}
		d, err := c.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		back, err := c.Encode(*d)
		if err != nil || !bytes.Equal(back, raw) {
			t.Fatal(back, err)
		}
		if _, err := c.Decode(raw[:11]); err == nil {
			t.Fatal("accepted truncated configuration packet")
		}
	}
	if out := os.Getenv("XTENSA_CONFIGURED_RUST"); out != "" {
		if err := c.GenerateRust(out); err != nil {
			t.Fatal(err)
		}
		// Give this independently configured consumer its own package identity.
		path := filepath.Join(out, "Cargo.toml")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.Replace(b, []byte(`name = "xtensa"`), []byte(`name = "xtensa_configured"`), 1)
		// Keep the library crate name used by generated consumer tests.
		b = bytes.Replace(b, []byte("[lib]\n"), []byte("[lib]\nname = \"xtensa\"\n"), 1)
		if err = os.WriteFile(path, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
func TestConfigurationRejectsUnspecifiedBits(t *testing.T) {
	c := fixture(t, "xtensa")
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	var copy Catalog
	if e = json.Unmarshal(raw, &copy); e != nil {
		t.Fatal(e)
	}
	for id, m := range copy.Metadata {
		m.Mask[0] = 0
		copy.Metadata[id] = m
		break
	}
	if e = copy.ValidateConfiguration(); e == nil {
		t.Fatal("accepted inconsistent physical slot ownership")
	}
}

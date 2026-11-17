package xtensa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestArchitecturalBoundaries(t *testing.T) {
	c := fixture(t, "xtensa")
	for _, src := range [][]byte{nil, {0}, {0, 0}, {8}, {14}, {14, 0, 0, 0, 0, 0, 0}} {
		if _, err := c.Decode(src); !errors.Is(err, codec.ErrTruncated) {
			t.Fatalf("%x must be truncated: %v", src, err)
		}
	}
	if _, err := c.Decode([]byte{15, 0, 0, 0, 0, 0, 0, 128}); err == nil {
		t.Fatal("reserved format bit accepted")
	}
	for _, text := range []string{"all4 b0,b1", "all8 b0,b4", "extui a2,a3,31,2", "slli a2,a3,32", "l32i a2,a3,3", "s32e a2,a3,0", "movi.n a2,96", "{ add a2,a3,a4 }", "{ nop; nop; nop; nop }"} {
		if _, err := c.Assemble(text, 0x1000); err == nil {
			t.Errorf("illegal assembly accepted %s", text)
		}
	}
	for _, text := range []string{"beqi a2,-1,0x1004", "bgeui a2,65536,0x1004", "movi.n a2,-32", "movi.n a2,95", "addi.n a2,a3,-1", "s32e a2,a3,-64", "s32e a2,a3,-4", "all4 b3,b12", "all8 b3,b8", "extui a2,a3,31,1", "slli a2,a3,1"} {
		bb, err := c.Assemble(text, 0x1000)
		if err != nil || len(bb) == 0 {
			t.Errorf("legal %s: %v", text, err)
		}
	}
}
func TestRelativeBases(t *testing.T) {
	c := fixture(t, "xtensa")
	for addr := uint64(0x1000); addr < 0x1004; addr++ {
		for _, text := range []string{"call0 0x1010", "l32r a2,0xffc", "beqz a2,0x1008", "beqz.n a2,0x1008"} {
			bb, err := c.Assemble(text, addr)
			if err != nil {
				t.Fatal(addr, text, err)
			}
			for _, b := range bb {
				d, err := c.Decode(b)
				if err != nil {
					t.Fatal(err)
				}
				got := c.Format(d, addr)
				again, err := c.Assemble(got, addr)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, x := range again {
					found = found || bytes.Equal(x, b)
				}
				if !found {
					t.Fatal("relative byte mismatch")
				}
				if text == "l32r a2,0xffc" {
					want := byte(255)
					if addr&3 != 0 {
						want = 254
					}
					if b[1] != want || b[2] != 255 {
						t.Errorf("literal base %x => %x", addr, b)
					}
				}
				if text == "call0 0x1010" && b[0] != 0xc5 {
					t.Errorf("aligned call base %x => %x", addr, b)
				}
			}
		}
	}
}
func TestFeatureProfiles(t *testing.T) {
	c := fixture(t, "xtensa")
	generic := c.Core.FeatureSets["generic"]
	esp32 := c.Core.FeatureSets["esp32"]
	esp8266 := c.Core.FeatureSets["esp8266"]
	for _, x := range []struct {
		text     string
		features []string
		valid    bool
	}{{"add a2,a3,a4", generic, true}, {"add.n a2,a3,a4", generic, false}, {"add.n a2,a3,a4", esp8266, true}, {"entry a1,32", esp8266, false}, {"entry a1,32", esp32, true}, {"rsr a2,lbeg", generic, false}, {"rsr a2,sar", generic, true}, {"rsr a2,lbeg", esp32, true}, {"rsr a2,ccompare2", esp32, true}, {"rsr a2,ccompare2", esp8266, false}, {"wsr a2,prid", esp32, false}, {"xsr a2,interrupt", esp32, false}, {"rur a2,fcr", esp32, true}, {"rur a2,fcr", esp8266, false}} {
		_, err := c.AssembleWithFeatures(x.text, 0, x.features)
		if (err == nil) != x.valid {
			t.Errorf("%s valid=%v err=%v features%v", x.text, x.valid, err, x.features)
		}
	}
}

func TestEveryDensityWord(t *testing.T) {
	counts := map[string]int{}
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		for word := 0; word < 65536; word++ {
			src := []byte{byte(word), byte(word >> 8)}
			op := src[0] & 15
			if arch == "xtensaeb" {
				op = src[0] >> 4
			}
			if op < 8 || op >= 14 {
				continue
			}
			d, err := c.Decode(src)
			if err != nil {
				if !errors.Is(err, codec.ErrUnknown) {
					t.Fatalf("%s framed density %x: %v", arch, src, err)
				}
				continue
			}
			b, err := c.Encode(*d)
			if err != nil || !bytes.Equal(b, src) {
				t.Fatalf("%s density %x/%x %v", arch, src, b, err)
			}
			counts[arch]++
		}
	}
	if counts["xtensa"] != counts["xtensaeb"] || counts["xtensa"] < 10000 {
		t.Fatal("density word domains differ", counts)
	}
	t.Log("legal density words", counts)
}

func TestCPUSelectionCoversBundles(t *testing.T) {
	c := fixture(t, "xtensa")
	base, err := c.WithCPU("generic")
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Slots.Encodings) != 0 {
		t.Fatal("generic CPU retained FLIX")
	}
	if _, err := base.Assemble("add.n a2,a3,a4", 0); err == nil {
		t.Fatal("selected generic retained density")
	}
	if _, err := base.Assemble("{ add a2,a3,a4; nop; nop }", 0); err == nil {
		t.Fatal("selected generic retained bundles")
	}
	all, err := c.WithCPU("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Core.Encodings) != len(c.Core.Encodings) || len(all.Slots.Encodings) != 184 {
		t.Fatal("all CPU omitted source forms")
	}
	if len(c.Slots.Encodings) != 184 || len(c.Core.Encodings) != 611 {
		t.Fatal("selection modified source catalog")
	}
	if _, err := c.WithCPU("missing"); err == nil {
		t.Fatal("unknown CPU accepted")
	}
}

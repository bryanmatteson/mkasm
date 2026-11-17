package mips

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestGNUMicro64MachineRows(t *testing.T) {
	if exporter := os.Getenv("MKASM_MICRO64_EXPORTER"); exporter != "" {
		actual, err := exec.Command(exporter).Output()
		if err != nil || !bytes.Equal(actual, gnuMicro64JSON) {
			t.Fatalf("live GNU microMIPS64 export differs from retained primary rows: %v", err)
		}
	}
	for _, arch := range []string{"micromips32", "micromips32el", "micromips64", "micromips64el"} {
		t.Run(arch, func(t *testing.T) {
			c := compressedCatalog(t, arch)
			rows := 0
			for _, e := range c.Encodings {
				if !strings.HasPrefix(e.ID, "GNU_MICRO64_ROW_") {
					continue
				}
				rows++
				values := referenceOperands(e)
				raw, err := codec.Encode(&e, values)
				if err != nil {
					t.Fatal(e.ID, values, err)
				}
				one := &codec.Catalog{Architecture: arch, Encodings: []codec.Encoding{e}}
				decoded, err := one.DecodeWithFeatures(raw, e.Features)
				if err != nil {
					t.Fatal(e.ID, err)
				}
				if _, err := one.DecodeWithFeatures(raw, []string{"InMicroMips", "HasMSA", "HasVirt"}); err == nil {
					t.Fatal(e.ID, "64-bit requirement not enforced")
				}
				text := decoded.Format(0x123456780000)
				all, err := c.Assemble(text, 0x123456780000)
				if err != nil || !containsBytes(all, raw) {
					t.Fatalf("%s public source %q: %x %v", e.ID, text, all, err)
				}
			}
			want := 0
			if strings.Contains(arch, "64") {
				want = 85
			}
			if rows != want {
				t.Fatalf("GNU microMIPS64 rows: %d, want %d", rows, want)
			}
		})
	}
}

func TestGNUMicro64BitfieldBoundaries(t *testing.T) {
	c := compressedCatalog(t, "micromips64el")
	forms := 0
	for _, e := range c.Encodings {
		if !strings.HasPrefix(e.ID, "GNU_MICRO64_ROW_") || !strings.HasPrefix(e.Mnemonic, "dext") && !strings.HasPrefix(e.Mnemonic, "dins") {
			continue
		}
		forms++
		for pos := int64(-1); pos <= 64; pos++ {
			for size := int64(0); size <= 65; size++ {
				values := map[string]int64{"op1": 2, "op2": 3, "op3": pos, "op4": size}
				b, err := codec.Encode(&e, values)
				if err == nil {
					if pos < 0 || size < 1 || pos+size > 64 {
						t.Fatalf("accepted invalid field %s pos=%d size=%d", e.ID, pos, size)
					}
					one := &codec.Catalog{Architecture: c.Architecture, Encodings: []codec.Encoding{e}}
					d, err := one.Decode(b)
					if err != nil || d.Values["op3"] != pos || d.Values["op4"] != size {
						t.Fatalf("%s pos=%d size=%d: %v", e.ID, pos, size, err)
					}
				}
			}
		}
	}
	if forms != 10 {
		t.Fatal("bitfield forms", forms)
	}
}

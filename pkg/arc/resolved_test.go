package arc

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func containsBytes(encodings [][]byte, want []byte) bool {
	for _, b := range encodings {
		if bytes.Equal(b, want) {
			return true
		}
	}
	return false
}

func decodeFollowedByNOP(t *testing.T, c *codec.Catalog, b []byte) *codec.Decoded {
	t.Helper()
	nop := []byte{0xe0, 0x78}
	if strings.HasSuffix(c.Architecture, "be") {
		nop[0], nop[1] = nop[1], nop[0]
	}
	stream := append(append([]byte{}, b...), nop...)
	d, err := c.Decode(stream)
	if err != nil {
		t.Fatalf("stream decode %x: %v", stream, err)
	}
	if d.Length != len(b) {
		t.Fatalf("consumed %d bytes for %x; want %d", d.Length, b, len(b))
	}
	next, err := c.Decode(stream[d.Length:])
	if err != nil || next.Length != 2 || next.Encoding.Mnemonic != "nop_s" {
		t.Fatalf("following nop_s lost: %v, %v", next, err)
	}
	return d
}

// These images follow the actual ARCv3 opcode/operand/flag definitions. The
// acquire/release cases also match GNU hs6x assembler ELF .text bytes.
func TestARCv3BoundaryEncodings(t *testing.T) {
	for _, arch := range []string{"arc64", "arc64be", "arcv3-32", "arcv3-32be"} {
		t.Run(arch, func(t *testing.T) {
			c := catalog(t, "testdata/arcv3-resolved.tar.gz", arch)
			for _, suffix := range []string{"", ".aq", ".rl", ".aq.rl"} {
				want := []byte{0x2f, 0x21, 0xb0, 0}
				if suffix != "" {
					want[3] = 0x80
				}
				if strings.HasSuffix(arch, "be") {
					want[0], want[1] = want[1], want[0]
					want[2], want[3] = want[3], want[2]
				}
				text := "atld.add" + suffix + " r1, [r2]"
				bs, err := c.Assemble(text, 0)
				if err != nil || !containsBytes(bs, want) {
					t.Fatalf("%s: %x, %v; want %x", text, bs, err, want)
				}
				d := decodeFollowedByNOP(t, c, want)
				bs, err = c.Assemble(d.Format(0), 0)
				if err != nil || !containsBytes(bs, want) {
					t.Fatalf("union text round trip %x: %x, %v", want, bs, err)
				}
			}
			if !strings.HasPrefix(arch, "arc64") {
				return
			}
			// LIMM34 has 32 physical bits, a signed 34-bit byte displacement,
			// and PCL alignment. Test both extrema and modular 64-bit targets.
			for _, tc := range []struct {
				address, target uint64
				image           string
			}{
				{0, 0x1fffffffc, "e07bff7fffff"},
				{0, 0xfffffffe00000000, "e07b00800000"},
				{0x100000002, 0x100000064, "e07b00001900"},
				{0xfffffffffffffffe, 0x60, "e07b00001900"},
			} {
				want, _ := hex.DecodeString(tc.image)
				if strings.HasSuffix(arch, "be") {
					for i := 0; i < len(want); i += 2 {
						want[i], want[i+1] = want[i+1], want[i]
					}
				}
				text := fmt.Sprintf("bl_s 0x%x", tc.target)
				bs, err := c.Assemble(text, tc.address)
				if err != nil || !containsBytes(bs, want) {
					t.Fatalf("%s at %#x: %x, %v; want %x", text, tc.address, bs, err, want)
				}
				d := decodeFollowedByNOP(t, c, want)
				if target, ok := d.BranchTarget(tc.address); !ok || target != tc.target {
					t.Fatalf("long branch target %#x, %v; want %#x", target, ok, tc.target)
				}
			}
			for _, text := range []string{"bl_s 0x200000000", "bl_s 0xfffffffdfffffffc", "bl_s 0x2", "add r1, r2, r60", "add r1, r2, lp_count"} {
				if bs, err := c.Assemble(text, 0); err == nil {
					t.Fatalf("accepted invalid ARC64 operand: %s = %x", text, bs)
				}
			}
		})
	}
}

func TestNPSWideFramingAndRegisterMask(t *testing.T) {
	for _, arch := range []string{"arcnps400", "arcnps400be"} {
		t.Run(arch, func(t *testing.T) {
			c := catalog(t, "testdata/binutils244-nps400.tar.gz", arch)
			for _, reg := range []int{0, 1, 15, 31, 61} {
				want := []byte{0x5b, 0x38, byte(0x3e | reg<<6), byte(reg >> 2)}
				if strings.HasSuffix(arch, "be") {
					want[0], want[1] = want[1], want[0]
					want[2], want[3] = want[3], want[2]
				}
				text := fmt.Sprintf("wkup 0, r%d", reg)
				bs, err := c.Assemble(text, 0)
				if err != nil || !containsBytes(bs, want) {
					t.Fatalf("%s: %x, %v; want %x", text, bs, err, want)
				}
				d, err := c.Decode(want)
				if err != nil || d.Values["op1"] != int64(reg) {
					t.Fatalf("wkup register %d: %v, %v", reg, d, err)
				}
			}
			seen := map[string]bool{}
			for _, e := range c.Encodings {
				if seen[e.Mnemonic] || (e.Mnemonic != "mrgb" && e.Mnemonic != "mov2b" && e.Mnemonic != "mov3b" && e.Mnemonic != "mov4b") {
					continue
				}
				seen[e.Mnemonic] = true
				for sample := 0; sample < 3; sample++ {
					b, err := codec.Encode(&e, seed(&e, sample))
					if err != nil {
						t.Fatal(err)
					}
					d := decodeFollowedByNOP(t, c, b)
					back, err := c.Encode(d.Encoding.ID, d.Values)
					if err != nil || !bytes.Equal(back, b) {
						t.Fatalf("extended decode %s: %x, %v; want %x", e.ID, back, err, b)
					}
					bs, err := c.Assemble(d.Format(0), 0)
					if err != nil || !containsBytes(bs, b) {
						t.Fatalf("extended text %s: %x, %v; want %x", d.Format(0), bs, err, b)
					}
					single := &codec.Catalog{Encodings: []codec.Encoding{e}}
					for n := 0; n < len(b); n++ {
						if _, err := single.Decode(b[:n]); err == nil {
							t.Fatalf("accepted truncated %s at %d bytes", e.ID, n)
						}
					}
				}
			}
			if len(seen) != 4 {
				t.Fatalf("missing extended NPS families: %v", seen)
			}
		})
	}
}

func TestRejectUnresolvedExtensionMacros(t *testing.T) {
	for _, table := range []string{"arc-ext-tbl.h", "arc-nps400-tbl.h"} {
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		for _, name := range []string{"arc-tbl.h", "arc-opc.c", "arc-fxi.h", "arc-nps400-tbl.h", "arc-ext-tbl.h"} {
			data := "source present\n"
			if name == table {
				data = "  # define NEW_OPCODE(...) __VA_ARGS__\n"
			}
			if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseGNU(&buf, "arcnps400"); err == nil || !strings.Contains(err.Error(), "macros require the complete resolved export") {
			t.Fatalf("%s: expected explicit macro-resolution error, got %v", table, err)
		}
	}
}

func TestResolvedQuarkExtensionMacros(t *testing.T) {
	c := catalog(t, "testdata/binutils244-nps400.tar.gz", "arcem")
	if len(c.Unsupported) != 0 {
		t.Fatalf("unresolved ARC EM source rows: %v", c.Unsupported)
	}
	rows := map[string]bool{}
	for _, e := range c.Encodings {
		if !strings.Contains(e.Mnemonic, "dsp_fp_") {
			continue
		}
		rows[strings.Split(e.ID, "/")[2]] = true
		roundtrip(t, &codec.Catalog{Architecture: c.Architecture, Encodings: []codec.Encoding{e}})
	}
	if len(rows) != 58 {
		t.Fatalf("resolved %d extension rows; want all 58 macro expansions", len(rows))
	}
}

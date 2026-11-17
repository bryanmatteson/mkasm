package mcs51

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentSDCCAllOpcodes(t *testing.T) {
	for _, name := range []string{"sdas8051", "sdas390", "sdld"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip("SDCC unavailable: ", err)
		}
	}
	rows := readVectors(t, "sdcc.json")
	for _, arch := range []string{"mcs51", "mcs80390"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(strings.NewReader(source), arch)
			if err != nil {
				t.Fatal(err)
			}
			var assembly strings.Builder
			assembly.WriteString(".module reference\n.area CODE (ABS,CODE)\n")
			as := "sdas8051"
			if arch == "mcs80390" {
				as = "sdas390"
				assembly.WriteString(".DS80C390\n.amode 2\n")
			}
			var selected []oracleVector
			for _, row := range rows {
				if row.Architecture != arch {
					continue
				}
				fmt.Fprintf(&assembly, ".org 0x%x\n%s\n", row.Address, strings.ReplaceAll(row.Assembly, "CY", "c"))
				selected = append(selected, row)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "reference.asm"), []byte(assembly.String()), 0644); err != nil {
				t.Fatal(err)
			}
			for _, command := range [][]string{{as, "-plosgff", "reference.asm"}, {"sdld", "-n", "-i", "reference", "reference.rel"}} {
				cmd := exec.Command(command[0], command[1:]...)
				cmd.Dir = dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s: %v\n%s", command[0], err, out)
				}
			}
			data, err := os.ReadFile(filepath.Join(dir, "reference.ihx"))
			if err != nil {
				t.Fatal(err)
			}
			image := readIntelHEX(t, string(data))
			seen := map[byte]bool{}
			for _, row := range selected {
				want := bytesOf(t, row.Bytes)
				actual := make([]byte, len(want))
				for n := range actual {
					value, ok := image[row.Address+uint64(n)]
					if !ok {
						t.Fatalf("SDCC omitted byte %#x", row.Address+uint64(n))
					}
					actual[n] = value
				}
				candidates, err := c.Assemble(row.Assembly, row.Address)
				if err != nil || !hasBytes(candidates, actual) || !bytes.Equal(actual, want) {
					t.Fatalf("%#x %s: SDCC=%x mkasm=%x retained=%x err=%v", row.Address, row.Assembly, actual, candidates, want, err)
				}
				decoded, err := c.Decode(actual)
				if err != nil || decoded.Length != len(actual) {
					t.Fatalf("decode SDCC %x: %v", actual, err)
				}
				seen[actual[0]] = true
			}
			if len(selected) != 765 || len(seen) != 255 || seen[0xa5] {
				t.Fatalf("incomplete SDCC coverage: samples=%d opcodes=%d", len(selected), len(seen))
			}
			t.Logf("%s + sdld: %d live byte comparisons, all %d defined opcodes, 3 operand patterns", as, len(selected), len(seen))
		})
	}
}

// Container parsing only: instruction bytes come from SDCC's assembler/linker.
func readIntelHEX(t *testing.T, text string) map[uint64]byte {
	t.Helper()
	image := map[uint64]byte{}
	base := uint64(0)
	for _, line := range strings.Fields(text) {
		if !strings.HasPrefix(line, ":") {
			t.Fatalf("invalid Intel HEX line %q", line)
		}
		raw, err := hex.DecodeString(line[1:])
		if err != nil || len(raw) < 5 || int(raw[0])+5 != len(raw) {
			t.Fatalf("invalid Intel HEX record %q: %v", line, err)
		}
		var sum byte
		for _, b := range raw {
			sum += b
		}
		if sum != 0 {
			t.Fatalf("Intel HEX checksum: %q", line)
		}
		address := uint64(raw[1])<<8 | uint64(raw[2])
		data := raw[4 : len(raw)-1]
		switch raw[3] {
		case 0:
			for n, b := range data {
				image[base+address+uint64(n)] = b
			}
		case 1:
			return image
		case 2, 4:
			if len(data) != 2 {
				t.Fatal("invalid Intel HEX address record")
			}
			base = uint64(data[0])<<8 | uint64(data[1])
			if raw[3] == 2 {
				base <<= 4
			} else {
				base <<= 16
			}
		default:
			t.Fatalf("unexpected Intel HEX record type %d", raw[3])
		}
	}
	t.Fatal("Intel HEX has no EOF")
	return nil
}

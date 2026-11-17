package xtensa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func sample(e *codec.Encoding, seed int) Instruction {
	v := map[string]int64{}
	for i, o := range e.Operands {
		raw := uint64(0)
		if len(o.Names) > 0 {
			var legal []int
			for j, n := range o.Names {
				if n != "" {
					legal = append(legal, j)
				}
			}
			raw = uint64(legal[(seed+i)%len(legal)])
		} else {
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					vb := b.ValueBit + k
					if seed == 2 || seed == 1 && vb%2 == 0 {
						raw |= 1 << uint(vb)
					}
				}
			}
		}
		value := int64(raw)
		if len(o.Lookup) > 0 {
			if raw >= uint64(len(o.Lookup)) {
				raw = 0
			}
			value = o.Lookup[raw]
		} else if o.Signed && o.Width() < 64 && raw&(1<<uint(o.Width()-1)) != 0 {
			value = int64(raw | (^uint64(0) << uint(o.Width())))
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		v[o.Name] = value*scale + o.Bias
	}
	for _, c := range e.Constraints {
		if c.Kind == "sum_le" && v[c.Left]+v[c.Right] > c.Limit {
			v[c.Right] = c.Limit - v[c.Left]
		}
	}
	return Instruction{ID: e.ID, Values: v}
}
func bundle(c *Catalog, e *codec.Encoding, seed int) Decoded {
	m := c.Metadata[e.ID]
	d := Decoded{Format: c.Formats[m.Format].Name, Length: 8}
	for _, slot := range c.Formats[m.Format].Slots {
		if slot == m.Slot {
			d.Instructions = append(d.Instructions, sample(e, seed))
		} else {
			for i := range c.Slots.Encodings {
				p := &c.Slots.Encodings[i]
				mm := c.Metadata[p.ID]
				if mm.Format == m.Format && mm.Slot == slot && p.Mnemonic == "nop" {
					d.Instructions = append(d.Instructions, sample(p, 0))
					break
				}
			}
		}
	}
	return d
}
func TestCorpusRoundTrip(t *testing.T) {
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		for _, table := range []*codec.Catalog{c.Core, c.Slots} {
			for i := range table.Encodings {
				e := &table.Encodings[i]
				for seed := 0; seed < 3; seed++ {
					d := Decoded{Format: "scalar", Instructions: []Instruction{sample(e, seed)}, Length: len(e.Mask)}
					if len(e.Mask) == 8 {
						d = bundle(c, e, seed)
					}
					b, err := c.Encode(d)
					if err != nil {
						t.Fatalf("%s %s %d encode: %v values%v", arch, e.ID, seed, err, d)
					}
					decoded, err := c.Decode(b)
					if err != nil {
						t.Fatalf("%s %s %d decode %x: %v", arch, e.ID, seed, b, err)
					}
					re, err := c.Encode(*decoded)
					if err != nil || !bytes.Equal(re, b) {
						t.Fatalf("%s %s roundtrip %x/%x %v", arch, e.ID, b, re, err)
					}
					text := c.Format(decoded, 0x40000)
					bb, err := c.Assemble(text, 0x40000)
					if err != nil {
						t.Fatalf("%s %s text %q: %v", arch, e.ID, text, err)
					}
					found := false
					for _, x := range bb {
						if bytes.Equal(x, b) {
							found = true
						}
					}
					if !found {
						t.Fatalf("%s %s text %q has no exact %x", arch, e.ID, text, b)
					}
				}
			}
		}
	}
}
func TestGeneratedRust(t *testing.T) {
	out := os.Getenv("XTENSA_RUST_OUTPUT")
	if out == "" {
		t.Skip("set XTENSA_RUST_OUTPUT to retain generated crates")
	}
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		if err := c.GenerateRust(filepath.Join(out, arch)); err != nil {
			t.Fatal(err)
		}
	}
}

type oracleCase struct {
	ID, Architecture, Text, Bytes string
	Seed                          int
	Address                       uint64
	Values                        map[string]int64
}

func TestWriteOracleCases(t *testing.T) {
	out := os.Getenv("XTENSA_ARTIFACTS")
	if out == "" {
		t.Skip("set XTENSA_ARTIFACTS to generate full independent cases")
	}
	writeOracleCases(t, out)
}

func writeOracleCases(t *testing.T, out string) {
	t.Helper()
	var cases []oracleCase
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		for _, table := range []*codec.Catalog{c.Core, c.Slots} {
			for i := range table.Encodings {
				e := &table.Encodings[i]
				if e.AssemblyOnly {
					continue
				}
				for seed := 0; seed < 3; seed++ {
					d := Decoded{Format: "scalar", Instructions: []Instruction{sample(e, seed)}, Length: len(e.Mask)}
					if len(e.Mask) == 8 {
						d = bundle(c, e, seed)
					}
					b, err := c.Encode(d)
					if err != nil {
						t.Fatal(e.ID, err)
					}
					text := c.Format(&d, 0x40000)
					cases = append(cases, oracleCase{ID: e.ID, Architecture: arch, Text: text, Bytes: hex.EncodeToString(b), Seed: seed, Address: 0x40000, Values: d.Instructions[0].Values})
				}
			}
		}
	}
	data, _ := json.MarshalIndent(cases, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "cases.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("wrote", len(cases), "cases")
}
func TestActualLLVM(t *testing.T) {
	path := os.Getenv("XTENSA_SOURCE")
	if path == "" {
		t.Skip("set XTENSA_SOURCE to actual llvm-tblgen dump")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := Parse(f, "xtensa")
	if err != nil {
		t.Fatal(err)
	}
	c := b.(*Catalog)
	if len(c.Core.Encodings) != 611 || len(c.Slots.Encodings) != 184 {
		t.Fatal("source count changed")
	}
}
func TestRustConsumer(t *testing.T) {
	out := os.Getenv("XTENSA_RUST_OUTPUT")
	if out == "" {
		t.Skip("set XTENSA_RUST_OUTPUT")
	}
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		cmd := exec.Command("cargo", "test", "--lib")
		cmd.Dir = filepath.Join(out, arch)
		log, err := cmd.CombinedOutput()
		_ = os.WriteFile(filepath.Join(out, arch, "test.log"), log, 0644)
		if err != nil {
			t.Fatalf("%s %v\n%s", arch, err, log)
		}
		t.Log(arch, strings.TrimSpace(string(log)))
	}
}

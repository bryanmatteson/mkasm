package mips

import (
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/object"
)

func compressedCatalog(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	f, err := os.Open("testdata/llvm22-compressed.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	c, err := Parse(z, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c.InstructionCatalog()
}

func TestRealCompressedTableGenCorpus(t *testing.T) {
	for _, arch := range []string{"micromips32", "micromips32el", "micromips64", "micromips64el", "mips16", "mips16el", "mips16-64", "mips16-64el"} {
		t.Run(arch, func(t *testing.T) {
			actual, fixture := corpus(t, arch), compressedCatalog(t, arch)
			if len(actual.Unsupported) != 0 {
				t.Fatalf("unhandled actual source forms: %+v", actual.Unsupported)
			}
			if len(actual.Encodings) != len(fixture.Encodings) {
				t.Fatalf("actual %d versus fixture %d", len(actual.Encodings), len(fixture.Encodings))
			}
			for i, e := range actual.Encodings {
				a, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(fixture.Encodings[i])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(a, b) {
					t.Fatalf("full-source metadata differs from fixture: %s\nactual: %s\nfixture: %s", e.ID, a, b)
				}
			}
			t.Logf("actual LLVM dump matches fixture: %d forms", len(actual.Encodings))
		})
	}
}

func TestCompressedOperandBoundaries(t *testing.T) {
	c := compressedCatalog(t, "micromips32el")
	values := map[string]int64{"rt": 2, "addr_base": 3, "addr_offset": -1}
	b, err := c.Encode("LBU16_MM", values)
	if err != nil || !bytes.Equal(b, []byte{0x3f, 0x09}) {
		t.Fatalf("LBU16 sentinel: %x %v", b, err)
	}
	values["addr_offset"] = 15
	if _, err := c.Encode("LBU16_MM", values); err == nil {
		t.Fatal("LBU16 accepts reserved +15 offset")
	}
	if _, err := c.Encode("SB16_MM", values); err != nil {
		t.Fatal("SB16 unsigned +15:", err)
	}

	for _, tc := range []struct {
		id     string
		values map[string]int64
	}{
		{"BOVC_MMR6", map[string]int64{"rs": 8, "rt": 10, "offset": 4}},
		{"BEQC_MMR6", map[string]int64{"rs": 10, "rt": 8, "offset": 4}},
		{"BEQC_MMR6", map[string]int64{"rs": 0, "rt": 8, "offset": 4}},
		{"BGEC_MMR6", map[string]int64{"rs": 8, "rt": 8, "offset": 4}},
		{"BEQZALC_MMR6", map[string]int64{"rt": 0, "offset": 4}},
	} {
		if _, err := c.Encode(tc.id, tc.values); err == nil {
			t.Errorf("%s accepts another opcode's register partition", tc.id)
		}
	}
	features := []string{"InMicroMips", "HasMips32r6"}
	for _, text := range []string{"bovc $8, $10, 0x14", "bnvc $8, $10, 0x14", "beqc $8, $10, 0x14", "bnec $8, $10, 0x14"} {
		swapped := strings.NewReplacer("$8", "$10", "$10", "$8").Replace(text)
		a, err := c.AssembleWithFeatures(text, 0, features)
		if err != nil {
			t.Fatal(text, err)
		}
		b, err := c.AssembleWithFeatures(swapped, 0, features)
		if err != nil || len(a) != 1 || len(b) != 1 || !bytes.Equal(a[0], b[0]) {
			t.Fatalf("commuted %s: %x versus %x (%v)", text, a, b, err)
		}
		d, err := c.DecodeWithFeatures(a[0], features)
		if err != nil || d.Encoding.Mnemonic != strings.Fields(text)[0] {
			t.Fatalf("partition %s: %v %v", text, d, err)
		}
	}

	m := compressedCatalog(t, "mips16el")
	b, err = m.Encode("Jal16", map[string]int64{"imm26": 0x1234})
	if err != nil {
		t.Fatal(err)
	}
	d, err := m.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if target, ok := d.BranchTarget(0x8ffffffc); !ok || target != 0x90001234 {
		t.Fatalf("JAL region: %#x %v", target, ok)
	}
	if d.Encoding.FlowControl != "call" || d.Encoding.DelaySlots != 1 || d.Length != 4 {
		t.Fatalf("JAL physical metadata: %+v", d.Encoding)
	}
	if encoded, err := m.Assemble(d.Format(0x8ffffffc), 0x8ffffffc); err != nil || !containsBytes(encoded, b) {
		t.Fatalf("JAL region text: %x %v", encoded, err)
	}
	for _, e := range m.Encodings {
		if strings.HasPrefix(e.ID, "GNU_MIPS16_") && (e.Mnemonic == "ld" || e.Mnemonic == "sd" || e.Mnemonic == "lwu") && !has(e.Features, "HasMips3") {
			t.Errorf("missing I3 gate: %s", e.ID)
		}
	}
	if _, err := m.AssembleWithFeatures("ld $2, 8($3)", 0, []string{"InMips16Mode"}); err == nil {
		t.Fatal("MIPS16 I1 admits I3 load")
	}
	if _, err := m.AssembleWithFeatures("ld $2, 8($3)", 0, []string{"InMips16Mode", "HasMips3"}); err != nil {
		t.Fatal(err)
	}
}

func TestCompressedGNUBranchTargets(t *testing.T) {
	as := os.Getenv("MKASM_MIPS_AS")
	if as == "" {
		t.Skip("set MKASM_MIPS_AS to GNU MIPS assembler")
	}
	for _, arch := range []string{"micromips32", "micromips32el", "mips16", "mips16el", "mips16-64", "mips16-64el"} {
		t.Run(arch, func(t *testing.T) {
			c := compressedCatalog(t, arch)
			flag, texts := "-mmicromips", []string{"beqz $2, target", "bnez $3, target", "b target"}
			if strings.HasPrefix(arch, "mips16") {
				flag, texts = "-mips16", []string{"beqz $2, target", "b target", "jal 0x1234"}
			}
			endian := "-EB"
			if strings.HasSuffix(arch, "el") {
				endian = "-EL"
			}
			for _, text := range texts {
				binding := ""
				if flag == "-mmicromips" {
					binding = ".globl target\n"
				}
				o, err := object.Assemble(context.Background(), ".text\n.set noreorder\n"+binding+text+"\nnop\n.space 8\ntarget:\nnop\n", object.Options{Executable: as, Kind: "gnu", Arguments: []string{flag, endian, "-32", "-O0"}})
				if err != nil {
					t.Fatal(text, err)
				}
				var code []byte
				var target uint64
				for _, s := range o.Sections {
					if s.Name == ".text" {
						code = s.Data
					}
				}
				for _, s := range o.Symbols {
					if s.Name == "target" {
						target = s.Value &^ 1
					}
				}
				if strings.HasPrefix(text, "jal") {
					target = 0x1234
				} else if len(o.Relocations) != 0 {
					linker := os.Getenv("MIPS_LD")
					if linker == "" {
						linker = "ld.lld"
					}
					if _, err := exec.LookPath(linker); err != nil {
						t.Skip("set MIPS_LD to a linker supporting microMIPS")
					}
					dir := t.TempDir()
					input, output := filepath.Join(dir, "input.o"), filepath.Join(dir, "linked.elf")
					if err := os.WriteFile(input, o.Data, 0600); err != nil {
						t.Fatal(err)
					}
					if log, err := exec.Command(linker, "--image-base=0", "-Ttext=0", "-e", "0", input, "-o", output).CombinedOutput(); err != nil {
						t.Fatalf("link %s: %v\n%s", text, err, log)
					}
					f, err := elf.Open(output)
					if err != nil {
						t.Fatal(err)
					}
					code, err = f.Section(".text").Data()
					f.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				d, err := c.DecodeWithFeatures(code, []string{"InMicroMips", "NotMips32r6", "RelocPIC", "InMips16Mode"})
				if err != nil {
					t.Fatalf("%s %x: %v", text, code, err)
				}
				if got, ok := d.BranchTarget(0); !ok || got != target {
					t.Fatalf("%s %x %s: target %#x, GNU %#x", text, code[:d.Length], d.Encoding.ID, got, target)
				}
				spell := d.Format(0)
				encoded, err := c.Assemble(spell, 0)
				found := false
				for _, b := range encoded {
					found = found || bytes.Equal(b, code[:d.Length])
				}
				if err != nil || !found {
					t.Fatalf("%s: %s %x %v", text, spell, encoded, err)
				}
				t.Logf("%s: %s %x => %#x", arch, text, code[:d.Length], target)
			}
		})
	}
}

package z80

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentGNU(t *testing.T) {
	assembler := os.Getenv("MKASM_Z80_AS")
	if assembler == "" {
		t.Skip("set MKASM_Z80_AS to GNU z80-elf assembler")
	}
	artifact := os.Getenv("MKASM_Z80_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	if err := os.MkdirAll(artifact, 0755); err != nil {
		t.Fatal(err)
	}
	cases := oracleCases(t)
	for _, arch := range []string{"z80", "z180"} {
		t.Run(arch, func(t *testing.T) {
			var src strings.Builder
			var selected []oracleCase
			for _, c := range cases {
				if c.architecture != arch {
					continue
				}
				if strings.HasPrefix(c.id, "prefix") {
					continue
				}
				if arch == "z180" && c.id == "ed30" {
					t.Log("GNU lacks the Ghidra/MAME flag-only IN0 form ED30")
					continue
				}
				selected = append(selected, c)
				text := c.text
				d, _ := c.catalog.Decode(c.bytes)
				for _, o := range d.Encoding.Operands {
					if o.Relative {
						target, _ := d.BranchTarget(0x1000)
						text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", target), fmt.Sprintf(".+%d", int64(target)-0x1000))
					}
				}
				fmt.Fprintf(&src, ".section .text.case%d,\"ax\"\n.org 0x1000\n%s\n", len(selected)-1, text)
			}
			path := filepath.Join(artifact, arch+"-gnu-corpus.s")
			if err := os.WriteFile(path, []byte(src.String()), 0644); err != nil {
				t.Fatal(err)
			}
			object := strings.TrimSuffix(path, ".s") + ".o"
			cpu := arch
			if arch == "z80" {
				cpu += "+full"
			}
			out, err := exec.Command(assembler, "-march="+cpu, "-o", object, path).CombinedOutput()
			os.WriteFile(filepath.Join(artifact, arch+"-gnu.log"), out, 0644)
			if err != nil {
				t.Fatalf("assembler: %v\n%s", err, out)
			}
			f, err := elf.Open(object)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			for i, c := range selected {
				s := f.Section(fmt.Sprintf(".text.case%d", i))
				if s == nil {
					t.Fatalf("section %d missing", i)
				}
				data, err := s.Data()
				if err != nil {
					t.Fatal(err)
				}
				if len(data) < 0x1000 {
					t.Fatal("short section")
				}
				b := data[0x1000:]
				all, err := c.catalog.Assemble(c.text, 0x1000)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, v := range all {
					found = found || bytes.Equal(v, b)
				}
				if !found {
					t.Errorf("%s %q GNU%x ours%x", c.id, c.text, b, all)
				}
			}
			t.Logf("GNU assembler verified %d source forms", len(selected))
		})
	}
	// A real loop with resolved labels exercises length accounting and targets.
	routine := `.section .text,"ax"
.org 0x1000
ld ix,0x2000
ld de,0x3000
ld b,4
loop:
ld a,(ix+0)
ld (de),a
inc ix
inc de
djnz loop
ret
`
	path := filepath.Join(artifact, "copy-loop.s")
	os.WriteFile(path, []byte(routine), 0644)
	object := filepath.Join(artifact, "copy-loop.o")
	out, err := exec.Command(assembler, "-march=z80", "-o", object, path).CombinedOutput()
	if err != nil {
		t.Fatalf("routine %v %s", err, out)
	}
	f, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := f.Section(".text").Data()
	if err != nil {
		t.Fatal(err)
	}
	data = data[0x1000:]
	want := []byte{0xdd, 0x21, 0, 0x20, 0x11, 0, 0x30, 0x06, 4, 0xdd, 0x7e, 0, 0x12, 0xdd, 0x23, 0x13, 0x10, 0xf7, 0xc9}
	if !bytes.Equal(data, want) {
		t.Fatalf("GNU routine %x want%x", data, want)
	}
	c, err := Parse(nil, "z80")
	if err != nil {
		t.Fatal(err)
	}
	for pos := 0; pos < len(data); {
		d, err := c.Decode(data[pos:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := d.Reencode()
		if err != nil || !bytes.Equal(raw, data[pos:pos+d.Length]) {
			t.Fatal("routine exact reencode", err)
		}
		all, err := c.Assemble(d.Format(uint64(0x1000+pos)), uint64(0x1000+pos))
		if err != nil || !bytes.Equal(all[0], raw) {
			t.Fatal("routine text roundtrip", err)
		}
		if d.Encoding.Mnemonic == "djnz" {
			target, ok := d.BranchTarget(uint64(0x1000 + pos))
			if !ok || target != 0x1009 {
				t.Fatalf("loop target%x %v", target, ok)
			}
		}
		pos += d.Length
	}
}

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

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestVariantCorpus(t *testing.T) {
	for arch, count := range map[string]int{"ez80": 6705, "ez80-adl": 6705, "z80n": 1279, "r800": 1255, "gbz80": 500} {
		t.Run(arch, func(t *testing.T) {
			c, e := ParseVariant(nil, arch)
			if e != nil {
				t.Fatal(e)
			}
			if len(c.Encodings) != count {
				t.Fatalf("%d source forms, want %d", len(c.Encodings), count)
			}
			for i := range c.Encodings {
				form := &c.Encodings[i]
				for _, seed := range []int64{0, 1, -1} {
					values := map[string]int64{}
					for _, o := range form.Operands {
						v := seed
						if !o.Signed && v < 0 {
							v = (1 << uint(o.Width())) - 1
						}
						values[o.Name] = v
					}
					raw, e := codec.Encode(form, values)
					if e != nil {
						t.Fatalf("%s %v", form.ID, e)
					}
					d, e := c.Decode(raw)
					if e != nil {
						t.Fatalf("%s %x %v", form.ID, raw, e)
					}
					back, e := codec.Encode(d.Encoding, d.Values)
					if e != nil || !bytes.Equal(back, raw) {
						t.Fatalf("%s %x %x %v", form.ID, raw, back, e)
					}
					all, e := c.Assemble(d.Format(0x1000), 0x1000)
					found := false
					for _, b := range all {
						found = found || bytes.Equal(b, raw)
					}
					if e != nil || !found {
						t.Fatalf("%s %q %x %v", form.ID, d.Format(0x1000), raw, e)
					}
				}
			}
		})
	}
}

func TestVariantNegativeIndexSyntax(t *testing.T) {
	for _, arch := range []string{"ez80", "ez80-adl", "z80n", "r800"} {
		c, e := ParseVariant(nil, arch)
		if e != nil {
			t.Fatal(e)
		}
		for _, reg := range []string{"ix", "iy"} {
			all, e := c.Assemble("ld a,("+reg+"-5)", 0x1000)
			prefix := byte(0xdd)
			if reg == "iy" {
				prefix = 0xfd
			}
			found := false
			for _, b := range all {
				found = found || bytes.Equal(b, []byte{prefix, 0x7e, 0xfb})
			}
			if e != nil || !found {
				t.Fatalf("%s %s: %x %v", arch, reg, all, e)
			}
		}
	}
}

// The assembler chooses a canonical opcode for aliases. Compare its bytes with
// the complete candidate set, while the corpus test preserves every alias.
func TestVariantGNUOracle(t *testing.T) {
	as := os.Getenv("MKASM_Z80_AS")
	if as == "" {
		t.Skip("set MKASM_Z80_AS")
	}
	for _, arch := range []string{"ez80", "ez80-adl", "z80n", "r800", "gbz80"} {
		t.Run(arch, func(t *testing.T) {
			c, e := ParseVariant(nil, arch)
			if e != nil {
				t.Fatal(e)
			}
			var src strings.Builder
			var texts []string
			for i := range c.Encodings {
				form := &c.Encodings[i]
				raw, e := codec.Encode(form, sample(form))
				if e != nil {
					t.Fatal(e)
				}
				d := codec.Decoded{Encoding: form, Values: sample(form), Length: len(raw)}
				text := strings.ReplaceAll(d.Format(0x1000), "+-", "-")
				assemblerText := text
				if arch == "ez80" && (strings.Contains(form.Syntax, "mb,") || strings.Contains(form.Syntax, ",mb") || strings.HasSuffix(form.Syntax, "i,hl") || strings.HasSuffix(form.Syntax, "hl,i")) {
					assemblerText = ".assume adl=1\n" + text + "\n.assume adl=0"
				}
				if arch == "gbz80" && text == "stop" {
					assemblerText += "\n.byte 0"
				}
				for _, o := range form.Operands {
					if o.Relative {
						target, _ := d.BranchTarget(0x1000)
						assemblerText = strings.ReplaceAll(assemblerText, fmt.Sprintf("0x%x", target), fmt.Sprintf("mkasm_case%d+%d", len(texts), int64(target)-0x1000))
					}
				}
				fmt.Fprintf(&src, ".section .text.case%d,\"ax\"\n.org 0x1000\nmkasm_case%d:\n%s\n", len(texts), len(texts), assemblerText)
				texts = append(texts, text)
			}
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input.s"), filepath.Join(dir, "output.o")
			if e = os.WriteFile(input, []byte(src.String()), 0600); e != nil {
				t.Fatal(e)
			}
			cpu := arch
			if arch == "ez80-adl" {
				cpu = "ez80+adl"
			}
			if arch != "gbz80" {
				cpu += "+full"
			}
			log, e := exec.Command(as, "-march="+cpu, "-o", output, input).CombinedOutput()
			if e != nil {
				t.Fatalf("%v\n%s", e, log)
			}
			f, e := elf.Open(output)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			for i, text := range texts {
				s := f.Section(fmt.Sprintf(".text.case%d", i))
				if s == nil {
					t.Fatal("missing oracle section")
				}
				b, e := s.Data()
				if e != nil || len(b) < 0x1000 {
					t.Fatal("short oracle section", e)
				}
				b = b[0x1000:]
				var all [][]byte
				// Only index syntax needs a '+' before a negative displacement.
				all, e = c.Assemble(strings.NewReplacer("ix-", "ix+-", "iy-", "iy+-").Replace(text), 0x1000)
				found := false
				for _, v := range all {
					found = found || bytes.Equal(v, b)
				}
				if e != nil || !found {
					t.Errorf("%s %q GNU %x candidates %x %v", c.Encodings[i].ID, text, b, all, e)
					if t.Failed() {
						return
					}
				}
			}
			t.Logf("GNU verified %d physical source forms", len(texts))
		})
	}
}

package m68k

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The GNU assembler and disassembler are built from pristine binutils 2.44,
// independently of this interpreter. Enable with MKASM_M68K_BINUTILS.
func TestGNUCorpus(t *testing.T) {
	root := os.Getenv("MKASM_M68K_BINUTILS")
	if root == "" {
		t.Skip("set MKASM_M68K_BINUTILS to a target-only binutils build")
	}
	c := corpus(t)
	type testCase struct {
		o *Opcode
		b []byte
	}
	groups := map[string][]testCase{}
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		cpu := ""
		args := ""
		for _, p := range []string{"68000", "68010", "68020", "68030", "68040", "68060", "68881", "68851", "cpu32", "fido"} {
			if o.Features&Profiles[p] != 0 {
				cpu = p
				args = "-march=" + p
				break
			}
		}
		if cpu == "68881" {
			args = "-march=68020 -m68881"
		}
		if cpu == "68851" {
			args = "-march=68020 -m68851"
		}
		if cpu == "fido" {
			args = "-march=fidoa"
		}
		c.Architecture = "m68k"
		if cpu == "" {
			c.Architecture = "coldfire"
			cpu = "coldfire-all"
			switch {
			case o.Features&16384 != 0:
				args = "-march=isaa"
			case o.Features&32768 != 0:
				args = "-march=isaaplus"
			case o.Features&65536 != 0:
				args = "-march=isab"
			case o.Features&131072 != 0:
				args = "-march=isac"
			case o.Features&1024 != 0:
				args = "-march=isaa -mmac"
			case o.Features&2048 != 0:
				args = "-march=isaa -memac"
			case o.Features&4096 != 0:
				args = "-march=cfv4e"
			case o.Features&8192 != 0:
				args = "-march=isaa -mdiv"
			case o.Features&262144 != 0:
				args = "-march=isab -musp"
			default:
				t.Fatal(o.ID)
			}
		}
		c.CPU = cpu
		v, e := sampleOpcode(c, o)
		if e != nil {
			t.Fatal(e)
		}
		b, e := c.Encode(o.ID, v)
		if e != nil {
			t.Fatal(e)
		}
		groups[args] = append(groups[args], testCase{o, b})
	}
	dir := t.TempDir()
	checked := 0
	known := 0
	for flags, cases := range groups {
		var s strings.Builder
		s.WriteString(".text\n")
		for n, x := range cases {
			fmt.Fprintf(&s, "sample_%d:\n.byte ", n)
			for j, b := range x.b {
				if j > 0 {
					s.WriteByte(',')
				}
				fmt.Fprintf(&s, "0x%02x", b)
			}
			s.WriteByte('\n')
		}
		src := filepath.Join(dir, "corpus.s")
		obj := filepath.Join(dir, "corpus.o")
		os.WriteFile(src, []byte(s.String()), 0644)
		args := append(strings.Fields(flags), "-o", obj, src)
		if out, e := exec.Command(filepath.Join(root, "gas/as-new"), args...).CombinedOutput(); e != nil {
			t.Fatalf("as %s: %v %s", flags, e, out)
		}
		out, e := exec.Command(filepath.Join(root, "binutils/objdump"), "-d", "-z", "--insn-width=24", "-m", gnuArch(flags), obj).CombinedOutput()
		if e != nil {
			t.Fatal(e, string(out))
		}
		current := -1
		seen := map[int]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			if i := strings.Index(line, "<sample_"); i >= 0 && strings.HasSuffix(line, ">:") {
				n, err := strconv.Atoi(strings.TrimSuffix(line[i+8:], ">:"))
				if err != nil {
					t.Fatal(line)
				}
				current = n
				continue
			}
			if current < 0 || seen[current] {
				continue
			}
			cols := strings.Split(line, "\t")
			if len(cols) < 3 {
				continue
			}
			x := cases[current]
			seen[current] = true
			size := len(strings.ReplaceAll(strings.TrimSpace(cols[1]), " ", "")) / 2
			text := strings.Join(cols[2:], " ")
			if size != len(x.b) || strings.Contains(text, ".short") || strings.Contains(text, ".word") {
				if x.o.Mnemonic == "swbeg" || x.o.Mnemonic == "swbegl" || x.o.Correction != "" || x.o.Args == "#lg]" || strings.HasPrefix(x.o.Mnemonic, "ftrap") || strings.HasPrefix(x.o.Mnemonic, "ptrap") {
					known++
					continue
				}
				t.Errorf("GNU %s %s bytes %x: size%d wanted%d: %s", flags, x.o.ID, x.b, size, len(x.b), text)
			} else {
				checked++
			}
		}
		if len(seen) != len(cases) {
			for n, x := range cases {
				if !seen[n] {
					if x.o.Mnemonic == "rtm" {
						known++
						continue
					}
					t.Errorf("GNU %s missing sample_%d %s %x", flags, n, x.o.ID, x.b)
				}
			}

		}
	}
	t.Logf("GNU decoded %d complete source templates; %d explicit upstream table/pseudo exceptions", checked, known)
}

type gnuVector struct {
	CPU      string
	Assembly string
	Text     string
	Hex      string
}

func TestGNUAssemblerVectors(t *testing.T) {
	b, e := os.ReadFile("testdata/gnu-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []gnuVector
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	c := corpus(t)
	root := os.Getenv("MKASM_M68K_BINUTILS")
	dir := t.TempDir()
	for _, x := range cases {
		c.CPU = x.CPU
		c.Architecture = "m68k"
		if strings.Contains(x.CPU, "isa") || x.CPU == "coldfire-all" {
			c.Architecture = "coldfire"
		}
		expected, e := hex.DecodeString(x.Hex)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := c.Assemble(x.Text)
		if e != nil || !bytes.Equal(actual, expected) {
			t.Errorf("%s: got%x expected%x %v", x.Assembly, actual, expected, e)
			continue
		}
		i, e := c.Decode(expected)
		if e != nil || i.Length != len(expected) {
			t.Errorf("%s: decode %v", x.Assembly, e)
		}
		if root != "" {
			src := filepath.Join(dir, "case.s")
			obj := filepath.Join(dir, "case.o")
			raw := filepath.Join(dir, "case.bin")
			os.WriteFile(src, []byte(".text\n"+x.Assembly+"\n"), 0644)
			flags := gnuFlags(x.CPU)
			args := append(strings.Fields(flags), "-o", obj, src)
			if out, e := exec.Command(filepath.Join(root, "gas/as-new"), args...).CombinedOutput(); e != nil {
				t.Errorf("%s: %v %s", x.Assembly, e, out)
				continue
			}
			if out, e := exec.Command(filepath.Join(root, "binutils/objcopy"), "-O", "binary", "-j", ".text", obj, raw).CombinedOutput(); e != nil {
				t.Fatal(e, string(out))
			}
			actual, e := os.ReadFile(raw)
			if e != nil || !bytes.Equal(actual, expected) {
				t.Errorf("GNU %s: got%x expected%x %v", x.Assembly, actual, expected, e)
			}
		}
	}
}
func gnuFlags(cpu string) string {
	switch cpu {
	case "68851":
		return "-march=68020 -m68851"
	case "68020+68881":
		return "-march=68020 -m68881"
	case "68030+68881":
		return "-march=68030 -m68881"
	case "isa-a":
		return "-march=isaa"
	case "isa-a+":
		return "-march=isaaplus"
	case "isa-b":
		return "-march=isab"
	case "isa-c":
		return "-march=isac"
	case "coldfire-all":
		return "-march=cfv4e -memac -mdiv -musp"
	}
	return "-march=" + cpu
}

func gnuArch(flags string) string {
	arch := strings.TrimPrefix(strings.Fields(flags)[0], "-march=")
	switch arch {
	case "isaa":
		arch = "isa-a"
	case "isaaplus":
		arch = "isa-aplus"
	case "isab":
		arch = "isa-b"
	case "isac":
		arch = "isa-c"
	case "fidoa":
		arch = "fido"
	}
	if strings.Contains(flags, "-memac") {
		arch += ":emac"
	} else if strings.Contains(flags, "-mmac") {
		arch += ":mac"
	}
	return "m68k:" + arch
}

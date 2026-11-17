package msp430

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

func load(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	p := os.Getenv("MKASM_MSP430_TABLEGEN_JSON")
	if p == "" {
		p = "data/llvm22-msp430.json"
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestCorpus(t *testing.T) {
	for _, arch := range []string{"msp430", "msp430x"} {
		t.Run(arch, func(t *testing.T) {
			c := load(t, arch)
			t.Logf("encodings=%d unsupported=%v", len(c.Encodings), c.Unsupported)
			for _, e := range c.Encodings {
				if strings.Contains(e.Syntax, "$") {
					t.Errorf("unresolved syntax: %s", e.Syntax)
				}
			}
		})
	}
}

func TestIndependentGNUCorpus(t *testing.T) {
	as := os.Getenv("MSP430_AS")
	if as == "" {
		t.Skip("set MSP430_AS to GNU msp430 assembler")
	}
	ld := os.Getenv("MSP430_LD")
	if ld == "" {
		t.Fatal("set MSP430_LD to matching GNU linker")
	}
	arch := os.Getenv("MKASM_MSP430_AUDIT_ARCH")
	if arch == "" {
		arch = "msp430"
	}
	c := load(t, arch)
	dir := t.TempDir()
	var source strings.Builder
	source.WriteString(".text\n.global case_0\n")
	var expected [][]byte
	var encodings []codec.Encoding
	for _, e := range c.Encodings {
		values := sampleValues(e)
		b, err := codec.Encode(&e, values)
		if err != nil {
			t.Fatalf("sample %s: %v", e.ID, err)
		}
		d := codec.Decoded{Encoding: &e, Values: values, Length: len(b)}
		text := gnuSpelling(e, d.Format(0))
		for _, o := range e.Operands {
			if o.Relative {
				delta := o.PCBias + values[o.Name]
				target := uint64(delta)
				wrap := o.PCWrapBits
				if o.PCLowWrapBits > 0 && uint64(o.PCBias) < uint64(1)<<o.PCLowWrapBits {
					wrap = o.PCLowWrapBits
				}
				if wrap > 0 && wrap < 64 {
					target &= (uint64(1) << wrap) - 1
				}
				oracleDelta := delta
				// GNU 2.44 extended relocations are based at the opcode/prefix,
				// without the hardware PC bias of the addressed extension word.
				if o.PCWrapBits == 20 && strings.HasPrefix(e.ID, "X_") {
					oracleDelta -= o.PCBias
				}
				replacement := fmt.Sprintf(".%+d", oracleDelta)
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", target), replacement)
			}
		}
		if arch == "msp430x" && (strings.HasPrefix(text, "rlax") || strings.HasPrefix(text, "rlcx")) {
			for _, o := range e.Operands {
				if o.Implicit && o.BiasOperand != "" {
					parts := strings.SplitN(text, " ", 2)
					name := strings.Replace(parts[0], "rla", "add", 1)
					name = strings.Replace(name, "rlc", "addc", 1)
					text = name + " " + parts[1] + "," + parts[1] + "-2"
				}
			}
		}
		// GNU's statement separator for repetition is a literal open brace.
		text = strings.ReplaceAll(text, "{{", "{")
		fmt.Fprintf(&source, "case_%d: ; %s\n%s\ncase_%d_end:\n", len(expected), e.ID, text, len(expected))
		expected = append(expected, b)
		encodings = append(encodings, e)
	}
	asm := filepath.Join(dir, "corpus.s")
	obj := filepath.Join(dir, "corpus.o")
	binary := filepath.Join(dir, "corpus.elf")
	script := filepath.Join(dir, "layout.ld")
	if err := os.WriteFile(asm, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("SECTIONS { . = 0; .text : { *(.text) } }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Use 430X for the classic subset too: GNU unconditionally rewrites
	// classic PUSH #4/#8 to work around CPU4. LLVM retains the short encoding.
	cpu := "430x"
	result, err := exec.Command(as, "-mcpu="+cpu, "-mN", "-mY", "-mU", "-no-pad-sections", "-o", obj, asm).CombinedOutput()
	if err != nil {
		t.Fatalf("GNU assembler: %v\n%s", err, result)
	}
	result, err = exec.Command(ld, "-m", "msp430X", "--no-relax", "-T", script, "-o", binary, obj).CombinedOutput()
	if err != nil {
		t.Fatalf("GNU linker: %v\n%s", err, result)
	}
	f, err := elf.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := f.Section(".text").Data()
	if err != nil {
		t.Fatal(err)
	}
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	positions := map[string]uint64{}
	for _, s := range syms {
		positions[s.Name] = s.Value
	}
	for i, want := range expected {
		start, end := positions[fmt.Sprintf("case_%d", i)], positions[fmt.Sprintf("case_%d_end", i)]
		if end > uint64(len(data)) || start > end {
			t.Fatalf("GNU framing %d..%d out of%d", start, end, len(data))
		}
		got := data[start:end]
		if !bytes.Equal(got, want) {
			t.Errorf("%s %q: got %x GNU %x", encodings[i].ID, encodings[i].Syntax, want, got)
		}
	}
	t.Logf("independent GNU %s machine forms=%d bytes=%d", arch, len(expected), len(data))
}

// GNU chooses different valid opcodes for these aliases. Spell the originating
// instruction explicitly so the byte comparison checks this encoding variant.
func gnuSpelling(e codec.Encoding, text string) string {
	if strings.HasPrefix(text, "popx") {
		parts := strings.SplitN(text, " ", 2)
		return strings.Replace(parts[0], "popx", "movx", 1) + " @r1+," + parts[1]
	}
	for _, pair := range [][2]string{{"clra ", "mova #0, "}, {"incda ", "adda #2, "}, {"decda ", "suba #2, "}, {"tsta ", "cmpa #0, "}} {
		if strings.HasPrefix(text, pair[0]) {
			return strings.Replace(text, pair[0], pair[1], 1)
		}
	}
	if len(e.Value) < 4 || !strings.HasPrefix(e.ID, "X_") || strings.HasPrefix(text, "rpt ") || strings.Contains(text, ",") {
		return text
	}
	op := e.Value[3] >> 4
	mnemonics := []string{"", "", "", "", "movx", "addx", "addcx", "subcx", "subx", "cmpx", "daddx", "bitx", "bicx", "bisx", "xorx", "andx"}
	if op < 4 || e.Mask[3]&15 != 15 {
		return text
	}
	code := int(e.Value[3]&15) | int((e.Value[2]>>4)&3)<<4
	constants := map[int]int{3: 0, 0x13: 1, 0x23: 2, 0x22: 4, 0x32: 8, 0x33: -1}
	value, ok := constants[code]
	if !ok {
		return text
	}
	size := ".w"
	if strings.Contains(e.Mnemonic, ".") {
		size = e.Mnemonic[strings.LastIndex(e.Mnemonic, "."):]
	}
	if pos := strings.Index(text, " "); pos >= 0 {
		return fmt.Sprintf("%s%s #%d,%s", mnemonics[op], size, value, text[pos+1:])
	}
	return text
}

func sampleValues(e codec.Encoding) map[string]int64 {
	values := map[string]int64{}
	for i, o := range e.Operands {
		v := int64(17)
		if o.Kind == "immediate" && o.Width() == 20 {
			v = 0x12345
		}
		if o.Kind == "register" {
			v = int64(4 + i%6)
		}
		if o.Name == "count" {
			v = 2
		}
		if o.Name == "repeat" {
			v = 3
			if o.Kind == "register" {
				v = 6
			}
		}
		if o.Kind == "address" {
			v = 0x1234
			if o.Width() == 20 {
				v = 0x12345
			}
		}
		if o.Kind == "displacement" {
			v = 20
			if o.Width() == 20 {
				v = 0x12344
			}
		}
		if o.Implicit {
			v = 0
		}
		values[o.Name] = v
	}
	for _, con := range e.Constraints {
		if con.Kind == "sum_le" && con.Limit < 0 && con.Right == "" {
			values[con.Left] = con.Limit
		}
	}
	return values
}

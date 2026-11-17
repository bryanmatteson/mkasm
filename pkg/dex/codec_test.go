package dex

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func load(t *testing.T) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/dex_instruction_list.h")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, "dex")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func sample(d Definition) *Instruction {
	in := &Instruction{Opcode: d.Opcode, Values: map[string]int64{}}
	for _, f := range d.Fields {
		v := int64(5)
		switch f.Kind {
		case "register":
			switch f.Name {
			case "a":
				v = 3
			case "b":
				v = 5
			case "c":
				v = 7
			}
		case "literal":
			v = -7
			if f.Shift > 0 {
				v <<= uint(f.Shift)
			}
		case "target":
			v = -3
		}
		in.Values[f.Name] = v
	}
	switch d.Format {
	case "35c", "45cc":
		in.Registers = []uint16{1, 3, 5, 7, 9}
	case "3rc", "4rcc":
		in.Range = &RegisterRange{257, 6}
	}
	if d.Opcode >= 256 {
		in.Payload = &Payload{}
		switch d.Opcode {
		case 0x100:
			in.Payload.FirstKey = -5
			in.Payload.Targets = []int32{-3, -1, 1}
		case 0x200:
			in.Payload.Keys = []int32{-5, -2, 1}
			in.Payload.Targets = []int32{-3, -1, 1}
		case 0x300:
			in.Payload.ElementWidth = 1
			in.Payload.Data = []byte{1, 2, 3}
		}
	}
	return in
}
func TestCorpus(t *testing.T) {
	c := load(t)
	if len(c.Instructions) != 259 {
		t.Fatal(len(c.Instructions))
	}
	reserved := 0
	formats := map[string]bool{}
	for _, d := range c.Instructions {
		if d.Reserved {
			reserved++
		}
		formats[d.Format] = true
	}
	t.Logf("%d defined, %d reserved, %d formats including payloads", 259-reserved, reserved, len(formats))
	if len(c.Templates()) != 259-reserved {
		t.Fatal("templates")
	}
}
func TestEveryOpcode(t *testing.T) {
	c := load(t)
	for _, d := range c.Instructions {
		t.Run(d.Mnemonic, func(t *testing.T) {
			in := sample(d)
			b, e := c.Encode(in, 100)
			if d.Reserved {
				if !errors.Is(e, ErrReserved) {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := c.Decode(b, 100)
			if e != nil {
				t.Fatal(e)
			}
			back, e := c.Encode(got, 100)
			if e != nil || !bytes.Equal(b, back) {
				t.Fatalf("roundtrip %x %v", back, e)
			}
			text := c.Format(got)
			back, e = c.Assemble(text, 100)
			if e != nil || !bytes.Equal(back, b) {
				t.Fatalf("text %q %x %v", text, back, e)
			}
			for n := 0; n < len(b); n++ {
				if _, e = c.Decode(b[:n], 100); !errors.Is(e, ErrTruncated) {
					t.Fatalf("prefix%d %v", n, e)
				}
			}
		})
	}
}
func TestDexlibOracle(t *testing.T) {
	jar := os.Getenv("MKASM_SMALI_JAR")
	if jar == "" {
		t.Skip("set MKASM_SMALI_JAR to smali 3.0.9 fat jar")
	}
	c := load(t)
	dir := t.TempDir()
	if e := exec.Command("javac", "-cp", jar, "-d", dir, "testdata/Oracle.java").Run(); e != nil {
		t.Fatal(e)
	}
	var input strings.Builder
	var expected [][]byte
	var names []string
	for _, d := range c.Instructions {
		if d.Reserved {
			continue
		}
		in := sample(d)
		form := d.Format
		if d.Opcode == 256 {
			form = "packed"
		}
		if d.Opcode == 512 {
			form = "sparse"
		}
		if d.Opcode == 768 {
			form = "array1"
		}
		for _, w := range []int{1, 2, 4, 8} {
			if d.Opcode != 768 && w != 1 {
				continue
			}
			if d.Opcode == 768 {
				form = fmt.Sprintf("array%d", w)
				in.Payload.ElementWidth = uint16(w)
				in.Payload.Data = make([]byte, 3*w)
				for i := 0; i < 3; i++ {
					in.Payload.Data[i*w] = byte(i + 1)
				}
			}
			b, e := c.Encode(in, 0)
			if e != nil {
				t.Fatal(e)
			}
			fmt.Fprintf(&input, "%d\t%s\t%s\n", d.Opcode, form, d.Mnemonic)
			expected = append(expected, b)
			names = append(names, d.Mnemonic+"/"+form)
		}
	}
	cmd := exec.Command("java", "-cp", dir+string(os.PathListSeparator)+jar, "com.android.tools.smali.dexlib2.writer.Oracle")
	cmd.Stdin = strings.NewReader(input.String())
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v\n%s", e, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(expected) {
		t.Fatalf("oracle returned %d rows for %d", len(lines), len(expected))
	}
	for i, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatal(line)
		}
		b, e := hex.DecodeString(parts[2])
		if e != nil || !bytes.Equal(b, expected[i]) {
			t.Errorf("%s dexlib %x codec %x %v", names[i], b, expected[i], e)
		}
	}
	t.Logf("%d independent dexlib2 byte comparisons", len(lines))
	if p := os.Getenv("MKASM_DEX_ARTIFACT_DIR"); p != "" {
		os.MkdirAll(p, 0755)
		os.WriteFile(filepath.Join(p, "dexlib-oracle.tsv"), out, 0644)
	}
}
func TestInvalid(t *testing.T) {
	c := load(t)
	for _, b := range [][]byte{{0, 4}, {0x0e, 1}, {0x03, 1, 0, 0, 0, 0}, {0x6e, 0x60, 0, 0, 0, 0}, {0x6e, 0, 0, 0, 1, 0}, {0x28, 0}, {0x32, 0, 0, 0}, {0x74, 2, 0, 0, 0xff, 0xff}, {0, 3, 3, 0, 0, 0, 0, 0}, {0, 3, 1, 0, 1, 0, 0, 0, 5, 1}} {
		if _, e := c.Decode(b, 0); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	for _, text := range []string{"move v16, v0", "const/4 v0, #8", "const/high16 v0, #1", "invoke-static {v16}, method@0", "invoke-static/range {v65535 .. v65536}, method@0", "if-eqz v0, 0", "goto 0"} {
		if _, e := c.Assemble(text, 0); e == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	for _, op := range []uint16{0xfa, 0xfc, 0xfe, 0xff} {
		in := sample(*c.definition(op))
		if _, e := c.EncodeVersion(in, 0, 35); !errors.Is(e, ErrVersion) {
			t.Fatal(op, e)
		}
	}
	if _, e := c.EncodeVersion(sample(*c.definition(0xfe)), 0, 38); !errors.Is(e, ErrVersion) {
		t.Fatal(e)
	}
	for _, v := range []int{34, 36, 42} {
		if _, e := c.DecodeVersion([]byte{0, 0}, 0, v); e == nil {
			t.Fatal(v)
		}
	}
	for _, input := range []string{"", "{}"} {
		if _, e := Parse(strings.NewReader(input), "dex"); e == nil {
			t.Fatal("bad input")
		}
	}
}
func TestRealDEX(t *testing.T) {
	c := load(t)
	data, e := os.ReadFile("testdata/example.dex")
	if e != nil {
		t.Fatal(e)
	}
	m, e := c.DecodeDEX(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Methods) != 5 {
		t.Fatal(len(m.Methods))
	}
	for _, method := range m.Methods {
		ci := method.Code
		back, e := c.EncodeCodeItem(ci, m.Version)
		if e != nil || !bytes.Equal(back, data[method.CodeOffset:uint32(int(method.CodeOffset)+ci.Length)]) {
			t.Fatalf("method %d code_item reencode differs %v", method.Index, e)
		}
		for _, in := range ci.Instructions {
			b, e := c.AssembleVersion(c.Format(in), in.Offset, m.Version)
			if e != nil {
				t.Fatal(e)
			}
			back, e := c.EncodeVersion(in, in.Offset, m.Version)
			if e != nil || !bytes.Equal(b, back) {
				t.Fatal("real DEX text roundtrip", e)
			}
		}
	}
	t.Logf("decoded %d real smali DEX methods in version %03d", len(m.Methods), m.Version)
}
func TestSmaliWorkflow(t *testing.T) {
	jar := os.Getenv("MKASM_SMALI_JAR")
	if jar == "" {
		t.Skip("set MKASM_SMALI_JAR")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "example.dex")
	cmd := exec.Command("java", "-jar", jar, "assemble", "--api", "28", "-o", path, "testdata/Example.smali")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%v %s", e, b)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	m, e := load(t).DecodeDEX(b)
	if e != nil || len(m.Methods) != 5 {
		t.Fatalf("%v %+v", e, m)
	}
	retained, e := os.ReadFile("testdata/example.dex")
	if e != nil || !bytes.Equal(b, retained) {
		t.Fatal("fresh smali output differs from retained complete DEX")
	}
	if p := os.Getenv("MKASM_BAKSMALI_JAR"); p != "" {
		out := filepath.Join(dir, "disassembled")
		cmd = exec.Command("java", "-jar", p, "disassemble", path, "-o", out)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%v %s", e, b)
		}
		cmd = exec.Command("java", "-jar", jar, "assemble", "--api", "28", "-o", filepath.Join(dir, "back.dex"), out)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%v %s", e, b)
		}
		back, e := os.ReadFile(filepath.Join(dir, "back.dex"))
		if e != nil {
			t.Fatal(e)
		}
		round, e := load(t).DecodeDEX(back)
		if e != nil || len(round.Methods) != 5 {
			t.Fatal("baksmali/smali module roundtrip", e)
		}
		for j, method := range m.Methods {
			before, err := load(t).EncodeCodeItem(method.Code, m.Version)
			if err != nil {
				t.Fatal(err)
			}
			after, err := load(t).EncodeCodeItem(round.Methods[j].Code, round.Version)
			if err != nil || method.Index != round.Methods[j].Index || !bytes.Equal(before, after) {
				t.Fatalf("baksmali/smali changed method %d code_item: %v", method.Index, err)
			}
		}
	}
}
func TestRetainedIndependentOracle(t *testing.T) {
	c := load(t)
	data, e := os.ReadFile("testdata/dexlib-oracle.tsv")
	if e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 230 {
		t.Fatal(len(lines))
	}
	for _, line := range lines {
		p := strings.Split(line, "\t")
		if len(p) != 3 {
			t.Fatal(line)
		}
		op, e := strconv.ParseUint(p[0], 10, 16)
		if e != nil {
			t.Fatal(e)
		}
		in := sample(*c.definition(uint16(op)))
		if op == 768 {
			width, e := strconv.Atoi(p[1][5:])
			if e != nil {
				t.Fatal(e)
			}
			in.Payload.ElementWidth = uint16(width)
			in.Payload.Data = make([]byte, 3*width)
			for j := 0; j < 3; j++ {
				in.Payload.Data[j*width] = byte(j + 1)
			}
		}
		want, e := hex.DecodeString(p[2])
		if e != nil {
			t.Fatal(e)
		}
		got, e := c.Encode(in, 0)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("oracle %s: %x != %x %v", p[0], got, want, e)
		}
		decoded, e := c.Decode(want, 100)
		if e != nil {
			t.Fatal(e)
		}
		back, e := c.Encode(decoded, 100)
		if e != nil || !bytes.Equal(back, want) {
			t.Fatal("oracle decode", line, e)
		}
	}
}

package jvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func catalog(t *testing.T) *Catalog {
	t.Helper()
	f, err := os.Open("testdata/bytecodes.cpp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "jvm")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func sample(d Definition, wide bool) *Instruction { return representativeInstruction(d, wide) }
func vectors(t *testing.T, c *Catalog) []struct {
	code   []byte
	offset uint32
} {
	t.Helper()
	var out []struct {
		code   []byte
		offset uint32
	}
	for _, d := range c.Instructions {
		if d.Reserved || d.Opcode == 0xc4 {
			continue
		}
		for _, wide := range []bool{false, true} {
			if wide && !wideAllowed(d.Opcode) {
				continue
			}
			for _, offset := range []uint32{0, 1, 2, 3} {
				b, err := c.Encode(sample(d, wide), offset)
				if err != nil {
					t.Fatalf("%s: %v", d.Mnemonic, err)
				}
				out = append(out, struct {
					code   []byte
					offset uint32
				}{b, offset})
			}
		}
	}
	return out
}
func TestCompleteOpenJDKCorpus(t *testing.T) {
	c := catalog(t)
	if len(c.Instructions) != 205 {
		t.Fatalf("%d definitions", len(c.Instructions))
	}
	if _, err := Parse(strings.NewReader("def(_nop, \"nop\", \"b\", nullptr)"), "jvm"); err == nil {
		t.Fatal("partial corpus accepted")
	}
	for _, v := range vectors(t, c) {
		in, err := c.Decode(v.code, v.offset)
		if err != nil {
			t.Fatal(err)
		}
		b, err := c.Encode(in, v.offset)
		if err != nil || !bytes.Equal(b, v.code) {
			t.Fatalf("binary roundtrip %x: %x %v", v.code, b, err)
		}
		b, err = c.Assemble(in.Format(), v.offset)
		if err != nil || !bytes.Equal(b, v.code) {
			t.Fatalf("text roundtrip %q (%x): %x %v", in.Format(), v.code, b, err)
		}
		for n := 0; n < len(v.code); n++ {
			if _, err := c.Decode(v.code[:n], v.offset); !errors.Is(err, ErrTruncated) {
				t.Fatalf("%s truncation %d: %v", in.Mnemonic, n, err)
			}
		}
	}
}
func TestIndependentJVMSVectors(t *testing.T) {
	c := catalog(t)
	for _, tt := range []struct {
		text   string
		offset uint32
		bytes  []byte
	}{
		{"iload 008", 0, []byte{0x15, 8}},
		{"bipush -128", 0, []byte{0x10, 0x80}}, {"sipush -32768", 0, []byte{0x11, 0x80, 0}},
		{"ldc #255", 0, []byte{0x12, 255}}, {"ldc_w #4660", 0, []byte{0x13, 0x12, 0x34}},
		{"wide iload 500", 0, []byte{0xc4, 0x15, 1, 244}}, {"wide iinc 300 -300", 0, []byte{0xc4, 0x84, 1, 44, 254, 212}},
		{"goto 0", 3, []byte{0xa7, 255, 253}}, {"goto_w 65536", 0, []byte{0xc8, 0, 1, 0, 0}},
		{"invokeinterface #4660 2", 0, []byte{0xb9, 0x12, 0x34, 2, 0}}, {"invokedynamic #4660", 0, []byte{0xba, 0x12, 0x34, 0, 0}},
		{"newarray int", 0, []byte{0xbc, 10}}, {"multianewarray #4660 3", 0, []byte{0xc5, 0x12, 0x34, 3}},
		{`tableswitch {"default":20,"low":-1,"targets":[4,8]}`, 3, []byte{0xaa, 0, 0, 0, 17, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 5}},
	} {
		t.Run(tt.text, func(t *testing.T) {
			b, err := c.Assemble(tt.text, tt.offset)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, tt.bytes) {
				t.Fatalf("got %x want %x", b, tt.bytes)
			}
		})
	}
}
func TestMalformedInstructions(t *testing.T) {
	c := catalog(t)
	bad := [][]byte{{0xca}, {0xcb}, {0xfe}, {0xff}, {0xc4, 0xc4}, {0xc4, 0x60}, {0x12, 0}, {0x13, 0, 0}, {0xb9, 0, 1, 0, 0}, {0xb9, 0, 1, 1, 1}, {0xba, 0, 1, 0, 1}, {0xbc, 3}, {0xbc, 12}, {0xc5, 0, 1, 0}, {0xaa, 1, 0, 0}, {0xab, 1, 0, 0}}
	for _, b := range bad {
		if _, err := c.Decode(b, 0); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	b := []byte{0xaa, 0, 0, 0}
	for _, v := range []int32{0, 5, 4} {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	if _, err := c.Decode(b, 0); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	b = []byte{0xab, 0, 0, 0}
	for _, v := range []int32{0, 2, 1, 0, 1, 0} {
		b = binary.BigEndian.AppendUint32(b, uint32(v))
	}
	if _, err := c.Decode(b, 0); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	for _, b := range [][]byte{{0xa7, 0, 1}, {0xa7, 0, 3}, {0xc4, 0x15, 0, 1, 0xa7, 255, 253}} {
		if _, err := c.DecodeMethod(b); err == nil {
			t.Fatalf("invalid method target accepted %x", b)
		}
	}
	for _, text := range []string{"wide nop", "ldc #0", "newarray void", "iinc 256 0", "wide iinc 65536 0", "sipush 32768", `tableswitch {"default":0,"targets":[]}`, `lookupswitch {"default":0,"pairs":[{"match":2,"target":0},{"match":1,"target":0}]}`, `lookupswitch {"wat":0}`, `lookupswitch {} trailing`} {
		if _, err := c.Assemble(text, 0); err == nil {
			t.Fatalf("invalid text accepted %q", text)
		}
	}
}
func TestRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("Rust unavailable")
	}
	c := catalog(t)
	dir := t.TempDir()
	if artifact := os.Getenv("MKASM_JVM_ARTIFACT_DIR"); artifact != "" {
		dir = filepath.Join(artifact, "rust")
	}
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	var tests strings.Builder
	tests.WriteString("use mkasm_jvm::*;\n#[test]fn strict(){assert!(decode_method(&[0xa7,0,1]).is_err());assert!(decode(&[0xc4,0x60],0).is_err());assert!(assemble(\"ldc #0\",0).is_err());assert_eq!(assemble(\"iload 008\",0).unwrap(),vec![0x15,8]);assert!(decode(&[0xba,0,1,0,1],0).is_err());}\n")

	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if artifact := os.Getenv("MKASM_JVM_ARTIFACT_DIR"); artifact != "" {
		paths, _ := filepath.Glob(filepath.Join(artifact, "javac", "*.code"))
		if len(paths) > 0 {
			tests.WriteString("#[test]fn javac_methods(){\n")
			for _, path := range paths {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				fmt.Fprintf(&tests, "{let code:&[u8]=&%s;let method=decode_method(code).unwrap();assert_eq!(encode_method(&method).unwrap(),code);let mut text=vec![];for i in method{text.extend(assemble(&i.format(),i.offset).unwrap());}assert_eq!(text,code); }\n", rustBytes(b))
			}
			tests.WriteString("}\n")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/conformance.rs"), []byte(tests.String()), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "conformance")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated Rust: %v\n%s", err, out)
	}
	t.Log(string(out))
}
func rustBytes(b []byte) string {
	var parts []string
	for _, v := range b {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestSourceOpcodeNumbers(t *testing.T) {
	c := catalog(t)
	source, err := os.ReadFile("testdata/bytecodes.hpp")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`_([a-z0-9_]+)\s*=\s*([0-9]+),`).FindAllSubmatch(source, -1)
	checked := 0
	for _, m := range matches {
		n, err := strconv.Atoi(string(m[2]))
		if err != nil {
			t.Fatal(err)
		}
		if n > 202 {
			continue
		}
		d := c.definition(byte(n))
		if d == nil || d.Mnemonic != string(m[1]) {
			t.Fatalf("opcode %d source %s catalog %#v", n, m[1], d)
		}
		checked++
	}
	if checked != 203 {
		t.Fatalf("checked %d independent numeric definitions", checked)
	}
}
func FuzzDecode(f *testing.F) {
	source, err := os.Open("testdata/bytecodes.cpp")
	if err != nil {
		f.Fatal(err)
	}
	defer source.Close()
	c, err := Parse(source, "jvm")
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{{0}, {0xc4, 0x84, 1, 44, 255, 0}, {0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		f.Add(seed, uint32(0))
	}
	f.Fuzz(func(t *testing.T, b []byte, offset uint32) {
		in, err := c.Decode(b, offset)
		if err != nil {
			return
		}
		if in.Length < 1 || in.Length > len(b) {
			t.Fatal("invalid decoder length")
		}
		encoded, err := c.Encode(in, offset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, b[:in.Length]) {
			t.Fatalf("roundtrip %x %x", b[:in.Length], encoded)
		}
	})
}

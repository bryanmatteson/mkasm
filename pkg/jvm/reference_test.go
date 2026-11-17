package jvm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// OpenJDK's ASM produces every legal opcode, all twelve wide forms, immediate
// boundaries and all switch alignments. Expected bytes never pass through our
// encoder. The ordinary javac/JVM test separately verifies executable methods.
func TestIndependentASMAllOpcodes(t *testing.T) {
	for _, tool := range []string{"javac", "java"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("JDK unavailable: ", err)
		}
	}
	dir := t.TempDir()
	const exports = "java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED"
	if out, err := exec.Command("javac", "--add-exports", exports, "-d", dir, "testdata/ASMOracle.java").CombinedOutput(); err != nil {
		t.Fatalf("compile independent OpenJDK ASM oracle: %v\n%s", err, out)
	}
	c := catalog(t)
	type request struct {
		d      Definition
		wide   bool
		offset uint32
	}
	var requests []request
	var input strings.Builder
	for _, d := range c.Instructions {
		if d.Reserved || d.Opcode == 0xc4 {
			continue
		}
		for _, wide := range []bool{false, true} {
			if wide && !wideAllowed(d.Opcode) {
				continue
			}
			for offset := uint32(0); offset < 4; offset++ {
				for boundary := 0; boundary < 2; boundary++ {
					w := 0
					if wide {
						w = 1
					}
					fmt.Fprintf(&input, "%d %d %d %d\n", d.Opcode, w, offset, boundary)
					requests = append(requests, request{d, wide, offset})
				}
			}
		}
	}
	cmd := exec.Command("java", "--add-exports", exports, "-cp", dir, "ASMOracle")
	cmd.Stdin = strings.NewReader(input.String())
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("OpenJDK ASM: %v\n%s", err, diagnostics.String())
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != len(requests) {
		t.Fatalf("oracle returned %d cases, want %d", len(lines), len(requests))
	}
	var vectors strings.Builder
	seen := map[byte]bool{}
	wideSeen := map[byte]bool{}
	for n, line := range lines {
		r := requests[n]
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("malformed oracle row %d: %q", n, line)
		}
		class, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		methods, err := extractCode(class)
		if err != nil || len(methods) != 1 {
			t.Fatalf("oracle class %d: %v, methods=%d", n, err, len(methods))
		}
		code := methods[0].code
		if len(code) <= int(r.offset)+1 || code[len(code)-1] != 0xb1 {
			t.Fatalf("bad oracle frame %d: %x", n, code)
		}
		want := code[r.offset : len(code)-1]
		text := r.d.Mnemonic + parts[0]
		if r.wide {
			text = "wide " + text
		}
		got, err := c.Assemble(text, r.offset)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("ASM case %d offset=%d %q: mkasm=%x ASM=%x err=%v", n, r.offset, text, got, want, err)
		}
		decoded, err := c.Decode(want, r.offset)
		if err != nil || decoded.Opcode != r.d.Opcode || decoded.Wide != r.wide || decoded.Length != len(want) {
			t.Fatalf("ASM decode %d %q %x: %+v %v", n, text, want, decoded, err)
		}
		round, err := c.Assemble(decoded.Format(), r.offset)
		if err != nil || !bytes.Equal(round, want) {
			t.Fatalf("ASM decoded operands %q: %x != %x: %v", decoded.Format(), round, want, err)
		}
		seen[r.d.Opcode] = true
		if r.wide {
			wideSeen[r.d.Opcode] = true
		}
		fmt.Fprintf(&vectors, "%d\t%s\t%s\n", r.offset, text, hex.EncodeToString(want))
	}
	if len(seen) != 201 || len(wideSeen) != 12 || len(requests) != 1704 {
		t.Fatalf("incomplete reference coverage: opcodes=%d wide=%d cases=%d", len(seen), len(wideSeen), len(requests))
	}
	if output := os.Getenv("MKASM_JVM_REFERENCE_RUST"); output != "" {
		if err := c.GenerateRust(output); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, "tests", "asm-reference.tsv"), []byte(vectors.String()), 0644); err != nil {
			t.Fatal(err)
		}
		const rust = `use mkasm_jvm::*;
#[test] fn independent_openjdk_asm() {
    let mut count = 0;
    for line in include_str!("asm-reference.tsv").lines() {
        let fields: Vec<_> = line.split('\t').collect();
        let offset: u32 = fields[0].parse().unwrap();
        let bytes: Vec<u8> = fields[2].as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect();
        assert_eq!(assemble(fields[1],offset).unwrap(),bytes,"{}",fields[1]);
        let decoded = decode(&bytes,offset).unwrap();
        assert_eq!(encode(&decoded,offset).unwrap(),bytes);
        assert_eq!(assemble(&decoded.format(),offset).unwrap(),bytes);
        count += 1;
    }
    assert_eq!(count,1704);
}
`
		if err := os.WriteFile(filepath.Join(output, "tests", "asm_reference.rs"), []byte(rust), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("OpenJDK ASM: %s independent byte comparisons; all 201 legal opcodes, 12 wide forms, 4 alignments, 2 operand cases", strconv.Itoa(len(requests)))
}

package mips

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// A second independent implementation catches five incorrect LLVM records that
// LLVM-only differential tests cannot detect. Run their real GNU bytes through
// Go and the CLI's freshly generated Rust consumers in all four target modes.
func TestIndependentMicroDSPConsumers(t *testing.T) {
	cli, as := os.Getenv("MKASM_REFERENCE_CLI"), os.Getenv("MKASM_MIPS_AS")
	if cli == "" || as == "" || os.Getenv("MKASM_MIPS_TABLEGEN_JSON") == "" {
		t.Skip("set MKASM_REFERENCE_CLI, MKASM_MIPS_AS and MKASM_MIPS_TABLEGEN_JSON")
	}
	out := os.Getenv("MKASM_MIPS_DSP_REFERENCE_RUST")
	if out == "" {
		out = t.TempDir()
	}
	arches := []string{"micromips32", "micromips32el", "micromips64", "micromips64el"}
	var members []string
	comparisons := 0
	for _, arch := range arches {
		members = append(members, strconv.Quote(arch))
		c := corpus(t, arch)
		dir := filepath.Join(out, arch)
		cmd := exec.Command(cli, "--arch", arch, "--codegen", "rust", "--output", dir, os.Getenv("MKASM_MIPS_TABLEGEN_JSON"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("CLI %s generation: %v\n%s", arch, err, output)
		}
		var rust strings.Builder
		fmt.Fprintf(&rust, "use %s::*;\n#[test]fn independent_gnu_dsp(){\n", arch)
		forms := 0
		for i := range c.Encodings {
			e := &c.Encodings[i]
			if !correctedMicroDSP(e.ID) {
				continue
			}
			forms++
			for _, pattern := range [][3]int64{{0, 1, 2}, {31, 30, 29}, {8, 9, 10}} {
				values := map[string]int64{}
				var rustValues []string
				for n, operand := range e.Operands {
					values[operand.Name] = pattern[n%3]
					rustValues = append(rustValues, strconv.FormatInt(pattern[n%3], 10))
				}
				d := codec.Decoded{Encoding: e, Values: values, Length: 4}
				text := d.Format(0)
				expected := assembleGNUReference(t, as, arch, text, true)
				actual, err := c.Encode(e.ID, values)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("%s %s: Go %x GNU %x: %v", arch, text, actual, expected, err)
				}
				decoded, err := c.Decode(expected)
				if err != nil || decoded.Encoding.ID != e.ID {
					t.Fatalf("%s GNU decode %s: %+v %v", arch, text, decoded, err)
				}
				for name, value := range values {
					if decoded.Values[name] != value {
						t.Fatalf("%s %s operand %s: %d != %d", arch, e.ID, name, decoded.Values[name], value)
					}
				}
				candidates, err := c.Assemble(text, 0)
				if err != nil || !containsBytes(candidates, expected) {
					t.Fatalf("%s source %s: %x != GNU %x: %v", arch, text, candidates, expected, err)
				}
				var rustBytes []string
				for _, b := range expected {
					rustBytes = append(rustBytes, strconv.Itoa(int(b)))
				}
				fmt.Fprintf(&rust, "{let bytes:&[u8]=&[%s];let values:&[i128]=&[%s];assert_eq!(encode(%q,values).unwrap(),bytes);let d=decode(bytes).unwrap();assert_eq!(d.encoding().id,%q);assert_eq!(&d.values[..values.len()],values);assert!(assemble(%q).unwrap().iter().any(|b|b.as_slice()==bytes));}\n", strings.Join(rustBytes, ","), strings.Join(rustValues, ","), e.ID, e.ID, text)
				comparisons++
			}
		}
		if forms != 5 {
			t.Fatalf("%s: %d corrected forms, want five", arch, forms)
		}
		rust.WriteString("}\n")
		if err := os.WriteFile(filepath.Join(dir, "tests", "gnu_dsp_reference.rs"), []byte(rust.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "Cargo.toml"), []byte("[workspace]\nresolver=\"2\"\nmembers=["+strings.Join(members, ",")+"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--workspace", "--lib", "--test", "gnu_dsp_reference")
	cmd.Dir = out
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("four CLI-generated microMIPS consumers against GNU: %v\n%s", err, output)
	}
	t.Logf("GNU DSP: %d independent boundary encodings; five corrected upstream layouts; Go and four fresh CLI-generated Rust crates agree", comparisons)
}

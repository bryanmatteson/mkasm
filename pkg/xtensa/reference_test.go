package xtensa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every sample needs an independent byte match. Ghidra disagreements are only
// diagnostic when another native reference establishes that sample's bytes.
// Optional BE formats use native LE instruction selection and vendor BE field
// functions; the QEMU BE core itself does not have a floating-point option.
func TestIndependentAssemblerCorpus(t *testing.T) {
	required := []string{"MKASM_XTENSA_GNU_AS", "MKASM_XTENSA_LLVM_MC", "MKASM_GHIDRA_HOME", "MKASM_XTENSA_LE_CONFIG", "MKASM_XTENSA_BE_CONFIG", "MKASM_XTENSA_NATIVE_FIELDS", "MKASM_REFERENCE_CLI"}
	for _, name := range required {
		if os.Getenv(name) == "" {
			t.Skip("set " + strings.Join(required, ", "))
		}
	}
	dir := t.TempDir()
	writeOracleCases(t, dir)
	for _, command := range [][]string{
		{"python3", "testdata/validate-asm.py", dir, "--assembler", os.Getenv("MKASM_XTENSA_GNU_AS"), "--gnu-config", os.Getenv("MKASM_XTENSA_LE_CONFIG")},
		{"python3", "testdata/validate-asm.py", dir, "--assembler", os.Getenv("MKASM_XTENSA_LLVM_MC"), "--llvm"},
		{"python3", "testdata/validate-asm.py", dir, "--assembler", os.Getenv("MKASM_XTENSA_GNU_AS"), "--architecture", "xtensaeb", "--gnu-config", os.Getenv("MKASM_XTENSA_BE_CONFIG")},
		{"python3", "testdata/validate-ghidra.py", dir, "--ghidra", os.Getenv("MKASM_GHIDRA_HOME")},
		{"python3", "testdata/validate-native-fields.py", dir, "--library", os.Getenv("MKASM_XTENSA_NATIVE_FIELDS")},
	} {
		if out, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", command, err, out)
		}
	}
	type result struct {
		ID, Architecture, Text, Bytes, Actual, Encoded, Status string
		Seed                                                   int
	}
	read := func(name string) []result {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var records []result
		if err := json.Unmarshal(body, &records); err != nil {
			t.Fatal(err)
		}
		return records
	}
	key := func(r result) string { return fmt.Sprintf("%s/%s/%d", r.Architecture, r.ID, r.Seed) }
	cases := read("cases.json")
	expected, verified := map[string]result{}, map[string]result{}
	for _, c := range cases {
		expected[key(c)] = c
	}
	if len(cases) != 4158 || len(expected) != len(cases) {
		t.Fatal("incomplete/duplicate independent input corpus", len(cases), len(expected))
	}
	for _, name := range []string{"gnu-results.json", "llvm-results.json", "gnu-be-results.json", "native-fields-results.json", "ghidra-comparison.json"} {
		counts := map[string]int{}
		for _, r := range read(name) {
			c, ok := expected[key(r)]
			if !ok || c.Bytes != r.Bytes || c.Text != r.Text {
				t.Fatalf("%s: unexpected source sample %+v", name, r)
			}
			counts[r.Status]++
			switch r.Status {
			case "exact":
				if r.Actual == "" {
					r.Actual = r.Encoded
				}
				if r.Actual != c.Bytes {
					t.Fatalf("%s: false exact match %+v", name, r)
				}
				if _, ok := verified[key(r)]; !ok {
					verified[key(r)] = r
				}
			case "different":
				if name != "ghidra-comparison.json" {
					t.Fatalf("native byte mismatch %s: %+v", name, r)
				}
			case "rejected":
			default:
				t.Fatalf("%s: unknown result %+v", name, r)
			}
		}
		t.Logf("%s: %v", name, counts)
	}
	catalogs := map[string]*Catalog{"xtensa": fixture(t, "xtensa"), "xtensaeb": fixture(t, "xtensaeb")}
	vectors := map[string]*strings.Builder{"xtensa": {}, "xtensaeb": {}}
	for _, c := range cases {
		r, ok := verified[key(c)]
		if !ok {
			t.Fatalf("no independent reference covers %s %q", key(c), c.Text)
		}
		raw, err := hex.DecodeString(r.Actual)
		if err != nil {
			t.Fatal(err)
		}
		catalog := catalogs[c.Architecture]
		d, err := catalog.Decode(raw)
		if err != nil || d.Length != len(raw) {
			t.Fatalf("native Go decode %s: %v", key(c), err)
		}
		encoded, err := catalog.Encode(*d)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("native Go encode %s: %x != %x: %v", key(c), encoded, raw, err)
		}
		text := catalog.Format(d, 0x40000)
		all, err := catalog.Assemble(text, 0x40000)
		found := false
		for _, b := range all {
			found = found || bytes.Equal(b, raw)
		}
		if err != nil || !found {
			t.Fatalf("native Go text %s %q: %v", key(c), text, err)
		}
		fmt.Fprintf(vectors[c.Architecture], "%s\t%s\n", key(c), r.Actual)
	}
	root := os.Getenv("MKASM_XTENSA_REFERENCE_RUST")
	if root == "" {
		root = filepath.Join(t.TempDir(), "rust")
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		output := filepath.Join(root, arch)
		cli := exec.Command(os.Getenv("MKASM_REFERENCE_CLI"), "--arch", arch, "--codegen", "rust", "--output", output, "testdata/llvm.json")
		if out, err := cli.CombinedOutput(); err != nil {
			t.Fatalf("fresh CLI %s: %v\n%s", arch, err, out)
		}
		testdir := filepath.Join(output, "tests")
		if err := os.MkdirAll(testdir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testdir, "native.tsv"), []byte(vectors[arch].String()), 0644); err != nil {
			t.Fatal(err)
		}
		rust := fmt.Sprintf(`use %s::*;
#[test] fn native_reference() {
 for line in include_str!("native.tsv").lines() {
  let (id,hex)=line.split_once('\t').unwrap();
  let raw:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
  let d=decode(&raw).unwrap_or_else(|e|panic!("{id}: {e:?}"));
  assert_eq!(d.length,raw.len(),"{id}"); assert_eq!(d.encode().unwrap(),raw,"{id}");
  let text=d.format(0x40000);
  assert!(assemble_at(&text,0x40000).unwrap_or_else(|e|panic!("{id} {text}: {e:?}")).contains(&raw),"{id} {text}");
 }
}
`, arch)
		if err := os.WriteFile(filepath.Join(testdir, "native_reference.rs"), []byte(rust), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte("[workspace]\nresolver=\"2\"\nmembers=[\"xtensa\",\"xtensaeb\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--workspace", "--lib", "--test", "native_reference")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI Rust native corpus: %v\n%s", err, out)
	}
	t.Logf("all %d independently verified physical samples passed Go decode/encode/text and both fresh CLI-generated Rust codecs", len(verified))
}

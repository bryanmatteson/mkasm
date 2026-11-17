package x86

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRust(t *testing.T) {
	output := filepath.Join(t.TempDir(), "x86-rs")
	if err := GenerateRust(codecCatalog(), output); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"Cargo.toml", "LICENSE", "src/lib.rs"} {
		if _, err := os.Stat(filepath.Join(output, path)); err != nil {
			t.Errorf("missing %s: %v", path, err)
		}
	}
	source, err := os.ReadFile(filepath.Join(output, "src/lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"static BUCKETS", "static OPERANDS", "pub fn decode", "pub fn encode", "static CANDIDATES",
		"pub struct PhysicalDecode", "pub fn operands", "pub fn format_intel", "pub enum FlowControl",
		"pub struct SemanticAccess", "pub fn semantic_access",
		"pub fn encode_relative_branch", "pub fn relocate",
		"pub force_rex: bool", "pub lock: bool", "pub repeat: u8", "pub struct FormInstruction",
		`e.id == "NOP" && head.opcode == 0x90 && head.base_ext != 0`,
		"head.vvvv & e.reserved_vvvv != 0",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("generated Rust lacks %q", required)
		}
	}
	assembler, err := os.ReadFile(filepath.Join(output, "src/assemble.rs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"pub struct Template", "pub fn parse(text: &str) -> Result<Template, AssembleError>",
		"pub fn matches(&self, bytes: &[u8], values: &mut Vec<OperandValue>) -> Option<usize>",
		"pub fn encode(&self, values: &[OperandValue]) -> Result<Vec<Encoded>, AssembleError>",
		"pub fn assemble(text: &str)", "pub fn assemble_at(text: &str, address: u64)",
		"pub fn set_memory", "fn every_form_round_trips_through_text_and_templates",
	} {
		if !strings.Contains(string(assembler), required) {
			t.Errorf("generated assembler lacks %q", required)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "examples/asm_check.rs")); err != nil {
		t.Errorf("missing examples/asm_check.rs: %v", err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	const sibRegression = `use x86_64::*;
#[test]
fn exact_encoding_requires_consistent_sib_fields() {
    let form = (0..encoding_count()).find(|&i| encoding(i).unwrap().form_id == "ADD_rm64_r64/1").unwrap();
    for address_override in [false, true] {
        for mod_bits in [0, 1, 2] {
            for rm in [0, 4] {
                for use_sib in [false, true] {
                    let mut out = [0; 15];
                    let fields = EncodeFields { mode: Mode::Mode64, address_override, mod_bits, rm, use_sib, ..Default::default() };
                    let result = encode(form, fields, &mut out);
                    if use_sib != (rm == 4) {
                        assert_eq!(result, Err(EncodeError::BadField));
                    } else {
                        let length = result.unwrap();
                        assert_eq!(decode(&out[..length], Mode::Mode64).unwrap().length as usize, length);
                    }
                }
            }
        }
    }
    let form = (0..encoding_count()).find(|&i| encoding(i).unwrap().form_id == "ADD_rm64_r64/0").unwrap();
    let fields = EncodeFields { mode: Mode::Mode64, mod_bits: 3, rm: 4, use_sib: true, ..Default::default() };
    assert_eq!(encode(form, fields, &mut [0; 15]), Err(EncodeError::BadField));
}
`
	if err := os.WriteFile(filepath.Join(output, "tests", "encoding_fields.rs"), []byte(sibRegression), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests", "format_reuse.rs"), []byte(rustIntelFormatReuseTest), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cargo", "test", "--lib", "--examples", "--test", "encoding_fields", "--test", "format_reuse", "--quiet")
	command.Dir = output
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated crate failed: %v\n%s", err, output)
	}
}

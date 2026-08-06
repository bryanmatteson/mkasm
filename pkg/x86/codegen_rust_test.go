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
		"pub struct PhysicalDecode", "pub fn operands", "pub fn format_intel",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("generated Rust lacks %q", required)
		}
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	command := exec.Command("cargo", "test", "--quiet")
	command.Dir = output
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated crate failed: %v\n%s", err, output)
	}
}

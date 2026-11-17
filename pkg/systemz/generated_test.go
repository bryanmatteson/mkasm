package systemz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This exercises the public generated API. Raw .insn formats deliberately
// accept opcode bytes that a normal instruction decoder must reject.
func TestGeneratedRawDirectives(t *testing.T) {
	if testing.Short() {
		t.Skip("standalone Rust consumer")
	}
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Skip("managed cargo unavailable")
	}
	dir := os.Getenv("MKASM_SYSTEMZ_RUST_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, "Documents", "Developer", "go-mkasm", "architecture-expansion", "systemz", "generated-rust-regression")
	}
	c := load(t)
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("testdata/raw-insn.rs")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "raw_insn.rs"), source, 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cargo, "test", "--manifest-path", filepath.Join(dir, "Cargo.toml"), "--lib", "--test", "raw_insn")
	cmd.Env = os.Environ()
	flags := os.Getenv("RUSTFLAGS")
	if !strings.Contains(flags, "-D warnings") {
		flags = strings.TrimSpace(flags + " -D warnings")
	}
	cmd.Env = append(cmd.Env, "RUSTFLAGS="+flags)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("standalone SystemZ raw consumer: %v\n%s", err, output)
	}
	t.Logf("all generated forms and raw-directive consumer passed under -D warnings\n%s", output)
}

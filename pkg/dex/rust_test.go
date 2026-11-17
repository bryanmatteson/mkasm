package dex

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedRust(t *testing.T) {
	if os.Getenv("MKASM_DEX_RUST") == "" {
		t.Skip("set MKASM_DEX_RUST=1 to validate standalone Rust")
	}
	dir := t.TempDir()
	if p := os.Getenv("MKASM_DEX_ARTIFACT_DIR"); p != "" {
		dir = filepath.Join(p, "rust")
	}
	c := load(t)
	if e := c.GenerateRust(dir); e != nil {
		t.Fatal(e)
	}

	cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(dir, "Cargo.toml"), "--test", "behavior")
	out, e := cmd.CombinedOutput()
	if p := os.Getenv("MKASM_DEX_ARTIFACT_DIR"); p != "" {
		os.WriteFile(filepath.Join(p, "rust-validation.log"), out, 0644)
	}
	if e != nil {
		t.Fatalf("%v\n%s", e, out)
	}
	t.Logf("%s", out)
}

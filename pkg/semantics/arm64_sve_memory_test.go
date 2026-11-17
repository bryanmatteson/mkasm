package semantics

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SVEGatherScatter(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "tests.rs": sveGatherScatterTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

//go:embed testdata/arm64_sve_memory.rs
var sveGatherScatterTests string

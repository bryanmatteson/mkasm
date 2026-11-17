package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustIndexedRegisters(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	tests, err := os.ReadFile("testdata/indexed_register.rs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), append([]byte(RustRuntime), tests...), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", "indexed-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile indexed state: %v\n%s", err, out)
	}
	if out, err := exec.Command(filepath.Join(dir, "indexed-tests"), "indexed_register_tests::", "--nocapture").CombinedOutput(); err != nil {
		t.Fatalf("indexed state behavior: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

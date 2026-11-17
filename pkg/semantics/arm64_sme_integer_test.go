package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SMEInteger(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for _, name := range []string{"arm64_sme_integer.rs", "arm64_sme_integer_cases.rs"} {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(RustRuntime), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "arm64_sme_integer.rs", "-Copt-level=1", "-Dwarnings", "-o", "sme-integer-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SME integer recipes: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "sme-integer-tests"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("evaluate SME integer recipes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

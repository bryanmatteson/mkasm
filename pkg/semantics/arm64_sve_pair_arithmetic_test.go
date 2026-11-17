package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustA64SVEPairArithmetic(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/arm64_sve_pair_arithmetic.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_sve_pair_arithmetic") {
		t.Fatal("production runtime must embed the SVE pair arithmetic helper")
	}

	for name, data := range map[string][]byte{"semantics.rs": []byte(source), "sve_pair_arithmetic.rs": body} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "sve_pair_arithmetic.rs", "-Copt-level=1", "-Dwarnings", "-o", "sve-pair-arithmetic-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE pair arithmetic: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "sve-pair-arithmetic-tests"), "--nocapture")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("evaluate SVE pair arithmetic: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

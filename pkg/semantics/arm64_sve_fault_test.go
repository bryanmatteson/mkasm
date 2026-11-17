package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SVEFaultLoads(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/arm64_sve_fault.rs")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"semantics.rs": []byte(RustRuntime), "fault.rs": body} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "fault.rs", "-Copt-level=1", "-Dwarnings", "-o", "fault-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE fault loads: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "fault-tests"), "--nocapture")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute SVE fault loads: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

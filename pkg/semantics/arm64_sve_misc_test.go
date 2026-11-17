package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SVEMisc(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for destination, source := range map[string]string{"misc.rs": "arm64_sve_misc.rs", "tests.rs": "testdata/arm64_sve_misc.rs"} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if destination == "tests.rs" {
			data = append(data, []byte("\n#[test]fn unrelated_helper_class_is_none(){assert!(misc::a64(0xd503201f,0,128).is_none());}\n")...)
		}
		if err := os.WriteFile(filepath.Join(dir, destination), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE misc: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("evaluate SVE misc: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

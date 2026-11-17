package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustA64SVECounters(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/arm64_sve_counter.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_sve_counter") {
		module, err := os.ReadFile("arm64_sve_counter.rs")
		if err != nil {
			t.Fatal(err)
		}
		source += "\npub mod arm64_sve_counter {\n" + string(module) + "\n}\n"
	}
	for name, data := range map[string][]byte{"semantics.rs": []byte(source), "sve_counter.rs": body} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "sve_counter.rs", "-Copt-level=1", "-Dwarnings", "-o", "sve-counter-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE counters: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "sve-counter-tests"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("evaluate SVE counters: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

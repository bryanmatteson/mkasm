package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SVEBoundedRound(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/arm64_sve_bounded_round.rs")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"semantics.rs": []byte(RustRuntime), "bounded.rs": body} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"--edition=2021", "--test", "bounded.rs", "-Copt-level=1", "-Dwarnings", "-o", "bounded-tests"}, {"./bounded-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if args[0][0] == '.' {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

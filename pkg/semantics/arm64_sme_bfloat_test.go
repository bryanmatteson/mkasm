package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustA64SME2BFloat(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	native, err := os.ReadFile("../../../binary-toolkit/crates/isa/core/src/floating_point/bfloat16.rs")
	if os.IsNotExist(err) {
		t.Skip("native BF16 consumer checkout unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile("testdata/arm64_scalable_bfloat.rs")
	if err != nil {
		t.Fatal(err)
	}
	tests, err := os.ReadFile("testdata/arm64_sme_bfloat.rs")
	if err != nil {
		t.Fatal(err)
	}
	body := string(base)
	start := strings.Index(body, "fn recipe(")
	end := strings.Index(body, "#[derive(Default)]")
	cut := strings.Index(body, "#[test]\nfn sve_bfloat_")
	cases := strings.Index(body, "const CASES:")
	if start < 0 || end < start || cut < end || cases < cut {
		t.Fatal("shared BF16 fixture changed")
	}
	body = body[:start] + "fn recipe(word:u32,vl:u16,_sme:bool)->Recipe{semantics::arm64_sme_bfloat::a64(word,0x1000,vl).unwrap()}\n" + body[end:cut] + string(tests) + body[cases:]
	body = strings.Replace(body, "impl State {", "#[allow(dead_code)]impl State {", 1)
	body = strings.Replace(body, "fn fill(", "#[allow(dead_code)]fn fill(", 1)
	body = strings.Replace(body, "fn output(", "#[allow(dead_code)]fn output(", 1)
	runtime := RustRuntime
	if !strings.Contains(runtime, "pub mod arm64_sme_bfloat") {
		t.Fatal("RustRuntime must embed the production SME2 BF16 module")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{"semantics.rs": runtime, "tests.rs": "#[allow(dead_code)]mod semantics;\n" + body, "native_bfloat.rs": strings.ReplaceAll(string(native), "crate::", "crate::native_contract::")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Copt-level=1", "-Dwarnings", "-o", "bfloat-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile SME2 BF16: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "bfloat-tests"), "--nocapture")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute SME2 BF16: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

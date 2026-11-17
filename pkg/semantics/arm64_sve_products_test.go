package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SVEProducts(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/arm64_sve_products.rs")
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile("testdata/arm64_sve_integer.rs")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"semantics.rs": []byte(RustRuntime), "sve_products.rs": body, "sve_integer_base.rs": base} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "sve_products.rs", "-Dwarnings", "-o", filepath.Join(dir, "sve-products-tests"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE products: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "sve-products-tests"), "--nocapture")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("evaluate SVE products: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

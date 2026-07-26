package arm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedMITLicenseMatchesRepository(t *testing.T) {
	root, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if string(root) != mitLicense {
		t.Fatal("generated MIT license text differs from repository LICENSE")
	}

	dir := t.TempDir()
	if err := writeLicense(dir); err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile(filepath.Join(dir, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(root) {
		t.Fatal("written generated license differs from repository LICENSE")
	}
}

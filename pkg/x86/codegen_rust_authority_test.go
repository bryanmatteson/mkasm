package x86

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedRustExportsCatalogAuthority(t *testing.T) {
	catalog := codecCatalog()
	output := t.TempDir()
	if err := GenerateRust(catalog, output); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(output, "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"pub fn encoding_supports_mode",
		"pub fn encode_representative",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("generated Rust lacks %q", required)
		}
	}
}

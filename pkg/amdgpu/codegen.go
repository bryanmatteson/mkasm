package amdgpu

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed testdata/consumer.rs
var rustConsumer []byte

// WriteRustTests installs the public shader/profile consumer alongside a
// generated codec. The CLI and direct generator callers use the same checks.
func WriteRustTests(output string) error {
	dir := filepath.Join(output, "tests")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "consumer.rs"), rustConsumer, 0644)
}

package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/bryanmatteson/mkasm/pkg/amdgpu"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type amdgpuBackend struct {
	*codec.Catalog
	originalForms int
}

func parseAMDGPU(r io.Reader, architecture string) (*amdgpuBackend, error) {
	c, err := amdgpu.Parse(r, architecture)
	if err != nil {
		return nil, err
	}
	return &amdgpuBackend{Catalog: c, originalForms: len(c.Encodings)}, nil
}

func (c *amdgpuBackend) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	if err := amdgpu.WriteRustTests(output); err != nil {
		return err
	}
	if len(c.Encodings) != c.originalForms {
		// The independent shader fixture spans several GPU generations. A
		// CPU-filtered crate tests all retained encodings through the generated
		// corpus checks, without referring to instructions removed by selection.
		return os.WriteFile(filepath.Join(output, "tests/consumer.rs"), []byte("// CPU-filtered corpus tests are generated in src/lib.rs.\n"), 0644)
	}
	return nil
}

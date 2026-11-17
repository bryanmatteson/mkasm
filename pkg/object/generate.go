package object

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed runtime.rs
var rustRuntime string

//go:embed testdata/multi-table.elf
var symbolTableFixture []byte

//go:embed testdata/bpf-program.s
var bpfProgram []byte

//go:embed testdata/hexagon-program.s
var hexagonProgram []byte

// InstallRust adds the same dependency-free object API to a generated library.
func InstallRust(dir string) error {
	path := filepath.Join(dir, "src/lib.rs")
	lib, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !strings.Contains(string(lib), "pub mod object;") && !strings.Contains(string(lib), "pub use core::object;") {
		lib = append(lib, []byte("\n/// Complete-program assembly with an explicit target toolchain.\n#[path = \"object.rs\"]\npub mod object;\n")...)
		if e = os.WriteFile(path, lib, 0644); e != nil {
			return e
		}
	}
	if e = os.WriteFile(filepath.Join(dir, "src/object.rs"), []byte(rustRuntime), 0644); e != nil {
		return e
	}
	for _, fixture := range []struct {
		name string
		data []byte
	}{
		{"object-fixture.elf", symbolTableFixture},
		{"object-bpf.s", bpfProgram},
		{"object-hexagon.s", hexagonProgram},
	} {
		if e = os.WriteFile(filepath.Join(dir, "src", fixture.name), fixture.data, 0644); e != nil {
			return e
		}
	}
	return nil
}

package z80

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed block_relocation.rs.tmpl
var rustBlockRelocation string

//go:embed data/LICENSE-MAME
var mameLicense string

//go:embed data/COPYING-binutils
var gnuLicense string

//go:embed data/LICENSE-Ghidra
var ghidraLicense string

//go:embed data/NOTICE-Ghidra
var ghidraNotice string

func (c *Catalog) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	src := filepath.Join(output, "src")
	core, err := os.ReadFile(filepath.Join(src, "lib.rs"))
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(src, "core.rs"), core, 0644); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(src, "lib.rs"), []byte(rustRuntime+rustAnalysis), 0644); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(src, "block_relocation.rs"), []byte(rustBlockRelocation), 0644); err != nil {
		return err
	}
	cargo := fmt.Sprintf("[package]\nname = %q\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"GPL-3.0-or-later\"\n\n[lib]\npath = \"src/lib.rs\"\n", strings.ReplaceAll(c.Architecture, "-", "_"))
	if err = os.WriteFile(filepath.Join(output, "Cargo.toml"), []byte(cargo), 0644); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte("MAME z80.lst and z180ed.hxx "+MAMERevision+"\nCopyright Juergen Buchmueller, Andrei I. Holub\nBSD-3-Clause:\n"+mameLicense+"\nGNU binutils 2.44 z80-dis.c (GPL-3.0-or-later):\n"+gnuLicense+"\nGhidra Z80 description:\n"+ghidraNotice+"\n"+ghidraLicense), 0644); err != nil {
		return err
	}
	return nil
}

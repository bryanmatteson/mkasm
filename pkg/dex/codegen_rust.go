package dex

import (
	_ "embed"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed testdata/APACHE-2.0.txt
var aospLicense string

//go:embed conformance.rs.tmpl
var rustConformance string

//go:embed testdata/dexlib-oracle.tsv
var independentOracle string

//go:embed testdata/example.dex
var exampleDEX []byte

func (c *Catalog) generateConformance(output string) error {
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "tests", "oracle.tsv"), []byte(independentOracle), 0644); err != nil {
		return err
	}
	module, err := c.DecodeDEX(exampleDEX)
	if err != nil {
		return err
	}
	var methods strings.Builder
	for i, method := range module.Methods {
		name := fmt.Sprintf("method%d.bin", i)
		code := exampleDEX[int(method.CodeOffset) : int(method.CodeOffset)+method.Code.Length]
		if err := os.WriteFile(filepath.Join(output, "tests", name), code, 0644); err != nil {
			return err
		}
		fmt.Fprintf(&methods, "(include_bytes!(%q).as_slice(),%d),", name, module.Version)
	}
	return os.WriteFile(filepath.Join(output, "tests", "behavior.rs"), []byte(strings.ReplaceAll(rustConformance, "METHODS", methods.String())), 0644)
}

func (c *Catalog) GenerateRust(output string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(output)
		}
	}()

	if len(c.Instructions) != 259 {
		return fmt.Errorf("DEX generation requires full opcode catalog")
	}
	if e := os.MkdirAll(filepath.Join(output, "src"), 0755); e != nil {
		return e
	}
	var b strings.Builder
	b.WriteString("// Generated from AOSP ART dex_instruction_list.h.\n// Opcode metadata Copyright (C) 2011 The Android Open Source Project.\n// Licensed under Apache 2.0; see AOSP-APACHE-2.0.txt.\n// Validated source: android-16.0.0_r1, ed6c006bd06ae060bd9698fd2cb25c4865512ec3.\npub static INSTRUCTIONS: &[Definition] = &[\n")
	for _, d := range c.Instructions {
		fmt.Fprintf(&b, "Definition { opcode: %d, mnemonic: %s, format: %s, index_kind: %s, flags: %s, verify: %s, min_version: %d, reserved: %t, fields: &[", d.Opcode, strconv.Quote(d.Mnemonic), strconv.Quote(d.Format), strconv.Quote(d.IndexKind), strconv.Quote(d.Flags), strconv.Quote(d.Verify), d.MinVersion, d.Reserved)
		for _, f := range d.Fields {
			fmt.Fprintf(&b, "Field { name: %s, kind: %s, bit: %d, width: %d, signed: %t, shift: %d, wide: %t },", strconv.Quote(f.Name), strconv.Quote(f.Kind), f.Bit, f.Width, f.Signed, f.Shift, f.Wide)
		}
		b.WriteString("] },\n")
	}
	b.WriteString("];\n")
	files := map[string]string{"Cargo.toml": "[package]\nname = \"mkasm_dex\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n[lib]\npath = \"src/lib.rs\"\n", "src/lib.rs": b.String() + rustRuntime + rustAnalysis, "README.md": "# Generated DEX codec\n\nDependency-free standard Android DEX instruction and code_item codec.\nOffsets and branch displacements use 16-bit code units. Length fields use bytes.\nScalar fields use named operands; invocation registers and payloads are structured.\nText pool references use numeric kind@index notation; branch text uses absolute code-unit targets.\nODEX quickened instructions and VM type/dataflow verification are outside this codec.\n"}
	for name, s := range files {
		if e := os.WriteFile(filepath.Join(output, name), []byte(s), 0644); e != nil {
			return e
		}
	}
	if err := os.WriteFile(filepath.Join(output, "AOSP-APACHE-2.0.txt"), []byte(aospLicense), 0644); err != nil {
		return err
	}
	if err := c.generateConformance(output); err != nil {
		return err
	}
	return codec.WriteLicense(output)
}

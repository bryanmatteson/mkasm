package arm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/templates"
)

// GenerateRust emits a Rust crate for catalog under outputDir.
func (cg *CodeGenerator) GenerateRust(catalog *Catalog) error {
	if catalog == nil || len(catalog.Entries) == 0 {
		return fmt.Errorf("rust codegen: empty catalog")
	}
	srcDir := filepath.Join(cg.outputDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return err
	}

	tmpl, err := template.New("rust").Funcs(template.FuncMap{
		"rustStr": rustStringLiteral,
	}).ParseFS(templates.FS, "rust/*.tmpl")
	if err != nil {
		return fmt.Errorf("parse rust templates: %w", err)
	}

	cargoData := struct{ CrateName string }{CrateName: cg.arch.ArtifactName()}
	if err := execTmplWrite(tmpl, "cargo.toml.tmpl", filepath.Join(cg.outputDir, "Cargo.toml"), cargoData); err != nil {
		return err
	}
	if err := writeLicense(cg.outputDir); err != nil {
		return err
	}
	if err := execTmplWrite(tmpl, "lib.rs.tmpl", filepath.Join(srcDir, "lib.rs"), nil); err != nil {
		return err
	}

	encData := struct {
		FixedTable  string
		FieldsTable string
		ClassTable  string
	}{
		FixedTable:  emitRustFixedTable(catalog),
		FieldsTable: emitRustFieldsTable(catalog),
		ClassTable:  emitRustClassTable(catalog),
	}
	if err := execTmplWrite(tmpl, "encoders.rs.tmpl", filepath.Join(srcDir, "encoders.rs"), encData); err != nil {
		return err
	}

	decData := struct{ Table string }{Table: emitRustDecodeTable(catalog)}
	if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(srcDir, "decoders.rs"), decData); err != nil {
		return err
	}

	regData := struct{ AllTable string }{AllTable: emitRustRegistryTable(catalog)}
	if err := execTmplWrite(tmpl, "registry.rs.tmpl", filepath.Join(srcDir, "registry.rs"), regData); err != nil {
		return err
	}

	exDir := filepath.Join(cg.outputDir, "examples")
	if err := os.MkdirAll(exDir, 0755); err != nil {
		return err
	}
	// The worked example names specific instructions, so it is only emitted when
	// this generate actually produced them: a -max-iforms smoke run resolves a
	// handful of encodings and would not compile against it.
	example := "example_minimal.rs.tmpl"
	if cg.surfaceHasAll("mov", "add", "movz", "ldr", "str", "bl", "b_cond", "b", "nop", "ret") {
		example = "example.rs.tmpl"
	}
	if err := execTmplWrite(tmpl, example, filepath.Join(exDir, "hello.rs"), cargoData); err != nil {
		return err
	}
	// Operand placement checked against LLVM's assembler. The round-trip tests
	// confirm each word decodes to the right encoding, which does not prove an
	// operand's bits landed where they belong — a split immediate would decode
	// to the correct instruction with the value mangled. These words come from
	// clang, so they check the placements the decoder cannot.
	// Base mnemonics only: the arity-suffixed variants the example calls
	// (movi_amount, ptrue_pattern) are named during emission, not in the surface.
	if cg.surfaceHasAll("adr", "movi", "st1", "umov", "ld1b", "ptrue", "scvtf",
		"st1_asisdlso_h1_1h", "ld1b_mzx_p_br_2x8") {
		if err := execTmplWrite(tmpl, "example_llvm.rs.tmpl", filepath.Join(exDir, "llvm_check.rs"), cargoData); err != nil {
			return err
		}
	}

	// The typed assembler surface: operand types, then one method per mnemonic.
	if err := execTmplWrite(tmpl, "asm_support.rs.tmpl", filepath.Join(srcDir, "asm_support.rs"), nil); err != nil {
		return err
	}
	if cg.surface != nil {
		if err := os.WriteFile(filepath.Join(srcDir, "insns.rs"), []byte(emitRustInsns(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "encodings.rs"), []byte(emitRustExact(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "raw.rs"), []byte(emitRustRaw(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "insns_test.rs"), []byte(emitRustInsnTests(cg.surface)), 0644); err != nil {
			return err
		}
		testDir := filepath.Join(cg.outputDir, "tests")
		if err := os.MkdirAll(testDir, 0755); err != nil {
			return err
		}
		conformance, cases := EmitRustConformanceTest(cg.arch.ArtifactName(), cg.surface)
		if len(cases) == 0 {
			return fmt.Errorf("rust codegen: no typed conformance calls")
		}
		if err := os.WriteFile(filepath.Join(testDir, "conformance.rs"), []byte(conformance), 0644); err != nil {
			return err
		}
		exactConformance, exactCases := EmitRustExactConformanceTestFor(
			cg.arch.ArtifactName(), cg.surface, cg.disasm,
		)
		if len(exactCases) != len(cg.surface.Exact) {
			return fmt.Errorf("rust codegen: exact conformance calls %d, exact encoders %d",
				len(exactCases), len(cg.surface.Exact))
		}
		if err := os.WriteFile(filepath.Join(testDir, "exact_conformance.rs"), []byte(exactConformance), 0644); err != nil {
			return err
		}
	}
	return nil
}

func execTmplWrite(tmpl *template.Template, name, path string, data any) error {
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, name, data); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func rustStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u{%x}`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func emitRustFixedTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → fixed word (sorted for binary search)\n")
	b.WriteString("static FIXED: &[(&str, u32)] = &[\n")
	for _, e := range c.Entries {
		if !e.HasFixed {
			continue
		}
		fmt.Fprintf(&b, "    (%s, 0x%08X),\n", rustStringLiteral(e.EncodingID), e.FixedWord)
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustFieldsTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → variable field layouts (sorted)\n")
	b.WriteString("static FIELDS: &[(&str, &[(&str, FieldLayout)])] = &[\n")
	for _, e := range c.Entries {
		var parts []string
		for _, f := range e.Fields {
			if f.Fixed || f.Name == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("(%s, FieldLayout { start: %d, end: %d, free: 0x%08X })",
				rustStringLiteral(f.Name), f.Start, f.End, f.Free))
		}
		if len(parts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "    (%s, &[%s]),\n", rustStringLiteral(e.EncodingID), strings.Join(parts, ", "))
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustClassTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → iclass (sorted)\n")
	b.WriteString("static ENCODING_CLASS: &[(&str, &str)] = &[\n")
	for _, e := range c.Entries {
		fmt.Fprintf(&b, "    (%s, %s),\n", rustStringLiteral(e.EncodingID), rustStringLiteral(e.Class))
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustDecodeTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("static TABLE: &[Entry] = &[\n")
	for _, e := range c.Entries {
		var fields []string
		for _, f := range e.Fields {
			fields = append(fields, fmt.Sprintf(
				"FieldDef { name: %s, start: %d, end: %d, fixed: %v }",
				rustStringLiteral(f.Name), f.Start, f.End, f.Fixed))
		}
		fieldLit := "&[]"
		if len(fields) > 0 {
			fieldLit = "&[" + strings.Join(fields, ", ") + "]"
		}
		fmt.Fprintf(&b,
			"    Entry { mask: 0x%08X, value: 0x%08X, mnemonic: %s, encoding_id: %s, class: %s, pattern: %s, alias_of: %s, fields: %s },\n",
			e.Mask, e.Value,
			rustStringLiteral(e.Mnemonic),
			rustStringLiteral(e.EncodingID),
			rustStringLiteral(e.Class),
			rustStringLiteral(e.Pattern),
			rustStringLiteral(e.AliasOf),
			fieldLit,
		)
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustRegistryTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("pub static ALL: &[Instruction] = &[\n")
	for _, e := range c.Entries {
		fmt.Fprintf(&b,
			"    Instruction { encoding_id: %s, mnemonic: %s, class: %s, bit_pattern: %s, fixed_word: 0x%08X, has_fixed: %v, iform_file: %s, asm: %s, alias_of: %s },\n",
			rustStringLiteral(e.EncodingID),
			rustStringLiteral(e.Mnemonic),
			rustStringLiteral(e.Class),
			rustStringLiteral(e.Pattern),
			e.FixedWord, e.HasFixed,
			rustStringLiteral(e.IFormFile),
			rustStringLiteral(e.Asm),
			rustStringLiteral(e.AliasOf),
		)
	}
	b.WriteString("];\n")
	return b.String()
}

// surfaceHasAll reports whether every named method was generated.
func (cg *CodeGenerator) surfaceHasAll(methods ...string) bool {
	if cg.surface == nil {
		return false
	}
	for _, m := range methods {
		if len(cg.surface.Methods[m]) == 0 {
			return false
		}
	}
	return true
}

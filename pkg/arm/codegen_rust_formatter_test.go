package arm

import (
	"strings"
	"testing"
	"text/template"

	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

func TestRustFormatterExportsAPIAndPreservesNegativeFormulaScale(t *testing.T) {
	tmpl, err := template.New("rust").ParseFS(assettemplates.FS, "rust/formatters.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	if err := tmpl.ExecuteTemplate(&source, "formatters.rs.tmpl", rustDisasmData{}); err != nil {
		t.Fatal(err)
	}
	generated := source.String()
	for _, required := range []string{
		"pub enum FormatError", "pub fn format(word: u32, _address: u64)",
		"if formula.raw_mul == 0 { 1 } else { formula.raw_mul }",
		"31u32.checked_sub((n << 6 | (!imms & 0x3f)).leading_zeros())?",
	} {
		if !strings.Contains(generated, required) {
			t.Fatalf("generated formatter is missing %q", required)
		}
	}
}

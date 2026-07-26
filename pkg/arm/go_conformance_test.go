package arm

import (
	"strings"
	"testing"
)

func TestEmitGoConformanceTest(t *testing.T) {
	catalog := &Catalog{Entries: []CatalogEntry{
		{
			EncodingID: "FIXED",
			FixedWord:  0xD503201F,
			HasFixed:   true,
		},
		{
			EncodingID: "PARTIAL",
			FixedWord:  0xA0000200,
			HasFixed:   true,
			Fields: []CatalogField{{
				Name: "field", Start: 8, End: 11, Free: 0x00000C00,
			}},
		},
	}}

	src, cases := EmitGoConformanceTest("aarch64", catalog)
	if len(cases) != len(catalog.Entries) {
		t.Fatalf("cases = %d, entries = %d", len(cases), len(catalog.Entries))
	}
	if got := cases[1].Fields; len(got) != 1 || got[0].Name != "field" || got[0].Value != 6 {
		t.Fatalf("partial field sample = %#v, want field=6 including pinned bit", got)
	}
	for _, want := range []string{
		`"aarch64/encoders"`,
		"func TestExactConformanceWords",
		`{"FIXED", map[string]uint64{}}`,
		`{"PARTIAL", map[string]uint64{"field": 6}}`,
		`encoders.EncodeWithFields(c.id, c.fields)`,
		`fmt.Printf("%d\t%s\t%08X\n", i, c.id, word)`,
		"2 exact encoders emitted",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated source does not contain %q", want)
		}
	}
}

func TestGoConformanceCasesNilCatalog(t *testing.T) {
	if cases := GoConformanceCases(nil); cases != nil {
		t.Fatalf("nil catalog cases = %#v", cases)
	}
}

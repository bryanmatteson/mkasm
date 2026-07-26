package arm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mkasm/pkg/ir"
)

func TestParseIFormFile_CLREX(t *testing.T) {
	path := clrexFixture(t)
	parsed, err := ParseIFormFile(path, "CLREX_BN_barriers")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EncodingName != "CLREX_BN_barriers" {
		t.Fatalf("encoding name: %q", parsed.EncodingName)
	}
	if !strings.Contains(parsed.AsmTemplate, "CLREX") {
		t.Fatalf("asmtemplate missing CLREX: %q", parsed.AsmTemplate)
	}
	if len(parsed.Boxes) < 6 {
		t.Fatalf("expected >=6 boxes, got %d", len(parsed.Boxes))
	}

	byHi := map[int]RegBox{}
	for _, b := range parsed.Boxes {
		byHi[b.HiBit] = b
	}
	for _, want := range []struct {
		hi, width int
		name      string
		fixed     *uint64
	}{
		{11, 4, "CRm", nil},
		{7, 3, "op2", uint64Ptr(0b010)},
		{4, 5, "Rt", uint64Ptr(0b11111)},
	} {
		b, ok := byHi[want.hi]
		if !ok {
			t.Fatalf("missing box hibit=%d", want.hi)
		}
		if b.Width != want.width {
			t.Fatalf("hibit %d width: got %d want %d", want.hi, b.Width, want.width)
		}
		if b.Name != want.name {
			t.Fatalf("hibit %d name: got %q want %q", want.hi, b.Name, want.name)
		}
		if want.fixed == nil {
			if b.Fixed != nil {
				t.Fatalf("hibit %d: expected non-fixed, got %#x", want.hi, *b.Fixed)
			}
		} else if b.Fixed == nil || *b.Fixed != *want.fixed {
			got := any(nil)
			if b.Fixed != nil {
				got = *b.Fixed
			}
			t.Fatalf("hibit %d fixed: got %v want %#x", want.hi, got, *want.fixed)
		}
	}

	instr := &ir.InstructionIR{EncodingID: "CLREX_BN_barriers", Mnemonic: "CLREX"}
	ApplyParsedIForm(instr, parsed)
	if instr.Asm.Raw == "" || !strings.Contains(instr.Asm.Raw, "CLREX") {
		t.Fatalf("Asm not applied: %+v", instr.Asm)
	}
	if len(instr.Encoding.Fields) < 6 {
		t.Fatalf("encoding fields: %d", len(instr.Encoding.Fields))
	}
	// CRm at bits [8:11]
	foundCRm := false
	for _, f := range instr.Encoding.Fields {
		if f.Name == "CRm" && f.Start == 8 && f.End == 11 && f.Fixed == nil {
			foundCRm = true
		}
	}
	if !foundCRm {
		t.Fatalf("CRm field missing/wrong: %+v", instr.Encoding.Fields)
	}
	if !strings.Contains(instr.BitPattern, "0") && !strings.Contains(instr.BitPattern, "1") {
		t.Fatalf("bit pattern still all-x: %s", instr.BitPattern)
	}
}

func TestParseIForm_colspanDontCare(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<instructionsection>
  <iclass>
    <regdiagram form="32">
      <box hibit="11" width="4" name="CRm"><c colspan="4"/></box>
      <box hibit="7" width="3" name="op2" settings="3"><c>0</c><c>1</c><c>0</c></box>
    </regdiagram>
    <encoding name="X">
      <asmtemplate><text>FOO</text></asmtemplate>
    </encoding>
  </iclass>
</instructionsection>`
	tmp := filepath.Join(t.TempDir(), "x.xml")
	if err := os.WriteFile(tmp, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := ParseIFormFile(tmp, "X")
	if err != nil {
		t.Fatal(err)
	}
	if p.AsmTemplate != "FOO" {
		t.Fatalf("asm: %q", p.AsmTemplate)
	}
	if len(p.Boxes) != 2 {
		t.Fatalf("boxes: %d", len(p.Boxes))
	}
	if p.Boxes[0].Fixed != nil {
		t.Fatalf("CRm should be variable, got %#x", *p.Boxes[0].Fixed)
	}
	if p.Boxes[1].Fixed == nil || *p.Boxes[1].Fixed != 0b010 {
		t.Fatalf("op2 fixed: %v", p.Boxes[1].Fixed)
	}
}

func TestParseIFormFileReportsOpenErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.xml")
	p, err := ParseIFormFile(path, "missing")
	if err == nil {
		t.Fatal("expected missing file error")
	}
	if p != nil {
		t.Fatalf("expected no parsed result, got %#v", p)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error does not identify input path: %v", err)
	}
}

func uint64Ptr(v uint64) *uint64 { return &v }

func clrexFixture(t testing.TB) string {
	t.Helper()
	candidates := []string{
		filepath.Join("spec", "ISA", "clrex.xml"),
		filepath.Join("..", "..", "spec", "ISA", "clrex.xml"),
		filepath.Join("..", "spec", "ISA", "clrex.xml"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 1000 {
			return p
		}
	}
	t.Skip("clrex.xml fixture not available locally")
	return ""
}

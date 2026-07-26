package arm_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mkasm/pkg/arm"
)

func TestE2E_Pass2_CLREX(t *testing.T) {
	enc := encodingIndexPath(t)
	iformDir := iformDirPath(t)

	p := arm.NewARMParser(arm.ARMParserConfig{
		EncodingIndexPath: enc,
		IFormDirectory:    iformDir,
		OutputDirectory:   t.TempDir(),
		SkipCodegen:       true,
		IFormWorkers:      4,
		MaxIForms:         1, // Pass 1 only needs the index; resolve CLREX below
	})
	defer p.Close(2 * time.Second)

	if err := p.Parse(context.Background()); err != nil {
		t.Fatalf("parse: %v", err)
	}

	found := false
	for _, instr := range p.GetRegistry().GetAll() {
		if instr.EncodingID != "CLREX_BN_barriers" {
			continue
		}
		found = true
		parsed, err := arm.ParseIFormFile(filepath.Join(iformDir, instr.IFormFile), instr.EncodingID)
		if err != nil {
			t.Fatal(err)
		}
		arm.ApplyParsedIForm(instr, parsed)

		if !strings.Contains(instr.Asm.Raw, "CLREX") {
			t.Fatalf("CLREX asm empty/wrong: %q", instr.Asm.Raw)
		}
		if len(instr.Encoding.Fields) < 6 {
			t.Fatalf("CLREX encoding fields: %d", len(instr.Encoding.Fields))
		}
		hasCRm := false
		for _, f := range instr.Encoding.Fields {
			if f.Name == "CRm" && f.Start == 8 && f.End == 11 {
				hasCRm = true
			}
		}
		if !hasCRm {
			t.Fatalf("CLREX missing CRm[8:11]: %+v", instr.Encoding.Fields)
		}
		if strings.Count(instr.BitPattern, "x") == 32 {
			t.Fatalf("CLREX bit pattern still provisional: %s", instr.BitPattern)
		}
		break
	}
	if !found {
		t.Fatal("CLREX_BN_barriers not in registry after Pass 1")
	}
}

func encodingIndexPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "spec", "ISA", "encodingindex.xml"),
		filepath.Join("spec", "ISA", "encodingindex.xml"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 1000 {
			return p
		}
	}
	t.Skip("optional extracted encodingindex.xml is not available")
	return ""
}

func iformDirPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "spec", "ISA"),
		filepath.Join("spec", "ISA"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(filepath.Join(p, "clrex.xml")); err == nil && st.Size() > 1000 {
			return p
		}
	}
	t.Skip("optional extracted IForm directory is not available")
	return ""
}

func iformFilePath(t *testing.T, name string) string {
	t.Helper()
	dir := iformDirPath(t)
	return filepath.Join(dir, name)
}

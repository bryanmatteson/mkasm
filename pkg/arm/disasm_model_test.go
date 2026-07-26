package arm_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mkasm/pkg/arm"
)

// loadResolvedParser runs Pass 1 and 2 and hands back the parser itself, which
// the print model needs: it reaches back into the iform cache for the operand
// prose the registry does not carry.
func loadResolvedParser(t *testing.T, maxIForms int) *arm.ARMParser {
	t.Helper()
	p := arm.NewARMParser(arm.ARMParserConfig{
		EncodingIndexPath: encodingIndexPath(t),
		IFormDirectory:    iformDirPath(t),
		OutputDirectory:   t.TempDir(),
		SkipCodegen:       true,
		IFormWorkers:      8,
		MaxIForms:         maxIForms,
	})
	t.Cleanup(func() { _ = p.Close(2 * time.Second) })
	if err := p.Parse(context.Background()); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// TestDisasmTemplateReassembles pins the invariant the print model rests on:
// an encoding's operand prefixes, its operand symbols and its trailing suffix,
// concatenated in order, reproduce ARM's asmtemplate exactly. If that fails the
// template text is being lost somewhere between the XML and the model, which is
// how "ABS <Wd> , <Wn>" used to reach the generated registry.
func TestDisasmTemplateReassembles(t *testing.T) {
	for _, tc := range []struct{ file, enc, want, suffix string }{
		{"ldr_imm_gen.xml", "LDR_64_ldst_pos", "LDR  <Xt>, [<Xn|SP>{, #<pimm>}]", "}]"},
		{"ldr_imm_gen.xml", "LDR_32_ldst_immpost", "LDR  <Wt>, [<Xn|SP>], #<simm>", ""},
		{"abs_advsimd.xml", "ABS_asimdmisc_R", "ABS  <Vd>.<T>, <Vn>.<T>", ""},
		{"b_cond.xml", "B_only_condbranch", "B.<cond>  <label>", ""},
		{"addg.xml", "ADDG_64_addsub_immtags", "ADDG  <Xd|SP>, <Xn|SP>, #<uimm6>, #<uimm4>", ""},
	} {
		p, err := arm.ParseIFormFile(filepath.Join(iformDirPath(t), tc.file), tc.enc)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.file, tc.enc, err)
		}
		if p.AsmTemplate != tc.want {
			t.Errorf("%s: template = %q, want %q", tc.enc, p.AsmTemplate, tc.want)
		}
		if p.AsmSuffix != tc.suffix {
			t.Errorf("%s: suffix = %q, want %q", tc.enc, p.AsmSuffix, tc.suffix)
		}
		var b strings.Builder
		for _, o := range p.AsmOperands {
			b.WriteString(o.Prefix)
			b.WriteString(o.Symbol)
		}
		b.WriteString(p.AsmSuffix)
		if got := b.String(); got != p.AsmTemplate {
			t.Errorf("%s: reassembled %q != template %q", tc.enc, got, p.AsmTemplate)
		}
	}
}

// TestDisasmSurfaceCoverage reports how much of the ISA has a printable form and
// enforces a floor. The floor exists so a regression that silently stops
// resolving a whole operand class fails here rather than showing up as
// instructions that decode but cannot be printed.
func TestDisasmSurfaceCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("full ISA parse")
	}
	p := loadResolvedParser(t, 0)
	s := p.DisasmSurface()
	total := len(s.Forms) + len(s.Skipped)
	if total == 0 {
		t.Fatal("no encodings resolved")
	}
	pct := 100 * float64(len(s.Forms)) / float64(total)
	t.Logf("printable=%d skipped=%d total=%d (%.1f%%)", len(s.Forms), len(s.Skipped), total, pct)

	reasons := map[string]int{}
	for _, sk := range s.Skipped {
		reasons[skipBucket(sk.Reason)]++
	}
	for r, n := range reasons {
		t.Logf("  skipped %5d  %s", n, r)
	}
	if pct < 80 {
		t.Fatalf("printable coverage %.1f%%, want >= 80%%", pct)
	}
}

func skipBucket(reason string) string {
	switch {
	case strings.HasPrefix(reason, "operand is algorithmic"):
		return "algorithmic operand"
	case strings.Contains(reason, "absent from encoding"):
		return "field absent from encoding"
	case strings.Contains(reason, "fully pinned"):
		return "field fully pinned"
	case strings.Contains(reason, "non-contiguous"):
		return "non-contiguous free bits"
	case strings.Contains(reason, "value table row"):
		return "value table shape mismatch"
	case strings.HasPrefix(reason, "operand is computed per row"):
		return "per-row decode formula"
	case strings.HasPrefix(reason, "operand class"):
		return reason
	}
	return reason
}

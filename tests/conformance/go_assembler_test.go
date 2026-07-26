package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"mkasm/pkg/arm"
)

// TestGoAssemblerLLVMConformance verifies every generated Go exact encoder
// against LLVM. The generated module owns the call ledger; this repository
// supplies only the independent oracle driver.
func TestGoAssemblerLLVMConformance(t *testing.T) {
	if os.Getenv("MKASM_GO_LLVM_CONFORMANCE") != "1" {
		t.Skip("set MKASM_GO_LLVM_CONFORMANCE=1 or run mise run conformance:go")
	}
	if testing.Short() {
		t.Skip("full Go generation, compile, and LLVM byte comparison")
	}
	cc := findClang(t)
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required by the activated Go conformance gate: %v", err)
	}

	p, outDir := loadCorpusParser(t, parserOptions{codegen: arm.LangGo})
	cases := arm.GoConformanceCasesFor(
		arm.BuildCatalog(p.ResolvedInstructions()),
		p.DisasmSurface(),
	)
	requireEncodingCoverage(t, p, goCaseIDs(cases))
	testPath := filepath.Join(outDir, "conformance", "conformance_test.go")
	if _, err := os.Stat(testPath); err != nil {
		t.Fatalf("generated Go conformance test: %v", err)
	}

	cmd := exec.Command(goTool, "test", "./conformance",
		"-run", "^TestExactConformanceWords$", "-v", "-count=1")
	cmd.Dir = outDir
	cmd.Env = append(os.Environ(), "MKASM_GO_CONFORMANCE_LEDGER=1")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated Go exact conformance calls: %v\n%s", err, raw)
	}

	ids := goCaseIDs(cases)
	words := parseConformanceWords(t, "Go", raw, ids)
	verifyAssemblerWords(t, cc, p, "go-exact", ids, words)
}

func goCaseIDs(cases []arm.GoConformanceCase) []string {
	ids := make([]string, len(cases))
	for i := range cases {
		ids[i] = cases[i].EncodingID
	}
	return ids
}

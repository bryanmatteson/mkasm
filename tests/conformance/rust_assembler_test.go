package conformance_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/arm"
	encodingcoverage "github.com/bryanmatteson/mkasm/pkg/coverage"
)

type renderedCase struct {
	call int
	id   string
	word uint32
	text string
}

// TestRustAssemblerLLVMConformance is the end-to-end external reassembly gate
// for the typed generated Rust assembler.
//
// It deliberately sits outside the ordinary unit suite: it generates the full
// crate, compiles and calls every emitted typed overload, renders each resulting
// word as assembly, and asks clang's independent AArch64 assembler for the
// bytes. Run it through `mise run conformance:rust`.
//
// Unsupported LLVM extensions are reported separately. They are not evidence
// for or against mkasm. Set MKASM_LLVM_REQUIRE_ALL=1 to make any such unverified
// case fail too (useful with a toolchain expected to cover the whole XML corpus).
//
// This gate is decisive when red. A green result would still need a direct
// call-operand -> source-text corpus for fully independent operand-semantics
// proof, because the print model and assembler model both originate in ARM XML.
func TestRustAssemblerLLVMConformance(t *testing.T) {
	if os.Getenv("MKASM_RUST_LLVM_CONFORMANCE") != "1" {
		t.Skip("set MKASM_RUST_LLVM_CONFORMANCE=1 or run mise run conformance:rust")
	}
	if testing.Short() {
		t.Skip("full Rust generation, compile, and LLVM byte comparison")
	}
	cc := findClang(t)
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Fatalf("cargo is required by the activated Rust conformance gate: %v", err)
	}

	p, outDir := loadCorpusParser(t, parserOptions{codegen: arm.LangRust})

	_, cases := arm.EmitRustConformanceTest("aarch64", p.AsmSurface())
	if len(cases) == 0 {
		t.Fatal("no typed Rust calls emitted")
	}
	testPath := filepath.Join(outDir, "tests", "conformance.rs")
	if _, err := os.Stat(testPath); err != nil {
		t.Fatalf("generated conformance test: %v", err)
	}

	cmd := exec.Command(cargo, "test", "--quiet", "--test", "conformance",
		"typed_conformance_words", "--", "--ignored", "--nocapture", "--test-threads=1")
	cmd.Dir = outDir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated Rust conformance calls: %v\n%s", err, raw)
	}
	words := parseRustConformanceWords(t, raw, cases)
	verifyAssemblerWords(t, cc, p, "typed", rustCaseIDs(cases), words)

	_, exactCases := arm.EmitRustExactConformanceTestFor(
		"aarch64", p.AsmSurface(), p.DisasmSurface(),
	)
	requireEncodingCoverage(t, p, rustCaseIDs(exactCases))
	exactPath := filepath.Join(outDir, "tests", "exact_conformance.rs")
	if _, err := os.Stat(exactPath); err != nil {
		t.Fatalf("generated exact conformance test: %v", err)
	}
	cmd = exec.Command(cargo, "test", "--quiet", "--test", "exact_conformance",
		"exact_conformance_words", "--", "--ignored", "--nocapture", "--test-threads=1")
	cmd.Dir = outDir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	raw, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated Rust exact conformance calls: %v\n%s", err, raw)
	}
	exactWords := parseRustConformanceWords(t, raw, exactCases)
	verifyAssemblerWords(t, cc, p, "exact", rustCaseIDs(exactCases), exactWords)
}

func requireEncodingCoverage(t *testing.T, p *arm.ARMParser, observed []string) {
	t.Helper()
	resolved := p.ResolvedInstructions()
	expected := make([]string, len(resolved))
	for i := range resolved {
		expected[i] = resolved[i].EncodingID
	}
	report := encodingcoverage.Analyze(expected, observed)
	t.Logf("encoding-coverage=%.2f%% covered=%d expected=%d", report.Percent(), report.Covered, report.Expected)
	if err := report.Error(); err != nil {
		t.Fatal(err)
	}
}

func rustCaseIDs(cases []arm.RustConformanceCase) []string {
	ids := make([]string, len(cases))
	for i := range cases {
		ids[i] = cases[i].EncodingID
	}
	return ids
}

func verifyAssemblerWords(t *testing.T, cc string, p *arm.ARMParser, ledger string, ids []string, words []uint32) {
	t.Helper()
	if len(ids) != len(words) {
		t.Fatalf("%s conformance ids=%d words=%d", ledger, len(ids), len(words))
	}
	forms := map[string]*arm.DisasmForm{}
	skipReasons := map[string]string{}
	disasm := p.DisasmSurface()
	for i := range disasm.Forms {
		f := &disasm.Forms[i]
		forms[f.EncodingID] = f
	}
	for _, sk := range disasm.Skipped {
		skipReasons[sk.EncodingID] = sk.Symbol + ": " + sk.Reason
	}

	rendered := make([]renderedCase, 0, len(ids))
	var noPrint []string
	var illegalSamples []string
	noPrintCount := 0
	noPrintReasons := map[string]int{}
	noPrintDetails := map[string]int{}
	noPrintDetailSample := map[string]string{}
	contextPaired := 0
	for i, id := range ids {
		f := forms[id]
		if f == nil {
			noPrintCount++
			noPrintReasons[printModelReasonBucket(skipReasons[id])]++
			noPrintDetails[skipReasons[id]]++
			if noPrintDetailSample[skipReasons[id]] == "" {
				noPrintDetailSample[skipReasons[id]] = id
			}
			if len(noPrint) < 25 {
				noPrint = append(noPrint, id+": no complete print model ("+skipReasons[id]+")")
			}
			continue
		}
		text, ok := f.Render(words[i])
		if !ok || strings.TrimSpace(text) == "" {
			noPrintCount++
			const reason = "rendered sample is architecturally illegal"
			noPrintReasons[reason]++
			noPrintDetails[reason]++
			if noPrintDetailSample[reason] == "" {
				noPrintDetailSample[reason] = id
			}
			if len(illegalSamples) < 25 {
				illegalSamples = append(illegalSamples, illegalSampleSummary(id, f, words[i]))
			}
			if len(noPrint) < 25 {
				noPrint = append(noPrint, id+": emitted word has no legal assembly spelling")
			}
			continue
		}
		if follower, ok := movprfxFollower(text); ok {
			// MOVPRFX is checked in the architectural context it requires. The
			// independent assembler emits both words; assembleLines records the
			// first word at each sample's variable-width position.
			text += "\n" + follower
			contextPaired++
		}
		rendered = append(rendered, renderedCase{i, id, words[i], text})
	}

	lines := make([]string, len(rendered))
	for i := range rendered {
		lines[i] = rendered[i].text
	}
	res := assembleLines(t, cc, t.TempDir(), lines)
	mcFallbacks := verifyWithLLVMCFallback(t, rendered, &res)

	var exact, wrong, toolchainDivergence int
	var firstWrong []string
	for i, c := range rendered {
		got, ok := res.words[i]
		if !ok {
			continue
		}
		if got == c.word {
			exact++
			continue
		}
		if known, ok := knownLLVMEncodingDivergence[c.id]; ok &&
			c.word == known.specWord && got == known.llvmWord {
			toolchainDivergence++
			continue
		}
		wrong++
		if len(firstWrong) < 25 || os.Getenv("MKASM_LLVM_VERBOSE") == "1" {
			firstWrong = append(firstWrong, fmt.Sprintf(
				"%s via call #%d: %q emitted 0x%08X, LLVM emitted 0x%08X",
				c.id, c.call, c.text, c.word, got))
		}
	}

	t.Logf("%s-calls=%d rendered=%d no-print-model=%d context-paired=%d llvm-mc-fallbacks=%d unsupported-by-LLVM=%d rejected-by-LLVM=%d assembled=%d byte-identical=%d known-LLVM-divergence=%d wrong=%d",
		ledger, len(ids), len(rendered), noPrintCount, contextPaired, mcFallbacks,
		len(res.unsupported), len(res.rejected), len(res.words), exact, toolchainDivergence, wrong)
	for _, entry := range sortedCounts(noPrintReasons) {
		t.Logf("  UNPRINTABLE-CAUSE %4d %s", entry.count, entry.name)
	}
	for i, entry := range sortedCounts(noPrintDetails) {
		if i == 20 {
			break
		}
		t.Logf("  UNPRINTABLE-DETAIL %4d %-64s e.g. %s",
			entry.count, entry.name, noPrintDetailSample[entry.name])
	}
	for _, s := range noPrint {
		t.Logf("  UNPRINTABLE %s", s)
	}
	if len(illegalSamples) > 0 {
		t.Logf("  ILLEGAL-SAMPLE %s", strings.Join(illegalSamples, ", "))
	}
	for _, s := range firstWrong {
		t.Logf("  WRONG %s", s)
	}
	rejectedReasons := map[string]int{}
	rejectedSamples := map[string]string{}
	for i, why := range res.rejected {
		reason := rejectReasonBucket(why)
		rejectedReasons[reason]++
		if rejectedSamples[reason] == "" && i >= 0 && i < len(rendered) {
			rejectedSamples[reason] = rendered[i].id
		}
	}
	for i, entry := range sortedCounts(rejectedReasons) {
		if i == 20 {
			break
		}
		t.Logf("  REJECTED-CAUSE %4d %-72s e.g. %s",
			entry.count, entry.name, rejectedSamples[entry.name])
	}
	unsupportedShown := 0
	for i := range res.unsupported {
		if (unsupportedShown >= 25 && os.Getenv("MKASM_LLVM_VERBOSE") != "1") || i < 0 || i >= len(rendered) {
			continue
		}
		c := rendered[i]
		t.Logf("  UNSUPPORTED %s: 0x%08X %q", c.id, c.word, c.text)
		unsupportedShown++
	}
	rejectedShown := 0
	for i, why := range res.rejected {
		if (rejectedShown >= 25 && os.Getenv("MKASM_LLVM_VERBOSE") != "1") || i < 0 || i >= len(rendered) {
			continue
		}
		c := rendered[i]
		t.Logf("  REJECTED %s: 0x%08X %q: %s", c.id, c.word, c.text, why)
		rejectedShown++
	}

	if noPrintCount != 0 {
		t.Errorf("%s: %d/%d calls could not be rendered for the independent assembler",
			ledger, noPrintCount, len(ids))
	}
	if len(res.rejected) != 0 {
		t.Errorf("%s: %d rendered calls were rejected by LLVM for reasons other than an unsupported extension",
			ledger, len(res.rejected))
	}
	if wrong != 0 {
		t.Errorf("%s: %d generated calls were not byte-identical to LLVM", ledger, wrong)
	}
	if os.Getenv("MKASM_LLVM_REQUIRE_ALL") == "1" && len(res.unsupported) != 0 {
		t.Errorf("%s: %d calls were unsupported by LLVM and therefore unverified", ledger, len(res.unsupported))
	}
	if os.Getenv("MKASM_LLVM_REQUIRE_ALL") == "1" && toolchainDivergence != 0 {
		t.Errorf("%s: %d calls matched only a documented toolchain divergence, not the ARM XML word",
			ledger, toolchainDivergence)
	}
	if os.Getenv("MKASM_LLVM_REQUIRE_ALL") == "1" && exact != len(ids) {
		t.Errorf("%s: strict conformance verified %d/%d calls exactly", ledger, exact, len(ids))
	}
}

func illegalSampleSummary(id string, form *arm.DisasmForm, word uint32) string {
	for _, part := range form.Parts {
		if part.Op == nil {
			continue
		}
		if _, ok := part.Op.Render(word); !ok {
			return fmt.Sprintf("%s[%s %s word=%08x parts=%v cols=%v rows=%v formulas=%v]",
				id, part.Op.Symbol, part.Op.Kind, word, part.Op.Parts,
				part.Op.Cols, part.Op.Rows, part.Op.Formulas)
		}
	}
	return fmt.Sprintf("%s[form-constraints word=%08x mask=%08x value=%08x equal=%v unequal=%v onehot=%v forbidden=%v sve-mask=%v]",
		id, word, form.ConstraintMask, form.ConstraintValue, form.EqualFields,
		form.UnequalFields, form.OneHotMasks, form.Forbidden, form.SVEMoveMaskField)
}

func rejectReasonBucket(reason string) string {
	switch {
	case strings.Contains(reason, "expected first even register"):
		return "register pair must start even"
	case strings.Contains(reason, "invalid element width"):
		return "invalid element width"
	case strings.Contains(reason, "immediate must be an integer in range"):
		return "immediate outside architectural range"
	case strings.Contains(reason, "invalid operand for instruction"):
		return "invalid operand combination"
	case strings.Contains(reason, "immediate value expected for prefetch operand"):
		return "prefetch operation rendered as symbol instead of immediate"
	case strings.Contains(reason, "unrecognized instruction mnemonic"):
		return "instruction unsupported by LLVM"
	case strings.Contains(reason, "expected an even-numbered x-register"):
		return "restricted register must be even"
	case strings.Contains(reason, "expected 'lsl'") ||
		strings.Contains(reason, "expected 'sxtx'") ||
		strings.Contains(reason, "expected 'uxtw'"):
		return "invalid extend or shift combination"
	default:
		return reason
	}
}

type namedCount struct {
	name  string
	count int
}

func sortedCounts(counts map[string]int) []namedCount {
	out := make([]namedCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, namedCount{name, count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].name < out[j].name
	})
	return out
}

func printModelReasonBucket(reason string) string {
	switch {
	case strings.Contains(reason, "operand is algorithmic"):
		return "algorithmic operand inversion"
	case strings.Contains(reason, "operand is computed per row"):
		return "per-row decode formula"
	case strings.Contains(reason, "has no register bank"):
		return "operand class has no print rule"
	case strings.Contains(reason, "absent from encoding"):
		return "field reference absent from encoding"
	case strings.Contains(reason, "fully pinned"):
		return "operand field fully pinned"
	case strings.Contains(reason, "non-contiguous free bits"):
		return "operand field has non-contiguous free bits"
	case strings.Contains(reason, "value table row"):
		return "value-table shape mismatch"
	case strings.Contains(reason, "no encoding field"):
		return "operand has no encoding field"
	case strings.Contains(reason, "states no relation"):
		return "derived operand has no relation"
	case reason == "":
		return "missing skip reason"
	default:
		return reason
	}
}

func movprfxFollower(text string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) < 3 || !strings.EqualFold(fields[0], "MOVPRFX") {
		return "", false
	}
	dest := strings.TrimSuffix(fields[1], ",")
	if len(fields) == 3 {
		return fmt.Sprintf("ADD %s.s, p0/m, %s.s, z0.s", dest, dest), true
	}
	if len(fields) == 4 {
		predicate := strings.TrimSuffix(fields[2], ",")
		if len(predicate) < 2 || !strings.EqualFold(predicate[len(predicate)-2:], "/z") {
			return "", false
		}
		predicate = predicate[:len(predicate)-2] + "/m"
		dot := strings.LastIndexByte(dest, '.')
		if dot < 0 || dot+1 == len(dest) {
			return "", false
		}
		return fmt.Sprintf("ADD %s, %s, %s, z0.%s",
			dest, predicate, dest, dest[dot+1:]), true
	}
	return "", false
}

func verifyWithLLVMCFallback(t *testing.T, rendered []renderedCase, res *asmResult) int {
	t.Helper()
	mc := findLLVMMC(t)
	if mc == "" {
		return 0
	}
	verified := 0
	for i, c := range rendered {
		_, unsupported := res.unsupported[i]
		_, rejected := res.rejected[i]
		known := knownLLVMEncodingDivergence[c.id]
		got, assembled := res.words[i]
		if !unsupported && !rejected &&
			(!assembled || got == c.word || known == (llvmEncodingDivergence{})) {
			continue
		}
		word, err := assembleWithLLVMMC(mc, c.text)
		if err != nil {
			if llvmMCMissingInstruction(err) {
				res.unsupported[i] = true
				delete(res.rejected, i)
				continue
			}
			if os.Getenv("MKASM_LLVM_VERBOSE") == "1" {
				t.Logf("  llvm-mc could not verify %s: %v", c.id, err)
			}
			continue
		}
		res.words[i] = word
		delete(res.unsupported, i)
		delete(res.rejected, i)
		verified++
	}
	return verified
}

func llvmMCMissingInstruction(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "unrecognized instruction mnemonic") ||
		strings.Contains(text, "unknown mnemonic")
}

func findLLVMMC(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("MKASM_LLVM_MC"); configured != "" {
		if mc, err := exec.LookPath(configured); err == nil {
			return mc
		} else {
			t.Fatalf("MKASM_LLVM_MC=%q: %v", configured, err)
		}
	}
	if mc, err := exec.LookPath("llvm-mc"); err == nil {
		return mc
	}
	for _, candidate := range []string{
		"/opt/homebrew/opt/llvm/bin/llvm-mc",
		"/usr/local/opt/llvm/bin/llvm-mc",
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

var llvmMCEncodingRE = regexp.MustCompile(`encoding:\s*\[(0x[0-9a-fA-F]{2}),\s*(0x[0-9a-fA-F]{2}),\s*(0x[0-9a-fA-F]{2}),\s*(0x[0-9a-fA-F]{2})\]`)

func assembleWithLLVMMC(mc, text string) (uint32, error) {
	features := map[string]bool{}
	for round := 0; round < 16; round++ {
		args := []string{"-triple=aarch64", "-show-encoding"}
		if len(features) != 0 {
			names := make([]string, 0, len(features))
			for name := range features {
				names = append(names, "+"+name)
			}
			sort.Strings(names)
			args = append(args, "-mattr="+strings.Join(names, ","))
		}
		cmd := exec.Command(mc, args...)
		cmd.Stdin = strings.NewReader(text + "\n")
		out, err := cmd.CombinedOutput()
		if err == nil {
			match := llvmMCEncodingRE.FindSubmatch(out)
			if match == nil {
				return 0, fmt.Errorf("no encoding in output %q", out)
			}
			var word uint32
			for i := 1; i <= 4; i++ {
				value, parseErr := strconv.ParseUint(string(match[i][2:]), 16, 8)
				if parseErr != nil {
					return 0, parseErr
				}
				word |= uint32(value) << uint(8*(i-1))
			}
			return word, nil
		}
		added := false
		for _, name := range requiredLLVMFeatures(string(out)) {
			if !features[name] {
				features[name] = true
				added = true
			}
		}
		if !added {
			return 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return 0, fmt.Errorf("llvm-mc feature discovery did not converge")
}

func requiredLLVMFeatures(output string) []string {
	seen := map[string]bool{}
	var features []string
	for _, line := range strings.Split(output, "\n") {
		marker := "instruction requires:"
		at := strings.Index(line, marker)
		if at < 0 {
			marker = " requires:"
			at = strings.LastIndex(line, marker)
		}
		if at < 0 {
			continue
		}
		rest := strings.ToLower(line[at+len(marker):])
		for i := 0; i < len(rest); {
			for i < len(rest) && !llvmFeatureByte(rest[i]) {
				i++
			}
			start := i
			for i < len(rest) && llvmFeatureByte(rest[i]) {
				i++
			}
			if start == i {
				break
			}
			name := rest[start:i]
			if name == "or" || name == "and" || seen[name] {
				continue
			}
			seen[name] = true
			features = append(features, name)
		}
	}
	sort.Strings(features)
	return features
}

func llvmFeatureByte(b byte) bool {
	return b >= 'a' && b <= 'z' ||
		b >= '0' && b <= '9' ||
		b == '.' || b == '_' || b == '-'
}

func TestMovprfxFollower(t *testing.T) {
	tests := []struct {
		text string
		want string
		ok   bool
	}{
		{"MOVPRFX z1, z2", "ADD z1.s, p0/m, z1.s, z0.s", true},
		{"MOVPRFX z1.b, p2/z, z4.b", "ADD z1.b, p2/m, z1.b, z0.b", true},
		{"ADD z1.s, z2.s, z3.s", "", false},
	}
	for _, test := range tests {
		got, ok := movprfxFollower(test.text)
		if got != test.want || ok != test.ok {
			t.Errorf("movprfxFollower(%q) = %q, %v; want %q, %v",
				test.text, got, ok, test.want, test.ok)
		}
	}
}

func TestRequiredLLVMFeatures(t *testing.T) {
	got := requiredLLVMFeatures("error: instruction requires: sme2p3 or sve2p3\n")
	want := []string{"sme2p3", "sve2p3"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("features = %v, want %v", got, want)
	}
	got = requiredLLVMFeatures("error: GIC cddis requires: gcie\n")
	if fmt.Sprint(got) != "[gcie]" {
		t.Fatalf("operation feature = %v, want [gcie]", got)
	}
}

func TestLLVMMCMissingInstruction(t *testing.T) {
	if !llvmMCMissingInstruction(fmt.Errorf("error: unrecognized instruction mnemonic")) {
		t.Fatal("unrecognized mnemonic was not classified as unsupported")
	}
	if llvmMCMissingInstruction(fmt.Errorf("error: invalid operand")) {
		t.Fatal("invalid operand was classified as unsupported")
	}
}

func TestLLVMMCFeatureEncodings(t *testing.T) {
	mc := findLLVMMC(t)
	if mc == "" {
		t.Skip("llvm-mc is not installed")
	}
	tests := []struct {
		text string
		word uint32
	}{
		{"PSB CSYNC", 0xD503223F},
		{"PACIASPPC", 0xDAC1A3FE},
		{"STSHH STRM", 0xD503263F},
		{"SCVTF z1.h, z2.b", 0x654C3041},
	}
	for _, test := range tests {
		got, err := assembleWithLLVMMC(mc, test.text)
		if err != nil {
			t.Fatalf("assemble %q: %v", test.text, err)
		}
		if got != test.word {
			t.Errorf("assemble %q = 0x%08X, want 0x%08X", test.text, got, test.word)
		}
	}
}

type llvmEncodingDivergence struct {
	specWord uint32
	llvmWord uint32
}

// Apple LLVM 21 accepts STSHH but still emits its pre-final PCDPHINT opcode.
// The current ARM XML fixes the unnamed opcode bits to the specWord below.
// Pinning both sides makes this an explicit toolchain-version exception rather
// than a wildcard that could hide a future mkasm regression.
var knownLLVMEncodingDivergence = map[string]llvmEncodingDivergence{
	"STSHH_HI_hints": {specWord: 0xD503261F, llvmWord: 0xD501961F},
}

var conformanceLineRE = regexp.MustCompile(`(?m)^(\d+)\t([^\t]+)\t([0-9A-F]{8})$`)

func parseRustConformanceWords(t *testing.T, raw []byte, cases []arm.RustConformanceCase) []uint32 {
	t.Helper()
	return parseConformanceWords(t, "Rust", raw, rustCaseIDs(cases))
}

func parseConformanceWords(t *testing.T, language string, raw []byte, ids []string) []uint32 {
	t.Helper()
	words := make([]uint32, len(ids))
	seen := make([]bool, len(ids))
	for _, m := range conformanceLineRE.FindAllSubmatch(raw, -1) {
		i64, err1 := strconv.ParseUint(string(m[1]), 10, 32)
		w64, err2 := strconv.ParseUint(string(m[3]), 16, 32)
		i := int(i64)
		if err1 != nil || err2 != nil || i < 0 || i >= len(ids) {
			t.Fatalf("bad %s conformance output line %q", language, m[0])
		}
		if got, want := string(m[2]), ids[i]; got != want {
			t.Fatalf("%s conformance case %d identified as %q, want %q", language, i, got, want)
		}
		words[i], seen[i] = uint32(w64), true
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("%s conformance runner omitted case %d (%s); output tail:\n%.2000s",
				language, i, ids[i], raw)
		}
	}
	return words
}

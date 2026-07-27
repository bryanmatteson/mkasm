package conformance_test

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/arm"
	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// The only external oracle in this repo that runs on an ordinary machine.
//
// Every other check compares one parse of ARM's XML against itself: the same
// field table drives the encoder and the decoder, so a field read wrong at parse
// time stays green everywhere. This test hands the disassembler's own output to
// a toolchain that never saw that XML, and requires the word to come back.
//
// A rendered instruction that assembles to the word it was rendered from is
// right for the reasons that matter — the operands are in the fields ARM says,
// scaled and biased as ARM says, spelled from the bank ARM says. A rendered
// instruction that assembles to a different word is a bug the round-trip tests
// structurally cannot see, because both of their sides come from the same table.

const (
	// The floor below which the test fails. Measured before this test existed:
	// nothing rendered at all, so any regression is a regression against a
	// verified number rather than against an aspiration.
	parityAssembleFloor = 0.90
	parityExactFloor    = 0.98
)

func TestDisasmAssemblesBack(t *testing.T) {
	if os.Getenv("MKASM_DISASM_LLVM_PARITY") != "1" {
		t.Skip("set MKASM_DISASM_LLVM_PARITY=1 to run the full external parity corpus")
	}
	if testing.Short() {
		t.Skip("full ISA parse plus assembler round-trip")
	}
	cc := findClang(t)

	p, _ := loadCorpusParser(t, parserOptions{})
	surface := p.DisasmSurface()
	byID := map[string]*ir.InstructionIR{}
	for _, instr := range p.ResolvedInstructions() {
		byID[instr.EncodingID] = instr
	}

	var samples []renderedCase
	movprfx := 0
	rng := rand.New(rand.NewSource(20260725))
	for i := range surface.Forms {
		f := &surface.Forms[i]
		instr := byID[f.EncodingID]
		if instr == nil {
			continue
		}
		word, ok := legalWord(instr, rng)
		if !ok {
			continue
		}
		word, ok = f.SatisfyConstraints(word)
		if !ok || !ir.MatchWord(instr, word) {
			continue
		}
		text, ok := f.Render(word)
		if !ok || strings.TrimSpace(text) == "" {
			continue
		}
		if follower, paired := movprfxFollower(text); paired {
			// Supply the destructive following instruction required by MOVPRFX.
			// assembleLines tracks variable-width samples and still attributes
			// the first emitted word to this form.
			text += "\n" + follower
			movprfx++
		}
		samples = append(samples, renderedCase{
			call: len(samples),
			id:   f.EncodingID,
			word: word,
			text: text,
		})
	}
	if len(samples) == 0 {
		t.Fatal("no samples rendered")
	}

	dir := t.TempDir()
	lines := make([]string, len(samples))
	for i, s := range samples {
		lines[i] = s.text
	}
	res := assembleLines(t, cc, dir, lines)
	mcFallbacks := verifyWithLLVMCFallback(t, samples, &res)

	var exact, wrong int
	var firstWrong []string
	for i, s := range samples {
		w, ok := res.words[i]
		if !ok {
			continue
		}
		if w == s.word {
			exact++
			continue
		}
		wrong++
		if len(firstWrong) < 25 {
			firstWrong = append(firstWrong, fmt.Sprintf(
				"%s: rendered %q from 0x%08X, assembles to 0x%08X", s.id, s.text, s.word, w))
		}
	}

	// An instruction this toolchain has never heard of tells us nothing either
	// way, so it is excluded rather than counted against the disassembler.
	checkable := len(samples) - len(res.unsupported)
	accepted := len(res.words)
	asmPct, exactPct := 0.0, 0.0
	if checkable > 0 {
		asmPct = float64(accepted) / float64(checkable)
	}
	if accepted > 0 {
		exactPct = float64(exact) / float64(accepted)
	}
	t.Logf("rendered=%d movprfx-paired=%d llvm-mc-fallbacks=%d unsupported-by-toolchain=%d checkable=%d assembled=%d (%.1f%%) exact=%d (%.1f%%) wrong=%d",
		len(samples), movprfx, mcFallbacks, len(res.unsupported), checkable, accepted, 100*asmPct, exact, 100*exactPct, wrong)

	byReason := map[string]int{}
	var rejectedSamples []string
	for i, why := range res.rejected {
		byReason[rejectBucket(why)]++
		if len(rejectedSamples) < 25 && i >= 0 && i < len(samples) {
			rejectedSamples = append(rejectedSamples, fmt.Sprintf(
				"%s: %q from 0x%08X: %s",
				samples[i].id, samples[i].text, samples[i].word, why))
		}
	}
	for _, r := range sortedKeys(toSet(byReason)) {
		t.Logf("  rejected %5d  %s", byReason[r], r)
	}
	sort.Strings(rejectedSamples)
	for _, sample := range rejectedSamples {
		t.Logf("  REJECTED %s", sample)
	}
	for _, w := range firstWrong {
		t.Logf("  WRONG %s", w)
	}

	if os.Getenv("MKASM_DISASM_AUDIT") == "1" {
		if asmPct < parityAssembleFloor {
			t.Errorf("only %.1f%% of checkable rendered instructions assemble, want >= %.0f%%",
				100*asmPct, 100*parityAssembleFloor)
		}
		if exactPct < parityExactFloor {
			t.Errorf("only %.1f%% of assembled instructions reproduce their word, want >= %.0f%%",
				100*exactPct, 100*parityExactFloor)
		}
	} else {
		if len(res.rejected) != 0 {
			t.Errorf("%d rendered instructions were rejected by the independent assembler", len(res.rejected))
		}
		if wrong != 0 {
			t.Errorf("%d rendered instructions did not reassemble to identical bytes", wrong)
		}
		if exact != checkable {
			t.Errorf("supported-instruction disassembly conformance verified %d/%d exactly",
				exact, checkable)
		}
	}
	if os.Getenv("MKASM_DISASM_REQUIRE_ALL") == "1" {
		if len(res.unsupported) != 0 {
			t.Errorf("%d rendered instructions are unsupported and unverified", len(res.unsupported))
		}
		if exact != len(samples) {
			t.Errorf("strict disassembly conformance verified %d/%d rendered instructions exactly",
				exact, len(samples))
		}
	}
}

func toSet(m map[string]int) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// rejectBucket groups assembler complaints so the tail is readable. The text
// after the operand name varies per instruction and would otherwise give every
// rejection its own line.
func rejectBucket(why string) string {
	switch {
	case strings.Contains(why, "invalid operand"):
		return "invalid operand"
	case strings.Contains(why, "expected") && strings.Contains(why, "range"):
		return "operand out of range"
	case strings.Contains(why, "unrecognized instruction mnemonic"):
		return "unknown mnemonic"
	case strings.Contains(why, "too few operands"):
		return "too few operands"
	case strings.Contains(why, "unexpected token"):
		return "unexpected token"
	case strings.Contains(why, "immediate must be"):
		return "immediate out of range"
	case strings.Contains(why, "index must be"):
		return "index out of range"
	case strings.Contains(why, "expected"):
		return "expected different syntax"
	}
	return why
}

// legalWord builds a word this encoding accepts: its pinned bits, its variable
// fields filled pseudorandomly, and its own bitdiffs constraints satisfied.
//
// Filling the variable bits with zero instead would exercise only the one input
// class every existing decode test already uses, and is exactly the class in
// which a field-placement error is invisible — a zero operand lands correctly
// wherever it is put.
//
// Fields wider than a register number are held to small values. ARM states the
// legal range of a shift amount or an extend amount in pseudocode rather than in
// the encoding, so this generator cannot honour it; a uniformly random imm6
// would spend most of its draws on words that are UNDEFINED and measure the
// assembler's range checking instead of this disassembler's placement.
func legalWord(instr *ir.InstructionIR, rng *rand.Rand) (uint32, bool) {
	mask, value := ir.FixedBitsFromPattern(instr.BitPattern)
	if mask == 0 {
		return 0, false
	}
	for try := 0; try < 64; try++ {
		w := value
		for _, f := range instr.Encoding.Fields {
			if f.Start < 0 || f.End < f.Start || f.End > 31 {
				continue
			}
			width := f.End - f.Start + 1
			limit := uint32(1) << uint(width)
			if width > 5 {
				limit = 8
			}
			free := fieldRangeMaskTest(f.Start, f.End) &^ mask
			if free == 0 {
				continue
			}
			w |= (rng.Uint32() % limit << uint(f.Start)) & free
		}
		if ir.MatchWord(instr, w) {
			return w, true
		}
	}
	return 0, false
}

func fieldRangeMaskTest(start, end int) uint32 {
	width := uint(end - start + 1)
	if width >= 32 {
		return ^uint32(0)
	}
	return uint32((uint64(1)<<width)-1) << uint(start)
}

var (
	asmErrorRE    = regexp.MustCompile(`(?m)^[^:\n]*:(\d+):\d+: error: (.*)$`)
	needFeatureRE = regexp.MustCompile(`^instruction requires: ([a-z0-9][a-z0-9._-]*)`)
	noFeatureRE   = regexp.MustCompile(`unsupported architectural extension: ([a-z0-9][a-z0-9._-]*)`)
)

// asmResult is what the assembler made of the rendered text.
type asmResult struct {
	// words holds the encoding of each accepted line, by index into lines.
	words map[int]uint32
	// unsupported are the lines this toolchain rejected for an architecture
	// extension it does not know. The Xcode assembler can be older than the
	// selected corpus, so these are unverifiable here rather than wrong.
	unsupported map[int]bool
	// rejected are the lines it rejected on their text.
	rejected map[int]string
}

// assembleLines assembles one instruction per sample.
//
// The feature set is discovered rather than declared: clang names the extension
// each instruction needs, so the first rounds collect those names and re-arm
// .arch with them, dropping any the toolchain does not recognise. Hardcoding the
// list instead would silently stop verifying a whole extension the day the spec
// gains one, which is the failure mode this test exists to prevent.
//
// Every sample is followed by a spelled NOP. This is not padding for alignment:
// it makes every instruction its own semantic context. MOVPRFX constrains the
// instruction immediately following it. A raw .inst has no parsed instruction
// semantics and therefore does not reliably clear LLVM's MOVPRFX state.
func assembleLines(t *testing.T, cc, dir string, lines []string) asmResult {
	t.Helper()
	res := asmResult{
		words:       map[int]uint32{},
		unsupported: map[int]bool{},
		rejected:    map[int]string{},
	}
	features := map[string]bool{
		"sve2": true, "sme2": true, "crypto": true, "bf16": true,
		"i8mm": true, "fp16": true, "mte": true,
	}
	// An extension this toolchain rejects must never be offered again, or the
	// loop alternates between adding it because an instruction asks for it and
	// dropping it because .arch will not take it.
	banned := map[string]bool{}
	live := make([]int, 0, len(lines))
	for i, line := range lines {
		if isolated, ok := isolatedADRPSource(line); ok {
			src := filepath.Join(dir, fmt.Sprintf("adrp-%d.s", i))
			obj := filepath.Join(dir, fmt.Sprintf("adrp-%d.o", i))
			source := ".text\n" + isolated + "\nnop\n"
			if err := os.WriteFile(src, []byte(source), 0644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(cc, "-c", "-target", "arm64-apple-macos",
				"-o", obj, src).CombinedOutput(); err != nil {
				res.rejected[i] = strings.TrimSpace(string(out))
			} else {
				for _, word := range disassembleWords(t, obj, map[int]int{i: 0}, 2) {
					res.words[i] = word
				}
			}
			continue
		}
		live = append(live, i)
	}

	for round := 0; round < 60 && len(live) > 0; round++ {
		src := filepath.Join(dir, fmt.Sprintf("r%d.s", round))
		obj := filepath.Join(dir, fmt.Sprintf("r%d.o", round))
		var b strings.Builder
		b.WriteString(".arch armv9.5-a")
		for _, f := range sortedKeys(features) {
			b.WriteString("+" + f)
		}
		b.WriteString("\n.text\n")
		lineToIndex := map[int]int{}
		sourceLine := 3
		wordPositions := make(map[int]int, len(live))
		wordCount := 0
		for _, i := range live {
			instructionLines := nonEmptyLineCount(lines[i])
			for line := range instructionLines {
				lineToIndex[sourceLine+line] = i
			}
			wordPositions[i] = wordCount
			b.WriteString(lines[i])
			b.WriteByte('\n')
			sourceLine += instructionLines
			wordCount += instructionLines
			b.WriteString("nop\n")
			sourceLine++
			wordCount++
		}
		if err := os.WriteFile(src, []byte(b.String()), 0644); err != nil {
			t.Fatal(err)
		}
		// Without an unlimited error budget clang stops after twenty errors and
		// this loop would need one round per twenty rejected lines.
		out, err := exec.Command(cc, "-c", "-target", "arm64-apple-macos",
			"-ferror-limit=0", "-o", obj, src).CombinedOutput()
		if err == nil {
			for k, v := range disassembleWords(t, obj, wordPositions, wordCount) {
				res.words[k] = v
				// A line can be provisionally rejected before feature
				// discovery converges, then assemble in the final round.
				// Keep the result census disjoint.
				delete(res.rejected, k)
				delete(res.unsupported, k)
			}
			return res
		}

		// An unrecognised extension invalidates the whole .arch line, so it must
		// be dropped and the round retried before any line is judged.
		if m := noFeatureRE.FindAllStringSubmatch(string(out), -1); len(m) > 0 {
			for _, mm := range m {
				delete(features, mm[1])
				banned[mm[1]] = true
			}
			continue
		}

		bad := map[int]bool{}
		gained := false
		for _, m := range asmErrorRE.FindAllStringSubmatch(string(out), -1) {
			n, convErr := strconv.Atoi(m[1])
			if convErr != nil {
				continue
			}
			idx, ok := lineToIndex[n]
			// Apple clang occasionally reports an operand diagnostic on the
			// following .inst separator's line. The diagnostic still prints the
			// sample text, and the immediately preceding source line is the only
			// instruction that can own it.
			if !ok {
				idx, ok = lineToIndex[n-1]
			}
			if !ok {
				continue
			}
			if strings.Contains(m[2], "movprfx") {
				// MOVPRFX itself is excluded by the caller. If clang still
				// diagnoses one here, attribute it to this isolated sample
				// rather than poisoning its neighbour.
				bad[idx] = true
				res.unsupported[idx] = true
				continue
			}
			if fm := needFeatureRE.FindStringSubmatch(m[2]); fm != nil {
				if !features[fm[1]] && !banned[fm[1]] {
					features[fm[1]] = true
					gained = true
					continue
				}
				res.unsupported[idx] = true
				bad[idx] = true
				continue
			}
			res.rejected[idx] = m[2]
			bad[idx] = true
		}
		if gained {
			// Re-arm with the newly named extensions before dropping anything:
			// a line rejected for a feature this round may assemble next round.
			for idx := range bad {
				if res.unsupported[idx] {
					continue
				}
				delete(res.rejected, idx)
			}
			continue
		}
		if len(bad) == 0 {
			detail := ""
			if m := asmErrorRE.FindStringSubmatch(string(out)); m != nil {
				if n, convErr := strconv.Atoi(m[1]); convErr == nil {
					srcLines := strings.Split(b.String(), "\n")
					if n > 0 && n <= len(srcLines) {
						detail = fmt.Sprintf("\nsource line %d=%q mapped=%v",
							n, srcLines[n-1], lineToIndex[n])
					}
				}
			}
			t.Fatalf("assembler failed with no attributable line%s:\n%s", detail, out)
		}
		if round > 8 && round < 12 {
			t.Logf("ROUND %d bad=%d raw:\n%.2000s", round, len(bad), out)
		}
		next := live[:0:0]
		for _, i := range live {
			if !bad[i] {
				next = append(next, i)
			}
		}
		live = next
	}
	if len(live) > 0 {
		t.Fatalf("assembler did not converge, %d lines left", len(live))
	}
	return res
}

// isolatedADRPSource converts the decoder's location-relative spelling to the
// absolute numeric syntax accepted by the Darwin assembler. Mach-O otherwise
// requires an @PAGE relocation and leaves zeroes in the object, which cannot
// prove the immediate bits. Assembling this one instruction at PC=0 makes the
// numeric target equal to the decoded relative offset and yields final bytes.
func isolatedADRPSource(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "ADRP ") {
		return "", false
	}
	comma := strings.LastIndexByte(trimmed, ',')
	if comma < 0 {
		return "", false
	}
	target := strings.TrimSpace(trimmed[comma+1:])
	sign := int64(1)
	switch {
	case strings.HasPrefix(target, ".+"):
		target = target[2:]
	case strings.HasPrefix(target, ".-"):
		target = target[2:]
		sign = -1
	default:
		return "", false
	}
	offset, err := strconv.ParseInt(target, 10, 64)
	if err != nil {
		return "", false
	}
	return trimmed[:comma+1] + " " + strconv.FormatInt(sign*offset, 10), true
}

func nonEmptyLineCount(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func TestIsolatedADRPSource(t *testing.T) {
	for _, test := range []struct {
		in, want string
		ok       bool
	}{
		{"ADRP x4, .+4096", "ADRP x4, 4096", true},
		{"adrp x4, .-8192", "adrp x4, -8192", true},
		{"ADR x4, .+4", "", false},
	} {
		got, ok := isolatedADRPSource(test.in)
		if got != test.want || ok != test.ok {
			t.Errorf("isolatedADRPSource(%q) = %q, %v; want %q, %v",
				test.in, got, ok, test.want, test.ok)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// disassembleWords reads back the encoded sample words in source order,
// ignoring the separator words between them.
func disassembleWords(t *testing.T, obj string, positions map[int]int, expectedWords int) map[int]uint32 {
	t.Helper()
	out, err := exec.Command("xcrun", "objdump", "-d", "--section=__text", obj).Output()
	if err != nil {
		t.Fatalf("objdump: %v", err)
	}
	atWord := make(map[int]int, len(positions))
	for sample, position := range positions {
		atWord[position] = sample
	}
	words := make(map[int]uint32, len(positions))
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	n := 0
	wordRE := regexp.MustCompile(`^\s+[0-9a-f]+:\s+([0-9a-f]{8})\s`)
	for sc.Scan() {
		m := wordRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v, err := strconv.ParseUint(m[1], 16, 32)
		if err != nil {
			continue
		}
		if sample, ok := atWord[n]; ok {
			words[sample] = uint32(v)
		}
		n++
	}
	if n != expectedWords {
		t.Fatalf("objdump returned %d words, expected %d", n, expectedWords)
	}
	return words
}

func findClang(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("MKASM_CLANG"); configured != "" {
		cc, err := exec.LookPath(configured)
		if err != nil {
			t.Fatalf("MKASM_CLANG=%q: %v", configured, err)
		}
		return cc
	}
	out, err := exec.Command("xcrun", "--find", "clang").Output()
	if err != nil {
		if cc, lookErr := exec.LookPath("clang"); lookErr == nil {
			return cc
		}
		t.Skipf("no clang to assemble against: %v", err)
	}
	return strings.TrimSpace(string(out))
}

var _ = arm.RegisterName

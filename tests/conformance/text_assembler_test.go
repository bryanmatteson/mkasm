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

// TestTextAssemblerLLVMParity checks the generated Rust text assembler
// against LLVM's assembler.
//
// Two spelling sets are checked. The first is the generated formatter's own
// text for the disassembly-parity samples: LLVM assembles it to a word, and
// the text assembler must return that word first. The second is LLVM's
// spelling of the same words (llvm-mc --disassemble): LLVM accepts its own
// output, so the text assembler must accept it too and again return LLVM's
// word first. Lines LLVM cannot assemble or print are unsupported here and
// counted separately, never as passing.
func TestTextAssemblerLLVMParity(t *testing.T) {
	if os.Getenv("MKASM_TEXT_ASM_LLVM_PARITY") != "1" {
		t.Skip("set MKASM_TEXT_ASM_LLVM_PARITY=1 to run the text-assembler LLVM parity corpus")
	}
	if testing.Short() {
		t.Skip("full Rust generation, compile, and LLVM byte comparison")
	}
	cc := findClang(t)
	mc := findLLVMMC(t)
	if mc == "" {
		t.Fatal("llvm-mc is required for LLVM's spelling of each word")
	}
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Fatalf("cargo is required by the text assembler gate: %v", err)
	}

	p, outDir := loadCorpusParser(t, parserOptions{codegen: arm.LangRust})
	surface := p.DisasmSurface()
	byID := map[string]*ir.InstructionIR{}
	for _, instr := range p.ResolvedInstructions() {
		byID[instr.EncodingID] = instr
	}

	var samples []renderedCase
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
			text += "\n" + follower
		}
		samples = append(samples, renderedCase{call: len(samples), id: f.EncodingID, word: word, text: text})
	}
	lines := make([]string, len(samples))
	for i := range samples {
		lines[i] = samples[i].text
	}
	res := assembleLines(t, cc, t.TempDir(), lines)
	verifyWithLLVMCFallback(t, samples, &res)

	// Only the words LLVM produced are oracle words.
	var accepted []int
	for i := range samples {
		if _, ok := res.words[i]; ok {
			accepted = append(accepted, i)
		}
	}
	llvmText := disassembleWithLLVMMC(t, mc, accepted, res.words)

	var input strings.Builder
	type query struct {
		set    string
		sample int
		text   string
		word   uint32
	}
	var queries []query
	for _, i := range accepted {
		own := strings.SplitN(samples[i].text, "\n", 2)[0]
		queries = append(queries, query{"formatter", i, own, res.words[i]})
		if text, ok := llvmText[i]; ok {
			queries = append(queries, query{"llvm", i, text, res.words[i]})
		}
	}
	for _, q := range queries {
		fmt.Fprintf(&input, "0\t%s\n", q.text)
	}
	cmd := exec.Command(cargo, "run", "--quiet", "--example", "assemble")
	cmd.Dir = outDir
	cmd.Stdin = strings.NewReader(input.String())
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("run generated assemble example: %v", err)
	}
	answers := parseAssembleOutput(t, raw, len(queries))

	type tally struct{ total, first, later, absent, rejected int }
	counts := map[string]*tally{"formatter": {}, "llvm": {}}
	failures := map[string][]string{}
	rejectReasons := map[string]map[string]int{"formatter": {}, "llvm": {}}
	for k, q := range queries {
		c := counts[q.set]
		c.total++
		a := answers[k]
		sample := samples[q.sample]
		switch {
		case a.err != "":
			c.rejected++
			rejectReasons[q.set][textAssemblerErrorBucket(a.err)]++
			failures[q.set] = append(failures[q.set], fmt.Sprintf("%s: %q (LLVM 0x%08X): %s", sample.id, q.text, q.word, a.err))
		case len(a.words) > 0 && a.words[0] == q.word:
			c.first++
		case containsWord(a.words, q.word):
			c.later++
			failures[q.set] = append(failures[q.set], fmt.Sprintf("%s: %q LLVM 0x%08X is not first in %08X", sample.id, q.text, q.word, a.words))
		default:
			c.absent++
			failures[q.set] = append(failures[q.set], fmt.Sprintf("%s: %q LLVM 0x%08X missing from %08X", sample.id, q.text, q.word, a.words))
		}
	}
	unsupported := len(samples) - len(accepted)
	t.Logf("samples=%d llvm-assembled=%d unsupported-or-rejected-by-LLVM=%d llvm-printed=%d", len(samples), len(accepted), unsupported, len(llvmText))
	t.Logf("| Spelling | Checked | LLVM word first | Later | Absent | Rejected |")
	t.Logf("|---|---:|---:|---:|---:|---:|")
	for _, set := range []string{"formatter", "llvm"} {
		c := counts[set]
		t.Logf("| %s | %d | %d | %d | %d | %d |", set, c.total, c.first, c.later, c.absent, c.rejected)
	}
	for _, set := range []string{"formatter", "llvm"} {
		for _, entry := range sortedCounts(rejectReasons[set]) {
			t.Logf("  %s REJECTED-CAUSE %4d %s", set, entry.count, entry.name)
		}
		list := failures[set]
		sort.Strings(list)
		for i, failure := range list {
			if i == 60 && os.Getenv("MKASM_LLVM_VERBOSE") != "1" {
				t.Logf("  ... %d more", len(list)-i)
				break
			}
			t.Logf("  %s FAIL %s", set, failure)
		}
	}
	if c := counts["formatter"]; c.first != c.total {
		t.Errorf("formatter spellings: %d/%d return LLVM's word first", c.first, c.total)
	}
	if c := counts["llvm"]; c.first != c.total {
		t.Errorf("LLVM spellings: %d/%d return LLVM's word first", c.first, c.total)
	}
}

func containsWord(words []uint32, want uint32) bool {
	for _, word := range words {
		if word == want {
			return true
		}
	}
	return false
}

func textAssemblerErrorBucket(message string) string {
	switch {
	case strings.HasPrefix(message, "unknown mnemonic"):
		return "unknown mnemonic"
	case strings.Contains(message, "out of range"):
		return "out of range"
	case strings.Contains(message, "InvalidRegister"):
		return "invalid register"
	case strings.Contains(message, "MissingOperand"):
		return "missing operand"
	case strings.Contains(message, "ExtraText"):
		return "extra text"
	case strings.Contains(message, "InvalidOperand"):
		return "invalid operand"
	case strings.Contains(message, "Incompatible"):
		return "incompatible operands"
	}
	return message
}

type assembleAnswer struct {
	words []uint32
	err   string
}

func parseAssembleOutput(t *testing.T, raw []byte, want int) []assembleAnswer {
	t.Helper()
	answers := make([]assembleAnswer, want)
	seen := make([]bool, want)
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 3)
		if len(fields) != 3 {
			t.Fatalf("bad assemble output line %q", sc.Text())
		}
		index, err := strconv.Atoi(fields[0])
		if err != nil || index < 0 || index >= want {
			t.Fatalf("bad assemble output index in %q", sc.Text())
		}
		seen[index] = true
		if fields[1] == "ERR" {
			answers[index].err = fields[2]
			continue
		}
		for _, hex := range strings.Fields(fields[2]) {
			word, err := strconv.ParseUint(hex, 16, 32)
			if err != nil {
				t.Fatalf("bad word %q in %q", hex, sc.Text())
			}
			answers[index].words = append(answers[index].words, uint32(word))
		}
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("assemble example omitted line %d", i)
		}
	}
	return answers
}

var llvmMCLineRE = regexp.MustCompile(`<stdin>:(\d+):\d+: (?:warning|error): invalid instruction encoding`)

// disassembleWithLLVMMC returns LLVM's printed spelling of each sample word.
// Words llvm-mc reports as invalid have no entry.
func disassembleWithLLVMMC(t *testing.T, mc string, samples []int, words map[int]uint32) map[int]string {
	t.Helper()
	var in strings.Builder
	for _, i := range samples {
		w := words[i]
		fmt.Fprintf(&in, "0x%02x,0x%02x,0x%02x,0x%02x\n", w&0xff, w>>8&0xff, w>>16&0xff, w>>24)
	}
	dir := t.TempDir()
	stderrPath := filepath.Join(dir, "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(mc, "--disassemble", "-triple=aarch64", "-mattr=+all")
	cmd.Stdin = strings.NewReader(in.String())
	cmd.Stderr = stderr
	out, _ := cmd.Output()
	stderr.Close()
	diag, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[int]bool{}
	for _, m := range llvmMCLineRE.FindAllStringSubmatch(string(diag), -1) {
		line, _ := strconv.Atoi(m[1])
		invalid[line-1] = true
	}
	var printed []string
	for _, line := range strings.Split(string(out), "\n") {
		text := strings.TrimSpace(strings.ReplaceAll(line, "\t", " "))
		if text == "" || strings.HasPrefix(text, ".") {
			continue
		}
		printed = append(printed, strings.Join(strings.Fields(text), " "))
	}
	result := map[int]string{}
	next := 0
	for k, i := range samples {
		if invalid[k] {
			continue
		}
		if next >= len(printed) {
			t.Fatalf("llvm-mc printed %d instructions for %d valid words", len(printed), len(samples)-len(invalid))
		}
		result[i] = printed[next]
		next++
	}
	if next != len(printed) {
		t.Fatalf("llvm-mc printed %d instructions, mapped %d", len(printed), next)
	}
	return result
}

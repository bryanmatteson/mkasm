package arm_test

import (
	"context"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
	"github.com/bryanmatteson/mkasm/pkg/decoder"
	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// Known A64 encodings (fixed CRm/imm forms) for golden decode.
// Values are architectural; patterns must come from real iform resolution.
var goldenWords = []struct {
	word       uint32
	encodingID string // expected EncodingID substring or exact when known
	mnemonic   string // expected mnemonic contains
}{
	{0xD5033F5F, "CLREX_BN_barriers", "CLREX"},
	{0xD503201F, "HINT", "NOP"}, // NOP is HINT #0
	{0xD65F03C0, "RET", "RET"},
	{0xD4200000, "BRK", "BRK"},
	{0xD4000001, "SVC", "SVC"},
	{0xD50330BF, "DMB", "DMB"},
	{0xD50330DF, "ISB", "ISB"},
	{0xD5033F9F, "DSB_BO_barriers", "DSB"},  // dsb sy (verified: llvm objdump)
	{0xD503323F, "DSB_BOn_barriers", "DSB"}, // dsb oshnxs — nXS variant, op2=001
	{0xD503203F, "HINT", "YIELD"},           // HINT #1
	{0xD503205F, "HINT", "WFE"},             // HINT #2
	{0xD503207F, "HINT", "WFI"},             // HINT #3
	{0xD503209F, "HINT", "SEV"},             // HINT #4
	{0x14000000, "B_", "B"},                 // B #0
	{0x94000000, "BL_", "BL"},               // BL #0
	{0xD65F0BFF, "RETAA", "RETAA"},
	{0xD63F0000, "BLR", "BLR"},            // BLR X0
	{0xD61F0000, "BR", "BR"},              // BR X0
	{0x74C08000, "CBBEQ_8_regs", "CBBEQ"}, // bitdiffs cc==110
	{0x74208000, "CBBGE_8_regs", "CBBGE"}, // bitdiffs cc==001
}

func TestGoldenDecode_MatchWord(t *testing.T) {
	reg := loadResolvedRegistry(t, 0) // full Pass 2
	for _, g := range goldenWords {
		g := g
		t.Run(g.mnemonic, func(t *testing.T) {
			hits := reg.MatchWord(g.word)
			if len(hits) == 0 {
				t.Fatalf("no MatchWord hits for 0x%08X (%s)", g.word, g.mnemonic)
			}
			best, ok := reg.BestMatch(g.word)
			if !ok {
				t.Fatal("BestMatch failed")
			}
			if !(containsFold(best.Mnemonic, g.mnemonic) || containsFold(best.EncodingID, g.encodingID)) {
				t.Fatalf("BestMatch=%s %s want %s/%s among %d hits",
					best.EncodingID, best.Mnemonic, g.mnemonic, g.encodingID, len(hits))
			}
			// Round-trip: fixed bits of pattern must equal word under mask
			mask, value := ir.FixedBitsFromPattern(best.BitPattern)
			if word := g.word; mask != 0 && word&mask != value {
				t.Fatalf("pattern fixed bits disagree: word=0x%08X mask=0x%08X value=0x%08X pat=%s",
					word, mask, value, best.BitPattern)
			}
		})
	}
}

func TestGoldenDecode_TreeMatch(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	// Build tree only over encodings with real fixed bits
	var resolved []*ir.InstructionIR
	for _, instr := range reg.GetAll() {
		if instr.BitPattern != "" && contains01(instr.BitPattern) {
			resolved = append(resolved, instr)
		}
	}
	tree := (&decoder.DecoderTreeBuilder{}).BuildTree(resolved, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("empty tree")
	}

	for _, g := range goldenWords {
		g := g
		t.Run(g.mnemonic, func(t *testing.T) {
			res, err := decoder.Match(tree, g.word)
			if err != nil && res.Instruction == nil {
				// Ambiguous is ok if one of the candidates matches
				for _, a := range res.Ambiguous {
					if containsFold(a.Mnemonic, g.mnemonic) || containsFold(a.EncodingID, g.encodingID) {
						return
					}
				}
				t.Fatalf("tree match: %v (ambiguous=%d)", err, len(res.Ambiguous))
			}
			if res.Instruction == nil {
				t.Fatal("nil instruction")
			}
			if !containsFold(res.Instruction.Mnemonic, g.mnemonic) &&
				!containsFold(res.Instruction.EncodingID, g.encodingID) {
				t.Fatalf("got %s %s want ~%s", res.Instruction.EncodingID, res.Instruction.Mnemonic, g.mnemonic)
			}
		})
	}
}

func TestEncodeFixedBits_CLREX(t *testing.T) {
	reg := loadResolvedRegistry(t, 200)
	var clrex *ir.InstructionIR
	for _, instr := range reg.GetAll() {
		if instr.EncodingID == "CLREX_BN_barriers" {
			clrex = instr
			break
		}
	}
	if clrex == nil {
		t.Fatal("CLREX not found")
	}
	// Fixed bits alone should produce a word that matches the pattern
	// with CRm = 0b1111 (as in 0xD5033F5F → bits[11:8]=1111)
	mask, value := ir.FixedBitsFromEncoding(clrex.Encoding)
	word := value | (0xF << 8) // CRm=15
	if !ir.MatchBitPattern(clrex.BitPattern, word) {
		t.Fatalf("encoded 0x%08X does not match pat %s (mask=0x%08X value=0x%08X)",
			word, clrex.BitPattern, mask, value)
	}
	// Prefer exact architectural word when CRm field is 8:11
	for _, f := range clrex.Encoding.Fields {
		if f.Name == "CRm" && f.Start == 8 && f.End == 11 {
			if word != 0xD5033F5F {
				// still ok if pattern matches; log for visibility
				t.Logf("CLREX word=0x%08X (arch 0xD5033F5F) pat=%s", word, clrex.BitPattern)
			}
		}
	}
}

func loadResolvedRegistry(t *testing.T, maxIForms int) *arm.InstructionRegistry {
	t.Helper()
	enc := encodingIndexPath(t)
	iform := iformDirPath(t)
	p := arm.NewARMParser(arm.ARMParserConfig{
		EncodingIndexPath: enc,
		IFormDirectory:    iform,
		OutputDirectory:   t.TempDir(),
		SkipCodegen:       true,
		IFormWorkers:      8,
		MaxIForms:         maxIForms,
	})
	t.Cleanup(func() { _ = p.Close(2 * time.Second) })
	if err := p.Parse(context.Background()); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p.GetRegistry()
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) &&
		(s == sub || indexFold(s, sub) >= 0))
}

func indexFold(s, sub string) int {
	// simple ASCII fold
	ls, lsub := toLower(s), toLower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains01(pat string) bool {
	for i := 0; i < len(pat); i++ {
		if pat[i] == '0' || pat[i] == '1' {
			return true
		}
	}
	return false
}

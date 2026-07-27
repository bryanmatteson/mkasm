package arm_test

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/decoder"
	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// treeCoverageSeed fixes the fills so a regression reproduces from the failure
// message alone.
const treeCoverageSeed = 0x5EED

// treeCoverageFills is how many words each encoding contributes. Four is enough
// to exercise several distinct values of every multi-bit variable field without
// making MatchByPattern's O(n) oracle the runtime of the suite.
const treeCoverageFills = 4

// TestDecodeTreeCoverage_pseudorandomFills walks the decoder tree with words
// whose variable bits are filled pseudorandomly rather than zeroed.
//
// Zeroed variable bits are exactly the input class that hid the misrouting this
// test was written for: groupByMask filed an encoding under the single key
// obtained by zeroing its 'x' bits, so a word that set any of them found no
// child edge and the tree dead-ended. Under this fill the walk resolved 69.3%
// of 18253 words before the fix — the rest fell through to the O(n) table with
// Decoded.Via reporting "table".
func TestDecodeTreeCoverage_pseudorandomFills(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	all := reg.GetAll()
	if len(all) == 0 {
		t.Fatal("resolved registry is empty")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].EncodingID < all[j].EncodingID })

	tree := (&decoder.DecoderTreeBuilder{}).BuildTree(all, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("empty decoder tree")
	}

	rng := rand.New(rand.NewSource(treeCoverageSeed))
	var words, resolved, contributed int
	var firstMiss string

	for _, instr := range all {
		pinned, value := treeCoverPinnedBits(instr)
		if pinned == 0 {
			// No fixed bit anywhere: MatchWord rejects every word for this
			// encoding, so it cannot contribute a decodable fill.
			continue
		}
		before := words
		for k := 0; k < treeCoverageFills; k++ {
			word := value | (rng.Uint32() &^ pinned)
			if !ir.EvalBitDiffs(instr.BitDiffsTree, word) {
				continue
			}
			words++
			res, _ := decoder.Match(tree, word)
			if len(treeCoverHits(res)) > 0 {
				resolved++
				continue
			}
			if firstMiss == "" {
				firstMiss = instr.EncodingID
				t.Logf("first tree miss: 0x%08X (%s pattern %s)", word, instr.EncodingID, instr.BitPattern)
			}
		}
		if words > before {
			contributed++
		}
	}

	if words == 0 {
		t.Fatal("no decodable fills generated")
	}
	if contributed*2 < len(all) {
		t.Fatalf("only %d/%d encodings produced a decodable fill", contributed, len(all))
	}

	pct := 100 * float64(resolved) / float64(words)
	t.Logf("encodings=%d contributing=%d words=%d treeResolved=%d (%.2f%%)",
		len(all), contributed, words, resolved, pct)

	if pct < 99 {
		t.Fatalf("decoder tree resolved %.2f%% of pseudorandom fills, want >= 99%% "+
			"(the rest fall back to the O(n) table)", pct)
	}
}

// TestDecodeTreeAgreesWithTable_pseudorandomFills pins the tree walk to the flat
// matcher: same winner, same peers. A tree that resolves fast but names a
// different encoding, or claims uniqueness the table contradicts, is worse than
// no tree at all.
func TestDecodeTreeAgreesWithTable_pseudorandomFills(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	all := reg.GetAll()
	if len(all) == 0 {
		t.Fatal("resolved registry is empty")
	}
	sort.Slice(all, func(i, j int) bool { return all[i].EncodingID < all[j].EncodingID })

	tree := (&decoder.DecoderTreeBuilder{}).BuildTree(all, nil)
	if tree == nil || tree.Root == nil {
		t.Fatal("empty decoder tree")
	}

	rng := rand.New(rand.NewSource(treeCoverageSeed))
	var compared int

	check := func(word uint32) {
		res, _ := decoder.Match(tree, word)
		fromTree := treeCoverHits(res)
		fromTable := decoder.MatchByPattern(all, word)
		if len(fromTree) == 0 || len(fromTable) == 0 {
			return
		}
		compared++

		treeWin, treePeers := treeCoverRank(fromTree)
		tableWin, tablePeers := treeCoverRank(fromTable)
		if treeWin != tableWin {
			t.Fatalf("0x%08X: tree picked %s, table picked %s", word, treeWin, tableWin)
		}
		if !treeCoverSameIDs(treePeers, tablePeers) {
			t.Fatalf("0x%08X (%s): tree Ambiguous=%v, table Ambiguous=%v",
				word, treeWin, treePeers, tablePeers)
		}
	}

	for _, instr := range all {
		pinned, value := treeCoverPinnedBits(instr)
		if pinned == 0 {
			continue
		}
		for k := 0; k < treeCoverageFills; k++ {
			word := value | (rng.Uint32() &^ pinned)
			if !ir.EvalBitDiffs(instr.BitDiffsTree, word) {
				continue
			}
			check(word)
		}
	}
	// Words unrelated to any encoding's fixed base reach nodes the per-encoding
	// fills never route to; a node that dead-ends only for them still costs the
	// table walk at run time.
	for i := 0; i < 20000; i++ {
		check(rng.Uint32())
	}

	if compared == 0 {
		t.Fatal("no word matched both tree and table")
	}
	t.Logf("agreed on winner and ambiguous set for %d words", compared)
}

// treeCoverPinnedBits mirrors the (mask, value) chain emitDecoderSource writes
// into each flat table entry, so a fill built here satisfies the encoding's
// pattern by construction and only BitDiffs can reject it.
func treeCoverPinnedBits(instr *ir.InstructionIR) (mask, value uint32) {
	pat := instr.BitPattern
	if !contains01(pat) {
		pat = ir.PatternFromEncoding(instr.Encoding)
	}
	mask, value = ir.FixedBitsFromPattern(pat)
	if mask == 0 {
		mask, value = ir.FixedBitsFromEncoding(instr.Encoding)
	}
	return mask, value
}

// treeCoverHits flattens a MatchResult back into the candidate list the walk
// found: a resolved walk yields one instruction, an ambiguous one yields all
// of them, and a dead end yields nothing.
func treeCoverHits(res decoder.MatchResult) []*ir.InstructionIR {
	if res.Instruction != nil {
		return []*ir.InstructionIR{res.Instruction}
	}
	return res.Ambiguous
}

// treeCoverRank mirrors pickBest in templates/go/decoder.tmpl: most pinned bits
// first, canonical before alias, then EncodingID. Both sides of the comparison
// rank through it, so what the assertion actually bites on is set equality —
// the winner can only diverge when the candidate sets do.
func treeCoverRank(hits []*ir.InstructionIR) (winner string, peers []string) {
	best := hits[0]
	for _, h := range hits[1:] {
		if treeCoverBetter(h, best) {
			best = h
		}
	}
	for _, h := range hits {
		if h != best {
			peers = append(peers, h.EncodingID)
		}
	}
	sort.Strings(peers)
	return best.EncodingID, peers
}

func treeCoverBetter(a, b *ir.InstructionIR) bool {
	ma, _ := treeCoverPinnedBits(a)
	mb, _ := treeCoverPinnedBits(b)
	if na, nb := popcount32(ma), popcount32(mb); na != nb {
		return na > nb
	}
	if aa, ab := a.AliasOf != "", b.AliasOf != ""; aa != ab {
		return !aa && ab
	}
	return a.EncodingID < b.EncodingID
}

func popcount32(m uint32) int {
	n := 0
	for m != 0 {
		n++
		m &= m - 1
	}
	return n
}

func treeCoverSameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

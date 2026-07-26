package ir

import "testing"

func TestMatchBitPattern(t *testing.T) {
	// CLREX-like: top bits fixed
	pat := "11010101000000110011xxxxxxxxxxxx"
	// pad to 32
	for len(pat) < 32 {
		pat += "x"
	}
	pat = pat[:32]

	// word with matching MSB pattern from first fixed bits
	mask, value := FixedBitsFromPattern(pat)
	word := value // all don't-cares zero
	if !MatchBitPattern(pat, word) {
		t.Fatalf("expected match for word=0x%08x mask=0x%08x value=0x%08x pat=%s", word, mask, value, pat)
	}
	// flip a fixed bit
	for i := 0; i < 32; i++ {
		if pat[i] == '0' || pat[i] == '1' {
			bad := word ^ (1 << uint(31-i))
			if MatchBitPattern(pat, bad) {
				t.Fatalf("expected mismatch after flip bit %d", 31-i)
			}
			break
		}
	}
}

func TestFixedBitsFromEncoding(t *testing.T) {
	one := uint64(1)
	three := uint64(3)
	enc := EncodingMask{
		Width: 32,
		Fields: []BitField{
			{Name: "op", Start: 0, End: 0, Fixed: &one},
			{Name: "sf", Start: 30, End: 31, Fixed: &three},
		},
	}
	mask, value := FixedBitsFromEncoding(enc)
	// bit 0 = 1, bits 30-31 = 11
	wantMask := uint32(1) | (3 << 30)
	wantVal := uint32(1) | (3 << 30)
	if mask != wantMask || value != wantVal {
		t.Fatalf("mask=0x%08x want 0x%08x; value=0x%08x want 0x%08x", mask, wantMask, value, wantVal)
	}
	pat := PatternFromEncoding(enc)
	if !MatchBitPattern(pat, value) {
		t.Fatalf("pattern %s does not match value 0x%08x", pat, value)
	}
}

func TestFixedWord(t *testing.T) {
	one := uint64(1)
	instr := &InstructionIR{
		EncodingID: "X",
		BitPattern: "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Encoding: EncodingMask{
			Width:  32,
			Fields: []BitField{{Name: "hi", Start: 31, End: 31, Fixed: &one}},
		},
	}
	w, ok := FixedWord(instr)
	if !ok || w != 0x80000000 {
		t.Fatalf("got 0x%08X ok=%v", w, ok)
	}
}

func TestValidateBitFieldsOverlap(t *testing.T) {
	err := ValidateBitFields([]BitField{
		{Name: "a", Start: 0, End: 3},
		{Name: "b", Start: 2, End: 5},
	})
	if err == nil {
		t.Fatal("expected overlap error")
	}
	err = ValidateBitFields([]BitField{
		{Name: "a", Start: 0, End: 3},
		{Name: "b", Start: 4, End: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
}

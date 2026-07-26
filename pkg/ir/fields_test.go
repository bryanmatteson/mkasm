package ir

import "testing"

func TestExtractAndInsertField(t *testing.T) {
	// CRm-like [11:8]
	f := BitField{Name: "CRm", Start: 8, End: 11}
	w := uint32(0xD503305F)
	w2, err := InsertField(w, f, 0xF)
	if err != nil {
		t.Fatal(err)
	}
	if w2 != 0xD5033F5F {
		t.Fatalf("got 0x%08X", w2)
	}
	fs := ExtractFields(w2, EncodingMask{Width: 32, Fields: []BitField{f}})
	if len(fs) != 1 || fs[0].Value != 0xF {
		t.Fatalf("%+v", fs)
	}
}

func TestPackFields(t *testing.T) {
	enc := EncodingMask{
		Width: 32,
		Fields: []BitField{
			{Name: "CRm", Start: 8, End: 11},
			{Name: "op2", Start: 5, End: 7},
		},
	}
	base := uint32(0xD503305F)
	w, err := PackFields(base, enc, map[string]uint64{"CRm": 0xF})
	if err != nil || w != 0xD5033F5F {
		t.Fatalf("0x%08X err=%v", w, err)
	}
}

func TestInsertFieldOverflow(t *testing.T) {
	f := BitField{Name: "x", Start: 0, End: 3}
	if _, err := InsertField(0, f, 16); err == nil {
		t.Fatal("expected overflow")
	}
}

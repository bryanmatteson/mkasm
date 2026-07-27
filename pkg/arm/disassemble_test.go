package arm_test

import (
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestDisassemble_CLREX(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	d, ok := reg.Disassemble(0xD5033F5F)
	if !ok {
		t.Fatal("no match")
	}
	if d.Instruction.EncodingID != "CLREX_BN_barriers" {
		t.Fatalf("got %s", d.Instruction.EncodingID)
	}
	var crm *ir.FieldValue
	for i := range d.Fields {
		if d.Fields[i].Name == "CRm" {
			crm = &d.Fields[i]
			break
		}
	}
	if crm == nil || crm.Value != 0xF {
		t.Fatalf("fields=%+v", d.Fields)
	}
	// Named constants should appear for unnamed fixed boxes
	hasConst := false
	for _, f := range d.Fields {
		if len(f.Name) > 0 && f.Name[0] == '_' {
			hasConst = true
			break
		}
	}
	if !hasConst {
		t.Logf("note: no synthetic _const fields (ok if all boxes named): %+v", d.Fields)
	}
}

func TestRoundTrip_PackAndMatch(t *testing.T) {
	reg := loadResolvedRegistry(t, 200)
	instr, ok := reg.GetByEncodingID("CLREX_BN_barriers")
	if !ok {
		// resolve may not include CLREX if max-iforms ordering skips it
		reg = loadResolvedRegistry(t, 0)
		instr, ok = reg.GetByEncodingID("CLREX_BN_barriers")
		if !ok {
			t.Fatal("CLREX missing")
		}
	}
	base, ok := ir.FixedWord(instr)
	if !ok {
		t.Fatal("no fixed word")
	}
	word, err := ir.PackFields(base, instr.Encoding, map[string]uint64{"CRm": 0xF})
	if err != nil {
		t.Fatal(err)
	}
	if word != 0xD5033F5F {
		t.Fatalf("packed 0x%08X", word)
	}
	best, ok := reg.BestMatch(word)
	if !ok || best.EncodingID != "CLREX_BN_barriers" {
		t.Fatalf("best=%v ok=%v", best, ok)
	}
}

func TestMatchWord_specificityOrder(t *testing.T) {
	// Build a tiny registry manually via full parse; ensure BestMatch prefers more fixed bits.
	reg := loadResolvedRegistry(t, 0)
	// DSB and similar system encodings share high fixed bits; CLREX with CRm=15 should still win for its word.
	best, ok := reg.BestMatch(0xD5033F5F)
	if !ok {
		t.Fatal("no match")
	}
	if best.EncodingID != "CLREX_BN_barriers" {
		t.Fatalf("got %s", best.EncodingID)
	}
}

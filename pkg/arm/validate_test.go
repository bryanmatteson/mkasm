package arm

import (
	"reflect"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestInstructionValidator_resolvedCLREX(t *testing.T) {
	// Realistic CLREX-shaped fields after Pass 2 (hibit layout).
	// Pattern and fixed bits must agree.
	pat := "11010101000000110011xxxx01011111"
	for len(pat) < 32 {
		pat += "x"
	}
	pat = pat[:32]

	// Fixed fields derived from pattern via FixedBits — rebuild fields that
	// don't conflict with CRm variable [11:8].
	instr := &ir.InstructionIR{
		Mnemonic:   "CLREX",
		EncodingID: "CLREX_BN_barriers",
		BitPattern: pat,
		Encoding: ir.EncodingMask{
			Width: 32,
			Fields: []ir.BitField{
				{Name: "CRm", Start: 8, End: 11}, // variable
			},
		},
		Operands: []ir.OperandIR{
			{Name: "CRm", Type: ir.Imm, BitRange: ir.BitRange{Start: 8, End: 11}},
		},
		Asm: ir.AsmTemplate{Raw: "CLREX {#<imm>}"},
	}
	// Mark resolved via Asm.Raw / pattern fixed bits (hasPass2Encoding).
	v := NewInstructionValidator()
	if !v.Validate(instr) {
		t.Fatalf("expected valid: %v", v.GetErrors())
	}
}

func TestInstructionValidator_skipsProvisional(t *testing.T) {
	// Pass-1 style provisional fields all start at 0 — must not flag overlap.
	instr := &ir.InstructionIR{
		Mnemonic:   "FOO",
		EncodingID: "FOO_bar",
		BitPattern: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Encoding: ir.EncodingMask{
			Width: 32,
			Fields: []ir.BitField{
				{Name: "col0", Start: 0, End: 3},
				{Name: "col1", Start: 0, End: 4},
			},
		},
	}
	v := NewInstructionValidator()
	if !v.Validate(instr) {
		t.Fatalf("provisional should not hard-fail: %v", v.GetErrors())
	}
}

func TestInferOperandType(t *testing.T) {
	cases := map[string]ir.OperandType{
		"Rd":    ir.Reg,
		"Rn":    ir.Reg,
		"imm12": ir.Imm,
		"CRm":   ir.Imm,
		"cond":  ir.Cond,
		"Vd":    ir.SIMD,
	}
	for name, want := range cases {
		if got := InferOperandType(name); got != want {
			t.Errorf("InferOperandType(%q)=%q want %q", name, got, want)
		}
	}
}

func TestParseAsmTemplate_options(t *testing.T) {
	asm := parseAsmTemplate("ADD <Xd>, <Xn>, #<imm>{, <shift>}")
	if asm.Raw == "" {
		t.Fatal("empty raw")
	}
	hasOp := false
	hasSym := false
	for _, tok := range asm.Tokens {
		if tok.Kind == ir.TokenOperand {
			hasOp = true
		}
		if tok.Kind == ir.TokenSymbol {
			hasSym = true
		}
	}
	if !hasOp {
		t.Fatalf("no operand tokens: %+v", asm.Tokens)
	}
	if !hasSym {
		t.Fatalf("expected {shift}-style symbol token: %+v", asm.Tokens)
	}
}

func TestParseAsmTemplateHandScanner(t *testing.T) {
	asm := parseAsmTemplate("ADD <Xd:foo,bar>, <Xn>{, <shift>}")
	want := []ir.AsmToken{
		{Kind: ir.TokenLiteral, Value: "ADD"},
		{Kind: ir.TokenOperand, Operand: "Xd", Options: []string{"foo", "bar"}},
		{Kind: ir.TokenLiteral, Value: ","},
		{Kind: ir.TokenOperand, Operand: "Xn"},
		{Kind: ir.TokenSymbol, Value: ", <shift>"},
	}
	if !reflect.DeepEqual(asm.Tokens, want) {
		t.Fatalf("tokens = %#v, want %#v", asm.Tokens, want)
	}
}

func TestHoverFieldHandScanner(t *testing.T) {
	if got := hoverField(`register encoded in the "Rm_2" field`); got != "Rm_2" {
		t.Fatalf("hoverField = %q", got)
	}
	for _, prose := range []string{
		`encoded in the "" field`,
		`encoded in the "Rm-2" field`,
	} {
		if got := hoverField(prose); got != "" {
			t.Fatalf("hoverField(%q) = %q", prose, got)
		}
	}
}

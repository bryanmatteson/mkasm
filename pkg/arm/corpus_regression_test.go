package arm

import (
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestPtruePatternDefaultIsAll(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "ptrue_p_s.xml"), "ptrue_p_s_")
	if err != nil {
		t.Fatal(err)
	}
	exps := ExplanationsFor(p.Explanations, p.EncodingName)
	var pattern *ClassifiedOperand
	for _, op := range p.AsmOperands {
		if op.Symbol != "<pattern>" {
			continue
		}
		c := ClassifyOperandWith(op, exps[op.Symbol])
		pattern = &c
		break
	}
	if pattern == nil {
		t.Fatal("pattern operand not parsed")
	}
	if !pattern.HasDefault || pattern.DefaultSymbol != "ALL" {
		t.Fatalf("pattern default = (%v, %q), want ALL", pattern.HasDefault, pattern.DefaultSymbol)
	}

	params, why := TypedParamsFor(p.AsmTemplate, p.AsmOperands, exps)
	if why != "" {
		t.Fatal(why)
	}
	MarkOptional(p.AsmTemplate, params, p.AsmOperands, exps)
	instr := &ir.InstructionIR{EncodingID: p.EncodingName}
	ApplyParsedIForm(instr, p)
	_, fw := ir.FixedBitsFromPattern(instr.BitPattern)
	form, err := buildForm(instr, p, "ptrue", params, AddrNone, fw)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range form.Enums {
		if d.Param == "pattern" {
			if !d.HasDefault || d.DefaultOr != 0x3e0 {
				t.Fatalf("resolved pattern default = (%v, %#x), want 0x3e0", d.HasDefault, d.DefaultOr)
			}
			return
		}
	}
	t.Fatal("pattern enum dispatch not built")
}

func TestBareAliasRetainsEquivalentDefault(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "gcspopx_sys.xml"), "GCSPOPX_SYS_CR_systeminstrs")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.EquivalentOperands) != 1 {
		t.Fatalf("equivalent operands = %d, want 1", len(p.EquivalentOperands))
	}
	c := ClassifyOperand(p.EquivalentOperands[0])
	if c.ResolvedField != "Rt" || !c.HasDefault || c.Default != 31 {
		t.Fatalf("equivalent default = field %q value %d present %v", c.ResolvedField, c.Default, c.HasDefault)
	}
}

func TestFloatingImmediateGetsCompactType(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "fmov_float_imm.xml"), "FMOV_D_floatimm")
	if err != nil {
		t.Fatal(err)
	}
	exps := ExplanationsFor(p.Explanations, p.EncodingName)
	for _, op := range p.AsmOperands {
		if op.Symbol != "<imm>" {
			continue
		}
		c := ClassifyOperandWith(op, exps[op.Symbol])
		if c.Class != ClassFpImm {
			t.Fatalf("floating immediate class = %q, want %q", c.Class, ClassFpImm)
		}
		return
	}
	t.Fatal("floating immediate operand not parsed")
}

func TestStshhUsesCurrentXMLOpcode(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "stshh.xml"), "STSHH_HI_hints")
	if err != nil {
		t.Fatal(err)
	}
	instr := &ir.InstructionIR{EncodingID: p.EncodingName}
	ApplyParsedIForm(instr, p)
	_, word := ir.FixedBitsFromPattern(instr.BitPattern)
	if word != 0xD503261F {
		t.Fatalf("STSHH KEEP XML word = %#08x, want 0xD503261F", word)
	}
}

func TestRegisterOffsetWIndexRequiresLegalExtend(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "ldr_reg_gen.xml"), "LDR_32_ldst_regoff")
	if err != nil {
		t.Fatal(err)
	}
	exps := ExplanationsFor(p.Explanations, p.EncodingName)
	params, why := TypedParamsFor(p.AsmTemplate, p.AsmOperands, exps)
	if why != "" {
		t.Fatal(why)
	}
	MarkOptional(p.AsmTemplate, params, p.AsmOperands, exps)
	ApplySelectorConstraints(params)
	for _, prm := range params {
		t.Logf("%s class=%s field=%s optional=%v default=(%v,%d,%q) selector=%v %s<%d>=%d choices=%v",
			prm.Name, prm.Class, prm.Field, prm.Optional, prm.HasDefault,
			prm.Default, prm.DefaultSymbol, prm.HasSelector, prm.SelectorField,
			prm.SelectorBit, prm.SelectorValue, prm.Choices)
		if prm.Class == ClassExtend && prm.Optional {
			t.Fatal("W-index register offset must not omit its extend")
		}
	}
}

func TestStridedMultiVectorListRetainsTypedSurface(t *testing.T) {
	p, err := ParseIFormFile(iformFilePath(t, "ld1b_mzx_p_br.xml"), "ld1b_mzx_p_br_2x8")
	if err != nil {
		t.Fatal(err)
	}
	exps := ExplanationsFor(p.Explanations, p.EncodingName)
	params, why := TypedParamsFor(p.AsmTemplate, p.AsmOperands, exps)
	if why != "" {
		t.Fatalf("strided list lost typed surface: %s", why)
	}
	if len(params) != 4 {
		t.Fatalf("strided list params = %d, want first vector + predicate + base + offset", len(params))
	}
}

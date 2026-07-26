package arm

import (
	"strings"
	"testing"

	"mkasm/pkg/ir"
)

func TestEmitRustConformanceTest(t *testing.T) {
	surface := &AsmSurface{
		Methods: map[string][]AsmForm{
			"nop": {{
				Method:        "nop",
				EncodingID:    "NOP_HI_hints",
				RequiredArity: 0,
			}},
		},
		MethodOrder: []string{"nop"},
	}

	src, cases := EmitRustConformanceTest("aarch64-test", surface)
	if len(cases) != 1 || cases[0].EncodingID != "NOP_HI_hints" || cases[0].Method != "nop" {
		t.Fatalf("cases = %#v", cases)
	}
	for _, want := range []string{
		"use aarch64_test::*;",
		`#[ignore = "ledger consumed by the external LLVM conformance gate"]`,
		"fn typed_conformance_words()",
		"a.nop();",
		`println!("0\tNOP_HI_hints\t{:08X}", a.words()[0]);`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated source does not contain %q", want)
		}
	}
	if strings.Contains(src, "fn main()") || strings.Contains(src, "transient") {
		t.Fatal("generated integration test still looks like the former transient runner")
	}
}

func TestEmitRustExactConformanceTest(t *testing.T) {
	surface := &AsmSurface{
		Exact: []ExactEncoding{{
			Fn:         "enc_nop_hi_hints",
			EncodingID: "NOP_HI_hints",
			FixedWord:  0xD503201F,
			Fields: []RawField{{
				Name: "CRm", Start: 8, End: 11, Free: 0x00000F00,
			}},
		}},
	}

	src, cases := EmitRustExactConformanceTest("aarch64", surface)
	if len(cases) != 1 || cases[0].EncodingID != "NOP_HI_hints" {
		t.Fatalf("cases = %#v", cases)
	}
	for _, want := range []string{
		"fn exact_conformance_words()",
		"a.enc_nop_hi_hints(1);",
		`println!("0\tNOP_HI_hints\t{:08X}", a.words()[0]);`,
		"1 exact encoders emitted",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated source does not contain %q", want)
		}
	}
}

func TestBiasedRegisterPlacementKeepsArchitecturalRange(t *testing.T) {
	prm := Param{
		Name: "png", Class: ClassSvePN, Field: "PNg",
		Bias: 8, Lo: 0, Hi: 7, HasRange: true,
		RegLo: 8, RegHi: 15, HasRegRange: true,
	}
	pl, err := placementFor(&prm, "png.raw()", map[string]ir.BitField{
		"PNg": {Name: "PNg", Start: 10, End: 12},
	}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pl.Bias != 8 || !pl.HasRange || pl.Lo != 8 || pl.Hi != 15 {
		t.Fatalf("placement = bias %d range %d..%d present=%v; want bias 8, range 8..15",
			pl.Bias, pl.Lo, pl.Hi, pl.HasRange)
	}
}

package arm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/templates"
)

func TestFeatureRequirementsScopeAndConditions(t *testing.T) {
	page := `<instructionsection><classes><iclass isa="A64"><arch_variants><arch_variant feature="FEAT_FP"/></arch_variants><encoding name="FP"/><ps_section><pstext>if ftype == '11' &amp;&amp; !IsFeatureImplemented(FEAT_FP16) then EndOfDecode(Decode_UNDEF); end;</pstext></ps_section></iclass><iclass isa="A64"><arch_variants><arch_variant feature="FEAT_SVE"/></arch_variants><encoding name="SVE"/></iclass></classes></instructionsection>`
	p, err := parseIForm(strings.NewReader(page), "FP")
	if err != nil {
		t.Fatal(err)
	}
	i := &ir.InstructionIR{EncodingID: "FP"}
	ApplyParsedIForm(i, p)
	for _, test := range []struct {
		f    uint64
		fp16 bool
		want ir.Satisfaction
	}{{0, false, ir.Satisfied}, {3, false, ir.Unsatisfied}, {3, true, ir.Satisfied}} {
		result := instructionRequirements(i).Evaluate(ir.RequirementContext{Mode: "a64", Features: map[string]bool{"FEAT_FP": true, "FEAT_FP16": test.fp16}, Fields: map[string]uint64{"ftype": test.f}})
		if result.Primary != test.want {
			t.Fatalf("%+v -> %+v; source %+v", test, result, p)
		}
	}
	if len(p.FeatureAlternatives) != 1 || p.FeatureAlternatives[0] != "FEAT_FP" {
		t.Fatalf("features escaped iclass: %+v", p.FeatureAlternatives)
	}
}

func TestMultilineDecodeGuardsKeepCompleteBooleanAndNestedScope(t *testing.T) {
	for _, kind := range []string{"UNDEF", "NOP"} {
		i := &ir.InstructionIR{}
		applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{`if size == '11' then
if ((!IsFeatureImplemented(FEAT_SVE2) && !IsFeatureImplemented(FEAT_SME2)) ||
      !IsFeatureImplemented(FEAT_LUT)) then
    EndOfDecode(Decode_` + kind + `); end;
end;`}})
		for size := uint64(0); size < 4; size++ {
			for mask := 0; mask < 8; mask++ {
				ctx := ir.RequirementContext{Fields: map[string]uint64{"size": size}, Features: map[string]bool{"FEAT_SVE2": mask&1 != 0, "FEAT_SME2": mask&2 != 0, "FEAT_LUT": mask&4 != 0}}
				got := i.Requirements.Evaluate(ctx)
				want := ir.Satisfied
				if size == 3 && (mask&3 == 0 || mask&4 == 0) {
					want = ir.Unsatisfied
				}
				if got.Primary != want {
					t.Fatalf("%s size%d features%x: %+v want %v", kind, size, mask, got, want)
				}
				fallback := ir.Unsatisfied
				if want == ir.Unsatisfied {
					fallback = ir.Satisfied
				}
				if kind == "NOP" && got.Fallback != fallback {
					t.Fatalf("NOP fallback size%d features%x: %+v", size, mask, got)
				}
			}
		}
	}
}

func TestA32UndefinedFeatureGuardsKeepScalarAndVectorDimensions(t *testing.T) {
	for _, condition := range []string{"sz == '1'", "F == '1' && size == '01'"} {
		i := &ir.InstructionIR{InstructionSet: "A32"}
		applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{"if " + condition + " && !IsFeatureImplemented(FEAT_FP16) then Undefined(); end;"}})
		for f := uint64(0); f < 2; f++ {
			for size := uint64(0); size < 4; size++ {
				for _, half := range []bool{false, true} {
					want := ir.Satisfied
					if !half && ((condition == "sz == '1'" && size&1 != 0) || (condition != "sz == '1'" && size == 1 && f == 1)) {
						want = ir.Unsatisfied
					}
					got := instructionRequirements(i).Evaluate(ir.RequirementContext{Mode: "a32", Features: map[string]bool{"FEAT_FP16": half}, Fields: map[string]uint64{"F": f, "size": size, "sz": size}})
					if got.Primary != want {
						t.Fatalf("%s F%d size%d half%t: %+v want %v", condition, f, size, half, got, want)
					}
				}
			}
		}
	}
}

func TestCaseFeatureGuardsKeepTheirSelectedField(t *testing.T) {
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{`case op of
when '00' =>
    if !IsFeatureImplemented(FEAT_DIT) then EndOfDecode(Decode_UNDEF); end;
when '01', '10' =>
    if !IsFeatureImplemented(FEAT_MTE) then EndOfDecode(Decode_UNDEF); end;
otherwise =>
    if !IsFeatureImplemented(FEAT_SME) then EndOfDecode(Decode_UNDEF); end;
end;
if !IsFeatureImplemented(FEAT_BASE) then EndOfDecode(Decode_UNDEF); end;`}})
	for _, tc := range []struct {
		op      uint64
		feature string
	}{{0, "FEAT_DIT"}, {1, "FEAT_MTE"}, {2, "FEAT_MTE"}, {3, "FEAT_SME"}} {
		features := map[string]bool{"FEAT_BASE": true, tc.feature: true}
		context := ir.RequirementContext{Features: features, Fields: map[string]uint64{"op": tc.op}}
		if got := i.Requirements.Evaluate(context).Primary; got != ir.Satisfied {
			t.Fatalf("selected %v: %v", tc, got)
		}
		features[tc.feature] = false
		if got := i.Requirements.Evaluate(context).Primary; got != ir.Unsatisfied {
			t.Fatalf("missing selected %v: %v", tc, got)
		}
	}
}

func TestCaseDerivedEnumFeatureGuardsRemainUnknownWithoutTheirSelector(t *testing.T) {
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{`case field of
when PSTATEField_DIT =>
    if !IsFeatureImplemented(FEAT_DIT) then EndOfDecode(Decode_UNDEF); end;
when PSTATEField_TCO =>
    if !IsFeatureImplemented(FEAT_MTE) then EndOfDecode(Decode_UNDEF); end;
end;`}})
	if got := i.Requirements.Evaluate(ir.RequirementContext{Features: map[string]bool{"FEAT_DIT": true}}).Primary; got != ir.Unknown {
		t.Fatalf("unresolved case imposed an unrelated mandatory feature: %v", got)
	}
}

func TestGeneratedArmRequirementModule(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	instrs := rustDecoderWildcardFixture()
	instrs[0].EncodingID = "FP"
	instrs[0].Features.Tags = []ir.FeatureTag{{Name: "FEAT_FP", Required: true}}
	applyFeatureRequirements(instrs[0], &ParsedIForm{Pseudocode: []string{"if mid == '11' && !IsFeatureImplemented(FEAT_FP16) then EndOfDecode(Decode_UNDEF); end;"}})
	instrs[1].EncodingID = "HINT"
	applyFeatureRequirements(instrs[1], &ParsedIForm{Pseudocode: []string{"if !IsFeatureImplemented(FEAT_BTI) then EndOfDecode(Decode_NOP); end;"}})
	alias := *instrs[0]
	alias.EncodingID = "ALIAS"
	alias.AliasOf = "FP"
	alias.Requirements = ir.Requirements{}
	alias.Features = ir.FeatureSet{}
	instrs = append(instrs, &alias)
	catalog := BuildCatalog(instrs)
	dir := t.TempDir()
	if err := writeRustRequirements(dir, catalog); err != nil {
		t.Fatal(err)
	}
	data, err := buildRustDecoderData(catalog)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("rust").ParseFS(templates.FS, "rust/decoders.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(dir, "decoders.rs"), data); err != nil {
		t.Fatal(err)
	}
	source := `#![allow(dead_code)]
mod requirements; mod decoders;
use requirements::{Satisfaction::*, UnknownPolicy};
#[test] fn architecture_requirements() {
 let fp=requirements::for_encoding("FP");
 assert_eq!(fp.evaluate(&["FEAT_FP"],"a64",&|_|Some(0)).primary,Satisfied);
 assert_eq!(fp.evaluate(&["FEAT_FP"],"a64",&|_|Some(3)).primary,Unsatisfied);
 assert_eq!(fp.evaluate(&["FEAT_FP","FEAT_FP16"],"a64",&|_|Some(3)).primary,Satisfied);
 assert_eq!(fp.evaluate(&["FEAT_FP","FEAT_FP16"],"a32",&|_|Some(3)).primary,Unsatisfied);
 assert_eq!(fp.expression.evaluate_with(&|name|if name=="FEAT_FP16"{Some(false)}else{None},"a64",&|_|Some(3)),Unsatisfied);
 assert_eq!(fp.expression.evaluate_with(&|_|None,"a64",&|_|Some(0)),Unknown);
 assert_eq!(fp.evaluate(&["FEAT_FP"],"",&|_|Some(0)).primary,Unknown);
 let hint=requirements::for_encoding("HINT").evaluate(&[],"a64",&|_|None);
 assert_eq!(hint.primary,Unsatisfied); assert!(!hint.admit(UnknownPolicy::Allow));
 assert!(hint.admit_fallback(UnknownPolicy::Reject)); assert_eq!(hint.fallback_behavior,"nop");
 assert_eq!(requirements::for_encoding("ALIAS").evaluate(&["FEAT_FP"],"a64",&|_|Some(0)).primary,Satisfied);
 assert_eq!(requirements::for_encoding("absent").evaluate(&[],"a64",&|_|None).primary,Unknown);
 let d=decoders::decode(0x80000001).unwrap(); assert_eq!(d.encoding_id,"HINT");
}
`
	if err := os.WriteFile(filepath.Join(dir, "test.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "test.rs", "-o", "test")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "test"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runtime: %v\n%s", err, out)
	}
}

func TestNestedFeatureGuardKeepsOuterFieldCondition(t *testing.T) {
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{"if size == '11' then\n    if !IsFeatureImplemented(FEAT_OPTIONAL) then EndOfDecode(Decode_UNDEF); end;\nend;"}})
	for _, test := range []struct {
		size uint64
		want ir.Satisfaction
	}{{0, ir.Satisfied}, {3, ir.Unsatisfied}} {
		if got := i.Requirements.Evaluate(ir.RequirementContext{Fields: map[string]uint64{"size": test.size}}).Primary; got != test.want {
			t.Fatalf("outer condition lost: %+v got %v", test, got)
		}
	}
}

func TestGeneratedARM32RequirementHelpers(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "xml")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	var instructions []*ir.InstructionIR
	for _, test := range []struct {
		id, isa, pattern, asm string
		width                 int
	}{{"OPTIONAL_A32", "A32", "00000001001000110100010101100111", "OPT", 32}, {"OPTIONAL_T16", "T32", "1011111100000000", "OPT", 16}, {"OPTIONAL_T32", "T32", "11110000000000001000000000000000", "OPT", 32}} {
		page := `<instructionsection><classes><iclass isa="` + test.isa + `"><arch_variants><arch_variant feature="FEAT_OPTIONAL"/></arch_variants><regdiagram form="` + map[int]string{16: "16", 32: "32"}[test.width] + `"><box hibit="` + map[int]string{16: "15", 32: "31"}[test.width] + `" width="` + map[int]string{16: "16", 32: "32"}[test.width] + `"><c colspan="` + map[int]string{16: "16", 32: "32"}[test.width] + `">` + test.pattern + `</c></box></regdiagram><encoding name="` + test.id + `"><asmtemplate><text>` + test.asm + `</text></asmtemplate></encoding></iclass></classes></instructionsection>`
		filename := test.id + ".xml"
		if err := os.WriteFile(filepath.Join(source, filename), []byte(page), 0644); err != nil {
			t.Fatal(err)
		}
		p, err := parseIForm(strings.NewReader(page), test.id)
		if err != nil {
			t.Fatal(err)
		}
		i := &ir.InstructionIR{EncodingID: test.id, IFormFile: filename, IClass: "optional"}
		ApplyParsedIForm(i, p)
		instructions = append(instructions, i)
	}
	output := filepath.Join(dir, "crate")
	ap := NewARMParser(ARMParserConfig{IFormDirectory: source, OutputDirectory: output, Arch: ArchARM32})
	if err := ap.generateARM32Rust(instructions); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	sourceTest := `use arm32::*;
use requirements::Satisfaction::*;
#[test] fn arm_and_thumb_helpers() {
 for (bytes,mode,context) in [(&[0x67,0x45,0x23,0x01][..],Mode::Arm,"a32"),(&[0x00,0xbf][..],Mode::Thumb,"thumb"),(&[0x00,0xf0,0x00,0x80][..],Mode::Thumb,"thumb")] {
  let d=decode(bytes,mode,Endian::Little).unwrap();
  assert_eq!(d.evaluate_requirements(&[],context).primary,Unsatisfied);
  assert_eq!(d.evaluate_requirements(&["FEAT_OPTIONAL"],context).primary,Satisfied);
  assert_eq!(d.evaluate_requirements(&["FEAT_OPTIONAL"],"a64").primary,Unsatisfied);
 }
}
`
	if err := os.WriteFile(filepath.Join(output, "tests", "requirements.rs"), []byte(sourceTest), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "requirements", "--quiet")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated arm32 requirements: %v\n%s", err, out)
	}
}

func TestFallbackRequiresEarlierDecodeGuards(t *testing.T) {
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{"if !IsFeatureImplemented(FEAT_BASE) then EndOfDecode(Decode_UNDEF); end;\nif !IsFeatureImplemented(FEAT_HINT) then EndOfDecode(Decode_NOP); end;"}})
	if got := i.Requirements.Evaluate(ir.RequirementContext{}).Fallback; got != ir.Unsatisfied {
		t.Fatalf("fallback bypassed prior UNDEF: %v", got)
	}
	if got := i.Requirements.Evaluate(ir.RequirementContext{Features: map[string]bool{"FEAT_BASE": true}}).Fallback; got != ir.Satisfied {
		t.Fatalf("valid fallback rejected: %v", got)
	}
}

func TestNestedElseIfRequirementContexts(t *testing.T) {
	prefix := "if size == '00' then\nX();\nelsif size == '01' then\nX();\nelsif size == '10' then\n"
	contexts := requirementGuardContext(prefix)
	if len(contexts) != 1 {
		t.Fatal(contexts)
	}
	for size := uint64(0); size < 4; size++ {
		got := contexts[0].Evaluate(ir.RequirementContext{Fields: map[string]uint64{"size": size}})
		want := ir.Unsatisfied
		if size == 2 {
			want = ir.Satisfied
		}
		if got != want {
			t.Fatalf("size %d got %v want %v", size, got, want)
		}
	}
}

func TestIndexRequirementKeepsDisjunctionWithLegacyTags(t *testing.T) {
	expression := "FEAT_SVE2 || FEAT_SME2"
	r := rowFeatureRequirements([]string{expression})
	if got := r.Evaluate(ir.RequirementContext{Features: map[string]bool{"FEAT_SME2": true}}).Primary; got != ir.Satisfied {
		t.Fatalf("index alternatives flattened: %v", got)
	}
	tags := legacyFeatureTags([]string{expression})
	if len(tags) != 2 {
		t.Fatalf("legacy feature annotation lookup lost: %v", tags)
	}
	i := &ir.InstructionIR{Requirements: r, Features: ir.FeatureSet{Tags: parseFeatureTags(tags)}}
	applyFeatureRequirements(i, &ParsedIForm{})
	if got := i.Requirements.Evaluate(ir.RequirementContext{Features: map[string]bool{"FEAT_SME2": true}}).Primary; got != ir.Satisfied {
		t.Fatalf("legacy tags overrode structured alternatives: %v", got)
	}
}

func TestFeatureAlternativeGroupsInheritWithoutFlattening(t *testing.T) {
	page := `<instructionsection><arch_variants><arch_variant feature="FEAT_BASE"/></arch_variants><classes><iclass><arch_variants><arch_variant feature="FEAT_A"/><arch_variant feature="FEAT_B"/></arch_variants><encoding name="GROUPED"><arch_variants><arch_variant feature="FEAT_EXTRA"/></arch_variants></encoding></iclass></classes></instructionsection>`
	p, err := parseIForm(strings.NewReader(page), "GROUPED")
	if err != nil {
		t.Fatal(err)
	}
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, p)
	if len(p.FeatureAlternativeGroups) != 3 {
		t.Fatalf("lost alternative groups: %+v", p.FeatureAlternativeGroups)
	}
	for _, test := range []struct {
		features map[string]bool
		want     ir.Satisfaction
	}{{map[string]bool{"FEAT_BASE": true, "FEAT_B": true, "FEAT_EXTRA": true}, ir.Satisfied}, {map[string]bool{"FEAT_B": true, "FEAT_EXTRA": true}, ir.Unsatisfied}, {map[string]bool{"FEAT_BASE": true, "FEAT_B": true}, ir.Unsatisfied}} {
		if got := i.Requirements.Evaluate(ir.RequirementContext{Features: test.features}).Primary; got != test.want {
			t.Fatalf("groups flattened %v -> %v", test.features, got)
		}
	}
}

func TestConditionalExpressionsDoNotScopeFeatureGuards(t *testing.T) {
	for _, expression := range []string{
		"let datasize : integer = if sf == '1' then 64 else 32;",
		"let datasize : integer =\n    if sf == '1' then\n        (if size == '11' then 64 else 32)\n    else 16;",
		"let datasize : integer = Choose(if sf == '1' then 64 else 32);",
		"let text = \"if sf then end; else;\"; // if size == '11' then\n/* else; end; */",
	} {
		for _, nested := range []bool{false, true} {
			code := expression + "\nif !IsFeatureImplemented(FEAT_OPTIONAL) then EndOfDecode(Decode_UNDEF); end;"
			if nested {
				code = "if size == '11' then\n" + code + "\nend;"
			}
			i := &ir.InstructionIR{}
			applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{code}})
			for _, size := range []uint64{0, 3} {
				for _, sf := range []uint64{0, 1} {
					for _, enabled := range []bool{false, true} {
						want := ir.Satisfied
						if !enabled && (!nested || size == 3) {
							want = ir.Unsatisfied
						}
						got := i.Requirements.Evaluate(ir.RequirementContext{
							Features: map[string]bool{"FEAT_OPTIONAL": enabled},
							Fields:   map[string]uint64{"sf": sf, "size": size},
						}).Primary
						if got != want {
							t.Fatalf("%q nested=%t size=%d sf=%d enabled=%t: got %v want %v", expression, nested, size, sf, enabled, got, want)
						}
					}
				}
			}
		}
	}
}

func TestConditionalExpressionBeforeElseIfPreservesStatementBranches(t *testing.T) {
	code := "if size == '00' then\n let x = if sf == '1' then 64 else 32;\nelsif size == '01' then\n let y = if sf == '1' then 64 else 32;\n if !IsFeatureImplemented(FEAT_OPTIONAL) then EndOfDecode(Decode_UNDEF); end;\nelse\n X();\nend;"
	i := &ir.InstructionIR{}
	applyFeatureRequirements(i, &ParsedIForm{Pseudocode: []string{code}})
	for size := uint64(0); size < 4; size++ {
		for sf := uint64(0); sf < 2; sf++ {
			want := ir.Satisfied
			if size == 1 {
				want = ir.Unsatisfied
			}
			got := i.Requirements.Evaluate(ir.RequirementContext{Fields: map[string]uint64{"size": size, "sf": sf}}).Primary
			if got != want {
				t.Fatalf("size=%d sf=%d: got %v want %v", size, sf, got, want)
			}
		}
	}
}

func aliasFallbackRequirementFixture() []*ir.InstructionIR {
	base := ir.RequirementExpr{Op: "feature", Name: "FEAT_BASE"}
	own := ir.RequirementExpr{Op: "feature", Name: "FEAT_OWN"}
	hint := ir.RequirementExpr{Op: "feature", Name: "FEAT_HINT"}
	truth := ir.RequirementExpr{Op: "true"}
	notOwn, notHint := ir.RequirementNot(own), ir.RequirementNot(hint)
	localNOP := ir.Requirements{Expression: &truth, Fallback: &truth, FallbackBehavior: "nop"}
	return []*ir.InstructionIR{
		{EncodingID: "BASE", Requirements: ir.Requirements{Expression: &base}},
		{EncodingID: "ALIAS", AliasOf: "BASE", Requirements: ir.Requirements{Expression: &own, Fallback: &notOwn, FallbackBehavior: "nop"}},
		{EncodingID: "CHAIN", AliasOf: "ALIAS", Requirements: localNOP},
		{EncodingID: "HINT", Requirements: ir.Requirements{Expression: &hint, Fallback: &notHint, FallbackBehavior: "nop"}},
		{EncodingID: "MATCHING", AliasOf: "HINT", Requirements: localNOP},
		{EncodingID: "INHERITED", AliasOf: "HINT"},
		{EncodingID: "OTHER", Requirements: ir.Requirements{Expression: &hint, Fallback: &notHint, FallbackBehavior: "other"}},
		{EncodingID: "MISMATCH", AliasOf: "OTHER", Requirements: localNOP},
		{EncodingID: "MISSING", AliasOf: "UNAVAILABLE", Requirements: localNOP},
		{EncodingID: "MISSING_CHILD", AliasOf: "MISSING"},
		{EncodingID: "CYCLE_A", AliasOf: "CYCLE_B", Requirements: localNOP},
		{EncodingID: "CYCLE_B", AliasOf: "CYCLE_A", Requirements: localNOP},
	}
}

func TestAliasLocalFallbackRespectsCanonicalAdmission(t *testing.T) {
	catalog := BuildCatalog(aliasFallbackRequirementFixture())
	byID := make(map[string]ir.Requirements)
	for _, entry := range catalog.Entries {
		byID[entry.EncodingID] = entry.Requirements
	}
	for _, test := range []struct {
		id, mode          string
		features          []string
		primary, fallback ir.Satisfaction
	}{
		{"ALIAS", "a64", nil, ir.Unsatisfied, ir.Unsatisfied},
		{"ALIAS", "a64", []string{"FEAT_BASE"}, ir.Unsatisfied, ir.Satisfied},
		{"ALIAS", "a64", []string{"FEAT_BASE", "FEAT_OWN"}, ir.Satisfied, ir.Unsatisfied},
		{"ALIAS", "a32", []string{"FEAT_BASE"}, ir.Unsatisfied, ir.Unsatisfied},
		{"CHAIN", "a64", nil, ir.Unsatisfied, ir.Unsatisfied},
		{"CHAIN", "a64", []string{"FEAT_BASE"}, ir.Unsatisfied, ir.Satisfied},
		{"MATCHING", "a64", nil, ir.Unsatisfied, ir.Satisfied},
		{"INHERITED", "a64", nil, ir.Unsatisfied, ir.Satisfied},
		{"MISMATCH", "a64", nil, ir.Unsatisfied, ir.Unsatisfied},
		{"MISMATCH", "a64", []string{"FEAT_HINT"}, ir.Satisfied, ir.Satisfied},
		{"MISSING", "a64", nil, ir.Unknown, ir.Unknown},
		{"MISSING_CHILD", "a64", nil, ir.Unknown, ir.Unknown},
		{"CYCLE_A", "a64", nil, ir.Unknown, ir.Unknown},
		{"CYCLE_B", "a64", nil, ir.Unknown, ir.Unknown},
		{"MISSING", "a32", nil, ir.Unsatisfied, ir.Unsatisfied},
		{"CYCLE_A", "a32", nil, ir.Unsatisfied, ir.Unsatisfied},
	} {
		context := ir.RequirementContext{Mode: test.mode, Features: make(map[string]bool)}
		for _, feature := range test.features {
			context.Features[feature] = true
		}
		got := byID[test.id].Evaluate(context)
		if !got.HasFallback || got.Primary != test.primary || got.Fallback != test.fallback {
			t.Fatalf("%s mode=%s features=%v: got %+v want primary=%v fallback=%v", test.id, test.mode, test.features, got, test.primary, test.fallback)
		}
		if got.Fallback == ir.Unknown && got.Fallback.Admit(ir.RejectUnknown) {
			t.Fatal("unknown alias fallback admitted by reject policy")
		}
	}
}

func TestGeneratedAliasFallbackAndExpressionGuardRequirements(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	instructions := aliasFallbackRequirementFixture()
	conditional := &ir.InstructionIR{EncodingID: "EXPRESSION"}
	applyFeatureRequirements(conditional, &ParsedIForm{Pseudocode: []string{"let x = if sf == '1' then 64 else 32;\nif !IsFeatureImplemented(FEAT_OPTIONAL) then EndOfDecode(Decode_UNDEF); end;"}})
	instructions = append(instructions, conditional)
	dir := t.TempDir()
	if err := writeRustRequirements(dir, BuildCatalog(instructions)); err != nil {
		t.Fatal(err)
	}
	source := `mod requirements;
use requirements::{for_encoding,Satisfaction::*,UnknownPolicy};
#[test]fn alias_fallbacks_and_guards(){
 for sf in [0,1] {assert_eq!(for_encoding("EXPRESSION").evaluate(&[],"a64",&|_|Some(sf)).primary,Unsatisfied);assert_eq!(for_encoding("EXPRESSION").evaluate(&["FEAT_OPTIONAL"],"a64",&|_|Some(sf)).primary,Satisfied);}
 assert_eq!(for_encoding("ALIAS").evaluate(&[],"a64",&|_|None).fallback,Some(Unsatisfied));
 assert_eq!(for_encoding("ALIAS").evaluate(&["FEAT_BASE"],"a64",&|_|None).fallback,Some(Satisfied));
 assert_eq!(for_encoding("CHAIN").evaluate(&[],"a64",&|_|None).fallback,Some(Unsatisfied));
 assert_eq!(for_encoding("CHAIN").evaluate(&["FEAT_BASE"],"a64",&|_|None).fallback,Some(Satisfied));
 assert_eq!(for_encoding("MATCHING").evaluate(&[],"a64",&|_|None).fallback,Some(Satisfied));
 assert_eq!(for_encoding("INHERITED").evaluate(&[],"a64",&|_|None).fallback,Some(Satisfied));
 assert_eq!(for_encoding("MISMATCH").evaluate(&[],"a64",&|_|None).fallback,Some(Unsatisfied));
 for id in ["MISSING","MISSING_CHILD","CYCLE_A","CYCLE_B"] {let result=for_encoding(id).evaluate(&[],"a64",&|_|None);assert_eq!(result.primary,Unknown);assert_eq!(result.fallback,Some(Unknown));assert!(!result.admit_fallback(UnknownPolicy::Reject));assert!(result.admit_fallback(UnknownPolicy::Allow));assert_eq!(for_encoding(id).evaluate(&[],"a32",&|_|None).fallback,Some(Unsatisfied));}
}
`
	if err := os.WriteFile(filepath.Join(dir, "test.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "test.rs", "-o", "test")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile requirements: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "test"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated requirements: %v\n%s", err, out)
	}
}

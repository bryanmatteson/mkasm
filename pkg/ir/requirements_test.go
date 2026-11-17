package ir

import (
	"strings"
	"testing"
)

func TestRequirementLogicPreservesAlternativesAndUnknown(t *testing.T) {
	e := ParseRequirementExpression("FEAT_A && (FEAT_B || FEAT_C) && !FEAT_D", false)
	for _, test := range []struct {
		features []string
		want     Satisfaction
	}{{[]string{"FEAT_A", "FEAT_C"}, Satisfied}, {[]string{"FEAT_A"}, Unsatisfied}, {[]string{"FEAT_A", "FEAT_B", "FEAT_D"}, Unsatisfied}} {
		c := RequirementContext{Features: map[string]bool{}}
		for _, f := range test.features {
			c.Features[f] = true
		}
		if got := e.Evaluate(c); got != test.want {
			t.Fatalf("%v: got %v want %v", test.features, got, test.want)
		}
	}
	unknown := ParseRequirementExpression("HasFoo && FEAT_A", false)
	if got := unknown.Evaluate(RequirementContext{Features: map[string]bool{"FEAT_A": true}}); got != Unknown {
		t.Fatalf("opaque predicate became a feature: %v", unknown)
	}
	if Unknown.Admit(RejectUnknown) || !Unknown.Admit(AllowUnknown) {
		t.Fatal("unknown policy ignored")
	}
}

func TestRequirementFieldConditionAndIf(t *testing.T) {
	e := RequirementNot(ParseRequirementExpression("ftype == '11' && !IsFeatureImplemented(FEAT_FP16)", false))
	for _, test := range []struct {
		field   uint64
		enabled bool
		want    Satisfaction
	}{{0, false, Satisfied}, {3, false, Unsatisfied}, {3, true, Satisfied}} {
		got := e.Evaluate(RequirementContext{Features: map[string]bool{"FEAT_FP16": test.enabled}, Fields: map[string]uint64{"ftype": test.field}})
		if got != test.want {
			t.Fatalf("%+v got %v", test, got)
		}
	}
	c := RequirementExpr{Op: "if", Args: []RequirementExpr{UnknownRequirement("condition"), {Op: "true"}, {Op: "true"}}}
	if c.Evaluate(RequirementContext{}) != Satisfied {
		t.Fatal("equal conditional branches should resolve")
	}
	sliced := ParseRequirementExpression("size<3:2> == '1x'", false)
	if sliced.Evaluate(RequirementContext{Fields: map[string]uint64{"size": 8}}) != Satisfied {
		t.Fatal("field slice mask lost")
	}
	if (Requirements{}).Evaluate(RequirementContext{}).Primary != Unknown {
		t.Fatal("missing metadata became baseline")
	}
}

func TestRequirementSquareFieldSlices(t *testing.T) {
	for _, source := range []string{"op[1] == '0'", "op[3:2] == '1x'", "op[3:2] != '01'"} {
		angle := strings.NewReplacer("[", "<", "]", ">").Replace(source)
		for value := uint64(0); value < 16; value++ {
			context := RequirementContext{Fields: map[string]uint64{"op": value}}
			got, want := ParseRequirementExpression(source, false).Evaluate(context), ParseRequirementExpression(angle, false).Evaluate(context)
			if got == Unknown || got != want {
				t.Fatalf("%s op%d: %v want %v", source, value, got, want)
			}
		}
	}
	for _, source := range []string{"op[0:1] == '00'", "op[64] == '0'", "op[2:1] == '0'"} {
		if got := ParseRequirementExpression(source, false).Evaluate(RequirementContext{Fields: map[string]uint64{"op": 0}}); got != Unknown {
			t.Fatalf("invalid slice %s: %v", source, got)
		}
	}
}

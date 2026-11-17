package codec

import (
	"encoding/json"
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedRequirementAdmission(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	expr := ir.RequirementExpr{Op: "if", Args: []ir.RequirementExpr{{Op: "field_eq", Name: "imm", Mask: 1, Value: 1}, ir.RequirementAll(ir.RequirementExpr{Op: "feature", Name: "A"}, ir.RequirementAny(ir.RequirementExpr{Op: "feature", Name: "B"}, ir.RequirementExpr{Op: "feature", Name: "C"}), ir.RequirementNot(ir.RequirementExpr{Op: "feature", Name: "D"})), {Op: "true"}}}
	cat, err := NewCatalog("requirements_test", "fixture", []Encoding{{ID: "OP", Mnemonic: "op", Syntax: "op {imm}", Mask: []byte{0xfe}, Value: []byte{0x80}, Operands: []Operand{{Name: "imm", Kind: "immediate", Bits: []BitSlice{{InstructionBit: 0, Width: 1}}}}, Requirements: ir.Requirements{Expression: &expr}}, {ID: "OPAQUE", Mnemonic: "opaque", Syntax: "opaque", Mask: []byte{0xff}, Value: []byte{0x90}, Features: []string{"HasFoo"}, SourcePredicates: []string{"HasFoo"}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := cat.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	test := `use requirements_test::*;
use requirements::{Satisfaction::*,UnknownPolicy};
#[test] fn admission() {
 let d=decode(&[0x81]).unwrap();
 assert_eq!(d.evaluate_requirements(&["A","C"],"").primary,Satisfied);
 assert_eq!(d.evaluate_requirements(&["A"],"").primary,Unsatisfied);
 assert_eq!(d.evaluate_requirements(&["A","C","D"],"").primary,Unsatisfied);
 let d=decode(&[0x80]).unwrap(); assert_eq!(d.evaluate_requirements(&[],"").primary,Satisfied);
 let d=decode(&[0x90]).unwrap(); let e=d.evaluate_requirements(&["HasFoo"],"");
 assert_eq!(e.primary,Unknown); assert!(!e.admit(UnknownPolicy::Reject)); assert!(e.admit(UnknownPolicy::Allow));
}
`
	if err := os.WriteFile(filepath.Join(dir, "tests", "requirements.rs"), []byte(test), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "requirements", "--quiet")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated requirements: %v\n%s", err, out)
	}
}

func TestTableGenPredicatesRemainOpaqueRequirements(t *testing.T) {
	var record map[string]any
	if err := json.Unmarshal([]byte(`{"Inst":[1,0,0,0,0,0,0,0],"Size":1,"AsmString":"opaque","Predicates":[{"def":"HasFoo"}]}`), &record); err != nil {
		t.Fatal(err)
	}
	e, err := tableGenEncoding("OPAQUE", record, TableGenOptions{Architecture: "fixture", LittleEndian: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.SourcePredicates) != 1 || e.SourcePredicates[0] != "HasFoo" {
		t.Fatal("source predicate lost", e.SourcePredicates)
	}
	if got := encodingRequirements(e).Evaluate(ir.RequirementContext{Features: map[string]bool{"HasFoo": true}}).Primary; got != ir.Unknown {
		t.Fatalf("predicate fabricated a feature: %v", got)
	}
}

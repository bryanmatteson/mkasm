package x86

import (
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpcodesDBRequirementMetadata(t *testing.T) {
	input := `{"version":"3","arch":"x86","records":[{"id":"SCALAR","rectype":"ENCODING","extensions":["OPTIONAL"],"metadata":{"isa":"FEAT_OPTIONAL || FEAT_ALTERNATIVE"},"diagram":{"fields":[{"name":"OP","value":"0x90"}]},"templates":[{"syntax":{"mnem":"SCALAR"}}]},{"id":"MISSING","rectype":"ENCODING","diagram":{"fields":[{"name":"OP","value":"0x91"}]},"templates":[{"syntax":{"mnem":"MISSING"}}]}]}`
	c, err := ParseOpcodesDB(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Encodings[0].SourceExtensions) != 1 || c.Encodings[0].SourceISA != "FEAT_OPTIONAL || FEAT_ALTERNATIVE" {
		t.Fatalf("lost source metadata: %+v", c.Encodings[0])
	}
	if got := c.Encodings[0].Requirements.Evaluate(ir.RequirementContext{Features: map[string]bool{"FEAT_ALTERNATIVE": true}}).Primary; got != ir.Satisfied {
		t.Fatal("ISA expression flattened", got)
	}
	if got := c.Encodings[1].Requirements.Evaluate(ir.RequirementContext{}).Primary; got != ir.Unknown {
		t.Fatal("missing metadata invented a baseline", got)
	}
}

func TestGeneratedX86Requirements(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	catalog := codecCatalog()
	e := ir.RequirementExpr{Op: "feature", Name: "OPTIONAL_SCALAR"}
	catalog.Encodings[0].Requirements = ir.Requirements{Expression: &e}
	fallback := ir.RequirementNot(e)
	catalog.Encodings[1].Requirements = ir.Requirements{Expression: &e, Fallback: &fallback, FallbackBehavior: "alternate"}
	dir := t.TempDir()
	if err := GenerateRust(catalog, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	test := `use x86_64::*;
use requirements::{Satisfaction::*,UnknownPolicy};
#[test] fn admission() {
 let scalar=decode(&[0x90],Mode::Mode64).unwrap();
 assert_eq!(scalar.evaluate_requirements(&[],Mode::Mode64).primary,Unsatisfied);
 assert_eq!(scalar.evaluate_requirements(&["OPTIONAL_SCALAR"],Mode::Mode64).primary,Satisfied);
 let opaque=requirements_for("ENDBR64/0").evaluate(&[],"x86_64",&|_|None);
 assert_eq!(opaque.primary,Unknown); assert!(!opaque.admit(UnknownPolicy::Reject));
 let wrong_mode=requirements_for("ENDBR64/0").evaluate(&[],"x86_32",&|_|None);
 assert_eq!(wrong_mode.primary,Unsatisfied);
 assert_eq!(requirements_for("ADD_rm64_r64/0").evaluate(&[],"x86_32",&|_|None).fallback,Some(Unsatisfied));
 assert_eq!(requirements_for("ADD_rm64_r64/0").evaluate(&[],"x86_64",&|_|None).fallback,Some(Satisfied));
}
`
	if err := os.WriteFile(filepath.Join(dir, "tests", "requirements.rs"), []byte(test), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "requirements", "--quiet")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated requirement admission: %v\n%s", err, out)
	}
}

package arm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

// Exercise the emitted checked APIs, including a fixed-only allocation that
// must fail. Field range checks alone cannot enforce this boolean constraint.
func TestGeneratedCheckedEncoderAllocationConstraints(t *testing.T) {
	tree, err := ParseBitDiffs("!(bits == '00xx' && bits IN {'000x', '0010'}) && bits != '1111'")
	if err != nil {
		t.Fatal(err)
	}
	instr := &ir.InstructionIR{EncodingID: "VARIABLE", IClass: "test", Mnemonic: "VARIABLE", BitPattern: strings.Repeat("0", 28) + "xxxx", Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "bits", Start: 0, End: 3}}}, BitDiffsTree: tree}
	if err := ir.ResolveBitDiffFields(tree, instr.Encoding); err != nil {
		t.Fatal(err)
	}
	fixedTree := &ir.BitDiffNode{Kind: ir.BitDiffAtomKind, Atom: &ir.BitDiffAtom{Start: 0, End: 0, Op: ir.BitDiffEq, Bits: "1"}}
	zero := uint64(0)
	fixed := &ir.InstructionIR{EncodingID: "FIXED", IClass: "test", Mnemonic: "FIXED", BitPattern: strings.Repeat("0", 32), Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "fixed", Start: 0, End: 31, Fixed: &zero}}}, BitDiffsTree: fixedTree}
	instructions := []*ir.InstructionIR{instr, fixed}
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module constraintconsumer\n\ngo 1.22\n")
	write("encoders.go", emitMasterEncoderSource(nil, nil, instructions))
	var goTest, rustTest strings.Builder
	goTest.WriteString("package encoders\nimport \"testing\"\nfunc TestAllocation(t *testing.T){\n")
	rustTest.WriteString("\n#[test]fn allocation_constraints(){\n")
	for value := 0; value < 16; value++ {
		want := value >= 3 && value != 15
		fmt.Fprintf(&goTest, "{ w,err:=EncodeWithFields(\"VARIABLE\",map[string]uint64{\"bits\":%d}); if (err==nil)!=%t {t.Fatalf(\"value %d: %%v\",err)};if err==nil&&w!=%d {t.Fatal(w)} }\n", value, want, value, value)
		fmt.Fprintf(&rustTest, "{let result=encode_with_fields(\"VARIABLE\",&[(\"bits\",%d)]);assert_eq!(result.is_ok(),%t,\"value %d\");if let Ok(word)=result{assert_eq!(word,%d);}}\n", value, want, value, value)
	}
	goTest.WriteString("if _,err:=EncodeWithFields(\"FIXED\",nil);err==nil{t.Fatal(\"fixed allocation bypassed constraint\")}\n}\n")
	rustTest.WriteString("assert!(matches!(encode_with_fields(\"FIXED\",&[]),Err(EncodeError::AllocationConstraint(_))));\n}\n")
	write("encoders_test.go", goTest.String())
	catalog := BuildCatalog(instructions)
	data := struct{ FixedTable, FieldsTable, ClassTable string }{emitRustFixedTable(catalog), emitRustFieldsTable(catalog), emitRustClassTable(catalog)}
	tmpl, err := template.New("rust").ParseFS(assettemplates.FS, "rust/encoders.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	if err := tmpl.ExecuteTemplate(&source, "encoders.rs.tmpl", data); err != nil {
		t.Fatal(err)
	}
	write("encoders.rs", source.String()+rustTest.String())
	for _, args := range [][]string{{"go", "test", "."}, {"rustc", "--edition=2021", "--test", "encoders.rs", "-Dwarnings", "-o", "constraint-tests"}, {filepath.Join(dir, "constraint-tests")}} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

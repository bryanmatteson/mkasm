package codec

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedRustRecipeUnsupported(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	if err := exampleCatalog(t).GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	const consumer = `use example::*;
 #[test]fn imported_mnemonics_do_not_imply_semantics(){
 let bytes=encode("MOV",&[2,-8]).unwrap();let d=decode(&bytes).unwrap();let recipe=d.semantic_recipe(0x1000);
 assert!(matches!(recipe.support,semantics::Support::Unsupported(_)));assert!(recipe.effects.is_empty());assert!(recipe.temporaries.is_empty());
 assert!(matches!(recipe.flow.kind,semantics::FlowKind::Next));
 }
 `
	if err := os.WriteFile(filepath.Join(dir, "tests", "recipes.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "recipes", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("common recipe API: %v\n%s", err, out)
	}
}

package arm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the same numeric/alias/trap tests through the real upstream decoder,
// rather than a mnemonic or synthetic encoding fixture.
func TestRustA64SVEGatherScatterCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the real Arm A64 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := NewARMParser(ARMParserConfig{EncodingIndexPath: ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: ArchAArch64, Languages: []CodegenLang{LangRust}})
	defer func() {
		if err := parser.Close(5 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_memory.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[allow(dead_code)]mod runtime;\nuse runtime::*;\nuse runtime::arm64_sve_memory::a64;", `use aarch64::semantics::*;
fn a64(word:u32,address:u64,endian:Endian,vl:u16)->Option<Recipe> {
 let decoded=aarch64::decode(word).ok()?;
 let recipe=decoded.semantic_recipe_with_context(address,aarch64::recipes::RecipeContext{endian,vector_length:vl,streaming_vector_length:None});
 if recipe.support==Support::Full{Some(recipe)}else{None}
}`, 1)
	if strings.Contains(source, "mod runtime;") || !strings.Contains(source, "aarch64::decode(word)") {
		t.Fatal("fixture must exercise generated decoder")
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_memory.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_memory.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-memory-tests"},
		{"./sve-memory-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE gather/scatter consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}

}

package semantics_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

func TestRustA64SVEFaultLoadsCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the June 2026 A64 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	corpus, err := arm.OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := arm.NewARMParser(arm.ARMParserConfig{EncodingIndexPath: arm.ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: arm.ArchAArch64, Languages: []arm.CodegenLang{arm.LangRust}})
	defer parser.Close(5 * time.Second)
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("testdata/arm64_sve_fault.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	const directCall = "semantics::arm64_sve_fault::a64(word,0x1000,endian,vl).unwrap()"
	if strings.Count(source, directCall) != 1 {
		t.Fatal("fixture recipe adapter changed")
	}
	source = strings.Replace(source, directCall, "aarch64::decode(word).unwrap().semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:None,endian})", 1)
	if err := os.WriteFile(filepath.Join(dir, "fault.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "fault.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "fault-tests"},
		{"./fault-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated public SVE fault loads %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

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

func TestRustA64ScalableEnhancedBFloatCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the June Arm A64 archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	native, err := os.ReadFile("../../../binary-toolkit/crates/isa/core/src/floating_point/bfloat16.rs")
	if os.IsNotExist(err) {
		t.Skip("native BF16 consumer checkout unavailable")
	}
	if err != nil {
		t.Fatal(err)
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
	fixture, err := os.ReadFile("../semantics/testdata/arm64_scalable_bfloat.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := string(fixture)
	start := strings.Index(source, "fn recipe(")
	end := strings.Index(source, "#[derive(Default)]")
	if start < 0 || end <= start {
		t.Fatal("scalable BF16 fixture preamble changed")
	}
	source = "use aarch64::semantics;\n" + source[:start] + `fn recipe(word:u32,vl:u16,_sme:bool)->Recipe{aarch64::decode(word).unwrap_or_else(|e|panic!("decode {word:08x}: {e:?}")).semantic_recipe_with_vector_length(0x1000,vl)}
` + source[end:]
	for name, data := range map[string]string{"bfloat.rs": source, "native_bfloat.rs": strings.ReplaceAll(string(native), "crate::", "crate::native_contract::")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "bfloat.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "bfloat-tests"}, {"./bfloat-tests"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated scalable BF16 %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

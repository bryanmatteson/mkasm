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
	"github.com/bryanmatteson/mkasm/pkg/semantics"
)

func TestRustA64SVEScaleLogB(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	body, err := os.ReadFile("testdata/arm64_sve_scale.rs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"semantics.rs": semantics.RustRuntime, "scale.rs": string(body)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runScaleRust(t, dir, "--edition=2021", "--test", "scale.rs", "-Dwarnings", "-o", "scale-tests")
	runScaleRust(t, dir, "./scale-tests")
}

// The same behavior tests run through the real June decoder and its public
// recipe method. No synthetic decoder or mnemonic-directed recipe is involved.
func TestRustA64SVEScaleLogBProduction(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the real Arm A64 XML archive")
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
	defer func() {
		if err := parser.Close(5 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("testdata/arm64_sve_scale.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[allow(dead_code)]\n#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	source = strings.Replace(source, "semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl)", "aarch64::decode(word).ok().map(|decoded| decoded.semantic_recipe_with_vector_length(0x1000, vl)).filter(|r| r.support == Support::Full)", 1)
	// The generic decoder also owns BFSCALE: the byte-sized slot reserved in
	// the ordinary FSCALE family is a valid BFloat instruction, not a decode hole.
	source = strings.Replace(source,
		"for word in [0x65098020, 0x6518a020, 0x641e8020]",
		`let bfloat = aarch64::decode(0x65098020).unwrap();
        assert!(bfloat.format(0x1000).unwrap().to_ascii_lowercase().starts_with("bfscale "));
        assert_eq!(bfloat.semantic_recipe_with_vector_length(0x1000, 128).support, Support::Full);
        for word in [0x6518a020, 0x641e8020]`, 1)
	if !strings.Contains(source, "aarch64::decode(word)") || strings.Contains(source, "mod semantics;") {
		t.Fatal("fixture must exercise the generated production decoder and recipe API")
	}
	if err := os.WriteFile(filepath.Join(dir, "scale.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	runScaleRust(t, dir, "--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib")
	runScaleRust(t, dir, "--edition=2021", "--test", "scale.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "scale-tests")
	runScaleRust(t, dir, "./scale-tests")
}

func runScaleRust(t *testing.T, dir string, args ...string) {
	t.Helper()
	program := "rustc"
	if strings.HasPrefix(args[0], "./") {
		program, args = filepath.Join(dir, strings.TrimPrefix(args[0], "./")), args[1:]
	}
	cmd := exec.Command(program, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", program, err, out)
	} else if len(out) != 0 {
		t.Log(string(out))
	}
}

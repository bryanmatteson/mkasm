package arm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// These tests consume complete upstream corpora, supplied explicitly so the
// ordinary unit suite never downloads an ISA release or assumes a local path.
func TestGeneratedArmRelocation(t *testing.T) {
	for _, tc := range []struct {
		name, env, consumer string
		arch                Arch
	}{
		{"a64", "MKASM_RELOCATION_A64_CORPUS", "relocation_a64.rs", ArchAArch64},
		{"arm32", "MKASM_RELOCATION_ARM32_CORPUS", "relocation_arm32.rs", ArchARM32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := os.Getenv(tc.env)
			if source == "" {
				t.Skip("set " + tc.env + " to a complete ISA XML archive")
			}
			corpus, err := OpenTarXMLCorpus(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			p := NewARMParser(ARMParserConfig{EncodingIndexPath: tc.arch.SpecIndexFile(), Corpus: corpus, OutputDirectory: out, Arch: tc.arch, Languages: []CodegenLang{LangRust}})
			defer func() {
				if err := p.Close(5 * time.Second); err != nil {
					t.Error(err)
				}
			}()
			if err := p.Parse(context.Background()); err != nil {
				t.Fatal(err)
			}
			consumer, err := os.ReadFile(filepath.Join("testdata", tc.consumer))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "tests", "relocation.rs"), consumer, 0644); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("cargo", "test", "--test", "relocation", "--quiet")
			command.Dir = out
			command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
			if b, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated relocation consumer: %v\n%s", err, b)
			}
		})
	}
}

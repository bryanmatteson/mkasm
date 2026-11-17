package semantics_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/arm"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRustA64SVEBoundedRoundCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the June2026 A64 XML archive")
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
	runtime, err := os.ReadFile(filepath.Join(dir, "src/semantics.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtime), "pub mod arm64_sve") {
		t.Fatal("production runtime must embed the SVE bounded-round FP helper")
	}

	fixture, err := os.ReadFile("testdata/arm64_sve_bounded_round.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(fixture), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	if strings.Contains(source, "mod semantics;") {
		t.Fatal("fixture preamble changed")
	}
	recipes, err := os.ReadFile(filepath.Join(dir, "src/recipes.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recipes), "arm64_sve::a64") {
		t.Fatal("production public recipe builder must dispatch the SVE bounded-round FP helper")
	}
	const helperCall = "fn recipe(word: u32, vl: u16) -> Recipe {\n    semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl).unwrap()\n}"
	if strings.Count(source, helperCall) != 1 {
		t.Fatal("fixture recipe adapter changed")
	}
	source = strings.Replace(source, helperCall, "fn recipe(word:u32,vl:u16)->Recipe { aarch64::decode(word).unwrap().semantic_recipe_with_vector_length(0x1000,vl) }", 1)
	t.Log("behavioral fixture uses actual generated public recipe API")

	source += sveBoundedRoundPrimary(t, path)
	if err := os.WriteFile(filepath.Join(dir, "bounded_round.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "bounded_round.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "bounded-round-tests"}, {"./bounded-round-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE while extra %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func sveBoundedRoundPrimary(t *testing.T, path string) string {
	t.Helper()
	selected := map[string]bool{}
	for _, n := range strings.Fields("frint32x frint32z frint64x frint64z") {
		selected[n+"_z_p_z.xml"] = true
	}
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Name  string `xml:"name,attr"`
		Cells []cell `xml:"c"`
	}
	type enc struct {
		Name string `xml:"name,attr"`
	}
	type cl struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Enc []enc `xml:"encoding"`
	}
	type page struct {
		Classes []cl `xml:"classes>iclass"`
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	classes := 0
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_bounded_round_encoding_classes(){for(word,id)in[\n")
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !selected[name] || seen[name] || !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		seen[name] = true
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		for _, c := range p.Classes {
			classes++
			if len(c.Enc) != 1 {
				t.Fatal("unexpected class")
			}
			var base uint32
			sizebit := 0
			for _, b := range c.Diagram.Boxes {
				pos := b.Hi
				if b.Name == "sz" {
					sizebit = b.Hi
				}
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					bits := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(bits) != span {
						bits = strings.Repeat("x", span)
					}
					for _, bit := range bits {
						if bit == '1' {
							base |= 1 << uint(pos)
						}
						pos--
					}
				}
			}
			for size := uint32(0); size < 2; size++ {
				fmt.Fprintf(&out, "(0x%08xu32,%q),\n", base|(size<<uint(sizebit))|(1<<5), c.Enc[0].Name)
			}
		}
	}
	if len(seen) != 4 || classes != 8 {
		t.Fatalf("primary classes: %d pages %d classes", len(seen), classes)
	}
	out.WriteString(`]{let d=aarch64::decode(word).unwrap();assert!(d.encoding_id==id||d.ambiguous.iter().any(|x|x==id),"{word:08x} {id} {}",d.encoding_id);for feat in["FEAT_SVE2p2","FEAT_SME2p2"]{assert_eq!(d.evaluate_requirements(&[feat],"a64").primary,aarch64::requirements::Satisfaction::Satisfied);}for vl in[128,256,512,1024,2048]{let r=recipe(word,vl);assert_eq!(r.support,Support::Full);r.validate().unwrap();}}}`)
	t.Logf("June primary: %d pages %d classes, both widths and all VLs", len(seen), classes)
	return out.String()
}

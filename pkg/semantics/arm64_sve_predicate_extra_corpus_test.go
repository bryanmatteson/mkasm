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

func TestRustA64SVEPredicateExtraCorpus(t *testing.T) {
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
	if !strings.Contains(string(runtime), "pub mod arm64_sve_predicate_extra") {
		t.Fatal("production runtime must embed the SVE predicate helper")
	}

	fixture, err := os.ReadFile("testdata/arm64_sve_predicate_extra.rs")
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
	if !strings.Contains(string(recipes), "arm64_sve_predicate_extra::a64") {
		t.Fatal("production public recipe builder must dispatch the SVE predicate helper")
	}
	const helperCall = "semantics::arm64_sve_predicate_extra::a64(word, 0x1000, vl)"
	if strings.Count(source, helperCall) != 1 {
		t.Fatal("fixture recipe adapter changed")
	}
	source = strings.Replace(source, helperCall, "aarch64::decode(word).ok().map(|d| d.semantic_recipe_with_vector_length(0x1000,vl))", 1)
	t.Log("behavioral fixture uses actual generated public recipe API")

	source += svePredicateExtraPrimary(t, path)
	if err := os.WriteFile(filepath.Join(dir, "predicate_extra.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "predicate_extra.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "predicate-extra-tests"}, {"./predicate-extra-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE predicate extra %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func svePredicateExtraPrimary(t *testing.T, path string) string {
	t.Helper()
	selected := map[string]bool{}
	for _, n := range strings.Fields("rdffr_p_f rdffr_p_p_f rdffrs_p_p_f wrffr_f_p setffr_f cnot_z_p_z cpy_z_o_i cpy_z_p_i cpy_z_p_r cpy_z_p_v fcpy_z_p_i fdup_z_i") {
		selected[n+".xml"] = true
	}
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name string `xml:"name,attr"`
	}
	type class struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
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
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	words := map[uint32]bool{}
	classes := 0
	var out strings.Builder
	out.WriteString("\n#[test] fn all_primary_extra_classes_legal_selectors_and_features(){\n for(word,id)in[\n")
	for {
		h, err := reader.Next()
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
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			classes++
			if len(cl.Encodings) != 1 {
				t.Fatalf("unexpected multi-encoding class %s", name)
			}
			var fixed, base, controls uint32
			for _, b := range cl.Diagram.Boxes {
				pos := b.Hi
				for _, cell := range b.Cells {
					span := cell.Span
					if span == 0 {
						span = 1
					}
					bits := strings.Trim(strings.TrimSpace(cell.Text), "()")
					if len(bits) != span {
						bits = strings.Repeat("x", span)
					}
					for _, bit := range bits {
						if bit == '0' || bit == '1' {
							fixed |= 1 << uint(pos)
							if bit == '1' {
								base |= 1 << uint(pos)
							}
						}
						pos--
					}
				}
			}
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "size" || b.Name == "sh" {
					width := b.Width
					if width == 0 {
						width = 1
					}
					controls |= (((1 << uint(width)) - 1) << uint(b.Hi-width+1)) &^ fixed
				}
			}
			var controlBits []uint
			for bit := uint(0); bit < 32; bit++ {
				if controls&(1<<bit) != 0 {
					controlBits = append(controlBits, bit)
				}
			}
			for combo := uint32(0); combo < 1<<uint(len(controlBits)); combo++ {
				for pattern := 0; pattern < 4; pattern++ {
					word := base
					for j, bit := range controlBits {
						word |= ((combo >> uint(j)) & 1) << bit
					}
					values := map[string]uint32{}
					for j, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						if b.Name == "" {
							continue
						}
						value := uint32(0)
						if strings.HasPrefix(b.Name, "Z") || strings.HasPrefix(b.Name, "R") || strings.HasPrefix(b.Name, "P") {
							switch pattern {
							case 0:
								value = uint32(j*7 + 1)
							case 1:
								value = 1
							case 2:
								value = 31
							case 3:
								if b.Name == "Zd" || b.Name == "Zdn" || b.Name == "Zda" || b.Name == "Rd" {
									value = 2
								} else {
									value = uint32(j + 1)
								}
							}
							low := uint(b.Hi - width + 1)
							word |= (value << low) & (((1 << uint(width)) - 1) << low) &^ fixed
						}
						if b.Name == "imm8" {
							low := uint(b.Hi - width + 1)
							word &^= 255 << low
							word |= []uint32{0, 127, 128, 255}[pattern] << low
						}
						values[b.Name] = (word >> uint(b.Hi-width+1)) & ((1 << uint(width)) - 1)
					}
					if ((name == "cpy_z_o_i.xml" || name == "cpy_z_p_i.xml") && values["size"] == 0 && values["sh"] == 1) || ((name == "fcpy_z_p_i.xml" || name == "fdup_z_i.xml") && values["size"] == 0) {
						continue
					}
					if words[word] {
						continue
					}
					words[word] = true
					fmt.Fprintf(&out, "(0x%08xu32,%q),\n", word, cl.Encodings[0].Name)
				}
			}
		}
	}
	if len(seen) != 12 || classes != 13 {
		t.Fatalf("primary cohort: %d pages %d classes", len(seen), classes)
	}
	t.Logf("June primary: %d pages %d encoding classes %d distinct legal words", len(seen), classes, len(words))
	out.WriteString(`]{let d=aarch64::decode(word).unwrap_or_else(|e|panic!("decode {word:08x} {id}: {e:?}"));assert!(d.encoding_id==id||d.ambiguous.iter().any(|other|other==id),"{word:08x} expected{id}, decoded{}",d.encoding_id);assert_eq!(d.evaluate_requirements(&[],"a64").primary,aarch64::requirements::Satisfaction::Unsatisfied,"{id}");assert_eq!(d.evaluate_requirements(&["FEAT_SVE","FEAT_SVE2","FEAT_SME","FEAT_SVE2p2","FEAT_SME2p2"],"a64").primary,aarch64::requirements::Satisfaction::Satisfied,"{id}");for vl in VLS{let r=recipe(d.raw,vl).unwrap();assert_eq!(r.support,Support::Full,"{word:08x} {id} VL{vl}");r.validate().unwrap();}}}
`)
	return out.String()
}

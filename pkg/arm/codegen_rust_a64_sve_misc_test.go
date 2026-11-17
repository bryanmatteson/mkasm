package arm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRustA64SVEMiscCorpus(t *testing.T) {
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_misc.rs")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "use std::")
	if start < 0 {
		t.Fatal("fixture preamble changed")
	}
	source := `use aarch64::semantics::*;
fn a64(word:u32,address:u64,vl:u16)->Option<Recipe>{
 let decoded=aarch64::decode(word).ok()?;
 let recipe=decoded.semantic_recipe_with_vector_length(address,vl);
 if recipe.support==Support::Full{Some(recipe)}else{None}
}
` + string(body)[start:] + a64SVEMiscPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_misc.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_misc.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-misc-tests"},
		{"./sve-misc-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE misc consumer %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

// These physical witnesses come from primary diagrams, not helper masks.
func a64SVEMiscPrimaryCases(t *testing.T, path string) string {
	t.Helper()
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
	type class struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	selected := map[string]bool{}
	for _, name := range strings.Fields("match_p_p_zz nmatch_p_p_zz histcnt_z_p_zz histseg_z_zz addpt_z_zz subpt_z_zz addpt_z_p_zz subpt_z_p_zz") {
		selected[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_misc_dispatch(){for(word,name,legal)in[\n")
	pages, classes, words := 0, 0, 0
	seen := map[uint32]bool{}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(header.Name)
		if !selected[name] || header.Name != "ISA_A64_xml_A_profile-2026-06/"+name {
			continue
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			classes++
			var fixed, base uint32
			for _, b := range cl.Diagram.Boxes {
				var bits strings.Builder
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					value := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(value) != span {
						value = strings.Repeat("x", span)
					}
					bits.WriteString(value)
				}
				for i, c := range bits.String() {
					if c == '0' || c == '1' {
						bit := uint32(1) << uint(b.Hi-i)
						fixed |= bit
						if c == '1' {
							base |= bit
						}
					}
				}
			}
			for size := uint32(0); size < 4; size++ {
				for _, high := range []bool{false, true} {
					word := base
					for _, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						var v uint32
						switch b.Name {
						case "size", "sz":
							v = size
						case "Zn":
							v = 1
						case "Zm":
							v = 2
						case "Zd", "Zdn", "Pd", "Pg":
							if high {
								v = (1 << uint(width)) - 1
							}
						}
						low := uint(b.Hi - width + 1)
						mask := ((uint32(1) << uint(width)) - 1) << low
						word |= (v << low) & mask &^ fixed
					}
					if seen[word] {
						continue
					}
					seen[word] = true
					words++
					legal := true
					if name == "histseg_z_zz.xml" {
						legal = (word>>22)&3 == 0
					}
					if name == "histcnt_z_p_zz.xml" {
						legal = (word>>22)&3 >= 2
					}
					fmt.Fprintf(&out, "(0x%08xu32,%q,%t),\n", word, name, legal)
				}
			}
		}
	}
	if pages != len(selected) || classes != 8 {
		t.Fatalf("primary SVE misc corpus: %d pages %d classes", pages, classes)
	}
	t.Logf("primary SVE misc: %d pages, %d classes, %d distinct words x five VLs", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let r=a64(word,0,vl);if legal{let r=r.unwrap_or_else(||panic!(\"decode {word:08x} {name}\"));assert_eq!(r.support,Support::Full,\"{word:08x} {name} VL{vl}\");r.validate().unwrap();}else{assert!(r.is_none()||r.unwrap().support!=Support::Full,\"reserved {word:08x} {name}\");}}}}\n")
	return out.String()
}

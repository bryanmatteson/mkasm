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

// Run the numerical and access-order oracle through the generated public decoder
// and RecipeContext API, including every CurrentVL and the Q128 access contract.
func TestRustA64SVEStructuredCorpus(t *testing.T) {
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_structured.rs")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "use std::")
	old := `fn recipe(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_structured::a64(word, address, endian, vl)
}`
	if start < 0 || !strings.Contains(string(body), old) {
		t.Fatal("fixture preamble changed")
	}
	source := "use aarch64::semantics::*;\n" + strings.Replace(string(body)[start:], old, `fn recipe(word:u32,address:u64,endian:Endian,vl:u16)->Option<Recipe>{
 let decoded=aarch64::decode(word).ok()?;
 let recipe=decoded.semantic_recipe_with_context(address,aarch64::recipes::RecipeContext{endian,vector_length:vl,streaming_vector_length:None});
 if recipe.support==Support::Full{Some(recipe)}else{None}
}`, 1) + a64SVEStructuredPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_structured.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cases, err := os.ReadFile("../semantics/testdata/arm64_sve_structured_cases.rs")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/arm64_sve_structured_cases.rs"), cases, 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_structured.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "sve-structured-tests"},
		{"./sve-structured-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE structured consumer %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

// Reconstruct witnesses independently from the June primary diagrams. Exercise
// both register extremes, signed-immediate extremes, predicate7, SP and wrap Z31.
func a64SVEStructuredPrimaryCases(t *testing.T, path string) string {
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
	for _, op := range []string{"ld", "st"} {
		for n := 2; n <= 4; n++ {
			for _, size := range []string{"b", "h", "w", "d", "q"} {
				for _, offset := range []string{"bi", "br"} {
					selected[fmt.Sprintf("%s%d%s_z_p_%s.xml", op, n, size, offset)] = true
				}
			}
		}
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_structured_dispatch(){for(word,name,legal)in[\n")
	pages, classes, words := 0, 0, 0
	reader := tar.NewReader(gz)
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !selected[name] || h.Name != "ISA_A64_xml_A_profile-2026-06/"+name {
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
			var base, fixed uint32
			for _, b := range cl.Diagram.Boxes {
				var bits strings.Builder
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					v := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(v) != span {
						v = strings.Repeat("x", span)
					}
					bits.WriteString(v)
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
			for variant := 0; variant < 4; variant++ {
				word := base
				legal := true
				for _, b := range cl.Diagram.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					var value uint32
					switch b.Name {
					case "Zt", "Rn", "Pg":
						if variant != 0 {
							value = (1 << uint(width)) - 1
						}
					case "Rm":
						value = []uint32{0, 30, 31, 1}[variant]
						if value == 31 {
							legal = false
						}
					case "imm4":
						value = []uint32{0, 7, 8, 15}[variant]
					}
					low := uint(b.Hi - width + 1)
					mask := ((uint32(1) << uint(width)) - 1) << low
					word |= (value << low) & mask &^ fixed
				}
				words++
				fmt.Fprintf(&out, "(0x%08xu32,%q,%t),\n", word, name, legal)
			}
		}
	}
	if pages != 60 || classes != 60 {
		t.Fatalf("primary SVE structured corpus: %d pages %d classes", pages, classes)
	}
	t.Logf("primary SVE structured: %d pages, %d classes, %d words x five VLs x two endians", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{for endian in[Endian::Little,Endian::Big]{let r=recipe(word,0,endian,vl);if legal{let r=r.unwrap_or_else(||panic!(\"decode {word:08x} {name}\"));assert_eq!(r.support,Support::Full,\"{word:08x} {name} VL{vl}\");r.validate().unwrap();}else{assert!(r.is_none()||r.unwrap().support!=Support::Full,\"reserved {word:08x} {name}\");}}}}}\n")
	return out.String()
}

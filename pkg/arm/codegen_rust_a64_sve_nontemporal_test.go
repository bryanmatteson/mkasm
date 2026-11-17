package arm

import (
	"archive/tar"
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

// Compile the real June decoder and exercise nontemporal recipes through its
// public context-aware recipe entry, including every byte/alias/fault oracle.
func TestRustA64SVENontemporalCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("June primary corpus unavailable")
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_nontemporal.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[allow(dead_code)]\nmod runtime;\nuse runtime::arm64_sve_nontemporal::a64;\nuse runtime::*;", `use aarch64::semantics::*;
fn a64(word:u32,address:u64,endian:Endian,vl:u16)->Option<Recipe> {
 aarch64::semantics::arm64_sve_nontemporal::a64(word,address,endian,vl)?;
 let decoded=aarch64::decode(word).ok()?;
 Some(decoded.semantic_recipe_with_context(address,aarch64::recipes::RecipeContext{endian,vector_length:vl,streaming_vector_length:None}))
}
`, 1)
	source += a64SVENontemporalGeneratedCorpus(t)
	if strings.Contains(source, "mod runtime;") {
		t.Fatal("fixture must call the production-generated decoder")
	}
	if err := os.WriteFile(filepath.Join(dir, "nontemporal.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "nontemporal.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "nontemporal-tests"}, {"./nontemporal-tests", "nontemporal::", "--test-threads=1"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated nontemporal consumer %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a64SVENontemporalGeneratedCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Skip("June primary corpus unavailable")
	}
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
	tr := tar.NewReader(gz)
	pages, classes, words := 0, 0, 0
	var out strings.Builder
	out.WriteString("\nconst PRIMARY:&[(u32,&str)]=&[\n")
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(h.Name), ".xml")
		if !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") || !(strings.HasPrefix(name, "ldnt1") || strings.HasPrefix(name, "stnt1")) || !(strings.HasSuffix(name, "_z_p_ar") || strings.HasSuffix(name, "_z_p_br") || strings.HasSuffix(name, "_z_p_bi")) {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			classes++
			for variant := 0; variant < 4; variant++ {
				var word uint32
				for _, b := range cl.Diagram.Boxes {
					w := b.Width
					if w == 0 {
						w = 1
					}
					pos := b.Hi
					var mask, value uint32
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						txt := strings.Trim(strings.TrimSpace(c.Text), "()")
						if len(txt) == span {
							for _, bit := range txt {
								if bit == '0' || bit == '1' {
									mask |= 1 << uint(pos)
									if bit == '1' {
										value |= 1 << uint(pos)
									}
								}
								pos--
							}
						} else {
							pos -= span
						}
					}
					v := uint32(0)
					switch b.Name {
					case "Rn", "Zn":
						v = []uint32{0, 31, 29, 1}[variant]
					case "Rm":
						v = []uint32{0, 30, 1, 17}[variant]
					case "Zt":
						v = []uint32{0, 31, 29, 1}[variant]
					case "Pg":
						v = uint32(variant * 2)
					case "imm4":
						v = []uint32{0, 7, 8, 15}[variant]
					}
					region := ((uint32(1) << uint(w)) - 1) << uint(b.Hi-w+1)
					word |= (v<<uint(b.Hi-w+1))&(region&^mask) | value
				}
				fmt.Fprintf(&out, "(0x%08x,%q),\n", word, name)
				words++
			}
		}
	}
	if pages != 27 || classes != 35 || words != 140 {
		t.Fatalf("primary coverage: %d pages %d classes %d words", pages, classes, words)
	}
	t.Logf("June corpus: %d pages, %d classes, %d words", pages, classes, words)
	out.WriteString("];\n")
	return out.String()
}

package semantics_test

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

func TestRustA32ScalarDSPCompletionCorpus(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to June 2026 AArch32 XML")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "Documents/Developer/go-mkasm")
	if err = os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "a32-scalar-dsp-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	corpus, err := arm.OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	parser := arm.NewARMParser(arm.ARMParserConfig{EncodingIndexPath: arm.ArchARM32.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: arm.ArchARM32, Languages: []arm.CodegenLang{arm.LangRust}})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("testdata/arm32_scalar_dsp.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[path = \"semantics.rs\"]\nmod semantics;", "use arm32::semantics;", 1)
	adapter := regexp.MustCompile(`(?s)fn recipe\(word: u32, thumb: bool\) -> Option<Recipe> \{.*?\n\}`)
	if len(adapter.FindAllStringIndex(source, -1)) != 1 {
		t.Fatal("scalar DSP adapter changed")
	}
	source = adapter.ReplaceAllString(source, `fn recipe(word:u32,thumb:bool)->Option<Recipe>{let bytes=if thumb{[(word>>16)as u8,(word>>24)as u8,word as u8,(word>>8)as u8]}else{word.to_le_bytes()};arm32::decode(&bytes,if thumb{arm32::Mode::Thumb}else{arm32::Mode::Arm},arm32::Endian::Little).ok().map(|d|d.semantic_recipe(0x1000))}`)
	source += a32ScalarDSPPrimary(t, path)
	if err = os.WriteFile(filepath.Join(dir, "scalar.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "arm32", "--crate-type", "lib", "src/lib.rs", "-Dwarnings", "-o", "libarm32.rlib"}, {"--edition=2021", "--test", "scalar.rs", "--extern", "arm32=libarm32.rlib", "-Copt-level=1", "-Dwarnings", "-o", "scalar-tests"}, {"./scalar-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		} else {
			t.Log(string(output))
		}
	}
}
func a32ScalarDSPPrimary(t *testing.T, path string) string {
	t.Helper()
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
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
	}
	type class struct {
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	wanted := map[string]bool{}
	for _, n := range strings.Fields("crc32 crc32c mls pkh sadd16 sadd8 sasx sel ssax ssub16 ssub8 sxtab16 sxtb16 uadd16 uadd8 uasx umaal usad8 usada8 usax usub16 usub8 uxtab16 uxtb16") {
		wanted[n+".xml"] = true
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
	var out strings.Builder
	out.WriteString("\nconst PRIMARY_SCALAR_DSP:&[(bool,u32,&str)]=&[\n")
	seen := map[string]bool{}
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !strings.HasPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !wanted[name] || seen[name] {
			continue
		}
		seen[name] = true
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err = xml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			for _, en := range cl.Encodings {
				count++
				for variant := 0; variant < 4; variant++ {
					var word uint32
					for _, b := range append(append([]box(nil), cl.Diagram.Boxes...), en.Boxes...) {
						w := b.Width
						if w == 0 {
							w = 1
						}
						lo := b.Hi - w + 1
						mask := uint32(((uint64(1) << w) - 1) << lo)
						word &= ^mask
						var variable uint32
						switch b.Name {
						case "cond":
							variable = 14
						case "Rn":
							variable = 1
						case "Rm":
							variable = 2
						case "Ra":
							variable = 3
						case "RdHi":
							variable = 1
						case "rotate":
							variable = uint32(variant)
						case "imm5":
							variable = uint32(variant * 10)
						case "imm3":
							variable = uint32(variant)
						case "imm2":
							variable = uint32(variant)
						}
						word |= (variable << lo) & mask
						position := b.Hi
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
								if bit == '0' {
									word &= ^(1 << position)
								} else if bit == '1' {
									word |= 1 << position
								}
								position--
							}
						}
					}
					fmt.Fprintf(&out, "(%t,0x%08x,%q),\n", cl.ISA == "T32", word, en.Name)
				}
			}
		}
	}
	if len(seen) != len(wanted) || count != 58 {
		t.Fatalf("primary scalar DSP: %d/%d pages, %d encodings", len(seen), len(wanted), count)
	}
	out.WriteString(`];
#[test]fn every_primary_scalar_dsp_encoding_decodes_and_builds_complete_recipes(){for &(thumb,word,id)in PRIMARY_SCALAR_DSP{let bytes=if thumb{[(word>>16)as u8,(word>>24)as u8,word as u8,(word>>8)as u8]}else{word.to_le_bytes()};let d=arm32::decode(&bytes,if thumb{arm32::Mode::Thumb}else{arm32::Mode::Arm},arm32::Endian::Little).unwrap();assert!(d.encoding_id()==id||matches!(id,"USADA8_A1"|"USADA8_T1"),"{word:08x} expected{id} got{}",d.encoding_id());let graph=d.semantic_recipe(0x1000);assert_eq!(graph.support,Support::Full,"{word:08x} {id}");graph.validate().unwrap();}}
`)
	t.Logf("June primary scalar DSP: %d pages, %d encoding entries", len(seen), count)
	return out.String()
}

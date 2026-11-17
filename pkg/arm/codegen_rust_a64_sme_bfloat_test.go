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

func TestRustA64SME2BFloatCorpus(t *testing.T) {
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
	base := string(fixture)
	start := strings.Index(base, "fn recipe(")
	end := strings.Index(base, "#[derive(Default)]")
	cut := strings.Index(base, "#[test]\nfn sve_bfloat_")
	cases := strings.Index(base, "const CASES:")
	if start < 0 || end <= start || cut <= end || cases <= cut {
		t.Fatal("shared BF16 fixture preamble changed")
	}
	owned, err := os.ReadFile("../semantics/testdata/arm64_sme_bfloat.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := "use aarch64::semantics;\n" + base[:start] + `fn recipe(word:u32,vl:u16,_sme:bool)->Recipe{aarch64::decode(word).unwrap_or_else(|e|panic!("decode {word:08x}: {e:?}")).semantic_recipe_with_vector_length(0x1000,vl)}
` + base[end:cut] + string(owned) + base[cases:] + a64SME2BFloatPrimaryCases(t, path)
	source = strings.Replace(source, "impl State {", "#[allow(dead_code)]impl State {", 1)
	source = strings.Replace(source, "fn fill(", "#[allow(dead_code)]fn fill(", 1)
	source = strings.Replace(source, "fn output(", "#[allow(dead_code)]fn output(", 1)
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
			t.Fatalf("generated SME2 BF16 %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

// Derive physical witnesses from all six June diagrams independently of the
// implementation's form parser, including selectors and high register fields.
func a64SME2BFloatPrimaryCases(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
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
	expected := map[[2]uint32]bool{{0xfff09038, 0xc1501018}: false, {0xfff09078, 0xc1509018}: false, {0xfff09c18, 0xc1201010}: false, {0xfff09c18, 0xc1301010}: false, {0xffe19c38, 0xc1a01010}: false, {0xffe39c78, 0xc1a11010}: false}
	selected := map[string]bool{"bfdot_za_zzi.xml": true, "bfdot_za_zzv.xml": true, "bfdot_za_zzw.xml": true}
	var out strings.Builder
	out.WriteString("\n#[test]fn sme2_bfdot_primary_physical_dispatch(){for(word,name)in[\n")
	seen := map[uint32]bool{}
	pages, classes := 0, 0
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
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
		var p page
		if err := xml.NewDecoder(tr).Decode(&p); err != nil {
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
					v := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(v) != span {
						v = strings.Repeat("x", span)
					}
					bits.WriteString(v)
				}
				for i, c := range bits.String() {
					if c == '0' || c == '1' {
						fixed |= 1 << uint(b.Hi-i)
						if c == '1' {
							base |= 1 << uint(b.Hi-i)
						}
					}
				}
			}
			key := [2]uint32{fixed, base}
			if _, ok := expected[key]; !ok {
				t.Fatalf("unexpected SME2 BF16 diagram %s %08x/%08x", name, fixed, base)
			}
			expected[key] = true
			for _, high := range []bool{false, true} {
				for selector := uint32(0); selector < 4; selector++ {
					for index := uint32(0); index < 4; index++ {
						word := base
						for _, b := range cl.Diagram.Boxes {
							width := b.Width
							if width == 0 {
								width = 1
							}
							var value uint32
							if high {
								value = (1 << uint(width)) - 1
							}
							if b.Name == "Rv" {
								value = selector
							}
							if b.Name == "i2" {
								value = index
							}
							mask := ((uint32(1) << uint(width)) - 1) << uint(b.Hi-width+1)
							word |= value << uint(b.Hi-width+1) & mask &^ fixed
						}
						if !seen[word] {
							seen[word] = true
							fmt.Fprintf(&out, "(0x%08xu32,%q),\n", word, name)
						}
					}
				}
			}
		}
	}
	if pages != 3 || classes != 6 {
		t.Fatalf("SME2 BF16 corpus has %d pages/%d classes", pages, classes)
	}
	for key, found := range expected {
		if !found {
			t.Fatalf("missing SME2 BF16 diagram %x", key)
		}
	}
	t.Logf("SME2 BF16 primary: %d classes, %d physical words x five SVLs", classes, len(seen))
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let r=recipe(word,vl,true);assert_eq!(r.support,Support::Full,\"{word:08x} {name} SVL{vl}\");r.validate().unwrap();}}}\n")
	return out.String()
}

func TestA64SME2BFloatPrimaryDiagrams(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("optional June architecture corpus unavailable")
	}
	a64SME2BFloatPrimaryCases(t, path)
}

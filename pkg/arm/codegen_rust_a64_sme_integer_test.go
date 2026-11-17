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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Run the independent integer-state oracle through the public decoder and
// semantic_recipe_with_vector_length API emitted from the complete Arm corpus.
func TestRustA64SMEIntegerCorpus(t *testing.T) {
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sme_integer.rs")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := os.ReadFile("../semantics/testdata/arm64_sme_integer_cases.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	source = strings.Replace(source, "semantics::arm64_sme::a64(word, 0x1000, svl)", "aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_vector_length(0x1000,svl)).filter(|r|r.support==Support::Full)", 1)
	if strings.Contains(source, "mod semantics;") || !strings.Contains(source, "aarch64::decode(word)") {
		t.Fatal("fixture must use generated decoder")
	}
	source += a64SMEIntegerPrimaryCases(t, path, string(cases))
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"sme_integer.rs": []byte(source), "arm64_sme_integer_cases.rs": cases} {
		if err := os.WriteFile(filepath.Join(dir, "tests", name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sme_integer.rs", "-Copt-level=1", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sme-integer-tests"},
		{"./sme-integer-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SME integer consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}
}

// Read primary diagrams independently of recipe masks. Every diagram must be
// represented in the checked-in behavioral cohort; additional word cases cover
// all element-size selectors, immediate endpoints and reserved tsize=00 forms.
func a64SMEIntegerPrimaryCases(t *testing.T, path, fixture string) string {
	t.Helper()
	selected := map[string]bool{}
	for _, name := range strings.Fields("sdot_za32_zzi sdot_za32_zzv sdot_za32_zzw sdot_za_zzi sdot_za_zzv sdot_za_zzw smlal_za_zzi smlal_za_zzv smlal_za_zzw smlall_za_zzi smlall_za_zzv smlall_za_zzw smlsl_za_zzi smlsl_za_zzv smlsl_za_zzw smlsll_za_zzi smlsll_za_zzv smlsll_za_zzw sqcvt_z_mz2 sqcvt_z_mz4 sqcvtn_z_mz2 sqcvtn_z_mz4 sqcvtu_z_mz2 sqcvtu_z_mz4 sqcvtun_z_mz2 sqcvtun_z_mz4 uqcvt_z_mz2 uqcvt_z_mz4 uqcvtn_z_mz2 uqcvtn_z_mz4 srshl_mz_zzv srshl_mz_zzw urshl_mz_zzv urshl_mz_zzw sqdmulh_mz_zzv sqdmulh_mz_zzw sqrshr_z_mz2 sqrshr_z_mz4 sqrshrn_z_mz2 sqrshrn_z_mz4 sqrshru_z_mz2 sqrshru_z_mz4 sqrshrun_z_mz2 sqrshrun_z_mz4 sqshrn_z_mz2 sqshrun_z_mz2 sudot_za_zzi sudot_za_zzv udot_za32_zzi udot_za32_zzv udot_za32_zzw udot_za_zzi udot_za_zzv udot_za_zzw umlal_za_zzi umlal_za_zzv umlal_za_zzw umlall_za_zzi umlall_za_zzv umlall_za_zzw umlsl_za_zzi umlsl_za_zzv umlsl_za_zzw umlsll_za_zzi umlsll_za_zzv umlsll_za_zzw uqrshr_z_mz2 uqrshr_z_mz4 uqrshrn_z_mz2 uqrshrn_z_mz4 uqshrn_z_mz2 usdot_za_zzi usdot_za_zzv usdot_za_zzw") {
		selected[name+".xml"] = true
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
	type class struct {
		Name    string `xml:"name,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Decode string `xml:"ps_section>ps>pstext"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	var behavior []uint32
	for _, match := range regexp.MustCompile(`word:\s*0x([0-9a-f]+)`).FindAllStringSubmatch(fixture, -1) {
		value, err := strconv.ParseUint(match[1], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		behavior = append(behavior, uint32(value))
	}
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
	reader := tar.NewReader(gz)
	seenPages := map[string]bool{}
	seenWords := map[uint32]bool{}
	classes := 0
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sme_integer_dispatch(){let mut failures=Vec::new();for(word,name,legal)in[\n")
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !selected[name] || seenPages[name] || !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		seenPages[name] = true
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			classes++
			var mask, base uint32
			for _, b := range cl.Diagram.Boxes {
				position := b.Hi
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
							mask |= 1 << uint(position)
							if bit == '1' {
								base |= 1 << uint(position)
							}
						}
						position--
					}
				}
			}
			covered := false
			for _, word := range behavior {
				if word&mask == base {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("behavioral cohort omits %s/%s mask%08x value%08x", name, cl.Name, mask, base)
			}
			for size := uint32(0); size < 4; size++ {
				for _, high := range []bool{false, true} {
					word := base
					for _, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						value := uint32(0)
						switch b.Name {
						case "size", "sz", "tsize":
							value = size
						case "Zn", "Zm":
							value = 1
							if high {
								value = (1 << uint(width)) - 1
							}
						case "Zd", "Zdn", "Rv", "off3", "off2", "o1", "i1", "i2", "i3h", "i3l", "i4h", "i4l", "imm3", "imm4", "imm5":
							if high {
								value = (1 << uint(width)) - 1
							}
						}
						low := uint(b.Hi - width + 1)
						word |= (value << low) & (((1 << uint(width)) - 1) << low) &^ mask
					}
					if seenWords[word] {
						continue
					}
					seenWords[word] = true
					legal := true
					if strings.Contains(cl.Decode, "tsize == '00'") {
						for _, b := range cl.Diagram.Boxes {
							if b.Name == "tsize" {
								width := b.Width
								if width == 0 {
									width = 1
								}
								legal = (word>>uint(b.Hi-width+1))&((1<<uint(width))-1) != 0
							}
						}
					}
					fmt.Fprintf(&out, "(0x%08xu32,%q,%t),\n", word, name, legal)
				}
			}
		}
	}
	if len(seenPages) != len(selected) {
		t.Fatalf("primary SME integer pages: found%d expected%d", len(seenPages), len(selected))
	}
	t.Logf("primary SME integer: %d pages, %d classes, %d behavioral words, %d independent dispatch words", len(seenPages), classes, len(behavior), len(seenWords))
	out.WriteString("]{for svl in[128,256,512,1024,2048]{if !legal {if let Ok(d)=aarch64::decode(word){if d.semantic_recipe_with_vector_length(0x1000,svl).support==Support::Full{failures.push(format!(\"overadmitted {word:08x} {name} SVL{svl}\"));}}continue;}match recipe(word,svl){Some(r)=>if let Err(e)=r.validate(){failures.push(format!(\"invalid {word:08x} {name} SVL{svl}: {e:?}\"));},None=>failures.push(format!(\"unhandled {word:08x} {name} SVL{svl}\"))}}}assert!(failures.is_empty(),\"{}\",failures.join(\"\\n\"));}\n")
	return out.String()
}

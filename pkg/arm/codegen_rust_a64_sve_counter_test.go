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

func TestRustA64SVECountersCorpus(t *testing.T) {
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_counter.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	source = strings.Replace(source, "semantics::arm64_sve_counter::a64(word, 0x1000, vl)", "aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_vector_length(0x1000,vl)).filter(|r|r.support==Support::Full)", 1)
	if strings.Contains(source, "mod semantics;") || !strings.Contains(source, "aarch64::decode(word)") {
		t.Fatal("counter fixture must use generated decoder")
	}
	source += a64SVECounterPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_counter.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_counter.rs", "-Copt-level=1", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-counter-tests"},
		{"./sve-counter-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE counter consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}
}

// Generate dispatch words directly from all12 primary encoding diagrams. The
// behavioral fixture separately checks the encoded counter rather than counting
// set bits in P, including arbitrary 16-bit inputs and source/destination aliases.
func a64SVECounterPrimaryCases(t *testing.T, path string) string {
	t.Helper()
	selected := map[string]bool{}
	for _, name := range strings.Fields("ptrue_pn_i whilege_pn_rr whilegt_pn_rr whilehi_pn_rr whilehs_pn_rr whilele_pn_rr whilelo_pn_rr whilels_pn_rr whilelt_pn_rr pext_pn_rr pext_pp_rr cntp_r_pn") {
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
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
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
	out.WriteString("\n#[test]fn all_primary_counter_classes_dispatch_at_all_lengths(){for(word,name)in[\n")
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
			var fixed, base uint32
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
							fixed |= 1 << uint(position)
							if bit == '1' {
								base |= 1 << uint(position)
							}
						}
						position--
					}
				}
			}
			for size := uint32(0); size < 4; size++ {
				for scale := uint32(0); scale < 2; scale++ {
					for part := uint32(0); part < 4; part++ {
						for _, high := range []bool{false, true} {
							word := base
							for _, b := range cl.Diagram.Boxes {
								width := b.Width
								if width == 0 {
									width = 1
								}
								value := uint32(0)
								switch b.Name {
								case "size":
									value = size
								case "vl":
									value = scale
								case "imm2", "i1":
									value = part
								case "Rn", "Rm", "PNn":
									value = 1
									if high {
										value = (1 << uint(width)) - 1
									}
								case "PNd", "Pd", "Rd":
									if high {
										value = (1 << uint(width)) - 1
									}
								}
								low := uint(b.Hi - width + 1)
								word |= (value << low) & (((1 << uint(width)) - 1) << low) &^ fixed
							}
							if seenWords[word] {
								continue
							}
							seenWords[word] = true
							fmt.Fprintf(&out, "(0x%08xu32,%q),\n", word, name)
						}
					}
				}
			}
		}
	}
	if len(seenPages) != len(selected) || classes != 12 {
		t.Fatalf("primary counter cohort: %d pages %d classes", len(seenPages), classes)
	}
	t.Logf("primary SVE counters: %d pages, %d classes, %d independent physical words", len(seenPages), classes, len(seenWords))
	out.WriteString("]{for vl in VLS{let r=recipe(word,vl).unwrap_or_else(||panic!(\"unhandled {word:08x} {name} VL{vl}\"));assert_eq!(r.support,Support::Full);r.validate().unwrap();}}}\n")
	return out.String()
}

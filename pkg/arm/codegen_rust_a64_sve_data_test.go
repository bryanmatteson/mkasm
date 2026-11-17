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

// Exercise the same numeric/alias/trap tests through the real upstream decoder,
// rather than a mnemonic or synthetic encoding fixture.
func TestRustA64SVEDataCorpus(t *testing.T) {
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_integer.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[allow(dead_code)]\n#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	source = strings.Replace(source, "semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl)", "aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_vector_length(0x1000,vl)).filter(|r|r.support==Support::Full)", 1)
	if strings.Contains(source, "mod semantics;") || !strings.Contains(source, "aarch64::decode(word)") {
		t.Fatal("fixture must exercise generated decoder")
	}
	dataBody, err := os.ReadFile("../semantics/testdata/arm64_sve_data.rs")
	if err != nil {
		t.Fatal(err)
	}
	source += strings.Replace(string(dataBody), `include!("sve_integer_base.rs");`, "", 1)
	source += a64SVEDataPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_data.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_data.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-data-tests"},
		{"./sve-data-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE data consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}

}

// Primary diagrams generate dispatch cases independently of recipe masks.
func a64SVEDataPrimaryCases(t *testing.T, path string) string {
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
	reader := tar.NewReader(gz)
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
		Decode string `xml:"ps_section>ps>pstext"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	selected := map[string]bool{}
	for _, name := range strings.Fields("shsubr_z_p_zz uhsubr_z_p_zz sqshlr_z_p_zz uqshlr_z_p_zz sqrshlr_z_p_zz uqrshlr_z_p_zz srshlr_z_p_zz urshlr_z_p_zz compact_z_p_z splice_z_p_zz lasta_r_p_z lastb_r_p_z lasta_v_p_z lastb_v_p_z clasta_r_p_z clastb_r_p_z clasta_v_p_z clastb_v_p_z clasta_z_p_zz clastb_z_p_zz insr_z_r insr_z_v sunpkhi_z_z uunpkhi_z_z and_z_zi orr_z_zi eor_z_zi dupm_z_i bsl_z_zzz bsl1n_z_zzz bsl2n_z_zzz nbsl_z_zzz eor3_z_zzz bcax_z_zzz xar_z_zzi brkas_p_p_p brka_p_p_p brkbs_p_p_p brkb_p_p_p brkns_p_p_pp brkn_p_p_pp brkpas_p_p_pp brkpa_p_p_pp brkpbs_p_p_pp brkpb_p_p_pp pfirst_p_p_p pnext_p_p_p punpkhi_p_p sqincb_r_rs uqincb_r_rs sqdecb_r_rs uqdecb_r_rs sqinch_r_rs uqinch_r_rs sqdech_r_rs uqdech_r_rs sqincw_r_rs uqincw_r_rs sqdecw_r_rs uqdecw_r_rs sqincd_r_rs uqincd_r_rs sqdecd_r_rs uqdecd_r_rs sqinch_z_zs uqinch_z_zs sqdech_z_zs uqdech_z_zs sqincw_z_zs uqincw_z_zs sqdecw_z_zs uqdecw_z_zs sqincd_z_zs uqincd_z_zs sqdecd_z_zs uqdecd_z_zs saddlb_z_zz saddlt_z_zz uaddlb_z_zz uaddlt_z_zz ssublb_z_zz ssublt_z_zz usublb_z_zz usublt_z_zz saddwb_z_zz saddwt_z_zz uaddwb_z_zz uaddwt_z_zz ssubwb_z_zz ssubwt_z_zz usubwb_z_zz usubwt_z_zz addhnb_z_zz addhnt_z_zz raddhnb_z_zz raddhnt_z_zz subhnb_z_zz subhnt_z_zz rsubhnb_z_zz rsubhnt_z_zz sqxtnb_z_zz sqxtnt_z_zz uqxtnb_z_zz uqxtnt_z_zz sqxtunb_z_zz sqxtunt_z_zz cmpeq_p_p_zi cmpeq_p_p_zw incp_r_p_r decp_r_p_r incp_z_p_z decp_z_p_z sqincp_r_p_r uqincp_r_p_r sqdecp_r_p_r uqdecp_r_p_r sqincp_z_p_z uqincp_z_p_z sqdecp_z_p_z uqdecp_z_p_z incb_r_rs decb_r_rs incd_z_zs decd_z_zs shadd_z_p_zz uhadd_z_p_zz srhadd_z_p_zz urhadd_z_p_zz shsub_z_p_zz uhsub_z_p_zz srshl_z_p_zz urshl_z_p_zz sqshl_z_p_zi sqshl_z_p_zz uqshl_z_p_zi uqshl_z_p_zz sqrshl_z_p_zz uqrshl_z_p_zz sqshlu_z_p_zi srshr_z_p_zi urshr_z_p_zi srsra_z_zi ursra_z_zi sadalp_z_p_z uadalp_z_p_z addp_z_p_zz smaxp_z_p_zz sminp_z_p_zz umaxp_z_p_zz uminp_z_p_zz") {
		selected[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_data_dispatch(){let mut failures=Vec::new();for(word,name,legal,minvl)in[\n")
	seen := map[uint32]bool{}
	pages, classes, words := 0, 0, 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(header.Name)
		if !selected[name] || !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") {
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
			for _, size := range []uint32{0, 1, 2, 3} {
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
						case "Pd":
							v = 1
						case "tsz":
							v = 1 << size
						case "tszh":
							v = (1 << size) >> 2
						case "tszl":
							v = (1 << size) & 3
						case "imm13":
							if high {
								v = 8191
							}
						case "imms":
							if high {
								v = 63
							}
						case "imm8", "imm8h", "imm8l", "imm2", "sh":
							if high {
								v = (uint32(1) << uint(width)) - 1
							}
						}
						low := uint(b.Hi - width + 1)
						mask := ((uint32(1) << uint(width)) - 1) << low
						word |= (v << low) & mask &^ fixed
					}
					if !seen[word] {
						seen[word] = true
						words++
						physicalSize := (word >> 22) & 3
						legal := true
						if strings.Contains(cl.Decode, "size::sh == '001'") && physicalSize == 0 && word&(1<<13) != 0 {
							legal = false
						}
						if strings.Contains(cl.Decode, "size IN {'0x'}") && physicalSize < 2 {
							legal = false
						}
						if strings.Contains(cl.Decode, "size == '00'") && physicalSize == 0 {
							legal = false
						}
						if strings.Contains(cl.Decode, "size == '11'") && physicalSize == 3 {
							legal = false
						}
						if strings.Contains(cl.Decode, "size != '11'") && physicalSize != 3 {
							legal = false
						}
						if name == "and_z_zi.xml" || name == "orr_z_zi.xml" || name == "eor_z_zi.xml" || name == "dupm_z_i.xml" {
							imm := (word >> 5) & 8191
							combined := ((imm >> 12) << 6) | ((^imm) & 63)
							if combined < 2 {
								legal = false
							} else {
								levels := uint32(1)
								for levels*2 <= combined {
									levels *= 2
								}
								if imm&(levels-1) == levels-1 {
									legal = false
								}
							}
						}
						if strings.Contains(cl.Decode, "tsize IN {'001', '010', '100'}") {
							tsize := ((word>>22)&1)<<2 | ((word >> 19) & 3)
							legal = tsize == 1 || tsize == 2 || tsize == 4
						}
						minVL := 128
						if strings.Contains(cl.Decode, "let esize : integer{} = 128;") {
							minVL = 256
						}
						fmt.Fprintf(&out, "(0x%08xu32,%q,%t,%du16),\n", word, name, legal, minVL)
					}
				}
			}
		}
	}
	if pages != len(selected) {
		t.Fatalf("primary SVE data pages: found%d expected%d", pages, len(selected))
	}
	t.Logf("primary SVE data: %d pages, %d classes, %d distinct physical words", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let decoded=aarch64::decode(word);if !legal||vl<minvl{if let Ok(d)=decoded{let r=d.semantic_recipe_with_vector_length(0x1000,vl);if r.support==Support::Full{failures.push(format!(\"overadmitted {word:08x} {name} VL{vl}\"));}}continue;}let r=recipe(word,vl);match r{Some(r)=>if let Err(e)=r.validate(){failures.push(format!(\"invalid {word:08x} {name} VL{vl}: {e:?}\"));},None=>failures.push(format!(\"unhandled {word:08x} {name} VL{vl}\"))}}}assert!(failures.is_empty(),\"{}\",failures.join(\"\\n\"));}\n")

	return out.String()
}

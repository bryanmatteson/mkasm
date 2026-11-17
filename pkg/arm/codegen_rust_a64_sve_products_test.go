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
func TestRustA64SVEProductsCorpus(t *testing.T) {
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
	dataBody, err := os.ReadFile("../semantics/testdata/arm64_sve_products.rs")
	if err != nil {
		t.Fatal(err)
	}
	source += strings.Replace(string(dataBody), `include!("sve_integer_base.rs");`, "", 1)
	source += a64SVEProductsPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_products.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_products.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-products-tests"},
		{"./sve-products-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE products consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}

}

// Primary diagrams generate dispatch cases independently of recipe masks.
func a64SVEProductsPrimaryCases(t *testing.T, path string) string {
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
	for _, name := range strings.Fields("sdot_z32_zzz sdot_z32_zzzi udot_z32_zzz udot_z32_zzzi adclb_z_zzz adclt_z_zzz bdep_z_zz bext_z_zz bgrp_z_zz eorbt_z_zz eortb_z_zz rshrnb_z_zi rshrnt_z_zi sbclb_z_zzz sbclt_z_zzz sdot_z_zzz sdot_z_zzzi shrnb_z_zi shrnt_z_zi smlalb_z_zzz smlalb_z_zzzi smlalt_z_zzz smlalt_z_zzzi smlslb_z_zzz smlslb_z_zzzi smlslt_z_zzz smlslt_z_zzzi smmla_z_zzz smullb_z_zz smullb_z_zzi smullt_z_zz smullt_z_zzi sqdmlalb_z_zzz sqdmlalb_z_zzzi sqdmlalt_z_zzz sqdmlalt_z_zzzi sqdmlslb_z_zzz sqdmlslb_z_zzzi sqdmlslt_z_zzz sqdmlslt_z_zzzi sqdmulh_z_zz sqdmulh_z_zzi sqdmullb_z_zz sqdmullb_z_zzi sqdmullt_z_zz sqdmullt_z_zzi sqrdmlah_z_zzz sqrdmlah_z_zzzi sqrdmlsh_z_zzz sqrdmlsh_z_zzzi sqrdmulh_z_zz sqrdmulh_z_zzi sqrshrnb_z_zi sqrshrnt_z_zi sqrshrunb_z_zi sqrshrunt_z_zi sqshrnb_z_zi sqshrnt_z_zi sqshrunb_z_zi sqshrunt_z_zi sudot_z_zzzi udot_z_zzz udot_z_zzzi umlalb_z_zzz umlalb_z_zzzi umlalt_z_zzz umlalt_z_zzzi umlslb_z_zzz umlslb_z_zzzi umlslt_z_zzz umlslt_z_zzzi ummla_z_zzz umullb_z_zz umullb_z_zzi umullt_z_zz umullt_z_zzi uqrshrnb_z_zi uqrshrnt_z_zi uqshrnb_z_zi uqshrnt_z_zi usdot_z_zzz usdot_z_zzzi usmmla_z_zzz sqdmlalbt_z_zzz sqdmlslbt_z_zzz pmullb_z_zz pmullt_z_zz cdot_z_zzz cdot_z_zzzi cmla_z_zzz cmla_z_zzzi sqrdcmlah_z_zzz sqrdcmlah_z_zzzi") {
		selected[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_products_dispatch(){let mut failures=Vec::new();for(word,name,legal,minvl)in[\n")
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
						case "imm8", "imm8h", "imm8l", "imm2", "sh", "imm3", "i3h", "i3l", "i2h", "i2l", "i2", "i1", "rot":
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
						if strings.Contains(cl.Decode, "tsize == '000'") {
							tsize := ((word>>22)&1)<<2 | ((word >> 19) & 3)
							if tsize == 0 {
								legal = false
							}
						}
						if name == "pmullb_z_zz.xml" || name == "pmullt_z_zz.xml" {
							legal = physicalSize != 2
						}
						minVL := 128
						fmt.Fprintf(&out, "(0x%08xu32,%q,%t,%du16),\n", word, name, legal, minVL)
					}
				}
			}
		}
	}
	if pages != len(selected) {
		t.Fatalf("primary SVE products pages: found%d expected%d", pages, len(selected))
	}
	t.Logf("primary SVE products: %d pages, %d classes, %d distinct physical words", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let decoded=aarch64::decode(word);if !legal||vl<minvl{if let Ok(d)=decoded{let r=d.semantic_recipe_with_vector_length(0x1000,vl);if r.support==Support::Full{failures.push(format!(\"overadmitted {word:08x} {name} VL{vl}\"));}}continue;}let r=recipe(word,vl);match r{Some(r)=>if let Err(e)=r.validate(){failures.push(format!(\"invalid {word:08x} {name} VL{vl}: {e:?}\"));},None=>failures.push(format!(\"unhandled {word:08x} {name} VL{vl}\"))}}}assert!(failures.is_empty(),\"{}\",failures.join(\"\\n\"));}\n")

	return out.String()
}

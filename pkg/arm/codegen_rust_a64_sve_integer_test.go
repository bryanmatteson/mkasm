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
func TestRustA64SVEIntegerCorpus(t *testing.T) {
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
	source += a64SVEIntegerPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_integer.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "tests/sve_integer.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve-integer-tests"},
		{"./sve-integer-tests"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]))
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE integer consumer %v: %v\n%s", args, err, out)
		} else {
			t.Logf("%s", out)
		}
	}

}

// Primary diagrams generate dispatch cases independently of recipe masks.
func a64SVEIntegerPrimaryCases(t *testing.T, path string) string {
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
	for _, name := range strings.Fields("sdiv_z_p_zz udiv_z_p_zz sdivr_z_p_zz udivr_z_p_zz smax_z_p_zz smin_z_p_zz umax_z_p_zz umin_z_p_zz smax_z_zi smin_z_zi umax_z_zi umin_z_zi sabd_z_p_zz uabd_z_p_zz smulh_z_p_zz umulh_z_p_zz mla_z_p_zzz mls_z_p_zzz mad_z_p_zzz msb_z_p_zzz add_z_zi sub_z_zi subr_z_zi mul_z_zi abs_z_p_z neg_z_p_z cls_z_p_z clz_z_p_z cnt_z_p_z not_z_p_z rbit_z_p_z revb_z_z rev_z_z sqabs_z_p_z sqneg_z_p_z suqadd_z_p_zz usqadd_z_p_zz sxtb_z_p_z uxtb_z_p_z sqadd_z_p_zz uqadd_z_p_zz sqsub_z_p_zz uqsub_z_p_zz sqsubr_z_p_zz uqsubr_z_p_zz sqadd_z_zz uqadd_z_zz sqsub_z_zz uqsub_z_zz sqadd_z_zi uqadd_z_zi sqsub_z_zi uqsub_z_zi saddv_r_p_z uaddv_r_p_z smaxv_r_p_z sminv_r_p_z umaxv_r_p_z uminv_r_p_z andv_r_p_z orv_r_p_z eorv_r_p_z zip1_z_zz uzp1_z_zz trn1_z_zz zip1_p_pp uzp1_p_pp trn1_p_pp rev_p_p ext_z_zi tbl_z_zz tbx_z_zz dup_z_r dup_z_zi dup_z_i") {
		selected[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_integer_dispatch(){let mut failures=Vec::new();for(word,name,legal,minvl)in[\n")
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
		t.Fatalf("primary SVE integer pages: found%d expected%d", pages, len(selected))
	}
	t.Logf("primary SVE integer: %d pages, %d classes, %d distinct physical words", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let decoded=aarch64::decode(word);if !legal||vl<minvl{if let Ok(d)=decoded{let r=d.semantic_recipe_with_vector_length(0x1000,vl);if r.support==Support::Full{failures.push(format!(\"overadmitted {word:08x} {name} VL{vl}\"));}}continue;}let r=recipe(word,vl);match r{Some(r)=>if let Err(e)=r.validate(){failures.push(format!(\"invalid {word:08x} {name} VL{vl}: {e:?}\"));},None=>failures.push(format!(\"unhandled {word:08x} {name} VL{vl}\"))}}}assert!(failures.is_empty(),\"{}\",failures.join(\"\\n\"));}\n")

	return out.String()
}

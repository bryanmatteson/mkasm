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
func TestRustA64SVEFloatCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the real Arm A64 XML archive")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
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
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_float.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(body), "#[allow(dead_code)] #[path=\"semantics.rs\"] mod semantics;", "use aarch64::semantics;", 1)
	source = strings.Replace(source, "fn recipe(word:u32,vl:u16)->Option<Recipe>{semantics::arm64_sve::a64(word,0x1000,Endian::Little,vl)}", "fn recipe(word:u32,vl:u16)->Option<Recipe>{let r=aarch64::decode(word).ok()?.semantic_recipe_with_vector_length(0x1000,vl);if r.support==Support::Full{Some(r)}else{None}}", 1)
	if !strings.Contains(source, "use aarch64::semantics;") || !strings.Contains(source, "aarch64::decode(word).ok()?.semantic_recipe_with_vector_length") {
		t.Fatal("SVE FP fixture must exercise the generated decoder and public recipe API")
	}
	source += a64SVEFloatPrimaryCases(t, path)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/sve_float.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "sve_float", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated SVE FP consumer: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

// Primary diagrams generate dispatch cases independently of recipe masks.
func a64SVEFloatPrimaryCases(t *testing.T, path string) string {
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
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	selected := map[string]bool{}
	for _, name := range strings.Fields("ftmad_z_zzi fexpa_z_z facge_p_p_zz fmax_z_p_zs fmin_z_p_zs fmaxnm_z_p_zs fminnm_z_p_zs fsubr_z_p_zs fabs_z_p_z fadd_z_p_zs fadd_z_p_zz fadd_z_zz fadda_v_p_z faddv_v_p_z fcmeq_p_p_z0 fcmeq_p_p_zz fcvt_z_p_z fcvtzs_z_p_z fcvtzu_z_p_z fdiv_z_p_zz fdivr_z_p_zz fmax_z_p_zz fmaxnm_z_p_zz fmaxnmv_v_p_z fmaxv_v_p_z fmin_z_p_zz fminnm_z_p_zz fminnmv_v_p_z fminv_v_p_z fmla_z_p_zzz fmla_z_zzzi fmls_z_p_zzz fmls_z_zzzi fmad_z_p_zzz fmsb_z_p_zzz fnmad_z_p_zzz fnmsb_z_p_zzz fmul_z_p_zs fmul_z_p_zz fmul_z_zz fmul_z_zzi fmulx_z_p_zz fneg_z_p_z fnmla_z_p_zzz fnmls_z_p_zzz frinta_z_p_z fsqrt_z_p_z scvtf_z_p_z ucvtf_z_p_z faddp_z_p_zz fmaxp_z_p_zz fminp_z_p_zz fmaxnmp_z_p_zz fminnmp_z_p_zz frecpe_z_z frecps_z_zz frecpx_z_p_z frsqrte_z_z frsqrts_z_zz bfcvt_z_p_z") {
		selected[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\n#[test]fn primary_xml_sve_fp_dispatch(){for(word,name)in[\n")
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
			for _, size := range []uint32{1, 2, 3} {
				word := base
				for _, b := range cl.Diagram.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					var v uint32
					switch b.Name {
					case "size":
						v = size
					case "Zn":
						v = 1
					case "Zm":
						v = 2
					case "Pd":
						v = 1
					}
					low := uint(b.Hi - width + 1)
					mask := ((uint32(1) << uint(width)) - 1) << low
					word |= (v << low) & mask &^ fixed
				}
				if !seen[word] {
					seen[word] = true
					words++
					fmt.Fprintf(&out, "(0x%08xu32,%q),\n", word, name)
				}
			}
		}
	}
	if pages != len(selected) {
		t.Fatalf("primary SVE FP pages: found%d expected%d", pages, len(selected))
	}
	t.Logf("primary SVE FP: %d pages, %d classes, %d distinct physical words", pages, classes, words)
	out.WriteString("]{for vl in[128,256,512,1024,2048]{let r=recipe(word,vl).unwrap_or_else(||panic!(\"unhandled {word:08x} {name} VL{vl}\"));assert_eq!(r.support,Support::Full);r.validate().unwrap_or_else(|e|panic!(\"invalid {word:08x} {name}: {e:?}\"));}}}\n")
	return out.String()
}

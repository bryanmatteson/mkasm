package semantics_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/arm"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRustA64SVEIntegerExtraCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the June2026 A64 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	corpus, err := arm.OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := arm.NewARMParser(arm.ARMParserConfig{EncodingIndexPath: arm.ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: arm.ArchAArch64, Languages: []arm.CodegenLang{arm.LangRust}})
	defer parser.Close(5 * time.Second)
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, err := os.ReadFile(filepath.Join(dir, "src/semantics.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtime), "pub mod arm64_sve_integer_extra") {
		t.Fatal("generated RustRuntime must embed the production SVE integer/address helper")
	}

	fixture, err := os.ReadFile("testdata/arm64_sve_integer_extra.rs")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(fixture), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
	if strings.Contains(source, "mod semantics;") {
		t.Fatal("fixture preamble changed")
	}
	recipes, err := os.ReadFile(filepath.Join(dir, "src/recipes.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recipes), "arm64_sve_integer_extra::a64") {
		t.Fatal("generated public recipe dispatch must call the SVE integer/address helper")
	}
	const helperCall = "semantics::arm64_sve_integer_extra::a64(word, 0x1000, vl)"
	if strings.Count(source, helperCall) != 1 {
		t.Fatal("fixture recipe adapter changed")
	}
	source = strings.Replace(source, helperCall, "aarch64::decode(word).ok().map(|d| d.semantic_recipe_with_vector_length(0x1000,vl))", 1)
	t.Log("behavioral fixture uses generated public recipe dispatch; adjacent-class ownership checks use the helper")

	source += sveIntegerExtraPrimary(t, path)
	if err := os.WriteFile(filepath.Join(dir, "integer_extra.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "integer_extra.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "integer-extra-tests"}, {"./integer-extra-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE integer extra %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func sveIntegerExtraPrimary(t *testing.T, path string) string {
	t.Helper()
	selected := map[string]bool{}
	for _, n := range strings.Fields("addpl_r_ri addvl_r_ri rdvl_r_i adr_z_az asrd_z_p_zi smulh_z_zz umulh_z_zz asr_z_p_zw asr_z_zw asrr_z_p_zz lsl_z_p_zw lsl_z_zw lslr_z_p_zz lsr_z_p_zw lsr_z_zw lsrr_z_p_zz sshllb_z_zi sshllt_z_zi ushllb_z_zi ushllt_z_zi ssra_z_zi usra_z_zi sri_z_zzi sli_z_zzi saba_z_zzz uaba_z_zzz sabalb_z_zzz sabalt_z_zzz uabalb_z_zzz uabalt_z_zzz sabdlb_z_zz sabdlt_z_zz uabdlb_z_zz uabdlt_z_zz saddlbt_z_zz ssublbt_z_zz ssubltb_z_zz sclamp_z_zz uclamp_z_zz cadd_z_zz") {
		selected[n+".xml"] = true
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
	type encoding struct {
		Name string `xml:"name,attr"`
	}
	type class struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
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
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	words := map[uint32]bool{}
	classes := 0
	var out strings.Builder
	var physical, arithmeticPhysical strings.Builder
	out.WriteString("\n#[test] fn all_primary_extra_classes_legal_selectors_and_features(){\n for(word,id)in[\n")
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !selected[name] || seen[name] || !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		seen[name] = true
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			classes++
			if len(cl.Encodings) != 1 {
				t.Fatalf("unexpected multi-encoding class %s", name)
			}
			var fixed, base, controls uint32
			for _, b := range cl.Diagram.Boxes {
				pos := b.Hi
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
							fixed |= 1 << uint(pos)
							if bit == '1' {
								base |= 1 << uint(pos)
							}
						}
						pos--
					}
				}
			}
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "size" || b.Name == "sz" || b.Name == "tszh" || b.Name == "tszl" || b.Name == "imm3" || b.Name == "imm6" || b.Name == "msz" || b.Name == "rot" {
					width := b.Width
					if width == 0 {
						width = 1
					}
					controls |= (((1 << uint(width)) - 1) << uint(b.Hi-width+1)) &^ fixed
				}
			}
			fmt.Fprintf(&physical, "(0x%08xu32,0x%08xu32),", fixed, base)
			if !strings.HasPrefix(name, "addpl_") && (base&0xff000000 == 0x45000000 || base&0xff000000 == 0x44000000) && (strings.Contains(name, "aba") || strings.Contains(name, "abdl") || strings.Contains(name, "clamp") || strings.HasPrefix(name, "saddlbt_") || strings.HasPrefix(name, "ssubl") || strings.HasPrefix(name, "cadd_")) {
				fmt.Fprintf(&arithmeticPhysical, "(0x%08xu32,0x%08xu32),", fixed, base)
			}
			var controlBits []uint
			for bit := uint(0); bit < 32; bit++ {
				if controls&(1<<bit) != 0 {
					controlBits = append(controlBits, bit)
				}
			}
			for combo := uint32(0); combo < 1<<uint(len(controlBits)); combo++ {
				for pattern := 0; pattern < 4; pattern++ {
					word := base
					for j, bit := range controlBits {
						word |= ((combo >> uint(j)) & 1) << bit
					}
					values := map[string]uint32{}
					for j, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						if b.Name == "" {
							continue
						}
						value := uint32(0)
						if strings.HasPrefix(b.Name, "Z") || strings.HasPrefix(b.Name, "R") || strings.HasPrefix(b.Name, "P") {
							switch pattern {
							case 0:
								value = uint32(j*7 + 1)
							case 1:
								value = 1
							case 2:
								value = 31
							case 3:
								if b.Name == "Zd" || b.Name == "Zdn" || b.Name == "Zda" || b.Name == "Rd" {
									value = 2
								} else {
									value = uint32(j + 1)
								}
							}
							low := uint(b.Hi - width + 1)
							word |= (value << low) & (((1 << uint(width)) - 1) << low) &^ fixed
						}
						values[b.Name] = (word >> uint(b.Hi-width+1)) & ((1 << uint(width)) - 1)
					}
					if (strings.Contains(name, "_zw.xml") && values["size"] == 3) || ((strings.Contains(name, "_z_zi.xml") || strings.Contains(name, "_z_zzi.xml") || strings.HasPrefix(name, "asrd_")) && values["tszh"] == 0 && values["tszl"] == 0) {
						continue
					}
					if values["size"] == 0 && (strings.HasPrefix(name, "sabal") || strings.HasPrefix(name, "uabal") || strings.HasPrefix(name, "sabdl") || strings.HasPrefix(name, "uabdl") || strings.HasPrefix(name, "saddlbt_") || strings.HasPrefix(name, "ssubl")) {
						continue
					}
					if words[word] {
						continue
					}
					words[word] = true
					fmt.Fprintf(&out, "(0x%08xu32,%q),\n", word, cl.Encodings[0].Name)
				}
			}
		}
	}
	if len(seen) != 40 || classes != 42 {
		t.Fatalf("primary cohort: %d pages %d classes", len(seen), classes)
	}
	t.Logf("June primary: %d pages %d encoding classes %d distinct legal words", len(seen), classes, len(words))
	out.WriteString(`]{let d=aarch64::decode(word).unwrap_or_else(|e|panic!("decode {word:08x} {id}: {e:?}"));assert!(d.encoding_id==id||d.ambiguous.iter().any(|other|other==id),"{word:08x} expected{id}, decoded{}",d.encoding_id);assert_eq!(d.evaluate_requirements(&[],"a64").primary,aarch64::requirements::Satisfaction::Unsatisfied,"{id}");assert_eq!(d.evaluate_requirements(&["FEAT_SVE","FEAT_SVE2","FEAT_SME"],"a64").primary,aarch64::requirements::Satisfaction::Satisfied,"{id}");for vl in VLS{let r=recipe(d.raw,vl).unwrap();assert_eq!(r.support,Support::Full,"{word:08x} {id} VL{vl}");r.validate().unwrap();}}}
`)
	out.WriteString("\n#[test]fn arithmetic_primary_fixed_neighbors_and_sqcadd_are_not_claimed(){let all=[" + physical.String() + "];let arithmetic=[" + arithmeticPhysical.String() + "];assert_eq!(arithmetic.len(),16);for(mask,base)in arithmetic{for bit in 0..32{if mask&(1<<bit)==0{continue;}let word=base^(1<<bit);let expected=all.iter().any(|(m,b)|word&m==*b);assert_eq!(semantics::arm64_sve_integer_extra::a64(word,0x1000,128).is_some(),expected,\"{word:08x}\");}}for size in 0..4{assert!(semantics::arm64_sve_integer_extra::a64(0x4501d800|(size<<22),0x1000,128).is_none());}}\n")
	return out.String()
}

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
	"regexp"
	"strings"
	"testing"
	"time"
)

// Generate one public consumer for the complete integer/lookup/rounding slice.
// Each behavioral fixture then exercises that same generated decoder and API.
func TestRustA64SVECompletionCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to June2026 A64 XML")
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
	run := func(t *testing.T, args ...string) {
		t.Helper()
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
	run(t, "--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib")
	fixtures := []struct {
		name     string
		primary  func(*testing.T, string) string
		optional bool
	}{
		{"arm64_sve_indexed_integer", sveIndexedIntegerPrimary, true},
		{"arm64_sve_integer_estimate", sveIntegerEstimatePrimary, true},
		{"arm64_sve_bounded_round", sveBoundedRoundPrimary, false},
		{"arm64_sve_lookup_pointer", sveLookupPointerPrimary, true},
		{"arm64_sme_lookup", smeLookupPrimary, true},
		{"arm64_sme_base_integer", smeBaseIntegerPrimary, true},
		{"arm64_lse128", lse128Primary, true},
		{"arm64_lsfe", lsfePrimary, true},
		{"arm64_lsui", lsuiPrimary, true},
		{"arm64_lor", lorPrimary, true},
		{"arm64_rcw", rcwPrimary, true},
		{"arm64_mops_tags", mopsTagsPrimary, true},
		{"arm64_ls64", ls64Primary, true},
		{"arm64_timedwait", timedWaitPrimary, true},
		{"arm64_system_hints", systemHintsPrimary, true},
		{"arm64_ordered", orderedMemoryPrimary, true},
		{"arm64_exclusive", exclusiveMemoryPrimary, true},
		{"arm64_bti_api", btiPrimary, true},
		{"arm64_gcs_memory", gcsMemoryPrimary, true},
		{"arm64_gcs_stack", gcsStackPrimary, true},
		{"arm64_fp8", fp8Primary, true},
		{"arm64_fp8_scalable", fp8ScalablePrimary, true},
		{"arm64_bfloat_widening", bfloatWideningPrimary, true},
		{"arm64_fp8_widening", fp8WideningPrimary, true},
		{"arm64_fp8_dot", fp8DotPrimary, true},
		{"arm64_fp8_matrix", fp8MatrixPrimary, true},
		{"arm64_fixed_fp8", fixedFp8Primary, true},
		{"arm64_fixed_half_matrix", fixedHalfMatrixPrimary, true},
		{"arm64_sve_float_matrix", sveFloatMatrixPrimary, true},
		{"arm64_float_lane_ops", floatLaneOpsPrimary, true},
		{"arm64_za_addsub", zaAddSubPrimary, true},
		{"arm64_za_integer", zaIntegerPrimary, true},
		{"arm64_sme_state", smeStatePrimary, true},
		{"arm64_sve_ordinary", sveOrdinaryPrimary, true},
		{"arm64_sve_final_data", sveFinalDataPrimary, true},
		{"arm64_za_integer_multiply", zaIntegerMultiplyPrimary, true},
		{"arm64_za_fused", zaFusedPrimary, true},
		{"arm64_za_outer", zaOuterPrimary, true},
		{"arm64_group_float", groupFloatPrimary, true},
		{"arm64_group_integer", groupIntegerPrimary, true},
		{"arm64_group_bfloat", groupBFloatPrimary, true},
		{"arm64_group_convert", groupConvertPrimary, true},
		{"arm64_float_quad_reduce", floatQuadReducePrimary, true},
		{"arm64_sve_float_misc", sveFloatMiscPrimary, true},
		{"arm64_sve_bfloat_arithmetic", sveBFloatArithmeticPrimary, true},
		{"arm64_za_partial", zaPartialPrimary, true},
		{"arm64_za_dot", zaDotPrimary, true},
		{"arm64_za_half_widening", zaHalfWideningPrimary, true},
		{"arm64_sve_replicate", sveReplicatePrimary, true},
		{"arm64_float_classic", classicFloatPrimary, true},
		{"arm64_sve_group_memory", groupMemoryCorpus, false},
	}
	adapter := regexp.MustCompile(`(?s)fn recipe\(word: u32, vl: u16(?:, endian: Endian)?\) -> (?:Option<Recipe>|Recipe) \{.*?\n\}`)
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			body, err := os.ReadFile("testdata/" + fixture.name + ".rs")
			if err != nil {
				t.Fatal(err)
			}
			source := strings.Replace(string(body), "#[path = \"semantics.rs\"]\nmod semantics;", "use aarch64::semantics;", 1)
			if strings.Contains(source, "mod semantics;") {
				t.Fatal("fixture preamble changed")
			}
			if len(adapter.FindAllStringIndex(source, -1)) != 1 {
				t.Fatal("fixture adapter changed")
			}
			replacement := "fn recipe(word:u32,vl:u16)->Recipe { aarch64::decode(word).unwrap().semantic_recipe_with_vector_length(0x1000,vl) }"
			if fixture.optional {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_vector_length(0x1000,vl)) }"
			}
			if fixture.name == "arm64_bti_api" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe>{aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_branch_target_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:None,endian:Endian::Little}))}"
			}
			if fixture.name == "arm64_fp8_scalable" || fixture.name == "arm64_bfloat_widening" || fixture.name == "arm64_fp8_widening" || fixture.name == "arm64_fp8_dot" || fixture.name == "arm64_fp8_matrix" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:Some(if word>>31!=0{vl}else if vl==128{2048}else{128}),endian:Endian::Little})) }"
			}
			if fixture.name == "arm64_fp8_matrix" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:if word>>31!=0{128}else{vl},streaming_vector_length:Some(if word>>31!=0{vl}else if vl==128{2048}else{128}),endian:Endian::Little})) }"
			}
			if fixture.name == "arm64_sme_state" || fixture.name == "arm64_za_integer_multiply" || fixture.name == "arm64_za_integer" || fixture.name == "arm64_group_integer" || fixture.name == "arm64_sme_base_integer" || fixture.name == "arm64_za_addsub" || fixture.name == "arm64_za_fused" || fixture.name == "arm64_za_outer" || fixture.name == "arm64_group_float" || fixture.name == "arm64_group_bfloat" || fixture.name == "arm64_group_convert" || fixture.name == "arm64_za_partial" || fixture.name == "arm64_za_dot" || fixture.name == "arm64_za_half_widening" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:if vl==128{2048}else{128},streaming_vector_length:Some(vl),endian:Endian::Little})) }"
			}
			if fixture.name == "arm64_group_convert" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe>{let narrow=word>>31==0;aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:if narrow{vl}else if vl==128{2048}else{128},streaming_vector_length:Some(if narrow{if vl==128{2048}else{128}}else{vl}),endian:Endian::Little}))}"
			}
			if fixture.name == "arm64_sve_bfloat_arithmetic" {
				replacement = "fn recipe(word:u32,vl:u16)->Option<Recipe>{aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:Some(if vl==128{2048}else{128}),endian:Endian::Little}))}"
			}
			if fixture.name == "arm64_gcs_stack" || fixture.name == "arm64_gcs_memory" || fixture.name == "arm64_lse128" || fixture.name == "arm64_ordered" || fixture.name == "arm64_exclusive" || fixture.name == "arm64_lor" || fixture.name == "arm64_rcw" || fixture.name == "arm64_mops_tags" || fixture.name == "arm64_ls64" || fixture.name == "arm64_timedwait" {
				replacement = "fn recipe(word:u32,vl:u16,endian:Endian)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:None,endian})) }"
			}
			if fixture.name == "arm64_sve_ordinary" || fixture.name == "arm64_lsfe" || fixture.name == "arm64_lsui" {
				replacement = "fn recipe(word:u32,vl:u16,endian:Endian)->Option<Recipe>{aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:Some(if vl==128{2048}else{128}),endian}))}"
			}
			if fixture.name == "arm64_sve_replicate" {
				cases, err := os.ReadFile("testdata/arm64_sve_replicate_cases.rs")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "arm64_sve_replicate_cases.rs"), cases, 0644); err != nil {
					t.Fatal(err)
				}
				replacement = "fn recipe(word:u32,vl:u16,endian:Endian)->Option<Recipe> { aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:Some(if vl==128{2048}else{128}),endian})) }"
			}
			if fixture.name == "arm64_sve_group_memory" {
				// A deliberately different saved SVL exposes dispatch that
				// accidentally treats CurrentVL memory as SME-only state.
				replacement = "fn recipe(word:u32,vl:u16,endian:Endian)->Recipe { aarch64::decode(word).unwrap().semantic_recipe_with_context(0x1000,aarch64::recipes::RecipeContext{vector_length:vl,streaming_vector_length:Some(if vl==128{2048}else{128}),endian}) }"
			}
			if fixture.name == "arm64_mops_tags" {
				cases, err := os.ReadFile("testdata/arm64_mops_tags_cases.rs")
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "arm64_mops_tags_cases.rs"), cases, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.name == "arm64_rcw" {
				cases, err := os.ReadFile("testdata/arm64_rcw_cases.rs")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "arm64_rcw_cases.rs"), cases, 0644); err != nil {
					t.Fatal(err)
				}
			}
			source = adapter.ReplaceAllLiteralString(source, replacement) + fixture.primary(t, path)
			if fixture.name == "arm64_sve_group_memory" {
				source += `
#[test]fn primary_group_decoder_and_requirement_admission(){for &(word,id,_,_,_,_,_)in GROUP_CLASSES{let d=aarch64::decode(word).unwrap();assert!(d.encoding_id==id||d.ambiguous.iter().any(|x|x==id),"{word:08x} {id} {}",d.encoding_id);assert_eq!(d.evaluate_requirements(&["FEAT_SVE2p1","FEAT_SME2"],"a64").primary,aarch64::requirements::Satisfaction::Satisfied,"{id}");}}
`
			}
			if err := os.WriteFile(filepath.Join(dir, fixture.name+".rs"), []byte(source), 0644); err != nil {
				t.Fatal(err)
			}
			run(t, "--edition=2021", "--test", fixture.name+".rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", fixture.name+"-tests")
			run(t, "./"+fixture.name+"-tests", "--nocapture")
		})
	}
}

func sveLookupPointerPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "luti2_z_zz luti4_z_zz luti6_z_z2zz luti6_z_zzz madpt_z_zzz mlapt_z_zzz mul_z_zz movprfx_z_z movprfx_z_p_z ctermeq_rr ftssel_z_zz luti2_advsimd luti4_advsimd", 19)
}

func sveReplicatePrimary(t *testing.T, path string) string {
	source := a64CompletionPrimary(t, path, "ld1rb_z_p_bi ld1rh_z_p_bi ld1rw_z_p_bi ld1rd_z_p_bi ld1rsb_z_p_bi ld1rsh_z_p_bi ld1rsw_z_p_bi ld1rqb_z_p_bi ld1rqh_z_p_bi ld1rqw_z_p_bi ld1rqd_z_p_bi ld1rqb_z_p_br ld1rqh_z_p_br ld1rqw_z_p_br ld1rqd_z_p_br ld1rob_z_p_bi ld1roh_z_p_bi ld1row_z_p_bi ld1rod_z_p_bi ld1rob_z_p_br ld1roh_z_p_br ld1row_z_p_br ld1rod_z_p_br", 32)
	return strings.ReplaceAll(source, "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func fp8ScalablePrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bf1cvtlt_z_z8 bf1cvtl_mz2_z8 bf1cvt_mz2_z8 bf1cvt_z_z8 f1cvtlt_z_z8 f1cvtl_mz2_z8 f1cvt_mz2_z8 f1cvt_z_z8 fcvtnb_z8_mz2 fcvtnt_z8_mz2 fcvtn_z8_mz2 fcvtn_z8_mz4 fcvt_z8_mz2 fcvt_z8_mz4 bfcvt_z8_mz2 bfcvtn_z8_mz2", 24)
}

func fp8Primary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bf12cvtl_advsimd f12cvtl_advsimd fcvtn_advsimd_168 fcvtn_advsimd_328", 6)
}

func exclusiveMemoryPrimary(t *testing.T, path string) string {
	source := a64CompletionPrimary(t, path, "ldxp ldaxp stxp stlxp ldxr ldxrb ldxrh ldaxr ldaxrb ldaxrh stxr stxrb stxrh stlxr stlxrb stlxrh", 24)
	return strings.ReplaceAll(source, "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func orderedMemoryPrimary(t *testing.T, path string) string {
	source := a64CompletionPrimary(t, path, "ldapr ldaprb ldaprh ldapur_gen ldapurb ldapurh ldapursb ldapursh ldapursw stlur_gen stlurb stlurh ldapur_fpsimd stlur_fpsimd ldap1_advsimd_sngl stl1_advsimd_sngl ldiapp stilp ldap_gen ldapp_gen stlp_gen", 42)
	return strings.ReplaceAll(source, "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func lse128Primary(t *testing.T, path string) string {
	source := a64CompletionPrimary(t, path, "swpp ldclrp ldsetp", 12)
	return strings.ReplaceAll(source, "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func smeBaseIntegerPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "addha_za_pp_z addva_za_pp_z addspl_r_ri addsvl_r_ri rdsvl_r_i", 7)
}

func smeLookupPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "luti2_mz2_ztz luti2_mz4_ztz luti2_z_ztz luti4_mz2_ztz luti4_mz4_ztmz2 luti4_mz4_ztz luti4_z_ztz luti6_mz4_zmz2 luti6_mz4_ztz luti6_z_ztz", 17)
}

func classicFloatPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fmlal_advsimd_vec fmlal_advsimd_elt fmlsl_advsimd_vec fmlsl_advsimd_elt fcmla_advsimd_vec fcmla_advsimd_elt fcadd_advsimd_vec fmov_advsimd fabs_advsimd fneg_advsimd fabd_advsimd fabs_float fneg_float", 28)
}

func a64CompletionPrimary(t *testing.T, path, pages string, wantEncodings int) string {
	t.Helper()
	selected := map[string]bool{}
	for _, n := range strings.Fields(pages) {
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
	type enc struct {
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
	}
	type cl struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Enc []enc `xml:"encoding"`
	}
	type page struct {
		Classes []cl `xml:"classes>iclass"`
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
	seen := map[string]bool{}
	encodings := 0
	words := 0
	var out strings.Builder
	out.WriteString("\nstatic PRIMARY_ENCODINGS: &[(u32,&str,u16)] = &[\n")
	for {
		h, err := tr.Next()
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
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		for _, c := range p.Classes {
			for _, encoding := range c.Enc {
				encodings++
				id := encoding.Name
				minimum := 128
				if id == "fmmla_z_zzz_d" || strings.HasPrefix(id, "ld1ro") || strings.HasSuffix(id, "1x16") || id == "luti6_z_zzz_8" {
					minimum = 256
				}
				if id == "luti6_z_zzz_16" || strings.HasPrefix(id, "luti6_mz4_zmz2_") {
					minimum = 512
				}
				var base, fixed, parts uint32
				// Encoding boxes override the shared class diagram, including fields
				// that become fixed only for one entry (FMOV's S/D op and Q bits).
				boxes := append(append([]box(nil), c.Diagram.Boxes...), encoding.Boxes...)
				for _, b := range boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					mask := uint32(((uint64(1) << uint(width)) - 1) << uint(b.Hi-width+1))
					previousBase, previousFixed := base, fixed
					base &^= mask
					fixed &^= mask
					parts &^= mask
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
							if bit != '0' && bit != '1' && previousFixed&(1<<uint(pos)) != 0 {
								fixed |= 1 << uint(pos)
								base |= previousBase & (1 << uint(pos))
							}
							if bit == '0' || bit == '1' {
								fixed |= 1 << uint(pos)
								if bit == '1' {
									base |= 1 << uint(pos)
								}
							}
							pos--
						}
					}
					if strings.HasPrefix(b.Name, "i") || b.Name == "size" || b.Name == "sz" || b.Name == "M" || b.Name == "Q" || b.Name == "H" || b.Name == "L" || b.Name == "rot" || strings.HasPrefix(id, "LUTI") && (b.Name == "len" || b.Name == "op") {
						parts |= (((1 << uint(width)) - 1) << uint(b.Hi-width+1)) &^ fixed
					}
				}
				var bits []uint
				for bit := uint(0); bit < 32; bit++ {
					if parts&(1<<bit) != 0 {
						bits = append(bits, bit)
					}
				}
				for combo := 0; combo < 1<<uint(len(bits)); combo++ {
					for _, vars := range []uint32{0, 0x00020020, 0x001fffff} {
						w := base | (vars &^ fixed &^ parts)
						for i, bit := range bits {
							w |= ((uint32(combo) >> uint(i)) & 1) << bit
						}
						if strings.Contains(id, "_mz_") && (strings.HasPrefix(id, "fmul_") || strings.HasPrefix(id, "fmax_") || strings.HasPrefix(id, "fmin_") || strings.HasPrefix(id, "fmaxnm_") || strings.HasPrefix(id, "fminnm_") || strings.HasPrefix(id, "fscale_") || strings.HasPrefix(id, "famax_") || strings.HasPrefix(id, "famin_") || strings.HasPrefix(id, "fclamp_")) && (w>>22)&3 == 0 {
							continue
						}
						if (id == "fabd_z_p_zz_" || strings.HasPrefix(id, "scvtf_z_z_") || strings.HasPrefix(id, "scvtflt_z_z_") || strings.HasPrefix(id, "ucvtf_z_z_") || strings.HasPrefix(id, "ucvtflt_z_z_") || strings.HasPrefix(id, "ftssel_") || strings.HasPrefix(id, "fcvtzsn_") || strings.HasPrefix(id, "fcvtzun_") || strings.Contains(id, "qv_z_p_z_") || strings.HasPrefix(id, "famax_z_") || strings.HasPrefix(id, "famin_z_") || strings.HasPrefix(id, "fclamp_z_") || strings.HasPrefix(id, "ftsmul_z_")) && (w>>22)&3 == 0 {
							continue
						}
						if (strings.HasPrefix(id, "FABS_asimd") || strings.HasPrefix(id, "FNEG_asimd") || strings.HasPrefix(id, "FABD_asimd")) && !strings.Contains(id, "fp16") && w&(1<<22) != 0 && w&(1<<30) == 0 {
							continue
						}
						if id == "FSCALE_asimdsame_only" && w&(1<<22) != 0 && w&(1<<30) == 0 {
							continue
						}
						if strings.HasPrefix(id, "FCADD_") || strings.HasPrefix(id, "FCMLA_") {
							size, q := (w>>22)&3, w&(1<<30) != 0
							if size == 0 || size == 3 && !q || id == "FCMLA_advsimd_elt" && (size == 3 || size == 2 && (w&(1<<21) != 0 || !q) || size == 1 && !q && w&(1<<11) != 0) {
								continue
							}
						}
						if (strings.HasPrefix(id, "sunpk_mz_z_") || strings.HasPrefix(id, "uunpk_mz_z_")) && (w>>22)&3 == 0 {
							continue
						}
						if strings.HasPrefix(id, "prf") && strings.Contains(id, "_i_p_br_") && (w>>16)&31 == 31 {
							continue
						}
						if id == "psel_p_ppi_" && ((w>>19)&8)|((w>>18)&7) == 0 {
							continue
						}
						if (id == "st1h_z_p_bi_" || id == "st1h_z_p_br_") && (w>>21)&3 == 0 {
							continue
						}
						if (strings.HasPrefix(id, "ld1") || strings.HasPrefix(id, "st1")) && strings.Contains(id, "_z_p_br_") && (w>>16)&31 == 31 {
							continue
						}
						if strings.HasPrefix(id, "ld1r") && strings.Contains(id, "_br_") && (w>>16)&31 == 31 {
							continue
						}
						if id == "HINTE_extendedhint" && w&(1<<21) == 0 && (w>>16)&7 == 3 && w&31 == 31 {
							continue
						}
						if (strings.HasPrefix(id, "LD64B_") || strings.HasPrefix(id, "ST64B_") || strings.HasPrefix(id, "ST64BV_") || strings.HasPrefix(id, "ST64BV0_")) && (w&31 >= 24 || w&1 != 0) {
							continue
						}
						if strings.HasSuffix(id, "_memcms") && w>>30 != 0 {
							continue
						} // Primary MOPS sz reserves nonzero values.
						if strings.HasSuffix(id, "_rcwcomswappr") && (w&1 != 0 || (w>>16)&1 != 0) {
							continue // Primary CASP decode reserves odd register pairs.
						}
						if strings.HasSuffix(id, "_memop_128") && (w&31 == 31 || (w>>16)&31 == 31) {
							continue
						}
						size := (w >> 12) & 3
						if strings.Contains(id, "ztz") && (strings.HasPrefix(id, "luti2_") || strings.HasPrefix(id, "luti4_")) {
							if size == 3 || (strings.HasSuffix(id, "_8") || strings.HasSuffix(id, "_4")) && size == 2 || strings.HasPrefix(id, "luti4_mz4_") && size == 0 {
								continue
							}
						}
						if strings.HasPrefix(id, "luti4_mz4_ztmz2_") && size != 0 {
							continue
						}
						if strings.HasPrefix(id, "zip_mz_") || strings.HasPrefix(id, "uzp_mz_") {
							bits := 8 << ((w >> 22) & 3)
							if strings.HasSuffix(id, "q") {
								bits = 128
							}
							group := 2
							if strings.Contains(id, "_mz_z_") {
								group = 4
							}
							minimum = bits * group
							if minimum < 128 {
								minimum = 128
							}
						}
						if id == "movaz_mz4_za_d1" {
							minimum = 256
						}
						fmt.Fprintf(&out, "(0x%08xu32,%q,%du16),\n", w, id, minimum)
						words++
					}
				}
			}
		}
	}
	if len(seen) != len(selected) || encodings != wantEncodings {
		t.Fatalf("primary cohort: %d pages %d encoding entries", len(seen), encodings)
	}
	out.WriteString(`];
#[test]fn primary_encodings_parts_and_requirements(){for &(word,id,minvl) in PRIMARY_ENCODINGS {let d=aarch64::decode(word).unwrap();assert!(d.encoding_id==id||d.ambiguous.iter().any(|x|x==id),"{word:08x} expected{id} actual{}",d.encoding_id);let features=["FEAT_GCS","FEAT_BTI","FEAT_LSCP","FEAT_WFxT","FEAT_HINTE","FEAT_LS64","FEAT_LS64_V","FEAT_LS64_ACCDATA","FEAT_MOPS","FEAT_MTE","FEAT_MTE2","FEAT_THE","FEAT_D128","FEAT_LOR","FEAT_LSUI","FEAT_CLRBHB","FEAT_DGH","FEAT_CMH","FEAT_PCDPHINT","FEAT_SPE","FEAT_TRF","FEAT_CHK","FEAT_XS","FEAT_LSFE","FEAT_SVE_AES2","FEAT_SSVE_AES","FEAT_SVE","FEAT_SVE2","FEAT_SVE2p1","FEAT_SVE2p2","FEAT_SVE2p3","FEAT_SME2","FEAT_SME2p3","FEAT_LUT","FEAT_CPA","FEAT_FP","FEAT_AdvSIMD","FEAT_FP16","FEAT_F16MM","FEAT_F32MM","FEAT_SVE_F16F32MM","FEAT_SVE_B16MM","FEAT_F16F32DOT","FEAT_F16F32MM","FEAT_FHM","FEAT_FCMA","FEAT_SME2p1","FEAT_SME_LUTv2","FEAT_F64MM","FEAT_SME","FEAT_SME_I16I64","FEAT_LSE128","FEAT_LRCPC","FEAT_LRCPC2","FEAT_LRCPC3","FEAT_FP8","FEAT_BF16","FEAT_FP8FMA","FEAT_SSVE_FP8FMA","FEAT_F8F16MM","FEAT_F8F32MM","FEAT_SME_MOP4","FEAT_SME_TMOP","FEAT_FP8DOT2","FEAT_FP8DOT4","FEAT_SSVE_FP8DOT2","FEAT_SSVE_FP8DOT4","FEAT_SME_F8F16","FEAT_SME_F8F32","FEAT_SME_F16F16","FEAT_SME_F64F64","FEAT_SME_B16B16","FEAT_SME2p2","FEAT_FAMINMAX","FEAT_SVE_B16B16","FEAT_SVE_BFSCALE"];assert_eq!(d.evaluate_requirements(&features,"a64").primary,if id.contains("_SYS_CR_systeminstrs") || id.contains("_SYSL_RC_systeminstrs") || matches!(id,"movt_r_zt_"|"movt_zt_r_"|"CSDB_HI_hints"|"DSB_BO_barriers") || id.contains("_ldstexcl"){aarch64::requirements::Satisfaction::Unknown}else{aarch64::requirements::Satisfaction::Satisfied},"{id}");for vl in[128,256,512,1024,2048]{let r=recipe(word,vl).unwrap();assert_eq!(r.support==Support::Full,vl>=minvl,"{word:08x} {id} VL{vl}");if vl>=minvl{r.validate().unwrap();}}}}`)
	t.Logf("June primary: %d pages %d encoding entries %d legal selector/register words", len(seen), encodings, words)
	return out.String()
}

func bfloatWideningPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmlal_advsimd_vec bfmlal_advsimd_elt bfmlalb_z_zzz bfmlalb_z_zzzi bfmlalt_z_zzz bfmlalt_z_zzzi bfmlslb_z_zzz bfmlslb_z_zzzi bfmlslt_z_zzz bfmlslt_z_zzzi bfmlal_za_zzi bfmlal_za_zzv bfmlal_za_zzw bfmlsl_za_zzi bfmlsl_za_zzv bfmlsl_za_zzw", 26)
}

func fp8WideningPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fmlalb_z_z8z8z8 fmlalb_z_z8z8z8i fmlalt_z_z8z8z8 fmlalt_z_z8z8z8i fmlallbb_z32_z8z8z8 fmlallbb_z32_z8z8z8i fmlallbt_z32_z8z8z8 fmlallbt_z32_z8z8z8i fmlalltb_z32_z8z8z8 fmlalltb_z32_z8z8z8i fmlalltt_z32_z8z8z8 fmlalltt_z32_z8z8z8i fmlal_za_z8z8i fmlal_za_z8z8v fmlal_za_z8z8w fmlall_za32_z8z8i fmlall_za32_z8z8v fmlall_za32_z8z8w", 28)
}

func fp8DotPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fdot_z32_zz8z8 fdot_z32_zz8z8i fdot_z_zz8z8 fdot_z_zz8z8i fdot_za32_z8z8i fdot_za32_z8z8v fdot_za32_z8z8w fdot_za_z8z8i fdot_za_z8z8v fdot_za_z8z8w fvdotb_za32_z8z8i fvdott_za32_z8z8i fvdot_za_z8z8i", 19)
}

func fp8MatrixPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fmmla_fp8fp16 fmmla_fp8fp32 fmmla_z16_zz8z8 fmmla_z32_zz8z8 fmop4a_za16_z8z8 fmop4a_za32_z8z8 fmopa_za16_pp_z8z8 fmopa_za32_pp_z8z8 ftmopa_za16_z8z8zi ftmopa_za32_z8z8zi", 16)
}

func zaAddSubPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfadd_za_zw bfsub_za_zw fadd_za_zw fsub_za_zw", 12)
}

func zaFusedPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmla_za_zzi bfmla_za_zzv bfmla_za_zzw bfmls_za_zzi bfmls_za_zzv bfmls_za_zzw fmla_za_zzi fmla_za_zzv fmla_za_zzw fmls_za_zzi fmls_za_zzv fmls_za_zzw", 40)
}

func zaOuterPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmopa_za32_pp_zz bfmopa_za_pp_zz bfmops_za32_pp_zz bfmops_za_pp_zz fmopa_za_pp_zz fmops_za_pp_zz fmopa_za32_pp_zz fmops_za32_pp_zz", 12)
}

func zaHalfWideningPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fmlal_za_zzi fmlal_za_zzv fmlal_za_zzw fmlsl_za_zzi fmlsl_za_zzv fmlsl_za_zzw", 16)
}

func zaDotPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fdot_za_zzi fdot_za_zzv fdot_za_zzw fvdot_za_zzi bfvdot_za_zzi", 8)
}

func zaPartialPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmop4a_za32_zz bfmop4a_za_zz bfmop4s_za32_zz bfmop4s_za_zz bftmopa_za32_zzzi bftmopa_za_zzzi fmop4a_za32_zz fmop4a_za_zz fmop4s_za32_zz fmop4s_za_zz ftmopa_za32_zzzi ftmopa_za_zzzi smop4a_za32_zz smop4a_za_zz smop4s_za32_zz smop4s_za_zz stmopa_za32_zzzi stmopa_za_zzzi sumop4a_za_zz sumop4s_za_zz sutmopa_za_zzzi umop4a_za32_zz umop4a_za_zz umop4s_za32_zz umop4s_za_zz usmop4a_za_zz usmop4s_za_zz ustmopa_za_zzzi utmopa_za32_zzzi utmopa_za_zzzi", 139)
}

func groupFloatPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fmul_mz_zzv fmul_mz_zzw fmax_mz_zzv fmax_mz_zzw fmin_mz_zzv fmin_mz_zzw fmaxnm_mz_zzv fmaxnm_mz_zzw fminnm_mz_zzv fminnm_mz_zzw fscale_mz_zzv fscale_mz_zzw frinta_mz_z frintm_mz_z frintn_mz_z frintp_mz_z famax_mz_zzw famin_mz_zzw fclamp_mz_zz", 38)
}

func groupBFloatPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmul_mz_zzv bfmul_mz_zzw bfmax_mz_zzv bfmax_mz_zzw bfmin_mz_zzv bfmin_mz_zzw bfmaxnm_mz_zzv bfmaxnm_mz_zzw bfminnm_mz_zzv bfminnm_mz_zzw bfscale_mz_zzv bfscale_mz_zzw bfclamp_mz_zz", 26)
}

func sveBFloatArithmeticPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfadd_z_p_zz bfadd_z_zz bfsub_z_p_zz bfsub_z_zz bfmul_z_p_zz bfmul_z_zz bfmul_z_zzi bfmax_z_p_zz bfmin_z_p_zz bfmaxnm_z_p_zz bfminnm_z_p_zz bfscale_z_p_zz bfclamp_z_zz bfmla_z_p_zzz bfmla_z_zzzi bfmls_z_p_zzz bfmls_z_zzzi", 17)
}

func groupConvertPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fcvt_mz2_z fcvtl_mz2_z fcvt_z_mz2 fcvtn_z_mz2 bfcvt_z_mz2 bfcvtn_z_mz2 fcvtzs_mz_z fcvtzu_mz_z fcvtzsn_z_mz2 fcvtzun_z_mz2 scvtf_mz_z ucvtf_mz_z", 16)
}

func floatQuadReducePrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "faddqv_z_p_z fmaxqv_z_p_z fminqv_z_p_z fmaxnmqv_z_p_z fminnmqv_z_p_z", 5)
}

func sveFloatMiscPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "famax_z_p_zz famin_z_p_zz fclamp_z_zz ftsmul_z_zz ftssel_z_zz", 5)
}

func fixedFp8Primary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fdot_advsimd_2wayelem fdot_advsimd_2wayvec fdot_advsimd_4wayelem fdot_advsimd_4wayvec fmlalb_advsimd_elem fmlalb_advsimd_vec fmlallbb_advsimd_elem fmlallbb_advsimd_vec", 16)
}

func fixedHalfMatrixPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fdot_advsimd_elt_fp16fp32 fdot_advsimd_fp16fp32 fmmla_advsimd_fp16fp16 fmmla_advsimd_fp16fp32", 4)
}

func sveFloatMatrixPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "bfmmla_z16_zzz bfmmla_z_zzz fmmla_z32_zzz fmmla_z_zzz", 6)
}

func floatLaneOpsPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "fabd_z_p_zz fdot_z_zzz fdot_z_zzzi scvtf_z_z scvtflt_z_z ucvtf_z_z ucvtflt_z_z fscale_advsimd", 9)
}

func groupIntegerPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "add_mz_zzv smax_mz_zzv smax_mz_zzw smin_mz_zzv smin_mz_zzw umax_mz_zzv umax_mz_zzw umin_mz_zzv umin_mz_zzw sclamp_mz_zz uclamp_mz_zz sel_mz_p_zz sunpk_mz_z uunpk_mz_z zip_mz_z zip_mz_zz uzp_mz_z uzp_mz_zz", 36)
}

func zaIntegerPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "add_za_zw add_za_zzv add_za_zzw sub_za_zw sub_za_zzv sub_za_zzw", 12)
}

func zaIntegerMultiplyPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "sumlall_za_zzi sumlall_za_zzv usmlall_za_zzi usmlall_za_zzv usmlall_za_zzw svdot_za32_zzi svdot_za_zzi suvdot_za_zzi usvdot_za_zzi uvdot_za32_zzi uvdot_za_zzi", 21)
}

func smeStatePrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "movaz_mz2_za movaz_mz4_za movaz_mz_za2 movaz_mz_za4 movaz_z_rza movt_r_zt movt_zt_r movt_zt_z zero_za1_ri zero_za2_ri zero_za4_ri zero_zt_i", 27)
}

func sveOrdinaryPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "ld1b_z_p_bi ld1b_z_p_br ld1d_z_p_bi ld1d_z_p_br ld1h_z_p_bi ld1h_z_p_br ld1q_z_p_ar ld1sb_z_p_bi ld1sb_z_p_br ld1sh_z_p_bi ld1sh_z_p_br ld1sw_z_p_bi ld1sw_z_p_br ld1w_z_p_bi ld1w_z_p_br ldr_p_bi ldr_z_bi st1b_z_p_bi st1b_z_p_br st1d_z_p_bi st1d_z_p_br st1h_z_p_bi st1h_z_p_br st1q_z_p_ar st1w_z_p_bi st1w_z_p_br str_p_bi str_z_bi", 54), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func sveFinalDataPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "pmlal_mz_zzzw prfb_i_p_ai prfb_i_p_bi prfb_i_p_br prfb_i_p_bz prfd_i_p_ai prfd_i_p_bi prfd_i_p_br prfd_i_p_bz prfh_i_p_ai prfh_i_p_bi prfh_i_p_br prfh_i_p_bz prfw_i_p_ai prfw_i_p_bi prfw_i_p_br prfw_i_p_bz psel_p_ppi", 30)
}

func lsfePrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "ldbfadd ldbfmax ldbfmaxnm ldbfmin ldbfminnm ldfadd ldfmax ldfmaxnm ldfmin ldfminnm stbfadd stbfmax stbfmaxnm stbfmin stbfminnm stfadd stfmax stfmaxnm stfmin stfminnm", 120), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func systemHintsPrimary(t *testing.T, path string) string {
	return a64CompletionPrimary(t, path, "csdb clrbhb dgh stcph stshh shuh psb tsb chkfeat dsb", 11)
}

func lsuiPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "caspt cast ldatxr ldtadd ldtclr ldtnp_fpsimd ldtnp_gen ldtp_fpsimd ldtp_gen ldtset ldtxr stltxr sttnp_fpsimd sttnp_gen sttp_fpsimd sttp_gen sttxr swpt", 64), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func lorPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "ldlar ldlarb ldlarh stllr stllrb stllrh", 8), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func rcwPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "rcwcas rcwcasp rcwclr rcwclrp rcwscas rcwscasp rcwsclr rcwsclrp rcwset rcwsetp rcwsset rcwssetp rcwsswp rcwsswpp rcwswp rcwswpp", 64), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func mopsTagsPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "cpyfp cpyfpn cpyfprn cpyfprt cpyfprtn cpyfprtrn cpyfprtwn cpyfpt cpyfptn cpyfptrn cpyfptwn cpyfpwn cpyfpwt cpyfpwtn cpyfpwtrn cpyfpwtwn cpyp cpypn cpyprn cpyprt cpyprtn cpyprtrn cpyprtwn cpypt cpyptn cpyptrn cpyptwn cpypwn cpypwt cpypwtn cpypwtrn cpypwtwn setgp setgpn setgpt setgptn setp setpn setpt setptn ldg ldgm st2g stg stgm stgp stz2g stzg stzgm", 139), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func ls64Primary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "ld64b st64b st64bv st64bv0", 4), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func timedWaitPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "wfet wfit hinte", 3), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func btiPrimary(t *testing.T, path string) string { return a64CompletionPrimary(t, path, "bti", 1) }

func gcsMemoryPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "gcsb gcsstr gcssttr", 3), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()")
}

func gcsStackPrimary(t *testing.T, path string) string {
	return strings.ReplaceAll(a64CompletionPrimary(t, path, "gcspushm_sys gcspopm_sysl gcsss1_sys gcsss2_sysl gcspushx_sys gcspopcx_sys gcspopx_sys", 7), "recipe(word,vl).unwrap()", "recipe(word,vl,Endian::Little).unwrap()") + `
#[test]
fn generated_gcs_calls_and_returns_use_public_context_api() {
 for endian in [Endian::Little,Endian::Big] {
  let context=aarch64::recipes::RecipeContext{vector_length:128,streaming_vector_length:None,endian};
  for word in [0x94000002u32,0xd63f0020,0xd73f0822,0xd63f083f,0xd73f0c22,0xd63f0c3f] {
   let mut state=State::default();state.gpr[1]=0x8000;
   let graph=aarch64::decode(word).unwrap().semantic_recipe_with_gcs_context(0x1000,context);
   graph.validate().unwrap();assert_eq!(graph.support,Support::Full);
   let transition=evaluate(&graph,&state).unwrap();assert_eq!(transition.trap,None);
   assert_eq!(transition.next_pc,Value::known(64,if word==0x94000002{0x1008}else{0x8000}));
   state.apply(&transition);assert_eq!(state.pointer,0x2ff8);assert_eq!(state.gpr[30],0x1004);
   assert_eq!(state.read_guarded_control_stack(0x2ff8,endian,MemoryPrivilege::Current).unwrap(),Value::known(64,0x1004));
  }
  for word in [0xd65f03c0u32,0xd65f0bff,0xd65f0fff,0xd65f0be2,0xd65f0fe2,0x5500007f,0x5520007f] {
   let mut state=State::default();state.gpr[30]=0x8000;state.store(state.pointer,0x8000,endian);
   let graph=aarch64::decode(word).unwrap().semantic_recipe_with_gcs_context(0x1000,context);
   graph.validate().unwrap();assert_eq!(graph.support,Support::Full);
   let transition=evaluate(&graph,&state).unwrap();assert_eq!(transition.trap,None);assert_eq!(transition.next_pc,Value::known(64,0x8000));
   state.apply(&transition);assert_eq!(state.pointer,0x3008);
   state.pointer=0x3000;state.store(state.pointer,0x9000,endian);
   let transition=evaluate(&graph,&state).unwrap();
   let expected=if word==0xd65f03c0{TrapKind::AArch64GcsReturn}else if word&(if word&0xffc0001f==0x5500001f{1<<21}else{1<<10})==0{TrapKind::AArch64GcsReturnA}else{TrapKind::AArch64GcsReturnB};
   assert_eq!(transition.trap,Some(expected));assert!(transition.registers.is_empty());
  }
 }
}
`
}

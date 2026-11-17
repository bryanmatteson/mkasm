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
	"strings"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/arm"
)

func TestRustA64SVEIndexedIntegerCorpus(t *testing.T) {
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
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime, err := os.ReadFile(filepath.Join(dir, "src/semantics.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runtime), "pub mod arm64_sve_indexed_integer") {
		t.Fatal("production runtime must embed the SVE indexed integer helper")
	}
	fixture, err := os.ReadFile("testdata/arm64_sve_indexed_integer.rs")
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
	if !strings.Contains(string(recipes), "arm64_sve_indexed_integer::a64") {
		t.Fatal("production public builder must dispatch the SVE indexed integer helper")
	}
	const adapter = "fn recipe(word: u32, vl: u16) -> Option<Recipe> {\n    semantics::arm64_sve_indexed_integer::a64(word, 0x1000, vl)\n}"
	if strings.Count(source, adapter) != 1 {
		t.Fatal("fixture recipe adapter changed")
	}
	source = strings.Replace(source, adapter, "fn recipe(word:u32,vl:u16)->Option<Recipe>{aarch64::decode(word).ok().map(|d|d.semantic_recipe_with_vector_length(0x1000,vl))}", 1)
	t.Log("behavioral fixtures use the actual generated public decoder/recipe API")
	source += sveIndexedIntegerPrimary(t, path)
	if err = os.WriteFile(filepath.Join(dir, "indexed_integer.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "indexed_integer.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "indexed-integer-tests"},
		{"./indexed-integer-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE indexed integer %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func sveIndexedIntegerPrimary(t *testing.T, path string) string {
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
	type physical struct {
		mask, base uint32
		width      int
		op         int
	}
	expected := map[string]physical{}
	for op, name := range []string{"mla_z_zzzi", "mls_z_zzzi", "mul_z_zzi"} {
		for _, sz := range []struct {
			suffix     string
			bits       int
			mask, base uint32
		}{{"h", 16, 0xffa0fc00, 0x44200000}, {"s", 32, 0xffe0fc00, 0x44a00000}, {"d", 64, 0xffe0fc00, 0x44e00000}} {
			expected[name+"_"+sz.suffix] = physical{sz.mask, sz.base | []uint32{0x800, 0xc00, 0xf800}[op], sz.bits, op}
		}
	}
	selected := map[string]bool{"mla_z_zzzi.xml": true, "mls_z_zzzi.xml": true, "mul_z_zzi.xml": true}
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
	var out, physicalMasks strings.Builder
	out.WriteString("\n#[test]fn all_primary_indexed_integer_classes_and_legal_selectors(){\nfor(raw,id,w,op,index,d,n,m)in[\n")
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
		if err = xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			classes++
			if len(cl.Encodings) != 1 {
				t.Fatalf("unexpected multi-encoding class %s", name)
			}
			id := cl.Encodings[0].Name
			want, ok := expected[id]
			if !ok {
				t.Fatalf("unknown primary class %s", id)
			}
			var mask, base uint32
			fields := map[string]box{}
			for _, b := range cl.Diagram.Boxes {
				fields[b.Name] = b
				pos := b.Hi
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					bits := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(bits) == 1 && span > 1 && (bits == "0" || bits == "1") {
						bits = strings.Repeat(bits, span)
					}
					if len(bits) != span {
						bits = strings.Repeat("x", span)
					}
					for _, bit := range bits {
						if bit == '0' || bit == '1' {
							mask |= 1 << uint(pos)
							if bit == '1' {
								base |= 1 << uint(pos)
							}
						}
						pos--
					}
				}
			}
			if mask != want.mask || base != want.base {
				t.Fatalf("%s mask/value %08x/%08x, expected %08x/%08x", id, mask, base, want.mask, want.base)
			}
			fmt.Fprintf(&physicalMasks, "(0x%08xu32,0x%08xu32),", mask, base)
			put := func(word uint32, name string, value uint32) uint32 {
				b, ok := fields[name]
				if !ok {
					t.Fatalf("%s missing field %s", id, name)
				}
				width := b.Width
				if width == 0 {
					width = 1
				}
				shift := uint(b.Hi - width + 1)
				return word | (value<<shift)&(((1<<uint(width))-1)<<shift)&^mask
			}
			mb := fields["Zm"]
			for index := 0; index < 128/want.width; index++ {
				for m := 0; m < 1<<uint(mb.Width); m++ {
					for _, pair := range [][2]int{{31, 30}, {0, 1}, {m, 31}, {m, m}} {
						d, n := pair[0], pair[1]
						word := base
						if want.width == 16 {
							word = put(put(word, "i3h", uint32(index>>2)), "i3l", uint32(index&3))
						} else if want.width == 32 {
							word = put(word, "i2", uint32(index))
						} else {
							word = put(word, "i1", uint32(index))
						}
						dest := "Zda"
						if want.op == 2 {
							dest = "Zd"
						}
						word = put(put(put(word, "Zm", uint32(m)), "Zn", uint32(n)), dest, uint32(d))
						if words[word] {
							continue
						}
						words[word] = true
						fmt.Fprintf(&out, "(0x%08xu32,%q,%du8,%dusize,%du16,%du32,%du32,%du32),\n", word, id, want.width, want.op, index, d, n, m)
					}
				}
			}
			delete(expected, id)
		}
	}
	if len(seen) != 3 || classes != 9 || len(expected) != 0 {
		t.Fatalf("primary cohort %d pages %d classes remaining=%v", len(seen), classes, expected)
	}
	t.Logf("June primary: %d pages %d classes %d legal words; every index and Zm value", len(seen), classes, len(words))
	out.WriteString(`]{let dcd=aarch64::decode(raw).unwrap_or_else(|e|panic!("decode {raw:08x} {id}: {e:?}"));assert_eq!(dcd.encoding_id,id,"{raw:08x}");assert_eq!(dcd.evaluate_requirements(&[],"a64").primary,aarch64::requirements::Satisfaction::Unsatisfied);for f in["FEAT_SVE2","FEAT_SME"]{assert_eq!(dcd.evaluate_requirements(&[f],"a64").primary,aarch64::requirements::Satisfaction::Satisfied,"{id} {f}");}for vl in VLS{let r=dcd.semantic_recipe_with_vector_length(0x1000,vl);assert_eq!(r.support,Support::Full,"{raw:08x} {id} VL{vl}");r.validate().unwrap();let s=State::new();check_recipe(&r,vl,&s,w,op,index,d,n,m);}}}
`)
	out.WriteString(`#[test]fn primary_fixed_bits_reject_unowned_neighbors(){let physical=[` + physicalMasks.String() + `];for(mask,base)in physical{for variables in[0,u32::MAX,0xaaaaaaaa,0x55555555]{for bit in 0..32{if mask&(1<<bit)==0{continue}let raw=(base|(variables&!mask))^(1<<bit);assert_eq!(semantics::arm64_sve_indexed_integer::a64(raw,0,128).is_some(),physical.iter().any(|(m,b)|raw&m==*b),"{raw:08x}");}}}}
`)
	return out.String()
}

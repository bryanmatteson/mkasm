package semantics

import (
	"archive/tar"
	"compress/gzip"
	_ "embed"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed arm64_simd_integer_extra.rs
var a64SimdIntegerExtraSource string

//go:embed testdata/arm64_simd_integer_extra.rs
var a64SimdIntegerExtraTests string

func TestRustA64SIMDIntegerExtra(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	// Compile the actual shared evaluator and new helper, without depending on
	// production dispatch integration (owned separately by the caller).
	source := rustRuntime + "\npub mod arm64_simd_integer_extra {\n" + a64SimdIntegerExtraSource + "\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.rs"), []byte(a64SimdIntegerExtraTests+a64SimdIntegerExtraPrimary(t)), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "extra.rs", "-Dwarnings", "-o", filepath.Join(dir, "a64-extra-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 integer SIMD extra: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "a64-extra-tests"), "simd_integer_extra::", "--nocapture")
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("execute A64 integer SIMD extra: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// Read physical class and encoding-specific fixed bits from primary June XML.
// Selector permutations respect those bits; this is independent of the masks
// in the production helper and includes reserved size/Q/sz combinations.
func a64SimdIntegerExtraPrimary(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	result.WriteString("\nconst PRIMARY:&[(u32,bool,&str)]=&[\n")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional primary June XML absent; portable numerical tests remain enabled")
		return result.String() + "];\n"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
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
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
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
	wanted := map[string]bool{}
	for _, stem := range []string{"cmeq_advsimd_zero", "cmge_advsimd_zero", "cmgt_advsimd_zero", "cmle_advsimd", "cmlt_advsimd", "cmeq_advsimd_reg", "cmge_advsimd_reg", "cmgt_advsimd_reg", "cmhi_advsimd", "cmhs_advsimd", "cmtst_advsimd", "movi_advsimd", "mvni_advsimd", "orr_advsimd_imm", "bic_advsimd_imm", "urecpe_advsimd", "ursqrte_advsimd"} {
		wanted[stem+".xml"] = true
	}
	fixedBits := func(boxes []box) (uint32, uint32) {
		var mask, value uint32
		for _, b := range boxes {
			width := b.Width
			if width == 0 {
				width = 1
			}
			var bits strings.Builder
			for _, c := range b.Cells {
				span := c.Span
				if span == 0 {
					span = 1
				}
				s := strings.Trim(strings.TrimSpace(c.Text), "()")
				if len(s) != span {
					s = strings.Repeat("x", span)
				}
				bits.WriteString(s)
			}
			if bits.Len() != width {
				t.Fatalf("bad primary diagram field %q", b.Name)
			}
			for i, c := range bits.String() {
				if c == '0' || c == '1' {
					bit := uint32(1) << uint(b.Hi-i)
					mask |= bit
					if c == '1' {
						value |= bit
					}
				}
			}
		}
		return mask, value
	}
	pages, encodings, cases := 0, 0, 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(header.Name)
		if !wanted[name] || !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		pages++
		var doc page
		if err = xml.NewDecoder(reader).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		for _, cl := range doc.Classes {
			for _, enc := range cl.Encodings {
				encodings++
				mask, value := fixedBits(cl.Diagram.Boxes)
				em, ev := fixedBits(enc.Boxes)
				value = (value &^ em) | ev
				mask |= em
				selector := uint32(0)
				for _, b := range cl.Diagram.Boxes {
					switch b.Name {
					case "Q", "size", "sz", "op", "cmode":
						width := b.Width
						if width == 0 {
							width = 1
						}
						selector |= uint32((uint64(1)<<uint(width))-1) << uint(b.Hi-width+1)
					}
				}
				selector &^= mask
				var positions []uint
				for bit := uint(0); bit < 32; bit++ {
					if selector&(1<<bit) != 0 {
						positions = append(positions, bit)
					}
				}
				for combo := 0; combo < 1<<len(positions); combo++ {
					word := value
					for i, bit := range positions {
						if combo&(1<<i) != 0 {
							word |= 1 << bit
						}
					}
					for variant := 0; variant < 3; variant++ {
						w := word
						for _, b := range cl.Diagram.Boxes {
							width := b.Width
							if width == 0 {
								width = 1
							}
							v := uint32(0)
							switch b.Name {
							case "Rd":
								if variant == 2 {
									v = 31
								}
							case "Rn":
								v = 1
								if variant == 1 {
									v = 0
								}
								if variant == 2 {
									v = 31
								}
							case "Rm":
								v = 2
								if variant == 1 {
									v = 0
								}
								if variant == 2 {
									v = 31
								}
							case "a", "b", "c", "d", "e", "f", "g", "h":
								if variant != 0 {
									v = 1
								}
							}
							m := uint32((uint64(1)<<uint(width))-1) << uint(b.Hi-width+1)
							w |= (v << uint(b.Hi-width+1)) & m &^ mask
						}
						legal := true
						if strings.HasPrefix(name, "urecpe") || strings.HasPrefix(name, "ursqrte") {
							legal = w&(1<<22) == 0
						} else if !strings.Contains(name, "_imm") && !strings.HasPrefix(name, "movi") && !strings.HasPrefix(name, "mvni") && w&(1<<28) == 0 {
							legal = ((w>>22)&3) != 3 || w&(1<<30) != 0
						}
						fmt.Fprintf(&result, "(0x%08x,%t,%q),\n", w, legal, enc.Name)
						cases++
					}
				}
			}
		}
	}
	if pages != 17 || encodings != 37 {
		t.Fatalf("primary closure: %d pages/%d encodings, want17/37", pages, encodings)
	}
	t.Logf("derived %d physical selector/alias cases from %d June pages / %d encodings (32 inventory gaps + 5 companion vector comparisons)", cases, pages, encodings)
	result.WriteString("];\n")
	return result.String()
}

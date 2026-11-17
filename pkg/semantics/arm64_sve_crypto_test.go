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

//go:embed testdata/arm64_sve_crypto.rs
var a64SVECryptoTests string

func TestRustA64SVECrypto(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"runtime.rs": RustRuntime, "tests.rs": a64SVECryptoTests + a64SVECryptoCorpus(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile SVE crypto recipes: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "tests"), "sve_crypto::", "--test-threads=1", "--nocapture")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute SVE crypto recipes: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
func a64SVECryptoCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Skip("June primary corpus unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
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
	tr := tar.NewReader(gz)
	pages, classes, words := 0, 0, 0
	var out strings.Builder
	out.WriteString("\nconst PRIMARY:&[(u32,&str)]=&[\n")
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(h.Name), ".xml")
		wanted := map[string]bool{"aese_mz_zzi": true, "aesd_mz_zzi": true, "aesemc_mz_zzi": true, "aesdimc_mz_zzi": true, "pmull_mz_zzw": true, "aese_z_zz": true, "aesd_z_zz": true, "aesmc_z_z": true, "aesimc_z_z": true, "sm4e_z_zz": true, "sm4ekey_z_zz": true, "rax1_z_zz": true, "pmul_z_zz": true, "eor3_z_zzz": true, "bcax_z_zzz": true, "xar_z_zzi": true, "bdep_z_zz": true, "bext_z_zz": true, "bgrp_z_zz": true}
		if !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") || !wanted[name] {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			classes++
			for variant := 0; variant < 4; variant++ {
				var word uint32
				for _, b := range cl.Diagram.Boxes {
					w := b.Width
					if w == 0 {
						w = 1
					}
					pos := b.Hi
					var mask, value uint32
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						txt := strings.Trim(strings.TrimSpace(c.Text), "()")
						if len(txt) == span {
							for _, bit := range txt {
								if bit == '0' || bit == '1' {
									mask |= 1 << uint(pos)
									if bit == '1' {
										value |= 1 << uint(pos)
									}
								}
								pos--
							}
						} else {
							pos -= span
						}
					}
					v := uint32(0)
					switch b.Name {
					case "Zn", "Zk":
						v = []uint32{0, 31, 29, 1}[variant]
					case "Zm":
						v = []uint32{1, 31, 30, 0}[variant]
					case "Zt", "Zd", "Zdn":
						v = []uint32{0, 31, 29, 30}[variant]
					case "size":
						v = uint32(variant)
					case "tszh":
						v = []uint32{1, 2, 4, 8}[variant] >> 2
					case "tszl":
						v = []uint32{1, 2, 4, 8}[variant] & 3
					case "i2":
						v = uint32(variant)
					case "imm3":
						v = []uint32{0, 7, 1, 4}[variant]
					}
					region := ((uint32(1) << uint(w)) - 1) << uint(b.Hi-w+1)
					word |= (v<<uint(b.Hi-w+1))&(region&^mask) | value
				}
				fmt.Fprintf(&out, "(0x%08x,%q),\n", word, name)
				words++
			}
		}
	}
	if pages != 19 || classes != 23 || words != 92 {
		t.Fatalf("primary coverage: %d pages %d classes %d words", pages, classes, words)
	}
	t.Logf("June corpus: %d pages, %d classes, %d words", pages, classes, words)
	out.WriteString("];\n")
	return out.String()
}

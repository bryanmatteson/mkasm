package arm

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
	"regexp"
	"strings"
	"testing"
	"time"
)

// Compile the real June decoder and exercise SVE crypto recipes through its
// public context-aware recipe entry, including every byte/alias/fault oracle.
func TestRustA64SVECryptoCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("June primary corpus unavailable")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := os.Getenv("MKASM_A64_SVE_REFERENCE_RUST")
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if cli := os.Getenv("MKASM_REFERENCE_CLI"); cli != "" {
		cmd := exec.Command(cli, "--arch", "aarch64", "--codegen", "rust", "--output", dir, path)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("CLI AArch64 generation: %v\n%s", err, out)
		}
	} else {
		corpus, err := OpenTarXMLCorpus(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		parser := NewARMParser(ARMParserConfig{EncodingIndexPath: ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: ArchAArch64, Languages: []CodegenLang{LangRust}})
		defer func() {
			if err := parser.Close(5 * time.Second); err != nil {
				t.Error(err)
			}
		}()
		if err := parser.Parse(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile("../semantics/testdata/arm64_sve_crypto.rs")
	if err != nil {
		t.Fatal(err)
	}
	adapter := regexp.MustCompile(`(?s)\A#\[allow\(dead_code\)\]\nmod runtime;\nuse runtime::\*;\nfn a64\(word: u32, address: u64, vl: u16\) -> Option<Recipe> \{.*?\n\}`)
	if !adapter.Match(body) {
		t.Fatal("crypto fixture adapter changed")
	}
	source := adapter.ReplaceAllLiteralString(string(body), `use aarch64::semantics::*;
fn a64(word:u32,address:u64,vl:u16)->Option<Recipe> {
 aarch64::semantics::arm64_sve_crypto_group::a64(word,address,vl).or_else(||aarch64::semantics::arm64_sve_crypto::a64(word,address,vl))?;
 let decoded=aarch64::decode(word).ok()?;
 Some(decoded.semantic_recipe_with_context(address,aarch64::recipes::RecipeContext{endian:Endian::Little,vector_length:vl,streaming_vector_length:None}))
}
`)
	source = strings.ReplaceAll(source, "runtime::arm64_sve::a64", "aarch64::semantics::arm64_sve::a64")
	source += a64SVECryptoGeneratedCorpus(t, path)
	if strings.Contains(source, "mod runtime;") {
		t.Fatal("fixture must call the production-generated decoder")
	}
	if err := os.WriteFile(filepath.Join(dir, "sve_crypto.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"}, {"--edition=2021", "--test", "sve_crypto.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-o", "sve_crypto-tests"}, {"./sve_crypto-tests", "sve_crypto::", "--test-threads=1", "--nocapture"}} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated SVE crypto consumer %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a64SVECryptoGeneratedCorpus(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
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

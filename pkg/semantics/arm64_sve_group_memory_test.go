package semantics_test

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/semantics"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Primary metadata supplies an independent register diagram and operation shape
// for each of the 128 classes; behavioral tests do not mirror runtime masks.
func groupMemoryCorpus(t *testing.T, path string) string {
	t.Helper()
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
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Hi    int    `xml:"hibit,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name string `xml:"name,attr"`
	}
	type class struct {
		Boxes []box      `xml:"regdiagram>box"`
		Enc   []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	var out strings.Builder
	out.WriteString("\nconst GROUP_CLASSES:&[(u32,&str,u16,u16,bool,bool,bool)]=&[\n")
	tr := tar.NewReader(gz)
	pages, classes := 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(h.Name), ".xml")
		if !strings.HasSuffix(h.Name, ".xml") || !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") || !(strings.Contains(name, "_mz_p_") || strings.Contains(name, "_mzx_p_")) || !(strings.HasPrefix(name, "ld1") || strings.HasPrefix(name, "st1") || strings.HasPrefix(name, "ldnt1") || strings.HasPrefix(name, "stnt1")) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err := xml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			var word uint32
			for _, b := range cl.Boxes {
				pos := b.Hi
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					text := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(text) != span {
						text = strings.Repeat("x", span)
					}
					for _, bit := range text {
						if bit == '1' {
							word |= 1 << uint(pos)
						}
						pos--
					}
				}
			}
			for _, en := range cl.Enc {
				classes++
				stem := strings.Split(name, "_")[0]
				width := map[byte]int{'b': 8, 'h': 16, 'w': 32, 'd': 64}[stem[len(stem)-1]]
				count := 2
				if strings.HasSuffix(en.Name, "_4") || strings.HasSuffix(en.Name, "_4x4") {
					count = 4
				}
				fmt.Fprintf(&out, "(0x%08x,%q,%d,%d,%t,%t,%t),\n", word, en.Name, width, count, strings.Contains(name, "_mzx_"), strings.HasSuffix(name, "_bi"), strings.HasPrefix(name, "st"))
			}
		}
	}
	if pages != 64 || classes != 128 {
		t.Fatalf("grouped memory primary corpus: %d pages %d classes", pages, classes)
	}
	out.WriteString("];\n")
	t.Logf("grouped memory: %d primary pages, %d physical classes", pages, classes)
	return out.String()
}
func TestRustA64GroupedMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to June 2026 A64 XML")
	}
	body, err := os.ReadFile("testdata/arm64_sve_group_memory.rs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"semantics.rs": []byte(semantics.RustRuntime), "group.rs": append(body, []byte(groupMemoryCorpus(t, path))...)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"--edition=2021", "--test", "group.rs", "-Copt-level=1", "-Dwarnings", "-o", "group-tests"}, {"./group-tests", "--nocapture"}} {
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
}

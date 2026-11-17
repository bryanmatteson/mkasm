package sparc

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func catalog(t *testing.T, path, arch string) *codec.Catalog {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func seed(e *codec.Encoding, sample int) map[string]int64 {
	v := map[string]int64{}
	for i, o := range e.Operands {
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		raw := int64(0)
		if sample > 0 {
			raw = int64((sample+i*3)%7 + 1)
		}
		if len(o.Names) > 0 {
			var allowed []int
			for i, n := range o.Names {
				if n != "" {
					allowed = append(allowed, i)
				}
			}
			if len(allowed) > 0 {
				raw = int64(allowed[(sample+i)%len(allowed)])
				if strings.Contains(e.ID, "/v9-registers") && o.Kind == "register" && len(o.Names) > 32 {
					raw = int64(allowed[len(allowed)-1])
				}
			}
		}
		if o.Signed && sample == 2 {
			raw = -raw
		}
		v[o.Name] = raw*scale + o.Bias
	}
	return v
}
func roundtrip(t *testing.T, c *codec.Catalog) {
	t.Helper()
	for i := range c.Encodings {
		e := &c.Encodings[i]
		for sample := 0; sample < 3; sample++ {
			v := seed(e, sample)
			b, err := c.Encode(e.ID, v)
			if err != nil {
				t.Fatalf("encode %s: %v (%v)", e.ID, err, v)
			}
			d, err := c.Decode(b)
			if err != nil {
				t.Fatalf("decode %s %x: %v", e.ID, b, err)
			}
			back, err := c.Encode(d.Encoding.ID, d.Values)
			if err != nil || !bytes.Equal(back, b) {
				t.Fatalf("byte roundtrip %s: %x %v", e.ID, back, err)
			}
			text := (&codec.Decoded{Encoding: e, Values: v, Length: 4}).Format(0)
			bs, err := c.Assemble(text, 0)
			if err != nil {
				t.Fatalf("format %s %q: %v", e.ID, text, err)
			}
			found := false
			for _, got := range bs {
				found = found || bytes.Equal(got, b)
			}
			if !found {
				t.Fatalf("text roundtrip %s %q %x want %x", e.ID, text, bs, b)
			}
		}
	}
}
func TestFixture(t *testing.T) {
	for _, arch := range []string{"sparc32", "sparc64", "sparc32le"} {
		t.Run(arch, func(t *testing.T) { c := catalog(t, "testdata/llvm22-sparc.json", arch); roundtrip(t, c) })
	}
}
func TestFullCorpus(t *testing.T) {
	path := os.Getenv("SPARC_TABLEGEN_JSON")
	if path == "" {
		t.Skip("set SPARC_TABLEGEN_JSON to full LLVM dump")
	}
	for _, arch := range []string{"sparc32", "sparc64", "sparc32le"} {
		t.Run(arch, func(t *testing.T) {
			c := catalog(t, path, arch)
			t.Logf("%s: %d encodings, %d unsupported", arch, len(c.Encodings), len(c.Unsupported))
			direct, aliases, variants := 0, 0, 0
			for _, e := range c.Encodings {
				if strings.Contains(e.ID, "/cc") || strings.Contains(e.ID, "/v9-registers") {
					variants++
				} else if strings.HasPrefix(e.ID, "anonymous_") {
					aliases++
				} else {
					direct++
				}
			}
			t.Logf("direct=%d aliases=%d syntax/register variants=%d", direct, aliases, variants)
			roundtrip(t, c)
			if dir := os.Getenv("SPARC_REPORT_DIR"); dir != "" {
				data, _ := json.MarshalIndent(c.Unsupported, "", "  ")
				if err := os.WriteFile(filepath.Join(dir, arch+"-unsupported.json"), data, 0644); err != nil {
					t.Fatal(err)
				}
				if err := c.GenerateRust(filepath.Join(dir, arch+"-rust")); err != nil {
					t.Fatal(err)
				}
			}
			if os.Getenv("SPARC_LLVM_PARITY") == "1" {
				oracle(t, c)
			}
		})
	}
}

type oracleCase struct {
	id, text string
	want     []byte
	line     int
	label    int
}

var diagnostic = regexp.MustCompile(`<stdin>:(\d+):\d+: error:`)

func oracle(t *testing.T, c *codec.Catalog) {
	t.Helper()
	llvm := os.Getenv("LLVM_MC")
	if llvm == "" {
		llvm = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	triple := map[string]string{"sparc32": "sparc", "sparc64": "sparcv9", "sparc32le": "sparcel"}[c.Architecture]
	var cases []oracleCase
	for i := range c.Encodings {
		e := &c.Encodings[i]
		v := seed(e, 1)
		want, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		text := (&codec.Decoded{Encoding: e, Values: v, Length: 4}).Format(0)
		for _, o := range e.Operands {
			if o.Relative {
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint64(v[o.Name])), fmt.Sprintf(".L%d%+d", i, v[o.Name]))
			}
		}
		cases = append(cases, oracleCase{id: e.ID, text: text, want: want, label: i})
	}
	var rejected []string
	var gnuCases []oracleCase
	dir := t.TempDir()
	object := filepath.Join(dir, "oracle.o")
	for attempt := 0; attempt < 4; attempt++ {
		var input strings.Builder
		lines := map[int]int{}
		for i := range cases {
			fmt.Fprintf(&input, ".section .text.c%d,\"ax\"\n.L%d:\n", i, cases[i].label)
			cases[i].line = i*3 + 3
			lines[cases[i].line] = i
			fmt.Fprintln(&input, cases[i].text)
		}
		cmd := exec.Command(llvm, "-triple="+triple, "-mattr=+v9,+v8plus,+deprecated-v8,+vis,+vis2,+vis3,+hard-quad-float,+crypto,+ua2005,+ua2007,+osa2011,+leonpwrpsr,+hasleoncasa,+hasumacsmac", "-filetype=obj", "-o", object)
		cmd.Stdin = strings.NewReader(input.String())
		out, err := cmd.CombinedOutput()
		if err != nil {
			bad := map[int]bool{}
			for _, m := range diagnostic.FindAllSubmatch(out, -1) {
				line, _ := strconv.Atoi(string(m[1]))
				if i, ok := lines[line]; ok {
					bad[i] = true
				}
			}
			if len(bad) == 0 {
				t.Fatalf("LLVM execution: %v\n%s", err, out)
			}
			var keep []oracleCase
			for i, c := range cases {
				if bad[i] {
					rejected = append(rejected, c.id+": "+c.text)
					gnuCases = append(gnuCases, c)
				} else {
					keep = append(keep, c)
				}
			}
			cases = keep
			continue
		}
		f, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		for i, tc := range cases {
			section := f.Section(fmt.Sprintf(".text.c%d", i))
			if section == nil {
				t.Fatalf("missing oracle section %s", tc.id)
			}
			got, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("LLVM bytes %s %q: got %x want %x", tc.id, tc.text, got, tc.want)
			}
		}
		f.Close()
		if len(gnuCases) > 0 {
			verifyGNUForms(t, c.Architecture, gnuCases)
		}
		t.Logf("%s: %d LLVM forms and %d GNU forms matched; zero uncovered samples", c.Architecture, len(cases), len(gnuCases))
		if dir := os.Getenv("SPARC_REPORT_DIR"); dir != "" {
			data, _ := json.MarshalIndent(map[string]any{"architecture": c.Architecture, "llvm_matched": len(cases), "llvm_rejected": rejected, "gnu_matched": len(gnuCases), "uncovered": 0}, "", "  ")
			os.WriteFile(filepath.Join(dir, c.Architecture+"-llvm.json"), data, 0644)
		}
		return
	}
	t.Fatal("LLVM parity could not isolate diagnostics")
}

// LLVM's 32-bit parser rejects several V9 instructions that remain valid in
// a 32-bit ABI. GNU gas emits their ELF32 physical words. Its SPARC ELF backend
// is big-endian; the LE catalog compares the same native words in LE byte order.
func verifyGNUForms(t *testing.T, architecture string, cases []oracleCase) {
	t.Helper()
	assembler := os.Getenv("MKASM_SPARC_AS")
	if assembler == "" {
		t.Fatal("set MKASM_SPARC_AS for SPARC32 V9 reference coverage")
	}
	var input strings.Builder
	for n, c := range cases {
		fmt.Fprintf(&input, ".section .text.c%d,\"ax\"\n%s\n", n, c.text)
	}
	object := filepath.Join(t.TempDir(), "gnu.o")
	cmd := exec.Command(assembler, "-32", "-Av9m8", "-EB", "-no-relax", "-o", object)
	cmd.Stdin = strings.NewReader(input.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GNU %s: %v\n%s", architecture, err, out)
	}
	f, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS32 {
		t.Fatal("GNU did not emit ELF32")
	}
	for n, c := range cases {
		section := f.Section(fmt.Sprintf(".text.c%d", n))
		if section == nil {
			t.Fatal("missing GNU section for ", c.id)
		}
		actual, err := section.Data()
		if err == nil && architecture == "sparc32le" && len(actual) == 4 {
			word := binary.BigEndian.Uint32(actual)
			binary.LittleEndian.PutUint32(actual, word)
		}
		if err != nil || !bytes.Equal(actual, c.want) {
			t.Fatalf("GNU %s %s %q: %x != %x: %v", architecture, c.id, c.text, actual, c.want, err)
		}
	}
}

func TestEndianRegistersAndTargets(t *testing.T) {
	be := catalog(t, "testdata/llvm22-sparc.json", "sparc64")
	le := catalog(t, "testdata/llvm22-sparc.json", "sparc32le")
	for _, c := range []*codec.Catalog{be, le} {
		b, err := c.Encode("ADDri", map[string]int64{"rd": 8, "rs1": 1, "simm13": 17})
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0x90, 0x00, 0x60, 0x11}
		if c.Architecture == "sparc32le" {
			want = []byte{0x11, 0x60, 0x00, 0x90}
		}
		if !bytes.Equal(b, want) {
			t.Fatalf("%s bytes %x", c.Architecture, b)
		}
		for _, text := range []string{"add %g1, 17, %o0", "add %r1, 17, %r8"} {
			got, err := c.Assemble(text, 0)
			if err != nil || !bytes.Equal(got[0], want) {
				t.Fatalf("%q = %x %v", text, got, err)
			}
		}
	}
	b, err := be.Encode("FADDD", map[string]int64{"rd": 32, "rs1": 34, "rs2": 62})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x83, 0xa0, 0xc8, 0x5f}) {
		t.Fatalf("LLVM upper DFP bytes %x", b)
	}
	d, err := be.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Values["rd"] != 32 || d.Values["rs1"] != 34 || d.Values["rs2"] != 62 {
		t.Fatalf("upper FP registers: %+v", d)
	}
	q, err := be.Encode("FADDQ", map[string]int64{"rd": 32, "rs1": 36, "rs2": 60})
	if err != nil || !bytes.Equal(q, []byte{0x83, 0xa1, 0x48, 0x7d}) {
		t.Fatalf("LLVM upper QFP bytes %x %v", q, err)
	}
	for _, tc := range []struct {
		text string
		want []byte
	}{{"ld [%sp + -4096], %o0", []byte{0xd0, 0x03, 0xb0, 0x00}}, {"save %sp, -4096, %sp", []byte{0x9d, 0xe3, 0xb0, 0x00}}} {
		got, err := be.Assemble(tc.text, 0)
		if err != nil || !bytes.Equal(got[0], tc.want) {
			t.Fatalf("LLVM signed memory %q: %x %v", tc.text, got, err)
		}
	}
	for _, offset := range []int64{-8388608, -4, 0, 4, 8388604} {
		b, err := be.Encode("BCOND", map[string]int64{"cond": 9, "imm22": offset})
		if err != nil {
			t.Fatal(err)
		}
		d, err := be.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.Format(0x1000), fmt.Sprintf("0x%x", uint64(0x1000+offset))) {
			t.Fatalf("target %d: %s", offset, d.Format(0x1000))
		}
		if d.Encoding.DelaySlots != 1 {
			t.Fatalf("branch delay slot: %+v", d.Encoding)
		}
	}
	for _, offset := range []int64{-8388612, 1, 8388608} {
		if _, err := be.Encode("BCOND", map[string]int64{"cond": 9, "imm22": offset}); err == nil {
			t.Fatalf("accepted offset %d", offset)
		}
	}
	v8 := catalog(t, "testdata/llvm22-sparc.json", "sparc32")
	if _, err := v8.AssembleWithFeatures("faddd %f34, %f62, %f32", 0, v8.FeatureSets["v8"]); err == nil {
		t.Fatal("V8 accepted V9 FP bank")
	}
	if _, err := v8.AssembleWithFeatures("faddd %f34, %f62, %f32", 0, v8.FeatureSets["v9"]); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Encode("FADDD", map[string]int64{"rd": 33, "rs1": 2, "rs2": 4}); err == nil {
		t.Fatal("odd double FP register accepted")
	}
}
func TestRejectInvalidInput(t *testing.T) {
	for _, source := range []string{"{}", "{\"!instanceof\":{\"Instruction\":[]}}", "{} {}"} {
		if _, err := Parse(strings.NewReader(source), "sparc32"); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if _, err := Parse(strings.NewReader("{}"), "other"); err == nil {
		t.Fatal("accepted architecture")
	}
}

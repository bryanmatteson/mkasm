package arc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
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

			}
		}
		if o.Signed && o.Width() >= 9 && o.Width() < 32 {
			raw = 100
			if o.Width() >= 10 {
				raw = 300
			}
		}
		if o.Width() == 32 {
			raw = 0x12345678
		}
		var bits uint64
		for _, bit := range o.Bits {
			for k := 0; k < bit.Width; k++ {
				bits |= 1 << uint(bit.ValueBit+k)
			}
		}
		raw = int64(uint64(raw) & bits)
		if o.Signed && raw >= 1<<uint(o.Width()-1) {
			raw -= 1 << uint(o.Width())
		}
		if o.Signed && sample == 2 && raw >= 0 {
			raw = -raw
		}
		if len(o.Lookup) > 0 {
			raw = o.Lookup[raw]
		}
		v[o.Name] = raw*scale + o.Bias
	}
	for _, o := range e.Operands {
		if o.Implicit {
			v[o.Name] = 0
		}
	}
	for _, c := range e.Constraints {
		if c.Kind == "ne" && c.Right == "" && v[c.Left] == 0 {
			v[c.Left] = 2
		}
		if c.Kind == "sum_le" && c.Limit == -1 && v[c.Left] >= 0 {
			if v[c.Left] == 0 {
				v[c.Left] = 2
			}
			v[c.Left] = -v[c.Left]
		}
	}
	return v
}
func roundtrip(t *testing.T, c *codec.Catalog) {
	t.Helper()
	for i := range c.Encodings {
		e := &c.Encodings[i]
		for sample := 0; sample < 3; sample++ {
			v := seed(e, sample)
			b, err := codec.Encode(e, v)
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
			text := (&codec.Decoded{Encoding: e, Values: v, Length: len(e.Value)}).Format(0)
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
	for _, arch := range []string{"arc32", "arc32be"} {
		t.Run(arch, func(t *testing.T) { c := catalog(t, "testdata/llvm22-arc.json", arch); roundtrip(t, c) })
	}
}
func TestFullCorpus(t *testing.T) {
	path := os.Getenv("ARC_TABLEGEN_JSON")
	if path == "" {
		t.Skip("set ARC_TABLEGEN_JSON to full LLVM dump")
	}
	for _, arch := range []string{"arc32", "arc32be"} {
		t.Run(arch, func(t *testing.T) {
			c := catalog(t, path, arch)
			t.Logf("%s: %d encodings, %d unsupported", arch, len(c.Encodings), len(c.Unsupported))

			roundtrip(t, c)
			if os.Getenv("ARC_GAS") != "" {
				oracle(t, c)
			}
			if dir := os.Getenv("ARC_REPORT_DIR"); dir != "" {
				data, _ := json.MarshalIndent(c.Unsupported, "", "  ")
				if err := os.WriteFile(filepath.Join(dir, arch+"-unsupported.json"), data, 0644); err != nil {
					t.Fatal(err)
				}
				if err := c.GenerateRust(filepath.Join(dir, arch+"-rust")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGNUFullCorpus(t *testing.T) {
	p := os.Getenv("ARC_GNU_SOURCE")
	if p == "" {
		t.Skip("set ARC_GNU_SOURCE to binutils source archive")
	}
	modes := []string{"arc32"}
	if s := os.Getenv("ARC_MODES"); s != "" {
		modes = strings.Split(s, ",")
	}
	for _, mode := range modes {
		c := catalog(t, p, mode)
		t.Logf("GNU %d encodings, %d unsupported", len(c.Encodings), len(c.Unsupported))
		if dir := os.Getenv("ARC_REPORT_DIR"); dir != "" {
			d, _ := json.MarshalIndent(c.Unsupported, "", "  ")
			os.WriteFile(filepath.Join(dir, c.Architecture+"-gnu-unsupported.json"), d, 0644)
		}
		if os.Getenv("ARC_GAS") != "" {
			oracle(t, c)
		}
		if os.Getenv("ARC_NATIVE_ORACLE") != "" {
			nativeOracle(t, c, p)
		}
		if dir := os.Getenv("ARC_GENERATE_NATIVE"); dir != "" {
			if err := c.GenerateRust(dir); err != nil {
				t.Fatal(err)
			}
		}
		for i := range c.Encodings {
			e := &c.Encodings[i]
			v := seed(e, 1)
			single := &codec.Catalog{Architecture: c.Architecture, Encodings: []codec.Encoding{*e}}
			roundtrip(t, single)
			if _, err := codec.Encode(e, v); err != nil {
				t.Fatalf("%s %s: %v seed=%v", e.ID, e.Syntax, err, v)
			}
		}
	}
}

type oracleCase struct {
	id, text  string
	canonical string
	want      []byte
	label     int
}

var gasDiagnostic = regexp.MustCompile(`(?m)^.*?:(\d+): (?:Error|error|Internal error)[: ]`)

func oracle(t *testing.T, c *codec.Catalog) {
	t.Helper()
	if strings.HasSuffix(c.Architecture, "be") && (strings.HasPrefix(c.Architecture, "arc64") || strings.HasPrefix(c.Architecture, "arcv3-32")) {
		t.Log("GNU ARCv3 assembler has no big-endian option; compiled upstream insertion functions cover this byte order")
		return
	}
	var cases []oracleCase
	var rejected []string
	for i := range c.Encodings {
		e := &c.Encodings[i]
		v := seed(e, 1)
		want, err := codec.Encode(e, v)
		if err != nil {
			t.Fatal(err)
		}
		text := (&codec.Decoded{Encoding: e, Values: v, Length: len(e.Value)}).Format(0)
		canonical := text
		for _, o := range e.Operands {
			if o.Relative {
				target := uint64(v[o.Name])
				if o.PCWrapBits == 32 {
					target &= 0xffffffff
				}
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", target), fmt.Sprintf(".L%d%+d", i, v[o.Name]))
			}
		}
		if strings.Contains(e.ID, "/C_CC30") || strings.Contains(e.ID, "/cc24") {
			rejected = append(rejected, e.ID+": GNU binutils 2.44 confuses nt condition with branch prediction: "+text)
			continue
		}
		cases = append(cases, oracleCase{id: e.ID, text: text, canonical: canonical, want: want, label: i})
	}
	dir := t.TempDir()
	object := filepath.Join(dir, "oracle.o")
	source := filepath.Join(dir, "oracle.s")
	for attempt := 0; attempt < 12; attempt++ {
		var input strings.Builder
		for i, tc := range cases {
			fmt.Fprintf(&input, ".section .text.c%d,\"ax\"\n.L%d:\n%s\nnop\n", i, tc.label, tc.text)
		}
		os.WriteFile(source, []byte(input.String()), 0644)
		if d := os.Getenv("ARC_REPORT_DIR"); d != "" {
			os.WriteFile(filepath.Join(d, "gas-input.s"), []byte(input.String()), 0644)
		}
		endian := "-EL"
		if strings.HasSuffix(c.Architecture, "be") {
			endian = "-EB"
		}
		args := []string{"-mcpu=archs", endian}
		if strings.HasPrefix(c.Architecture, "arcnps400") {
			args[0] = "-mcpu=nps400"
		} else if strings.HasPrefix(c.Architecture, "arc64") {
			args = []string{"-mcpu=hs6x"}
		} else if strings.HasPrefix(c.Architecture, "arcv3-32") {
			args = []string{"-mcpu=hs5x"}
		}
		cmd := exec.Command(os.Getenv("ARC_GAS"), append(args, "-o", object, source)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if d := os.Getenv("ARC_REPORT_DIR"); d != "" {
				os.WriteFile(filepath.Join(d, fmt.Sprintf("gas-errors-%d.txt", attempt)), out, 0644)
			}
			t.Logf("oracle pass %d: %d cases, %d diagnostic bytes", attempt, len(cases), len(out))
			bad := map[int]bool{}
			for _, m := range gasDiagnostic.FindAllSubmatch(out, -1) {
				line, _ := strconv.Atoi(string(m[1]))
				bad[(line-1)/4] = true
			}
			if len(bad) == 0 {
				t.Fatalf("GNU assembler %v\n%s", err, out)
			}
			var keep []oracleCase
			for i, tc := range cases {
				if bad[i] {
					rejected = append(rejected, tc.id+": "+tc.text)
				} else {
					keep = append(keep, tc)
				}
			}
			cases = keep
			continue
		}
		f, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		mismatch := 0
		alternate := 0
		groups := map[string][]codec.Encoding{}
		for _, e := range c.Encodings {
			groups[e.Mnemonic] = append(groups[e.Mnemonic], e)
		}
		var mismatches []string
		for i, tc := range cases {
			section := f.Section(fmt.Sprintf(".text.c%d", i))
			if section == nil {
				t.Fatalf("missing section %s", tc.id)
			}
			got, _ := section.Data()
			if len(got) >= len(tc.want) {
				got = got[:len(tc.want)]
			}
			if !bytes.Equal(got, tc.want) {
				subset := &codec.Catalog{Architecture: c.Architecture, Encodings: groups[strings.Fields(tc.canonical)[0]]}
				bs, _ := subset.Assemble(tc.canonical, 0)
				valid := false
				for _, b := range bs {
					if bytes.Equal(b, got) {
						valid = true
					}
				}
				if valid {
					alternate++
					continue
				}
				mismatch++
				mismatches = append(mismatches, fmt.Sprintf("%s %q got %x want %x", tc.id, tc.text, got, tc.want))
				if mismatch < 25 {
					t.Errorf("GNU bytes %s", mismatches[len(mismatches)-1])
				}
			}
		}
		f.Close()
		t.Logf("GNU %s: %d matched, %d mismatched, %d rejected", c.Architecture, len(cases)-mismatch-alternate, mismatch, len(rejected))
		if dir := os.Getenv("ARC_REPORT_DIR"); dir != "" {
			data, _ := json.MarshalIndent(map[string]any{"matched": len(cases) - mismatch - alternate, "alternate_encodings": alternate, "mismatched": mismatches, "rejected": rejected}, "", "  ")
			name := c.Architecture
			if strings.Contains(c.Source, "GNU") {
				name += "-gnu"
			}
			os.WriteFile(filepath.Join(dir, name+"-parity.json"), data, 0644)
			objectBytes, err := os.ReadFile(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+"-oracle.o"), objectBytes, 0644); err != nil {
				t.Fatal(err)
			}
		}
		if mismatch != 0 {
			t.Fail()
		}
		return
	}
	t.Fatal("GNU parity could not isolate diagnostics")
}

func nativeOracle(t *testing.T, c *codec.Catalog, source string) {
	t.Helper()
	f, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var archive io.Reader = f
	magic := make([]byte, 2)
	f.ReadAt(magic, 0)
	if magic[0] == 31 && magic[1] == 139 {
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer z.Close()
		archive = z
	}
	tr := tar.NewReader(archive)
	files := map[string]string{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(tr)
		files[filepath.Base(h.Name)] = string(b)
	}
	table := files["arc-tbl.h"]
	if strings.HasPrefix(c.Architecture, "arcnps400") {
		table += "\n" + files["arc-nps400-tbl.h"]
	}
	table += "\n" + files["arc-ext-tbl.h"]
	rows := gnuRow.FindAllStringSubmatch(table, -1)
	defs := cArray(files["arc-opc.c"], "arc_operands")
	classes := cArray(files["arc-opc.c"], "arc_flag_classes")
	var input strings.Builder
	var want [][]byte
	var caseIDs []string
	for sample := 0; sample < 3; sample++ {
		for i := range c.Encodings {
			e := &c.Encodings[i]
			parts := strings.Split(e.ID, "/")
			row, _ := strconv.Atoi(parts[2])
			m := rows[row]
			big := 0
			if strings.HasSuffix(c.Architecture, "be") {
				big = 1
			}
			fmt.Fprintf(&input, "%d %d", row, big)
			cls := fields(m[8])
			for j := 0; j < 4; j++ {
				ch := -1
				if j < len(cls) && cls[j] != "0" && !strings.Contains(classes[cls[j]], "F_CLASS_IMPLICIT") {
					for _, p := range parts[3:] {
						if strings.HasPrefix(p, cls[j]) {
							ch, _ = strconv.Atoi(strings.TrimPrefix(p, cls[j]))
							break
						}
					}
				}
				fmt.Fprintf(&input, " %d", ch)
			}
			v := seed(e, sample)
			if sample == 2 {
				for _, o := range e.Operands {
					var raw int64
					for _, b := range o.Bits {
						for k := 0; k < b.Width; k++ {
							raw |= 1 << uint(b.ValueBit+k)
						}
					}
					if len(o.Names) > 0 {
						for n := len(o.Names) - 1; n >= 0; n-- {
							if o.Names[n] != "" {
								raw = int64(n)
								break
							}
						}
					} else if o.Signed {
						raw = -(1 << uint(o.Width()-1))
					}
					scale := o.Scale
					if scale == 0 {
						scale = 1
					}
					if len(o.Lookup) > 0 {
						raw = o.Lookup[raw]
					}
					v[o.Name] = raw*scale + o.Bias
					if o.Implicit {
						v[o.Name] = 0
					}
				}
				for _, constraint := range e.Constraints {
					if constraint.Kind == "ne" && constraint.Right == "" && v[constraint.Left] == 0 {
						v[constraint.Left] = 2
					}
				}
			}
			got, err := codec.Encode(e, v)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, got)
			caseIDs = append(caseIDs, fmt.Sprintf("%s/sample%d", e.ID, sample))
			ops := fields(m[7])
			seen := map[string]int64{}
			for j := 0; j < 16; j++ {
				val := int64(math.MinInt64)
				if j < len(ops) && ops[j] != "0" {
					name := ops[j]
					key := strings.ReplaceAll(strings.TrimSuffix(name, "dup"), "_CHK", "")
					if key == "RBD" {
						key = "RB"
					}
					if strings.Contains(defs[name], "ARC_OPERAND_DUPLICATE") {
						if n, ok := seen[key]; ok {
							val = n
						}
					} else {
						op := fmt.Sprintf("op%d", j)
						if n, ok := v[op]; ok {
							val = n
							for _, o := range e.Operands {
								if o.Name == op && o.Class == "SIMM3_5_S" && n == 7 {
									val = -1
								}
							}
							if name == "RRANGE_EL" {
								val = (13 << 16) | val
							}
						} else if strings.HasSuffix(name, "_EL") {
							for _, part := range parts[3:] {
								if part == op+"1" {
									switch name {
									case "R13_EL":
										val = 13
									case "FP_EL":
										val = 27
									case "BLINK_EL":
										val = 31
									case "PCL_EL":
										val = 63
									}
								}
							}
						}
						seen[key] = val
					}
				}
				fmt.Fprintf(&input, " %d", val)
			}
			input.WriteByte('\n')
		}
	}
	cmd := exec.Command(os.Getenv("ARC_NATIVE_ORACLE"))
	if dir := os.Getenv("ARC_REPORT_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, c.Architecture+"-native-input.txt"), []byte(input.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 2000 {
			out = out[len(out)-2000:]
		}
		t.Fatalf("native oracle: %v (last output) %s", err, out)
	}
	lines := strings.Fields(string(out))
	if len(lines) != len(want) {
		t.Fatalf("native oracle returned %d forms want %d", len(lines), len(want))
	}
	bad := 0
	for i, line := range lines {
		got, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want[i]) {
			bad++
			if bad < 20 {
				t.Errorf("native functions %s %s got %x want %x", caseIDs[i], "", got, want[i])
			}
		}
	}
	t.Logf("compiled binutils insertion functions: %d matched, %d mismatched", len(want)-bad, bad)
	if dir := os.Getenv("ARC_REPORT_DIR"); dir != "" {
		data, _ := json.MarshalIndent(map[string]any{"architecture": c.Architecture, "forms": len(c.Encodings), "samples": 3, "matched": len(want) - bad, "mismatched": bad}, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, c.Architecture+"-native-functions.json"), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGNUFixture(t *testing.T) {
	for _, arch := range []string{"arc32", "arc32be", "arc600", "arc600be", "arc700", "arc700be", "arcem", "arcembe"} {
		t.Run(arch, func(t *testing.T) {
			c := catalog(t, "testdata/binutils244-arc.tar", arch)
			if len(c.Unsupported) != 0 {
				t.Fatalf("source gaps: %v", c.Unsupported)
			}
			for _, e := range c.Encodings {
				single := &codec.Catalog{Architecture: arch, Encodings: []codec.Encoding{e}}
				roundtrip(t, single)
			}
			t.Logf("%s %d forms", arch, len(c.Encodings))
		})
	}
}

func TestResolvedARCv3AndNPSFixtures(t *testing.T) {
	for _, tc := range []struct {
		arch, path string
		count      int
	}{
		{"arc64", "testdata/arcv3-resolved.tar.gz", 62646},
		{"arc64be", "testdata/arcv3-resolved.tar.gz", 62646},
		{"arcv3-32", "testdata/arcv3-resolved.tar.gz", 33947},
		{"arcv3-32be", "testdata/arcv3-resolved.tar.gz", 33947},
		{"arcnps400", "testdata/binutils244-nps400.tar.gz", 38104},
		{"arcnps400be", "testdata/binutils244-nps400.tar.gz", 38104},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			c := catalog(t, tc.path, tc.arch)
			if len(c.Encodings) != tc.count || len(c.Unsupported) != 0 {
				t.Fatalf("%d forms, %v gaps", len(c.Encodings), c.Unsupported)
			}
			// Exercise every physical form without an expensive union text search.
			for _, e := range c.Encodings {
				single := &codec.Catalog{Architecture: tc.arch, Encodings: []codec.Encoding{e}}
				roundtrip(t, single)
			}
			if strings.HasPrefix(tc.arch, "arcnps400") {
				for _, text := range []string{"wkup 0, r0", "wkup 0, r15"} {
					bs, e := c.Assemble(text, 0)
					if e != nil || len(bs) == 0 {
						t.Fatal(text, e)
					}
					for _, b := range bs {
						d, e := c.Decode(b)
						if e != nil {
							t.Fatal(e)
						}
						if !strings.Contains(d.Format(0), strings.Split(text, ", ")[1]) {
							t.Fatal("wkup register lost", d.Format(0))
						}
					}
				}
			} else {
				for _, e := range c.Encodings {
					if strings.Contains(e.Mnemonic, ".aq") {
						b, err := codec.Encode(&e, seed(&e, 1))
						if err != nil {
							t.Fatal(err)
						}
						// C_AQ and C_RL share ownership of bit 15 in the low halfword.
						i := 3
						if strings.HasSuffix(tc.arch, "be") {
							i = 2
						}
						if b[i]&0x80 == 0 {
							t.Fatal("acquire flag was cleared", e.ID, b)
						}
						break
					}
				}
			}
		})
	}
}
func TestGNUCoreFamiliesAndFraming(t *testing.T) {
	c := catalog(t, "testdata/binutils244-arc.tar", "arc32")
	for _, text := range []string{"lp 100", "sr r1, [5]", "lr r2, [32]", "flag 2", "clri r1", "rtie", "enter_s [r13-r16, fp, blink]", "leave_s [r13, blink]", "mov_s r15, -1", "bbit0.t r1, r2, 100", "bbit0.t r1, r2, 0xffffff9c", "bbit0.t r1, r2, 0"} {
		b, err := c.Assemble(text, 0)
		if err != nil {
			t.Errorf("%s: %v", text, err)
			continue
		}
		for _, v := range b {
			d, err := c.Decode(v)
			if err != nil || d.Length != len(v) {
				t.Errorf("decode %s %x: %v", text, v, err)
				continue
			}
			round, err := c.Assemble(d.Format(0), 0)
			valid := false
			for _, x := range round {
				valid = valid || bytes.Equal(x, v)
			}
			if err != nil || !valid {
				t.Errorf("preferred %s -> %s %x %v", text, d.Format(0), v, err)
			}
		}
	}
	for _, text := range []string{"add_s r1, r2, r3", "mov_s r1, 305419896", "add r1, r2, r3", "add r1, r2, 305419896"} {
		bs, err := c.Assemble(text, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bs {
			stream := append(append([]byte{}, b...), 0x4a, 0x26, 0x00, 0x70)
			d, err := c.Decode(stream)
			if err != nil || d.Length != len(b) {
				t.Fatalf("framing %s %x: %+v %v", text, b, d, err)
			}
			for n := 0; n < len(b); n++ {
				if _, err := c.Decode(b[:n]); err == nil {
					t.Fatalf("truncated %s at %d decoded", text, n)
				}
			}
		}
	}
}
func TestRejectInvalidInput(t *testing.T) {
	for _, s := range []string{"", "{}", "[]", "not a source archive", "{\"!instanceof\":{\"Instruction\":[\"A\"]}} trailing"} {
		if _, err := Parse(strings.NewReader(s), "arc32"); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	c := catalog(t, "testdata/binutils244-arc.tar", "arc32")
	for _, s := range []string{"add r1, r2, r62", "add_s r6, r6, r1", "enter_s [r13-r27]", "bbit0 r1, r2, 3"} {
		if b, err := c.Assemble(s, 0); err == nil {
			t.Errorf("accepted %s %x", s, b)
		}
	}
}

func TestRegistersAndImmediateBoundaries(t *testing.T) {
	c := catalog(t, "testdata/binutils244-arc.tar", "arc32")
	for _, text := range []string{"add gp, fp, sp", "add r1, pcl, r2", "add_s r15, r12, r13", "mov_s r30, -1", "mov_s r1, 6", "mov_s r1, -1", "add r1, r1, -2048", "add r1, r1, 2047", "mov_s r1, 4294967295"} {
		bs, err := c.Assemble(text, 0)
		if err != nil {
			t.Errorf("%s: %v", text, err)
			continue
		}
		for _, b := range bs {
			d, err := c.Decode(b)
			if err != nil {
				t.Errorf("decode %s: %v", text, err)
				continue
			}
			round, err := c.Assemble(d.Format(0), 0)
			found := false
			for _, x := range round {
				found = found || bytes.Equal(x, b)
			}
			if err != nil || !found {
				t.Errorf("%s -> %s %x %v", text, d.Format(0), b, err)
			}
		}
	}
}

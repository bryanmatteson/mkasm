package mips

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/object"
)

func gnu16Sample(t *testing.T, e codec.Encoding) (map[string]int64, []byte) {
	t.Helper()
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(1)
		if o.Implicit {
			n = 0
		} else if len(o.Names) > 0 {
			n = -1
			for i, s := range o.Names {
				if s != "" {
					n = int64(i)
					break
				}
			}
			if n < 0 {
				t.Fatalf("empty operand domain %s %s", e.ID, o.Name)
			}
		} else if len(o.Lookup) > 0 {
			n = o.Lookup[1%len(o.Lookup)]
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		n = n*scale + o.Bias
		if o.BiasOperand != "" {
			factor := o.BiasScale
			if factor == 0 {
				factor = 1
			}
			n += factor * v[o.BiasOperand]
		}
		if o.Implicit {
			n = 0
		}
		v[o.Name] = n
	}
	for _, o := range e.Operands {
		if o.BiasOperand != "" && !o.Implicit {
			v[o.Name] = 1
		}
	}
	b, err := codec.Encode(&e, v)
	if err != nil {
		t.Fatalf("sample %s %+v: %v", e.ID, v, err)
	}
	return v, b
}

func TestGNU16EveryMachineRow(t *testing.T) {
	var src gnu16Corpus
	if err := json.Unmarshal(gnu16JSON, &src); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		t.Run(arch, func(t *testing.T) {
			c := compressedCatalog(t, arch)
			rows := map[int]bool{}
			type sample struct {
				e codec.Encoding
				b []byte
			}
			var samples []sample
			var queries strings.Builder
			order := "be"
			if strings.HasSuffix(arch, "el") {
				order = "le"
			}
			for _, e := range c.Encodings {
				if !strings.HasPrefix(e.ID, "GNU_MIPS16_ROW_") || strings.Contains(e.ID, "_numeric_literals") || e.AssemblyOnly {
					continue
				}
				var row int
				fmt.Sscanf(e.ID, "GNU_MIPS16_ROW_%d", &row)
				rows[row] = true
				v, b := gnu16Sample(t, e)
				d := codec.Decoded{Encoding: &e, Values: v, Length: len(b)}
				text := d.Format(0x1000)
				parsed, ok := codec.ParseOperands(&e, text, 0x1000)
				encoded, err := codec.Encode(&e, parsed)
				if !ok || err != nil || string(encoded) != string(b) {
					t.Fatalf("source row %s text %q %x: %v", e.ID, text, b, err)
				}
				samples = append(samples, sample{e, b})
				legacy := 0
				if has(e.Features, "NotMips16e2") {
					legacy = 1
				}
				fmt.Fprintf(&queries, "%s 1000 %x 0 %d\n", order, b, legacy)
			}
			for _, r := range src.Instructions {
				if !rows[r.Row] {
					t.Errorf("source row omitted: %d %s %s", r.Row, r.Name, r.Args)
				}
			}
			t.Logf("all %d GNU machine rows imported; %d physical representative configurations", len(rows), len(samples))
			oracle := os.Getenv("MKASM_MIPS16_DISASSEMBLER")
			if oracle == "" {
				t.Log("set MKASM_MIPS16_DISASSEMBLER to compile/run upstream disassembler comparisons")
				return
			}
			cmd := exec.Command(oracle)
			cmd.Stdin = strings.NewReader(queries.String())
			data, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("GNU disassembler: %v\n%s", err, data)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != len(samples) {
				t.Fatalf("GNU returned %d lines for %d samples", len(lines), len(samples))
			}
			failures := 0
			for i, line := range lines {
				j := strings.LastIndexByte(line, '\t')
				if j < 0 {
					t.Fatal(line)
				}
				text := strings.Join(strings.Fields(line[:j]), " ")
				size, err := strconv.Atoi(line[j+1:])
				if err != nil {
					t.Fatal(line)
				}
				s := samples[i]
				if strings.Contains(s.e.ID, "_ignored_bits") {
					if size != len(s.b) {
						t.Errorf("ignored fields %s %x: GNU length %d", s.e.ID, s.b, size)
						failures++
					}
					continue
				}
				// GNU displays the MIPS16 ISA marker in code addresses. This
				// codec's address APIs use physical byte addresses, consistently
				// with standard MIPS and microMIPS; clear only code-target bit 0.
				if s.e.FlowControl == "branch" || s.e.FlowControl == "conditional_branch" || s.e.FlowControl == "call" {
					text = regexp.MustCompile(`0x[0-9a-fA-F]+`).ReplaceAllStringFunc(text, func(s string) string { n, _ := strconv.ParseUint(s[2:], 16, 64); return fmt.Sprintf("0x%x", n&^1) })
				}
				// Restrict only by independently supplied physical bytes, not by
				// the expected source mnemonic or operand values. This retains
				// all competing decodings/aliases without quadratic text scans
				// across thousands of fixed register-list configurations.
				physical := codec.Catalog{}
				for _, e := range c.Encodings {
					if len(e.Mask) != len(s.b) {
						continue
					}
					match := true
					for p, m := range e.Mask {
						if s.b[p]&m != e.Value[p] {
							match = false
							break
						}
					}
					if match {
						physical.Encodings = append(physical.Encodings, e)
					}
				}
				encoded, err := physical.Assemble(text, 0x1000)
				if size != len(s.b) || err != nil || !containsBytes(encoded, s.b) {
					if failures < 20 {
						t.Errorf("%s %x: GNU %q size %d; assembly %x %v", s.e.ID, s.b, text, size, encoded, err)
					}
					failures++
				}
			}
			if failures != 0 {
				t.Fatalf("GNU oracle mismatches: %d/%d", failures, len(samples))
			}
		})
	}
}

func TestGNU16UpstreamOperandBoundaries(t *testing.T) {
	var src gnu16Corpus
	if err := json.Unmarshal(gnu16JSON, &src); err != nil {
		t.Fatal(err)
	}
	for ch, pair := range src.Operands {
		for _, d := range []gnu16Operand{pair.Short, pair.Extended} {
			for _, sample := range d.Samples {
				if got := gnu16Integer(d, uint64(sample[0])); got != sample[1] {
					t.Errorf("upstream insert/extract %s %+v: got %d want %d", ch, d, sample[0], sample[1])
				}
			}
		}
	}
}

func TestGNU16NamedFamilies(t *testing.T) {
	c := compressedCatalog(t, "mips16el")
	for _, text := range []string{"save 128, $ra, $s0-$s1", "restore $a0-$a3, 2040, $ra, $s0-$fp", "entry $a0-$a3, $s0-$s1, $ra", "exit $s0-$s1, $ra, $f0-$f1", "daddiu $v0, -32768", "dsll $v0, $v1, 63", "sew $v0", "ins $v0, $v1, 8, 24", "ext $v0, $v1, 0, 32", "ll $v0, -256($v1)", "dmt $v0", "copyw $v0, $v1, 496, 4", "asmacro 7, 31, 7, 7, 31, 7"} {
		b, err := c.Assemble(text, 0)
		if err != nil || len(b) == 0 {
			t.Errorf("missing family %q: %v", text, err)
			continue
		}
		for _, bytes := range b {
			d, err := c.Decode(bytes)
			if err != nil {
				t.Fatal(text, err)
			}
			round, err := c.Assemble(d.Format(0), 0)
			if err != nil || !containsBytes(round, bytes) {
				t.Errorf("%s %x -> %q: %v", text, bytes, d.Format(0), err)
			}
		}
	}
	for _, text := range []string{"save 2048, $ra", "save 7, $ra", "save $a0-$a3, 128, $a1-$a3", "entry $s0-$s2", "exit $a0", "dsll $v0, $v1, 64", "ins $v0, $v1, 8, 25", "copyw $v0, $v1, 512, 1", "copyw $v0, $v1, 0, 0"} {
		if b, err := c.Assemble(text, 0); err == nil && len(b) > 0 {
			t.Errorf("invalid domain %q: %x", text, b)
		}
	}
	if b, err := c.AssembleWithFeatures("save 128, $ra", 0, []string{"InMips16Mode"}); err == nil || len(b) > 0 {
		t.Fatal("MIPS16 I1 admits MIPS16e SAVE")
	}
	if b, err := c.AssembleWithFeatures("ins $v0, $v1, 8, 24", 0, []string{"InMips16Mode"}); err == nil || len(b) > 0 {
		t.Fatal("MIPS16 I1 admits MIPS16e2 INS")
	}
}

func TestGNU16ActualAssemblerCorpus(t *testing.T) {
	as, oracle := os.Getenv("MKASM_MIPS_AS"), os.Getenv("MKASM_MIPS16_DISASSEMBLER")
	if as == "" || oracle == "" {
		t.Skip("set MKASM_MIPS_AS and MKASM_MIPS16_DISASSEMBLER for actual GNU corpus")
	}
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		c := compressedCatalog(t, arch)
		for _, file := range []string{"mips16.s", "mips16e.s", "mips16e-64.s", "mips16e2.s", "mips16e2-copy.s", "save.s"} {
			t.Run(arch+"/"+file, func(t *testing.T) {
				source, err := os.ReadFile("testdata/gnu-gas/" + file)
				if err != nil {
					t.Fatal(err)
				}
				endian, order := "-EB", "be"
				if strings.HasSuffix(arch, "el") {
					endian, order = "-EL", "le"
				}
				cpu := "-mips64r2"
				if file == "mips16e2-copy.s" {
					cpu = "-march=interaptiv-mr2"
				}
				o, err := object.Assemble(context.Background(), string(source), object.Options{Executable: as, Kind: "gnu", Arguments: []string{endian, "-32", cpu, "-mips16", "-mmips16e2", "-mmt", "-O0"}})
				if err != nil {
					t.Fatal(err)
				}
				var code []byte
				for _, s := range o.Sections {
					if s.Name == ".text" {
						code = s.Data
					}
				}
				var queries strings.Builder
				for pos := 0; pos < len(code); pos += 2 {
					end := pos + 8
					if end > len(code) {
						end = len(code)
					}
					fmt.Fprintf(&queries, "%s %x %x\n", order, pos, code[pos:end])
				}
				cmd := exec.Command(oracle)
				cmd.Stdin = strings.NewReader(queries.String())
				data, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("GNU disassembler: %v\n%s", err, data)
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				if len(lines) != len(code)/2 {
					t.Fatalf("disassembler returned %d lines for %d bytes", len(lines), len(code))
				}
				count := 0
				for pos := 0; pos < len(code); {
					line := lines[pos/2]
					j := strings.LastIndexByte(line, '\t')
					if j < 0 {
						t.Fatal(line)
					}
					size, err := strconv.Atoi(line[j+1:])
					if err != nil {
						t.Fatal(line)
					}
					d, err := c.Decode(code[pos:])
					if err != nil || size != d.Length {
						t.Fatalf("at %#x %x: GNU %q length %d; decode %+v %v", pos, code[pos:pos+size], line, size, d, err)
					}
					physical := codec.Catalog{}
					for _, e := range c.Encodings {
						if len(e.Mask) != size {
							continue
						}
						match := true
						for p, m := range e.Mask {
							if code[pos+p]&m != e.Value[p] {
								match = false
								break
							}
						}
						if match {
							physical.Encodings = append(physical.Encodings, e)
						}
					}
					text := strings.Join(strings.Fields(line[:j]), " ")
					if d.Encoding.FlowControl == "branch" || d.Encoding.FlowControl == "conditional_branch" || d.Encoding.FlowControl == "call" {
						text = regexp.MustCompile(`0x[0-9a-fA-F]+`).ReplaceAllStringFunc(text, func(s string) string {
							n, _ := strconv.ParseUint(s[2:], 16, 64)
							return fmt.Sprintf("0x%x", n&0xfffffffe)
						})
					}
					encoded, err := physical.Assemble(text, uint64(pos))
					if err != nil || !containsBytes(encoded, code[pos:pos+size]) {
						t.Fatalf("at %#x %x: GNU %q, got %x %v", pos, code[pos:pos+size], text, encoded, err)
					}
					values, ok := codec.ParseOperands(d.Encoding, d.Format(uint64(pos)), uint64(pos))
					round, err := codec.Encode(d.Encoding, values)
					if !ok || err != nil || string(round) != string(code[pos:pos+size]) {
						t.Fatalf("canonical at %#x %q: %x %v", pos, d.Format(uint64(pos)), round, err)
					}
					pos += size
					count++
				}
				t.Logf("actual GNU assembly/disassembly: %d bytes, %d decoded instructions", len(code), count)
			})
		}
	}
}

func TestGNU16SourceExport(t *testing.T) {
	if exporter := os.Getenv("MKASM_MIPS16_EXPORTER"); exporter != "" {
		got, err := exec.Command(exporter).Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(gnu16JSON) {
			t.Fatal("compiled original GNU operand export differs from retained fixture")
		}
	}
	var src gnu16Corpus
	if err := json.Unmarshal(gnu16JSON, &src); err != nil {
		t.Fatal(err)
	}
	if len(src.Instructions) != 221 || len(src.Operands) != 59 {
		t.Fatalf("unexpected source coverage: %d rows, %d operand descriptors", len(src.Instructions), len(src.Operands))
	}
}

func TestGNU16SourceEffects(t *testing.T) {
	c := compressedCatalog(t, "mips16")
	for _, row := range []struct {
		text, name  string
		read, write bool
	}{
		{"addiu $s0, $gp, 4", "$gp", true, false},
		{"save 128, $ra, $s0-$s1", "$s1", true, false},
		{"restore 128, $ra, $s0-$s1", "$s1", false, true},
	} {
		found := false
		for _, e := range c.Encodings {
			if !strings.HasPrefix(e.ID, "GNU_MIPS16_ROW_") {
				continue
			}
			values, ok := codec.ParseOperands(&e, row.text, 0)
			if !ok {
				continue
			}
			if _, err := codec.Encode(&e, values); err != nil {
				continue
			}
			for _, effect := range e.Effects.Registers {
				if effect.Name == row.name && effect.Read == row.read && effect.Write == row.write {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("source effect lost for %q: %s", row.text, row.name)
		}
	}
}

func TestGNU16IgnoredExtendFeatureGate(t *testing.T) {
	c := compressedCatalog(t, "mips16")
	b := []byte{0xf0, 0x41, 0x30, 0x00}
	legacy, err := c.DecodeWithFeatures(b, []string{"InMips16Mode", "NotMips16e2"})
	if err != nil || legacy.Length != 4 || !strings.Contains(legacy.Format(0), "encoding_bits:") {
		t.Fatalf("legacy ignored payload: %s %+v %v", legacy.Encoding.ID, legacy, err)
	}
	e2, err := c.DecodeWithFeatures(b, []string{"InMips16Mode", "HasMips16e2"})
	if err != nil || e2.Length != 2 || e2.Encoding.Mnemonic != "extend" {
		t.Fatalf("MIPS16e2 reserved payload: %s %+v %v", e2.Encoding.ID, e2, err)
	}
	text := legacy.Format(0)
	if encoded, err := c.AssembleWithFeatures(text, 0, []string{"InMips16Mode", "NotMips16e2"}); err != nil || !containsBytes(encoded, b) {
		t.Fatalf("legacy exact text %q: %x %v", text, encoded, err)
	}
}

// LLVM's MIPS16 compiler tables contain layout and operand-class errors that
// cannot be detected by round-tripping through the same source description.
// Check every retained LLVM form against the separately imported GNU machine
// model, whose complete rows are compared with the compiled upstream decoder.
func TestGNU16LLVMFormsAgree(t *testing.T) {
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		c := compressedCatalog(t, arch)
		gnu := codec.Catalog{}
		for _, e := range c.Encodings {
			if strings.HasPrefix(e.ID, "GNU_MIPS16_ROW_") {
				gnu.Encodings = append(gnu.Encodings, e)
			}
		}
		for _, e := range c.Encodings {
			if strings.HasPrefix(e.ID, "GNU_MIPS16_ROW_") || e.AssemblyOnly {
				continue
			}
			for _, seed := range []byte{0, 1, 0x80, 0x55, 255} {
				b := append([]byte(nil), e.Value...)
				for i := range b {
					b[i] |= seed &^ e.Mask[i]
				}
				only := codec.Catalog{Encodings: []codec.Encoding{e}}
				d, err := only.Decode(b)
				if err != nil {
					continue
				}
				text := d.Format(0x1000)
				assembled, err := gnu.Assemble(text, 0x1000)
				if err != nil || !containsBytes(assembled, b) {
					t.Errorf("%s %s seed %x %x %q: GNU forms %x %v", arch, e.ID, seed, b, text, assembled, err)
				}
			}
		}
	}
}

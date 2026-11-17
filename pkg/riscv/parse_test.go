package riscv

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func fixture(t *testing.T, arch string, files map[string]string) *codec.Catalog {
	t.Helper()
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	tw := tar.NewWriter(z)
	for n, s := range files {
		if e := tw.WriteHeader(&tar.Header{Name: "upstream/" + n, Mode: 0600, Size: int64(len(s))}); e != nil {
			t.Fatal(e)
		}
		tw.Write([]byte(s))
	}
	tw.Close()
	z.Close()
	c, e := Parse(&buf, arch)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestImportRegularPseudoAndImport(t *testing.T) {
	c := fixture(t, "riscv32", map[string]string{"arg_lut.csv": "\"rd\",11,7\n\"rs1\",19,15\n\"rs2\",24,20\n\"imm12\",31,20\n", "extensions/rv_i": "addi rd rs1 imm12 14..12=0 6..2=4 1..0=3\n$pseudo_op rv_i::addi mv rd rs1 31..20=0 14..12=0 6..2=4 1..0=3\n", "extensions/rv_extra": "$import rv_i::addi\n", "extensions/rv64_i": "addw rd rs1 rs2 31..25=0 14..12=0 6..2=0xe 1..0=3\n"})
	if len(c.Encodings) != 3 {
		t.Fatalf("encodings=%d", len(c.Encodings))
	}
	b, e := c.Encode("rv_i::addi", map[string]int64{"rd": 10, "rs1": 11, "imm": -17})
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", b) != "1385f5fe" {
		t.Fatalf("addi=%x", b)
	}
	d, e := c.Decode(b)
	if e != nil || d.Values["imm"] != -17 {
		t.Fatalf("decode=%+v %v", d, e)
	}
	for _, text := range []string{"addi x10, x11, -17", "addi a0, a1, -17"} {
		bs, e := c.Assemble(text, 0)
		if e != nil || !bytes.Equal(bs[0], b) {
			t.Fatalf("assemble %q: %x %v", text, bs, e)
		}
	}
}
func upstream(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	dir := os.Getenv("RISCV_OPCODES_DIR")
	if dir == "" {
		t.Skip("set RISCV_OPCODES_DIR to validate the real upstream checkout")
	}
	c, e := ParseDirectory(dir, arch)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestUpstreamCorpus(t *testing.T) {
	for _, arch := range []string{"riscv32", "riscv64"} {
		t.Run(arch, func(t *testing.T) {
			c := upstream(t, arch)
			t.Logf("%s imported %d encodings", arch, len(c.Encodings))
			source, variants := 0, 0
			for _, e := range c.Encodings {
				if strings.Contains(e.ID, "/order") || strings.Contains(e.ID, "/dyn") || strings.Contains(e.ID, "/standard") || strings.Contains(e.ID, "/default") || strings.Contains(e.ID, "/zero") || strings.Contains(e.ID, "/nf") || strings.Contains(e.ID, "/vm") || strings.Contains(e.ID, "/syntax") || strings.Contains(e.ID, "/rlist") {
					variants++
				} else {
					source++
				}
			}
			for _, u := range c.Unsupported {
				t.Logf("unsupported %s: %s", u.ID, u.Reason)
			}
			if len(c.Unsupported) != 0 {
				t.Fatalf("upstream source coverage has %d unsupported definitions", len(c.Unsupported))
			}
			t.Logf("source=%d assembly variants=%d", source, variants)
			for i := range c.Encodings {
				e := &c.Encodings[i]
				values := map[string]int64{}
				for _, o := range e.Operands {
					scale := o.Scale
					if scale == 0 {
						scale = 1
					}
					n := 0
					for n < len(o.Names) && o.Names[n] == "" {
						n++
					}
					values[o.Name] = int64(n)*scale + o.Bias
				}
				for _, ct := range e.Constraints {
					if ct.Kind == "ne" && values[ct.Left] == 0 {
						for _, o := range e.Operands {
							if o.Name == ct.Left {
								scale := o.Scale
								if scale == 0 {
									scale = 1
								}
								values[ct.Left] = scale
							}
						}
					}
				}
				b, err := c.Encode(e.ID, values)
				if err != nil {
					t.Fatalf("seed %s: %v", e.ID, err)
				}
				d, err := c.Decode(b)
				if err != nil {
					t.Fatalf("decode %s %x: %v", e.ID, b, err)
				}
				round, err := c.Encode(d.Encoding.ID, d.Values)
				if err != nil || !bytes.Equal(round, b) {
					t.Fatalf("byte roundtrip %s: %x %v", e.ID, round, err)
				}
				text := (&codec.Decoded{Encoding: e, Values: values, Length: len(b)}).Format(0x1000)
				assembled, err := c.Assemble(text, 0x1000)
				if err != nil {
					t.Fatalf("text roundtrip %s %q: %v", e.ID, text, err)
				}
				found := false
				for _, candidate := range assembled {
					if bytes.Equal(candidate, b) {
						found = true
					}
				}
				if !found {
					t.Fatalf("text bytes %s %q got %x want %x", e.ID, text, assembled, b)
				}
			}
			if dir := os.Getenv("RISCV_REPORT_DIR"); dir != "" {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				report := map[string]any{"architecture": arch, "source_encodings": source, "assembly_variants": variants, "total_encodings": len(c.Encodings), "unsupported": c.Unsupported}
				data, _ := json.MarshalIndent(report, "", "  ")
				if err := os.WriteFile(filepath.Join(dir, arch+"-coverage.json"), data, 0644); err != nil {
					t.Fatal(err)
				}
				if err := c.GenerateRust(filepath.Join(dir, arch+"-rust")); err != nil {
					t.Fatal(err)
				}
			}
			if len(c.Encodings) < 1000 {
				t.Fatalf("unexpectedly small corpus: %d", len(c.Encodings))
			}
		})
	}
}

var llvmEncoding = regexp.MustCompile(`encoding: \[([^]]+)\]`)

func TestLLVMParity(t *testing.T) {
	llvm := os.Getenv("LLVM_MC")
	if llvm == "" {
		llvm = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	if _, e := os.Stat(llvm); e != nil {
		t.Skip("LLVM llvm-mc unavailable")
	}
	for _, arch := range []string{"riscv32", "riscv64"} {
		t.Run(arch, func(t *testing.T) {
			c := upstream(t, arch)
			cases := []string{"add x10, x11, x12", "addi a0, a1, -17", "sw a0, -20(a1)", "lw a0, 124(a1)", "lui a0, 74565", "jalr ra, -16(a0)", "mul a0, a1, a2", "amoadd.w.aqrl a0, a1, (a2)", "lr.w a0, (a1)", "fence rw, rw", "fence.tso", "fence", "csrrwi a0, mstatus, 3", "csrw mstatus, a0", "fadd.s fa0, fa1, fa2", "vadd.vv v8, v10, v12", "vadd.vv v8, v10, v12, v0.t", "vfadd.vf v8, v10, fa0", "vle32.v v8, (a0)", "vse32.v v8, (a0), v0.t", "vlseg2e32.v v8, (a0)", "vluxseg2ei32.v v8, (a0), v12", "vsetvl a0, a1, a2", "c.lbu a0, 3(a1)", "c.lhu a0, 2(a1)", "c.nop", "vsetvli a0, a1, e32, m1, ta, ma", "vsetivli a0, 3, e16, mf2, tu, mu", "vmerge.vvm v8, v10, v12, v0", "fli.s fa0, 1.0", "fcvtmod.w.d a0, fa1, rtz", "cm.push {ra,s0-s3}, -48", "cm.pop {ra,s0-s3}, 48", "cm.mvsa01 s0, s1", "beq a0, a1, -2048", "bgt a0, a1, 2046", "beqz a0, -128", "jal ra, -524288", "c.j -1024", "c.beqz a0, -128", "csrrw a0, 0x300, a1", "fadd.s fa0, fa1, fa2, rne", "fcvt.w.s a0, fa1, rtz", "fmv.s fa0, fa1", "c.addi s0, -17", "c.lw a0, 124(a1)", "c.sw a0, 124(a1)", "c.lwsp a0, 252(sp)", "c.swsp a0, 252(sp)", "c.addi4spn a0, sp, 1020", "c.addi16sp sp, -512", "c.mv a0, a1", "c.andi a0, -17", "c.slli a0, 13", "c.li a0, -17", "c.lui a0, 1", "c.lui a0, 1048575"}
			if arch == "riscv64" {
				cases = append(cases, "addw a0, a1, a2", "slli a0, a1, 47", "ld a0, -16(a1)", "c.ld a0, 248(a1)", "c.sd a0, 248(a1)", "c.ldsp a0, 504(sp)", "c.sdsp a0, 504(sp)")
			}
			for _, text := range cases {
				t.Run(text, func(t *testing.T) {
					cmd := exec.Command(llvm, "-triple="+arch, "-mattr=+m,+a,+f,+d,+c,+zicsr,+v,+zcb,+zfa", "-show-encoding")
					option := ".option norvc\n"
					if strings.HasPrefix(text, "c.") {
						option = ".option rvc\n"
					}
					if strings.HasPrefix(text, "cm.") {
						cmd = exec.Command(llvm, "-triple="+arch, "-mattr=+m,+a,+c,+zcmp", "-show-encoding")
						option = ".option rvc\n"
					}
					cmd.Stdin = strings.NewReader(option + text + "\n")
					out, e := cmd.CombinedOutput()
					if e != nil {
						t.Fatalf("LLVM: %v\n%s", e, out)
					}
					match := llvmEncoding.FindSubmatch(out)
					if len(match) != 2 {
						t.Fatalf("no LLVM encoding: %s", out)
					}
					var want []byte
					for _, n := range strings.Split(string(match[1]), ",") {
						v, e := strconv.ParseUint(strings.TrimSpace(n), 0, 8)
						if e != nil {
							t.Fatal(e)
						}
						want = append(want, byte(v))
					}
					got, e := c.Assemble(text, 0)
					if e != nil {
						t.Fatal(e)
					}
					for _, b := range got {
						if bytes.Equal(b, want) {
							d, e := c.Decode(want)
							if e != nil {
								t.Fatal(e)
							}
							round, e := c.Encode(d.Encoding.ID, d.Values)
							if e != nil || !bytes.Equal(round, want) {
								t.Fatalf("roundtrip %x %v", round, e)
							}
							return
						}
					}
					t.Fatalf("bytes=%x want=%x", got, want)
				})
			}
		})
	}
}

func TestSplitImmediateAndRegisterLegality(t *testing.T) {
	lut := map[string]field{"rs1": {19, 15}, "rs2": {24, 20}, "bimm12hi": {31, 25}, "bimm12lo": {11, 7}, "rd_rs1_n0": {11, 7}, "c_nzimm6lo": {6, 2}, "c_nzimm6hi": {12, 12}}
	branch, err := makeEncoding(definition{file: "extensions/rv_i", name: "beq", args: strings.Fields("bimm12hi rs1 rs2 bimm12lo 14..12=0 6..2=0x18 1..0=3")}, lut)
	if err != nil {
		t.Fatal(err)
	}
	branch.ID = "beq"
	caddi, err := makeEncoding(definition{file: "extensions/rv_c", name: "c.addi", args: strings.Fields("rd_rs1_n0 c_nzimm6lo c_nzimm6hi 1..0=1 15..13=0")}, lut)
	if err != nil {
		t.Fatal(err)
	}
	caddi.ID = "c.addi"
	c, err := codec.NewCatalog("riscv32", "unit", []codec.Encoding{branch, caddi})
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{-4096, -2048, -2, 0, 2, 2046, 4094} {
		b, err := c.Encode("beq", map[string]int64{"rs1": 10, "rs2": 11, "offset": offset})
		if err != nil {
			t.Fatal(err)
		}
		d, err := c.Decode(b)
		if err != nil || d.Values["offset"] != offset {
			t.Fatalf("offset %d: %+v %v", offset, d, err)
		}
	}
	for _, offset := range []int64{-4098, -3, 1, 4096} {
		if _, err := c.Encode("beq", map[string]int64{"rs1": 10, "rs2": 11, "offset": offset}); err == nil {
			t.Fatalf("accepted bad offset %d", offset)
		}
	}
	for _, values := range []map[string]int64{{"rd_rs1_n0": 0, "imm": 1}, {"rd_rs1_n0": 10, "imm": 0}, {"rd_rs1_n0": 32, "imm": 1}, {"rd_rs1_n0": 10, "imm": 32}} {
		if _, err := c.Encode("c.addi", values); err == nil {
			t.Fatalf("accepted illegal c.addi %v", values)
		}
	}
	if _, err := c.Encode("c.addi", map[string]int64{"rd_rs1_n0": 10, "imm": -32}); err != nil {
		t.Fatal(err)
	}
}
func TestRejectMalformedSources(t *testing.T) {
	for _, tc := range []struct{ name, body string }{{"unknown", "$unknown\n"}, {"missing import", "$import rv_missing::add\n"}, {"bad range", "add 32..0=1\n"}, {"overlap", "add 31..0=0 1..0=3\n"}, {"unknown operand", "add mystery 31..0=0\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFiles(map[string][]byte{"arg_lut.csv": []byte("\"rd\",11,7\n"), "extensions/rv_i": []byte(tc.body)}, "riscv64")
			if err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	if _, err := Parse(strings.NewReader("not an opcode archive"), "riscv64"); err == nil {
		t.Fatal("accepted malformed archive")
	}
}
func TestTiedAliasRejectsUnequalRegisterBits(t *testing.T) {
	lut := map[string]field{"rd": {11, 7}, "rs1": {19, 15}, "rs2": {24, 20}}
	e, err := makeEncoding(definition{file: "extensions/rv_f", name: "fmv.s", args: strings.Fields("rd rs1 rs2=rs1 31..25=0x10 14..12=0 6..0=0x53")}, lut)
	if err != nil {
		t.Fatal(err)
	}
	e.ID = "fmv.s"
	c, err := codec.NewCatalog("riscv64", "unit", []codec.Encoding{e})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode("fmv.s", map[string]int64{"rd": 10, "rs1": 11})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decode(b); err != nil {
		t.Fatal(err)
	}
	b[2] ^= 0x10
	if _, err := c.Decode(b); err == nil {
		t.Fatal("unequal source fields decoded as tied alias")
	}
}

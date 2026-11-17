package loongarch

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func fixture(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	f, err := os.Open("testdata/llvm-loongarch.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unsupported) != 0 {
		t.Fatalf("unsupported fixture records: %+v", c.Unsupported)
	}
	return c
}

// Bytes were independently assembled with LLVM 22.1.8 llvm-mc. The fixture is
// a field-pruned snapshot of the corresponding llvmorg-22.1.8 dump-json records.
func TestLLVMEncodings(t *testing.T) {
	c := fixture(t, "loongarch64")
	tests := []struct {
		text, want string
		address    uint64
	}{
		{"add.w $a0, $a1, $a2", "a4181000", 0},
		{"addi.d $a0, $a1, -32", "a480ff02", 0},
		{"b 0xffc", "ffffff53", 0x1000},
		{"beqz $a0, 0xbfffc", "9efcff43", 0x100000},
		{"stptr.d $a0, $sp, -16", "64f0ff27", 0},
		{"alsl.w $a0, $a1, $a2, 4", "a4980500", 0},
		{"fadd.s $fa0, $fa1, $fa2", "20880001", 0},
		{"vadd.b $vr0, $vr1, $vr2", "20080a70", 0},
		{"xvadd.b $xr0, $xr1, $xr2", "20080a74", 0},
		{"nop", "00004003", 0},
		{"ret", "2000004c", 0},
		{"move $a0, $a1", "a4001500", 0},
		{"amadd.w $a0, $a1, $a2, 0", "c4146138", 0},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			all, err := c.Assemble(tt.text, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			if len(all) == 0 {
				t.Fatal("no encoding")
			}
			for _, got := range all {
				if !bytes.Equal(got, want) {
					t.Fatalf("got %x want %x", got, want)
				}
			}
			d, err := c.Decode(want)
			if err != nil {
				t.Fatal(err)
			}
			reassembled, err := c.Assemble(d.Format(tt.address), tt.address)
			if err != nil {
				t.Fatalf("formatted %q: %v", d.Format(tt.address), err)
			}
			found := false
			for _, b := range reassembled {
				found = found || bytes.Equal(b, want)
			}
			if !found {
				t.Fatalf("formatted %q lost bytes %x", d.Format(tt.address), want)
			}
		})
	}
}

func TestWidthAndValidation(t *testing.T) {
	la32 := fixture(t, "loongarch32")
	la64 := fixture(t, "loongarch64")
	if _, err := la32.Assemble("add.d $r4, $r5, $r6", 0); err == nil {
		t.Fatal("LA32 accepted add.d")
	}
	if _, err := la64.Assemble("add.d $r4, $r5, $r6", 0); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"addi.d $r4, $r5, 2048", "add.w $r32, $r0, $r0", "stptr.d $r4, $r3, 3",
		"alsl.w $r4, $r5, $r6, 0", "alsl.w $r4, $r5, $r6, 5", "b 3",
		"bstrins.w $r4, $r5, 2, 3", "amadd.w $r4, $r4, $r5", "amadd.w $r4, $r5, $r4",
		"csrxchg $r4, $r0, 1", "csrxchg $r4, $ra, 1",
		"amadd.w $r4, $r5, $r6, 4",
	} {
		if _, err := la64.Assemble(text, 0); err == nil {
			t.Errorf("accepted invalid %q", text)
		}
	}
	if _, err := la64.Assemble("amadd.w $zero, $zero, $zero", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(strings.NewReader(`{}`), "loongarch128"); err == nil {
		t.Fatal("accepted unsupported architecture")
	}
}

func TestFullLLVMCorpus(t *testing.T) {
	path := os.Getenv("MKASM_LOONGARCH_JSON")
	if path == "" {
		t.Skip("set MKASM_LOONGARCH_JSON to llvm-tblgen --dump-json output")
	}
	for _, arch := range []string{"loongarch32", "loongarch64"} {
		t.Run(arch, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			c, err := Parse(f, arch)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Encodings) < 1500 {
				t.Fatalf("unexpected corpus size %d", len(c.Encodings))
			}
			if len(c.Unsupported) > 0 {
				t.Fatalf("unsupported concrete records: %+v", c.Unsupported)
			}
			t.Logf("%s imported %d encodings", arch, len(c.Encodings))
			verifyFullLLVMParity(t, c, arch)
		})
	}
}

func verifyFullLLVMParity(t *testing.T, c *codec.Catalog, arch string) {
	t.Helper()
	tool := os.Getenv("LLVM_MC")
	if tool == "" {
		tool = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	if _, err := os.Stat(tool); err != nil {
		t.Skip("LLVM_MC not available")
	}
	var lines []string
	var want [][]byte
	for _, enc := range c.Encodings {
		values := make(map[string]int64)
		text := enc.Syntax
		for i, op := range enc.Operands {
			n := int64(i + 4)
			if op.Kind == "register" {
				if int(n) >= len(op.Names) {
					n = 1
				}
			} else {
				n = 1
				if strings.HasPrefix(op.Name, "msb") {
					n = 4
				}
				scale := op.Scale
				if scale == 0 {
					scale = 1
				}
				n = n*scale + op.Bias
			}
			values[op.Name] = n
			spelling := strconv.FormatInt(n, 10)
			if op.Kind == "register" {
				spelling = op.Names[n]
			}
			text = strings.ReplaceAll(text, "{"+op.Name+"}", spelling)
		}
		b, err := c.Encode(enc.ID, values)
		if err != nil {
			t.Fatalf("%s sample: %v", enc.ID, err)
		}
		lines = append(lines, text)
		want = append(want, b)
	}
	cmd := exec.Command(tool, "--triple="+arch, "--mattr=+32s,+f,+d,+lsx,+lasx,+lbt,+lvz,+lam-bh,+lamcas,+frecipe,+scq", "--show-encoding")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("llvm-mc %s: %v\n%s", arch, err, out)
	}
	matches := regexp.MustCompile(`encoding: \[([^\]]+)\]`).FindAllStringSubmatch(string(out), -1)
	if len(matches) != len(lines) {
		t.Fatalf("%s: LLVM emitted %d encodings for %d records", arch, len(matches), len(lines))
	}
	for i, match := range matches {
		var got []byte
		for _, p := range strings.Split(match[1], ",") {
			b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(p), "0x"))
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, b...)
		}
		if !bytes.Equal(got, want[i]) {
			t.Errorf("%s %s: codec %x LLVM %x", c.Encodings[i].ID, lines[i], want[i], got)
		}
	}
	t.Log(fmt.Sprintf("%s: all %d imported encodings match independent LLVM assembler", arch, len(lines)))
}

func TestIndependentLLVMAssembler(t *testing.T) {
	tool := os.Getenv("LLVM_MC")
	if tool == "" {
		tool = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	if _, err := os.Stat(tool); err != nil {
		t.Skip("LLVM_MC not available")
	}
	c := fixture(t, "loongarch64")
	lines := []string{"add.w $r4, $r5, $r6", "addi.d $r4, $r5, -32", "stptr.d $r4, $r3, -16", "alsl.w $r4, $r5, $r6, 4", "fadd.s $f0, $f1, $f2", "vadd.b $vr0, $vr1, $vr2", "xvadd.b $xr0, $xr1, $xr2", "nop", "ret", "move $r4, $r5"}
	cmd := exec.Command(tool, "--triple=loongarch64", "--mattr=+lsx,+lasx", "--show-encoding")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("llvm-mc: %v\n%s", err, out)
	}
	r := regexp.MustCompile(`encoding: \[([^\]]+)\]`)
	matches := r.FindAllStringSubmatch(string(out), -1)
	if len(matches) != len(lines) {
		t.Fatalf("unexpected LLVM output %s", out)
	}
	for i, line := range lines {
		var want []byte
		for _, p := range strings.Split(matches[i][1], ",") {
			b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(p), "0x"))
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, b...)
		}
		got, err := c.Assemble(line, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range got {
			if !bytes.Equal(b, want) {
				t.Errorf("%s: %x != LLVM %x", line, b, want)
			}
		}
	}
}

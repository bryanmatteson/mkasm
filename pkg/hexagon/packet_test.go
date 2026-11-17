package hexagon

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func llvmBytes(t *testing.T, text string) []byte {
	t.Helper()
	tool := "/opt/homebrew/opt/llvm/bin/llvm-mc"
	if _, err := os.Stat(tool); err != nil {
		t.Skip("llvm-mc unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "input.o")
	cmd := exec.Command(tool, "-triple", "hexagon", "-mcpu=hexagonv79", "-mattr=+hvxv79,+hvx-length128b", "-filetype=obj", "-o", path)
	cmd.Stdin = bytes.NewBufferString(".text\n" + text + "\n")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("LLVM %s: %v\n%s", text, err, b)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := f.Section(".text").Data()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestPacketsLLVM(t *testing.T) {
	c := fixture(t)
	for _, text := range []string{
		"{\nr0 = #17\n}",
		"{\nr16 = add(r16,#1) ; r17 = add(r17,#2)\n}",
		"{\nr17:16 = combine(#0,#1) ; r2 = add(r2,#3)\n}",
		"{\nv0:1 = vcombine(v2,v3)\nvmem(r0+#0) = v0.new\n}",
		"{\nr0 = ##-1234567\n}",
		"{\nv1:0 = vcombine(v2,v3)\nvmem(r0+#0) = v1.new\n}",
		"{\nr0 = #1\nr1 = #2\nr2 = #3\n}:endloop0:endloop1",
		"{\nr0 = ##305419896\n}",
		"{\nr0 = add(r1,r2)\nr3 = xor(r4,r5)\n}",
		"{\nr0 = #1\nmemw(r1+#0) = r0.new\n}",
		"{\nr0 = add(r0,#1) ; r1 = add(r1,#2)\n}",
	} {
		t.Run(text, func(t *testing.T) {
			want := llvmBytes(t, text)
			p, n, err := c.DecodePacket(want, 0, nil)
			if err != nil {
				t.Fatalf("decode %x: %v", want, err)
			}
			if n != len(want) {
				t.Fatalf("length %d/%d", n, len(want))
			}
			got, err := c.EncodePacket(p, 0, nil)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("reencode %x != %x: %v\n%+v", got, want, err, p)
			}
			formatted := c.FormatPacket(p, 0)
			options, err := c.AssemblePacket(formatted, 0, nil)
			found := false
			for _, b := range options {
				found = found || bytes.Equal(b, want)
			}
			if err != nil || !found {
				t.Fatalf("text %s: %v %x wanted %x", formatted, err, options, want)
			}
		})
	}
}

func TestPacketRelativeBranchObject(t *testing.T) {
	c := fixture(t)
	object := llvmBytes(t, ".org 4096\n{\njump target\n}\n.space 60\ntarget:\n{\nnop\n}")
	p, n, err := c.DecodePacket(object[4096:], 4096, nil)
	if err != nil || n != 4 {
		t.Fatalf("branch decode %d %v", n, err)
	}
	text := c.FormatPacket(p, 4096)
	if !strings.Contains(text, "0x1040") {
		t.Fatalf("packet-relative target: %s", text)
	}
	options, err := c.AssemblePacket(text, 4096, nil)
	found := false
	for _, b := range options {
		found = found || bytes.Equal(b, object[4096:4100])
	}
	if err != nil || !found {
		t.Fatalf("branch assembly %s: %v %x", text, err, options)
	}
}

func TestLLVMIntegerSpelling(t *testing.T) {
	c := fixture(t)
	text := "{\nr0 = #0xffffffff\n}"
	want := llvmBytes(t, text)
	out, err := c.AssemblePacket(text, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range out {
		found = found || bytes.Equal(b, want)
	}
	if !found {
		t.Fatalf("32-bit signed spelling: %x != %x", out, want)
	}
}

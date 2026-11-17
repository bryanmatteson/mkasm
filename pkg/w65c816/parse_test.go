package w65c816

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func load(t *testing.T) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/opc65816.c")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, "w65c816")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestFullOpcodeContexts(t *testing.T) {
	c := load(t)
	for _, p := range []string{"m8x8", "m8x16", "m16x8", "m16x16"} {
		for op := 0; op < 256; op++ {
			d, e := c.DecodeWithFeatures([]byte{byte(op), 0x21, 0x43, 0x65}, c.FeatureSets[p])
			if e != nil {
				t.Fatalf("%s %02x %v", p, op, e)
			}
			b, e := c.Encode(d.Encoding.ID, d.Values)
			if e != nil || !bytes.Equal(b, []byte{byte(op), 0x21, 0x43, 0x65}[:d.Length]) {
				t.Fatalf("%s %02x: %x %v", p, op, b, e)
			}
			text := d.Format(0x12fffe)
			bb, e := c.AssembleWithFeatures(text, 0x12fffe, c.FeatureSets[p])
			if e != nil || !contains(bb, b) {
				t.Fatalf("%s %02x %s %v", p, op, text, e)
			}
		}
	}
	for _, op := range []byte{0, 2, 0x42} {
		d, e := c.Decode([]byte{op, 17})
		if e != nil || d.Length != 2 {
			t.Fatal(d, e)
		}
	}
	d, e := c.Decode([]byte{0x22, 1, 2, 3})
	if e != nil || d.Length != 4 {
		t.Fatal(d, e)
	}
}
func contains(all [][]byte, b []byte) bool {
	for _, a := range all {
		if bytes.Equal(a, b) {
			return true
		}
	}
	return false
}
func TestWidthAndBankContext(t *testing.T) {
	c := load(t)
	x := ExecutionContext{PC: 0x12fffe, Accumulator8: true, Index8: true}
	d, e := c.DecodeWithContext([]byte{0x80, 1}, x)
	if e != nil {
		t.Fatal(e)
	}
	v, ok := d.BranchTarget(uint64(x.PC))
	if !ok || v != 0x120001 {
		t.Fatalf("bank carry: %x", v)
	}
	if _, e = d.Relocated(uint64(x.PC), 0x130000); e == nil {
		t.Fatal("cross-bank short branch accepted")
	}
	rep, e := c.DecodeWithContext([]byte{0xc2, 0x30}, x)
	if e != nil {
		t.Fatal(e)
	}
	x, e = x.Next(rep)
	if e != nil || x.Profile() != "m16x16" || x.PC != 0x120000 {
		t.Fatal(x, e)
	}
	if d, e = c.DecodeWithContext([]byte{0xa9, 0x34, 0x12}, x); e != nil || d.Length != 3 {
		t.Fatal(d, e)
	}
	plp, e := c.Decode([]byte{0x28})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.Next(plp); e == nil {
		t.Fatal("guessed restored M/X state")
	}
}

func TestCC65FullCorpusOracle(t *testing.T) {
	bin := os.Getenv("MKASM_MOS6502_CC65")
	if bin == "" {
		t.Skip("set MKASM_MOS6502_CC65 to built cc65 bin directory")
	}
	c := load(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "link.cfg")
	if e := os.WriteFile(cfg, []byte("MEMORY { ROM:start=$1000,size=$10000,file=%O; } SEGMENTS { CODE:load=ROM,type=ro; }"), 0644); e != nil {
		t.Fatal(e)
	}
	var source strings.Builder
	source.WriteString(".setcpu \"65816\"\n.segment \"CODE\"\n")
	var expected []byte
	hex := regexp.MustCompile(`0x([0-9a-f]+)`)
	for _, profile := range []string{"m8x8", "m8x16", "m16x8", "m16x16"} {
		m, x := 8, 8
		if strings.HasPrefix(profile, "m16") {
			m = 16
		}
		if strings.HasSuffix(profile, "x16") {
			x = 16
		}
		for op := 0; op < 256; op++ {
			d, e := c.DecodeWithFeatures([]byte{byte(op), 0x21, 0x43, 0x65}, c.FeatureSets[profile])
			if e != nil {
				t.Fatal(e)
			}
			enc := d.Encoding
			v := map[string]int64{}
			for _, o := range enc.Operands {
				v[o.Name] = 0x21
				if o.Width() == 16 {
					v[o.Name] = 0x4321
				}
				if o.Width() == 24 {
					v[o.Name] = 0x654321
				}
				if o.Relative && o.PCRegionBits == 0 {
					v[o.Name] = 1
				}
			}
			text := (&codec.Decoded{Encoding: enc, Values: v}).Format(0x1000)
			for _, o := range enc.Operands {
				if o.Relative && o.PCRegionBits == 0 {
					target, _ := o.Position().Target(0x1000, v[o.Name])
					text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", target), fmt.Sprintf("*+%d", o.PCBias+v[o.Name]))
				}
			}
			text = hex.ReplaceAllString(text, "$$${1}")
			if op == 0 || op == 2 {
				text = strings.ReplaceAll(text, "#", "")
			}
			// WDM is a reserved escape, absent from ca65's mnemonic table.
			if op == 0x42 {
				text = ".byte $42,$21"
			}
			fmt.Fprintf(&source, ".a%d\n.i%d\n%s\n", m, x, text)
			b, e := c.Encode(enc.ID, v)
			if e != nil {
				t.Fatal(e)
			}
			expected = append(expected, b...)
		}
	}
	src, obj, out := filepath.Join(dir, "all.s"), filepath.Join(dir, "all.o"), filepath.Join(dir, "all.bin")
	os.WriteFile(src, []byte(source.String()), 0644)
	for _, cmd := range []*exec.Cmd{exec.Command(filepath.Join(bin, "ca65"), "-o", obj, src), exec.Command(filepath.Join(bin, "ld65"), "-C", cfg, "-o", out, obj)} {
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%v: %v %s", cmd.Args, e, b)
		}
	}
	actual, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(expected, actual) {
		n := min(len(expected), len(actual))
		at := 0
		for at < n && expected[at] == actual[at] {
			at++
		}
		t.Fatalf("ca65 corpus differs at byte %d; actual %x expected %x", at, actual[max(0, at-4):min(len(actual), at+6)], expected[max(0, at-4):min(len(expected), at+6)])
	}
	t.Logf("ca65 matched %d opcode/profile cases, %d bytes (WDM escape separately defined by WDC)", 1024, len(actual))
}

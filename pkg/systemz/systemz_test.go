package systemz

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func load(t *testing.T) *codec.Catalog {
	t.Helper()
	f, e := os.Open("testdata/llvm-22.1.8-systemz.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	c, e := Parse(z, "systemz")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestCorpus(t *testing.T) {
	c := load(t)
	if len(c.Encodings) != 4131 || len(c.Unsupported) != 0 {
		t.Fatalf("%d encodings, %d unsupported", len(c.Encodings), len(c.Unsupported))
	}
	t.Logf("%d encodings, %d unsupported", len(c.Encodings), len(c.Unsupported))
}

func TestFullUpstreamDump(t *testing.T) {
	path := os.Getenv("MKASM_SYSTEMZ_TABLEGEN_JSON")
	if path == "" {
		t.Skip("set MKASM_SYSTEMZ_TABLEGEN_JSON to compare an unmodified upstream dump")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	full, err := Parse(f, "s390x")
	if err != nil {
		t.Fatal(err)
	}
	var actual, fixture bytes.Buffer
	if err := full.WriteJSON(&actual); err != nil {
		t.Fatal(err)
	}
	if err := load(t).WriteJSON(&fixture); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.Bytes(), fixture.Bytes()) {
		t.Fatal("unmodified upstream dump differs from complete retained corpus")
	}
	t.Logf("unmodified upstream dump produced the same %d forms", len(full.Encodings))
}

func TestRejectInput(t *testing.T) {
	for _, input := range []string{"", "{}", `{"!instanceof":[]} `, `{"!instanceof":{}} {}`} {
		if _, err := Parse(strings.NewReader(input), "systemz"); err == nil {
			t.Fatalf("invalid TableGen input accepted: %q", input)
		}
	}
	if _, err := Parse(strings.NewReader("{}"), "arm64"); err == nil {
		t.Fatal("foreign architecture accepted")
	}
}
func sample(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(5)
		if o.Signed {
			n = -3
		}
		if o.Relative {
			n = 6
		}
		if o.Scale > 0 && !o.Relative {
			n = o.Scale*2 + o.Bias
		}
		if o.Kind == "register" {
			n = 2
			if strings.HasPrefix(o.Class, "VR") {
				n = 17
			}
			if o.Class == "FP128" {
				n = 4
			}
		}
		if o.Width() < 3 && n >= int64(1)<<uint(o.Width()) {
			n = 1
		}
		if len(o.Names) > 0 && (n < 0 || n >= int64(len(o.Names)) || o.Names[n] == "") {
			for i, name := range o.Names {
				if name != "" && i > 0 {
					n = int64(i)
					break
				}
			}
		}
		if o.Name == "enc" {
			n = 0
		}
		var represented uint64
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				represented |= uint64(1) << uint(b.ValueBit+k)
			}
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		raw := uint64((n-o.Bias)/scale) & represented
		if o.Signed && o.Width() < 64 && raw&(uint64(1)<<uint(o.Width()-1)) != 0 {
			raw |= ^uint64(0) << uint(o.Width())
		}
		n = int64(raw)*scale + o.Bias
		if len(o.Names) > 0 && (n < 0 || n >= int64(len(o.Names)) || o.Names[n] == "") {
			for i, name := range o.Names {
				if name != "" && uint64(i)&^represented == 0 {
					n = int64(i)
					break
				}
			}
		}
		v[o.Name] = n
	}
	return v
}
func TestEveryFormRoundTrip(t *testing.T) {
	c := load(t)
	for i := range c.Encodings {
		e := &c.Encodings[i]
		t.Run(e.ID, func(t *testing.T) {
			v := sample(e)
			b, err := c.Encode(e.ID, v)
			if err != nil {
				t.Fatal(err)
			}
			d := &codec.Decoded{Encoding: e, Values: v, Length: len(b)}
			forms, err := c.Assemble(d.Format(0x100), 0x100)
			if err != nil {
				t.Fatalf("%q: %v", d.Format(0x100), err)
			}
			found := false
			for _, f := range forms {
				if bytes.Equal(f, b) {
					found = true
				}
			}
			if !found {
				t.Fatalf("text roundtrip %q lost %x", d.Format(0x100), b)
			}
			if e.AssemblyOnly {
				return
			}
			decoded, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			back, err := c.Encode(decoded.Encoding.ID, decoded.Values)
			if err != nil || !bytes.Equal(back, b) {
				t.Fatalf("decode re-encode %x %v", back, err)
			}
		})
	}
}
func TestLLVMOracle(t *testing.T) {
	tool, err := exec.LookPath("llvm-mc")
	if err != nil {
		tool = "/opt/homebrew/opt/llvm/bin/llvm-mc"
		if _, err = os.Stat(tool); err != nil {
			t.Skip("LLVM MC unavailable")
		}
	}
	c := load(t)
	var source strings.Builder
	var expected [][]byte
	var texts []string
	for i := range c.Encodings {
		e := &c.Encodings[i]
		v := sample(e)
		b, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		d := codec.Decoded{Encoding: e, Values: v, Length: len(b)}
		text := d.Format(0)
		for _, o := range e.Operands {
			if o.Relative {
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint64(v[o.Name])+uint64(o.PCBias)), fmt.Sprintf(".%+d", v[o.Name]))
			}
		}
		fmt.Fprintf(&source, "L%d: %s\n", i, text)
		expected = append(expected, b)
		texts = append(texts, text)
	}
	dir := t.TempDir()
	if p := os.Getenv("MKASM_SYSTEMZ_ARTIFACT_DIR"); p != "" {
		dir = p
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "oracle.s"), []byte(source.String()), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(tool, "-triple=s390x-linux-gnu", "-mcpu=z17", "-filetype=obj")
	cmd.Stdin = strings.NewReader(source.String())
	var object, stderr bytes.Buffer
	cmd.Stdout = &object
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		os.WriteFile(filepath.Join(dir, "oracle-errors.txt"), stderr.Bytes(), 0644)
		t.Fatalf("LLVM rejected corpus: %v\n%s", err, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "oracle.o"), object.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	elfFile, err := elf.NewFile(bytes.NewReader(object.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer elfFile.Close()
	section := elfFile.Section(".text")
	if section == nil {
		t.Fatal("no .text")
	}
	oracle, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	pos := 0
	for i, b := range expected {
		if pos+len(b) > len(oracle) {
			t.Fatal("short oracle output")
		}
		if !bytes.Equal(oracle[pos:pos+len(b)], b) {
			t.Errorf("%s %q: codec %x LLVM %x", c.Encodings[i].ID, texts[i], b, oracle[pos:pos+len(b)])
		}
		pos += len(b)
	}
	if pos != len(oracle) {
		t.Fatalf("oracle text has %d trailing bytes", len(oracle)-pos)
	}
	t.Logf("%d forms matched LLVM MC z17 (%d instruction bytes)", len(expected), pos)
}
func TestIndependentBytesAndSyntax(t *testing.T) {
	c := load(t)
	for _, tt := range []struct {
		text    string
		address uint64
		want    []byte
	}{
		{"lr %r1,%r2", 0, []byte{0x18, 0x12}}, {"lgr %r1,%r2", 0, []byte{0xb9, 4, 0, 0x12}},
		{"l %r1,4095(%r2,%r3)", 0, []byte{0x58, 0x12, 0x3f, 0xff}},
		{"l %r1,8(%r2)", 0, []byte{0x58, 0x10, 0x20, 8}}, {"l %r1,8", 0, []byte{0x58, 0x10, 0, 8}},
		{"lg %r1,-1(%r2,%r3)", 0, []byte{0xe3, 0x12, 0x3f, 0xff, 0xff, 4}},
		{"mvc 0(256,%r1),4095(%r2)", 0, []byte{0xd2, 0xff, 0x10, 0, 0x2f, 0xff}},
		{"brc 8,0x104", 0x100, []byte{0xa7, 0x84, 0, 2}}, {"je 0x104", 0x100, []byte{0xa7, 0x84, 0, 2}},
		{"brcl 15,0x106", 0x100, []byte{0xc0, 0xf4, 0, 0, 0, 3}},
	} {
		t.Run(tt.text, func(t *testing.T) {
			forms, err := c.Assemble(tt.text, tt.address)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range forms {
				if bytes.Equal(b, tt.want) {
					return
				}
			}
			t.Fatalf("%q got %x want %x", tt.text, forms, tt.want)
		})
	}
}
func TestRegistersRangesReservedAndTruncation(t *testing.T) {
	c := load(t)
	for _, text := range []string{"lr %r16,%r1", "dlgr %r1,%r2", "axbr %f2,%f4", "l %r1,8(%r0)", "l %r1,8(%r0,%r1)", "l %r1,4096(%r2)", "lg %r1,-524289(%r2)", "mvc 0(0,%r1),0(%r2)", "mvc 0(257,%r1),0(%r2)", "brc 16,4", "brc 8,3", "vleg %v1,8(%r1),2"} {
		if _, err := c.Assemble(text, 0); err == nil {
			t.Fatalf("invalid text accepted %q", text)
		}
	}
	for _, id := range []string{"LR", "L", "LG", "MVC", "VFA"} {
		var e *codec.Encoding
		for i := range c.Encodings {
			if c.Encodings[i].ID == id {
				e = &c.Encodings[i]
				break
			}
		}
		if e == nil {
			t.Fatal(id)
		}
		b, err := c.Encode(id, sample(e))
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < len(b); n++ {
			if _, err := c.Decode(b[:n]); !errors.Is(err, codec.ErrTruncated) {
				t.Fatalf("%s prefix%d: %v", id, n, err)
			}
		}
	}
	for _, bad := range [][]byte{{0, 0, 0, 0, 0, 0}, {0xb9, 4, 1, 0x12, 0, 0}, {0xe7, 0x12, 0, 0, 0x01, 0x60}} {
		if _, err := c.Decode(bad); err == nil {
			t.Fatalf("reserved fields accepted %x", bad)
		}
	}
	// FP128 occupies pairs {0,2}, {1,3}, {4,6}, {5,7}, ... .
	if _, err := c.Assemble("axbr %f4,%f5", 0); err != nil {
		t.Fatal(err)
	}
}
func TestFeatureProfiles(t *testing.T) {
	c := load(t)
	if len(c.FeatureSets) < 10 {
		t.Fatalf("missing processor profiles %v", c.FeatureSets)
	}
	var e *codec.Encoding
	for i := range c.Encodings {
		if c.Encodings[i].ID == "VFA" {
			e = &c.Encodings[i]
		}
	}
	if e == nil {
		t.Fatal("VFA")
	}
	b, err := c.Encode(e.ID, sample(e))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecodeWithFeatures(b, c.FeatureSets["generic"]); !errors.Is(err, codec.ErrUnknown) {
		t.Fatalf("generic admitted vector instruction: %v", err)
	}
	if _, err := c.DecodeWithFeatures(b, c.FeatureSets["z17"]); err != nil {
		t.Fatal(err)
	}
}

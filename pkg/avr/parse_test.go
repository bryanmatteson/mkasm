package avr

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func fullCatalog(t *testing.T) *codec.Catalog {
	t.Helper()
	f, err := os.Open("testdata/avr.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "avr")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unsupported) != 0 {
		t.Fatalf("unsupported real records: %+v", c.Unsupported)
	}
	if len(c.Encodings) != 202 {
		t.Fatalf("got %d encodings; want 97 machine records + 14 pointer expansions + 33 aliases + 58 Tiny register variants", len(c.Encodings))
	}
	return c
}

func TestCompleteLLVMCorpus(t *testing.T) {
	c := fullCatalog(t)
	for _, e := range c.Encodings {
		for sample := 0; sample < 3; sample++ {
			values, _ := sampleOperands(e, sample)
			b, err := codec.Encode(&e, values)
			if err != nil {
				t.Fatalf("%s: %v", e.ID, err)
			}
			decoded, err := c.Decode(b)
			if err != nil {
				t.Fatalf("%s: decode %x: %v", e.ID, b, err)
			}
			round, err := codec.Encode(decoded.Encoding, decoded.Values)
			if err != nil || !bytes.Equal(b, round) {
				t.Fatalf("%s: round trip %x -> %x: %v", e.ID, b, round, err)
			}
		}
	}
}

func TestAVRKnownBytes(t *testing.T) {
	c := fullCatalog(t)
	tests := []struct {
		id     string
		values map[string]int64
		bytes  []byte
	}{
		{"LDIRdK", map[string]int64{"rd": 0, "k": 255}, []byte{0x0f, 0xef}},
		{"ADIWRdK", map[string]int64{"rd": 0, "k": 63}, []byte{0xcf, 0x96}},
		{"MOVWRdRr", map[string]int64{"rd": 15, "rr": 0}, []byte{0xf0, 0x01}},
		{"RJMPk", map[string]int64{"k": -2}, []byte{0xff, 0xcf}},
		{"CALLk", map[string]int64{"k": 4}, []byte{0x0e, 0x94, 0x02, 0x00}},
		{"LDSRdK", map[string]int64{"rd": 2, "k": 4660}, []byte{0x20, 0x90, 0x34, 0x12}},
		{"LDRdPtr_X", map[string]int64{"reg": 4}, []byte{0x4c, 0x90}},
		{"LDRdPtrPd_Y", map[string]int64{"reg": 4}, []byte{0x4a, 0x90}},
		{"LDDRdPtrQ_Y", map[string]int64{"reg": 4, "memri": 63}, []byte{0x4f, 0xac}},
		{"CLR", map[string]int64{"rd": 4}, []byte{0x44, 0x24}},
		{"CBR", map[string]int64{"rd": 0, "k": 15}, []byte{0x00, 0x7f}},
	}
	for _, tt := range tests {
		b, err := c.Encode(tt.id, tt.values)
		if err != nil || !bytes.Equal(b, tt.bytes) {
			t.Errorf("%s: got %x (%v), want %x", tt.id, b, err, tt.bytes)
		}
	}
	if _, err := c.Encode("CALLk", map[string]int64{"k": 3}); err == nil {
		t.Error("unaligned call accepted")
	}
	if _, err := c.Encode("RJMPk", map[string]int64{"k": 4096}); err == nil {
		t.Error("out-of-range relative branch accepted")
	}
}

func TestEveryFormTextAssembly(t *testing.T) {
	c := fullCatalog(t)
	for _, e := range c.Encodings {
		values, text := sampleOperands(e, 2)
		for _, o := range e.Operands {
			if o.Relative {
				text = strings.ReplaceAll(text, fmt.Sprint(values[o.Name]), fmt.Sprintf("0x%x", 0x10000+o.PCBias+values[o.Name]))
			}
		}
		want, err := codec.Encode(&e, values)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.AssembleWithFeatures(text, 0x10000, append([]string{}, e.Features...))
		found := false
		for _, b := range got {
			if bytes.Equal(b, want) {
				found = true
			}
		}
		if err != nil || !found {
			t.Errorf("%s: %q produced %x (%v), want %x", e.ID, text, got, err, want)
		}
	}
	for _, text := range []string{"adiw r25:r24, 63", "adiw X, 63", "movw r31:r30, r1:r0"} {
		if _, err := c.Assemble(text, 0); err != nil {
			t.Errorf("pair register alias %q: %v", text, err)
		}
	}
}

func TestFullSourceInput(t *testing.T) {
	path := os.Getenv("MKASM_AVR_TABLEGEN_JSON")
	if path == "" {
		t.Skip("set MKASM_AVR_TABLEGEN_JSON for unpruned LLVM source import")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "avr")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unsupported) != 0 || len(c.Encodings) != 202 {
		t.Fatalf("full source: %d encodings, unsupported %+v", len(c.Encodings), c.Unsupported)
	}
}

func TestLLVMByteParity(t *testing.T) {
	llvm := os.Getenv("MKASM_LLVM_MC")
	if llvm == "" {
		t.Skip("set MKASM_LLVM_MC for full LLVM byte differential")
	}
	c := fullCatalog(t)
	encodingRE := regexp.MustCompile(`encoding: \[([^]]+)\]`)
	for _, tiny := range []bool{false, true} {
		var input strings.Builder
		var expected [][]byte
		var labels []string
		for _, e := range c.Encodings {
			isTiny := false
			for _, f := range e.Features {
				if f == "HasTinyEncoding" {
					isTiny = true
				}
			}
			if isTiny != tiny {
				continue
			}
			for sample := 0; sample < 3; sample++ {
				values, text := sampleOperands(e, sample)
				b, err := codec.Encode(&e, values)
				if err != nil {
					t.Fatal(err)
				}
				input.WriteString(text + "\n")
				expected = append(expected, b)
				labels = append(labels, e.ID+": "+text)
			}
		}
		features := "+special,-tinyencoding"
		if tiny {
			features = "+special,+tinyencoding"
		}
		cmd := exec.Command(llvm, "-triple=avr", "-mcpu=avrxmega7", "-mattr="+features, "-show-encoding")
		cmd.Stdin = strings.NewReader(input.String())
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("LLVM: %v\n%s", err, output)
		}
		matches := encodingRE.FindAllStringSubmatch(string(output), -1)
		if len(matches) != len(expected) {
			t.Fatalf("LLVM produced %d encodings for %d forms\n%s", len(matches), len(expected), output)
		}
		for i, m := range matches {
			var b []byte
			for _, s := range strings.Split(m[1], ",") {
				n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
				if err != nil {
					t.Fatal(err)
				}
				b = append(b, byte(n))
			}
			if !bytes.Equal(b, expected[i]) {
				t.Errorf("%s: LLVM %x, imported %x", labels[i], b, expected[i])
			}
		}
		t.Logf("LLVM verified %d forms (tiny=%v)", len(expected), tiny)
	}
}

func sampleOperands(e codec.Encoding, sample int) (map[string]int64, string) {
	values := map[string]int64{}
	text := e.Syntax
	for _, o := range e.Operands {
		width := o.Width()
		raw := int64(0)
		if sample == 1 {
			raw = (int64(1) << uint(width)) - 1
		}
		if sample == 2 {
			raw = ((int64(1) << uint(width)) - 1) / 3
			for _, ch := range o.Name {
				raw = (raw*17 + int64(ch)) & ((int64(1) << uint(width)) - 1)
			}
		}
		if len(o.Names) > 0 && o.Names[raw] == "" {
			for o.Names[raw] == "" {
				raw = (raw + 1) % int64(len(o.Names))
			}
		}
		if o.Signed && raw&(int64(1)<<uint(width-1)) != 0 {
			raw -= int64(1) << uint(width)
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		value := raw*scale + o.Bias
		values[o.Name] = value
		spelling := fmt.Sprint(value)
		if len(o.Names) > 0 {
			spelling = o.Names[raw]
		}
		text = strings.ReplaceAll(text, "{"+o.Name+"}", spelling)
	}
	return values, text
}

func TestInvalidInput(t *testing.T) {
	for _, input := range []string{"{}", "[]", "{} {}"} {
		if _, err := Parse(strings.NewReader(input), "avr"); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
	if _, err := Parse(strings.NewReader("{}"), "arm"); err == nil {
		t.Fatal("accepted wrong architecture")
	}
}

func TestDeviceFeatureProfiles(t *testing.T) {
	c := fullCatalog(t)
	if len(c.FeatureSets) != 380 {
		t.Fatalf("got %d CPU profiles, want all 380 LLVM AVR Processor records", len(c.FeatureSets))
	}
	has := func(profile, feature string) bool {
		for _, f := range c.FeatureSets[profile] {
			if f == feature {
				return true
			}
		}
		return false
	}
	for _, feature := range []string{"HasSRAM", "HasNonTinyEncoding", "HasMOVW", "HasIJMPCALL"} {
		if !has("atmega328p", feature) {
			t.Errorf("atmega328p missing %s", feature)
		}
	}
	if has("atmega328p", "HasTinyEncoding") || has("atmega328p", "HasEIJMPCALL") {
		t.Error("atmega328p admitted unavailable features")
	}
	if !has("attiny40", "HasTinyEncoding") || has("attiny40", "HasNonTinyEncoding") {
		t.Error("attiny40 selected incorrect addressing encoding")
	}
	for _, tc := range []struct{ cpu, mnemonic string }{{"atmega328p", "ldd"}, {"attiny40", "lds"}} {
		d, err := c.DecodeWithFeatures([]byte{0, 0xa0}, c.FeatureSets[tc.cpu])
		if err != nil || d.Encoding.Mnemonic != tc.mnemonic {
			t.Errorf("%s: got %+v (%v), want %s", tc.cpu, d, err, tc.mnemonic)
		}
	}
	if _, err := c.AssembleWithFeatures("eijmp", 0, c.FeatureSets["atmega328p"]); err == nil {
		t.Error("unavailable extended indirect jump assembled")
	}
	if _, err := c.AssembleWithFeatures("add r0,r1", 0, c.FeatureSets["attiny40"]); err == nil {
		t.Error("Tiny admitted physically absent registers")
	}
	if _, err := c.AssembleWithFeatures("add r16,r17", 0, c.FeatureSets["attiny40"]); err != nil {
		t.Errorf("Tiny rejected valid high registers: %v", err)
	}
	if _, err := c.DecodeWithFeatures([]byte{1, 0x0c}, c.FeatureSets["attiny40"]); err == nil {
		t.Error("Tiny decoded physically absent registers")
	}
	d, err := c.Decode([]byte{0x0f, 0xef})
	if err != nil || d.Encoding.Mnemonic != "ldi" {
		t.Errorf("assembly-only SER alias decoded: %+v (%v)", d, err)
	}
}

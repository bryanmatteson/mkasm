package mcs51

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readVectors(t *testing.T, name string) []oracleVector {
	t.Helper()
	b, e := os.ReadFile("data/" + name)
	if e != nil {
		t.Fatal(e)
	}
	var v []oracleVector
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func bytesOf(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func hasBytes(all [][]byte, b []byte) bool {
	for _, a := range all {
		if bytes.Equal(a, b) {
			return true
		}
	}
	return false
}
func TestCompleteOracleCorpus(t *testing.T) {
	catalogs := map[string]*Catalog{}
	for _, arch := range []string{"mcs51", "mcs80390"} {
		c, e := Parse(strings.NewReader(source), arch)
		if e != nil {
			t.Fatal(e)
		}
		catalogs[arch] = c
		if len(c.Encodings) != 120 {
			t.Fatal(arch, len(c.Encodings))
		}
	}
	for _, filename := range []string{"oracle.json", "sdcc.json"} {
		v := readVectors(t, filename)
		expected := 4590
		if filename == "sdcc.json" {
			expected = 1530
		}
		if len(v) != expected {
			t.Fatal(filename, len(v))
		}
		seen := map[string]map[byte]bool{}
		for i, x := range v {
			c := catalogs[x.Architecture]
			raw := bytesOf(t, x.Bytes)
			if seen[x.Architecture] == nil {
				seen[x.Architecture] = map[byte]bool{}
			}
			seen[x.Architecture][raw[0]] = true
			d, e := c.Decode(raw)
			if e != nil || d.Length != len(raw) {
				t.Fatalf("%s[%d] decode %v", filename, i, e)
			}
			out, e := c.Encode(d.Encoding.ID, d.Values)
			if e != nil || !bytes.Equal(out, raw) {
				t.Fatal(filename, i, "encode", e)
			}
			text := d.Format(x.Address)
			all, e := c.Assemble(text, x.Address)
			if e != nil || !hasBytes(all, raw) {
				t.Fatalf("%s[%d] text %s %x %v", filename, i, text, all, e)
			}
			if x.OracleEncoded != "" && x.OracleEncoded != x.Bytes {
				t.Fatal("independent assembler mismatch", x)
			}
			if filename == "sdcc.json" && x.OracleEncoded == "" {
				t.Fatal("missing SDCC oracle", x)
			}
			if x.OracleText != "" {
				all, e = c.Assemble(x.OracleText, x.Address)
				if e != nil || !hasBytes(all, raw) {
					t.Fatal("Ghidra disassembly assembly", x, e)
				}
			}
			if i%9 == 0 || filename == "sdcc.json" && i%3 == 0 {
				tpl, e := c.ParseTemplate(text, x.Address)
				if e != nil {
					t.Fatal(filename, i, "template", e)
				}
				if _, _, ok := tpl.Match(raw); !ok {
					t.Fatal(filename, i, "template match", text)
				}
				all, e = tpl.Encode(nil)
				if e != nil || !hasBytes(all, raw) {
					t.Fatal(filename, i, "template encode", e)
				}
			}
			for n := 0; n < len(raw); n++ {
				if _, e = c.Decode(raw[:n]); e == nil {
					t.Fatal("accepted truncation", x, n)
				}
			}
		}
		for arch, opcodes := range seen {
			if len(opcodes) != 255 || opcodes[0xa5] {
				t.Fatal(arch, "incomplete defined opcode coverage", len(opcodes))
			}
		}
	}
}
func TestExhaustivePrefixAndPageValues(t *testing.T) {
	c := Default()
	for op := 0; op < 256; op++ {
		for second := 0; second < 256; second++ {
			raw := []byte{byte(op), byte(second), 0x5a}
			d, e := c.Decode(raw)
			if op == 0xa5 {
				if e == nil {
					t.Fatal("A5 reserved")
				}
				continue
			}
			if e != nil {
				t.Fatal(op, second, e)
			}
			out, e := c.Encode(d.Encoding.ID, d.Values)
			if e != nil || !bytes.Equal(out, raw[:d.Length]) {
				t.Fatal(op, second, e)
			}
		}
	}
}
func TestAddressesAndTemplates(t *testing.T) {
	c := Default()
	for _, x := range []struct {
		raw        string
		pc, target uint64
	}{{"0101", 0xffff, 1}, {"e100", 0x7fe, 0xf00}, {"80fe", 0xffff, 0xffff}, {"807f", 0xfffe, 0x7f}, {"8000", 0xffff, 1}} {
		d, e := c.Decode(bytesOf(t, x.raw))
		if e != nil {
			t.Fatal(e)
		}
		target, ok := d.BranchTarget(x.pc)
		if !ok || target != x.target {
			t.Fatal(x, target)
		}
		all, e := c.Assemble(d.Format(x.pc), x.pc)
		if e != nil || !hasBytes(all, bytesOf(t, x.raw)) {
			t.Fatal(x, e)
		}
	}
	for _, text := range []string{"ajmp 0x800", "sjmp 0x200", "mov R8,A", "mov @R2,A", "mov A,#256", "mov DPTR,#65536", "setb 0x100", "mov 0x100,A"} {
		if _, e := c.Assemble(text, 0); e == nil {
			t.Fatal("accepted invalid", text)
		}
	}
	for text, want := range map[string]string{"mov A,#0ffh": "74ff", "mov A,#101b": "7405", "mov A,#-1": "74ff", "mov P1,#1": "759001", "setb P1.3": "d293", "setb 20.0": "d200", "mov 0x34,0x12": "851234"} {
		all, e := c.Assemble(text, 0)
		if e != nil || !hasBytes(all, bytesOf(t, want)) {
			t.Fatal(text, e, all)
		}
	}
	tpl, e := c.ParseTemplate("mov $dst,#$imm", 0)
	if e != nil {
		t.Fatal(e)
	}
	all, e := tpl.Encode(map[string]int64{"dst": 3, "imm": 0x55})
	if e != nil || !hasBytes(all, []byte{0x7b, 0x55}) {
		t.Fatal(e, all)
	}
	_, values, ok := tpl.Match([]byte{0x7b, 0x55})
	if !ok || values["dst"] != 3 || values["imm"] != 0x55 {
		t.Fatal(values)
	}
	tpl, e = c.ParseTemplate("sjmp $delta", 0xffff)
	if e != nil {
		t.Fatal(e)
	}
	all, e = tpl.Encode(map[string]int64{"delta": -2})
	if e != nil || !hasBytes(all, []byte{0x80, 0xfe}) {
		t.Fatal(e)
	}
}
func TestStateHelpers(t *testing.T) {
	for bank := uint8(0); bank < 4; bank++ {
		for reg := uint8(0); reg < 8; reg++ {
			a, e := RegisterAddress(reg, bank<<3)
			if e != nil || a != bank*8+reg {
				t.Fatal(a, e)
			}
		}
	}
	if _, e := RegisterAddress(8, 0); e == nil {
		t.Fatal("invalid register")
	}
	for bit := 0; bit < 256; bit++ {
		a, b, s := ResolveBit(uint8(bit))
		if b > 7 || s == "INTMEM" && (a < 0x20 || a > 0x2f) || s == "SFR" && (a < 0x80 || a&7 != 0) {
			t.Fatal(a, b, s)
		}
	}
	if ExternalIndirectAddress(0x34, 0x12) != 0x1234 || ComputedCodeAddress(0xffff, 1, 1, 0, true, false) != 1 || ComputedCodeAddress(0, 0, 1, 0xffffff, false, true) != 0 {
		t.Fatal("computed address")
	}
}
func TestSourceErrors(t *testing.T) {
	for _, s := range []string{"", "@include \"8051_main.sinc\"", "@if defined(MCS51)\n:NOP is ophi=0 { }", strings.Replace(source, "ophi=0  & oplo=0", "unknownfield=0 & oplo=0", 1)} {
		if _, e := Parse(strings.NewReader(s), "mcs51"); e == nil {
			t.Fatal("invalid source accepted")
		}
	}
	if _, e := Parse(strings.NewReader(source), "80251"); e == nil {
		t.Fatal("unimplemented variant accepted")
	}
}
func TestCompiledCPrograms(t *testing.T) {
	for _, v := range readVectors(t, "programs.json") {
		c, e := Parse(strings.NewReader(source), v.Architecture)
		if e != nil {
			t.Fatal(e)
		}
		code := bytesOf(t, v.Bytes)
		var rebuilt []byte
		for at := 0; at < len(code); {
			d, e := c.Decode(code[at:])
			if e != nil {
				t.Fatal(v.Architecture, at, e)
			}
			raw, e := c.Encode(d.Encoding.ID, d.Values)
			if e != nil {
				t.Fatal(e)
			}
			all, e := c.Assemble(d.Format(v.Address+uint64(at)), v.Address+uint64(at))
			if e != nil || !hasBytes(all, raw) {
				t.Fatal(v.Architecture, at, e)
			}
			rebuilt = append(rebuilt, raw...)
			at += d.Length
		}
		if !bytes.Equal(code, rebuilt) {
			t.Fatal("compiled segment byte loss")
		}
	}
}
func TestSourceCoverage(t *testing.T) {
	for _, mode := range []string{"MCS51", "MCS80390"} {
		s, e := preprocess(source, mode)
		if e != nil {
			t.Fatal(e)
		}
		core, special := 0, 0
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, ":") {
				if strings.Contains(line, "bitaddr57=7") && strings.Contains(line, "sfrbit3=0") {
					special++
				} else {
					core++
				}
			}
		}
		if core != 111 {
			t.Fatal(mode, core)
		}
		t.Logf("%s: %d active instruction constructors, %d core forms, %d SFR-bit semantic specializations folded", mode, core+special, core, special)
	}
}
func TestIndependentExecutedBranchBoundaries(t *testing.T) {
	var raw []struct {
		PC       uint64 `json:"pc"`
		Bytes    string `json:"bytes"`
		Expected uint64 `json:"expected_target"`
		Observed uint64 `json:"observed_target"`
	}
	b, e := os.ReadFile("data/execution-boundaries.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &raw); e != nil {
		t.Fatal(e)
	}
	c := Default()
	for _, x := range raw {
		if x.Expected != x.Observed {
			t.Fatal("independent execution mismatch")
		}
		d, e := c.Decode(bytesOf(t, x.Bytes))
		if e != nil {
			t.Fatal(e)
		}
		target, ok := d.BranchTarget(x.PC)
		if !ok || target != x.Observed {
			t.Fatal(x, target)
		}
	}
}

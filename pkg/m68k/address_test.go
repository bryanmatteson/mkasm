package m68k

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func richCases(t *testing.T, c *Catalog, emit func(string, string, []Value, []byte)) {
	t.Helper()
	total := 0
	seen := map[string]bool{}
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		cpu := ""
		profiles := []string{"68020", "68010", "68000", "68030", "68040", "68060", "68020+68881", "68020+68851", "cpu32", "fido"}
		if c.Architecture == "coldfire" {
			profiles = []string{"coldfire-all"}
		}
		for _, p := range profiles {
			if Profiles[p]&o.Features != 0 {
				cpu = p
				break
			}
		}
		if cpu == "" {
			continue
		}
		c.CPU = cpu
		values, e := sampleOpcode(c, o)
		if e != nil {
			t.Fatal(e)
		}
		for n, a := range pairs(o) {
			if !isEA(a[0]) {
				continue
			}
			for code := 0; code <= 60; code++ {
				if !validEA(a[0], code) {
					continue
				}
				addresses := []Value{sampleEA(code, a[1])}
				key := fmt.Sprintf("%s:%s:%d", cpu, a, code)
				if (code>>3 == 6 || code == 59) && !seen[key] {
					seen[key] = true
					for _, index := range []int64{0, 7, 8, 15} {
						for _, scale := range []int64{1, 2, 4, 8} {
							addresses = append(addresses, L(S(int64(code)), S(index), U(1), S(scale), U(0), S(-128)))
						}
					}
					if hasFull(c) {
						for _, bd := range []int64{0, 16, 32} {
							for _, ind := range []int64{0, 1, 2, 3, 5, 6, 7} {
								for _, supp := range []int64{0, 1, 2, 3} {
									disp := int64(0)
									if bd != 0 {
										disp = -128
									}
									outer := int64(0)
									if ind&3 >= 2 {
										outer = -128
									}
									addresses = append(addresses, L(S(int64(code)), U(15), U(1), U(8), U(1), S(disp), S(bd), S(supp&1), S(supp>>1), S(ind), S(outer)))
								}
							}
						}
					}
				}
				for _, address := range addresses {
					if a[1] == '/' {
						address = L(address, U(1))
					}
					v := append([]Value(nil), values...)
					v[n] = address
					b, e := c.Encode(o.ID, v)
					if e != nil {
						if strings.Contains(e.Error(), "fixed opcode") || strings.Contains(e.Error(), "invalid immediate") || strings.Contains(e.Error(), "scaled index") || strings.Contains(e.Error(), "immediate addressing forbidden") || strings.Contains(e.Error(), "FPU control transfer") {
							continue
						}
						t.Fatalf("%s %s address%v: %v", c.Architecture, o.ID, address, e)
					}
					i, e := c.Decode(b)
					if e != nil || i.Length != len(b) {
						t.Fatalf("%s %s %x decode %v", c.Architecture, o.ID, b, e)
					}
					check, e := c.Assemble(i.Format())
					if e != nil || !bytes.Equal(check, b) {
						t.Fatal(o.ID, i.Format(), e)
					}
					if emit != nil {
						emit(cpu, o.ID, v, b)
					}
					total++
				}
			}
		}
	}
	t.Logf("%s addressing expansions %d", c.Architecture, total)
}
func TestAllAddressForms(t *testing.T) {
	for _, arch := range []string{"m68k", "coldfire"} {
		t.Run(arch, func(t *testing.T) { c := corpus(t); c.Architecture = arch; richCases(t, c, nil) })
	}
}
func TestStrictProfilesBranchesAndReservedBits(t *testing.T) {
	c := corpus(t)
	c.CPU = "68000"
	cases := []struct {
		cpu, text string
		good      bool
	}{{"68000", "bra [0]", true}, {"68000", "bras [0]", false}, {"68020", "bras [-1]", false}, {"68000", "bras [-1]", true}, {"68020", "bral [-100000]", true}, {"68000", "bral [-100000]", false}, {"68000", "braw [32768]", false}, {"68000", "movel [[48,0,1,2,0,0],[0]]", false}, {"68020", "movel [[48,0,1,2,0,0],[0]]", true}, {"68000", "movel [[48,0,1,1,1,0,0,0,0,0,0],[0]]", false}, {"68020", "movel [[48,0,1,1,1,0,0,0,0,4,0],[0]]", false}, {"68000", "movel [[40,32768],[0]]", false}, {"68020", "movel [[48,0,1,1,1,32768,16,0,0,0,0],[0]]", false}, {"68000", "moveq [128,0]", false}, {"68000", "moveq [-128,\"%d7\"]", true}, {"68000", "faddx [1,0,0]", false}}
	for _, x := range cases {
		c.CPU = x.cpu
		b, e := c.Assemble(x.text)
		if (e == nil) != x.good {
			t.Errorf("%s %s got%x err%v", x.cpu, x.text, b, e)
		}
	}
	c.CPU = "68000"
	b, e := c.Assemble("bra [-20]")
	if e != nil {
		t.Fatal(e)
	}
	i, e := c.Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	target, _ := i.BranchTarget(0xfffffff0)
	if target != 0xffffffde {
		t.Errorf("branch target %x", target)
	}
	for _, bad := range []string{"moveq [1]", "nop [0]", "movel [[61],[0]]", "nop [null]", "nop [] trailing"} {
		if _, e := c.Assemble(bad); e == nil {
			t.Error("accepted", bad)
		}
	}
	c.CPU = "68020+68881"
	for _, text := range []string{"movel [[58,-8],[0]]", "faddd [1,[58,-8],2]"} {
		b, e := c.Assemble(text)
		if e != nil {
			t.Fatal(e)
		}
		i, e := c.Decode(b)
		if e != nil {
			t.Fatal(e)
		}
		index := 0
		if strings.HasPrefix(text, "fadd") {
			index = 1
		}
		target, ok := i.PCRelativeTarget(index, 0x1000)
		want := uint64(0xffa)
		if index == 1 {
			want = 0xffc
		}
		if !ok || target != want {
			t.Errorf("%s PC target%x %v wanted%x", text, target, ok, want)
		}
	}
}
func TestDecodeAlwaysReencodes(t *testing.T) {
	c := corpus(t)
	c.CPU = "68020+68851+68881"
	r := rand.New(rand.NewSource(1))
	for n := 0; n < 8000; n++ {
		b := make([]byte, 24)
		r.Read(b)
		i, e := c.Decode(b)
		if e != nil {
			continue
		}
		actual, e := c.Assemble(i.Format())
		if e != nil || !bytes.Equal(actual, b[:i.Length]) {
			t.Fatalf("%x: %s got%x err%v", b, i.Format(), actual, e)
		}
	}
}
func TestRoundTripJSONAndTemplates(t *testing.T) {
	c := corpus(t)
	c.CPU = "68000"
	var b bytes.Buffer
	if e := c.WriteJSON(&b); e != nil {
		t.Fatal(e)
	}
	again, e := Parse(&b, "m68k")
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := again.Assemble("moveq [-7,\"d3\"]")
	if e != nil {
		t.Fatal(e)
	}
	i, e := again.Decode(encoded)
	if e != nil {
		t.Fatal(e)
	}
	template, e := again.Template(i.Opcode.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = template.Encode(); e == nil {
		t.Fatal("missing operands accepted")
	}
	for n, v := range i.Operands {
		if e = template.Set(fmt.Sprintf("op%d", n), v); e != nil {
			t.Fatal(e)
		}
	}
	actual, e := template.Encode()
	if e != nil || !bytes.Equal(encoded, actual) {
		t.Fatal(e)
	}
	bad := *c
	bad.CPU = "isa-a"
	if bad.Validate() == nil {
		t.Fatal("profile family accepted")
	}
	data, _ := json.Marshal(c)
	if _, e := Parse(bytes.NewReader(data), "coldfire"); e == nil {
		t.Fatal("incompatible resolved catalog accepted")
	}
}

func TestLargeTrailingInputAndTruncation(t *testing.T) {
	data, e := os.ReadFile("testdata/gnu-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []gnuVector
	if e = json.Unmarshal(data, &cases); e != nil {
		t.Fatal(e)
	}
	c := corpus(t)
	large := make([]byte, 1<<20)
	for j := range large {
		large[j] = 0xff
	}
	for _, x := range cases {
		c.CPU = x.CPU
		c.Architecture = "m68k"
		if strings.Contains(x.CPU, "isa") || x.CPU == "coldfire-all" {
			c.Architecture = "coldfire"
		}
		b, e := hex.DecodeString(x.Hex)
		if e != nil {
			t.Fatal(e)
		}
		copy(large, b)
		i, e := c.Decode(large)
		if e != nil || i.Length != len(b) {
			t.Fatalf("large trailing %s: %v", x.Assembly, e)
		}
		check, e := c.Assemble(i.Format())
		if e != nil || !bytes.Equal(check, b) {
			t.Fatal(x.Assembly, e)
		}
		for n := 0; n < len(b); n++ {
			if partial, e := c.Decode(b[:n]); e == nil && partial.Length > n {
				t.Fatal("decoder consumed beyond truncated input")
			}
		}
	}
}

func TestCoprocessorBranchSizes(t *testing.T) {
	c := corpus(t)
	c.CPU = "68851"
	for _, d := range []int64{-2147483648, -100000, -32769, -32768, 0, 32767, 32768, 2147483647} {
		b, e := c.Encode("pbbc", []Value{S(d)})
		if e != nil {
			t.Fatal(d, e)
		}
		want := 4
		if d < -32768 || d > 32767 {
			want = 6
		}
		if len(b) != want {
			t.Fatalf("pbbc %d got%x expected%d bytes", d, b, want)
		}
		i, e := c.Decode(b)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := number(i.Operands[0])
		if e != nil || actual != d {
			t.Fatalf("pbbc %d got%d %v", d, actual, e)
		}
	}
}

func TestRegisterSpelling(t *testing.T) {
	c := corpus(t)
	c.CPU = "68000"
	b, e := c.Assemble("linkw [\"%fp\",-32]")
	if e != nil || fmt.Sprintf("%x", b) != "4e56ffe0" {
		t.Fatal(b, e)
	}
	c.Architecture = "coldfire"
	c.CPU = "cfv4e"
	for _, x := range []struct{ text, hex string }{{"movec [\"d0\",\"asid\"]", "4e7b0003"}, {"movec [\"a1\",\"pcr1u1\"]", "4e7b9d0b"}, {"movec [\"d3\",\"mmubar\"]", "4e7b3008"}} {
		b, e := c.Assemble(x.text)
		if e != nil || fmt.Sprintf("%x", b) != x.hex {
			t.Fatal(x.text, b, e)
		}
	}
}

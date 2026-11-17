package msp430

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestCatalogConsumers(t *testing.T) {
	for _, arch := range []string{"msp430", "msp430x"} {
		t.Run(arch, func(t *testing.T) {
			c := load(t, arch)
			for i := range c.Encodings {
				e := &c.Encodings[i]
				values := sampleValues(*e)
				b, err := codec.Encode(e, values)
				if err != nil {
					t.Fatalf("%s encode: %v", e.ID, err)
				}
				d, err := c.Decode(b)
				if err != nil {
					t.Fatalf("%s decode %x: %v", e.ID, b, err)
				}
				again, err := codec.Encode(d.Encoding, d.Values)
				if err != nil || !bytes.Equal(b, again) {
					t.Fatalf("%s decoded as %s: %x != %x (%v)", e.ID, d.Encoding.ID, b, again, err)
				}
				if d.Length != len(b) {
					t.Fatalf("%s framing=%d want%d", e.ID, d.Length, len(b))
				}
				address := uint64(0xfffe)
				if arch == "msp430x" {
					address = 0xffffe
				}
				for _, constraint := range e.Constraints {
					// The16-bit wrapped alias partition has equal effective
					// targets only when both PC bases use lower-memory wrap.
					if constraint.Kind == "encoded_targets_eq" {
						address = 0
					}
				}
				text := (&codec.Decoded{Encoding: e, Values: values, Length: len(b)}).Format(address)
				parsed, ok := codec.ParseOperands(e, text, address)
				if !ok {
					t.Fatalf("%s cannot parse formatted %q", e.ID, text)
				}
				again, err = codec.Encode(e, parsed)
				if err != nil || !bytes.Equal(b, again) {
					t.Fatalf("%s text %q: %x != %x (%v)", e.ID, text, b, again, err)
				}
			}
		})
	}
}
func TestGhidraConstructorMnemonics(t *testing.T) {
	c := load(t, "msp430x")
	names := map[string]bool{}
	for _, e := range c.Encodings {
		names[e.Mnemonic] = true
	}
	for _, m := range constructor.FindAllStringSubmatch(extendedSource, -1) {
		if !names[strings.ToLower(m[1])] {
			t.Errorf("missing actual source mnemonic %s", m[1])
		}
	}
}

func TestBranchTargetsExcludeDataAndIndirectCalls(t *testing.T) {
	for _, arch := range []string{"msp430", "msp430x"} {
		c := load(t, arch)
		for _, tc := range []struct {
			raw    []byte
			target uint64
			known  bool
		}{
			{[]byte{0x14, 0x40, 2, 0}, 0, false},       // symbolic MOV source
			{[]byte{0x90, 0x50, 2, 0, 0, 0}, 0, false}, // symbolic ADD operands
			{[]byte{0x90, 0x12, 2, 0}, 0, false},       // CALL through symbolic memory
			{[]byte{0x92, 0x12, 2, 0}, 0, false},       // CALL through absolute memory
			{[]byte{0x84, 0x12}, 0, false},             // CALL through r4
			{[]byte{0xb0, 0x12, 2, 0}, 2, true},
			{[]byte{0xb0, 0x12, 0xfe, 0xff}, 0xfffe, true},
			{[]byte{0xb0, 0x12, 0xff, 0xff}, 0xfffe, true}, // CALL clears the low PC bit
			{[]byte{0x83, 0x12}, 0, true},                  // constant generator #0
			{[]byte{0x93, 0x12}, 0, true},                  // constant generator #1, aligned
			{[]byte{0xa3, 0x12}, 2, true},
			{[]byte{0xa2, 0x12}, 4, true},
			{[]byte{0xb2, 0x12}, 8, true},
			{[]byte{0xb3, 0x12}, 0xfffe, true},
			{[]byte{0x00, 0x3c}, 0x1002, true},
		} {
			d, err := c.Decode(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if target, known := d.BranchTarget(0x1000); target != tc.target || known != tc.known {
				t.Errorf("%s %x %s: target=%x known=%t, want %x %t", arch, tc.raw, d.Format(0x1000), target, known, tc.target, tc.known)
			}
		}
	}
}
func requireAssembly(t *testing.T, c *codec.Catalog, text string, address uint64, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	all, err := c.Assemble(text, address)
	if err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	for _, b := range all {
		if bytes.Equal(b, want) {
			return
		}
	}
	t.Fatalf("%q at%x: got%x want%x", text, address, all, want)
}
func TestAddressingAndExtensions(t *testing.T) {
	classic := load(t, "msp430")
	for _, test := range []struct{ text, bytes string }{
		{"mov #0,r4", "0443"}, {"mov #1,r4", "1443"}, {"mov #2,r4", "2443"}, {"mov #4,r4", "2442"}, {"mov #8,r4", "3442"}, {"mov #-1,r4", "3443"},
		{"mov #65535,r4", "3440ffff"}, {"mov @r5+,r4", "3445"}, {"mov @pc,r4", "2440"}, {"rrc @pc", "2010"}, {"mov &0xabcd,r4", "1442cdab"}, {"mov -2(r5),r4", "1445feff"},
		{"push.b #17", "70121100"}, {"push 20(r5)", "15121400"}, {"pop.b &0xabcd", "f241cdab"},
		{"rla 0x16", "905014001200"}, {"jmp 0xfffe", "fe3f"},
	} {
		requireAssembly(t, classic, test.text, 0, test.bytes)
	}
	requireAssembly(t, classic, "jmp 0", 0xfffe, "003c")
	x := load(t, "msp430x")
	requireAssembly(t, x, "mov 0,r4", 0xfffc, "14400200")
	requireAssembly(t, x, "mov 0x20000,r4", 0x1fffc, "14400200")
	requireAssembly(t, x, "mov 0x10000,r4", 0xfffe, "14400000")
	requireAssembly(t, x, "jmp 0x20000", 0x1fffe, "003c")
	requireAssembly(t, x, "jmp 0", 0xffffe, "003c")
	// At instruction FFFCh, the source displacement is based at FFFEh
	// (16-bit wrap), while the destination base10000h uses20-bit arithmetic.
	if _, err := x.Assemble("rla 0", 0xfffc); err == nil {
		t.Fatal("accepted RLA alias whose two effective targets differ at the64K boundary")
	}
	requireAssembly(t, x, "rla 0xfffe", 0xfffc, "90500000feff")
	d, err := x.Decode([]byte{0x90, 0x50, 0x02, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Format(0xfffc); got != "add 0x0, 0x10000" {
		t.Fatalf("boundary decode %q", got)
	}

	if _, err := x.Assemble("mov 0,r4", 0x1fffc); err == nil {
		t.Fatal("classic signed16 offset accepted unreachable upper-memory target")
	}

	// TI SLAU367P 4.4.3.3: source 3579Ch - PC21036h =14766h;
	// destination77778h - PC21038h =56740h. Their PC bases differ by2.
	requireAssembly(t, x, "addx.b 0x3579c,0x77778", 0x21032, "c518d05066474067")
	for _, test := range []struct{ text, bytes string }{
		{"mova #0xabcde,r5", "850adebc"}, {"movx.a #0xabcde,r5", "001d7540debc"},
		{"calla #0xabcde", "ba13debc"}, {"pushm.a #2,r5", "1514"}, {"popm.a #2,r5", "1416"},
		{"rpt #3 { rrcx.w r4", "42180410"}, {"rpt pc { rrcx.w r4", "c0180410"}, {"rpt r6 { rrux.a r4", "86194410"},
	} {
		requireAssembly(t, x, test.text, 0, test.bytes)
	}
	if _, err := classic.Decode([]byte{0x40, 0x18, 0x04, 0x10}); err == nil {
		t.Fatal("classic accepted CPUX prefix")
	}
	if _, err := x.Decode([]byte{0x40, 0x18, 0x04}); !errors.Is(err, codec.ErrTruncated) {
		t.Fatalf("partial prefix: %v", err)
	}
	if _, err := classic.Assemble("mov @r2,r4", 0); err == nil {
		t.Fatal("accepted CG register as indirect memory")
	}
	if _, err := x.Assemble("rpt #3 { movx.w @r5,r4", 0); err == nil {
		t.Fatal("accepted register repetition on indirect addressing")
	}
	if _, err := x.Assemble("rpt #3 { addx.w #4,r4", 0); err == nil {
		t.Fatal("accepted register repetition on constant addressing with As!=0")
	}
	if _, err := x.Assemble("rpt #17 { rrcx.w r4", 0); err == nil {
		t.Fatal("accepted out-of-range repetition")
	}
}

func TestSymbolicTargetsKeepUnsignedAddressSpelling(t *testing.T) {
	// InputSignedBits permits lexical unsigned spellings of signed immediates.
	// A symbolic operand's text is an absolute target, even when bit15 is set.
	for _, arch := range []string{"msp430", "msp430x"} {
		t.Run(arch, func(t *testing.T) {
			c := load(t, arch)
			raw := []byte{0x90, 0x50, 0, 0x80, 0xfe, 0x7f}
			for _, at := range []uint64{0, 0x1000, 0x7ffe, 0x8000, 0xfffc, 0xfffe} {
				d, err := c.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				text := d.Format(at)
				if at == 0x1000 && text != "add 0x9002, 0x9002" {
					t.Fatalf("decoded boundary %q", text)
				}
				all, err := c.Assemble(text, at)
				if err != nil {
					t.Fatalf("%s at%x: %v", text, at, err)
				}
				found := false
				for _, b := range all {
					found = found || bytes.Equal(raw, b)
				}
				if !found {
					t.Fatalf("%s at%x: %x want%x", text, at, all, raw)
				}
			}
			requireAssembly(t, c, "rla 0x9002", 0x1000, "90500080fe7f")
			if arch == "msp430x" {
				requireAssembly(t, c, "movx.a 0xf0000,r4", 0xe0000, "00185440fcff")
				requireAssembly(t, c, "addx.a 0xf0000,0xf0002", 0xe0000, "0018d050fcfffcff")
			}
		})
	}
}

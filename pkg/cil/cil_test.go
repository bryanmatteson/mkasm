package cil

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type oracle struct {
	Runtime  string
	Metadata []struct {
		Name                           string
		Code                           uint16
		Size                           int
		Operand, Kind, Flow, Pop, Push string
	}
	Encodings []struct {
		Code  uint16
		Bytes string
	}
	DynamicMethods []struct{ Name, IL string }
	Methods        []struct {
		Name, Body, IL string
		MaxStack       uint16
		InitLocals     bool
		LocalSignature uint32
		Exceptions     []struct {
			Kind                                                                         string
			TryOffset, TryLength, HandlerOffset, HandlerLength, CatchToken, FilterOffset uint32
		}
	}
	Execution map[string]interface{}
}

func loadOracle(t *testing.T) oracle {
	t.Helper()
	b, e := os.ReadFile("testdata/oracle.json")
	if e != nil {
		t.Fatal(e)
	}
	var o oracle
	if e = json.Unmarshal(b, &o); e != nil {
		t.Fatal(e)
	}
	return o
}
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestTemplateCaptureSyntax(t *testing.T) {
	c := Default()
	for _, text := range []string{"br.s $", "br.s ${}", "br.s ${Target", "br.s $Target}", "br.s $Target!", "br.s $λ", "nop $Target"} {
		if _, err := c.ParseTemplate(text, 0); err == nil {
			t.Errorf("accepted invalid capture %q", text)
		}
	}
	for _, text := range []string{"br.s $Target", "br.s ${Target}", "br.s _"} {
		if _, err := c.ParseTemplate(text, 0); err != nil {
			t.Errorf("rejected valid capture %q: %v", text, err)
		}
	}
}
func TestRuntimeOracle(t *testing.T) {
	verifyRuntimeOracle(t, loadOracle(t))
}

func verifyRuntimeOracle(t *testing.T, o oracle) {
	t.Helper()
	c := Default()
	if len(c.Definitions) != 218 || len(o.Metadata) != len(c.Definitions) {
		t.Fatalf("definitions %d oracle %d", len(c.Definitions), len(o.Metadata))
	}
	for _, m := range o.Metadata {
		d := c.Definition(m.Code)
		if d == nil || d.Mnemonic != m.Name || d.Size != m.Size || d.Operand != m.Operand {
			t.Fatalf("metadata %#v vs %#v", d, m)
		}
		norm := func(s string) string { return strings.ToLower(strings.NewReplacer("_", "", "+", "").Replace(s)) }
		if norm(strings.TrimPrefix(d.Kind, "I")) != norm(m.Kind) || norm(d.Flow) != norm(m.Flow) || norm(d.Pop) != norm(m.Pop) || norm(d.Push) != norm(m.Push) {
			t.Fatalf("stack/flow metadata %#v vs %#v", d, m)
		}
		cnt := func(s string) int {
			if strings.EqualFold(s, "Varpop") || strings.EqualFold(s, "Varpush") {
				return -1
			}
			if s == "Pop0" || s == "Push0" {
				return 0
			}
			return len(strings.Split(s, "_"))
		}
		if d.PopCount != cnt(m.Pop) || d.PushCount != cnt(m.Push) {
			t.Fatal("stack count", d)
		}

	}
	for _, x := range o.Encodings {
		t.Run(c.Definition(x.Code).Mnemonic, func(t *testing.T) {
			b := unhex(t, x.Bytes)
			for _, at := range []uint32{0, 0x10000} {
				in, e := c.Decode(b, at)
				if e != nil {
					t.Fatal(e)
				}
				if in.Opcode != x.Code || in.Length != len(b) {
					t.Fatal(in)
				}
				out, e := c.Encode(in, at)
				if e != nil || !bytes.Equal(out, b) {
					t.Fatalf("encode %x %v", out, e)
				}
				s, e := c.Format(in)
				if e != nil {
					t.Fatal(e)
				}
				out, e = c.Assemble(s, at)
				if e != nil || !bytes.Equal(out, b) {
					t.Fatalf("text %q %x %v", s, out, e)
				}
				tpl, e := c.Template(in.Mnemonic)
				if e != nil {
					t.Fatal(e)
				}
				out, e = tpl.Encode(in.Operand, at)
				if e != nil || !bytes.Equal(out, b) {
					t.Fatalf("template encode %x %v", out, e)
				}
				if _, ok := tpl.Match(b, at); !ok {
					t.Fatal("template match")
				}
				if e = tpl.Bind(in.Operand); e != nil {
					t.Fatal(e)
				}
				out, e = tpl.Encode(nil, at)
				if e != nil || !bytes.Equal(out, b) {
					t.Fatal("bound template", e)
				}
				for n := 0; n < len(b); n++ {
					if _, e = c.Decode(b[:n], at); !errors.Is(e, ErrTruncated) {
						t.Fatalf("truncate %d %v", n, e)
					}
				}
			}
		})
	}
	if o.Execution["generic"] != "123" || o.Execution["unaligned"] != float64(67305985) || o.Execution["filter"] != float64(-31) {
		t.Fatal("real execution evidence", o.Execution)
	}
}
func TestRealMethods(t *testing.T) {
	verifyMethodOracle(t, loadOracle(t))
}

func verifyMethodOracle(t *testing.T, o oracle) {
	t.Helper()
	c := Default()
	tiny, fat, smallEH, fatEH := false, false, false, false
	for _, m := range o.Methods {
		t.Run(m.Name, func(t *testing.T) {
			raw := unhex(t, m.Body)
			b, e := c.DecodeMethodBody(raw)
			if e != nil {
				t.Fatal(e)
			}
			if b.Length != len(raw) || !bytes.Equal(b.Code, unhex(t, m.IL)) || b.MaxStack != m.MaxStack || b.InitLocals != m.InitLocals || b.LocalSignatureToken != m.LocalSignature {
				t.Fatalf("body metadata %+v", b)
			}
			tiny = tiny || b.Tiny
			fat = fat || !b.Tiny
			var clauses []ExceptionClause
			for _, s := range b.Sections {
				smallEH = smallEH || !s.Fat
				fatEH = fatEH || s.Fat
				clauses = append(clauses, s.Clauses...)
			}
			if len(clauses) != len(m.Exceptions) {
				t.Fatal("EH count")
			}
			for i, x := range clauses {
				q := m.Exceptions[i]
				flags := map[string]uint32{"Catch": 0, "Filter": 1, "Finally": 2, "Fault": 4}[q.Kind]
				v := q.CatchToken
				if flags == 1 {
					v = q.FilterOffset
				}
				if x != (ExceptionClause{flags, q.TryOffset, q.TryLength, q.HandlerOffset, q.HandlerLength, v}) {
					t.Fatalf("EH %+v vs %+v", x, q)
				}
			}
			out, e := c.EncodeMethodBody(b)
			if e != nil || !bytes.Equal(out, raw) {
				t.Fatalf("body roundtrip %v", e)
			}
			text, e := c.FormatMethod(b.Instructions)
			if e != nil {
				t.Fatal(e)
			}
			out, e = c.AssembleMethod(text)
			if e != nil || !bytes.Equal(out, b.Code) {
				t.Fatalf("method text %v\n%s", e, text)
			}
			for n := 0; n < len(raw); n++ {
				if _, e = c.DecodeMethodBody(raw[:n]); e == nil {
					t.Fatalf("accepted truncated body %d", n)
				}
			}
		})
	}
	if !tiny || !fat || !smallEH || !fatEH {
		t.Fatalf("missing format coverage tiny%v fat%v smallEH%v fatEH%v", tiny, fat, smallEH, fatEH)
	}
	for _, m := range o.DynamicMethods {
		code := unhex(t, m.IL)
		in, e := c.DecodeMethod(code)
		if e != nil {
			t.Fatal(m.Name, e)
		}
		out, e := c.EncodeMethod(in)
		if e != nil || !bytes.Equal(code, out) {
			t.Fatal(m.Name, e)
		}
	}
}
func TestMalformed(t *testing.T) {
	c := Default()
	for _, s := range []string{"24", "fe19", "ff", "feff", "fe1200", "7200000070", "4501000000"} {
		if _, e := c.Decode(unhex(t, s), 0); e == nil {
			t.Fatal("accepted invalid", s)
		}
	}
	for _, s := range []string{"br.s IL_1000", "ldc.i4.s 128", "ldarg.s -1", "ldarg 65536", "unaligned. 3", "call 0x02000001", "ldstr 0x70000000", "nop 1", "switch (IL_0,, IL_1)", "ldc.r4 bits(0x100000000)"} {
		if _, e := c.Assemble(s, 0); e == nil {
			t.Fatal("accepted text", s)
		}
	}
	for _, s := range []string{"fe13", "fe13fe134a2a", "fe142a", "fe16010000022a", "2bff2a", "2b02fe134a2a", "4501000000010000002a"} {
		if _, e := c.DecodeMethod(unhex(t, s)); e == nil {
			t.Fatal("accepted method", s)
		}
	}
	for _, s := range []string{"00", "03300000010000000000000024", "032000000000000000000000", "1b30000001000000000000002a00000001040001", "1b30000001000000000000002a00000002040000"} {
		if _, e := c.DecodeMethodBody(unhex(t, s)); e == nil {
			t.Fatal("accepted body", s)
		}
	}
	if _, e := Parse(strings.NewReader("OPDEF(broken)"), "cil"); e == nil {
		t.Fatal("bad source")
	}
}
func TestLabelsAndTemplates(t *testing.T) {
	c := Default()
	code, e := c.AssembleMethod("start: ldc.i4.0\nswitch (start, done)\nbr.s start\ndone: ret")
	if e != nil {
		t.Fatal(e)
	}
	in, e := c.DecodeMethod(code)
	if e != nil {
		t.Fatal(e)
	}
	if len(in[1].BranchTargets()) != 2 {
		t.Fatal(in)
	}
	tpl, e := c.ParseTemplate("ldc.i4 $value", 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tpl.Encode(&Operand{Kind: "integer", Value: 42}, 0); e != nil {
		t.Fatal(e)
	}
	s, e := c.ParseTemplate("switch (IL_0000)", 0)
	if e != nil {
		t.Fatal(e)
	}
	out, e := s.Encode(nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := s.Match(out, 0); !ok {
		t.Fatal("bound switch")
	}
}

func TestExceptionFormatsAndNesting(t *testing.T) {
	c := Default()
	code, e := c.AssembleMethod("nop\nleave.s end\npop\nleave.s end\nnop\nendfinally\nend: ret")
	if e != nil {
		t.Fatal(e)
	}
	// One catch entry, followed by a disjoint fault entry; verify chain format and padding bytes.
	sections := []ExceptionSection{{Clauses: []ExceptionClause{{Flags: 0, TryOffset: 0, TryLength: 1, HandlerOffset: 3, HandlerLength: 1, ClassTokenOrFilterOffset: 0x01000001}}}, {Fat: true, Clauses: []ExceptionClause{{Flags: 4, TryOffset: 6, TryLength: 1, HandlerOffset: 7, HandlerLength: 1}}}}
	b := &MethodBody{MaxStack: 2, Code: code, Sections: sections}
	raw, e := c.EncodeMethodBody(b)
	if e != nil {
		t.Fatal(e)
	}
	x, e := c.DecodeMethodBody(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(x.Sections) != 2 || x.Sections[0].Fat || !x.Sections[1].Fat {
		t.Fatal(x)
	}
	out, e := c.EncodeMethodBody(x)
	if e != nil || !bytes.Equal(out, raw) {
		t.Fatal("chain roundtrip", e)
	}
	// Structural overlap and invalid filter termination must be rejected.
	b.Sections[0].Clauses[0].HandlerOffset = 0
	if _, e = c.EncodeMethodBody(b); e == nil {
		t.Fatal("overlap accepted")
	}
	b.Sections[0].Clauses[0].HandlerOffset = 3
	b.Sections[0].Clauses[0].Flags = 1
	b.Sections[0].Clauses[0].ClassTokenOrFilterOffset = 1
	if _, e = c.EncodeMethodBody(b); e == nil {
		t.Fatal("filter without endfilter accepted")
	}
}
func TestScalarBoundaries(t *testing.T) {
	c := Default()
	for name, values := range map[string][]int64{"ldc.i4.s": {-128, 127}, "ldc.i4": {-2147483648, 2147483647}, "ldc.i8": {-9223372036854775808, 9223372036854775807}, "ldarg.s": {0, 255}, "ldarg": {0, 65535}, "unaligned.": {1, 2, 4}} {
		for _, v := range values {
			d := c.Lookup(name)
			in := &Instruction{Opcode: d.Opcode, Operand: &Operand{Kind: d.OperandKind, Value: v}}
			b, e := c.Encode(in, 0)
			if e != nil {
				t.Fatal(name, v, e)
			}
			out, e := c.Decode(b, 0)
			if e != nil || out.Operand.Value != v {
				t.Fatal(name, v, e)
			}
		}
	}
	for _, text := range []string{"br -9223372036854775808", "switch (-9223372036854775808)", "nop _"} {
		var e error
		if text == "nop _" {
			_, e = c.ParseTemplate(text, 0)
		} else {
			_, e = c.Assemble(text, 0)
		}
		if e == nil {
			t.Fatal(text)
		}
	}
}

func TestEmptySwitchTemplate(t *testing.T) {
	c := Default()
	tpl, e := c.Template("switch")
	if e != nil {
		t.Fatal(e)
	}
	if e = tpl.Bind(&Operand{Kind: "switch"}); e != nil {
		t.Fatal(e)
	}
	b, e := tpl.Encode(nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := tpl.Match(b, 0); !ok {
		t.Fatal("nil and empty switch target lists must have identical meaning")
	}
}
func FuzzMethodBody(f *testing.F) {
	for _, s := range []string{"02", "062a", "1b30000001000000000000002a00000001040000", "fe", "4500000000"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c := Default()
		if body, e := c.DecodeMethodBody(b); e == nil {
			out, e := c.EncodeMethodBody(body)
			if e != nil || !bytes.Equal(out, b[:body.Length]) {
				t.Fatalf("body loss %x %v", b, e)
			}
		}
		if in, e := c.Decode(b, 0); e == nil {
			out, e := c.Encode(in, 0)
			if e != nil || !bytes.Equal(out, b[:in.Length]) {
				t.Fatalf("instruction loss %x %v", b, e)
			}
		}
	})
}

func TestFloatBitPatterns(t *testing.T) {
	c := Default()
	for name, patterns := range map[string][]uint64{"ldc.r4": {0, 0x80000000, 0x7f800000, 0xff800000, 0x7fc12345, 0xffffffff}, "ldc.r8": {0, 0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff0000000000001, 0xffffffffffffffff}} {
		d := c.Lookup(name)
		for _, bits := range patterns {
			in := &Instruction{Opcode: d.Opcode, Operand: &Operand{Kind: d.OperandKind, Bits: bits}}
			b, e := c.Encode(in, 0)
			if e != nil {
				t.Fatal(e)
			}
			x, e := c.Decode(b, 0)
			if e != nil || x.Operand.Bits != bits {
				t.Fatal(name, bits, e)
			}
			text, e := c.Format(x)
			if e != nil {
				t.Fatal(e)
			}
			out, e := c.Assemble(text, 0)
			if e != nil || !bytes.Equal(out, b) {
				t.Fatal(name, bits, e)
			}
		}
	}
}

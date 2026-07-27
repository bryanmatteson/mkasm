package asl_test

import (
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/asl"
)

// umovSource is the UMOV encoding as mra_tools emits it. It exercises every
// construct the encoder needs: declared fields, an opcode pattern, a case over
// a concatenation of two fields, mask patterns with don't-cares, and a slice
// whose bounds are themselves expressions.
const umovSource = `__instruction aarch64_vector_transfer_integer_move_unsigned
    __encoding aarch64_vector_transfer_integer_move_unsigned
        __instruction_set A64
        __field Q 30 +: 1
        __field imm5 16 +: 5
        __field Rn 5 +: 5
        __field Rd 0 +: 5
        __opcode '0x001110 000xxxxx 001111xx xxxxxxxx'
        __guard TRUE
        __decode
            integer d = UInt(Rd);
            integer n = UInt(Rn);

            integer size;
            case Q:imm5 of
                when '0xxxx1' size = 0;     // UMOV Wd, Vn.B
                when '0xxx10' size = 1;     // UMOV Wd, Vn.H
                when '1x1000' size = 3;     // UMOV Xd, Vn.D
                otherwise     UNDEFINED;

            integer idxdsize = if imm5<4> == '1' then 128 else 64;
            integer index = UInt(imm5<4:size+1>);
            integer esize = 8 << size;

    __execute
        CheckFPAdvSIMDEnabled64();
        bits(idxdsize) operand = V[n];

        X[d] = ZeroExtend(Elem[operand, index, esize], datasize);
`

func TestParseUmov(t *testing.T) {
	instrs, err := asl.ParseInstructions(umovSource)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(instrs) != 1 || len(instrs[0].Encodings) != 1 {
		t.Fatalf("got %d instructions", len(instrs))
	}
	enc := instrs[0].Encodings[0]

	if enc.Set != "A64" {
		t.Errorf("instruction set = %q", enc.Set)
	}
	if len(enc.Opcode) != 32 {
		t.Errorf("opcode %q has %d bits, want 32", enc.Opcode, len(enc.Opcode))
	}
	want := []asl.Field{
		{Name: "Q", Lo: 30, Width: 1}, {Name: "imm5", Lo: 16, Width: 5},
		{Name: "Rn", Lo: 5, Width: 5}, {Name: "Rd", Lo: 0, Width: 5},
	}
	if len(enc.Fields) != len(want) {
		t.Fatalf("got %d fields, want %d", len(enc.Fields), len(want))
	}
	for i, f := range enc.Fields {
		if f != want[i] {
			t.Errorf("field %d = %+v, want %+v", i, f, want[i])
		}
	}

	// The decode body is what prose cannot express, so check its shape closely.
	var caseStmt *asl.Case
	var index *asl.Assign
	for _, s := range enc.Decode {
		switch v := s.(type) {
		case *asl.Case:
			caseStmt = v
		case *asl.Assign:
			if tgt, ok := v.Target.(*asl.Var); ok && tgt.Name == "index" {
				index = v
			}
		}
	}
	if caseStmt == nil {
		t.Fatal("no case statement in decode")
	}
	// The subject must be a concatenation, not a comparison or a member access:
	// this is what ties the element size to bits of two different fields.
	if got := asl.String(caseStmt.Subject); got != "Q : imm5" {
		t.Errorf("case subject = %q, want %q", got, "Q : imm5")
	}
	if len(caseStmt.Alts) != 4 {
		t.Fatalf("got %d case alternatives, want 4", len(caseStmt.Alts))
	}
	if p := caseStmt.Alts[0].Patterns[0]; p.Kind != asl.MASK || p.Text != "0xxxx1" {
		t.Errorf("first pattern = %v %q, want MASK 0xxxx1", p.Kind, p.Text)
	}
	if !caseStmt.Alts[3].Otherwise {
		t.Error("last alternative should be otherwise")
	}
	if _, ok := caseStmt.Alts[3].Body[0].(*asl.Undefined); !ok {
		t.Errorf("otherwise body = %T, want UNDEFINED", caseStmt.Alts[3].Body[0])
	}

	if index == nil {
		t.Fatal("no index binding in decode")
	}
	// A slice whose high bound is a literal and low bound an expression is the
	// exact shape an encoder has to invert.
	if got := asl.String(index.Value); got != "UInt(imm5<4:size + 1>)" {
		t.Errorf("index = %q, want %q", got, "UInt(imm5<4:size + 1>)")
	}
}

// TestLessThanIsNotASlice pins the one genuine ambiguity in the grammar: "<"
// opens a bit slice and also compares. Reading "size < 3" as a slice would
// silently swallow the rest of the expression.
func TestLessThanIsNotASlice(t *testing.T) {
	src := `__instruction t
    __encoding t
        __instruction_set A64
        __field size 22 +: 2
        __opcode '00000000 00000000 00000000 00000000'
        __guard TRUE
        __decode
            boolean small = size < 3;
            integer hi = UInt(size<1>);

    __execute
        X[0] = 0;
`
	instrs, err := asl.ParseInstructions(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	body := instrs[0].Encodings[0].Decode
	if len(body) != 2 {
		t.Fatalf("got %d statements, want 2", len(body))
	}
	cmp := body[0].(*asl.Assign)
	if got := asl.String(cmp.Value); got != "size < 3" {
		t.Errorf("comparison parsed as %q, want %q", got, "size < 3")
	}
	if _, ok := cmp.Value.(*asl.BinOp); !ok {
		t.Errorf("comparison is %T, want a binary operation", cmp.Value)
	}
	sl := body[1].(*asl.Assign)
	if got := asl.String(sl.Value); got != "UInt(size<1>)" {
		t.Errorf("slice parsed as %q, want %q", got, "UInt(size<1>)")
	}
}

// TestUnpredictableUnless checks the declared form of a constraint the XML
// states only in prose.
func TestUnpredictableUnless(t *testing.T) {
	src := `__instruction t
    __encoding t
        __instruction_set A64
        __field Rt 0 +: 5
        __opcode '00000000 00000000 00000000 00000000'
        __guard TRUE
        __unpredictable_unless 12 == '0'
        __unpredictable_unless 13 == '1'
        __decode
            integer t = UInt(Rt);

    __execute
        X[0] = 0;
`
	instrs, err := asl.ParseInstructions(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := instrs[0].Encodings[0].Unpredictable
	if len(got) != 2 || got[0] != (asl.UnpredictableUnless{Bit: 12, Value: "0"}) ||
		got[1] != (asl.UnpredictableUnless{Bit: 13, Value: "1"}) {
		t.Errorf("unpredictable_unless = %+v", got)
	}
}

func TestLexBitLiterals(t *testing.T) {
	toks, err := asl.Lex("'0x00 1111' '0101' 0x2a 42 4.2 0..3")
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	var got []string
	for _, tk := range toks {
		if tk.Kind == asl.EOF {
			break
		}
		got = append(got, tk.Kind.String()+":"+tk.Text)
	}
	// Spaces inside a bit literal group digits and carry no meaning; "0..3" is a
	// range, not a real number followed by a fraction.
	want := "MASK:0x001111 BIN:0101 HEX:0x2a NAT:42 REAL:4.2 NAT:0 PUNCT:.. NAT:3"
	if strings.Join(got, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
}

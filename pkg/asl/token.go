// Package asl parses ARM's Specification Language, the machine-readable form of
// the pseudocode ARM also publishes as prose inside the instruction XML.
//
// The XML states an operand's encoding in English — "is the element index,
// encoded in Q:S:size" — and leaves the relations between operands implicit.
// The ASL states them as code:
//
//	__field imm5 16 +: 5
//	__opcode '0x001110 000xxxxx 001111xx xxxxxxxx'
//	__decode
//	    case Q:imm5 of
//	        when '0xxxx1' size = 0;
//	    integer index = UInt(imm5<4:size+1>);
//
// Field positions are declared rather than inferred from table cells, and the
// couplings that prose cannot express — an element size and an index sharing one
// field — are ordinary expressions.
//
// The grammar implemented here follows ASL.g4 from the asl-parser project, which
// is ANTLR's rendering of the language mra_tools emits.
package asl

import "fmt"

// Kind is a token class.
type Kind int

const (
	EOF Kind = iota
	// INDENT and DEDENT are synthesised: ASL takes its block structure from
	// layout, so the lexer has to turn columns into brackets.
	INDENT
	DEDENT
	IDENT
	NAT    // 42
	HEX    // 0x2a
	REAL   // 4.2
	BIN    // '0101'
	MASK   // '0x1x' — a bit pattern with don't-cares
	STRING // "text"
	SEE    // SEE <anything up to ;>
	PUNCT  // operators and separators
)

var kindNames = map[Kind]string{
	EOF: "EOF", INDENT: "INDENT", DEDENT: "DEDENT", IDENT: "IDENT",
	NAT: "NAT", HEX: "HEX", REAL: "REAL", BIN: "BIN", MASK: "MASK",
	STRING: "STRING", SEE: "SEE", PUNCT: "PUNCT",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Token is one lexeme with the position it came from.
type Token struct {
	Kind Kind
	// Text is the lexeme. Quotes are stripped from BIN, MASK and STRING, and
	// spaces are stripped from BIN and MASK, so '0x00 1111' reads as "0x001111".
	Text string
	Line int
	Col  int
}

func (t Token) String() string {
	return fmt.Sprintf("%s(%q) at %d:%d", t.Kind, t.Text, t.Line, t.Col)
}

// is reports whether the token is a specific piece of punctuation.
func (t Token) is(text string) bool { return t.Kind == PUNCT && t.Text == text }

// isWord reports whether the token is a specific bare word. ASL has no reserved
// words in the lexer: "case" and "of" are identifiers the parser recognises by
// position.
func (t Token) isWord(text string) bool { return t.Kind == IDENT && t.Text == text }

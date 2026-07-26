package asl

import (
	"fmt"
	"strings"
)

// Instruction is one __instruction block: a family of encodings sharing an
// execute body.
type Instruction struct {
	Name      string
	Encodings []Encoding
}

// Encoding is one __encoding block — one addressable encoding of the ISA.
type Encoding struct {
	Name string
	// Set is the instruction set: A64, A32, T32 or T16.
	Set string
	// Fields are the named bit ranges, declared rather than inferred.
	Fields []Field
	// Opcode is the 32-character bit pattern, using 0, 1 and x.
	Opcode string
	// Guard is the condition under which this encoding applies.
	Guard Expr
	// Unpredictable lists bits whose value is required for the encoding to be
	// predictable: "__unpredictable_unless 12 == '0'".
	Unpredictable []UnpredictableUnless
	// Decode is the decode body, which binds operand names to field expressions.
	Decode []Stmt
	Line   int
}

// Field is a named bit range of the instruction word.
type Field struct {
	Name string
	// Lo is the least significant bit, Width the number of bits, so a field
	// declared "16 +: 5" covers bits 16 through 20.
	Lo, Width int
}

// Hi is the most significant bit of the field.
func (f Field) Hi() int { return f.Lo + f.Width - 1 }

// UnpredictableUnless is a bit the encoding requires to hold a given value.
type UnpredictableUnless struct {
	Bit   int
	Value string
}

// --- statements ---

// Stmt is one statement of a decode body.
type Stmt interface{ stmt() }

// VarDecl declares variables without initialising them.
type VarDecl struct {
	Type  string
	Names []string
}

// Assign binds a name to a value; Decl marks a declaration with initialiser,
// Const marks it constant. The three are one node because the encoder only
// cares that a name now stands for an expression.
type Assign struct {
	Target Expr
	Value  Expr
	Type   string
	Decl   bool
	Const  bool
}

// Case is a match on an expression, the form ASL uses to tie an element size to
// the bits of a field it shares with another operand.
type Case struct {
	Subject Expr
	Alts    []CaseAlt
}

// CaseAlt is one arm. Otherwise is true for the default arm.
type CaseAlt struct {
	Patterns  []Pattern
	Guard     Expr // the optional "&& expr" refinement
	Body      []Stmt
	Otherwise bool
}

// Pattern is one case label.
type Pattern struct {
	// Kind is NAT, HEX, BIN, MASK or IDENT; Ignore is true for "-".
	Kind   Kind
	Text   string
	Ignore bool
	Tuple  []Pattern
}

// If is a conditional, with Elsifs flattened into ElseIf pairs.
type If struct {
	Cond   Expr
	Then   []Stmt
	Elsifs []ElseIf
	Else   []Stmt
}

// ElseIf is one elsif arm.
type ElseIf struct {
	Cond Expr
	Then []Stmt
}

// Call is a statement-position function call.
type Call struct {
	Name string
	Args []Expr
}

// Undefined marks the encoding invalid for the values reaching it.
type Undefined struct{}

// Unpredictable marks the behaviour architecturally unpredictable.
type Unpredictable struct{}

// See defers to another instruction page.
type See struct{ Text string }

// Assert is a checked invariant.
type Assert struct{ Cond Expr }

func (*VarDecl) stmt()       {}
func (*Assign) stmt()        {}
func (*Case) stmt()          {}
func (*If) stmt()            {}
func (*Call) stmt()          {}
func (*Undefined) stmt()     {}
func (*Unpredictable) stmt() {}
func (*See) stmt()           {}
func (*Assert) stmt()        {}

// --- expressions ---

// Expr is an ASL expression.
type Expr interface{ expr() }

// Lit is a literal. Kind distinguishes NAT, HEX, BIN, MASK, REAL and STRING.
type Lit struct {
	Kind Kind
	Text string
}

// Var is a name reference, qualified for AArch64.X style calls.
type Var struct{ Name string }

// CallExpr is a function application. UInt dominates decode bodies.
type CallExpr struct {
	Name string
	Args []Expr
}

// BinOp is a binary operation. ":" is bit concatenation, which is what makes a
// case subject like "Q:imm5" a pattern over two fields at once.
type BinOp struct {
	Op          string
	Left, Right Expr
}

// UnOp is a prefix operation: -, ! or NOT.
type UnOp struct {
	Op      string
	Operand Expr
}

// SliceExpr takes bits out of a value: imm5<4:size+1>.
type SliceExpr struct {
	Value  Expr
	Slices []Slice
}

// IndexExpr indexes an array or register bank: V[n].
type IndexExpr struct {
	Value  Expr
	Slices []Slice
}

// Slice is one bit selection. A range has Hi and Lo; an offset has Base and
// Count, as in "16 +: 5"; a single bit has only Hi.
type Slice struct {
	Hi, Lo Expr
	Base   Expr
	Count  Expr
	Offset bool
	Single bool
}

// Member selects a struct field.
type Member struct {
	Value Expr
	Name  string
}

// InMask tests a value against a bit pattern with don't-cares.
type InMask struct {
	Value Expr
	Mask  string
}

// InSet tests membership of a set of values or ranges.
type InSet struct {
	Value    Expr
	Elements []SetElement
}

// SetElement is one member of a set, either a value or an inclusive range.
type SetElement struct {
	Value   Expr
	Lo, Hi  Expr
	IsRange bool
}

// IfExpr is a conditional expression.
type IfExpr struct {
	Cond   Expr
	Then   Expr
	Elsifs []ElseIfExpr
	Else   Expr
}

// ElseIfExpr is one elsif arm of a conditional expression.
type ElseIfExpr struct {
	Cond Expr
	Then Expr
}

// Tuple is a parenthesised list, used for multi-value case subjects.
type Tuple struct{ Elements []Expr }

// Unknown is "bits(N) UNKNOWN" and friends.
type Unknown struct{ Type string }

// Ignore is the "-" placeholder in a tuple assignment, which discards one
// result: "(imm, -) = DecodeBitMasks(N, imms, immr, TRUE)".
type Ignore struct{}

func (*Lit) expr()       {}
func (*Var) expr()       {}
func (*CallExpr) expr()  {}
func (*BinOp) expr()     {}
func (*UnOp) expr()      {}
func (*SliceExpr) expr() {}
func (*IndexExpr) expr() {}
func (*Member) expr()    {}
func (*InMask) expr()    {}
func (*InSet) expr()     {}
func (*IfExpr) expr()    {}
func (*Tuple) expr()     {}
func (*Unknown) expr()   {}
func (*Ignore) expr()    {}

// String renders an expression close to its ASL source, for tests and errors.
func String(e Expr) string {
	switch v := e.(type) {
	case nil:
		return ""
	case *Lit:
		switch v.Kind {
		case BIN, MASK:
			return "'" + v.Text + "'"
		case STRING:
			return `"` + v.Text + `"`
		}
		return v.Text
	case *Var:
		return v.Name
	case *CallExpr:
		return v.Name + "(" + joinExprs(v.Args) + ")"
	case *BinOp:
		return String(v.Left) + " " + v.Op + " " + String(v.Right)
	case *UnOp:
		return v.Op + String(v.Operand)
	case *SliceExpr:
		return String(v.Value) + "<" + joinSlices(v.Slices) + ">"
	case *IndexExpr:
		return String(v.Value) + "[" + joinSlices(v.Slices) + "]"
	case *Member:
		return String(v.Value) + "." + v.Name
	case *InMask:
		return String(v.Value) + " IN '" + v.Mask + "'"
	case *InSet:
		return String(v.Value) + " IN {...}"
	case *IfExpr:
		return "if " + String(v.Cond) + " then " + String(v.Then) + " else " + String(v.Else)
	case *Tuple:
		return "(" + joinExprs(v.Elements) + ")"
	case *Unknown:
		return v.Type + " UNKNOWN"
	case *Ignore:
		return "-"
	}
	return fmt.Sprintf("%T", e)
}

func joinExprs(es []Expr) string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		parts = append(parts, String(e))
	}
	return strings.Join(parts, ", ")
}

func joinSlices(ss []Slice) string {
	parts := make([]string, 0, len(ss))
	for _, s := range ss {
		switch {
		case s.Offset:
			parts = append(parts, String(s.Base)+" +: "+String(s.Count))
		case s.Single:
			parts = append(parts, String(s.Hi))
		default:
			parts = append(parts, String(s.Hi)+":"+String(s.Lo))
		}
	}
	return strings.Join(parts, ", ")
}

package asl

import (
	"fmt"
	"strconv"
	"strings"
)

// typeWords are the type names a declaration can start with. ASL declares
// locals as "integer d = UInt(Rd);", so a statement beginning with one of these
// is a declaration rather than an assignment to an existing name.
var typeWords = map[string]bool{
	"integer": true, "boolean": true, "bit": true, "bits": true, "real": true,
	"string": true, "array": true,
}

// parser walks the token stream produced by Lex.
type parser struct {
	toks []Token
	pos  int
}

// ParseInstructions parses an arm_instrs.asl file.
func ParseInstructions(src string) ([]Instruction, error) {
	toks, err := Lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var out []Instruction
	for !p.at(EOF) {
		if !p.cur().isWord("__instruction") {
			return nil, p.errf("expected __instruction, got %s", p.cur())
		}
		instr, err := p.instruction()
		if err != nil {
			return nil, err
		}
		out = append(out, *instr)
	}
	return out, nil
}

// --- token helpers ---

func (p *parser) cur() Token     { return p.toks[p.pos] }
func (p *parser) at(k Kind) bool { return p.toks[p.pos].Kind == k }
func (p *parser) advance() Token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) accept(text string) bool {
	if p.cur().is(text) || p.cur().isWord(text) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) expect(text string) error {
	if p.accept(text) {
		return nil
	}
	return p.errf("expected %q, got %s", text, p.cur())
}

func (p *parser) expectKind(k Kind) (Token, error) {
	if p.cur().Kind != k {
		return Token{}, p.errf("expected %s, got %s", k, p.cur())
	}
	return p.advance(), nil
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("line %d:%d: %s", p.cur().Line, p.cur().Col, fmt.Sprintf(format, args...))
}

// skipBlock consumes a balanced INDENT…DEDENT region without interpreting it.
// The execute body describes what an instruction does at run time, which the
// encoder has no use for.
func (p *parser) skipBlock() {
	if !p.at(INDENT) {
		return
	}
	depth := 0
	for {
		switch {
		case p.at(INDENT):
			depth++
		case p.at(DEDENT):
			depth--
		case p.at(EOF):
			return
		}
		p.advance()
		if depth == 0 {
			return
		}
	}
}

// --- structure ---

func (p *parser) instruction() (*Instruction, error) {
	if err := p.expect("__instruction"); err != nil {
		return nil, err
	}
	name, err := p.dottedName()
	if err != nil {
		return nil, err
	}
	instr := &Instruction{Name: name}
	if _, err := p.expectKind(INDENT); err != nil {
		return nil, err
	}
	for p.cur().isWord("__encoding") {
		enc, err := p.encoding()
		if err != nil {
			return nil, err
		}
		instr.Encodings = append(instr.Encodings, *enc)
	}
	if p.accept("__postdecode") {
		p.skipBlock()
	}
	if p.accept("__execute") {
		p.accept("__conditional")
		p.skipBlock()
	}
	if _, err := p.expectKind(DEDENT); err != nil {
		return nil, err
	}
	return instr, nil
}

func (p *parser) encoding() (*Encoding, error) {
	line := p.cur().Line
	if err := p.expect("__encoding"); err != nil {
		return nil, err
	}
	name, err := p.dottedName()
	if err != nil {
		return nil, err
	}
	enc := &Encoding{Name: name, Line: line}
	if _, err := p.expectKind(INDENT); err != nil {
		return nil, err
	}
	if err := p.expect("__instruction_set"); err != nil {
		return nil, err
	}
	set, err := p.expectKind(IDENT)
	if err != nil {
		return nil, err
	}
	enc.Set = set.Text

	for p.cur().isWord("__field") {
		p.advance()
		fname, err := p.expectKind(IDENT)
		if err != nil {
			return nil, err
		}
		lo, err := p.natValue()
		if err != nil {
			return nil, err
		}
		if err := p.expect("+:"); err != nil {
			return nil, err
		}
		width, err := p.natValue()
		if err != nil {
			return nil, err
		}
		enc.Fields = append(enc.Fields, Field{Name: fname.Text, Lo: lo, Width: width})
	}

	if err := p.expect("__opcode"); err != nil {
		return nil, err
	}
	if p.cur().Kind != BIN && p.cur().Kind != MASK {
		return nil, p.errf("expected an opcode pattern, got %s", p.cur())
	}
	enc.Opcode = p.advance().Text

	if err := p.expect("__guard"); err != nil {
		return nil, err
	}
	if enc.Guard, err = p.expr(); err != nil {
		return nil, err
	}

	for p.cur().isWord("__unpredictable_unless") {
		p.advance()
		bit, err := p.natValue()
		if err != nil {
			return nil, err
		}
		if err := p.expect("=="); err != nil {
			return nil, err
		}
		val, err := p.expectKind(BIN)
		if err != nil {
			return nil, err
		}
		enc.Unpredictable = append(enc.Unpredictable, UnpredictableUnless{Bit: bit, Value: val.Text})
	}

	if err := p.expect("__decode"); err != nil {
		return nil, err
	}
	if p.at(INDENT) {
		if enc.Decode, err = p.block(); err != nil {
			return nil, err
		}
	}
	if _, err := p.expectKind(DEDENT); err != nil {
		return nil, err
	}
	return enc, nil
}

// dottedName reads an identifier that may carry dotted segments, as encoding
// names do: "LDNT1D_Z.P.BR_Contiguous".
func (p *parser) dottedName() (string, error) {
	first, err := p.expectKind(IDENT)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(first.Text)
	for p.cur().is(".") {
		p.advance()
		b.WriteByte('.')
		if p.at(IDENT) || p.at(NAT) {
			b.WriteString(p.advance().Text)
		}
	}
	return b.String(), nil
}

func (p *parser) natValue() (int, error) {
	t, err := p.expectKind(NAT)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(t.Text)
	if err != nil {
		return 0, p.errf("bad number %q", t.Text)
	}
	return n, nil
}

// --- statements ---

func (p *parser) block() ([]Stmt, error) {
	if _, err := p.expectKind(INDENT); err != nil {
		return nil, err
	}
	var out []Stmt
	for !p.at(DEDENT) && !p.at(EOF) {
		s, err := p.stmt()
		if err != nil {
			return nil, err
		}
		if s != nil {
			out = append(out, s)
		}
	}
	if _, err := p.expectKind(DEDENT); err != nil {
		return nil, err
	}
	return out, nil
}

// body reads either an indented block or the statements written inline after a
// "when" or "then" on the same line.
func (p *parser) body() ([]Stmt, error) {
	if p.at(INDENT) {
		return p.block()
	}
	// An inline body may hold several statements separated by semicolons —
	// "when '110' rounding = FPRoundingMode(FPCR); exact = TRUE;" — so it runs
	// to the end of the source line rather than to the first statement.
	var out []Stmt
	line := p.cur().Line
	for p.cur().Line == line && !p.at(DEDENT) && !p.at(EOF) && !p.at(INDENT) &&
		!p.cur().isWord("when") && !p.cur().isWord("otherwise") &&
		!p.cur().isWord("elsif") && !p.cur().isWord("else") {
		s, err := p.stmt()
		if err != nil {
			return nil, err
		}
		if s != nil {
			out = append(out, s)
		}
	}
	return out, nil
}

func (p *parser) stmt() (Stmt, error) {
	switch {
	case p.cur().isWord("case"):
		return p.caseStmt()
	case p.cur().isWord("if"):
		return p.ifStmt()
	}

	s, err := p.simpleStmt()
	if err != nil {
		return nil, err
	}
	p.accept(";")
	return s, nil
}

func (p *parser) simpleStmt() (Stmt, error) {
	switch {
	case p.cur().isWord("UNDEFINED"):
		p.advance()
		return &Undefined{}, nil
	case p.cur().isWord("UNPREDICTABLE"):
		p.advance()
		return &Unpredictable{}, nil
	case p.at(SEE):
		return &See{Text: p.advance().Text}, nil
	case p.cur().isWord("assert"):
		p.advance()
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		return &Assert{Cond: e}, nil
	case p.cur().isWord("constant"):
		p.advance()
		return p.declaration(true)
	}

	// A declaration starts with a type name; anything else is an assignment or
	// a call.
	if p.at(IDENT) && p.isTypeStart() {
		return p.declaration(false)
	}

	start := p.pos
	target, err := p.expr()
	if err != nil {
		return nil, err
	}
	if p.accept("=") {
		value, err := p.expr()
		if err != nil {
			return nil, err
		}
		return &Assign{Target: target, Value: value}, nil
	}
	if call, ok := target.(*CallExpr); ok {
		return &Call{Name: call.Name, Args: call.Args}, nil
	}
	p.pos = start
	return nil, p.errf("expected an assignment or call, got %s", p.cur())
}

// isTypeStart reports whether the current identifier begins a type, looking
// ahead far enough to tell "integer d = …" from "d = …" and from a call.
func (p *parser) isTypeStart() bool {
	name := p.cur().Text
	if typeWords[name] {
		return true
	}
	// A user-defined type such as "FPRounding rounding;" is two identifiers in
	// a row. A call or an assignment never is.
	if p.pos+1 < len(p.toks) && p.toks[p.pos+1].Kind == IDENT {
		return true
	}
	return false
}

func (p *parser) declaration(isConst bool) (Stmt, error) {
	typeName := p.advance().Text
	// "bits(N) x" and "array [a..b] of T x" carry a parameter before the name.
	if p.cur().is("(") {
		depth := 0
		for {
			if p.cur().is("(") {
				depth++
			}
			if p.cur().is(")") {
				depth--
			}
			if p.at(EOF) {
				return nil, p.errf("unterminated type parameter")
			}
			typeName += p.advance().Text
			if depth == 0 {
				break
			}
		}
	}
	first, err := p.expectKind(IDENT)
	if err != nil {
		return nil, err
	}
	names := []string{first.Text}
	for p.cur().is(",") {
		p.advance()
		n, err := p.expectKind(IDENT)
		if err != nil {
			return nil, err
		}
		names = append(names, n.Text)
	}
	if p.accept("=") {
		value, err := p.expr()
		if err != nil {
			return nil, err
		}
		return &Assign{Target: &Var{Name: names[0]}, Value: value, Type: typeName, Decl: true, Const: isConst}, nil
	}
	return &VarDecl{Type: typeName, Names: names}, nil
}

func (p *parser) caseStmt() (Stmt, error) {
	p.advance() // case
	subject, err := p.expr()
	if err != nil {
		return nil, err
	}
	if err := p.expect("of"); err != nil {
		return nil, err
	}
	if _, err := p.expectKind(INDENT); err != nil {
		return nil, err
	}
	c := &Case{Subject: subject}
	for !p.at(DEDENT) && !p.at(EOF) {
		var alt CaseAlt
		switch {
		case p.cur().isWord("when"):
			p.advance()
			for {
				pat, err := p.pattern()
				if err != nil {
					return nil, err
				}
				alt.Patterns = append(alt.Patterns, pat)
				if !p.cur().is(",") {
					break
				}
				p.advance()
			}
			if p.accept("&&") {
				if alt.Guard, err = p.expr(); err != nil {
					return nil, err
				}
			}
		case p.cur().isWord("otherwise"):
			p.advance()
			alt.Otherwise = true
		default:
			return nil, p.errf("expected when or otherwise, got %s", p.cur())
		}
		if alt.Body, err = p.body(); err != nil {
			return nil, err
		}
		c.Alts = append(c.Alts, alt)
	}
	if _, err := p.expectKind(DEDENT); err != nil {
		return nil, err
	}
	return c, nil
}

func (p *parser) pattern() (Pattern, error) {
	t := p.cur()
	switch {
	case t.is("-"):
		p.advance()
		return Pattern{Ignore: true}, nil
	case t.is("("):
		p.advance()
		var tuple []Pattern
		for !p.cur().is(")") && !p.at(EOF) {
			sub, err := p.pattern()
			if err != nil {
				return Pattern{}, err
			}
			tuple = append(tuple, sub)
			if !p.accept(",") {
				break
			}
		}
		if err := p.expect(")"); err != nil {
			return Pattern{}, err
		}
		return Pattern{Tuple: tuple}, nil
	case t.Kind == NAT, t.Kind == HEX, t.Kind == BIN, t.Kind == MASK, t.Kind == IDENT:
		p.advance()
		return Pattern{Kind: t.Kind, Text: t.Text}, nil
	}
	return Pattern{}, p.errf("expected a case pattern, got %s", t)
}

func (p *parser) ifStmt() (Stmt, error) {
	p.advance() // if
	cond, err := p.expr()
	if err != nil {
		return nil, err
	}
	if err := p.expect("then"); err != nil {
		return nil, err
	}
	node := &If{Cond: cond}
	if node.Then, err = p.body(); err != nil {
		return nil, err
	}
	for p.cur().isWord("elsif") {
		p.advance()
		c, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expect("then"); err != nil {
			return nil, err
		}
		b, err := p.body()
		if err != nil {
			return nil, err
		}
		node.Elsifs = append(node.Elsifs, ElseIf{Cond: c, Then: b})
	}
	if p.cur().isWord("else") {
		p.advance()
		if node.Else, err = p.body(); err != nil {
			return nil, err
		}
	}
	return node, nil
}

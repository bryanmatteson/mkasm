package asl

import (
	"fmt"
	"strings"
)

// operators are matched longest-first, so "+:" is not read as "+" then ":".
var operators = []string{
	"+:", "..", "<<", ">>", "++", "==", "!=", ">=", "<=", "&&", "||",
	".", ",", ";", ":", "(", ")", "[", "]", "{", "}", "<", ">", "=",
	"+", "-", "*", "/", "^", "!", "&",
}

type lexer struct {
	src  string
	pos  int
	line int
	col  int
}

// Lex turns ASL source into tokens, with INDENT and DEDENT inserted for layout.
func Lex(src string) ([]Token, error) {
	l := &lexer{src: src, line: 1}
	raw, err := l.run()
	if err != nil {
		return nil, err
	}
	return layout(raw)
}

func (l *lexer) run() ([]Token, error) {
	var out []Token
	for {
		if err := l.skipSpaceAndComments(); err != nil {
			return nil, err
		}
		if l.pos >= len(l.src) {
			out = append(out, Token{Kind: EOF, Line: l.line, Col: l.col})
			return out, nil
		}
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
}

func (l *lexer) advance(n int) {
	for i := 0; i < n && l.pos < len(l.src); i++ {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 0
		} else {
			l.col++
		}
		l.pos++
	}
}

func (l *lexer) skipSpaceAndComments() error {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.advance(1)
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance(1)
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			// Block comments nest.
			startLine := l.line
			depth := 0
			for l.pos < len(l.src) {
				if strings.HasPrefix(l.src[l.pos:], "/*") {
					depth++
					l.advance(2)
					continue
				}
				if strings.HasPrefix(l.src[l.pos:], "*/") {
					depth--
					l.advance(2)
					if depth == 0 {
						break
					}
					continue
				}
				l.advance(1)
			}
			if depth != 0 {
				return fmt.Errorf("unterminated block comment opened at line %d", startLine)
			}
		default:
			return nil
		}
	}
	return nil
}

func (l *lexer) next() (Token, error) {
	line, col := l.line, l.col
	c := l.src[l.pos]

	switch {
	case c == '\'':
		return l.bitLiteral(line, col)
	case c == '"':
		return l.stringLiteral(line, col)
	case c >= '0' && c <= '9':
		return l.number(line, col), nil
	case isIdentStart(c):
		return l.identifier(line, col), nil
	}

	for _, op := range operators {
		if strings.HasPrefix(l.src[l.pos:], op) {
			l.advance(len(op))
			return Token{Kind: PUNCT, Text: op, Line: line, Col: col}, nil
		}
	}
	return Token{}, fmt.Errorf("line %d:%d: unexpected character %q", line, col, string(c))
}

// bitLiteral reads '0101' or '0x1x'. Spaces group bits for readability and
// carry no meaning, so they are dropped.
func (l *lexer) bitLiteral(line, col int) (Token, error) {
	l.advance(1) // opening quote
	var b strings.Builder
	for l.pos < len(l.src) && l.src[l.pos] != '\'' {
		if c := l.src[l.pos]; c != ' ' {
			b.WriteByte(c)
		}
		l.advance(1)
	}
	if l.pos >= len(l.src) {
		return Token{}, fmt.Errorf("line %d:%d: unterminated bit literal", line, col)
	}
	l.advance(1) // closing quote
	kind := BIN
	if strings.ContainsAny(b.String(), "xX") {
		kind = MASK
	}
	return Token{Kind: kind, Text: b.String(), Line: line, Col: col}, nil
}

func (l *lexer) stringLiteral(line, col int) (Token, error) {
	l.advance(1)
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '"' {
		l.advance(1)
	}
	if l.pos >= len(l.src) {
		return Token{}, fmt.Errorf("line %d:%d: unterminated string", line, col)
	}
	text := l.src[start:l.pos]
	l.advance(1)
	return Token{Kind: STRING, Text: text, Line: line, Col: col}, nil
}

func (l *lexer) number(line, col int) Token {
	start := l.pos
	if strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X") {
		l.advance(2)
		for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
			l.advance(1)
		}
		return Token{Kind: HEX, Text: l.src[start:l.pos], Line: line, Col: col}
	}
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.advance(1)
	}
	// A single dot before a digit makes a real; two dots are the range operator,
	// so "0..3" must not be read as "0." followed by ".3".
	if l.pos+1 < len(l.src) && l.src[l.pos] == '.' && isDigit(l.src[l.pos+1]) {
		l.advance(1)
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.advance(1)
		}
		return Token{Kind: REAL, Text: l.src[start:l.pos], Line: line, Col: col}
	}
	return Token{Kind: NAT, Text: l.src[start:l.pos], Line: line, Col: col}
}

func (l *lexer) identifier(line, col int) Token {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.advance(1)
	}
	text := l.src[start:l.pos]
	// "SEE <anything>;" is one token: the tail is free-form prose naming another
	// instruction page, not an expression.
	if text == "SEE" && l.pos < len(l.src) && l.src[l.pos] == ' ' {
		tail := l.pos
		for l.pos < len(l.src) && l.src[l.pos] != ';' && l.src[l.pos] != '\n' {
			l.advance(1)
		}
		return Token{Kind: SEE, Text: strings.TrimSpace(l.src[tail:l.pos]), Line: line, Col: col}
	}
	return Token{Kind: IDENT, Text: text, Line: line, Col: col}
}

func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isHexDigit(c byte) bool { return isDigit(c) || (c|0x20) >= 'a' && (c|0x20) <= 'f' }
func isIdentStart(c byte) bool {
	return c == '_' || (c|0x20) >= 'a' && (c|0x20) <= 'z'
}
func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

// layout inserts INDENT and DEDENT tokens from column positions.
//
// This follows the reference implementation's rules exactly, and two of them are
// easy to miss. A token on the same line as the previous one never changes the
// indent, and indentation is ignored entirely inside brackets, so an argument
// list may be wrapped and indented freely without opening a block.
func layout(in []Token) ([]Token, error) {
	var out []Token
	indents := []int{0}
	nest := 0
	prevLine := -1

	for _, tok := range in {
		if tok.Kind == EOF {
			for len(indents) > 1 {
				indents = indents[:len(indents)-1]
				out = append(out, Token{Kind: DEDENT, Line: tok.Line, Col: tok.Col})
			}
			out = append(out, tok)
			break
		}
		if tok.Line != prevLine && nest == 0 {
			top := indents[len(indents)-1]
			switch {
			case tok.Col > top:
				indents = append(indents, tok.Col)
				out = append(out, Token{Kind: INDENT, Line: tok.Line, Col: tok.Col})
			case tok.Col < top:
				for len(indents) > 1 && tok.Col < indents[len(indents)-1] {
					indents = indents[:len(indents)-1]
					out = append(out, Token{Kind: DEDENT, Line: tok.Line, Col: tok.Col})
				}
				if tok.Col != indents[len(indents)-1] {
					return nil, fmt.Errorf("line %d:%d: dedent to a column no block opened", tok.Line, tok.Col)
				}
			}
		}
		if tok.is("(") || tok.is("[") || tok.is("{") {
			nest++
		}
		if tok.is(")") || tok.is("]") || tok.is("}") {
			nest--
		}
		prevLine = tok.Line
		out = append(out, tok)
	}
	return out, nil
}

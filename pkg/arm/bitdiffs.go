package arm

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// ParseBitDiffs parses an ARM encoding@bitdiffs expression into a boolean tree.
// Supported forms (observed in A-profile XML):
//
//	sf == 0
//	cc == 110
//	A == 1 && R == 0
//	imm5 == x1000
//	Rm != 11111
//	op2 IN {'00x', '010'}
//	!(op1 == '000' && op2 IN {'00x', '010'})
func ParseBitDiffs(expr string) (*ir.BitDiffNode, error) {
	expr = strings.TrimSpace(htmlUnescape(expr))
	if expr == "" {
		return nil, nil
	}
	p := &bitDiffParser{s: expr}
	n, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(p.s) {
		return nil, fmt.Errorf("bitdiffs: trailing input %q", p.s[p.pos:])
	}
	return n, nil
}

func htmlUnescape(s string) string {
	r := strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", `"`,
		"&&", "&&", // already fine
	)
	// XML attr decode usually already done; still normalize entity form of &&
	s = strings.ReplaceAll(s, "&amp;&amp;", "&&")
	return r.Replace(s)
}

type bitDiffParser struct {
	s   string
	pos int
}

func (p *bitDiffParser) skipSpace() {
	for p.pos < len(p.s) && unicode.IsSpace(rune(p.s[p.pos])) {
		p.pos++
	}
}

func (p *bitDiffParser) peek() byte {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *bitDiffParser) parseExpr() (*ir.BitDiffNode, error) {
	return p.parseAnd()
}

func (p *bitDiffParser) parseAnd() (*ir.BitDiffNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	kids := []*ir.BitDiffNode{left}
	for {
		p.skipSpace()
		if strings.HasPrefix(p.s[p.pos:], "&&") {
			p.pos += 2
			rhs, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			kids = append(kids, rhs)
			continue
		}
		break
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &ir.BitDiffNode{Kind: ir.BitDiffAnd, Kids: kids}, nil
}

func (p *bitDiffParser) parseUnary() (*ir.BitDiffNode, error) {
	p.skipSpace()
	if p.peek() == '!' {
		p.pos++
		p.skipSpace()
		if p.peek() != '(' {
			return nil, fmt.Errorf("bitdiffs: expected '(' after '!'")
		}
		p.pos++
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peek() != ')' {
			return nil, fmt.Errorf("bitdiffs: expected ')' after not-expr")
		}
		p.pos++
		return &ir.BitDiffNode{Kind: ir.BitDiffNot, Kids: []*ir.BitDiffNode{inner}}, nil
	}
	if p.peek() == '(' {
		// Could be grouped expr OR parenthesized value — try field-less group
		// Grouped expr: look ahead for operator after closing paren is hard;
		// ARM uses !(...) for groups. Bare (00000) appears only as values.
		// So '(' at unary start means grouped expression.
		p.pos++
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peek() != ')' {
			return nil, fmt.Errorf("bitdiffs: expected ')'")
		}
		p.pos++
		return inner, nil
	}
	return p.parseAtom()
}

func (p *bitDiffParser) parseAtom() (*ir.BitDiffNode, error) {
	field, err := p.parseIdent()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	rest := p.s[p.pos:]
	switch {
	case strings.HasPrefix(rest, "=="):
		p.pos += 2
		bits, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &ir.BitDiffNode{
			Kind: ir.BitDiffAtomKind,
			Atom: &ir.BitDiffAtom{Field: field, Op: ir.BitDiffEq, Bits: bits, Start: -1, End: -1},
		}, nil
	case strings.HasPrefix(rest, "!="):
		p.pos += 2
		bits, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &ir.BitDiffNode{
			Kind: ir.BitDiffAtomKind,
			Atom: &ir.BitDiffAtom{Field: field, Op: ir.BitDiffNe, Bits: bits, Start: -1, End: -1},
		}, nil
	case strings.HasPrefix(strings.ToUpper(rest), "IN"):
		// IN {'a','b'}
		if len(rest) < 2 || (rest[0] != 'I' && rest[0] != 'i') {
			return nil, fmt.Errorf("bitdiffs: expected IN")
		}
		p.pos += 2
		p.skipSpace()
		if p.peek() != '{' {
			return nil, fmt.Errorf("bitdiffs: expected '{' after IN")
		}
		p.pos++
		var alts []string
		for {
			p.skipSpace()
			if p.peek() == '}' {
				p.pos++
				break
			}
			if p.peek() == ',' {
				p.pos++
				continue
			}
			v, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			alts = append(alts, v)
		}
		return &ir.BitDiffNode{
			Kind: ir.BitDiffAtomKind,
			Atom: &ir.BitDiffAtom{Field: field, Op: ir.BitDiffIn, Alts: alts, Start: -1, End: -1},
		}, nil
	default:
		return nil, fmt.Errorf("bitdiffs: expected ==, !=, or IN after %q", field)
	}
}

func (p *bitDiffParser) parseIdent() (string, error) {
	p.skipSpace()
	start := p.pos
	if p.pos >= len(p.s) {
		return "", fmt.Errorf("bitdiffs: expected field name")
	}
	if !unicode.IsLetter(rune(p.s[p.pos])) && p.s[p.pos] != '_' {
		return "", fmt.Errorf("bitdiffs: expected field name at %q", p.s[p.pos:])
	}
	p.pos++
	for p.pos < len(p.s) {
		r := rune(p.s[p.pos])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func (p *bitDiffParser) parseValue() (string, error) {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return "", fmt.Errorf("bitdiffs: expected value")
	}
	// Quoted '010' or "010"
	if c := p.s[p.pos]; c == '\'' || c == '"' {
		q := c
		p.pos++
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] != q {
			p.pos++
		}
		if p.pos >= len(p.s) {
			return "", fmt.Errorf("bitdiffs: unterminated quote")
		}
		v := p.s[start:p.pos]
		p.pos++
		return strings.TrimSpace(v), nil
	}
	// Parenthesized (00000)
	if p.s[p.pos] == '(' {
		p.pos++
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] != ')' {
			p.pos++
		}
		if p.pos >= len(p.s) {
			return "", fmt.Errorf("bitdiffs: unterminated '(' value")
		}
		v := p.s[start:p.pos]
		p.pos++
		return strings.TrimSpace(v), nil
	}
	// Bare bit string: 0/1/x
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '0' || c == '1' || c == 'x' || c == 'X' {
			p.pos++
			continue
		}
		break
	}
	if p.pos == start {
		return "", fmt.Errorf("bitdiffs: expected bit value at %q", p.s[p.pos:])
	}
	return p.s[start:p.pos], nil
}

// applyBitDiffs parses bitdiffs, resolves fields, pins equalities, stores tree on instr.
func applyBitDiffs(instr *ir.InstructionIR, expr string) error {
	if instr == nil || strings.TrimSpace(expr) == "" {
		return nil
	}
	instr.BitDiffs = expr
	tree, err := ParseBitDiffs(expr)
	if err != nil {
		return err
	}
	if tree == nil {
		return nil
	}
	_ = ir.ResolveBitDiffFields(tree, instr.Encoding)
	ir.ApplyBitDiffPins(instr, tree)
	instr.BitDiffsTree = tree
	return nil
}

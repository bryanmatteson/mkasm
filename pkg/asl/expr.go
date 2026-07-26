package asl

// Binary operator precedence, transcribed from the ordering of the left
// recursive alternatives in the grammar: alternatives listed earlier bind
// tighter. Higher numbers bind tighter here.
//
// Note where ":" sits. Bit concatenation binds looser than arithmetic but
// tighter than comparison, which is why "case Q:imm5 of" matches the two fields
// as one value rather than comparing them.
var binPrec = map[string]int{
	"^": 6,
	"*": 5, "/": 5,
	"+": 4, "-": 4,
	">>": 3, "<<": 3, "QUOT": 3, "REM": 3, "DIV": 3, "MOD": 3,
	"OR": 3, "EOR": 3, "AND": 3, "++": 3, ":": 3,
	"==": 2, "!=": 2, ">": 2, ">=": 2, "<": 2, "<=": 2,
	"&&": 1, "||": 1,
}

// wordOperators are operators spelled as words, which the lexer returns as
// identifiers.
var wordOperators = map[string]bool{
	"QUOT": true, "REM": true, "DIV": true, "MOD": true,
	"OR": true, "EOR": true, "AND": true,
}

// sliceOps are the operators allowed inside a bit slice. The grammar keeps a
// separate expression rule for slice position, and the exclusions are what make
// it parseable: ":" separates the bounds rather than concatenating, and ">"
// closes the slice rather than comparing. Allowing either would let "imm5<4>"
// consume its own closing bracket.
var sliceOps = map[string]bool{
	"^": true, "*": true, "/": true, "+": true, "-": true,
	">>": true, "<<": true, "QUOT": true, "REM": true, "DIV": true,
	"MOD": true, "OR": true, "EOR": true, "AND": true, "++": true,
}

// expr parses a full expression.
func (p *parser) expr() (Expr, error) { return p.binary(0, true) }

// sliceExpr parses an expression in slice position, where the operator set is
// narrowed so that ":" and ">" retain their structural meaning.
func (p *parser) sliceExpr() (Expr, error) { return p.binary(0, false) }

func (p *parser) operatorAt(full bool) (string, int, bool) {
	t := p.cur()
	var op string
	switch {
	case t.Kind == PUNCT:
		op = t.Text
	case t.Kind == IDENT && wordOperators[t.Text]:
		op = t.Text
	default:
		return "", 0, false
	}
	if !full && !sliceOps[op] {
		return "", 0, false
	}
	prec, ok := binPrec[op]
	return op, prec, ok
}

func (p *parser) binary(minPrec int, full bool) (Expr, error) {
	left, err := p.unary(full)
	if err != nil {
		return nil, err
	}
	for {
		op, prec, ok := p.operatorAt(full)
		if !ok || prec < minPrec {
			return left, nil
		}
		p.advance()
		// All binary operators here are left associative.
		right, err := p.binary(prec+1, full)
		if err != nil {
			return nil, err
		}
		left = &BinOp{Op: op, Left: left, Right: right}
	}
}

func (p *parser) unary(full bool) (Expr, error) {
	t := p.cur()
	if t.is("-") || t.is("!") || t.isWord("NOT") {
		p.advance()
		operand, err := p.unary(full)
		if err != nil {
			return nil, err
		}
		return &UnOp{Op: t.Text, Operand: operand}, nil
	}
	return p.postfix(full)
}

func (p *parser) postfix(full bool) (Expr, error) {
	e, err := p.primary(full)
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.cur().is("."):
			p.advance()
			// ".[a,b]" and ".<a,b>" select several members at once; the encoder
			// has no use for either, so both collapse to a member reference.
			if p.cur().is("[") || p.cur().is("<") {
				closer := "]"
				if p.cur().is("<") {
					closer = ">"
				}
				p.advance()
				var names []string
				for !p.cur().is(closer) && !p.at(EOF) {
					if p.at(IDENT) {
						names = append(names, p.advance().Text)
					} else {
						p.advance()
					}
					p.accept(",")
				}
				if err := p.expect(closer); err != nil {
					return nil, err
				}
				name := ""
				if len(names) > 0 {
					name = names[0]
				}
				e = &Member{Value: e, Name: name}
				continue
			}
			name, err := p.expectKind(IDENT)
			if err != nil {
				return nil, err
			}
			e = &Member{Value: e, Name: name.Text}
		case p.cur().is("["):
			p.advance()
			slices, err := p.slices("]")
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			e = &IndexExpr{Value: e, Slices: slices}
		case p.cur().is("<"):
			// "<" is both the slice bracket and less-than. Try the slice; if it
			// does not close cleanly, rewind and let the binary parser treat it
			// as a comparison.
			save := p.pos
			p.advance()
			slices, err := p.slices(">")
			if err == nil && p.cur().is(">") {
				p.advance()
				e = &SliceExpr{Value: e, Slices: slices}
				continue
			}
			p.pos = save
			return e, nil
		case p.cur().isWord("IN"):
			p.advance()
			if p.cur().Kind == MASK || p.cur().Kind == BIN {
				e = &InMask{Value: e, Mask: p.advance().Text}
				continue
			}
			if err := p.expect("{"); err != nil {
				return nil, err
			}
			var elems []SetElement
			for !p.cur().is("}") && !p.at(EOF) {
				lo, err := p.expr()
				if err != nil {
					return nil, err
				}
				if p.accept("..") {
					hi, err := p.expr()
					if err != nil {
						return nil, err
					}
					elems = append(elems, SetElement{Lo: lo, Hi: hi, IsRange: true})
				} else {
					elems = append(elems, SetElement{Value: lo})
				}
				if !p.accept(",") {
					break
				}
			}
			if err := p.expect("}"); err != nil {
				return nil, err
			}
			e = &InSet{Value: e, Elements: elems}
		default:
			return e, nil
		}
	}
}

// slices parses a comma separated slice list up to but not including closer.
func (p *parser) slices(closer string) ([]Slice, error) {
	var out []Slice
	for !p.cur().is(closer) && !p.at(EOF) {
		s, err := p.slice()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		if !p.accept(",") {
			break
		}
	}
	return out, nil
}

func (p *parser) slice() (Slice, error) {
	first, err := p.sliceExpr()
	if err != nil {
		return Slice{}, err
	}
	switch {
	case p.accept(":"):
		lo, err := p.sliceExpr()
		if err != nil {
			return Slice{}, err
		}
		return Slice{Hi: first, Lo: lo}, nil
	case p.accept("+:"):
		count, err := p.sliceExpr()
		if err != nil {
			return Slice{}, err
		}
		return Slice{Base: first, Count: count, Offset: true}, nil
	}
	return Slice{Hi: first, Single: true}, nil
}

func (p *parser) primary(full bool) (Expr, error) {
	t := p.cur()
	switch t.Kind {
	case NAT, HEX, REAL, BIN, MASK, STRING:
		p.advance()
		return &Lit{Kind: t.Kind, Text: t.Text}, nil
	case PUNCT:
		if t.is("(") {
			p.advance()
			var elems []Expr
			for {
				// A lone "-" in a tuple discards that result rather than
				// negating anything.
				if p.cur().is("-") && p.pos+1 < len(p.toks) &&
					(p.toks[p.pos+1].is(",") || p.toks[p.pos+1].is(")")) {
					p.advance()
					elems = append(elems, &Ignore{})
					if !p.accept(",") {
						break
					}
					continue
				}
				e, err := p.expr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, e)
				if !p.accept(",") {
					break
				}
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			if len(elems) == 1 {
				return elems[0], nil
			}
			return &Tuple{Elements: elems}, nil
		}
	case IDENT:
		if t.Text == "if" {
			return p.ifExpr()
		}
		p.advance()
		name := t.Text
		// "AArch64.Foo(...)" is one qualified name.
		if (name == "AArch64" || name == "AArch32") && p.cur().is(".") {
			p.advance()
			part, err := p.expectKind(IDENT)
			if err != nil {
				return nil, err
			}
			name += "." + part.Text
		}
		// "bits(N) UNKNOWN" and "integer UNKNOWN" are values, not calls.
		if p.cur().isWord("UNKNOWN") {
			p.advance()
			return &Unknown{Type: name}, nil
		}
		if p.cur().is("(") {
			p.advance()
			var args []Expr
			for !p.cur().is(")") && !p.at(EOF) {
				a, err := p.expr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if !p.accept(",") {
					break
				}
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			if p.cur().isWord("UNKNOWN") {
				p.advance()
				return &Unknown{Type: name}, nil
			}
			return &CallExpr{Name: name, Args: args}, nil
		}
		return &Var{Name: name}, nil
	}
	return nil, p.errf("expected an expression, got %s", t)
}

func (p *parser) ifExpr() (Expr, error) {
	p.advance() // if
	cond, err := p.expr()
	if err != nil {
		return nil, err
	}
	if err := p.expect("then"); err != nil {
		return nil, err
	}
	then, err := p.expr()
	if err != nil {
		return nil, err
	}
	node := &IfExpr{Cond: cond, Then: then}
	for p.cur().isWord("elsif") {
		p.advance()
		c, err := p.expr()
		if err != nil {
			return nil, err
		}
		if err := p.expect("then"); err != nil {
			return nil, err
		}
		v, err := p.expr()
		if err != nil {
			return nil, err
		}
		node.Elsifs = append(node.Elsifs, ElseIfExpr{Cond: c, Then: v})
	}
	if err := p.expect("else"); err != nil {
		return nil, err
	}
	if node.Else, err = p.expr(); err != nil {
		return nil, err
	}
	return node, nil
}

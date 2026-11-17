package dotnet

// Validation checks structural safety and encoded references. It deliberately
// does not implement CLR type loading, instruction verification, or module policy.
func nullableIndex(table int, column int) bool {
	return table == 1 && column == 0 || table == 2 && column == 3 || table == 40 && column == 3 || table == 49 && column == 0 || table == 50 && column == 1 || table == 53 && column == 0
}
func (m *Metadata) validateGraph() error {
	nested := map[Token]Token{}
	for i := uint32(1); i <= m.Tables[41].Count; i++ {
		r, _ := m.Row(41, i)
		t := Token(2<<24 | r[0])
		if nested[t] != 0 {
			return bad("duplicate nested type owner")
		}
		nested[t] = Token(2<<24 | r[1])
	}
	done := map[Token]bool{}
	active := map[Token]bool{}
	var visit func(Token, int) error
	var typ func(Type, int) error
	var sig func(*Signature, int) error
	sig = func(s *Signature, depth int) error {
		if s == nil {
			return nil
		}
		if s.Return != nil {
			if e := typ(*s.Return, depth+1); e != nil {
				return e
			}
		}
		for _, t := range s.Parameters {
			if e := typ(t, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	typ = func(t Type, depth int) error {
		if depth > 64 {
			return bad("signature graph nesting limit")
		}
		if t.Token != 0 {
			if e := visit(t.Token, depth+1); e != nil {
				return e
			}
		}
		for _, a := range t.Args {
			if e := typ(a, depth+1); e != nil {
				return e
			}
		}
		return sig(t.Method, depth+1)
	}
	visit = func(t Token, depth int) error {
		if depth > 64 {
			return bad("metadata graph nesting limit")
		}
		if done[t] {
			return nil
		}
		if active[t] {
			return bad("metadata type cycle at %s", t)
		}
		active[t] = true
		switch t.Table() {
		case 1:
			r, e := m.Row(1, t.RID())
			if e != nil {
				return e
			}
			parent, _ := DecodeCoded("ResolutionScope", r[0])
			if parent != 0 && parent.Table() == 1 {
				if e = visit(parent, depth+1); e != nil {
					return e
				}
			}
		case 2:
			if p := nested[t]; p != 0 {
				if e := visit(p, depth+1); e != nil {
					return e
				}
			}
		case 27:
			r, e := m.Row(27, t.RID())
			if e != nil {
				return e
			}
			b, _ := m.Blob(r[0])
			v, e := m.TypeSignature(b)
			if e != nil {
				return bad("%s signature: %v", t, e)
			}
			if e = typ(v, depth+1); e != nil {
				return e
			}
		}
		delete(active, t)
		done[t] = true
		return nil
	}
	for _, table := range []uint8{1, 2, 27} {
		for rid := uint32(1); rid <= m.Tables[table].Count; rid++ {
			if e := visit(Token(uint32(table)<<24|rid), 0); e != nil {
				return e
			}
		}
	}
	return nil
}

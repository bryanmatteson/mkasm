package dotnet

// Member retains a member's encoded signature and its generic substitutions.
// ResolvedSignature substitutes !n/!!n without loading referenced assemblies.
type Member struct {
	Token             Token      `json:"token"`
	Parent            Token      `json:"parent"`
	Name              string     `json:"name"`
	DeclaringType     string     `json:"declaring_type"`
	Signature         *Signature `json:"signature"`
	ResolvedSignature *Signature `json:"resolved_signature"`
	TypeArguments     []Type     `json:"type_arguments,omitempty"`
	MethodArguments   []Type     `json:"method_arguments,omitempty"`
}

func (m *Metadata) Member(t Token) (*Member, error) { return m.member(t, 0) }
func (m *Metadata) member(t Token, depth int) (*Member, error) {
	if depth > 64 {
		return nil, bad("member resolution nesting limit")
	}
	if e := m.ValidateToken(t); e != nil {
		return nil, e
	}
	r, e := m.Row(t.Table(), t.RID())
	if e != nil {
		return nil, e
	}
	out := &Member{Token: t}
	switch t.Table() {
	case 4, 6:
		out.Parent, e = m.owner(t)
		if e != nil {
			return nil, e
		}
		col := 1
		sigCol := 2
		if t.Table() == 6 {
			col = 3
			sigCol = 4
		}
		out.Name, _ = m.String(r[col])
		b, _ := m.Blob(r[sigCol])
		out.Signature, e = m.ParseSignature(b)
	case 10:
		out.Parent, _ = DecodeCoded("MemberRefParent", r[0])
		out.Name, _ = m.String(r[1])
		b, _ := m.Blob(r[2])
		out.Signature, e = m.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if out.Parent.Table() == 27 {
			r, e := m.Row(27, out.Parent.RID())
			if e != nil {
				return nil, e
			}
			b, _ := m.Blob(r[0])
			typ, e := m.TypeSignature(b)
			if e != nil {
				return nil, e
			}
			if typ.Kind == "genericinst" {
				out.TypeArguments = append(out.TypeArguments, typ.Args[1:]...)
			}
		}
	case 43:
		base, _ := DecodeCoded("MethodDefOrRef", r[0])
		out, e = m.member(base, depth+1)
		if e != nil {
			return nil, e
		}
		out.Token = t
		b, _ := m.Blob(r[1])
		s, e := m.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if s.Kind != "method-instantiation" || out.Signature.Kind != "method" || uint32(len(s.Parameters)) != out.Signature.GenericArity {
			return nil, bad("MethodSpec generic arity mismatch")
		}
		out.MethodArguments = s.Parameters
	default:
		return nil, bad("token %s is not a field/method member", t)
	}
	if e != nil {
		return nil, e
	}
	out.DeclaringType, e = m.Resolve(out.Parent)
	if e != nil {
		return nil, e
	}
	out.ResolvedSignature = substituteSignature(out.Signature, out.TypeArguments, out.MethodArguments)
	return out, nil
}
func substituteSignature(s *Signature, types, methods []Type) *Signature {
	if s == nil {
		return nil
	}
	out := *s
	if s.Return != nil {
		t := substituteType(*s.Return, types, methods)
		out.Return = &t
	}
	out.Parameters = make([]Type, len(s.Parameters))
	for i, t := range s.Parameters {
		out.Parameters[i] = substituteType(t, types, methods)
	}
	return &out
}
func substituteType(t Type, types, methods []Type) Type {
	if t.Kind == "var" && uint64(t.Index) < uint64(len(types)) {
		return types[t.Index]
	}
	if t.Kind == "mvar" && uint64(t.Index) < uint64(len(methods)) {
		return methods[t.Index]
	}
	args := make([]Type, len(t.Args))
	for i, a := range t.Args {
		args[i] = substituteType(a, types, methods)
	}
	t.Args = args
	t.Method = substituteSignature(t.Method, types, methods)
	return t
}

// Attributes returns raw serialized attribute values with resolved constructor
// signatures. Attribute object construction and arbitrary enum loading are left
// to consumers, rather than guessed from an incomplete assembly reference set.
type Attribute struct {
	Token       Token   `json:"token"`
	Parent      Token   `json:"parent"`
	Constructor *Member `json:"constructor"`
	Value       []byte  `json:"value"`
}

func (m *Metadata) Attributes(parent Token) ([]Attribute, error) {
	if parent != 0 {
		if e := m.ValidateToken(parent); e != nil {
			return nil, e
		}
	}
	var out []Attribute
	for i := uint32(1); i <= m.Tables[12].Count; i++ {
		r, _ := m.Row(12, i)
		p, _ := DecodeCoded("HasCustomAttribute", r[0])
		if parent != 0 && parent != p {
			continue
		}
		ctor, _ := DecodeCoded("CustomAttributeType", r[1])
		member, e := m.Member(ctor)
		if e != nil {
			return nil, e
		}
		b, _ := m.Blob(r[2])
		if len(b) < 2 || b[0] != 1 || b[1] != 0 {
			return nil, bad("invalid custom attribute prolog")
		}
		out = append(out, Attribute{Token(12<<24 | i), p, member, b})
	}
	return out, nil
}

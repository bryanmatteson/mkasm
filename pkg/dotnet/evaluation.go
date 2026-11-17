package dotnet

// EvaluationContext describes the variables and result of a method, independent
// of the instruction decoder. Local signatures belong to the method body.
type EvaluationContext struct {
	Arguments    int  `json:"arguments"`
	Locals       int  `json:"locals"`
	ReturnsValue bool `json:"returns_value"`
}

// ReturnsValue ignores custom modifiers surrounding the encoded return type.
func (s *Signature) ReturnsValue() bool {
	if s == nil || s.Return == nil {
		return false
	}
	t := s.Return
	for (t.Kind == "modreq" || t.Kind == "modopt") && len(t.Args) == 1 {
		t = &t.Args[0]
	}
	return t.Kind != "void"
}

// CallSignature resolves MethodDef, MemberRef, MethodSpec and calli's
// StandAloneSig, including generic substitutions and explicit-this conventions.
func (m *Metadata) CallSignature(token Token) (*Signature, error) {
	if token.Table() == 17 {
		r, e := m.Row(17, token.RID())
		if e != nil {
			return nil, e
		}
		b, e := m.Blob(r[0])
		if e != nil {
			return nil, e
		}
		s, e := m.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if s.Kind != "method" {
			return nil, bad("call signature is not a method")
		}
		return s, nil
	}
	member, e := m.Member(token)
	if e != nil {
		return nil, e
	}
	s := member.ResolvedSignature
	if s == nil || s.Kind != "method" {
		return nil, bad("call token is not a method")
	}
	return s, nil
}

func (m *Metadata) EvaluationContext(method, locals Token) (EvaluationContext, error) {
	var out EvaluationContext
	if method.Table() != 6 {
		return out, bad("method context requires MethodDef")
	}
	s, e := m.CallSignature(method)
	if e != nil {
		return out, e
	}
	out.Arguments = len(s.Parameters)
	if s.CallingConvention&0x20 != 0 && s.CallingConvention&0x40 == 0 {
		out.Arguments++
	}
	out.ReturnsValue = s.ReturnsValue()
	if locals != 0 {
		if locals.Table() != 17 {
			return out, bad("locals require StandAloneSig")
		}
		r, e := m.Row(17, locals.RID())
		if e != nil {
			return out, e
		}
		b, e := m.Blob(r[0])
		if e != nil {
			return out, e
		}
		s, e := m.ParseSignature(b)
		if e != nil {
			return out, e
		}
		if s.Kind != "locals" {
			return out, bad("local token is not a local signature")
		}
		out.Locals = len(s.Parameters)
	}
	return out, nil
}

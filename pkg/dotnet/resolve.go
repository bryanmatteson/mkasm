package dotnet

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type Assembly struct {
	Token     Token  `json:"token"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Culture   string `json:"culture"`
	Flags     uint32 `json:"flags"`
	PublicKey []byte `json:"public_key"`
}
type TypeDefinition struct {
	Token             Token              `json:"token"`
	Name              string             `json:"name"`
	Namespace         string             `json:"namespace"`
	FullName          string             `json:"full_name"`
	Flags             uint32             `json:"flags"`
	Extends           Token              `json:"extends"`
	Fields            []Token            `json:"fields"`
	Methods           []Token            `json:"methods"`
	GenericParameters []GenericParameter `json:"generic_parameters,omitempty"`
}
type GenericParameter struct {
	Token       Token   `json:"token"`
	Number      uint32  `json:"number"`
	Flags       uint32  `json:"flags"`
	Name        string  `json:"name"`
	Constraints []Token `json:"constraints,omitempty"`
}
type Method struct {
	Token             Token              `json:"token"`
	DeclaringType     Token              `json:"declaring_type"`
	Name              string             `json:"name"`
	FullName          string             `json:"full_name"`
	RVA               uint32             `json:"rva"`
	Flags             uint32             `json:"flags"`
	ImplFlags         uint32             `json:"impl_flags"`
	Kind              string             `json:"kind"`
	Signature         *Signature         `json:"signature"`
	Parameters        []Token            `json:"parameters"`
	GenericParameters []GenericParameter `json:"generic_parameters,omitempty"`
}
type Field struct {
	Token         Token      `json:"token"`
	DeclaringType Token      `json:"declaring_type"`
	Name          string     `json:"name"`
	Flags         uint32     `json:"flags"`
	Signature     *Signature `json:"signature"`
}

func (m *Metadata) Assemblies() ([]Assembly, error) {
	var a []Assembly
	for i := uint32(1); i <= m.Tables[32].Count; i++ {
		r, _ := m.Row(32, i)
		n, e := m.String(r[7])
		if e != nil {
			return nil, e
		}
		c, _ := m.String(r[8])
		p, _ := m.Blob(r[6])
		a = append(a, Assembly{Token(32<<24 | i), n, fmt.Sprintf("%d.%d.%d.%d", r[1], r[2], r[3], r[4]), c, r[5], p})
	}
	return a, nil
}
func (m *Metadata) GenericParameters(owner Token) ([]GenericParameter, error) {
	out := append([]GenericParameter(nil), m.generics[owner]...)
	for i := range out {
		out[i].Constraints = append([]Token(nil), out[i].Constraints...)
	}
	return out, nil
}

func (m *Metadata) Types() ([]TypeDefinition, error) {
	var a []TypeDefinition
	for i := uint32(1); i <= m.Tables[2].Count; i++ {
		r, _ := m.Row(2, i)
		n, _ := m.String(r[1])
		ns, _ := m.String(r[2])
		tok := Token(2<<24 | i)
		full, e := m.Resolve(tok)
		if e != nil {
			return nil, e
		}
		fields, e := m.Range(2, i, 4, 4)
		if e != nil {
			return nil, e
		}
		methods, e := m.Range(2, i, 5, 6)
		if e != nil {
			return nil, e
		}
		base, _ := DecodeCoded("TypeDefOrRef", r[3])
		g, e := m.GenericParameters(tok)
		if e != nil {
			return nil, e
		}
		a = append(a, TypeDefinition{tok, n, ns, full, r[0], base, fields, methods, g})
	}
	return a, nil
}
func (m *Metadata) owner(t Token) (Token, error) {
	if t.Table() != 4 && t.Table() != 6 {
		return 0, bad("not a field/method token")
	}
	if o := m.owners[t]; o != 0 {
		return o, nil
	}
	return 0, bad("orphan member token %s", t)
}
func (m *Metadata) Method(t Token) (Method, error) {
	var out Method
	if t.Table() != 6 {
		return out, bad("not a MethodDef token")
	}
	r, e := m.Row(6, t.RID())
	if e != nil {
		return out, e
	}
	owner, e := m.owner(t)
	if e != nil {
		return out, e
	}
	n, _ := m.String(r[3])
	full, e := m.Resolve(owner)
	if e != nil {
		return out, e
	}
	blob, _ := m.Blob(r[4])
	sig, e := m.ParseSignature(blob)
	if e != nil {
		return out, bad("%s signature: %v", t, e)
	}
	if sig.Kind != "method" {
		return out, bad("MethodDef has non-method signature")
	}
	params, e := m.Range(6, t.RID(), 5, 8)
	if e != nil {
		return out, e
	}
	g, e := m.GenericParameters(t)
	if e != nil {
		return out, e
	}
	kind := "cil"
	switch r[1] & 3 {
	case 1:
		kind = "native"
	case 2:
		kind = "optil"
	case 3:
		kind = "runtime"
	}
	if r[2]&0x400 != 0 {
		kind = "abstract"
	} else if r[2]&0x2000 != 0 {
		kind = "pinvoke"
	} else if r[0] == 0 && kind == "cil" {
		kind = "no-body"
	}
	return Method{t, owner, n, full + "::" + n, r[0], r[2], r[1], kind, sig, params, g}, nil
}
func (m *Metadata) Methods() ([]Method, error) {
	var out []Method
	for i := uint32(1); i <= m.Tables[6].Count; i++ {
		v, e := m.Method(Token(6<<24 | i))
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (m *Metadata) Fields() ([]Field, error) {
	var out []Field
	for i := uint32(1); i <= m.Tables[4].Count; i++ {
		r, _ := m.Row(4, i)
		t := Token(4<<24 | i)
		o, e := m.owner(t)
		if e != nil {
			return nil, e
		}
		n, _ := m.String(r[1])
		b, _ := m.Blob(r[2])
		s, e := m.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if s.Kind != "field" {
			return nil, bad("Field has non-field signature")
		}
		out = append(out, Field{t, o, n, r[0], s})
	}
	return out, nil
}
func (m *Metadata) Resolve(t Token) (string, error) { return m.resolve(t, 0) }
func (m *Metadata) resolve(t Token, depth int) (string, error) {
	if depth > 64 {
		return "", bad("metadata resolution cycle/nesting limit")
	}
	if e := m.ValidateToken(t); e != nil {
		return "", e
	}
	if t.Table() == 0x70 {
		s, _, e := m.UserString(t.RID())
		return s, e
	}
	r, e := m.Row(t.Table(), t.RID())
	if e != nil {
		return "", e
	}
	str := func(i int) string { s, _ := m.String(r[i]); return s }
	switch t.Table() {
	case 0:
		return str(1), nil
	case 1:
		scope, _ := DecodeCoded("ResolutionScope", r[0])
		if scope.Table() == 1 && scope != 0 {
			n, e := m.resolve(scope, depth+1)
			return n + "+" + str(1), e
		}
		return qualify(str(2), str(1)), nil
	case 2:
		if parent := m.nested[t]; parent != 0 {
			n, e := m.resolve(parent, depth+1)
			return n + "+" + str(1), e
		}
		return qualify(str(2), str(1)), nil
	case 4, 6:
		o, e := m.owner(t)
		if e != nil {
			return "", e
		}
		n, e := m.resolve(o, depth+1)
		if t.Table() == 4 {
			return n + "::" + str(1), e
		}
		return n + "::" + str(3), e
	case 8:
		return str(2), nil
	case 10:
		parent, _ := DecodeCoded("MemberRefParent", r[0])
		n, e := m.resolve(parent, depth+1)
		return n + "::" + str(1), e
	case 17:
		b, _ := m.Blob(r[0])
		s, e := m.ParseSignature(b)
		if e != nil {
			return "", e
		}
		return s.format(m, depth+1), nil
	case 20, 23:
		return str(1), nil
	case 26, 32:
		return str(map[uint8]int{26: 0, 32: 7}[t.Table()]), nil
	case 27:
		b, _ := m.Blob(r[0])
		v, e := m.TypeSignature(b)
		if e != nil {
			return "", e
		}
		return v.format(m, depth+1), nil
	case 35:
		return str(6), nil
	case 38:
		return str(1), nil
	case 39:
		return qualify(str(3), str(2)), nil
	case 40:
		return str(2), nil
	case 42:
		return str(3), nil
	case 43:
		base, _ := DecodeCoded("MethodDefOrRef", r[0])
		n, e := m.resolve(base, depth+1)
		if e != nil {
			return "", e
		}
		b, _ := m.Blob(r[1])
		s, e := m.ParseSignature(b)
		if e != nil {
			return "", e
		}
		return n + s.format(m, depth+1), nil
	case 48:
		return m.DocumentName(t.RID())
	}
	return tableName(t.Table()) + "(" + t.String() + ")", nil
}
func (m *Metadata) DocumentName(rid uint32) (string, error) {
	r, e := m.Row(48, rid)
	if e != nil {
		return "", e
	}
	b, e := m.Blob(r[0])
	if e != nil {
		return "", e
	}
	if len(b) == 0 {
		return "", bad("empty document name blob")
	}
	runeValue, n := utf8.DecodeRune(b)
	if runeValue == utf8.RuneError && n == 1 {
		return "", bad("invalid document separator UTF-8")
	}
	sep := string(b[:n])
	if b[0] == 0 {
		sep = ""
	}
	if n >= len(b) {
		return "", bad("document name has no parts")
	}
	c := cursor{b: b, p: uint64(n)}
	parts := []string{}
	for c.p < uint64(len(b)) {
		n, e := c.compressed()
		if e != nil {
			return "", e
		}
		p, e := m.Blob(n)
		if e != nil {
			return "", e
		}
		if !utf8.Valid(p) {
			return "", bad("invalid document part UTF-8")
		}
		parts = append(parts, string(p))
	}
	return strings.Join(parts, sep), nil
}

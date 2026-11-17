package dotnet

import (
	"fmt"
	"strings"
)

// Type is an ECMA-335 signature type. Token and Index preserve the encoded
// identity; Args contains element types, generic arguments, or function pointers.
type Type struct {
	Kind        string     `json:"kind"`
	Token       Token      `json:"token,omitempty"`
	Index       uint32     `json:"index,omitempty"`
	Args        []Type     `json:"args,omitempty"`
	Rank        uint32     `json:"rank,omitempty"`
	Sizes       []uint32   `json:"sizes,omitempty"`
	LowerBounds []int32    `json:"lower_bounds,omitempty"`
	Method      *Signature `json:"method,omitempty"`
}
type Signature struct {
	Kind              string `json:"kind"`
	CallingConvention uint8  `json:"calling_convention"`
	GenericArity      uint32 `json:"generic_arity,omitempty"`
	Return            *Type  `json:"return,omitempty"`
	Parameters        []Type `json:"parameters,omitempty"`
	Sentinel          int    `json:"sentinel"`
}

var elementNames = map[uint32]string{1: "void", 2: "bool", 3: "char", 4: "int8", 5: "uint8", 6: "int16", 7: "uint16", 8: "int32", 9: "uint32", 10: "int64", 11: "uint64", 12: "float32", 13: "float64", 14: "string", 22: "typedref", 24: "native int", 25: "native uint", 28: "object"}

func (m *Metadata) ParseSignature(b []byte) (*Signature, error) {
	r := cursor{b: b}
	s, e := m.signature(&r, 0)
	if e == nil && r.p != uint64(len(b)) {
		e = bad("trailing signature bytes")
	}
	return s, e
}
func (m *Metadata) TypeSignature(b []byte) (Type, error) {
	r := cursor{b: b}
	t, e := m.signatureType(&r, 0)
	if e == nil && r.p != uint64(len(b)) {
		e = bad("trailing type signature bytes")
	}
	return t, e
}
func (m *Metadata) signature(r *cursor, depth int) (*Signature, error) {
	if depth > 64 {
		return nil, bad("signature nesting limit")
	}
	raw, e := r.uint(1)
	if e != nil {
		return nil, e
	}
	if raw&0x80 != 0 {
		return nil, bad("reserved calling convention")
	}
	s := &Signature{CallingConvention: uint8(raw), Sentinel: -1}
	cc := raw & 15
	switch cc {
	case 6:
		s.Kind = "field"
		t, e := m.signatureType(r, depth+1)
		s.Return = &t
		return s, e
	case 7:
		s.Kind = "locals"
	case 10:
		s.Kind = "method-instantiation"
	case 8:
		s.Kind = "property"
	case 0, 1, 2, 3, 4, 5, 9, 11:
		s.Kind = "method"
	default:
		return nil, bad("unknown signature calling convention %x", cc)
	}
	if raw&16 != 0 {
		s.GenericArity, e = r.compressed()
		if e != nil {
			return nil, e
		}
	}
	count, e := r.compressed()
	if e != nil {
		return nil, e
	}
	if uint64(count) > uint64(len(r.b))-r.p {
		return nil, ErrBounds
	}
	if s.Kind == "method" || s.Kind == "property" {
		t, e := m.signatureType(r, depth+1)
		if e != nil {
			return nil, e
		}
		s.Return = &t
	}
	for i := uint32(0); i < count; i++ {
		if r.p < uint64(len(r.b)) && r.b[r.p] == 0x41 {
			if cc != 5 || s.Sentinel >= 0 {
				return nil, bad("unexpected signature sentinel")
			}
			s.Sentinel = int(i)
			r.p++
		}
		t, e := m.signatureType(r, depth+1)
		if e != nil {
			return nil, e
		}
		s.Parameters = append(s.Parameters, t)
	}
	return s, nil
}
func (m *Metadata) signatureType(r *cursor, depth int) (Type, error) {
	var t Type
	if depth > 64 {
		return t, bad("signature nesting limit")
	}
	k, e := r.uint(1)
	if e != nil {
		return t, e
	}
	if r.native {
		k &= 0x7f
	}
	if name, ok := elementNames[k]; ok {
		t.Kind = name
		return t, nil
	}
	switch k {
	case 15, 16, 29, 69, 31, 32:
		t.Kind = map[uint32]string{15: "pointer", 16: "byref", 29: "szarray", 69: "pinned", 31: "modreq", 32: "modopt"}[k]
		if k == 31 || k == 32 {
			v, e := r.compressed()
			if e != nil {
				return t, e
			}
			t.Token, e = DecodeCoded("TypeDefOrRef", v)
			if e != nil {
				return t, e
			}
			if !r.native {
				e = m.ValidateToken(t.Token)
			}
			if e != nil {
				return t, e
			}
		}
		v, e := m.signatureType(r, depth+1)
		t.Args = []Type{v}
		return t, e
	case 17, 18:
		t.Kind = map[uint32]string{17: "valuetype", 18: "class"}[k]
		v, e := r.compressed()
		if e != nil {
			return t, e
		}
		t.Token, e = DecodeCoded("TypeDefOrRef", v)
		if e == nil && !r.native {
			e = m.ValidateToken(t.Token)
		}
		return t, e
	case 19, 30:
		t.Kind = map[uint32]string{19: "var", 30: "mvar"}[k]
		t.Index, e = r.compressed()
		return t, e
	case 20:
		t.Kind = "array"
		v, e := m.signatureType(r, depth+1)
		if e != nil {
			return t, e
		}
		t.Args = []Type{v}
		t.Rank, e = r.compressed()
		if e != nil {
			return t, e
		}
		if r.native && t.Rank == 0 {
			t.Kind = "szarray"
			return t, nil
		}
		n, e := r.compressed()
		if e != nil {
			return t, e
		}
		if n > t.Rank || uint64(n) > uint64(len(r.b))-r.p {
			return t, bad("invalid array sizes")
		}
		for i := uint32(0); i < n; i++ {
			v, e := r.compressed()
			if e != nil {
				return t, e
			}
			t.Sizes = append(t.Sizes, v)
		}
		n, e = r.compressed()
		if e != nil {
			return t, e
		}
		if n > t.Rank || uint64(n) > uint64(len(r.b))-r.p {
			return t, bad("invalid array lower bounds")
		}
		for i := uint32(0); i < n; i++ {
			var v int32
			var e error
			if r.native {
				var raw uint32
				raw, e = r.compressed()
				v = int32(raw >> 1)
				if raw&1 != 0 {
					v = -v
				}
			} else {
				v, e = r.signedCompressed()
			}
			if e != nil {
				return t, e
			}
			t.LowerBounds = append(t.LowerBounds, v)
		}
		return t, nil
	case 21:
		t.Kind = "genericinst"
		base, e := m.signatureType(r, depth+1)
		if e != nil {
			return t, e
		}
		kind := base.Kind
		if r.native && kind == "module" && len(base.Args) == 1 {
			kind = base.Args[0].Kind
		}
		if kind != "class" && kind != "valuetype" {
			return t, bad("generic base is not class/value type")
		}
		t.Args = []Type{base}
		n, e := r.compressed()
		if e != nil {
			return t, e
		}
		if uint64(n) > uint64(len(r.b))-r.p {
			return t, ErrBounds
		}
		for i := uint32(0); i < n; i++ {
			a, e := m.signatureType(r, depth+1)
			if e != nil {
				return t, e
			}
			t.Args = append(t.Args, a)
		}
		return t, nil
	case 27:
		t.Kind = "fnptr"
		t.Method, e = m.signature(r, depth+1)
		return t, e
	case 0x3e:
		if r.native {
			t.Kind = "canon"
			return t, nil
		}
	case 0x3f:
		if r.native {
			t.Kind = "module"
			t.Index, e = r.compressed()
			if e != nil {
				return t, e
			}
			v, e := m.signatureType(r, depth+1)
			t.Args = []Type{v}
			return t, e
		}
	default:
		return t, bad("unknown/reserved signature element 0x%x", k)
	}
	return t, bad("unknown/reserved signature element 0x%x", k)
}
func (t Type) Format(m *Metadata) string { return t.format(m, 0) }
func (t Type) format(m *Metadata, depth int) string {
	if depth > 64 {
		return "<cycle>"
	}
	child := func(i int) string {
		if i >= len(t.Args) {
			return "<?>"
		}
		return t.Args[i].format(m, depth+1)
	}
	switch t.Kind {
	case "class", "valuetype":
		n, e := m.resolve(t.Token, depth+1)
		if e != nil {
			return t.Token.String()
		}
		return n
	case "pointer":
		return child(0) + "*"
	case "byref":
		return child(0) + "&"
	case "szarray":
		return child(0) + "[]"
	case "pinned":
		return child(0) + " pinned"
	case "modreq", "modopt":
		n, e := m.resolve(t.Token, depth+1)
		if e != nil {
			n = t.Token.String()
		}
		return child(0) + " " + t.Kind + "(" + n + ")"
	case "var":
		return fmt.Sprintf("!%d", t.Index)
	case "mvar":
		return fmt.Sprintf("!!%d", t.Index)
	case "genericinst":
		a := []string{}
		for i := 1; i < len(t.Args); i++ {
			a = append(a, child(i))
		}
		return child(0) + "<" + strings.Join(a, ", ") + ">"
	case "array":
		if t.Rank > 256 {
			return child(0) + fmt.Sprintf("[rank %d]", t.Rank)
		}
		a := make([]string, t.Rank)
		for i := range a {
			if i < len(t.LowerBounds) {
				a[i] = fmt.Sprint(t.LowerBounds[i]) + "..."
			}
			if i < len(t.Sizes) {
				lo := int64(0)
				if i < len(t.LowerBounds) {
					lo = int64(t.LowerBounds[i])
				}
				a[i] = fmt.Sprintf("%d...%d", lo, lo+int64(t.Sizes[i])-1)
			}
		}
		return child(0) + "[" + strings.Join(a, ",") + "]"
	case "fnptr":
		if t.Method != nil {
			return "method " + t.Method.format(m, depth+1) + "*"
		}
	}
	return t.Kind
}
func (s *Signature) Format(m *Metadata) string { return s.format(m, 0) }
func (s *Signature) format(m *Metadata, depth int) string {
	if depth > 64 {
		return "<cycle>"
	}
	if s == nil {
		return ""
	}
	a := []string{}
	for i, t := range s.Parameters {
		if i == s.Sentinel {
			a = append(a, "...")
		}
		a = append(a, t.format(m, depth+1))
	}
	if s.Kind == "field" {
		return s.Return.format(m, depth+1)
	}
	if s.Kind == "locals" {
		return "locals (" + strings.Join(a, ", ") + ")"
	}
	if s.Kind == "method-instantiation" {
		return "<" + strings.Join(a, ", ") + ">"
	}
	ret := ""
	if s.Return != nil {
		ret = s.Return.format(m, depth+1) + " "
	}
	if s.CallingConvention&32 != 0 {
		ret = "instance " + ret
	}
	if s.GenericArity != 0 {
		ret += fmt.Sprintf("generic<%d> ", s.GenericArity)
	}
	return ret + "(" + strings.Join(a, ", ") + ")"
}

package dotnet

import (
	"fmt"
	"unicode/utf8"
)

// SerializedType is the ECMA-335 custom-attribute FieldOrPropType. Enum storage
// is obtained from its defining assembly, never guessed from the type's name.
type SerializedType struct {
	Kind          string          `json:"kind"`
	Enum          string          `json:"enum,omitempty"`
	EnumModule    *ModuleIdentity `json:"enum_module,omitempty"`
	EnumArguments []Type          `json:"enum_arguments,omitempty"`
	Element       *SerializedType `json:"element,omitempty"`
}

// AttributeValue keeps scalar bits exactly (including NaNs and signed values).
// Kind determines their width and interpretation. Null is distinct from an
// empty string/array. Boxed values have one element with its serialized type.
type AttributeValue struct {
	Type     SerializedType   `json:"type"`
	Bits     uint64           `json:"bits,omitempty"`
	Text     *string          `json:"text,omitempty"`
	Null     bool             `json:"null,omitempty"`
	Elements []AttributeValue `json:"elements,omitempty"`
}
type NamedArgument struct {
	Field bool           `json:"field"`
	Name  string         `json:"name"`
	Value AttributeValue `json:"value"`
}
type DecodedAttribute struct {
	Fixed []AttributeValue `json:"fixed"`
	Named []NamedArgument  `json:"named"`
}
type EnumResolver func(string) (string, error)

var serializedKinds = map[uint32]string{2: "bool", 3: "char", 4: "int8", 5: "uint8", 6: "int16", 7: "uint16", 8: "int32", 9: "uint32", 10: "int64", 11: "uint64", 12: "float32", 13: "float64", 14: "string", 0x50: "type", 0x51: "object"}
var serializedWidths = map[string]int{"bool": 1, "int8": 1, "uint8": 1, "char": 2, "int16": 2, "uint16": 2, "int32": 4, "uint32": 4, "float32": 4, "int64": 8, "uint64": 8, "float64": 8}

func serString(r *cursor) (*string, error) {
	if r.p >= uint64(len(r.b)) {
		return nil, ErrBounds
	}
	if r.b[r.p] == 255 {
		r.p++
		return nil, nil
	}
	n, e := r.compressed()
	if e != nil {
		return nil, e
	}
	b, e := r.take(uint64(n))
	if e != nil {
		return nil, e
	}
	if !utf8.Valid(b) {
		return nil, bad("invalid UTF-8 serialized string")
	}
	s := string(b)
	return &s, nil
}
func serializedType(r *cursor, depth int) (SerializedType, error) {
	var t SerializedType
	if depth > 64 {
		return t, bad("attribute nesting limit")
	}
	k, e := r.uint(1)
	if e != nil {
		return t, e
	}
	if name, ok := serializedKinds[k]; ok {
		t.Kind = name
		return t, nil
	}
	switch k {
	case 0x1d:
		t.Kind = "array"
		child, e := serializedType(r, depth+1)
		t.Element = &child
		return t, e
	case 0x55:
		t.Kind = "enum"
		name, e := serString(r)
		if e != nil {
			return t, e
		}
		if name == nil || *name == "" {
			return t, bad("empty enum type name")
		}
		t.Enum = *name
		return t, nil
	}
	return t, bad("invalid attribute type 0x%x", k)
}
func attributeValue(r *cursor, t SerializedType, enums EnumResolver, depth int) (AttributeValue, error) {
	return attributeValueScoped(r, t, func(typ SerializedType) (string, error) {
		if enums == nil {
			return "", bad("enum %s requires defining assembly resolver", typ.Enum)
		}
		return enums(typ.Enum)
	}, depth)
}
func attributeValueScoped(r *cursor, t SerializedType, enums func(SerializedType) (string, error), depth int) (AttributeValue, error) {
	out := AttributeValue{Type: t}
	if depth > 64 {
		return out, bad("attribute nesting limit")
	}
	kind := t.Kind
	if kind == "enum" {
		if enums == nil {
			return out, bad("enum %s requires defining assembly resolver", t.Enum)
		}
		var e error
		kind, e = enums(t)
		if e != nil {
			return out, e
		}
		if kind != "int8" && kind != "uint8" && kind != "int16" && kind != "uint16" && kind != "int32" && kind != "uint32" && kind != "int64" && kind != "uint64" {
			return out, bad("invalid enum underlying type %s", kind)
		}
	}
	if width, ok := serializedWidths[kind]; ok {
		b, e := r.take(uint64(width))
		if e != nil {
			return out, e
		}
		for i, v := range b {
			out.Bits |= uint64(v) << uint(i*8)
		}
		if kind == "bool" && out.Bits > 1 {
			return out, bad("invalid attribute boolean")
		}
		return out, nil
	}
	switch kind {
	case "string", "type":
		v, e := serString(r)
		out.Text = v
		out.Null = v == nil
		return out, e
	case "object":
		if r.p >= uint64(len(r.b)) {
			return out, ErrBounds
		}
		if r.b[r.p] == 255 {
			r.p++
			out.Null = true
			return out, nil
		}
		t, e := serializedType(r, depth+1)
		if e != nil {
			return out, e
		}
		if t.Kind == "object" {
			return out, bad("object cannot recursively box object")
		}
		v, e := attributeValueScoped(r, t, enums, depth+1)
		out.Elements = []AttributeValue{v}
		return out, e
	case "array":
		if t.Element == nil {
			return out, bad("array element type missing")
		}
		n, e := r.uint(4)
		if e != nil {
			return out, e
		}
		if n == 0xffffffff {
			out.Null = true
			return out, nil
		}
		if n > 0x7fffffff || uint64(n) > uint64(len(r.b))-r.p {
			return out, ErrBounds
		}
		for i := uint32(0); i < n; i++ {
			v, e := attributeValueScoped(r, *t.Element, enums, depth+1)
			if e != nil {
				return out, e
			}
			out.Elements = append(out.Elements, v)
		}
		return out, nil
	}
	return out, bad("unsupported attribute value type %s", kind)
}
func namedArguments(r *cursor, n uint32, enums EnumResolver) ([]NamedArgument, error) {
	return namedArgumentsScoped(r, n, func(typ SerializedType) (string, error) {
		if enums == nil {
			return "", bad("enum %s requires defining assembly resolver", typ.Enum)
		}
		return enums(typ.Enum)
	})
}
func namedArgumentsScoped(r *cursor, n uint32, enums func(SerializedType) (string, error)) ([]NamedArgument, error) {
	if uint64(n) > uint64(len(r.b))-r.p {
		return nil, ErrBounds
	}
	out := []NamedArgument{}
	for i := uint32(0); i < n; i++ {
		kind, e := r.uint(1)
		if e != nil {
			return nil, e
		}
		if kind != 0x53 && kind != 0x54 {
			return nil, bad("invalid named attribute argument")
		}
		t, e := serializedType(r, 0)
		if e != nil {
			return nil, e
		}
		name, e := serString(r)
		if e != nil {
			return nil, e
		}
		if name == nil || *name == "" {
			return nil, bad("empty named argument")
		}
		v, e := attributeValueScoped(r, t, enums, 0)
		if e != nil {
			return nil, e
		}
		out = append(out, NamedArgument{kind == 0x53, *name, v})
	}
	return out, nil
}
func (m *Metadata) attributeType(t Type) (SerializedType, error) {
	for (t.Kind == "modreq" || t.Kind == "modopt") && len(t.Args) == 1 {
		t = t.Args[0]
	}
	if _, ok := serializedWidths[t.Kind]; ok || t.Kind == "string" || t.Kind == "object" {
		return SerializedType{Kind: t.Kind}, nil
	}
	if t.Kind == "szarray" && len(t.Args) == 1 {
		child, e := m.attributeType(t.Args[0])
		return SerializedType{Kind: "array", Element: &child}, e
	}
	if t.Kind == "genericinst" && len(t.Args) > 1 && t.Args[0].Kind == "valuetype" {
		name, e := m.serializedArgumentName(t, 0)
		if e != nil {
			return SerializedType{}, e
		}
		return SerializedType{Kind: "enum", Enum: name, EnumArguments: append([]Type(nil), t.Args[1:]...)}, nil
	}
	if t.Kind == "class" || t.Kind == "valuetype" {
		name, e := m.Resolve(t.Token)
		if e != nil {
			return SerializedType{}, e
		}
		if name == "System.Type" {
			return SerializedType{Kind: "type"}, nil
		}
		if t.Kind == "valuetype" {
			name, e = m.enumTypeName(t.Token)
			return SerializedType{Kind: "enum", Enum: name}, e
		}
	}
	return SerializedType{}, bad("invalid custom attribute signature type %s", t.Kind)
}
func (m *Metadata) DecodeAttribute(a Attribute, enums EnumResolver) (*DecodedAttribute, error) {
	if a.Constructor == nil || a.Constructor.ResolvedSignature == nil {
		return nil, bad("attribute constructor missing")
	}
	r := cursor{b: a.Value}
	v, e := r.uint(2)
	if e != nil || v != 1 {
		return nil, bad("invalid custom attribute prolog")
	}
	out := &DecodedAttribute{}
	for _, p := range a.Constructor.ResolvedSignature.Parameters {
		t, e := m.attributeType(p)
		if e != nil {
			return nil, e
		}
		v, e := attributeValue(&r, t, enums, 0)
		if e != nil {
			return nil, e
		}
		out.Fixed = append(out.Fixed, v)
	}
	n, e := r.uint(2)
	if e != nil {
		return nil, e
	}
	out.Named, e = namedArguments(&r, n, enums)
	if e != nil {
		return nil, e
	}
	if r.p != uint64(len(r.b)) {
		return nil, bad("trailing attribute bytes")
	}
	return out, nil
}

// LocalEnumUnderlying resolves enum storage in this module. For external enums,
// provide a resolver using the actual referenced module's metadata.
func (m *Metadata) LocalEnumUnderlying(name string) (string, error) {
	typ, id, e := parseEnumIdentity(name)
	if e != nil {
		return "", e
	}
	if id != nil {
		return "", fmt.Errorf("dotnet: defining assembly for enum %s is required", name)
	}
	set, e := NewReferenceSet(m)
	if e != nil {
		return "", e
	}
	return set.EnumUnderlying(typ)
}

type SecurityAttribute struct {
	Type  string          `json:"type"`
	Named []NamedArgument `json:"named"`
}
type SecurityDeclaration struct {
	LegacyXML  []byte              `json:"legacy_xml,omitempty"`
	Attributes []SecurityAttribute `json:"attributes,omitempty"`
}

// DecodeSecurity accepts both legacy XML and the .NET 2.0+ permission-set form.
// Legacy XML remains bytes; no XML or serialized objects are executed.
func DecodeSecurity(b []byte, enums EnumResolver) (*SecurityDeclaration, error) {
	if len(b) == 0 {
		return nil, ErrBounds
	}
	out := &SecurityDeclaration{}
	if b[0] != '.' {
		out.LegacyXML = append([]byte(nil), b...)
		return out, nil
	}
	r := cursor{b: b, p: 1}
	n, e := r.compressed()
	if e != nil {
		return nil, e
	}
	if uint64(n) > uint64(len(b))-r.p {
		return nil, ErrBounds
	}
	for i := uint32(0); i < n; i++ {
		name, e := serString(&r)
		if e != nil {
			return nil, e
		}
		if name == nil || *name == "" {
			return nil, bad("security attribute type missing")
		}
		length, e := r.compressed()
		if e != nil {
			return nil, e
		}
		data, e := r.take(uint64(length))
		if e != nil {
			return nil, e
		}
		sub := cursor{b: data}
		count, e := sub.compressed()
		if e != nil {
			return nil, e
		}
		args, e := namedArguments(&sub, count, enums)
		if e != nil {
			return nil, e
		}
		if sub.p != uint64(len(data)) {
			return nil, bad("trailing security attribute bytes")
		}
		out.Attributes = append(out.Attributes, SecurityAttribute{*name, args})
	}
	if r.p != uint64(len(b)) {
		return nil, bad("trailing security declaration bytes")
	}
	return out, nil
}

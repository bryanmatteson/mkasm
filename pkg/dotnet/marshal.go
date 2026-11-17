package dotnet

// MarshalDescriptor retains all present optional fields, distinguishing an
// omitted value from zero. NativeType identifies the ECMA-335 native type code.
type MarshalDescriptor struct {
	NativeType    uint32    `json:"native_type"`
	ElementType   *uint32   `json:"element_type,omitempty"`
	SizeParameter *uint32   `json:"size_parameter,omitempty"`
	Size          *uint32   `json:"size,omitempty"`
	Flags         *uint32   `json:"flags,omitempty"`
	VariantType   *uint32   `json:"variant_type,omitempty"`
	UserType      *string   `json:"user_type,omitempty"`
	CustomStrings []*string `json:"custom_strings,omitempty"`
}

func DecodeMarshal(b []byte) (*MarshalDescriptor, error) {
	r := cursor{b: b}
	kind, e := r.uint(1)
	if e != nil {
		return nil, e
	}
	out := &MarshalDescriptor{NativeType: kind}
	read := func(target **uint32, required bool) error {
		if r.p == uint64(len(b)) && !required {
			return nil
		}
		v, e := r.compressed()
		if e != nil {
			return e
		}
		*target = &v
		return nil
	}
	switch kind {
	case 0x17: // fixed string
		e = read(&out.Size, true)
	case 0x1e: // fixed array
		e = read(&out.Size, true)
		if e == nil {
			e = read(&out.ElementType, false)
		}
	case 0x1d: // safe array
		e = read(&out.VariantType, false)
		if e == nil && r.p < uint64(len(b)) {
			out.UserType, e = serString(&r)
		}
	case 0x2a: // LPArray: NativeType, ParamNum, NumElem, Flags
		e = read(&out.ElementType, true)
		if e == nil {
			e = read(&out.SizeParameter, false)
		}
		if e == nil {
			e = read(&out.Size, false)
		}
		if e == nil {
			e = read(&out.Flags, false)
		}
	case 0x2c: // custom marshaler GUID, native name, managed type, cookie
		for i := 0; i < 4; i++ {
			v, err := serString(&r)
			if err != nil {
				return nil, err
			}
			out.CustomStrings = append(out.CustomStrings, v)
		}
	case 0x19, 0x1a, 0x1c: // IUnknown, IDispatch, interface optional IID parameter
		e = read(&out.SizeParameter, false)
	case 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x1b, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x2b, 0x2d, 0x2e, 0x2f, 0x30:
	default:
		return nil, bad("unknown native marshal type 0x%x", kind)
	}
	if e != nil {
		return nil, e
	}
	if r.p != uint64(len(b)) {
		return nil, bad("trailing marshal descriptor bytes")
	}
	return out, nil
}

package dotnet

// NativeMethodInstance describes one ReadyToRun generic entry. Tokens belong
// to Module, or to the owner type's module override when present. A nil module
// denotes the image's global metadata context; foreign tokens are never added
// to NativeFunction.Methods. Offsets are relative to section 109.
type NativeMethodInstance struct {
	Hash          uint8   `json:"hash"`
	Offset        uint32  `json:"offset"`
	Flags         uint32  `json:"flags"`
	Module        *uint32 `json:"module,omitempty"`
	Owner         *Type   `json:"owner,omitempty"`
	Token         Token   `json:"token,omitempty"`
	Slot          *uint32 `json:"slot,omitempty"`
	TypeArguments []Type  `json:"type_arguments,omitempty"`
	Constrained   *Type   `json:"constrained,omitempty"`
	FunctionIndex uint32  `json:"function_index"`
	FixupOffset   *uint32 `json:"fixup_offset,omitempty"`
	Signature     []byte  `json:"signature"`
}

func nativeSigned(b []byte, at uint64) (int32, uint64, error) {
	v, next, e := nativeUnsigned(b, at)
	if e != nil {
		return 0, at, e
	}
	bits := uint((next - at) * 7)
	if bits < 32 && v&(1<<(bits-1)) != 0 {
		v |= ^uint32(0) << bits
	}
	return int32(v), next, nil
}

func nativeEntryPoint(b []byte, at uint64) (uint32, *uint32, error) {
	id, next, e := nativeUnsigned(b, at)
	if e != nil {
		return 0, nil, e
	}
	if id&1 == 0 {
		return id >> 1, nil, nil
	}
	if id&2 != 0 {
		delta, _, e := nativeUnsigned(b, next)
		if e != nil {
			return 0, nil, e
		}
		if uint64(delta) > next {
			return 0, nil, ErrBounds
		}
		next -= uint64(delta)
	}
	if next >= uint64(len(b)) {
		return 0, nil, ErrBounds
	}
	p := uint32(next)
	return id >> 2, &p, nil
}

func (im *Image) NativeMethodInstances() ([]NativeMethodInstance, error) {
	h, e := im.ReadyToRunHeader()
	if e != nil || h == nil {
		return nil, e
	}
	for _, s := range h.Sections {
		if s.Type == 109 {
			return im.Metadata.nativeMethodInstances(s.Data)
		}
	}
	return nil, nil
}

func (m *Metadata) nativeMethodInstances(b []byte) ([]NativeMethodInstance, error) {
	if len(b) == 0 {
		return nil, ErrBounds
	}
	shift, code := uint(b[0]>>2), uint(b[0]&3)
	if shift > 31 || code > 2 {
		return nil, bad("invalid ReadyToRun hash header")
	}
	buckets, width := uint64(1)<<shift, uint64(1)<<code
	indexSize := (buckets + 1) * width
	if _, e := span(b, 1, indexSize); e != nil {
		return nil, e
	}
	read := func(i uint64) uint64 {
		v := uint64(0)
		for j := uint64(0); j < width; j++ {
			v |= uint64(b[1+i*width+j]) << (j * 8)
		}
		return v + 1
	}
	var out []NativeMethodInstance
	for bucket := uint64(0); bucket < buckets; bucket++ {
		at, end := read(bucket), read(bucket+1)
		if at < indexSize+1 || end < at || end > uint64(len(b)) {
			return nil, bad("invalid ReadyToRun hash bucket")
		}
		for at < end {
			hash := b[at]
			at++
			delta, next, e := nativeSigned(b, at)
			if e != nil {
				return nil, e
			}
			if next > end {
				return nil, ErrBounds
			}
			target := int64(at) + int64(delta)
			if target < int64(indexSize+1) || target >= int64(len(b)) {
				return nil, ErrBounds
			}
			instance, e := m.nativeMethodInstance(b, uint64(target))
			if e != nil {
				return nil, e
			}
			instance.Hash = hash
			out = append(out, instance)
			at = next
		}
	}
	return out, nil
}

func (m *Metadata) nativeMethodInstance(b []byte, at uint64) (NativeMethodInstance, error) {
	out := NativeMethodInstance{Offset: uint32(at)}
	r := cursor{b: b, p: at, native: true}
	var e error
	out.Flags, e = r.compressed()
	if e != nil {
		return out, e
	}
	if out.Flags&^uint32(255) != 0 {
		return out, bad("unknown ReadyToRun method flags")
	}
	if out.Flags&0x80 != 0 {
		v, e := r.compressed()
		if e != nil {
			return out, e
		}
		out.Module = &v
	}
	if out.Flags&0x40 != 0 {
		v, e := m.signatureType(&r, 0)
		if e != nil {
			return out, e
		}
		out.Owner = &v
	}
	rid, e := r.compressed()
	if e != nil {
		return out, e
	}
	if out.Flags&8 != 0 {
		out.Slot = &rid
	} else {
		if rid == 0 || rid > 0xffffff {
			return out, bad("invalid ReadyToRun method RID")
		}
		table := uint32(6)
		if out.Flags&16 != 0 {
			table = 10
		}
		out.Token = Token(table<<24 | rid)
	}
	if out.Flags&4 != 0 {
		count, e := r.compressed()
		if e != nil {
			return out, e
		}
		if uint64(count) > uint64(len(b))-r.p {
			return out, ErrBounds
		}
		for i := uint32(0); i < count; i++ {
			v, e := m.signatureType(&r, 0)
			if e != nil {
				return out, e
			}
			out.TypeArguments = append(out.TypeArguments, v)
		}
	}
	if out.Flags&0x20 != 0 {
		v, e := m.signatureType(&r, 0)
		if e != nil {
			return out, e
		}
		out.Constrained = &v
	}
	out.Signature = b[at:r.p]
	out.FunctionIndex, out.FixupOffset, e = nativeEntryPoint(b, r.p)
	return out, e
}

package dotnet

import (
	"encoding/binary"
)

type ExceptionClause struct {
	Flags         uint32 `json:"flags"`
	TryOffset     uint32 `json:"try_offset"`
	TryLength     uint32 `json:"try_length"`
	HandlerOffset uint32 `json:"handler_offset"`
	HandlerLength uint32 `json:"handler_length"`
	ClassToken    Token  `json:"class_token,omitempty"`
	FilterOffset  uint32 `json:"filter_offset,omitempty"`
}
type MethodSection struct {
	Kind uint8  `json:"kind"`
	Fat  bool   `json:"fat"`
	Data []byte `json:"data"`
}
type MethodBody struct {
	Token          Token             `json:"token"`
	RVA            uint32            `json:"rva"`
	Kind           string            `json:"kind"`
	Flags          uint16            `json:"flags"`
	MaxStack       uint16            `json:"max_stack"`
	LocalSignature Token             `json:"local_signature"`
	InitLocals     bool              `json:"init_locals"`
	Header         []byte            `json:"header"`
	IL             []byte            `json:"il"`
	Exceptions     []ExceptionClause `json:"exceptions,omitempty"`
	Sections       []MethodSection   `json:"sections,omitempty"`
	Raw            []byte            `json:"raw"`
}

// ParseMethodBody decodes framing and exception sections, not CIL instruction
// semantics or verification. Raw ends at the final section, excluding trailing data.
func ParseMethodBody(b []byte) (*MethodBody, error) {
	if len(b) == 0 {
		return nil, ErrBounds
	}
	out := &MethodBody{Kind: "cil"}
	var start, size uint64
	more := false
	switch b[0] & 3 {
	case 2:
		start = 1
		size = uint64(b[0] >> 2)
		out.MaxStack = 8
		out.Flags = 2
	case 3:
		if len(b) < 12 {
			return nil, ErrBounds
		}
		v := binary.LittleEndian.Uint16(b)
		out.Flags = v & 0xfff
		start = uint64(v>>12) * 4
		if start < 12 {
			return nil, bad("fat method header shorter than 12")
		}
		if out.Flags&^uint16(0x1b) != 0 {
			return nil, bad("reserved method flags")
		}
		out.MaxStack = binary.LittleEndian.Uint16(b[2:])
		size = uint64(binary.LittleEndian.Uint32(b[4:]))
		out.LocalSignature = Token(binary.LittleEndian.Uint32(b[8:]))
		if out.LocalSignature != 0 && (out.LocalSignature.Table() != 17 || out.LocalSignature.RID() == 0) {
			return nil, bad("invalid local signature token")
		}
		out.InitLocals = out.Flags&16 != 0
		more = out.Flags&8 != 0
	default:
		return nil, bad("invalid CIL method header")
	}
	header, e := span(b, 0, start)
	if e != nil {
		return nil, e
	}
	il, e := span(b, start, size)
	if e != nil {
		return nil, e
	}
	out.Header = header
	out.IL = il
	end := start + size
	for more {
		p := (end + 3) &^ 3
		h, e := span(b, p, 4)
		if e != nil {
			return nil, e
		}
		kind := h[0] & 63
		fat := h[0]&64 != 0
		more = h[0]&128 != 0
		var n uint32
		if fat {
			n = uint32(h[1]) | uint32(h[2])<<8 | uint32(h[3])<<16
		} else {
			n = uint32(h[1])
			if h[2] != 0 || h[3] != 0 {
				return nil, bad("reserved small section bytes")
			}
		}
		if n < 4 {
			return nil, bad("invalid method section size")
		}
		section, e := span(b, p, uint64(n))
		if e != nil {
			return nil, e
		}
		out.Sections = append(out.Sections, MethodSection{kind, fat, section})
		if kind != 1 {
			return nil, bad("unsupported method data section kind %d", kind)
		}
		width := 12
		if fat {
			width = 24
		}
		if (len(section)-4)%width != 0 {
			return nil, bad("misaligned exception clauses")
		}
		for q := 4; q < len(section); q += width {
			a := section[q : q+width]
			var c ExceptionClause
			var extra uint32
			if fat {
				c.Flags = binary.LittleEndian.Uint32(a)
				c.TryOffset = binary.LittleEndian.Uint32(a[4:])
				c.TryLength = binary.LittleEndian.Uint32(a[8:])
				c.HandlerOffset = binary.LittleEndian.Uint32(a[12:])
				c.HandlerLength = binary.LittleEndian.Uint32(a[16:])
				extra = binary.LittleEndian.Uint32(a[20:])
			} else {
				c.Flags = uint32(binary.LittleEndian.Uint16(a))
				c.TryOffset = uint32(binary.LittleEndian.Uint16(a[2:]))
				c.TryLength = uint32(a[4])
				c.HandlerOffset = uint32(binary.LittleEndian.Uint16(a[5:]))
				c.HandlerLength = uint32(a[7])
				extra = binary.LittleEndian.Uint32(a[8:])
			}
			if c.Flags != 0 && c.Flags != 1 && c.Flags != 2 && c.Flags != 4 {
				return nil, bad("invalid exception clause flags")
			}
			if uint64(c.TryOffset)+uint64(c.TryLength) > size || uint64(c.HandlerOffset)+uint64(c.HandlerLength) > size || c.TryLength == 0 || c.HandlerLength == 0 {
				return nil, bad("exception range outside CIL body")
			}
			if c.Flags == 0 {
				c.ClassToken = Token(extra)
				if c.ClassToken.RID() == 0 || (c.ClassToken.Table() != 1 && c.ClassToken.Table() != 2 && c.ClassToken.Table() != 27) {
					return nil, bad("invalid catch type token")
				}
			} else if c.Flags == 1 {
				c.FilterOffset = extra
				if uint64(extra) >= size || extra >= c.HandlerOffset {
					return nil, bad("invalid exception filter offset")
				}
			} else if extra != 0 {
				return nil, bad("nonzero finally/fault union")
			}
			out.Exceptions = append(out.Exceptions, c)
		}
		end = p + uint64(n)
	}
	out.Raw = b[:end]
	return out, nil
}
func (im *Image) rvaTail(rva uint32) ([]byte, error) {
	p, e := im.RVAOffset(rva, 1)
	if e != nil {
		return nil, e
	}
	end := uint64(im.SizeOfHeaders)
	if rva >= im.SizeOfHeaders {
		for _, s := range im.Sections {
			if uint64(rva) >= uint64(s.VirtualAddress) && uint64(rva) < uint64(s.VirtualAddress)+uint64(s.RawSize) {
				end = uint64(s.RawOffset) + uint64(s.RawSize)
				break
			}
		}
	}
	if end < p {
		return nil, ErrBounds
	}
	return span(im.Data, p, end-p)
}
func (im *Image) MethodBody(t Token) (*MethodBody, error) {
	method, e := im.Metadata.Method(t)
	if e != nil {
		return nil, e
	}
	if method.Kind != "cil" {
		return &MethodBody{Token: t, RVA: method.RVA, Kind: method.Kind}, nil
	}
	b, e := im.rvaTail(method.RVA)
	if e != nil {
		return nil, e
	}
	out, e := ParseMethodBody(b)
	if e != nil {
		return nil, bad("%s method body: %v", t, e)
	}
	out.Token = t
	out.RVA = method.RVA
	if out.LocalSignature != 0 {
		if e = im.Metadata.ValidateToken(out.LocalSignature); e != nil {
			return nil, e
		}
		r, _ := im.Metadata.Row(17, out.LocalSignature.RID())
		b, _ := im.Metadata.Blob(r[0])
		s, e := im.Metadata.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if s.Kind != "locals" {
			return nil, bad("method local signature is not locals")
		}
	}
	for _, c := range out.Exceptions {
		if c.ClassToken != 0 {
			if e := im.Metadata.ValidateToken(c.ClassToken); e != nil {
				return nil, e
			}
		}
	}
	return out, nil
}

type Resource struct {
	Token          Token  `json:"token"`
	Name           string `json:"name"`
	Flags          uint32 `json:"flags"`
	Implementation Token  `json:"implementation"`
	Offset         uint32 `json:"offset"`
	Data           []byte `json:"data,omitempty"`
}

func (im *Image) Resources() ([]Resource, error) {
	var a []Resource
	for i := uint32(1); i <= im.Metadata.Tables[40].Count; i++ {
		r, _ := im.Metadata.Row(40, i)
		n, _ := im.Metadata.String(r[2])
		impl, _ := DecodeCoded("Implementation", r[3])
		v := Resource{Token: Token(40<<24 | i), Name: n, Flags: r[1], Implementation: impl, Offset: r[0]}
		if impl == 0 {
			b, e := im.BytesAtRVA(im.CLI.Resources.RVA, im.CLI.Resources.Size)
			if e != nil {
				return nil, e
			}
			length, e := u32(b, uint64(r[0]))
			if e != nil {
				return nil, e
			}
			v.Data, e = span(b, uint64(r[0])+4, uint64(length))
			if e != nil {
				return nil, e
			}
		}
		a = append(a, v)
	}
	return a, nil
}

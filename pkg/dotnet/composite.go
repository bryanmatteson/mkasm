package dotnet

import (
	"encoding/binary"
	"math"
)

type NativeMethodReference struct {
	Component uint32 `json:"component"`
	Token     Token  `json:"token"`
}
type ReadyToRunComponent struct {
	Index          uint32          `json:"index"`
	CLIHeader      Directory       `json:"cli_header"`
	AssemblyHeader Directory       `json:"assembly_header"`
	Flags          uint32          `json:"flags"`
	Sections       []NativeSection `json:"sections"`
	Metadata       *Metadata       `json:"metadata,omitempty"`
}

// compositeDirectory locates the exported RTR_HEADER in native composite PE
// images. Export ordinals, RVAs and strings are bounded before dereferencing.
func (im *Image) compositeDirectory(exports Directory) (Directory, error) {
	if exports.RVA == 0 || exports.Size == 0 {
		return Directory{}, nil
	}
	b, e := im.BytesAtRVA(exports.RVA, exports.Size)
	if e != nil {
		return Directory{}, e
	}
	if len(b) < 40 {
		return Directory{}, ErrBounds
	}
	functions, names := binary.LittleEndian.Uint32(b[20:]), binary.LittleEndian.Uint32(b[24:])
	if uint64(functions)*4 > math.MaxUint32 || uint64(names)*4 > math.MaxUint32 {
		return Directory{}, ErrBounds
	}
	fs, e := im.BytesAtRVA(binary.LittleEndian.Uint32(b[28:]), functions*4)
	if e != nil {
		return Directory{}, e
	}
	ns, e := im.BytesAtRVA(binary.LittleEndian.Uint32(b[32:]), names*4)
	if e != nil {
		return Directory{}, e
	}
	os, e := im.BytesAtRVA(binary.LittleEndian.Uint32(b[36:]), names*2)
	if e != nil {
		return Directory{}, e
	}
	for i := uint32(0); i < names; i++ {
		rva := binary.LittleEndian.Uint32(ns[i*4:])
		matches := true
		for j, want := range []byte("RTR_HEADER\x00") {
			if uint64(rva)+uint64(j) > math.MaxUint32 {
				return Directory{}, ErrBounds
			}
			c, e := im.BytesAtRVA(rva+uint32(j), 1)
			if e != nil {
				return Directory{}, e
			}
			if c[0] != want {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		ordinal := uint32(binary.LittleEndian.Uint16(os[i*2:]))
		if ordinal >= functions {
			return Directory{}, bad("invalid PE export ordinal")
		}
		rva = binary.LittleEndian.Uint32(fs[ordinal*4:])
		if uint64(rva) >= uint64(exports.RVA) && uint64(rva) < uint64(exports.RVA)+uint64(exports.Size) {
			return Directory{}, bad("forwarded RTR_HEADER export")
		}
		head, e := im.BytesAtRVA(rva, 16)
		if e != nil {
			return Directory{}, e
		}
		if binary.LittleEndian.Uint32(head) != 0x00525452 {
			return Directory{}, bad("invalid composite signature")
		}
		size := uint64(16) + uint64(binary.LittleEndian.Uint32(head[12:]))*12
		if size > math.MaxUint32 {
			return Directory{}, ErrBounds
		}
		if _, e = im.BytesAtRVA(rva, uint32(size)); e != nil {
			return Directory{}, e
		}
		return Directory{rva, uint32(size)}, nil
	}
	return Directory{}, nil
}

func (im *Image) ReadyToRunComponents() ([]ReadyToRunComponent, error) {
	h, e := im.ReadyToRunHeader()
	if e != nil || h == nil {
		return nil, e
	}
	var data []byte
	for _, s := range h.Sections {
		if s.Type == 115 {
			data = s.Data
		}
	}
	if len(data)%16 != 0 {
		return nil, bad("invalid component assembly table")
	}
	out := []ReadyToRunComponent{}
	for i := 0; i < len(data); i += 16 {
		b := data[i:]
		c := ReadyToRunComponent{Index: uint32(i / 16), CLIHeader: Directory{binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])}, AssemblyHeader: Directory{binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[12:])}}
		b, e := im.BytesAtRVA(c.AssemblyHeader.RVA, c.AssemblyHeader.Size)
		if e != nil {
			return nil, e
		}
		if len(b) < 8 {
			return nil, ErrBounds
		}
		c.Flags = binary.LittleEndian.Uint32(b)
		count := binary.LittleEndian.Uint32(b[4:])
		if uint64(count)*12 > uint64(len(b))-8 {
			return nil, ErrBounds
		}
		var last uint32
		for n := uint32(0); n < count; n++ {
			p := 8 + n*12
			kind := binary.LittleEndian.Uint32(b[p:])
			if n > 0 && kind <= last {
				return nil, bad("unordered component sections")
			}
			last = kind
			d := Directory{binary.LittleEndian.Uint32(b[p+4:]), binary.LittleEndian.Uint32(b[p+8:])}
			raw, e := im.BytesAtRVA(d.RVA, d.Size)
			if e != nil {
				return nil, e
			}
			c.Sections = append(c.Sections, NativeSection{kind, d, raw})
		}
		if c.CLIHeader.Size != 0 {
			cli, e := im.BytesAtRVA(c.CLIHeader.RVA, c.CLIHeader.Size)
			if e != nil {
				return nil, e
			}
			if len(cli) < 72 || binary.LittleEndian.Uint32(cli) < 72 || binary.LittleEndian.Uint32(cli) > uint32(len(cli)) {
				return nil, bad("invalid component CLI header")
			}
			d := Directory{binary.LittleEndian.Uint32(cli[8:]), binary.LittleEndian.Uint32(cli[12:])}
			if d.Size != 0 {
				raw, e := im.BytesAtRVA(d.RVA, d.Size)
				if e != nil {
					return nil, e
				}
				c.Metadata, e = ParseMetadata(raw)
				if e != nil {
					return nil, e
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}

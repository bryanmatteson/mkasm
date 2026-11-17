package dotnet

import (
	"encoding/binary"
	"math"
)

// ReadyToRun layout follows dotnet/runtime v10.0.12 readytorun.h and the
// ILCompiler.Reflection.ReadyToRun reader. Unknown section types stay intact.
type NativeSection struct {
	Type      uint32    `json:"type"`
	Directory Directory `json:"directory"`
	Data      []byte    `json:"data"`
}
type ReadyToRunInfo struct {
	Major        uint16          `json:"major"`
	Minor        uint16          `json:"minor"`
	Flags        uint32          `json:"flags"`
	Architecture string          `json:"architecture"`
	OSOverride   uint16          `json:"os_override"`
	Sections     []NativeSection `json:"sections"`
}
type NativeFunction struct {
	Index            uint32                  `json:"index"`
	BeginRVA         uint32                  `json:"begin_rva"`
	EndRVA           uint32                  `json:"end_rva"`
	Unwind           uint32                  `json:"unwind"`
	Code             []byte                  `json:"code"`
	Methods          []Token                 `json:"methods,omitempty"`
	Instances        []NativeMethodInstance  `json:"instances,omitempty"`
	ComponentMethods []NativeMethodReference `json:"component_methods,omitempty"`
}

func nativeArchitecture(machine uint16) (string, uint16) {
	for _, os := range []uint16{0, 0x4644, 0xadc4, 0x7b79, 0x1993, 0x1992} {
		switch machine ^ os {
		case 0x14c:
			return "x86_32", os
		case 0x8664:
			return "x86_64", os
		case 0x1c4:
			return "arm32", os
		case 0xaa64:
			return "aarch64", os
		case 0x6264:
			return "loongarch64", os
		case 0x5064:
			return "riscv64", os
		case 0x1f0:
			return "powerpc32", os
		}
	}
	return "unknown", 0
}

func (im *Image) ReadyToRunHeader() (*ReadyToRunInfo, error) {
	if !im.ReadyToRun {
		return nil, nil
	}
	d := im.CLI.ManagedNativeHeader
	if im.Composite {
		d = im.NativeHeader
	}
	b, e := im.BytesAtRVA(d.RVA, d.Size)
	if e != nil {
		return nil, e
	}
	if len(b) < 16 {
		return nil, ErrBounds
	}
	out := &ReadyToRunInfo{Major: binary.LittleEndian.Uint16(b[4:]), Minor: binary.LittleEndian.Uint16(b[6:]), Flags: binary.LittleEndian.Uint32(b[8:])}
	out.Architecture, out.OSOverride = nativeArchitecture(im.Machine)
	n := binary.LittleEndian.Uint32(b[12:])
	if uint64(n)*12 > uint64(len(b))-16 {
		return nil, ErrBounds
	}
	last := uint32(0)
	for i := uint32(0); i < n; i++ {
		p := 16 + int(i)*12
		t := binary.LittleEndian.Uint32(b[p:])
		if i > 0 && t <= last {
			return nil, bad("unordered or duplicate ReadyToRun section")
		}
		last = t
		d := Directory{binary.LittleEndian.Uint32(b[p+4:]), binary.LittleEndian.Uint32(b[p+8:])}
		data, e := im.BytesAtRVA(d.RVA, d.Size)
		if e != nil {
			return nil, e
		}
		out.Sections = append(out.Sections, NativeSection{t, d, data})
	}
	return out, nil
}

func nativeUnsigned(b []byte, at uint64) (uint32, uint64, error) {
	a, e := span(b, at, 1)
	if e != nil {
		return 0, at, e
	}
	first := uint32(a[0])
	n := uint64(1)
	shift := uint(1)
	for n <= 4 && first&(1<<(n-1)) != 0 {
		n++
		shift++
	}
	if n == 5 {
		if first&16 != 0 {
			return 0, at, bad("invalid native unsigned integer")
		}
		v, e := u32(b, at+1)
		return v, at + 5, e
	}
	a, e = span(b, at, n)
	if e != nil {
		return 0, at, e
	}
	v := first >> shift
	for i := uint64(1); i < n; i++ {
		v |= uint32(a[i]) << (uint(8*i) - shift)
	}
	return v, at + n, nil
}

func nativeArrayAt(b []byte, base uint64, width uint32, index uint32) (uint64, bool, error) {
	n := uint64(1)
	if width == 1 {
		n = 2
	} else if width >= 2 {
		n = 4
	}
	p := base + uint64(index/16)*n
	a, e := span(b, p, n)
	if e != nil {
		return 0, false, e
	}
	offset := uint64(a[0])
	if n == 2 {
		offset = uint64(binary.LittleEndian.Uint16(a))
	} else if n == 4 {
		offset = uint64(binary.LittleEndian.Uint32(a))
	}
	offset += base
	for bit := uint32(8); bit > 0; bit >>= 1 {
		v, next, e := nativeUnsigned(b, offset)
		if e != nil {
			return 0, false, e
		}
		if index&bit != 0 {
			if v&2 != 0 {
				offset += uint64(v >> 2)
				continue
			}
		} else if v&1 != 0 {
			offset = next
			continue
		}
		if v&3 == 0 && v>>2 == index&15 {
			return next, true, nil
		}
		return 0, false, nil
	}
	return offset, true, nil
}

func (im *Image) NativeFunctions() ([]NativeFunction, error) {
	header, e := im.ReadyToRunHeader()
	if e != nil || header == nil {
		return nil, e
	}
	var table, entries []byte
	for _, s := range header.Sections {
		if s.Type == 102 {
			table = s.Data
		}
		if s.Type == 103 {
			entries = s.Data
		}
	}
	if len(table) == 0 {
		return nil, nil
	}
	width := 8
	if header.Architecture == "x86_64" {
		width = 12
	}
	if len(table)%width != 0 {
		return nil, bad("invalid runtime function table width")
	}
	if header.Architecture == "unknown" {
		return nil, bad("unknown ReadyToRun native machine %x", im.Machine)
	}
	out := make([]NativeFunction, len(table)/width)
	for i := range out {
		p := i * width
		start := binary.LittleEndian.Uint32(table[p:])
		unwind := binary.LittleEndian.Uint32(table[p+4:])
		end := uint64(0)
		if width == 12 {
			end = uint64(unwind)
			unwind = binary.LittleEndian.Uint32(table[p+8:])
		} else {
			length := uint32(0)
			switch header.Architecture {
			case "aarch64":
				if unwind&3 != 0 {
					length = ((unwind >> 2) & 0x7ff) * 4
				} else {
					b, e := im.BytesAtRVA(unwind, 4)
					if e != nil {
						return nil, e
					}
					length = (binary.LittleEndian.Uint32(b) & 0x3ffff) * 4
				}
			case "arm32":
				start &= ^uint32(1)
				if unwind&3 != 0 {
					length = ((unwind >> 2) & 0x7ff) * 2
				} else {
					b, e := im.BytesAtRVA(unwind, 4)
					if e != nil {
						return nil, e
					}
					length = (binary.LittleEndian.Uint32(b) & 0x3ffff) * 2
				}
			case "loongarch64", "riscv64":
				b, e := im.BytesAtRVA(unwind, 4)
				if e != nil {
					return nil, e
				}
				length = (binary.LittleEndian.Uint32(b) & 0x3ffff) * 4
			case "x86_32":
				offset, e := im.RVAOffset(unwind, 1)
				if e != nil {
					return nil, e
				}
				for n := 0; n < 5; n++ {
					b, e := span(im.Data, offset+uint64(n), 1)
					if e != nil {
						return nil, e
					}
					if length > math.MaxUint32>>7 {
						return nil, ErrBounds
					}
					length = length<<7 | uint32(b[0]&127)
					if b[0]&128 == 0 {
						break
					}
					if n == 4 {
						return nil, bad("invalid x86 GC length")
					}
				}
			default:
				return nil, bad("native function length decoding for %s requires its unwind format", header.Architecture)
			}
			end = uint64(start) + uint64(length)
		}
		if end > math.MaxUint32 || end <= uint64(start) {
			return nil, bad("invalid native function extent")
		}
		code, e := im.BytesAtRVA(start, uint32(end)-start)
		if e != nil {
			return nil, e
		}
		out[i] = NativeFunction{Index: uint32(i), BeginRVA: start, EndRVA: uint32(end), Unwind: unwind, Code: code}
	}
	if len(entries) > 0 {
		value, base, e := nativeUnsigned(entries, 0)
		if e != nil {
			return nil, e
		}
		count, width := value>>2, value&3
		if count > im.Metadata.Tables[6].Count {
			return nil, bad("ReadyToRun method array exceeds MethodDef count")
		}
		for i := uint32(0); i < count; i++ {
			at, found, e := nativeArrayAt(entries, base, width, i)
			if e != nil {
				return nil, e
			}
			if !found {
				continue
			}
			id, _, e := nativeUnsigned(entries, at)
			if e != nil {
				return nil, e
			}
			if id&1 != 0 {
				id >>= 2
			} else {
				id >>= 1
			}
			if uint64(id) >= uint64(len(out)) {
				return nil, bad("ReadyToRun function index out of bounds")
			}
			out[id].Methods = append(out[id].Methods, Token(6<<24|i+1))
		}
	}
	instances, e := im.NativeMethodInstances()
	if e != nil {
		return nil, e
	}
	for _, instance := range instances {
		if uint64(instance.FunctionIndex) >= uint64(len(out)) {
			return nil, bad("ReadyToRun generic function index out of bounds")
		}
		out[instance.FunctionIndex].Instances = append(out[instance.FunctionIndex].Instances, instance)
	}
	if im.Composite {
		components, e := im.ReadyToRunComponents()
		if e != nil {
			return nil, e
		}
		for _, c := range components {
			for _, s := range c.Sections {
				if s.Type != 103 {
					continue
				}
				count, base, e := nativeUnsigned(s.Data, 0)
				if e != nil {
					return nil, e
				}
				width := count & 3
				count >>= 2
				if uint64(count) > uint64(len(s.Data))*16 || (c.Metadata != nil && count > c.Metadata.Tables[6].Count) {
					return nil, bad("component method array exceeds metadata")
				}
				for i := uint32(0); i < count; i++ {
					at, found, e := nativeArrayAt(s.Data, base, width, i)
					if e != nil {
						return nil, e
					}
					if !found {
						continue
					}
					id, _, e := nativeEntryPoint(s.Data, at)
					if e != nil {
						return nil, e
					}
					if uint64(id) >= uint64(len(out)) {
						return nil, bad("component function index out of bounds")
					}
					out[id].ComponentMethods = append(out[id].ComponentMethods, NativeMethodReference{c.Index, Token(6<<24 | i + 1)})
				}
			}
		}
	}
	return out, nil
}

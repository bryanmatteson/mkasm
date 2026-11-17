package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

// Module contains class_data-referenced code_items from a standard little endian
// DEX file. Identifier pools are counted for instruction index validation.
type Module struct {
	Version int       `json:"version"`
	Pools   PoolSizes `json:"pools"`
	Methods []Method  `json:"methods"`
}
type Method struct {
	Index      uint32    `json:"index"`
	CodeOffset uint32    `json:"code_offset"`
	Code       *CodeItem `json:"code"`
}

func (c *Catalog) DecodeDEX(data []byte) (*Module, error) {
	if len(data) < 112 {
		return nil, ErrTruncated
	}
	if !bytes.Equal(data[:4], []byte("dex\n")) || data[7] != 0 {
		return nil, malformed("invalid DEX magic")
	}
	v, e := strconv.Atoi(string(data[4:7]))
	if e != nil || !validVersion(v) {
		return nil, malformed("unsupported DEX version")
	}
	size := binary.LittleEndian.Uint32(data[32:])
	header := binary.LittleEndian.Uint32(data[36:])
	expected := uint32(112)
	if v == 41 {
		expected = 120
	}
	if uint64(size) != uint64(len(data)) || header != expected {
		return nil, malformed("invalid DEX file/header size")
	}
	if binary.LittleEndian.Uint32(data[40:]) != 0x12345678 {
		return nil, malformed("DEX byte order unsupported")
	}
	if v == 41 {
		if len(data) < 120 {
			return nil, ErrTruncated
		}
		if binary.LittleEndian.Uint32(data[112:]) != size || binary.LittleEndian.Uint32(data[116:]) != 0 {
			return nil, malformed("multi-header DEX container requires selecting its logical file")
		}
	}
	m := &Module{Version: v, Pools: PoolSizes{"CallSite": 0, "MethodHandle": 0}}
	for i, s := range []struct {
		name  string
		width uint64
	}{{"String", 4}, {"Type", 4}, {"Proto", 12}, {"Field", 8}, {"Method", 8}, {"Class", 32}} {
		p := 56 + i*8
		count := binary.LittleEndian.Uint32(data[p:])
		off := binary.LittleEndian.Uint32(data[p+4:])
		if count > 0 && (off%4 != 0 || off < header || uint64(off)+uint64(count)*s.width > uint64(len(data))) {
			return nil, malformed("invalid DEX identifier section")
		}
		m.Pools[s.name] = count
	}
	// Call site and method handle counts live in the map rather than the header.
	mapoff := binary.LittleEndian.Uint32(data[52:])
	if mapoff != 0 {
		if mapoff%4 != 0 || uint64(mapoff)+4 > uint64(len(data)) {
			return nil, malformed("invalid DEX map")
		}
		count := binary.LittleEndian.Uint32(data[mapoff:])
		if uint64(mapoff)+4+uint64(count)*12 > uint64(len(data)) {
			return nil, ErrTruncated
		}
		for i := uint32(0); i < count; i++ {
			p := uint64(mapoff) + 4 + uint64(i)*12
			typ := binary.LittleEndian.Uint16(data[p:])
			n := binary.LittleEndian.Uint32(data[p+4:])
			off := binary.LittleEndian.Uint32(data[p+8:])
			if typ == 7 || typ == 8 {
				w := uint64(4)
				k := "CallSite"
				if typ == 8 {
					w = 8
					k = "MethodHandle"
				}
				if uint64(off)+uint64(n)*w > uint64(len(data)) {
					return nil, ErrTruncated
				}
				m.Pools[k] = n
			}
		}
	}
	classoff := binary.LittleEndian.Uint32(data[100:])
	seen := map[uint32]bool{}
	for i := uint32(0); i < m.Pools["Class"]; i++ {
		base := uint64(classoff) + uint64(i)*32
		off := binary.LittleEndian.Uint32(data[base+24:])
		if off == 0 {
			continue
		}
		if uint64(off) >= uint64(len(data)) {
			return nil, ErrTruncated
		}
		pos := int(off)
		counts := [4]uint32{}
		for j := range counts {
			counts[j], e = uleb(data, &pos)
			if e != nil {
				return nil, e
			}
			if uint64(counts[j]) > uint64(len(data)-pos)/2 {
				return nil, ErrTruncated
			}
		}
		for j := 0; j < 2; j++ {
			idx := uint64(0)
			for k := uint32(0); k < counts[j]; k++ {
				delta, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				idx += uint64(delta)
				if idx >= uint64(m.Pools["Field"]) {
					return nil, malformed("field index out of bounds")
				}
				if _, e = uleb(data, &pos); e != nil {
					return nil, e
				}
			}
		}
		for j := 2; j < 4; j++ {
			idx := uint64(0)
			for k := uint32(0); k < counts[j]; k++ {
				delta, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				idx += uint64(delta)
				if idx >= uint64(m.Pools["Method"]) {
					return nil, malformed("method index out of bounds")
				}
				if _, e = uleb(data, &pos); e != nil {
					return nil, e
				}
				code, e := uleb(data, &pos)
				if e != nil {
					return nil, e
				}
				if code == 0 {
					continue
				}
				if code%4 != 0 || uint64(code) >= uint64(len(data)) || seen[uint32(idx)] {
					return nil, malformed("invalid or duplicate method code")
				}
				ci, e := c.DecodeCodeItem(data[code:], v)
				if e != nil {
					return nil, fmt.Errorf("method %d code_item: %w", idx, e)
				}
				units := uint32(0)
				for _, in := range ci.Instructions {
					units += uint32(in.Length / 2)
				}
				if e = c.validateCodeItem(ci, units, m.Pools); e != nil {
					return nil, e
				}
				seen[uint32(idx)] = true
				m.Methods = append(m.Methods, Method{uint32(idx), code, ci})
			}
		}
	}
	return m, nil
}

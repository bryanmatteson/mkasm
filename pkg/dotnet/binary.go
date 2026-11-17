package dotnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrBounds = errors.New("dotnet: truncated or out-of-bounds data")

func span(b []byte, p, n uint64) ([]byte, error) {
	if p > uint64(len(b)) || n > uint64(len(b))-p {
		return nil, ErrBounds
	}
	return b[p : p+n], nil
}
func u16(b []byte, p uint64) (uint16, error) {
	a, e := span(b, p, 2)
	if e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint16(a), nil
}
func u32(b []byte, p uint64) (uint32, error) {
	a, e := span(b, p, 4)
	if e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint32(a), nil
}
func u64(b []byte, p uint64) (uint64, error) {
	a, e := span(b, p, 8)
	if e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint64(a), nil
}

type cursor struct {
	b []byte
	p uint64
	// ReadyToRun signatures extend ECMA types and permit padded integers.
	native bool
}

func (r *cursor) take(n uint64) ([]byte, error) {
	a, e := span(r.b, r.p, n)
	if e == nil {
		r.p += n
	}
	return a, e
}
func (r *cursor) uint(n int) (uint32, error) {
	a, e := r.take(uint64(n))
	if e != nil {
		return 0, e
	}
	switch n {
	case 1:
		return uint32(a[0]), nil
	case 2:
		return uint32(binary.LittleEndian.Uint16(a)), nil
	case 4:
		return binary.LittleEndian.Uint32(a), nil
	}
	return 0, errors.New("invalid integer width")
}
func (r *cursor) compressed() (uint32, error) {
	a, e := r.uint(1)
	if e != nil {
		return 0, e
	}
	if a&0x80 == 0 {
		return a, nil
	}
	if a&0xc0 == 0x80 {
		b, e := r.uint(1)
		if e != nil {
			return 0, e
		}
		n := (a&0x3f)<<8 | b
		if n < 0x80 && !r.native {
			return 0, errors.New("nonminimal compressed integer")
		}
		return n, nil
	}
	if a&0xe0 == 0xc0 {
		b, e := r.take(3)
		if e != nil {
			return 0, e
		}
		n := (a&31)<<24 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		if n < 0x4000 && !r.native {
			return 0, errors.New("nonminimal compressed integer")
		}
		return n, nil
	}
	return 0, errors.New("reserved compressed integer prefix")
}
func CompressedInteger(b []byte) (uint32, int, error) {
	r := cursor{b: b}
	n, e := r.compressed()
	return n, int(r.p), e
}
func (r *cursor) signedCompressed() (int32, error) {
	a, e := r.uint(1)
	if e != nil {
		return 0, e
	}
	bits := uint32(7)
	n := a
	if a&0xc0 == 0x80 {
		b, e := r.uint(1)
		if e != nil {
			return 0, e
		}
		bits = 14
		n = (a&63)<<8 | b
	} else if a&0xe0 == 0xc0 {
		b, e := r.take(3)
		if e != nil {
			return 0, e
		}
		bits = 29
		n = (a&31)<<24 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	} else if a&0x80 != 0 {
		return 0, bad("reserved signed compressed prefix")
	}
	v := int32(n >> 1)
	if n&1 != 0 {
		v |= -1 << (bits - 1)
	}
	if bits == 14 && v >= -64 && v <= 63 || bits == 29 && v >= -8192 && v <= 8191 {
		return 0, bad("nonminimal signed compressed integer")
	}
	return v, nil
}
func Parse(r io.Reader) (*Image, error) {
	b, e := io.ReadAll(r)
	if e != nil {
		return nil, e
	}
	return Open(b)
}
func bad(format string, a ...any) error { return fmt.Errorf("dotnet: "+format, a...) }

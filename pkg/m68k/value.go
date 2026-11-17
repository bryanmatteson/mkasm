package m68k

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Value struct {
	Kind     string
	U        uint64
	Negative bool
	Text     string
	Items    []Value
}

func U(n uint64) Value { return Value{Kind: "number", U: n} }
func S(n int64) Value {
	if n < 0 {
		return Value{Kind: "number", U: uint64(-(n + 1)) + 1, Negative: true}
	}
	return U(uint64(n))
}
func T(s string) Value   { return Value{Kind: "text", Text: s} }
func L(v ...Value) Value { return Value{Kind: "list", Items: v} }
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.Kind {
	case "number":
		s := strconv.FormatUint(v.U, 10)
		if v.Negative {
			s = "-" + s
		}
		return []byte(s), nil
	case "text":
		return json.Marshal(v.Text)
	case "list":
		if v.Items == nil {
			return []byte("[]"), nil
		}
		return json.Marshal(v.Items)
	}
	return nil, fmt.Errorf("invalid operand value kind %q", v.Kind)
}
func (v *Value) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty value")
	}
	switch b[0] {
	case '[':
		v.Kind = "list"
		return json.Unmarshal(b, &v.Items)
	case '"':
		v.Kind = "text"
		return json.Unmarshal(b, &v.Text)
	default:
		s := string(b)
		v.Kind = "number"
		v.Negative = strings.HasPrefix(s, "-")
		s = strings.TrimPrefix(s, "-")
		n, e := strconv.ParseUint(s, 10, 64)
		v.U = n
		return e
	}
}
func (v Value) unsigned(bits int) (uint64, error) {
	if v.Kind != "number" || v.Negative || (bits < 64 && v.U >= uint64(1)<<bits) {
		return 0, fmt.Errorf("expected unsigned %d-bit integer", bits)
	}
	return v.U, nil
}
func (v Value) signed(bits int) (int64, error) {
	if v.Kind != "number" {
		return 0, errors.New("expected signed integer")
	}
	limit := uint64(1) << (bits - 1)
	if v.Negative {
		if v.U > limit {
			return 0, errors.New("signed integer underflow")
		}
		return -int64(v.U), nil
	}
	if v.U >= limit {
		return 0, errors.New("signed integer overflow")
	}
	return int64(v.U), nil
}

// Byte immediates occupy an entire extension word. The unused upper byte
// is retained: GNU as sign-extends negative literals, and either padding
// convention is valid. A two-byte array represents other unused-bit values.
func byteImmediate(v Value) ([]byte, error) {
	if v.Kind == "list" {
		a, e := getList(v, 2)
		if e != nil {
			return nil, e
		}
		out := make([]byte, 2)
		for i, x := range a {
			n, e := x.unsigned(8)
			if e != nil {
				return nil, e
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	n, e := number(v)
	if e != nil || n < -128 || n > 255 {
		return nil, fmt.Errorf("byte immediate outside -128..255")
	}
	return []byte{byte(n >> 8), byte(n)}, nil
}
func decodeByteImmediate(b []byte) Value {
	if b[0] == 0 {
		return U(uint64(b[1]))
	}
	if b[0] == 255 && b[1] >= 128 {
		return S(int64(int8(b[1])))
	}
	return L(U(uint64(b[0])), U(uint64(b[1])))
}

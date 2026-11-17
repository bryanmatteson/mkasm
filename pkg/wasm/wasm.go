// Package wasm imports the complete wasm-tools opcode grammar and operates on
// individual instructions. It does not validate module types or control stacks.
package wasm

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const Schema = "mkasm.wasm-opcodes.v1"

type Field struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type Opcode struct {
	ID       string  `json:"id"`
	Mnemonic string  `json:"mnemonic"`
	Prefix   uint32  `json:"prefix"`
	Opcode   uint32  `json:"opcode"`
	Feature  string  `json:"feature"`
	Fields   []Field `json:"fields"`
	Nullable *bool   `json:"nullable,omitempty"`
}
type Catalog struct {
	Schema       string   `json:"schema"`
	Architecture string   `json:"architecture"`
	Source       string   `json:"source"`
	SourceCommit string   `json:"source_commit,omitempty"`
	Opcodes      []Opcode `json:"opcodes"`
	byCode       map[uint64]int
	byName       map[string][]int
}

// Value is a recursive, lossless operand tree. Numbers retain all 64 bits.
// Its JSON representation is a number, string, or array, without object wrappers.
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

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "wasm32" && architecture != "wasm64" {
		return nil, fmt.Errorf("wasm: unsupported architecture %q", architecture)
	}
	var c Catalog
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	// Source digests are metadata emitted by the upstream extractor.
	var input struct {
		Schema       string            `json:"schema"`
		Architecture string            `json:"architecture"`
		Source       string            `json:"source"`
		SourceCommit string            `json:"source_commit"`
		SourceSHA256 map[string]string `json:"source_sha256"`
		Opcodes      []Opcode          `json:"opcodes"`
	}
	if err := d.Decode(&input); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("wasm: trailing input")
	}
	c.Schema = input.Schema
	c.Source = input.Source
	c.SourceCommit = input.SourceCommit
	c.Opcodes = input.Opcodes
	c.Architecture = architecture
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
func (c *Catalog) Validate() error {
	if c.Architecture != "wasm32" && c.Architecture != "wasm64" {
		return fmt.Errorf("wasm: unsupported architecture %q", c.Architecture)
	}
	if c.Schema != Schema || len(c.Opcodes) == 0 {
		return errors.New("wasm: missing opcode grammar")
	}
	c.byCode = make(map[uint64]int)
	c.byName = make(map[string][]int)
	ids := map[string]bool{}
	kinds := map[string]bool{}
	for _, s := range strings.Fields("u32 s32 s64 f32 f64 lane v128 shuffle block br_table valtype valtypes memarg heaptype reftype try_table resume_table ordering cast zero") {
		kinds[s] = true
	}
	for i, o := range c.Opcodes {
		if o.ID == "" || o.Mnemonic == "" || o.Feature == "" || ids[o.ID] {
			return fmt.Errorf("wasm: invalid/duplicate opcode %s", o.ID)
		}
		ids[o.ID] = true
		if o.Prefix != 0 && o.Prefix != 0xfb && o.Prefix != 0xfc && o.Prefix != 0xfd && o.Prefix != 0xfe {
			return fmt.Errorf("wasm: invalid prefix %x", o.Prefix)
		}
		if o.Prefix == 0 && (o.Opcode > 255 || o.Opcode >= 0xfb) {
			return errors.New("wasm: invalid unprefixed opcode")
		}
		key := uint64(o.Prefix)<<32 | uint64(o.Opcode)
		if _, ok := c.byCode[key]; ok {
			return fmt.Errorf("wasm: duplicate opcode %s", o.ID)
		}
		c.byCode[key] = i
		c.byName[o.ID] = append(c.byName[o.ID], i)
		if o.Mnemonic != o.ID {
			c.byName[o.Mnemonic] = append(c.byName[o.Mnemonic], i)
		}
		names := map[string]bool{}
		for _, f := range o.Fields {
			if !kinds[f.Kind] || f.Name == "" || names[f.Name] {
				return fmt.Errorf("wasm %s: invalid field %s/%s", o.ID, f.Name, f.Kind)
			}
			names[f.Name] = true
		}
	}
	return nil
}
func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }

type Instruction struct {
	Opcode   *Opcode
	Operands []Value
	Length   int
}

func (i *Instruction) Format() string {
	if len(i.Operands) == 0 {
		return i.Opcode.Mnemonic
	}
	b, _ := json.Marshal(i.Operands)
	name := i.Opcode.Mnemonic
	if i.Opcode.Nullable != nil {
		name = i.Opcode.ID
	}
	return name + " " + string(b)
}

var ErrTruncated = errors.New("wasm: truncated instruction")
var ErrUnknown = errors.New("wasm: unknown opcode")

type reader struct {
	b []byte
	p int
}

func (r *reader) byte() (byte, error) {
	if r.p >= len(r.b) {
		return 0, ErrTruncated
	}
	v := r.b[r.p]
	r.p++
	return v, nil
}
func (r *reader) uleb(bits int) (uint64, error) {
	var n uint64
	for i := 0; i < (bits+6)/7; i++ {
		b, e := r.byte()
		if e != nil {
			return 0, e
		}
		remain := bits - i*7
		if remain < 7 && uint64(b&127) >= uint64(1)<<remain {
			return 0, errors.New("wasm: unsigned LEB overflow")
		}
		n |= uint64(b&127) << uint(i*7)
		if b&128 == 0 {
			return n, nil
		}
	}
	return 0, errors.New("wasm: unsigned LEB too long")
}
func (r *reader) sleb(bits int) (int64, error) {
	var n uint64
	for i := 0; i < (bits+6)/7; i++ {
		b, e := r.byte()
		if e != nil {
			return 0, e
		}
		shift := i * 7
		remain := bits - shift
		if remain < 7 {
			mask := byte(127 & (127 << uint(remain)))
			sign := byte(1) << uint(remain-1)
			if (b&sign == 0 && b&mask != 0) || (b&sign != 0 && b&mask != mask) {
				return 0, errors.New("wasm: signed LEB overflow")
			}
		}
		n |= uint64(b&127) << uint(shift)
		if b&128 == 0 {
			end := shift + 7
			if end < 64 && b&64 != 0 {
				n |= ^uint64(0) << uint(end)
			}
			return int64(n), nil
		}
	}
	return 0, errors.New("wasm: signed LEB too long")
}
func putU(b []byte, n uint64) []byte {
	for {
		v := byte(n & 127)
		n >>= 7
		if n != 0 {
			v |= 128
		}
		b = append(b, v)
		if n == 0 {
			return b
		}
	}
}
func putS(b []byte, n int64) []byte {
	for {
		v := byte(n & 127)
		n >>= 7
		done := (n == 0 && v&64 == 0) || (n == -1 && v&64 != 0)
		if !done {
			v |= 128
		}
		b = append(b, v)
		if done {
			return b
		}
	}
}
func (c *Catalog) Decode(src []byte) (*Instruction, error) {
	r := reader{b: src}
	first, e := r.byte()
	if e != nil {
		return nil, e
	}
	prefix, op := uint32(0), uint32(first)
	if first >= 0xfb && first <= 0xfe {
		prefix = uint32(first)
		n, e := r.uleb(32)
		if e != nil {
			return nil, e
		}
		op = uint32(n)
	}
	idx, ok := c.byCode[uint64(prefix)<<32|uint64(op)]
	if !ok {
		return nil, ErrUnknown
	}
	def := &c.Opcodes[idx]
	result := &Instruction{Opcode: def}
	for _, f := range def.Fields {
		v, e := c.readValue(&r, f.Kind, def)
		if e != nil {
			return nil, fmt.Errorf("%s %s: %w", def.ID, f.Name, e)
		}
		result.Operands = append(result.Operands, v)
	}
	result.Length = r.p
	return result, nil
}
func (c *Catalog) Encode(id string, values []Value) ([]byte, error) {
	indexes := c.byName[id]
	var last error
	for _, idx := range indexes {
		o := &c.Opcodes[idx]
		if len(values) != len(o.Fields) {
			last = errors.New("incorrect operand count")
			continue
		}
		var b []byte
		if o.Prefix != 0 {
			b = append(b, byte(o.Prefix))
			b = putU(b, uint64(o.Opcode))
		} else {
			b = append(b, byte(o.Opcode))
		}
		ok := true
		for i, f := range o.Fields {
			var e error
			b, e = c.writeValue(b, values[i], f.Kind, o)
			if e != nil {
				last = fmt.Errorf("%s %s: %w", o.ID, f.Name, e)
				ok = false
				break
			}
		}
		if ok {
			return b, nil
		}
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("wasm: unknown instruction %q", id)
}

// Assemble accepts the canonical lossless instruction syntax from Format. Simple
// scalar immediates may also be written as ordinary whitespace-separated integers.
func (c *Catalog) Assemble(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	name, rest := text, ""
	if i := strings.IndexFunc(text, unicode.IsSpace); i >= 0 {
		name, rest = text[:i], text[i:]
	}
	var values []Value
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") {
		if err := json.Unmarshal([]byte(rest), &values); err != nil {
			return nil, err
		}
	} else if rest != "" {
		for _, p := range strings.Fields(rest) {
			if n, e := strconv.ParseInt(p, 0, 64); e == nil {
				values = append(values, S(n))
			} else if n, e := strconv.ParseUint(p, 0, 64); e == nil {
				values = append(values, U(n))
			} else {
				values = append(values, T(p))
			}
		}
	}
	return c.Encode(name, values)
}
func (c *Catalog) Disassemble(src []byte) ([]*Instruction, error) {
	var result []*Instruction
	for len(src) > 0 {
		i, e := c.Decode(src)
		if e != nil {
			return result, e
		}
		result = append(result, i)
		src = src[i.Length:]
	}
	return result, nil
}

// AssembleReader assembles one canonical instruction per line; it does not add
// module headers, function bodies, local declarations, or implicit end opcodes.
func (c *Catalog) AssembleReader(r io.Reader) ([]byte, error) {
	var result []byte
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 16<<20)
	line := 0
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, ";;") {
			continue
		}
		b, e := c.Assemble(text)
		if e != nil {
			return nil, fmt.Errorf("line %d: %w", line, e)
		}
		result = append(result, b...)
	}
	return result, s.Err()
}
func (c *Catalog) Features() []string {
	m := map[string]bool{}
	for _, o := range c.Opcodes {
		m[o.Feature] = true
	}
	var r []string
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

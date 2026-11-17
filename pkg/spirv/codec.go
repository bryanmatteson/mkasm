package spirv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// Operand retains grammar structure: enum-dependent parameters and composite
// operands are nested; scalar IDs/numbers use Words; strings use Text.
type Operand struct {
	Kind       string    `json:"kind"`
	Words      []uint32  `json:"words,omitempty"`
	Text       string    `json:"text,omitempty"`
	Parameters []Operand `json:"parameters,omitempty"`
}
type Instruction struct {
	Opcode   uint16    `json:"opcode"`
	Operands []Operand `json:"operands,omitempty"`
}
type Context struct {
	TypeWidths     map[uint32]uint32
	IdTypes        map[uint32]uint32
	FloatTypes     map[uint32]bool
	SignedTypes    map[uint32]bool
	FloatEncodings map[uint32]uint32
}

func NewContext() *Context {
	return &Context{TypeWidths: map[uint32]uint32{}, IdTypes: map[uint32]uint32{}, FloatTypes: map[uint32]bool{}, SignedTypes: map[uint32]bool{}, FloatEncodings: map[uint32]uint32{}}
}
func (ctx *Context) Observe(i Instruction) {
	if ctx == nil {
		return
	}
	if ctx.TypeWidths == nil {
		ctx.TypeWidths = map[uint32]uint32{}
	}
	if ctx.IdTypes == nil {
		ctx.IdTypes = map[uint32]uint32{}
	}
	if ctx.FloatTypes == nil {
		ctx.FloatTypes = map[uint32]bool{}
	}
	if ctx.FloatEncodings == nil {
		ctx.FloatEncodings = map[uint32]uint32{}
	}
	if ctx.SignedTypes == nil {
		ctx.SignedTypes = map[uint32]bool{}
	}
	var id, typ uint32
	for _, o := range i.Operands {
		if o.Kind == "IdResult" {
			id = o.Words[0]
		}
		if o.Kind == "IdResultType" {
			typ = o.Words[0]
		}
	}
	if id != 0 && typ != 0 {
		ctx.IdTypes[id] = typ
	}
	if (i.Opcode == 21 || i.Opcode == 22) && len(i.Operands) >= 2 {
		ctx.TypeWidths[id] = i.Operands[1].Words[0]
		ctx.FloatTypes[id] = i.Opcode == 22
		if i.Opcode == 22 && len(i.Operands) > 2 {
			ctx.FloatEncodings[id] = i.Operands[2].Words[0]
		}
		if i.Opcode == 21 && len(i.Operands) > 2 {
			ctx.SignedTypes[id] = i.Operands[2].Words[0] != 0
		}
	}
}
func (ctx *Context) width(typ uint32) int {
	if ctx != nil {
		if n := ctx.TypeWidths[typ]; n != 0 {
			return int((uint64(n) + 31) / 32)
		}
	}
	return 0
}

func (c *Catalog) Decode(data []byte, ctx *Context, env *Environment) (Instruction, int, error) {
	if len(data) < 4 {
		return Instruction{}, 0, fmt.Errorf("spirv: truncated instruction header")
	}
	header := binary.LittleEndian.Uint32(data)
	count := int(header >> 16)
	if count == 0 {
		return Instruction{}, 0, fmt.Errorf("spirv: zero instruction word count")
	}
	if len(data) < count*4 {
		return Instruction{}, 0, fmt.Errorf("spirv: truncated %d-word instruction", count)
	}
	words := make([]uint32, count)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(data[4*i:])
	}
	i, err := c.decodeWords(words, ctx, env)
	return i, count * 4, err
}
func (c *Catalog) decodeWords(words []uint32, ctx *Context, env *Environment) (Instruction, error) {
	if len(words) == 0 || int(words[0]>>16) != len(words) {
		return Instruction{}, fmt.Errorf("spirv: inconsistent word count")
	}
	opcode := uint16(words[0])
	def := c.ops[opcode]
	if def == nil {
		return Instruction{}, fmt.Errorf("spirv: unknown opcode %d", opcode)
	}
	if !allowed(def.Requirements, env) {
		return Instruction{}, fmt.Errorf("spirv: %s unavailable in environment", def.Name)
	}
	numberWords := 0
	switchWords := 1
	if len(words) > 1 && (opcode == 43 || opcode == 50) {
		numberWords = ctx.width(words[1])
	}
	if len(words) > 1 && opcode == 251 && ctx != nil {
		if n := ctx.width(ctx.IdTypes[words[1]]); n != 0 {
			switchWords = n
		}
	}
	d := wordDecoder{c: c, ctx: ctx, env: env, numberWords: numberWords, switchWords: switchWords}
	operands, n, err := d.sequence(def.Operands, words[1:], 0)
	if err != nil {
		return Instruction{}, fmt.Errorf("%s: %w", def.Name, err)
	}
	if n != len(words)-1 {
		return Instruction{}, fmt.Errorf("%s: %d trailing operand words", def.Name, len(words)-1-n)
	}
	return Instruction{opcode, operands}, nil
}

type wordDecoder struct {
	c                        *Catalog
	ctx                      *Context
	env                      *Environment
	numberWords, switchWords int
}

func (d wordDecoder) sequence(specs []OperandSpec, words []uint32, depth int) ([]Operand, int, error) {
	if depth > 64 {
		return nil, 0, fmt.Errorf("operand grammar nesting limit")
	}
	var out []Operand
	pos := 0
	for _, s := range specs {
		repeat := s.Quantifier == "*"
		optional := repeat || s.Quantifier == "?"
		if optional && pos == len(words) {
			continue
		}
		for {
			v, n, err := d.one(s.Kind, words[pos:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			if n == 0 {
				return nil, 0, fmt.Errorf("empty operand")
			}
			out = append(out, v)
			pos += n
			if !repeat || pos == len(words) {
				break
			}
		}
	}
	return out, pos, nil
}
func (d wordDecoder) one(kind string, words []uint32, depth int) (Operand, int, error) {
	o := Operand{Kind: kind}
	if depth > 64 {
		return o, 0, fmt.Errorf("operand nesting limit")
	}
	if len(words) == 0 {
		return o, 0, fmt.Errorf("missing %s", kind)
	}
	k := d.c.kinds[kind]
	if k == nil {
		return o, 0, fmt.Errorf("unknown operand kind %s", kind)
	}
	if k.Category == "Composite" {
		pos := 0
		for _, base := range k.Bases {
			if kind == "PairLiteralIntegerIdRef" && base == "LiteralInteger" && d.switchWords > 1 {
				n := d.switchWords
				if n > len(words)-pos {
					return o, 0, fmt.Errorf("truncated wide switch literal")
				}
				o.Parameters = append(o.Parameters, Operand{Kind: base, Words: append([]uint32{}, words[pos:pos+n]...)})
				pos += n
				continue
			}
			v, n, err := d.one(base, words[pos:], depth+1)
			if err != nil {
				return o, 0, err
			}
			o.Parameters = append(o.Parameters, v)
			pos += n
		}
		return o, pos, nil
	}
	if kind == "LiteralString" {
		var b []byte
		for j, w := range words {
			for n := 0; n < 4; n++ {
				ch := byte(w >> uint(n*8))
				if ch == 0 {
					if w>>uint(n*8) != 0 {
						return o, 0, fmt.Errorf("nonzero string padding")
					}
					if !utf8.Valid(b) {
						return o, 0, fmt.Errorf("invalid UTF-8 string")
					}
					o.Text = string(b)
					return o, j + 1, nil
				}
				b = append(b, ch)
			}
		}
		return o, 0, fmt.Errorf("unterminated literal string")
	}
	n := 1
	if kind == "LiteralContextDependentNumber" {
		n = d.numberWords
		if n == 0 {
			n = len(words)
		}
		if n > len(words) {
			return o, 0, fmt.Errorf("truncated context-dependent number")
		}
	}
	o.Words = append([]uint32{}, words[:n]...)
	if k.Category == "Id" && words[0] == 0 {
		return o, 0, fmt.Errorf("zero %s", kind)
	}
	var specs []OperandSpec
	if k.Category == "BitEnum" || k.Category == "ValueEnum" {
		var err error
		specs, err = enumParams(k, words[0], d.env)
		if err != nil {
			return o, 0, err
		}
	}
	if kind == "LiteralSpecConstantOpInteger" {
		if words[0] > 65535 {
			return o, 0, fmt.Errorf("invalid embedded opcode")
		}
		def := d.c.ops[uint16(words[0])]
		if def == nil {
			return o, 0, fmt.Errorf("unknown embedded opcode")
		}
		if !allowed(def.Requirements, d.env) {
			return o, 0, fmt.Errorf("embedded instruction unavailable")
		}
		for _, s := range def.Operands {
			if s.Kind != "IdResult" && s.Kind != "IdResultType" {
				specs = append(specs, s)
			}
		}
	}
	if len(specs) > 0 {
		params, used, err := d.sequence(specs, words[n:], depth+1)
		if err != nil {
			return o, 0, err
		}
		o.Parameters = params
		n += used
	}
	return o, n, nil
}
func (c *Catalog) Encode(i Instruction, ctx *Context, env *Environment) ([]byte, error) {
	var words []uint32
	words = append(words, 0)
	for _, o := range i.Operands {
		w, err := c.operandWords(o)
		if err != nil {
			return nil, err
		}
		words = append(words, w...)
	}
	if len(words) > 65535 {
		return nil, fmt.Errorf("instruction exceeds 65535 words")
	}
	words[0] = uint32(len(words))<<16 | uint32(i.Opcode)
	decoded, err := c.decodeWords(words, ctx, env)
	if err != nil {
		return nil, err
	}
	if !equalOperands(i.Operands, decoded.Operands) {
		return nil, fmt.Errorf("structured operands do not match opcode grammar")
	}
	out := make([]byte, 4*len(words))
	for n, w := range words {
		binary.LittleEndian.PutUint32(out[4*n:], w)
	}
	return out, nil
}
func (c *Catalog) operandWords(o Operand) ([]uint32, error) {
	k := c.kinds[o.Kind]
	if k == nil {
		return nil, fmt.Errorf("unknown operand kind %s", o.Kind)
	}
	var words []uint32
	if o.Kind == "LiteralString" {
		if len(o.Words) > 0 || len(o.Parameters) > 0 || !utf8.ValidString(o.Text) || bytes.IndexByte([]byte(o.Text), 0) >= 0 {
			return nil, fmt.Errorf("invalid literal string")
		}
		b := append([]byte(o.Text), 0)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		for n := 0; n < len(b); n += 4 {
			words = append(words, binary.LittleEndian.Uint32(b[n:]))
		}
		return words, nil
	}
	if o.Text != "" {
		return nil, fmt.Errorf("text on non-string operand")
	}
	if k.Category == "Composite" {
		if len(o.Words) != 0 {
			return nil, fmt.Errorf("words on composite operand")
		}
	} else if len(o.Words) == 0 {
		return nil, fmt.Errorf("missing scalar operand words")
	}
	words = append(words, o.Words...)
	for _, p := range o.Parameters {
		w, err := c.operandWords(p)
		if err != nil {
			return nil, err
		}
		words = append(words, w...)
	}
	return words, nil
}
func equalOperands(a, b []Operand) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n].Kind != b[n].Kind || a[n].Text != b[n].Text || len(a[n].Words) != len(b[n].Words) || !equalOperands(a[n].Parameters, b[n].Parameters) {
			return false
		}
		for j, w := range a[n].Words {
			if w != b[n].Words[j] {
				return false
			}
		}
	}
	return true
}

type Module struct {
	Version      uint32        `json:"version"`
	Generator    uint32        `json:"generator"`
	Bound        uint32        `json:"bound"`
	Instructions []Instruction `json:"instructions"`
}

// DecodeModule checks binary/grammar structure, ID framing and scalar widths.
// It deliberately leaves dominance, type checking and execution-model rules to
// a semantic validator such as spirv-val.
func (c *Catalog) DecodeModule(data []byte) (Module, error) {
	if len(data) < 20 || len(data)%4 != 0 {
		return Module{}, fmt.Errorf("invalid SPIR-V module byte length")
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if order.Uint32(data) != 0x07230203 {
		if binary.BigEndian.Uint32(data) != 0x07230203 {
			return Module{}, fmt.Errorf("invalid SPIR-V magic")
		}
		order = binary.BigEndian
	}
	normalized := make([]byte, len(data))
	for n := 0; n < len(data); n += 4 {
		binary.LittleEndian.PutUint32(normalized[n:], order.Uint32(data[n:]))
	}
	data = normalized
	m := Module{Version: binary.LittleEndian.Uint32(data[4:]), Generator: binary.LittleEndian.Uint32(data[8:]), Bound: binary.LittleEndian.Uint32(data[12:])}
	if m.Version&0xff0000ff != 0 || m.Version>>16 != uint32(c.Major) || ((m.Version>>8)&255) > uint32(c.Minor) || m.Bound == 0 || binary.LittleEndian.Uint32(data[16:]) != 0 {
		return Module{}, fmt.Errorf("invalid module header")
	}
	ctx := NewContext()
	defined := map[uint32]bool{}
	for pos := 20; pos < len(data); {
		i, n, err := c.Decode(data[pos:], ctx, nil)
		if err != nil {
			return Module{}, fmt.Errorf("word %d: %w", pos/4, err)
		}
		if err := c.checkIDs(i.Operands, m.Bound, defined); err != nil {
			return Module{}, err
		}
		m.Instructions = append(m.Instructions, i)
		ctx.Observe(i)
		pos += n
	}
	if err := c.ValidateRequirements(m); err != nil {
		return Module{}, err
	}
	return m, nil
}

// ValidateRequirements checks the grammar's declared version/extension and
// capability requirements, including capabilities implied by OpCapability.
// This is intentionally narrower than SPIR-V semantic module validation.
func (c *Catalog) ValidateRequirements(m Module) error {
	env := &Environment{Version: m.Version, Capabilities: map[string]bool{}, Extensions: map[string]bool{}}
	capKind := c.kinds["Capability"]
	var enable func(string)
	enable = func(name string) {
		if env.Capabilities[name] {
			return
		}
		env.Capabilities[name] = true
		for _, e := range capKind.Enumerants {
			if e.Name == name {
				for _, dep := range e.Capabilities {
					enable(dep)
				}
				break
			}
		}
	}
	for _, i := range m.Instructions {
		if i.Opcode == 10 && len(i.Operands) > 0 {
			env.Extensions[i.Operands[0].Text] = true
		}
		if i.Opcode == 17 && len(i.Operands) > 0 {
			if e := findEnum(capKind, i.Operands[0].Words[0]); e != nil {
				enable(e.Name)
			}
		}
	}
	var check func([]Operand) error
	check = func(operands []Operand) error {
		for _, o := range operands {
			k := c.kinds[o.Kind]
			if k.Category == "BitEnum" || k.Category == "ValueEnum" {
				if _, err := enumParams(k, o.Words[0], env); err != nil {
					return err
				}
			}
			if err := check(o.Parameters); err != nil {
				return err
			}
		}
		return nil
	}
	for _, i := range m.Instructions {
		d := c.ops[i.Opcode]
		if !allowed(d.Requirements, env) {
			return fmt.Errorf("%s unavailable for declared module environment", d.Name)
		}
		if err := check(i.Operands); err != nil {
			return fmt.Errorf("%s: %w", d.Name, err)
		}
	}
	return nil
}
func (c *Catalog) checkIDs(operands []Operand, bound uint32, defined map[uint32]bool) error {
	for _, o := range operands {
		k := c.kinds[o.Kind]
		if k.Category == "Id" {
			id := o.Words[0]
			if id >= bound {
				return fmt.Errorf("ID %d exceeds module bound %d", id, bound)
			}
			if o.Kind == "IdResult" {
				if defined[id] {
					return fmt.Errorf("duplicate result ID %d", id)
				}
				defined[id] = true
			}
		}
		if err := c.checkIDs(o.Parameters, bound, defined); err != nil {
			return err
		}
	}
	return nil
}
func (c *Catalog) EncodeModule(m Module) ([]byte, error) {
	out := make([]byte, 20)
	for n, v := range []uint32{0x07230203, m.Version, m.Generator, m.Bound, 0} {
		binary.LittleEndian.PutUint32(out[4*n:], v)
	}
	ctx := NewContext()
	for _, i := range m.Instructions {
		b, err := c.Encode(i, ctx, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		ctx.Observe(i)
	}
	if _, err := c.DecodeModule(out); err != nil {
		return nil, err
	}
	return out, nil
}

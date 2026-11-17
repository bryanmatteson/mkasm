package spirv

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

func (c *Catalog) Format(i Instruction) string {
	def := c.ops[i.Opcode]
	if def == nil {
		return fmt.Sprintf("OpUnknown%d", i.Opcode)
	}
	var result string
	tokens := []string{def.Name}
	for _, o := range i.Operands {
		if o.Kind == "IdResult" {
			result = fmt.Sprintf("%%%d = ", o.Words[0])
			continue
		}
		tokens = append(tokens, c.formatOperand(o)...)
	}
	return result + strings.Join(tokens, " ")
}
func (c *Catalog) formatOperand(o Operand) []string {
	k := c.kinds[o.Kind]
	if o.Kind == "LiteralString" {
		return []string{strconv.Quote(o.Text)}
	}
	if k.Category == "Composite" {
		var out []string
		for _, p := range o.Parameters {
			out = append(out, c.formatOperand(p)...)
		}
		return out
	}
	var token string
	switch {
	case k.Category == "Id":
		token = fmt.Sprintf("%%%d", o.Words[0])
	case k.Category == "BitEnum" || k.Category == "ValueEnum":
		token = enumText(k, o.Words[0])
	case o.Kind == "LiteralSpecConstantOpInteger":
		if def := c.ops[uint16(o.Words[0])]; def != nil {
			token = strings.TrimPrefix(def.Name, "Op")
		}
	case o.Kind == "LiteralContextDependentNumber" || o.Kind == "LiteralFloat" || len(o.Words) > 1:
		var parts []string
		for _, w := range o.Words {
			parts = append(parts, fmt.Sprintf("!0x%08x", w))
		}
		return parts
	default:
		token = fmt.Sprint(o.Words[0])
	}
	out := []string{token}
	for _, p := range o.Parameters {
		out = append(out, c.formatOperand(p)...)
	}
	return out
}
func tokenize(s string) ([]string, error) {
	var out []string
	for len(s) > 0 {
		s = strings.TrimLeftFunc(s, unicode.IsSpace)
		if len(s) == 0 || s[0] == ';' {
			break
		}
		if s[0] == '"' {
			end := 1
			for end < len(s) {
				if s[end] == '\\' {
					end += 2
					continue
				}
				if s[end] == '"' {
					break
				}
				end++
			}
			if end >= len(s) {
				return nil, fmt.Errorf("unterminated quoted string")
			}
			out = append(out, s[:end+1])
			s = s[end+1:]
			continue
		}
		end := strings.IndexFunc(s, func(ch rune) bool { return unicode.IsSpace(ch) || ch == ';' })
		if end < 0 {
			end = len(s)
		}
		out = append(out, s[:end])
		s = s[end:]
	}
	return out, nil
}

// Assemble accepts standard numeric SPIR-V IDs and enum names/aliases. The
// lossless !0xxxxxxxxx raw-word spelling carries arbitrary-width literals in
// little-endian word order, including floating NaN payloads and wide integers.
func (c *Catalog) Assemble(text string, ctx *Context, env *Environment) (Instruction, error) {
	tokens, err := tokenize(text)
	if err != nil {
		return Instruction{}, err
	}
	if len(tokens) == 0 {
		return Instruction{}, fmt.Errorf("empty instruction")
	}
	var result string
	if len(tokens) > 2 && tokens[1] == "=" {
		result = tokens[0]
		tokens = tokens[2:]
	}
	def := c.names[tokens[0]]
	if def == nil {
		return Instruction{}, fmt.Errorf("unknown instruction %s", tokens[0])
	}
	tokens = tokens[1:]
	p := textParser{c: c, ctx: ctx, env: env, tokens: tokens}
	var operands []Operand
	for _, s := range def.Operands {
		if s.Kind == "IdResult" {
			if result == "" {
				return Instruction{}, fmt.Errorf("missing result assignment")
			}
			n, err := parseID(result)
			if err != nil {
				return Instruction{}, err
			}
			operands = append(operands, Operand{Kind: s.Kind, Words: []uint32{n}})
			result = ""
			continue
		}
		if s.Quantifier != "" && p.pos == len(p.tokens) {
			continue
		}
		for {
			v, err := p.one(s.Kind, 0)
			if err != nil {
				return Instruction{}, err
			}
			operands = append(operands, v)
			if s.Kind == "IdResultType" {
				p.typeID = v.Words[0]
			}
			if def.Opcode == 251 && len(operands) == 1 && ctx != nil {
				p.switchWords = ctx.width(ctx.IdTypes[v.Words[0]])
			}
			if s.Quantifier != "*" || p.pos == len(p.tokens) {
				break
			}
		}
	}
	if result != "" || p.pos != len(p.tokens) {
		return Instruction{}, fmt.Errorf("unexpected assembly operands")
	}
	i := Instruction{def.Opcode, operands}
	if _, err := c.Encode(i, ctx, env); err != nil {
		return Instruction{}, err
	}
	return i, nil
}
func parseID(s string) (uint32, error) {
	if !strings.HasPrefix(s, "%") {
		return 0, fmt.Errorf("expected numeric ID, got %q", s)
	}
	v, err := strconv.ParseUint(s[1:], 10, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid ID %s", s)
	}
	return uint32(v), nil
}

type textParser struct {
	c           *Catalog
	ctx         *Context
	env         *Environment
	tokens      []string
	pos         int
	typeID      uint32
	switchWords int
}

func (p *textParser) one(kind string, depth int) (Operand, error) {
	o := Operand{Kind: kind}
	if depth > 64 {
		return o, fmt.Errorf("operand nesting limit")
	}
	k := p.c.kinds[kind]
	if k == nil {
		return o, fmt.Errorf("unknown kind %s", kind)
	}
	if k.Category == "Composite" {
		for _, base := range k.Bases {
			var v Operand
			var err error
			if kind == "PairLiteralIntegerIdRef" && base == "LiteralInteger" && p.switchWords > 1 {
				if p.pos >= len(p.tokens) {
					return o, fmt.Errorf("missing wide switch literal")
				}
				v = Operand{Kind: base}
				token := p.tokens[p.pos]
				p.pos++
				token = p.rawTokens(token, p.switchWords)
				v.Words, err = parseNumber(token, p.switchWords, false)
			} else {
				v, err = p.one(base, depth+1)
			}
			if err != nil {
				return o, err
			}
			o.Parameters = append(o.Parameters, v)
		}
		return o, nil
	}
	if p.pos >= len(p.tokens) {
		return o, fmt.Errorf("missing %s", kind)
	}
	token := p.tokens[p.pos]
	p.pos++
	if kind == "LiteralString" {
		s, err := strconv.Unquote(token)
		if err != nil {
			return o, fmt.Errorf("invalid literal string: %w", err)
		}
		o.Text = s
		return o, nil
	}
	var n uint32
	var err error
	var params []OperandSpec
	switch {
	case k.Category == "Id":
		n, err = parseID(token)
	case k.Category == "BitEnum" || k.Category == "ValueEnum":
		if k.Category == "ValueEnum" && strings.Contains(token, "|") {
			return o, fmt.Errorf("%s is not a bitmask", kind)
		}

		for _, part := range strings.Split(token, "|") {
			v, e := enumValue(k, part)
			if e != nil {
				return o, e
			}
			n |= v
		}
		params, err = enumParams(k, n, p.env)
	case kind == "LiteralSpecConstantOpInteger":
		name := token
		if !strings.HasPrefix(name, "Op") {
			name = "Op" + name
		}
		def := p.c.names[name]
		if def == nil {
			v, e := strconv.ParseUint(token, 0, 16)
			if e != nil {
				return o, fmt.Errorf("unknown embedded instruction %s", token)
			}
			def = p.c.ops[uint16(v)]
		}
		if def == nil {
			return o, fmt.Errorf("unknown embedded opcode")
		}
		n = uint32(def.Opcode)
		for _, s := range def.Operands {
			if s.Kind != "IdResult" && s.Kind != "IdResultType" {
				params = append(params, s)
			}
		}
	case kind == "LiteralContextDependentNumber":
		width := p.ctx.width(p.typeID)
		token = p.rawTokens(token, width)
		floating := p.ctx != nil && p.ctx.FloatTypes[p.typeID]
		o.Words, err = parseNumber(token, width, floating)
		if floating && !strings.HasPrefix(token, "!") {
			bits := p.ctx.TypeWidths[p.typeID]
			encoding, alternative := p.ctx.FloatEncodings[p.typeID]
			if alternative {
				if encoding == 0 && bits == 16 {
					v, e := strconv.ParseFloat(token, 32)
					err = e
					w := math.Float32bits(float32(v))
					round := w + 0x7fff + ((w >> 16) & 1)
					o.Words = []uint32{round >> 16}
				} else {
					return o, fmt.Errorf("use raw literal words for extension floating encoding %d", encoding)
				}
			} else if bits == 16 {
				v, e := strconv.ParseFloat(token, 32)
				err = e
				o.Words = []uint32{uint32(float16bits(float32(v)))}
			} else if bits != 32 && bits != 64 {
				return o, fmt.Errorf("use raw words for %d-bit floating literal", bits)
			}
		}
	case kind == "LiteralFloat":
		o.Words, err = parseNumber(token, 1, true)
	default:
		if strings.HasPrefix(token, "!") {
			o.Words, err = parseNumber(token, 0, false)
		} else {
			var v uint64
			v, err = strconv.ParseUint(token, 0, 32)
			n = uint32(v)
		}
	}
	if err != nil {
		return o, err
	}
	if o.Words == nil {
		o.Words = []uint32{n}
	}
	for _, s := range params {
		if s.Quantifier != "" && p.pos == len(p.tokens) {
			continue
		}
		for {
			v, e := p.one(s.Kind, depth+1)
			if e != nil {
				return o, e
			}
			o.Parameters = append(o.Parameters, v)
			if s.Quantifier != "*" || p.pos == len(p.tokens) {
				break
			}
		}
	}
	return o, nil
}

func float16bits(v float32) uint16 {
	b := math.Float32bits(v)
	sign := uint16(b>>16) & 0x8000
	exp := int((b>>23)&255) - 127 + 15
	mant := b & 0x7fffff
	if (b>>23)&255 == 255 {
		if mant == 0 {
			return sign | 0x7c00
		}
		return sign | 0x7c00 | uint16(mant>>13) | 1
	}
	if exp >= 31 {
		return sign | 0x7c00
	}
	if exp <= 0 {
		if exp < -10 {
			return sign
		}
		mant |= 0x800000
		shift := uint(14 - exp)
		rounded := (mant + ((1 << (shift - 1)) - 1) + ((mant >> shift) & 1)) >> shift
		return sign | uint16(rounded)
	}
	mant += 0xfff + ((mant >> 13) & 1)
	if mant&0x800000 != 0 {
		mant = 0
		exp++
		if exp >= 31 {
			return sign | 0x7c00
		}
	}
	return sign | uint16(exp<<10) | uint16(mant>>13)
}
func (p *textParser) rawTokens(token string, width int) string {
	if !strings.HasPrefix(token, "!") || strings.Contains(token, ":") {
		return token
	}
	count := 1
	for p.pos < len(p.tokens) && (width == 0 || count < width) && strings.HasPrefix(p.tokens[p.pos], "!") {
		token += ":" + strings.TrimPrefix(p.tokens[p.pos], "!")
		p.pos++
		count++
	}
	return token
}

func parseNumber(token string, words int, floating bool) ([]uint32, error) {
	if words < 0 || words > 65535 {
		return nil, fmt.Errorf("literal exceeds instruction word-count limit")
	}
	if strings.HasPrefix(token, "!") {
		var out []uint32
		for _, part := range strings.Split(token[1:], ":") {
			v, err := strconv.ParseUint(strings.TrimPrefix(part, "0x"), 16, 32)
			if err != nil {
				return nil, err
			}
			out = append(out, uint32(v))
		}
		if words != 0 && len(out) != words {
			return nil, fmt.Errorf("literal width mismatch")
		}
		return out, nil
	}
	if words == 0 {
		words = 1
	}
	if floating {
		v, err := strconv.ParseFloat(token, 64)
		if err != nil {
			return nil, err
		}
		switch words {
		case 1:
			return []uint32{math.Float32bits(float32(v))}, nil
		case 2:
			b := math.Float64bits(v)
			return []uint32{uint32(b), uint32(b >> 32)}, nil
		default:
			return nil, fmt.Errorf("use raw literal words for this floating width")
		}
	}
	n, ok := new(big.Int).SetString(token, 0)
	if !ok {
		return nil, fmt.Errorf("invalid integer %s", token)
	}
	bits := words * 32
	if n.Sign() < 0 {
		if n.BitLen() > bits {
			return nil, fmt.Errorf("integer overflow")
		}
		n.Add(n, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	}
	if n.Sign() < 0 || n.BitLen() > bits {
		return nil, fmt.Errorf("integer overflow")
	}
	out := make([]uint32, words)
	for i := range out {
		out[i] = uint32(n.Uint64())
		n.Rsh(n, 32)
	}
	return out, nil
}

// AssembleModule resolves symbolic IDs across the complete text, retaining
// explicitly numeric IDs and avoiding collisions with generated numbers.
func (c *Catalog) AssembleModule(text string, moduleVersion, generator uint32) (Module, error) {
	var lines [][]string
	used := map[uint32]bool{}
	for _, line := range strings.Split(text, "\n") {
		tokens, err := tokenize(line)
		if err != nil {
			return Module{}, err
		}
		if len(tokens) == 0 {
			continue
		}
		for _, token := range tokens {
			if strings.HasPrefix(token, "%") {
				if n, err := parseID(token); err == nil {
					used[n] = true
				}
			}
		}
		lines = append(lines, tokens)
	}
	symbols := map[string]uint32{}
	next := uint32(1)
	bound := uint32(1)
	ctx := NewContext()
	m := Module{Version: moduleVersion, Generator: generator}
	for _, tokens := range lines {
		for j, token := range tokens {
			if !strings.HasPrefix(token, "%") {
				continue
			}
			n, err := parseID(token)
			if err != nil {
				if len(token) == 1 {
					return Module{}, fmt.Errorf("empty symbolic ID")
				}
				if _, ok := new(big.Int).SetString(token[1:], 10); ok {
					return Module{}, fmt.Errorf("invalid numeric ID %s", token)
				}
				for _, ch := range token[1:] {
					if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
						return Module{}, fmt.Errorf("invalid symbolic ID %s", token)
					}
				}
				n = symbols[token]
				if n == 0 {
					for used[next] {
						next++
						if next == 0 {
							return Module{}, fmt.Errorf("ID space exhausted")
						}
					}
					n = next
					used[n] = true
					symbols[token] = n
				}
			}
			if n == ^uint32(0) {
				return Module{}, fmt.Errorf("ID bound overflow")
			}
			if n >= bound {
				bound = n + 1
			}
			tokens[j] = fmt.Sprintf("%%%d", n)
		}
		i, err := c.Assemble(strings.Join(tokens, " "), ctx, nil)
		if err != nil {
			return Module{}, err
		}
		m.Instructions = append(m.Instructions, i)
		ctx.Observe(i)
	}
	m.Bound = bound
	if _, err := c.EncodeModule(m); err != nil {
		return Module{}, err
	}
	return m, nil
}
func (c *Catalog) FormatModule(m Module) string {
	var out strings.Builder
	for _, i := range m.Instructions {
		out.WriteString(c.Format(i))
		out.WriteByte('\n')
	}
	return out.String()
}

package mcs51

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"regexp"
	"strconv"
	"strings"
)

var hexLiteral = regexp.MustCompile(`(?i)\b([0-9][0-9a-f]*)h\b`)
var binLiteral = regexp.MustCompile(`(?i)\b([01]+)b\b`)

func normalizeText(s string) string {
	s = hexLiteral.ReplaceAllString(s, "0x${1}")
	return binLiteral.ReplaceAllString(s, "0b${1}")
}
func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.Catalog.Assemble(normalizeText(text), address)
}

type binding struct {
	operand string
	fixed   int64
	hole    string
	any     bool
}
type pattern struct {
	id       string
	bindings []binding
}

// Template is a reusable compiled instruction pattern. Captures use encoded
// semantic values: registers, immediates, relative displacements and page bits.
// Fixed branch text is an absolute address, resolved at compilation time.
type Template struct {
	catalog  *Catalog
	patterns []pattern
	address  uint64
}

func compact(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), "")) }
func (c *Catalog) ParseTemplate(text string, address uint64) (*Template, error) {
	t := &Template{catalog: c, address: address}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty MCS-51 template")
	}
	known := false
	for _, e := range c.Encodings {
		known = known || strings.EqualFold(e.Mnemonic, fields[0])
	}
	if !known {
		return nil, fmt.Errorf("unknown MCS-51 template mnemonic")
	}
	text = compact(normalizeText(text))
	for _, e := range c.Encodings {
		syntax := compact(e.Syntax)
		var names []string
		var re strings.Builder
		re.WriteByte('^')
		for {
			start := strings.IndexByte(syntax, '{')
			if start < 0 {
				re.WriteString(regexp.QuoteMeta(syntax))
				break
			}
			end := strings.IndexByte(syntax[start:], '}')
			if end < 0 {
				return nil, fmt.Errorf("invalid catalog syntax")
			}
			end += start
			re.WriteString(regexp.QuoteMeta(syntax[:start]))
			re.WriteString("(.+?)")
			names = append(names, syntax[start+1:end])
			syntax = syntax[end+1:]
		}
		re.WriteByte('$')
		matches := regexp.MustCompile(re.String()).FindStringSubmatch(text)
		if matches == nil {
			continue
		}
		p := pattern{id: e.ID}
		values := map[string]int64{}
		valid := true
		for i, n := range names {
			b := binding{operand: n}
			token := matches[i+1]
			if token == "_" {
				b.any = true
			} else if strings.HasPrefix(token, "$") && len(token) > 1 {
				b.hole = token[1:]
				if !regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(b.hole) {
					valid = false
					break
				}
			} else {
				o := operandNamed(&e, n)
				var ok bool
				b.fixed, ok = parseTemplateOperand(o, token, address)
				if !ok {
					valid = false
					break
				}
			}
			values[n] = b.fixed
			p.bindings = append(p.bindings, b)
		}
		if valid {
			if _, err := c.Encode(e.ID, values); err == nil {
				t.patterns = append(t.patterns, p)
			}
		}
	}
	if len(t.patterns) == 0 {
		return nil, fmt.Errorf("MCS-51 invalid template %q", text)
	}
	return t, nil
}
func operandNamed(e *codec.Encoding, n string) codec.Operand {
	for _, o := range e.Operands {
		if o.Name == n {
			return o
		}
	}
	panic("unknown catalog operand")
}
func parseTemplateOperand(o codec.Operand, s string, address uint64) (int64, bool) {
	for i, n := range o.Names {
		if n != "" && strings.EqualFold(n, s) {
			return int64(i), true
		}
	}
	for n, v := range o.RegisterAliases {
		if strings.EqualFold(n, s) {
			return v, true
		}
	}
	if o.Kind == "register" {
		return 0, false
	}
	v, e := strconv.ParseInt(s, 0, 64)
	if e != nil {
		return 0, false
	}
	if o.InputSignedBits > 0 && !o.Signed && v < 0 && v >= -(int64(1)<<uint(o.InputSignedBits-1)) {
		v += int64(1) << uint(o.InputSignedBits)
	}
	if o.Relative {
		base := address + uint64(o.PCBias)
		mask := uint64(1)<<uint(o.PCWrapBits) - 1
		if v < 0 || uint64(v) > mask {
			return 0, false
		}
		base &= mask
		if o.PCRegionBits > 0 {
			low := uint64(1)<<uint(o.PCRegionBits) - 1
			if uint64(v)&^low != base&^low {
				return 0, false
			}
			v = int64(uint64(v) & low)
		} else {
			v = int64(uint64(v) - base)
			shift := uint(64 - o.PCWrapBits)
			v = (v << shift) >> shift
		}
	}
	return v, true
}
func (t *Template) Encode(holes map[string]int64) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for _, p := range t.patterns {
		values := map[string]int64{}
		valid := true
		for _, b := range p.bindings {
			v := b.fixed
			if b.any {
				valid = false
				break
			}
			if b.hole != "" {
				var ok bool
				v, ok = holes[b.hole]
				if !ok {
					valid = false
					break
				}
			}
			values[b.operand] = v
		}
		if valid {
			raw, e := t.catalog.Encode(p.id, values)
			if e == nil && !seen[string(raw)] {
				out = append(out, raw)
				seen[string(raw)] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("MCS-51 template bindings do not encode")
	}
	return out, nil
}
func (t *Template) Match(src []byte) (*codec.Decoded, map[string]int64, bool) {
	d, e := t.catalog.Decode(src)
	if e != nil {
		return nil, nil, false
	}
	for _, p := range t.patterns {
		var enc *codec.Encoding
		for i := range t.catalog.Encodings {
			if t.catalog.Encodings[i].ID == p.id {
				enc = &t.catalog.Encodings[i]
				break
			}
		}
		if enc == nil || len(enc.Mask) > len(src) {
			continue
		}
		valid := true
		for i, m := range enc.Mask {
			if src[i]&m != enc.Value[i] {
				valid = false
				break
			}
		}
		holes := map[string]int64{}
		if valid {
			for _, b := range p.bindings {
				v := d.Values[b.operand]
				if b.any {
					continue
				}
				if b.hole != "" {
					if old, ok := holes[b.hole]; ok && old != v {
						valid = false
						break
					}
					holes[b.hole] = v
				} else if b.fixed != v {
					valid = false
					break
				}
			}
		}
		if valid {
			return d, holes, true
		}
	}
	return nil, nil, false
}

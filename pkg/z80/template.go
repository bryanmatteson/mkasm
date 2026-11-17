package z80

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"regexp"
	"strings"
)

var syntaxHole = regexp.MustCompile(`\{([A-Za-z_][A-Za-z_0-9]*)\}`)
var holeName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)

type binding struct {
	hole  string
	any   bool
	fixed int64
}
type templateEntry struct {
	encoding *codec.Encoding
	bindings map[string]binding
}
type Template struct {
	catalog  *Catalog
	entries  []templateEntry
	prefixes []byte
	address  uint64
}

func compact(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), "")) }
func defaults(e *codec.Encoding) map[string]int64 {
	values := map[string]int64{}
	for _, o := range e.Operands {
		raw := int64(0)
		if len(o.Names) > 0 {
			for i, n := range o.Names {
				if n != "" {
					raw = int64(i)
					break
				}
			}
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		values[o.Name] = raw*scale + o.Bias
	}
	return values
}

// ParseTemplate compiles instruction text with $name or ${name} bindings and
// operand wildcards _. Prefix qualifiers are matched exactly, including order.
// Binding values are structured semantic values (relative byte displacements,
// register indices, and immediates), not strings or absolute target spellings.
func (c *Catalog) ParseTemplate(text string, address uint64) (*Template, error) {
	prefix, id, body, err := qualifiers(text)
	if err != nil {
		return nil, err
	}
	body = compact(assemblyText(body))
	t := &Template{catalog: c, prefixes: prefix, address: address}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if id != "" && e.ID != id {
			continue
		}
		syntax := compact(e.Syntax)
		locs := syntaxHole.FindAllStringSubmatchIndex(syntax, -1)
		var pattern strings.Builder
		pattern.WriteByte('^')
		last := 0
		names := make([]string, 0, len(locs))
		for _, p := range locs {
			pattern.WriteString(regexp.QuoteMeta(syntax[last:p[0]]))
			pattern.WriteString("(.+?)")
			names = append(names, syntax[p[2]:p[3]])
			last = p[1]
		}
		pattern.WriteString(regexp.QuoteMeta(syntax[last:]))
		pattern.WriteByte('$')
		capture := regexp.MustCompile(pattern.String()).FindStringSubmatch(body)
		if capture == nil {
			continue
		}
		values := defaults(e)
		d := codec.Decoded{Encoding: e, Values: values, Length: len(e.Value)}
		seed := compact(d.Format((address + uint64(len(prefix))) & 65535))
		seedParts := regexp.MustCompile(pattern.String()).FindStringSubmatch(seed)
		if seedParts == nil {
			continue
		}
		var concrete strings.Builder
		last = 0
		bindings := map[string]binding{}
		valid := true
		for j, p := range locs {
			concrete.WriteString(syntax[last:p[0]])
			token := capture[j+1]
			b := binding{}
			if token == "_" {
				b.any = true
				concrete.WriteString(seedParts[j+1])
			} else if strings.HasPrefix(token, "$") {
				name := strings.TrimPrefix(token, "$")
				if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
					name = name[1 : len(name)-1]
				}
				if !holeName.MatchString(name) {
					valid = false
					break
				}
				b.hole = name
				concrete.WriteString(seedParts[j+1])
			} else {
				concrete.WriteString(token)
			}
			bindings[names[j]] = b
			last = p[1]
		}
		if !valid {
			continue
		}
		concrete.WriteString(syntax[last:])
		parsed, ok := codec.ParseOperands(e, concrete.String(), (address+uint64(len(prefix)))&65535)
		if !ok {
			continue
		}
		for name, b := range bindings {
			if b.hole == "" && !b.any {
				b.fixed = parsed[name]
				bindings[name] = b
			}
		}
		if len(locs) == 0 {
			if _, err := codec.Encode(e, parsed); err != nil {
				continue
			}
		}
		t.entries = append(t.entries, templateEntry{e, bindings})
	}
	if len(t.entries) == 0 {
		return nil, fmt.Errorf("no instruction matches template %q", text)
	}
	return t, nil
}
func (t *Template) Matches(src []byte) (int, map[string]int64, bool) {
	d, err := t.catalog.Decode(src)
	if err != nil || string(d.Prefixes) != string(t.prefixes) {
		return 0, nil, false
	}
	for _, entry := range t.entries {
		if entry.encoding.ID != d.Encoding.ID {
			continue
		}
		holes := map[string]int64{}
		ok := true
		for name, b := range entry.bindings {
			v := d.Values[name]
			if b.any {
				continue
			}
			if b.hole == "" {
				if v != b.fixed {
					ok = false
					break
				}
			} else if old, found := holes[b.hole]; found && old != v {
				ok = false
				break
			} else {
				holes[b.hole] = v
			}
		}
		if ok {
			return d.Length, holes, true
		}
	}
	return 0, nil, false
}
func (t *Template) Encode(holes map[string]int64) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for _, entry := range t.entries {
		values := map[string]int64{}
		ok := true
		for name, b := range entry.bindings {
			if b.any {
				ok = false
				break
			}
			if b.hole != "" {
				v, found := holes[b.hole]
				if !found {
					ok = false
					break
				}
				values[name] = v
			} else {
				values[name] = b.fixed
			}
		}
		if !ok {
			continue
		}
		b, err := t.catalog.Encode(entry.encoding.ID, values, t.prefixes...)
		if err != nil {
			continue
		}
		if !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("template bindings cannot be encoded")
	}
	return out, nil
}

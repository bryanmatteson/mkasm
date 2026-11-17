package mos6502

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type templatePattern struct {
	index int
	fixed map[string]int64
	holes map[string]string
}
type Template struct {
	catalog  *Catalog
	patterns []templatePattern
}

var placeholder = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)
var hole = regexp.MustCompile(`^\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}$`)

func compact(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
}

func (c *Catalog) ParseTemplate(text string, address uint64) (*Template, error) {
	return c.ParseTemplateWithFeatures(text, address, nil)
}
func (c *Catalog) ParseTemplateWithFeatures(text string, address uint64, active []string) (*Template, error) {
	text = compact(normalize(text))
	t := &Template{catalog: c}
	for index, e := range c.Encodings {
		if active != nil {
			allowed := true
			for _, required := range e.Features {
				found := false
				for _, f := range active {
					found = found || f == required
				}
				allowed = allowed && found
			}
			if !allowed {
				continue
			}
		}
		syntax := compact(e.Syntax)
		matches := placeholder.FindAllStringSubmatchIndex(syntax, -1)
		pattern := "^"
		start := 0
		names := []string{}
		for _, m := range matches {
			pattern += regexp.QuoteMeta(syntax[start:m[0]]) + `(.+?)`
			names = append(names, syntax[m[2]:m[3]])
			start = m[1]
		}
		pattern += regexp.QuoteMeta(syntax[start:]) + "$"
		got := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if got == nil {
			continue
		}
		p := templatePattern{index: index, fixed: map[string]int64{}, holes: map[string]string{}}
		valid := true
		for j, name := range names {
			token := got[j+1]
			if h := hole.FindStringSubmatch(token); h != nil {
				p.holes[name] = h[1]
				continue
			}
			base := 10
			if strings.HasPrefix(strings.TrimPrefix(token, "-"), "0x") || strings.HasPrefix(strings.TrimPrefix(token, "-"), "0b") {
				base = 0
			}
			n, err := strconv.ParseInt(token, base, 64)
			if err != nil {
				valid = false
				break
			}
			for _, o := range e.Operands {
				if o.Name == name {
					if o.Relative {
						if n < 0 || n > 65535 {
							valid = false
						}
						n = int64(int16(uint16(n) - uint16(address+uint64(o.PCBias))))
					} else if o.InputSignedBits > 0 && n < 0 && n >= -(1<<uint(o.InputSignedBits-1)) {
						n += 1 << uint(o.InputSignedBits)
					}
				}
			}
			p.fixed[name] = n
		}
		if valid {
			t.patterns = append(t.patterns, p)
		}
	}
	if len(t.patterns) == 0 {
		return nil, fmt.Errorf("invalid 6502 text template")
	}
	return t, nil
}
func (t *Template) Encode(bindings map[string]int64) ([][]byte, error) {
	var out [][]byte
	for _, p := range t.patterns {
		v := map[string]int64{}
		for k, n := range p.fixed {
			v[k] = n
		}
		valid := true
		for field, name := range p.holes {
			n, ok := bindings[name]
			if !ok {
				valid = false
				break
			}
			v[field] = n
		}
		if !valid {
			continue
		}
		b, err := t.catalog.Encode(t.catalog.Encodings[p.index].ID, v)
		if err == nil {
			found := false
			for _, old := range out {
				found = found || bytes.Equal(old, b)
			}
			if !found {
				out = append(out, b)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("template bindings have no valid encoding")
	}
	return out, nil
}
func (t *Template) Match(data []byte) (map[string]int64, error) {
	for _, p := range t.patterns {
		single := codec.Catalog{Encodings: []codec.Encoding{t.catalog.Encodings[p.index]}}
		d, err := single.Decode(data)
		if err != nil {
			continue
		}
		valid := true
		for field, want := range p.fixed {
			if d.Values[field] != want {
				valid = false
			}
		}
		bindings := map[string]int64{}
		for field, name := range p.holes {
			v := d.Values[field]
			if old, ok := bindings[name]; ok && old != v {
				valid = false
			}
			bindings[name] = v
		}
		if valid {
			return bindings, nil
		}
	}
	return nil, fmt.Errorf("instruction does not match template")
}

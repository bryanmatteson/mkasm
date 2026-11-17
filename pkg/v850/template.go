package v850

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type Template struct {
	catalog  *Catalog
	encoding *codec.Encoding
	values   map[string]int64
}

func (c *Catalog) Template(id string) (*Template, error) {
	var found *codec.Encoding
	for j := range c.Encodings {
		e := &c.Encodings[j]
		if e.ID == id || e.Mnemonic == id {
			if found != nil {
				return nil, fmt.Errorf("ambiguous V850 template; use encoding ID")
			}
			found = e
		}
	}
	if found == nil {
		return nil, fmt.Errorf("unknown V850 template")
	}
	return &Template{c, found, map[string]int64{}}, nil
}
func (t *Template) Set(name string, value int64) error {
	for _, o := range t.encoding.Operands {
		if o.Name == name {
			t.values[name] = value
			return nil
		}
	}
	return fmt.Errorf("unknown V850 template operand %s", name)
}
func (t *Template) Encode() ([]byte, error) { return t.catalog.Encode(t.encoding.ID, t.values) }
func (t *Template) Match(data []byte) (map[string]int64, error) {
	d, e := t.catalog.Decode(data)
	if e != nil {
		return nil, e
	}
	b, e := t.catalog.Encode(d.Encoding.ID, d.Values)
	if e != nil {
		return nil, e
	}
	enc := *t.encoding
	enc.AssemblyOnly = false
	single := codec.Catalog{Encodings: []codec.Encoding{enc}}
	target, e := single.Decode(b)
	if e != nil {
		return nil, e
	}
	for k, v := range t.values {
		if target.Values[k] != v {
			return nil, fmt.Errorf("V850 template operand %s differs", k)
		}
	}
	return target.Values, nil
}

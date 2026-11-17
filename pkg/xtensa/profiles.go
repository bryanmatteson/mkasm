package xtensa

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// WithCPU selects both scalar and FLIX tables, leaving the original catalog
// intact. CLI callers should use this before generation instead of filtering
// only InstructionCatalog(), which cannot describe the bundle slot tables.
func (c *Catalog) WithCPU(name string) (*Catalog, error) {
	features, ok := c.Core.FeatureSets[name]
	if !ok {
		return nil, fmt.Errorf("Xtensa: unknown CPU profile %q", name)
	}
	active := map[string]bool{}
	for _, f := range features {
		active[f] = true
	}
	selectTable := func(source *codec.Catalog) *codec.Catalog {
		out := *source
		out.Encodings = nil
		for _, e := range source.Encodings {
			allowed := true
			for _, f := range e.Features {
				if !active[f] {
					allowed = false
					break
				}
			}
			if allowed {
				out.Encodings = append(out.Encodings, e)
			}
		}
		return &out
	}
	out := *c
	out.Core = selectTable(c.Core)
	out.Slots = selectTable(c.Slots)
	if err := out.Core.Validate(); err != nil {
		return nil, err
	}
	if len(out.Slots.Encodings) > 0 {
		if err := out.Slots.Validate(); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

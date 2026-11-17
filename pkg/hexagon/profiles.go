package hexagon

import (
	"fmt"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// WithCPU returns a catalog containing only forms in a source-defined processor
// profile. The source catalog remains available for other generated targets.
func (c *Catalog) WithCPU(name string) (*Catalog, error) {
	features, ok := c.FeatureSets[name]
	if !ok {
		return nil, fmt.Errorf("hexagon: unknown CPU profile %q", name)
	}
	active := map[string]bool{}
	for _, feature := range features {
		active[feature] = true
	}
	filter := func(source *codec.Catalog) *codec.Catalog {
		copy := *source
		copy.Encodings = nil
		for _, e := range source.Encodings {
			match := true
			for _, feature := range e.Features {
				if !active[feature] {
					match = false
					break
				}
			}
			if match {
				copy.Encodings = append(copy.Encodings, e)
			}
		}
		return &copy
	}
	copy := *c
	copy.Words = filter(c.Words)
	copy.Subinstructions = filter(c.Subinstructions)
	return &copy, nil
}

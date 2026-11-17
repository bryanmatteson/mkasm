package z80

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed data/variants.json.gz
var variantDescriptions []byte

// ParseVariant loads the complete pinned GNU variant description, or a resolved
// catalog previously written by WriteJSON. eZ80 modes are separate targets:
// immediate width and PC wrapping are part of the selected execution mode.
func ParseVariant(r io.Reader, architecture string) (*codec.Catalog, error) {
	switch architecture {
	case "ez80", "ez80-adl", "z80n", "r800", "gbz80":
	default:
		return nil, fmt.Errorf("Z80: unsupported variant %q", architecture)
	}
	var c *codec.Catalog
	if r != nil {
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(data)) != 0 && !bytes.Equal(data, []byte(GNUDescription)) {
			if err = json.Unmarshal(data, &c); err != nil {
				return nil, err
			}
		}
	}
	if c == nil {
		z, err := gzip.NewReader(bytes.NewReader(variantDescriptions))
		if err != nil {
			return nil, err
		}
		var descriptions map[string]*codec.Catalog
		err = json.NewDecoder(z).Decode(&descriptions)
		z.Close()
		if err != nil {
			return nil, err
		}
		c = descriptions[architecture]
	}
	if c == nil || c.Architecture != architecture || c.Schema != codec.Schema {
		return nil, fmt.Errorf("Z80: variant description mismatch")
	}
	c.SourceLicense = "GNU binutils opcode descriptions: GPL-3.0-or-later. See data/COPYING-binutils.\nRuntime implementation: MIT.\n" + gnuLicense
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

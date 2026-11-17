package arm

import (
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"os"
	"path/filepath"
)

func writeRustRequirements(src string, catalog *Catalog) error {
	entries := make(map[string]ir.Requirements, len(catalog.Entries))
	for _, e := range catalog.Entries {
		entries[e.EncodingID] = e.Requirements
	}
	return os.WriteFile(filepath.Join(src, "requirements.rs"), []byte(codec.EmitRustRequirements(entries)), 0644)
}

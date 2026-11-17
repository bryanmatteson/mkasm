package arm

import (
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"path/filepath"
	"text/template"
)

func writeRustEffects(t *template.Template, src string, arm32 bool) error {
	name := "effects.rs.tmpl"
	if arm32 {
		name = "arm32_effects.rs.tmpl"
	}
	return execTmplWrite(t, name, filepath.Join(src, "effects.rs"), struct{ Types string }{codec.RustEffectTypes()})
}

package x86

import (
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"os"
	"path/filepath"
	"strconv"
)

func writeRustRequirements(src string, catalog *Catalog) error {
	entries := make(map[string]ir.Requirements, len(catalog.Encodings))
	for _, e := range catalog.Encodings {
		r := e.Requirements
		var modes []ir.RequirementExpr
		for _, m := range []Mode{Mode16, Mode32, Mode64} {
			if e.Modes.supports(m) {
				modes = append(modes, ir.RequirementExpr{Op: "mode", Name: "x86_" + strconv.Itoa(int(m))})
			}
		}
		requirement := ir.UnknownRequirement("x86 feature metadata absent")
		if r.Expression != nil {
			requirement = *r.Expression
		}
		modeRequirement := ir.RequirementAny(modes...)
		requirement = ir.RequirementAll(modeRequirement, requirement)
		if r.Fallback != nil {
			fallback := ir.RequirementAll(modeRequirement, *r.Fallback)
			r.Fallback = &fallback
		}
		r.Expression = &requirement
		entries[e.FormID] = r
	}
	return os.WriteFile(filepath.Join(src, "requirements.rs"), []byte(codec.EmitRustRequirements(entries)), 0644)
}

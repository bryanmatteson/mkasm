package amdgpu

import (
	"fmt"
	"sort"
	"strings"
)

func (p *importer) profiles(processors []string) map[string][]string {
	profiles := map[string][]string{}
	for _, id := range processors {
		r := p.rec(id)
		if !strings.HasPrefix(r.Name, "gfx") {
			continue
		}
		features := map[string]bool{}
		var add func(string)
		add = func(name string) {
			if features[name] {
				return
			}
			features[name] = true
			for _, f := range p.rec(name).Implies {
				add(f.Def)
			}
		}
		for _, f := range r.Features {
			add(f.Def)
		}
		// Match AMDGPUMCTargetDesc's target default when neither wave-size
		// feature is present in the processor's TableGen feature closure.
		if !features["FeatureWavefrontSize32"] && !features["FeatureWavefrontSize64"] {
			if p.evalPredicate("isGFX10Plus", features) {
				features["FeatureWavefrontSize32"] = true
			} else {
				features["FeatureWavefrontSize64"] = true
			}
		}
		for _, wave := range []int{0, 32, 64} {
			if wave == 32 && !p.evalPredicate("isGFX10Plus", features) {
				continue
			}
			for _, real16 := range []bool{false, true} {
				fs := map[string]bool{}
				for k, v := range features {
					fs[k] = v
				}
				name := r.Name
				if real16 {
					name += "-true16"
					fs["FeatureRealTrue16Insts"] = true
				}
				if wave != 0 {
					name += fmt.Sprintf("-wave%d", wave)
					fs["FeatureWavefrontSize32"] = wave == 32
					fs["FeatureWavefrontSize64"] = wave == 64
				}
				var active []string
				for _, predicate := range p.predicates {
					if p.evalPredicate(predicate, fs) {
						active = append(active, predicate)
					}
				}
				if fs["FeatureVOP3Literal"] {
					active = append(active, "HasVOP3Literal")
				}
				if fs["Feature64BitLiterals"] {
					active = append(active, "Has64BitLiterals")
				}
				if !fs["FeatureG16"] {
					active = append(active, "AMDGPU_NoG16")
				}
				if !fs["FeatureR128A16"] {
					active = append(active, "AMDGPU_NoR128A16")
				}
				if !fs["FeatureSouthernIslands"] && !fs["FeatureSeaIslands"] {
					active = append(active, "AMDGPU_D16Images")
				}
				if fs["FeatureDPALU_DPP"] {
					active = append(active, "AMDGPU_DPALUDPP")
				}
				if p.evalPredicate("isGFX10Plus", fs) {
					active = append(active, "AMDGPU_TwoConstantBus")
				}
				if fs["FeatureRequiresAlignedVGPRs"] {
					active = append(active, "AMDGPU_AlignedVGPRs")
				} else {
					active = append(active, "AMDGPU_UnalignedVGPRs")
				}
				if fs["FeatureGFX90AInsts"] {
					active = append(active, "AMDGPU_AGPRMemory")
				}
				if fs["FeatureMFMAInlineLiteralBug"] {
					active = append(active, "AMDGPU_MFMAInlineBug")
				} else {
					active = append(active, "AMDGPU_MFMAInlineAllowed")
				}
				sort.Strings(active)
				profiles[name] = active
			}
		}
	}
	return profiles
}
func (p *importer) evalPredicate(name string, features map[string]bool) bool {
	r := p.rec(name)
	if r.AssemblerCondDag == nil {
		return name != "FalsePredicate"
	}
	return evalDag(r.AssemblerCondDag, features)
}
func evalDag(v any, features map[string]bool) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if name, ok := m["def"].(string); ok {
		return features[name]
	}
	operator, _ := m["operator"].(map[string]any)
	op, _ := operator["def"].(string)
	args, _ := m["args"].([]any)
	values := make([]bool, 0, len(args))
	for _, raw := range args {
		pair, _ := raw.([]any)
		if len(pair) > 0 {
			values = append(values, evalDag(pair[0], features))
		}
	}
	switch op {
	case "not":
		return len(values) == 1 && !values[0]
	case "any_of":
		for _, v := range values {
			if v {
				return true
			}
		}
		return false
	case "all_of":
		for _, v := range values {
			if !v {
				return false
			}
		}
		return true
	}
	return false
}

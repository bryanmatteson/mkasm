package arm

import (
	"strings"

	"mkasm/pkg/ir"
)

var featureDescriptions = map[string]string{
	"FEAT_AES":     "AES cryptographic extensions",
	"FEAT_BF16":    "BFloat16 floating-point",
	"FEAT_BTI":     "Branch Target Identification",
	"FEAT_DIT":     "Data Independent Timing",
	"FEAT_DPB":     "Data Persistence writeback",
	"FEAT_DPB2":    "Data Persistence writeback version 2",
	"FEAT_DotProd": "Dot Product instructions",
	"FEAT_FCMA":    "Floating-point complex number support",
	"FEAT_FHM":     "Floating-point half-precision multiplication",
	"FEAT_FP16":    "Half-precision floating-point",
	"FEAT_FRINTTS": "Floating-point to integer with round to nearest and tie away from zero",
	"FEAT_I8MM":    "Int8 matrix multiplication",
	"FEAT_JSCVT":   "JavaScript conversion instructions",
	"FEAT_LRCPC":   "Load-Acquire RCpc instructions",
	"FEAT_LRCPC2":  "Load-Acquire RCpc instructions version 2",
	"FEAT_LSE":     "Large System Extensions",
	"FEAT_LSE2":    "Large System Extensions version 2",
	"FEAT_MTE":     "Memory Tagging Extension",
	"FEAT_PAuth":   "Pointer Authentication",
	"FEAT_RAS":     "Reliability, Availability, and Serviceability Extension",
	"FEAT_RNG":     "Random number generator",
	"FEAT_SB":      "Speculation Barrier",
	"FEAT_SHA":     "SHA1 and SHA256 cryptographic extensions",
	"FEAT_SHA3":    "SHA3 cryptographic extensions",
	"FEAT_SHA512":  "SHA512 cryptographic extensions",
	"FEAT_SME":     "Scalable Matrix Extension",
	"FEAT_SM3":     "SM3 cryptographic extensions",
	"FEAT_SM4":     "SM4 cryptographic extensions",
	"FEAT_SSBS":    "Speculative Store Bypass Safe",
	"FEAT_SVE":     "Scalable Vector Extension",
	"FEAT_SVE2":    "Scalable Vector Extension version 2",
	"FEAT_TME":     "Transactional Memory Extension",
}

func featureDescription(feature string) string {
	if description, ok := featureDescriptions[feature]; ok {
		return description
	}
	if strings.HasPrefix(feature, "FEAT_") {
		return strings.TrimPrefix(feature, "FEAT_") + " feature"
	}
	return feature
}

func mergeFeatures(sets ...[]ir.FeatureTag) ir.FeatureSet {
	seen := make(map[string]struct{})
	var merged []ir.FeatureTag
	for _, set := range sets {
		for _, feature := range set {
			if _, ok := seen[feature.Name]; ok {
				continue
			}
			seen[feature.Name] = struct{}{}
			merged = append(merged, feature)
		}
	}
	return ir.FeatureSet{Tags: merged}
}

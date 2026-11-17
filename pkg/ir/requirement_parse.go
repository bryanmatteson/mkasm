package ir

import (
	"regexp"
	"strconv"
	"strings"
)

var requirementFeatureCall = regexp.MustCompile(`IsFeatureImplemented\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`)
var requirementField = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:<([0-9]+)(?::([0-9]+))?>)?\s*(==|!=)\s*'([01x]+)'$`)
var requirementSquareSlice = regexp.MustCompile(`\[([0-9]+(?::[0-9]+)?)\]`)
var requirementIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// ParseRequirementExpression recognizes boolean feature logic and Arm field
// comparisons. Unsupported syntax is retained verbatim as unknown, never split
// into apparently mandatory feature tokens. bareFeatures is reserved for sources
// whose identifiers explicitly denote architectural features, not predicates.
func ParseRequirementExpression(source string, bareFeatures bool) RequirementExpr {
	original := strings.TrimSpace(source)
	source = requirementFeatureCall.ReplaceAllString(original, "$1")
	source = strings.TrimSpace(source)
	source = requirementSquareSlice.ReplaceAllString(source, "<$1>")
	if !balancedRequirement(source) {
		return UnknownRequirement(original)
	}
	for len(source) > 1 && source[0] == '(' && matchingOuter(source) {
		source = strings.TrimSpace(source[1 : len(source)-1])
	}
	for _, op := range []struct{ token, kind string }{{"||", "any"}, {" OR ", "any"}, {"&&", "all"}, {" AND ", "all"}} {
		parts := splitRequirement(source, op.token)
		if len(parts) > 1 {
			args := make([]RequirementExpr, len(parts))
			for i, p := range parts {
				args[i] = ParseRequirementExpression(p, bareFeatures)
			}
			return RequirementExpr{Op: op.kind, Args: args}
		}
	}
	if strings.HasPrefix(source, "!") {
		return RequirementNot(ParseRequirementExpression(source[1:], bareFeatures))
	}
	if strings.HasPrefix(source, "NOT ") {
		return RequirementNot(ParseRequirementExpression(source[4:], bareFeatures))
	}
	switch source {
	case "TRUE", "true":
		return RequirementExpr{Op: "true"}
	case "FALSE", "false":
		return RequirementNot(RequirementExpr{Op: "true"})
	}
	if m := requirementField.FindStringSubmatch(source); m != nil {
		mask, value := uint64(0), uint64(0)
		for _, c := range m[5] {
			mask <<= 1
			value <<= 1
			if c != 'x' {
				mask |= 1
			}
			if c == '1' {
				value |= 1
			}
		}
		if m[2] != "" {
			hi, _ := strconv.Atoi(m[2])
			lo := hi
			if m[3] != "" {
				lo, _ = strconv.Atoi(m[3])
			}
			if hi < lo || hi > 63 || hi-lo+1 != len(m[5]) {
				return UnknownRequirement(original)
			}
			mask <<= lo
			value <<= lo
		}
		e := RequirementExpr{Op: "field_eq", Name: m[1], Mask: mask, Value: value}
		if m[4] == "!=" {
			return RequirementNot(e)
		}
		return e
	}
	if requirementIdentifier.MatchString(source) && (strings.HasPrefix(source, "FEAT_") || bareFeatures) {
		return RequirementExpr{Op: "feature", Name: source}
	}
	return UnknownRequirement(original)
}
func matchingOuter(s string) bool {
	depth := 0
	for i, c := range s {
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
			if depth == 0 && i != len(s)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
func splitRequirement(s, separator string) []string {
	depth, start := 0, 0
	var parts []string
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && strings.HasPrefix(s[i:], separator) {
			parts = append(parts, s[start:i])
			i += len(separator) - 1
			start = i + 1
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[start:])
		return parts
	}
	return []string{s}
}

func balancedRequirement(s string) bool {
	depth := 0
	for _, r := range s {
		if r == '(' {
			depth++
		}
		if r == ')' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

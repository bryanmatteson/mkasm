package codec

import "sort"

type rustOperandName struct {
	Name string
	Raw  uint64
}

// Canonical names precede aliases, and the first canonical spelling wins when
// normalization makes two names equal. Alias order matches generated Operand.
func prepareRustOperandNames(o Operand) []rustOperandName {
	values := make(map[string]uint64)
	for i, name := range o.Names {
		if name == "" {
			continue
		}
		key := rustNormalizeLiteral(name)
		if _, exists := values[key]; !exists {
			values[key] = uint64(i)
		}
	}
	aliases := make([]string, 0, len(o.RegisterAliases))
	for name := range o.RegisterAliases {
		aliases = append(aliases, name)
	}
	sort.Strings(aliases)
	for _, name := range aliases {
		key := rustNormalizeLiteral(name)
		if _, exists := values[key]; !exists {
			values[key] = uint64(o.RegisterAliases[name])
		}
	}
	result := make([]rustOperandName, 0, len(values))
	for name, raw := range values {
		result = append(result, rustOperandName{name, raw})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

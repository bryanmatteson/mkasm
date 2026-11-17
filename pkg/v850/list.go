package v850

import (
	"fmt"
	"strconv"
	"strings"
)

func listRegister(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "ep":
		return 30, nil
	case "lp":
		return 31, nil
	}
	if !strings.HasPrefix(s, "r") {
		return 0, fmt.Errorf("invalid list register %s", s)
	}
	n, e := strconv.Atoi(s[1:])
	if e != nil || n < 20 || n > 31 {
		return 0, fmt.Errorf("register outside prepare/dispose list")
	}
	return n, nil
}
func normalizeLists(text string) (string, error) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return normalizeLiteralRegisters(text), nil
	}
	if name := strings.ToLower(fields[0]); name != "prepare" && name != "dispose" {
		return normalizeLiteralRegisters(text), nil
	}
	var out strings.Builder
	for {
		start := strings.IndexByte(text, '{')
		if start < 0 {
			out.WriteString(text)
			return normalizeLiteralRegisters(out.String()), nil
		}
		end := strings.IndexByte(text[start:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated V850 register list")
		}
		end += start
		if start > 0 && text[start-1] == '$' {
			out.WriteString(text[:end+1])
			text = text[end+1:]
			continue
		}
		mask := 0
		body := strings.TrimSpace(text[start+1 : end])
		if body != "" {
			for _, part := range strings.Split(body, ",") {
				r := strings.Split(part, "-")
				if len(r) > 2 {
					return "", fmt.Errorf("invalid list range")
				}
				first, e := listRegister(r[0])
				if e != nil {
					return "", e
				}
				last := first
				if len(r) == 2 {
					last, e = listRegister(r[1])
					if e != nil || last < first {
						return "", fmt.Errorf("invalid list range")
					}
				}
				for n := first; n <= last; n++ {
					bit := 1 << uint(n-20)
					if mask&bit != 0 {
						return "", fmt.Errorf("duplicate list register")
					}
					mask |= bit
				}
			}
		}
		out.WriteString(text[:start])
		out.WriteString(lists[mask])
		text = text[end+1:]
	}
}
func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.AssembleWithFeatures(text, address, nil)
}
func (c *Catalog) AssembleWithFeatures(text string, address uint64, features []string) ([][]byte, error) {
	normalized, err := normalizeLists(text)
	if err != nil {
		return nil, err
	}
	return c.Catalog.AssembleWithFeatures(normalized, address, features)
}

// The GNU grammar accepts the physical names of its fixed SP/EP operands and
// allows dispose's return register with or without memory brackets.
func normalizeLiteralRegisters(text string) string {
	lower := strings.ToLower(text)
	text = strings.NewReplacer("[r30]", "[ep]", "[r3]", "[sp]").Replace(lower)
	if strings.HasPrefix(strings.TrimSpace(text), "prepare ") {
		if at := strings.LastIndexByte(text, ','); at >= 0 && strings.TrimSpace(text[at+1:]) == "r3" {
			text = text[:at+1] + "sp"
		}
	}
	if strings.HasPrefix(strings.TrimSpace(text), "dispose ") {
		if at := strings.LastIndexByte(text, '}'); at >= 0 {
			rest := strings.TrimSpace(text[at+1:])
			if strings.HasPrefix(rest, ",") {
				reg := strings.TrimSpace(rest[1:])
				if !strings.HasPrefix(reg, "[") {
					text = text[:at+1] + ",[" + reg + "]"
				}
			}
		}
	}
	return text
}

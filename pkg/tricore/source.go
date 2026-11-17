package tricore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type field struct {
	start, width int
	signed       bool
	names        []string
}
type constructor struct {
	table, display, pattern, action, body string
	line                                  int
}
type description struct {
	fields       map[string]field
	helpers      map[string][]constructor
	instructions []constructor
}

var identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`)
var tokenRE = regexp.MustCompile(`(?s)define token\s+(\w+)\s*\(16\)(.*?);`)
var fieldRE = regexp.MustCompile(`(\w+)\s*=\s*\((\d+),\s*(\d+)\)\s*(signed)?`)
var attachRE = regexp.MustCompile(`(?s)attach variables\s*\[([^]]+)\]\s*\[([^]]+)\]\s*;`)
var ctorRE = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z_0-9]*)?:`)
var defineRE = regexp.MustCompile(`defined\((\w+)\)`)

func sourceDescription(source, profile string) (*description, error) {
	defines := map[string]bool{"TRICORE_GENERIC": true, "TRICORE_" + strings.ToUpper(strings.ReplaceAll(profile, "-", "_")): true}
	if profile == "v2" {
		defines["TRICORE_V2"] = true
	}
	lines := strings.Split(source, "\n")
	active := make([]bool, len(lines)+1)
	stack := []bool{true}
	conditions := []bool{}
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "@if ") {
			match := false
			for _, m := range defineRE.FindAllStringSubmatch(trim, -1) {
				match = match || defines[m[1]]
			}
			conditions = append(conditions, match)
			stack = append(stack, stack[len(stack)-1] && match)
		} else if trim == "@else" {
			if len(stack) < 2 {
				return nil, fmt.Errorf("line%d: unmatched else", i+1)
			}
			stack[len(stack)-1] = stack[len(stack)-2] && !conditions[len(conditions)-1]
		} else if trim == "@endif" {
			if len(stack) < 2 {
				return nil, fmt.Errorf("line%d: unmatched endif", i+1)
			}
			stack = stack[:len(stack)-1]
			conditions = conditions[:len(conditions)-1]
		}
		active[i+1] = stack[len(stack)-1]
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("unbalanced source conditional")
	}
	d := &description{fields: map[string]field{}, helpers: map[string][]constructor{}}
	for _, m := range tokenRE.FindAllStringSubmatch(source, -1) {
		base := 0
		if strings.HasSuffix(m[1], "2") {
			base = 16
		}
		for _, f := range fieldRE.FindAllStringSubmatch(m[2], -1) {
			a, _ := strconv.Atoi(f[2])
			b, _ := strconv.Atoi(f[3])
			if a < 0 || b < a || b >= 16 {
				return nil, fmt.Errorf("invalid field %s: (%d,%d)", f[1], a, b)
			}
			d.fields[f[1]] = field{start: base + a, width: b - a + 1, signed: f[4] != ""}
		}
	}
	for _, m := range attachRE.FindAllStringSubmatch(source, -1) {
		names := strings.Fields(m[2])
		for i, n := range names {
			if n == "_" {
				names[i] = ""
			}
		}
		for _, name := range strings.Fields(m[1]) {
			f, ok := d.fields[name]
			if !ok {
				return nil, fmt.Errorf("attachment to unknown field %s", name)
			}
			if len(names) != 1<<f.width {
				return nil, fmt.Errorf("attachment %s has %d names for %d bits", name, len(names), f.width)
			}
			f.names = append([]string(nil), names...)
			d.fields[name] = f
		}
	}
	for _, loc := range ctorRE.FindAllStringSubmatchIndex(source, -1) {
		line := strings.Count(source[:loc[0]], "\n") + 1
		if !active[line] {
			continue
		}
		start := loc[1]
		end := strings.IndexByte(source[start:], '{')
		if end < 0 {
			return nil, fmt.Errorf("line%d: missing constructor body", line)
		}
		header := strings.TrimSpace(source[start : start+end])
		is := strings.Index(header, " is ")
		if is < 0 { // some headers align is with a tab
			re := regexp.MustCompile(`\s+is\s+`)
			p := re.FindStringIndex(header)
			if p == nil {
				return nil, fmt.Errorf("line%d: missing pattern", line)
			}
			is = p[0]
			header = header[:p[0]] + " is " + header[p[1]:]
		}
		bodyStart := start + end
		nesting, bodyEnd := 1, bodyStart+1
		for bodyEnd < len(source) && nesting > 0 {
			switch source[bodyEnd] {
			case '{':
				nesting++
			case '}':
				nesting--
			}
			bodyEnd++
		}
		if nesting != 0 {
			return nil, fmt.Errorf("line%d: unbalanced constructor body", line)
		}
		c := constructor{body: source[bodyStart+1 : bodyEnd-1], display: strings.TrimSpace(header[:is]), pattern: strings.TrimSpace(header[is+4:]), line: line}
		if loc[2] >= 0 {
			c.table = source[loc[2]:loc[3]]
		}
		if p := strings.IndexByte(c.pattern, '['); p >= 0 {
			c.action = strings.TrimSpace(c.pattern[p:])
			c.pattern = strings.TrimSpace(c.pattern[:p])
		}
		if c.table == "" {
			d.instructions = append(d.instructions, c)
		} else {
			d.helpers[c.table] = append(d.helpers[c.table], c)
		}
	}
	return d, nil
}
func stripComments(source string) string {
	var out strings.Builder
	for _, line := range strings.Split(source, "\n") {
		quote := false
		for i, ch := range line {
			if ch == '"' {
				quote = !quote
			}
			if ch == '#' && !quote {
				line = line[:i]
				break
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

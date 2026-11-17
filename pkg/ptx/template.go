package ptx

import (
	"fmt"
	"strings"
)

type Hole struct {
	Name   string `json:"name"`
	Format string `json:"format,omitempty"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
}
type Template struct {
	Pattern string `json:"pattern"`
	Holes   []Hole `json:"holes"`
}

// CompileTemplate accepts LLVM's $name/${name:format} notation and $$ escapes.
// Format describes upstream printer semantics; replacement values are rendered
// PTX text supplied by the caller, not guessed register numbers or binary bits.
func CompileTemplate(pattern string) (*Template, error) {
	t := &Template{Pattern: pattern}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '$' {
			continue
		}
		start := i
		i++
		if i == len(pattern) {
			return nil, fmt.Errorf("PTX trailing template dollar")
		}
		if pattern[i] == '$' {
			continue
		}
		name, format := "", ""
		if pattern[i] == '{' {
			end := strings.IndexByte(pattern[i+1:], '}')
			if end < 0 {
				return nil, fmt.Errorf("PTX unclosed template hole")
			}
			end += i + 1
			body := pattern[i+1 : end]
			name, format, _ = strings.Cut(body, ":")
			i = end
		} else {
			a := i
			for i < len(pattern) && (identStart(pattern[i]) && pattern[i] != '$' && pattern[i] != '%' || pattern[i] >= '0' && pattern[i] <= '9') {
				i++
			}
			name = pattern[a:i]
			i--
		}
		if name == "" {
			return nil, fmt.Errorf("PTX empty template hole")
		}
		t.Holes = append(t.Holes, Hole{name, format, start, i + 1})
	}
	return t, nil
}
func (t *Template) Fill(values map[string]string) (string, error) {
	var out strings.Builder
	at := 0
	used := map[string]bool{}
	for _, h := range t.Holes {
		out.WriteString(strings.ReplaceAll(t.Pattern[at:h.Start], "$$", "$"))
		key := h.Name
		if h.Format != "" {
			if _, ok := values[key+":"+h.Format]; ok {
				key += ":" + h.Format
			}
		}
		s, ok := values[key]
		if !ok {
			return "", fmt.Errorf("PTX missing template value %s", key)
		}
		used[key] = true
		out.WriteString(s)
		at = h.End
	}
	out.WriteString(strings.ReplaceAll(t.Pattern[at:], "$$", "$"))
	for k := range values {
		if !used[k] {
			return "", fmt.Errorf("PTX unused template value %s", k)
		}
	}
	return out.String(), nil
}

// Match captures rendered PTX text, retaining each upstream printer format as
// part of its binding key. Repeated bindings must agree. This matches template
// text; instruction legality remains the responsibility of ValidateWith.
func (t *Template) Match(text string) (map[string]string, bool) {
	values := map[string]string{}
	var match func(int, int, string) bool
	match = func(index, at int, rest string) bool {
		if index == len(t.Holes) {
			return rest == strings.ReplaceAll(t.Pattern[at:], "$$", "$")
		}
		h := t.Holes[index]
		literal := strings.ReplaceAll(t.Pattern[at:h.Start], "$$", "$")
		if !strings.HasPrefix(rest, literal) {
			return false
		}
		rest = rest[len(literal):]
		key := h.Name
		if h.Format != "" {
			key += ":" + h.Format
		}
		if value, exists := values[key]; exists {
			return strings.HasPrefix(rest, value) && match(index+1, h.End, rest[len(value):])
		}
		end := len(t.Pattern)
		if index+1 < len(t.Holes) {
			end = t.Holes[index+1].Start
		}
		next := strings.ReplaceAll(t.Pattern[h.End:end], "$$", "$")
		for n := range rest + " " { // UTF-8 boundaries, including len(rest).
			if !strings.HasPrefix(rest[n:], next) {
				continue
			}
			values[key] = rest[:n]
			if match(index+1, h.End, rest[n:]) {
				return true
			}
		}
		delete(values, key)
		return false
	}
	if !match(0, 0, text) {
		return nil, false
	}
	return values, true
}
func (c *Catalog) Template(id string) (*Template, error) {
	for _, r := range c.LLVM {
		if r.ID == id {
			if r.Syntax == "" {
				return nil, fmt.Errorf("LLVM record %s has no printed PTX syntax", id)
			}
			return CompileTemplate(r.Syntax)
		}
	}
	return nil, fmt.Errorf("unknown LLVM PTX record %s", id)
}

// CompileModuleTemplate uses {{name}} holes, preserving PTX identifiers that
// contain dollar signs. This is convenient for complete modules and functions.
func CompileModuleTemplate(pattern string) (*Template, error) {
	var out strings.Builder
	for len(pattern) > 0 {
		start := strings.Index(pattern, "{{")
		if start < 0 {
			out.WriteString(strings.ReplaceAll(pattern, "$", "$$"))
			break
		}
		out.WriteString(strings.ReplaceAll(pattern[:start], "$", "$$"))
		end := strings.Index(pattern[start+2:], "}}")
		if end < 0 {
			return nil, fmt.Errorf("PTX unclosed module template hole")
		}
		end += start + 2
		name := strings.TrimSpace(pattern[start+2 : end])
		if name == "" {
			return nil, fmt.Errorf("PTX empty module template hole")
		}
		out.WriteString("${" + name + "}")
		pattern = pattern[end+2:]
	}
	return CompileTemplate(out.String())
}

package ptx

import "strings"

type Function struct {
	Name   string  `json:"name"`
	Entry  bool    `json:"entry"`
	Header []Token `json:"header"`
	Body   []Node  `json:"body"`
	Start  int     `json:"start"`
	End    int     `json:"end"`
}
type Declaration struct {
	Names  []string `json:"names"`
	Space  string   `json:"space"`
	Type   string   `json:"type"`
	Tokens []Token  `json:"tokens"`
	Start  int      `json:"start"`
	End    int      `json:"end"`
}
type Flow struct {
	Kind        string `json:"kind"`
	Target      string `json:"target,omitempty"`
	Conditional bool   `json:"conditional"`
	Offset      int    `json:"offset"`
}

func (m *Module) Functions() []Function {
	var out []Function
	var walk func([]Node)
	walk = func(nodes []Node) {
		for _, n := range nodes {
			if n.Kind == "function" {
				entry := false
				name := ""
				seen := false
				depth := 0
				for _, t := range n.Tokens {
					if t.Text == ".entry" || t.Text == ".func" {
						seen = true
						entry = t.Text == ".entry"
						continue
					}
					if !seen {
						continue
					}
					if t.Text == "(" {
						depth++
					} else if t.Text == ")" {
						depth--
					} else if depth == 0 && t.Kind == "identifier" {
						name = t.Text
						break
					}
				}
				out = append(out, Function{name, entry, n.Tokens, n.Children, n.Start, n.End})
			}
			walk(n.Children)
		}
	}
	walk(m.Nodes)
	return out
}
func (m *Module) Declarations() []Declaration {
	var out []Declaration
	var walk func([]Node)
	walk = func(nodes []Node) {
		for _, n := range nodes {
			if n.Kind == "directive" {
				d := Declaration{Tokens: n.Tokens, Start: n.Start, End: n.End}
				for _, t := range n.Tokens {
					if t.Text == "=" {
						break
					}
					switch t.Text {
					case ".reg", ".sreg", ".param", ".local", ".shared", ".global", ".const", ".tex", ".surf", ".sampler":
						if d.Space == "" {
							d.Space = t.Text
						}
					}
					if strings.HasPrefix(t.Text, ".b") || strings.HasPrefix(t.Text, ".u") || strings.HasPrefix(t.Text, ".s") || strings.HasPrefix(t.Text, ".f") || t.Text == ".pred" {
						if t.Text != ".shared" && t.Text != ".surf" && t.Text != ".sampler" && t.Text != ".sreg" {
							d.Type = t.Text
						}
					}
					if t.Kind == "register" || t.Kind == "identifier" {
						d.Names = append(d.Names, t.Text)
					}
				}
				if d.Space != "" {
					out = append(out, d)
				}
			}
			walk(n.Children)
		}
	}
	walk(m.Nodes)
	return out
}
func (m *Module) ControlFlow() []Flow {
	var out []Flow
	for _, in := range m.Instructions {
		kind := ""
		target := ""
		switch in.Mnemonic {
		case "bra", "brx":
			kind = "branch"
			i := 0
			if in.Mnemonic == "brx" {
				i = 1
			}
			if i < len(in.Operands) {
				target = in.Operands[i].Text
			}
		case "call":
			kind = "call"
			if len(in.Operands) > 0 {
				i := 0
				if in.Operands[0].Kind == "tuple" {
					i = 1
				}
				if i < len(in.Operands) {
					target = in.Operands[i].Text
				}
			}
		case "ret":
			kind = "return"
		case "exit":
			kind = "exit"
		case "trap", "brkpt":
			kind = "trap"
		}
		if kind != "" {
			out = append(out, Flow{kind, target, in.Predicate != "", in.Start})
		}
	}
	return out
}

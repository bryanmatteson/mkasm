package ptx

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Token struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}
type Node struct {
	Kind     string  `json:"kind"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
	Tokens   []Token `json:"tokens"`
	Children []Node  `json:"children,omitempty"`
}
type Operand struct {
	Kind   string  `json:"kind"`
	Text   string  `json:"text"`
	Tokens []Token `json:"tokens"`
}
type Instruction struct {
	Opcode    string    `json:"opcode"`
	Mnemonic  string    `json:"mnemonic"`
	Modifiers []string  `json:"modifiers"`
	Predicate string    `json:"predicate,omitempty"`
	Negated   bool      `json:"negated,omitempty"`
	Operands  []Operand `json:"operands"`
	Start     int       `json:"start"`
	End       int       `json:"end"`
}
type Module struct {
	Source       string        `json:"source"`
	Tokens       []Token       `json:"tokens"`
	Nodes        []Node        `json:"nodes"`
	Instructions []Instruction `json:"instructions"`
	Version      string        `json:"version"`
	Targets      []string      `json:"targets"`
	AddressSize  int           `json:"address_size"`
}
type SyntaxError struct {
	Offset, Line, Column int
	Message              string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("PTX %d:%d: %s", e.Line, e.Column, e.Message)
}
func Lex(source string) ([]Token, error) {
	if strings.IndexByte(source, 0) >= 0 {
		return nil, fmt.Errorf("PTX NUL in source")
	}
	if !utf8.ValidString(source) {
		return nil, fmt.Errorf("PTX source is not UTF-8")
	}
	var tokens []Token
	line, col := 1, 1
	emit := func(kind string, start, end, l, c int) {
		tokens = append(tokens, Token{kind, source[start:end], start, end, l, c})
	}
	for i := 0; i < len(source); {
		start, l, c := i, line, col
		ch := source[i]
		kind := "punctuation"
		if ch == 0 {
			return nil, &SyntaxError{i, line, col, "NUL in source"}
		}
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			kind = "whitespace"
			for i < len(source) && strings.ContainsRune(" \t\r\n", rune(source[i])) {
				if source[i] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
				i++
			}
			emit(kind, start, i, l, c)
			continue
		}
		if ch == '/' && i+1 < len(source) && source[i+1] == '/' {
			kind = "comment"
			i += 2
			for i < len(source) && source[i] != '\n' {
				i++
			}
		} else if ch == '/' && i+1 < len(source) && source[i+1] == '*' {
			kind = "comment"
			i += 2
			closed := false
			for i < len(source) {
				if i+1 < len(source) && source[i:i+2] == "*/" {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, &SyntaxError{start, l, c, "unterminated block comment"}
			}
		} else if ch == '"' {
			kind = "string"
			i++
			closed := false
			for i < len(source) {
				if source[i] == '\\' {
					i += 2
					continue
				}
				if source[i] == '"' {
					i++
					closed = true
					break
				}
				if source[i] == '\n' || source[i] == '\r' {
					return nil, &SyntaxError{start, l, c, "newline in string"}
				}
				i++
			}
			if !closed || i > len(source) {
				return nil, &SyntaxError{start, l, c, "unterminated string"}
			}
		} else if identStart(ch) || ch == '.' && i+1 < len(source) && identStart(source[i+1]) {
			kind = "identifier"
			i++
			for i < len(source) {
				if identPart(source[i]) {
					i++
				} else if i+1 < len(source) && source[i:i+2] == "::" {
					i += 2
				} else {
					break
				}
			}
			if ch == '%' {
				kind = "register"
			} else if ch == '.' {
				kind = "directive"
			}
		} else if ch >= '0' && ch <= '9' || ch == '.' && i+1 < len(source) && source[i+1] >= '0' && source[i+1] <= '9' {
			kind = "number"
			i++
			for i < len(source) && (identPart(source[i]) || source[i] == '+' || source[i] == '-') {
				if (source[i] == '+' || source[i] == '-') && source[i-1] != 'e' && source[i-1] != 'E' {
					break
				}
				i++
			}
		} else {
			if ch >= 128 {
				return nil, &SyntaxError{start, l, c, "non-ASCII unquoted token"}
			}
			i++
			if i < len(source) && map[string]bool{"::": true, "<<": true, ">>": true, "<=": true, ">=": true, "==": true, "!=": true, "&&": true, "||": true}[source[start:i+1]] && source[start] != ' ' {
				i++
			}
		}
		for _, v := range source[start:i] {
			if v == '\n' {
				line++
				col = 1
			} else {
				col++
			}
		}
		emit(kind, start, i, l, c)
	}
	return tokens, nil
}
func identStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.ContainsRune("_$%", rune(c))
}
func identPart(c byte) bool { return identStart(c) || c >= '0' && c <= '9' || c == '.' }
func ParseModule(r io.Reader) (*Module, error) {
	b, e := io.ReadAll(r)
	if e != nil {
		return nil, e
	}
	return Decode(string(b))
}
func Decode(source string) (*Module, error) {
	tokens, e := Lex(source)
	if e != nil {
		return nil, e
	}
	m := &Module{Source: source, Tokens: tokens}
	hasAddress := false
	sig := []Token{}
	for _, t := range tokens {
		if t.Kind != "whitespace" && t.Kind != "comment" {
			sig = append(sig, t)
		}
	}
	p := parser{tokens: sig, source: source, module: m}
	m.Nodes, e = p.nodes(false)
	if e != nil {
		return nil, e
	}
	for _, n := range m.Nodes {
		if n.Kind == "directive" && len(n.Tokens) > 1 {
			switch n.Tokens[0].Text {
			case ".version":
				if m.Version != "" {
					return nil, fmt.Errorf("duplicate .version")
				}
				m.Version = n.Tokens[1].Text
			case ".target":
				if len(m.Targets) > 0 {
					return nil, fmt.Errorf("duplicate .target")
				}
				for _, v := range n.Tokens[1:] {
					if v.Text != "," && v.Text != ";" {
						m.Targets = append(m.Targets, v.Text)
					}
				}
			case ".address_size":
				if hasAddress {
					return nil, fmt.Errorf("duplicate .address_size")
				}
				hasAddress = true
				var err error
				m.AddressSize, err = strconv.Atoi(n.Tokens[1].Text)
				if err != nil {
					return nil, fmt.Errorf("invalid .address_size integer")
				}
			}
		}
	}
	if !hasAddress {
		m.AddressSize = 32
	}
	return m, nil
}

type parser struct {
	tokens []Token
	source string
	at     int
	module *Module
	depth  int
}

func (p *parser) nodes(block bool) ([]Node, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 256 {
		return nil, p.fail("scope nesting limit")
	}
	var out []Node
	for p.at < len(p.tokens) {
		if p.tokens[p.at].Text == "}" {
			if !block {
				return nil, p.fail("unmatched closing brace")
			}
			p.at++
			return out, nil
		}
		if p.tokens[p.at].Text == "{" {
			t := p.tokens[p.at]
			p.at++
			children, e := p.nodes(true)
			if e != nil {
				return nil, e
			}
			out = append(out, Node{Kind: "scope", Start: t.Start, End: p.tokens[p.at-1].End, Children: children})
			continue
		}
		start := p.at
		depth := []string{}
		kind := "instruction"
		if p.tokens[start].Kind == "directive" {
			kind = "directive"
		}
		isFunction := false
		finished := false
		for p.at < len(p.tokens) {
			t := p.tokens[p.at]
			if len(depth) == 0 && p.at > start && kind == "directive" && t.Line > p.tokens[p.at-1].Line && !isFunction {
				first := p.tokens[start].Text
				if !semicolonDirective(first) {
					finished = true
					break
				}
			}
			if t.Text == ".entry" || t.Text == ".func" {
				isFunction = true
			}
			if len(depth) == 0 && t.Text == "{" && isFunction {
				header := append([]Token(nil), p.tokens[start:p.at]...)
				p.at++
				children, e := p.nodes(true)
				if e != nil {
					return nil, e
				}
				out = append(out, Node{Kind: "function", Start: p.tokens[start].Start, End: p.tokens[p.at-1].End, Tokens: header, Children: children})
				finished = true
				break
			}
			if len(depth) == 0 && t.Text == ":" {
				p.at++
				out = append(out, Node{Kind: "label", Start: p.tokens[start].Start, End: t.End, Tokens: p.tokens[start:p.at]})
				finished = true
				break
			}
			if len(depth) == 0 && t.Text == ";" {
				p.at++
				finished = true
				break
			}
			if t.Text == "(" || t.Text == "[" || t.Text == "{" {
				depth = append(depth, t.Text)
				if len(depth) > 256 {
					return nil, p.fail("delimiter nesting limit")
				}
			} else if t.Text == ")" || t.Text == "]" || t.Text == "}" {
				if len(depth) == 0 || !matching(depth[len(depth)-1], t.Text) {
					return nil, p.fail("mismatched delimiter or missing semicolon")
				}
				depth = depth[:len(depth)-1]
			}
			p.at++
		}
		if len(out) > 0 && (out[len(out)-1].Kind == "function" || out[len(out)-1].Kind == "label") && out[len(out)-1].Start == p.tokens[start].Start {
			continue
		}
		if len(depth) > 0 {
			return nil, p.fail("unclosed operand/declaration delimiter")
		}
		if p.at == start {
			return nil, p.fail("empty statement")
		}
		if !finished && (kind == "instruction" || kind == "directive" && semicolonDirective(p.tokens[start].Text)) {
			return nil, p.fail("statement missing semicolon")
		}
		ts := p.tokens[start:p.at]
		n := Node{Kind: kind, Start: ts[0].Start, End: ts[len(ts)-1].End, Tokens: ts}
		if kind == "instruction" {
			in, e := instruction(p.source, ts)
			if e != nil {
				return nil, e
			}
			p.module.Instructions = append(p.module.Instructions, in)
		}
		out = append(out, n)
	}
	if block {
		return nil, p.fail("unclosed scope")
	}
	return out, nil
}
func semicolonDirective(s string) bool {
	switch s {
	case ".reg", ".sreg", ".param", ".local", ".shared", ".global", ".const", ".tex", ".surf", ".sampler", ".visible", ".extern", ".weak", ".common", ".align":
		return true
	case ".alias", ".branchtargets", ".calltargets", ".callprototype", ".pragma", ".minperctamemory":
		return true
	}
	return false
}
func matching(a, b string) bool {
	return a == "(" && b == ")" || a == "[" && b == "]" || a == "{" && b == "}"
}
func (p *parser) fail(s string) error {
	if p.at < len(p.tokens) {
		t := p.tokens[p.at]
		return &SyntaxError{t.Start, t.Line, t.Column, s}
	}
	return fmt.Errorf("PTX EOF: %s", s)
}
func instruction(source string, ts []Token) (Instruction, error) {
	in := Instruction{Start: ts[0].Start, End: ts[len(ts)-1].End}
	i := 0
	if ts[i].Text == "@" {
		i++
		if i < len(ts) && ts[i].Text == "!" {
			in.Negated = true
			i++
		}
		if i >= len(ts) || ts[i].Kind != "register" && ts[i].Kind != "identifier" {
			return in, fmt.Errorf("PTX invalid predicate")
		}
		in.Predicate = ts[i].Text
		i++
	}
	if i >= len(ts) || ts[i].Kind != "identifier" {
		return in, fmt.Errorf("PTX invalid opcode")
	}
	in.Opcode = ts[i].Text
	parts := strings.Split(in.Opcode, ".")
	in.Mnemonic = parts[0]
	in.Modifiers = parts[1:]
	i++
	end := len(ts)
	if ts[end-1].Text == ";" {
		end--
	}
	depth := 0
	start := i
	for j := i; j <= end; j++ {
		if j == end || ts[j].Text == "," && depth == 0 {
			if start < j {
				a := ts[start:j]
				kind := "expression"
				if len(a) == 1 {
					kind = a[0].Kind
				} else if a[0].Text == "[" {
					kind = "address"
				} else if a[0].Text == "{" {
					kind = "vector"
				} else if a[0].Text == "(" {
					kind = "tuple"
				}
				in.Operands = append(in.Operands, Operand{kind, source[a[0].Start:a[len(a)-1].End], a})
			} else if j != end || j > i {
				return in, fmt.Errorf("PTX empty operand")
			}
			start = j + 1
		} else if strings.Contains("([{", ts[j].Text) && len(ts[j].Text) == 1 {
			depth++
		} else if strings.Contains(")]}", ts[j].Text) && len(ts[j].Text) == 1 {
			depth--
		}
	}
	return in, nil
}
func (m *Module) Encode() string              { return m.Source }
func (m *Module) Write(w io.Writer) error     { _, e := io.WriteString(w, m.Source); return e }
func (m *Module) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(m) }

// Replace applies a source-span edit and reparses the complete module, keeping all
// unaffected bytes (including comments and whitespace) unchanged.
func (m *Module) Replace(start, end int, text string) (*Module, error) {
	if start < 0 || end < start || end > len(m.Source) {
		return nil, fmt.Errorf("PTX replacement span out of bounds")
	}
	return Decode(m.Source[:start] + text + m.Source[end:])
}
func (m *Module) ReplaceOperand(instructionIndex, operandIndex int, text string) (*Module, error) {
	if instructionIndex < 0 || instructionIndex >= len(m.Instructions) {
		return nil, fmt.Errorf("PTX instruction index")
	}
	a := m.Instructions[instructionIndex].Operands
	if operandIndex < 0 || operandIndex >= len(a) {
		return nil, fmt.Errorf("PTX operand index")
	}
	ts := a[operandIndex].Tokens
	return m.Replace(ts[0].Start, ts[len(ts)-1].End, text)
}

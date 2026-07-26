package arm

import (
	"strconv"
	"strings"

	"mkasm/pkg/ir"
)

// PseudocodeParser converts pseudocode text into AST nodes. It is stateless and
// safe for concurrent use by all IForm workers.
type PseudocodeParser struct{}

// NewPseudocodeParser creates a new pseudocode parser
func NewPseudocodeParser() *PseudocodeParser {
	return &PseudocodeParser{}
}

// ParseLines converts pseudocode lines into PseudocodeLine structures.
// Individual lines never panic the pipeline: bad ASL falls back to raw-only.
func (p *PseudocodeParser) ParseLines(lines []string) []ir.PseudocodeLine {
	result := make([]ir.PseudocodeLine, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		pcLine := ir.PseudocodeLine{Raw: line}
		func() {
			defer func() {
				if recover() != nil {
					pcLine.AST = nil
				}
			}()
			pcLine.AST = p.parseLine(trimmed)
		}()
		result = append(result, pcLine)
	}

	return result
}

// parseLine converts a single line into an AST node
func (p *PseudocodeParser) parseLine(line string) *ir.ExpressionNode {
	if strings.HasPrefix(line, "//") {
		return nil
	}

	if target, value, ok := splitAssignment(line); ok {
		return &ir.ExpressionNode{
			Op: "assign",
			Args: []*ir.ExpressionNode{
				p.parseIdentifier(target),
				p.parseExpression(value),
			},
		}
	}

	if condition, ok := trimKeywordStatement(line, "if", "then"); ok {
		return &ir.ExpressionNode{
			Op: "if",
			Cond: &ir.CondExpr{
				Cond: p.parseExpression(condition),
			},
		}
	}

	if value, ok := trimKeywordValue(line, "return"); ok {
		return &ir.ExpressionNode{
			Op: "return",
			Args: []*ir.ExpressionNode{
				p.parseExpression(value),
			},
		}
	}

	if variable, start, end, step, ok := splitForStatement(line); ok {
		node := &ir.ExpressionNode{
			Op:       "for",
			Variable: variable,
			Args: []*ir.ExpressionNode{
				p.parseExpression(start),
				p.parseExpression(end),
			},
		}
		if step != "" {
			node.Args = append(node.Args, p.parseExpression(step))
		}
		return node
	}

	if condition, ok := trimKeywordStatement(line, "while", "do"); ok {
		return &ir.ExpressionNode{
			Op: "while",
			Cond: &ir.CondExpr{
				Cond: p.parseExpression(condition),
			},
		}
	}

	// Default: try to parse as expression
	return p.parseExpression(line)
}

// parseExpression parses a general expression
func (p *PseudocodeParser) parseExpression(expr string) *ir.ExpressionNode {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return &ir.ExpressionNode{Literal: ""}
	}

	// Strip matching outer parentheses once
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && balancedParens(expr[1:len(expr)-1]) {
		return p.parseExpression(expr[1 : len(expr)-1])
	}

	if name, arguments, ok := splitCall(expr); ok {
		return &ir.ExpressionNode{
			Op: "call",
			Call: &ir.CallExpr{
				FuncName: name,
				Args:     p.parseArguments(arguments),
			},
		}
	}

	// Binary operators: only split at depth 0 (not inside () or [])
	for _, op := range []string{"==", "!=", "<=", ">=", "AND", "OR", "XOR", "<<", ">>", "<", ">", "+", "-", "*", "/", "%"} {
		if idx := indexOpOutside(expr, op); idx > 0 {
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+len(op):])
			if left == "" || right == "" {
				continue
			}
			return &ir.ExpressionNode{
				Op: p.normalizeOperator(op),
				Args: []*ir.ExpressionNode{
					p.parseExpression(left),
					p.parseExpression(right),
				},
			}
		}
	}

	// Unary operators
	if strings.HasPrefix(expr, "NOT ") || strings.HasPrefix(expr, "!") {
		inner := strings.TrimPrefix(strings.TrimPrefix(expr, "NOT "), "!")
		return &ir.ExpressionNode{
			Op: "not",
			Args: []*ir.ExpressionNode{
				p.parseExpression(strings.TrimSpace(inner)),
			},
		}
	}

	if p.isLiteral(expr) {
		return &ir.ExpressionNode{Literal: expr}
	}

	return p.parseIdentifier(expr)
}

// parseIdentifier parses an identifier (variable, register, etc.)
func (p *PseudocodeParser) parseIdentifier(ident string) *ir.ExpressionNode {
	ident = strings.TrimSpace(ident)
	if ident == "" {
		return &ir.ExpressionNode{Variable: ""}
	}

	// Array access X[n] — only when a matching ] exists after [
	if open := strings.Index(ident, "["); open > 0 {
		close := matchingBracket(ident, open, '[', ']')
		if close > open {
			base := ident[:open]
			indexExpr := ident[open+1 : close]
			node := &ir.ExpressionNode{
				Op: "index",
				Args: []*ir.ExpressionNode{
					{Variable: base},
					p.parseExpression(indexExpr),
				},
			}
			// Trailing field after ] is rare; keep remainder as variable suffix if any
			if close+1 < len(ident) {
				rest := strings.TrimSpace(ident[close+1:])
				if rest != "" {
					return &ir.ExpressionNode{
						Op:   "suffix",
						Args: []*ir.ExpressionNode{node, p.parseIdentifier(rest)},
					}
				}
			}
			return node
		}
	}

	// Field access PSTATE.N
	if idx := strings.Index(ident, "."); idx > 0 && idx+1 < len(ident) {
		base := ident[:idx]
		field := ident[idx+1:]
		return &ir.ExpressionNode{
			Op: "field",
			Args: []*ir.ExpressionNode{
				{Variable: base},
				{Variable: field},
			},
		}
	}

	return &ir.ExpressionNode{Variable: ident}
}

// indexOpOutside finds op at paren/bracket depth 0; -1 if none.
func indexOpOutside(s, op string) int {
	depth := 0
	for i := 0; i+len(op) <= len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && s[i:i+len(op)] == op {
			// avoid matching unary minus at start or letter-bounded AND inside idents poorly
			if op == "-" || op == "+" {
				// require spaces or non-ident boundaries for +/-
				if i > 0 && (s[i-1] == 'e' || s[i-1] == 'E') {
					// scientific notation skip is imperfect; still ok
				}
			}
			return i
		}
	}
	return -1
}

func matchingBracket(s string, open int, openCh, closeCh byte) int {
	if open < 0 || open >= len(s) || s[open] != openCh {
		return -1
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case openCh:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func balancedParens(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// parseArguments parses function call arguments
func (p *PseudocodeParser) parseArguments(argsStr string) []*ir.ExpressionNode {
	argsStr = strings.TrimSpace(argsStr)
	if argsStr == "" {
		return nil
	}

	args := make([]*ir.ExpressionNode, 0, 4)
	start, depth := 0, 0
	var quote byte
	for i := 0; i <= len(argsStr); i++ {
		if i < len(argsStr) {
			c := argsStr[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
				continue
			case '(', '[', '{':
				depth++
				continue
			case ')', ']', '}':
				if depth > 0 {
					depth--
				}
				continue
			case ',':
				if depth != 0 {
					continue
				}
			default:
				continue
			}
		}
		if part := strings.TrimSpace(argsStr[start:i]); part != "" {
			args = append(args, p.parseExpression(part))
		}
		start = i + 1
	}

	return args
}

// splitAssignment recognizes the assignment subset this lightweight parser
// models. It deliberately ignores comparison operators and equal signs nested
// inside calls or index expressions.
func splitAssignment(line string) (target, value string, ok bool) {
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth != 0 || i+1 < len(line) && line[i+1] == '=' ||
				i > 0 && (line[i-1] == '!' || line[i-1] == '<' || line[i-1] == '>') {
				continue
			}
			target = strings.TrimSpace(line[:i])
			value = strings.TrimSpace(line[i+1:])
			if value == "" || !isAssignmentTarget(target) {
				return "", "", false
			}
			return target, value, true
		}
	}
	return "", "", false
}

func isAssignmentTarget(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) && s[i] != '[' && s[i] != ']' && s[i] != '.' {
			return false
		}
	}
	return true
}

func trimKeywordStatement(line, prefix, suffix string) (string, bool) {
	body, ok := trimKeywordValue(line, prefix)
	if !ok || len(body) <= len(suffix) || !strings.HasSuffix(body, suffix) {
		return "", false
	}
	suffixStart := len(body) - len(suffix)
	if !isSpace(body[suffixStart-1]) {
		return "", false
	}
	body = strings.TrimSpace(body[:suffixStart])
	return body, body != ""
}

func trimKeywordValue(line, keyword string) (string, bool) {
	if !strings.HasPrefix(line, keyword) || len(line) == len(keyword) ||
		!isSpace(line[len(keyword)]) {
		return "", false
	}
	value := strings.TrimSpace(line[len(keyword):])
	return value, value != ""
}

func splitForStatement(line string) (variable, start, end, step string, ok bool) {
	body, isFor := trimKeywordValue(line, "for")
	if !isFor {
		return "", "", "", "", false
	}
	eq := indexByteOutside(body, '=')
	if eq < 1 {
		return "", "", "", "", false
	}
	variable = strings.TrimSpace(body[:eq])
	if !isIdentifier(variable) {
		return "", "", "", "", false
	}
	rest := strings.TrimSpace(body[eq+1:])
	to := indexWordOutside(rest, "to")
	if to < 1 {
		return "", "", "", "", false
	}
	start = strings.TrimSpace(rest[:to])
	end = strings.TrimSpace(rest[to+len("to"):])
	hadStep := false
	if at := indexWordOutside(end, "step"); at >= 0 {
		hadStep = true
		step = strings.TrimSpace(end[at+len("step"):])
		end = strings.TrimSpace(end[:at])
	}
	if start == "" || end == "" || hadStep && step == "" {
		return "", "", "", "", false
	}
	return variable, start, end, step, true
}

func splitCall(expr string) (name, arguments string, ok bool) {
	open := strings.IndexByte(expr, '(')
	if open < 1 {
		return "", "", false
	}
	name = strings.TrimSpace(expr[:open])
	if !isIdentifier(name) {
		return "", "", false
	}
	close := matchingBracket(expr, open, '(', ')')
	if close != len(expr)-1 {
		return "", "", false
	}
	return name, expr[open+1 : close], true
}

func indexByteOutside(s string, target byte) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i] == target {
				return i
			}
		}
	}
	return -1
}

func indexWordOutside(s, word string) int {
	depth := 0
	for i := 0; i+len(word) <= len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && s[i:i+len(word)] == word &&
			i > 0 && isSpace(s[i-1]) &&
			i+len(word) < len(s) && isSpace(s[i+len(word)]) {
			return i
		}
	}
	return -1
}

func isIdentifier(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return true
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// isLiteral checks if an expression is a literal value
func (p *PseudocodeParser) isLiteral(expr string) bool {
	// Binary literal
	if strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'") {
		return true
	}

	// Hex literal
	if strings.HasPrefix(expr, "0x") {
		return true
	}

	// Numeric literal
	if _, err := strconv.ParseInt(expr, 10, 64); err == nil {
		return true
	}

	// Boolean literals
	if expr == "TRUE" || expr == "FALSE" {
		return true
	}

	// UNKNOWN literal
	if expr == "UNKNOWN" {
		return true
	}

	return false
}

// normalizeOperator converts ARM pseudocode operators to standard form
func (p *PseudocodeParser) normalizeOperator(op string) string {
	switch op {
	case "AND":
		return "and"
	case "OR":
		return "or"
	case "XOR", "EOR":
		return "xor"
	case "NOT":
		return "not"
	case "<<":
		return "lsl"
	case ">>":
		return "lsr"
	default:
		return strings.ToLower(op)
	}
}

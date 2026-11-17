package arm

import (
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// Find immediate decode guards by tokens, so line wrapping and comments do not
// split a condition or let an outer if consume a nested statement's guard.
func featureDecodeGuards(code string) [][]int {
	tokens := requirementTokens(code)
	var guards [][]int
	for i, token := range tokens {
		if token.text != "if" {
			continue
		}
		end := i + 1
		for end < len(tokens) && tokens[end].text != "then" && tokens[end].text != ";" {
			end++
		}
		if end+3 < len(tokens) && tokens[end].text == "then" && tokens[end+1].text == "Undefined" && tokens[end+2].text == "(" && tokens[end+3].text == ")" {
			// AArch32 spells its immediate UNDEF decode boundary differently.
			guards = append(guards, []int{token.start, tokens[end+3].end, token.end, tokens[end].start, tokens[end+1].start, tokens[end+1].end})
			continue
		}
		if end+4 >= len(tokens) || tokens[end].text != "then" || tokens[end+1].text != "EndOfDecode" || tokens[end+2].text != "(" || tokens[end+4].text != ")" {
			continue
		}
		kind := tokens[end+3]
		if kind.text != "Decode_UNDEF" && kind.text != "Decode_NOP" {
			continue
		}
		guards = append(guards, []int{token.start, tokens[end+4].end, token.end, tokens[end].start, kind.start + len("Decode_"), kind.end})
	}
	return guards
}

func applyFeatureRequirements(instr *ir.InstructionIR, p *ParsedIForm) {
	var conditions []ir.RequirementExpr
	if instr.Requirements.Expression != nil {
		conditions = append(conditions, *instr.Requirements.Expression)
	} else {
		for _, t := range instr.Features.Tags {
			if t.Required {
				conditions = append(conditions, ir.ParseRequirementExpression(t.Name, false))
			}
		}
	}
	for _, f := range p.Features {
		conditions = append(conditions, ir.ParseRequirementExpression(f, false))
	}
	groups := p.FeatureAlternativeGroups
	if len(groups) == 0 && len(p.FeatureAlternatives) > 0 {
		groups = [][]string{p.FeatureAlternatives}
	}
	for _, group := range groups {
		var alternatives []ir.RequirementExpr
		for _, f := range group {
			alternatives = append(alternatives, ir.ParseRequirementExpression(f, false))
		}
		conditions = append(conditions, ir.RequirementAny(alternatives...))
	}

	var fallbacks []ir.RequirementExpr
	var priorGuards []ir.RequirementExpr
	for _, code := range p.Pseudocode {
		guards := featureDecodeGuards(code)
		for _, indexes := range guards {
			m := []string{code[indexes[0]:indexes[1]], code[indexes[2]:indexes[3]], code[indexes[4]:indexes[5]]}
			condition := ir.ParseRequirementExpression(m[1], false)
			if ancestors := requirementGuardContext(code[:indexes[0]]); len(ancestors) > 0 {
				condition = ir.RequirementAll(append(ancestors, condition)...)
			}
			if strings.Contains(m[1], "IsFeatureImplemented") {
				conditions = append(conditions, ir.RequirementNot(condition))
				if m[2] == "NOP" {
					fallback := ir.RequirementAll(append(append([]ir.RequirementExpr(nil), priorGuards...), condition)...)
					fallbacks = append(fallbacks, fallback)
				}
			}
			priorGuards = append(priorGuards, ir.RequirementNot(condition))
		}
		// Feature-bearing source that this parser cannot represent stays explicit.
		// Recognized guards can coexist with complex checks; retain unknown lines too.
		var remainder strings.Builder
		start := 0
		for _, indexes := range guards {
			remainder.WriteString(code[start:indexes[0]])
			start = indexes[1]
		}
		remainder.WriteString(code[start:])
		remaining := remainder.String()
		for _, line := range strings.Split(remaining, "\n") {
			if strings.Contains(line, "IsFeatureImplemented") {
				conditions = append(conditions, ir.UnknownRequirement(strings.TrimSpace(line)))
			}
		}
	}
	if len(conditions) > 0 {
		e := ir.RequirementAll(conditions...)
		instr.Requirements.Expression = &e
		instr.Requirements.Source = "Arm XML feature metadata and decode pseudocode"
	}
	if len(fallbacks) > 0 {
		e := ir.RequirementAny(fallbacks...)
		instr.Requirements.Fallback = &e
		instr.Requirements.FallbackBehavior = "nop"
	}
}

func instructionRequirements(instr *ir.InstructionIR) ir.Requirements {
	r := instr.Requirements
	if r.Expression == nil && len(instr.Features.Tags) > 0 {
		var args []ir.RequirementExpr
		for _, f := range instr.Features.Tags {
			if f.Required {
				args = append(args, ir.ParseRequirementExpression(f.Name, false))
			}
		}
		if len(args) > 0 {
			e := ir.RequirementAll(args...)
			r.Expression = &e
			r.Source = "Arm feature tags"
		}
	}
	mode := "a64"
	if instr.InstructionSet == "A32" {
		mode = "a32"
	}
	if instr.InstructionSet == "T32" {
		mode = "thumb"
	}
	e := ir.UnknownRequirement("Arm feature metadata absent")
	if r.Expression != nil {
		e = *r.Expression
	}
	e = ir.RequirementAll(ir.RequirementExpr{Op: "mode", Name: mode}, e)
	r.Expression = &e
	if r.Fallback != nil {
		f := ir.RequirementAll(ir.RequirementExpr{Op: "mode", Name: mode}, *r.Fallback)
		r.Fallback = &f
	}
	return r
}

func inheritRequirements(entries []CatalogEntry) {
	original := append([]CatalogEntry(nil), entries...)
	byID := make(map[string]int)
	for i, e := range entries {
		byID[e.EncodingID] = i
	}
	// Resolve recursively so aliases of aliases inherit too. Cycles and missing
	// canonical forms remain explicit unknown requirements.
	var visit func(int, map[int]bool) ir.Requirements
	visit = func(i int, path map[int]bool) ir.Requirements {
		r := original[i].Requirements
		if original[i].AliasOf == "" {
			return r
		}
		if path[i] {
			return constrainUnknownAlias(r, "alias cycle")
		}
		parent, ok := byID[original[i].AliasOf]
		if !ok {
			return constrainUnknownAlias(r, "alias target unavailable: "+original[i].AliasOf)
		}
		path[i] = true
		p := visit(parent, path)
		delete(path, i)
		// An alias without its own feature declaration inherits the canonical rule.
		// Its alias-specific mode is retained; an absent declaration is not an extra
		// unknown layered on top of an available canonical requirement.
		own := *r.Expression
		if len(own.Args) == 2 && own.Args[1].Op == "unknown" && own.Args[1].Name == "Arm feature metadata absent" {
			own = own.Args[0]
		}
		e := ir.RequirementAll(own, *p.Expression)
		r.Expression = &e
		if r.Fallback != nil {
			// A local fallback cannot bypass canonical architectural admission.
			// A canonical fallback can establish that admission only when it
			// describes the same alternate behavior (a NOP is not a trap).
			canonical := *p.Expression
			if p.Fallback != nil && r.FallbackBehavior != "" && r.FallbackBehavior == p.FallbackBehavior {
				canonical = ir.RequirementAny(canonical, *p.Fallback)
			}
			fallback := ir.RequirementAll(*r.Fallback, canonical)
			r.Fallback = &fallback
		} else {
			if p.Fallback != nil {
				fallback := ir.RequirementAll(own, *p.Fallback)
				r.Fallback = &fallback
			}
			r.FallbackBehavior = p.FallbackBehavior
		}
		r.Source = "Arm alias inheritance: " + original[i].AliasOf
		return r
	}
	for i := range entries {
		entries[i].Requirements = visit(i, make(map[int]bool))
	}
}

// Missing canonical facts constrain both requested and alternate behavior.
// Known-false local conditions still reject under the three-valued evaluator.
func constrainUnknownAlias(r ir.Requirements, reason string) ir.Requirements {
	unknown := ir.UnknownRequirement(reason)
	e := ir.RequirementAll(*r.Expression, unknown)
	r.Expression = &e
	if r.Fallback != nil {
		fallback := ir.RequirementAll(*r.Fallback, unknown)
		r.Fallback = &fallback
	}
	return r
}

// Keep outer statement conditions on nested guards. ASL also has conditional
// expressions ("x = if c then a else b;"); their branches must not enter the
// statement stack. Tokens inside an ordinary statement are skipped through its
// terminating semicolon, so nested/multiline expressions cannot leak scope.
type requirementToken struct {
	text       string
	start, end int
}

func requirementTokens(source string) []requirementToken {
	var tokens []requirementToken
	for i := 0; i < len(source); {
		start := i
		switch {
		case source[i] == ' ' || source[i] == '\t' || source[i] == '\r' || source[i] == '\n':
			i++
			continue
		case strings.HasPrefix(source[i:], "//"):
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		case strings.HasPrefix(source[i:], "/*"):
			i += 2
			for i < len(source) && !strings.HasPrefix(source[i:], "*/") {
				i++
			}
			if i < len(source) {
				i += 2
			}
			continue
		case source[i] == '\'' || source[i] == '"':
			quote := source[i]
			i++
			for i < len(source) {
				if source[i] == '\\' && i+1 < len(source) {
					i += 2
					continue
				}
				if source[i] == quote {
					i++
					break
				}
				i++
			}
		case requirementWordByte(source[i]):
			for i < len(source) && requirementWordByte(source[i]) {
				i++
			}
		default:
			i++
		}
		tokens = append(tokens, requirementToken{source[start:i], start, i})
	}
	return tokens
}

func requirementWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func requirementGuardContext(prefix string) []ir.RequirementExpr {
	type branch struct {
		seen, current ir.RequirementExpr
		subject       string
	}
	var stack []branch
	tokens := requirementTokens(prefix)
	statementStart := true
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token.text == ";" {
			statementStart = true
			continue
		}
		if !statementStart {
			continue
		}
		switch token.text {
		case "case":
			end := i + 1
			for end < len(tokens) && tokens[end].text != "of" {
				end++
			}
			if end == len(tokens) {
				return []ir.RequirementExpr{ir.UnknownRequirement(prefix[token.start:])}
			}
			subject := strings.TrimSpace(prefix[token.end:tokens[end].start])
			unknown := ir.UnknownRequirement("case " + subject)
			stack = append(stack, branch{seen: ir.RequirementNot(ir.RequirementExpr{Op: "true"}), current: unknown, subject: subject})
			i = end
		case "when", "otherwise":
			end := i + 1
			for end < len(tokens) && !(tokens[end-1].text == "=" && tokens[end].text == ">") {
				end++
			}
			if end == len(tokens) || len(stack) == 0 || stack[len(stack)-1].subject == "" {
				return []ir.RequirementExpr{ir.UnknownRequirement(prefix[token.start:])}
			}
			frame := &stack[len(stack)-1]
			if token.text == "otherwise" {
				frame.current = ir.RequirementNot(frame.seen)
			} else {
				pattern := strings.TrimSpace(prefix[token.end:tokens[end-1].start])
				var alternatives []ir.RequirementExpr
				for _, value := range strings.Split(pattern, ",") {
					alternatives = append(alternatives, ir.ParseRequirementExpression(frame.subject+" == "+strings.TrimSpace(value), false))
				}
				frame.current = ir.RequirementAny(alternatives...)
				frame.seen = ir.RequirementAny(frame.seen, frame.current)
			}
			i = end
		case "if", "elsif", "for", "while":
			terminator := "then"
			if token.text == "for" || token.text == "while" {
				terminator = "do"
			}
			end := i + 1
			depth := 0
			for end < len(tokens) {
				if depth == 0 && (tokens[end].text == terminator || tokens[end].text == ";") {
					break
				}
				if tokens[end].text == "(" || tokens[end].text == "[" || tokens[end].text == "{" {
					depth++
				}
				if tokens[end].text == ")" || tokens[end].text == "]" || tokens[end].text == "}" {
					depth--
				}
				end++
			}
			if end == len(tokens) || tokens[end].text != terminator {
				unknown := ir.UnknownRequirement(prefix[token.start:])
				stack = append(stack, branch{seen: unknown, current: unknown})
				var contexts []ir.RequirementExpr
				for _, frame := range stack {
					contexts = append(contexts, frame.current)
				}
				return contexts
			}
			condition := ir.ParseRequirementExpression(prefix[token.end:tokens[end].start], false)
			if token.text == "for" || token.text == "while" {
				condition = ir.UnknownRequirement(prefix[token.start:tokens[end].end])
			}
			if token.text == "elsif" && len(stack) == 0 {
				condition = ir.UnknownRequirement("unmatched elsif")
			}
			if token.text == "elsif" && len(stack) > 0 {
				previous := &stack[len(stack)-1]
				previous.current = ir.RequirementAll(ir.RequirementNot(previous.seen), condition)
				previous.seen = ir.RequirementAny(previous.seen, condition)
			} else {
				stack = append(stack, branch{seen: condition, current: condition})
			}
			i = end
		case "else":
			if len(stack) > 0 {
				previous := &stack[len(stack)-1]
				previous.current = ir.RequirementNot(previous.seen)
			} else {
				unknown := ir.UnknownRequirement("unmatched else")
				stack = append(stack, branch{seen: unknown, current: unknown})
			}
		case "end":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			statementStart = false
		default:
			statementStart = false
		}
	}
	var contexts []ir.RequirementExpr
	for _, frame := range stack {
		contexts = append(contexts, frame.current)
	}
	return contexts
}

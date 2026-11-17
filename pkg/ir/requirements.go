package ir

// RequirementExpr preserves source feature logic rather than flattening it into
// tags. The zero value is unknown. Supported operations are true, feature, mode,
// field_eq, all, any, not and if (condition, then, else).
type RequirementExpr struct {
	Op    string            `json:"op"`
	Name  string            `json:"name,omitempty"`
	Value uint64            `json:"value,omitempty"`
	Mask  uint64            `json:"mask,omitempty"`
	Args  []RequirementExpr `json:"args,omitempty"`
}

// Requirements describes architectural admission, not an emulator's supported
// instruction set. Fallback is a separately reported alternate architectural
// behavior (for example a hint becoming a NOP). Absent metadata stays unknown.
type Requirements struct {
	Expression       *RequirementExpr `json:"expression,omitempty"`
	Fallback         *RequirementExpr `json:"fallback,omitempty"`
	FallbackBehavior string           `json:"fallback_behavior,omitempty"`
	Source           string           `json:"source,omitempty"`
}

func RequirementAll(args ...RequirementExpr) RequirementExpr {
	return RequirementExpr{Op: "all", Args: args}
}
func RequirementAny(args ...RequirementExpr) RequirementExpr {
	return RequirementExpr{Op: "any", Args: args}
}
func RequirementNot(arg RequirementExpr) RequirementExpr {
	return RequirementExpr{Op: "not", Args: []RequirementExpr{arg}}
}
func UnknownRequirement(source string) RequirementExpr {
	return RequirementExpr{Op: "unknown", Name: source}
}

// Satisfaction is a three-valued result; unknown is never silently admitted.
type Satisfaction uint8

const (
	Unknown Satisfaction = iota
	Satisfied
	Unsatisfied
)

type UnknownPolicy uint8

const (
	RejectUnknown UnknownPolicy = iota
	AllowUnknown
)

type RequirementContext struct {
	Features map[string]bool
	Mode     string
	Fields   map[string]uint64
}

func (s Satisfaction) Admit(policy UnknownPolicy) bool {
	return s == Satisfied || s == Unknown && policy == AllowUnknown
}
func (e RequirementExpr) Evaluate(c RequirementContext) Satisfaction {
	switch e.Op {
	case "true":
		return Satisfied
	case "feature":
		if c.Features[e.Name] {
			return Satisfied
		}
		return Unsatisfied
	case "mode":
		if c.Mode == "" {
			return Unknown
		}
		if c.Mode == e.Name {
			return Satisfied
		}
		return Unsatisfied
	case "field_eq":
		v, ok := c.Fields[e.Name]
		if !ok {
			return Unknown
		}
		if v&e.Mask == e.Value&e.Mask {
			return Satisfied
		}
		return Unsatisfied
	case "not":
		if len(e.Args) != 1 {
			return Unknown
		}
		s := e.Args[0].Evaluate(c)
		if s == Satisfied {
			return Unsatisfied
		}
		if s == Unsatisfied {
			return Satisfied
		}
		return Unknown
	case "all", "any":
		result := Satisfied
		if e.Op == "any" {
			result = Unsatisfied
		}
		for _, a := range e.Args {
			s := a.Evaluate(c)
			if e.Op == "all" && s == Unsatisfied {
				return Unsatisfied
			}
			if e.Op == "any" && s == Satisfied {
				return Satisfied
			}
			if s == Unknown {
				result = Unknown
			}
		}
		return result
	case "if":
		if len(e.Args) != 3 {
			return Unknown
		}
		switch e.Args[0].Evaluate(c) {
		case Satisfied:
			return e.Args[1].Evaluate(c)
		case Unsatisfied:
			return e.Args[2].Evaluate(c)
		}
		a, b := e.Args[1].Evaluate(c), e.Args[2].Evaluate(c)
		if a == b {
			return a
		}
		return Unknown
	}
	return Unknown
}

type RequirementEvaluation struct {
	Primary          Satisfaction
	Fallback         Satisfaction
	HasFallback      bool
	FallbackBehavior string
}

func (r Requirements) Evaluate(c RequirementContext) RequirementEvaluation {
	result := RequirementEvaluation{HasFallback: r.Fallback != nil, FallbackBehavior: r.FallbackBehavior}
	if r.Expression != nil {
		result.Primary = r.Expression.Evaluate(c)
	}
	if r.Fallback != nil {
		result.Fallback = r.Fallback.Evaluate(c)
	}
	return result
}

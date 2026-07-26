package arm

import (
	"fmt"
	"strconv"
	"strings"
)

// ValueChoice is one exact spelling/value pair accepted by a built-in operand
// type such as Extend.  These operands use shared Rust enums, but each encoding
// accepts only the rows listed in its own ARM value table.
type ValueChoice struct {
	Symbol string
	Value  uint32
}

// Param is one parameter of a generated typed assembler method.
type Param struct {
	// Name is the Rust parameter name, derived from the ARM operand symbol.
	Name string
	// RustType is the parameter's Rust type.
	RustType string
	// Field is the encoding bit field this parameter lands in.
	Field string
	// Split names the fields the value spans, most significant first, when it
	// does not fit in one field. Empty for the ordinary single-field case.
	Split []string
	Class OperandClass
	// Arrangement is true when a size specifier attaches to this register
	// operand, making the element arrangement part of the operand rather than a
	// parameter of its own.
	Arrangement bool
	// Arr carries ARM's arrangement table when the operand is sized by a <T>
	// specifier: which spellings are legal and what bits each one sets. Without
	// it the size and Q fields would be left at zero and the encoding would be
	// wrong for every arrangement but the first.
	Arr *ArrSpec
	// ArrDispatch is Arr resolved against one encoding's field layout: the mask
	// the arrangement controls and the bits each spelling sets.
	ArrDispatch *ArrDispatch
	// ArrSymbol is the specifier that sized this operand: <T>, <Ta>, <Tb>. A
	// narrowing instruction writes different specifiers on different operands
	// (ADDHNB <Zd>.<T>, <Zn>.<Tb>), and they are not interchangeable.
	ArrSymbol string
	// Enum is the generated Rust enum for an operand ARM defines by a table of
	// assembler spellings — a prefetch operation, an SVE count pattern.
	Enum *EnumSpec
	// WidthCases expands this operand into one form per register width, for the
	// positions where ARM writes the width as a specifier over a field rather
	// than in the operand's own name: "ADD <Xd|SP>, <Xn|SP>, <R><m>" takes a W
	// or an X register, selected by the "option" field. One Rust method with two
	// impls is the faithful rendering; a single type would silently accept one
	// width and encode the other.
	WidthCases []WidthCase
	// WidthFields and WidthBits are the chosen case after expansion: the fields
	// the specifier occupies, and the bits this variant sets in them.
	WidthFields []string
	WidthBits   []string
	// Lo/Hi/Scale carry ARM's stated immediate range and encoding multiplier.
	Lo, Hi   int64
	HasRange bool
	Scale    int64
	// RegLo/RegHi restrict a register operand to part of its bank, and Bias is
	// what the encoding subtracts: the SME vector-select register is written
	// W12-W15 and encoded in a 2-bit field as v-12.
	RegLo, RegHi int64
	HasRegRange  bool
	RegMultiple  int64
	RegRanges    []RegRange
	// Bias is what the encoding subtracts before storing the value.
	Bias int64
	// Negate is set when the field counts down from a constant.
	Negate int64
	// Default is the value ARM specifies when the operand is omitted, e.g.
	// RET's <Xn> "Defaults to X30 if absent". Leaving it out would silently
	// encode Rn = 0, making `ret()` mean `ret x0`.
	Default       int64
	HasDefault    bool
	DefaultSymbol string
	// Choices retains the legal rows for a shared built-in operand type.  A
	// register-offset form accepts UXTW/LSL/SXTW/SXTX, for example, rather than
	// every value in the global Extend enum.
	Choices []ValueChoice
	// Selector records ARM prose such as "option<0> is set to 0" on a
	// parenthesized register alternative.  It constrains any operand table that
	// owns the same field.
	SelectorField string
	SelectorBit   int
	SelectorValue uint32
	HasSelector   bool
	Mirrors       []string
	InvertLSB     bool
	// Optional is true when the asmtemplate wraps this operand in braces:
	// "ADD <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}". Rust has no default arguments,
	// so the plain method omits optional trailing operands and a suffixed
	// variant accepts them.
	Optional bool
}

// EnumSpec is a generated Rust enum standing for one ARM value table.
type EnumSpec struct {
	// Name is the Rust type name, derived from ARM's operand-class link id.
	Name string
	// Fields are the bit fields the table spans, in ARM's order.
	Fields []string
	// Rows is one entry per legal spelling.
	Rows []ArrRow
}

// MarkOptional flags the operands a caller may leave out.
//
// Braces alone do not decide it. ARM writes both an optional operand
// ("ADD <Xd>, <Xn>, #<imm>{, <shift>}") and a register list
// ("LD2B { <Zt1>.B, <Zt2>.B }, ...") in braces, and treating a list's first
// register as omittable would generate a method that drops a required operand.
// So the braces locate the candidates and ARM's own prose confirms them: an
// operand that may be left out always says so, either as "optional" or by
// naming the value assumed in its absence.
func MarkOptional(asmTemplate string, params []Param, ops []AsmOperand, exps map[string]AsmExplanation) {
	depth := 0
	idx := 0
	braced := map[int]bool{}
	// optionalByPosition marks operands inside a separator-led brace group,
	// which are optional regardless of what the prose says.
	optionalByPosition := map[int]bool{}
	// A brace group opening with a separator is an optional continuation of the
	// operand list — "{, LSL #<amount>}", "{[<imm>]}" — and never a register
	// list, which opens with its first register.
	sepGroup := map[int]bool{}
	openGroups := 0
	for i := 0; i < len(asmTemplate); i++ {
		switch asmTemplate[i] {
		case '{':
			depth++
			rest := strings.TrimSpace(asmTemplate[i+1:])
			sepGroup[depth] = rest != "" && (rest[0] == ',' || rest[0] == '[')
			if sepGroup[depth] {
				openGroups++
			}
		case '}':
			if depth > 0 {
				if sepGroup[depth] {
					openGroups--
				}
				delete(sepGroup, depth)
				depth--
			}
		case '<':
			end := strings.IndexByte(asmTemplate[i:], '>')
			if end < 0 {
				continue
			}
			if depth > 0 {
				braced[idx] = true
				if openGroups > 0 {
					optionalByPosition[idx] = true
				}
			}
			idx++
			i += end
		}
	}
	// Params drop specifiers, derived operands and alternative spellings, so
	// walk ops to keep indices aligned.
	alt := AlternativeOperands(asmTemplate)
	pi := 0
	for oi, o := range ops {
		if alt[oi] {
			continue
		}
		c := ClassifyOperandWith(o, exps[o.Symbol])
		if c.Class == ClassArrangement || c.Class == ClassDerived {
			continue
		}
		if pi >= len(params) {
			break
		}
		if braced[oi] && (optionalByPosition[oi] || statesOptional(exps[o.Symbol].Prose+" "+o.Hover)) {
			params[pi].Optional = true
			// ARM value tables use an explicit [absent] row when omission has
			// its own encoding (SMSTART/SMSTOP are the canonical examples).
			// Preserve that row as the field default instead of leaving the
			// selector at the encoding diagram's zero-valued free bits.
			if params[pi].Enum != nil && params[pi].DefaultSymbol == "" {
				for _, row := range params[pi].Enum.Rows {
					if strings.EqualFold(strings.TrimSpace(row.Symbol), "[absent]") {
						params[pi].DefaultSymbol = row.Symbol
						params[pi].HasDefault = true
						break
					}
				}
			}
		}
		pi++
	}
}

// AlternativeOperands marks the operands that are alternative spellings of an
// earlier one rather than operands of their own.
//
// ARM writes a choice as "DSB (<option>|#<imm>)": both name the same field, and
// only one is written at a call site. The first spelling becomes the typed
// method; the numeric alternative stays available through the exact encoder.
func AlternativeOperands(asmTemplate string) map[int]bool {
	alt := map[int]bool{}
	depth, idx := 0, 0
	// afterBar[d] records that a "|" has been seen at paren depth d.
	afterBar := map[int]bool{}
	for i := 0; i < len(asmTemplate); i++ {
		switch asmTemplate[i] {
		case '(':
			depth++
			afterBar[depth] = false
		case ')':
			if depth > 0 {
				delete(afterBar, depth)
				depth--
			}
		case '|':
			if depth > 0 {
				afterBar[depth] = true
			}
		case '<':
			end := strings.IndexByte(asmTemplate[i:], '>')
			if end < 0 {
				continue
			}
			for d := 1; d <= depth; d++ {
				if afterBar[d] {
					alt[idx] = true
					break
				}
			}
			idx++
			i += end
		}
	}
	return alt
}

// statesOptional reports whether ARM's prose says the operand may be left out.
func statesOptional(prose string) bool {
	p := strings.ToLower(prose)
	return strings.Contains(p, "optional") ||
		strings.Contains(p, "default") ||
		strings.Contains(p, "if absent") ||
		strings.Contains(p, "can be omitted") ||
		strings.Contains(p, "is omitted")
}

// tableTyped reports whether an operand is spelled from ARM's value table rather
// than placed as a number. Registers, conditions, shifts and extends have tables
// too, but the crate gives them their own types.
func tableTyped(c ClassifiedOperand) bool {
	return len(c.Explanation.Values) > 0 && !registerClass(c.Class) &&
		c.Class != ClassCond && c.Class != ClassShift && c.Class != ClassExtend
}

// enumParam builds a standalone parameter from an operand's value table.
func enumParam(c ClassifiedOperand, o AsmOperand, idx int, used, claimed map[string]bool) (Param, string) {
	spec, ok := enumSpecFrom(c)
	if !ok {
		return Param{}, "specifier " + o.Symbol + " is not a usable size table"
	}
	for _, f := range spec.Fields {
		if claimed[f] {
			return Param{}, "specifier " + o.Symbol + " shares a field with an earlier operand"
		}
		claimed[f] = true
	}
	name := paramName(o.Symbol, idx, used)
	used[name] = true
	return Param{
		Name: name, Class: ClassEnum, Enum: spec, RustType: spec.Name,
		Field: spec.Fields[0], Scale: 1,
		Default: c.Default, HasDefault: c.HasDefault, DefaultSymbol: c.DefaultSymbol,
	}, ""
}

// WidthCase is one register width a width-specifier position accepts.
type WidthCase struct {
	Symbol   string
	RustType string
	Bits     []string
}

// gprWidthType maps ARM's width-specifier spellings to the register type.
var gprWidthType = map[string]string{"W": "WReg", "X": "XReg"}

// widthCasesFrom reads a specifier table as a set of register widths.
//
// It reports false unless the table names each width exactly once. TBZ's <R> is
// a true selector: b5 = 0 means W and 1 means X, so each width fixes the field.
// ADD's extended-register <R> is not: it lists eight option values mapping onto
// W and X, because the width there is a consequence of the <extend> operand that
// owns the same field. Expanding that one would set the field from the register
// type and leave no way to ask for a different extension.
func widthCasesFrom(spec *ArrSpec) ([]WidthCase, bool) {
	out := make([]WidthCase, 0, len(spec.Rows))
	seen := map[string]bool{}
	for _, r := range spec.Rows {
		sym := strings.ToUpper(r.Symbol)
		rt, ok := gprWidthType[sym]
		if !ok || seen[sym] {
			return nil, false
		}
		seen[sym] = true
		out = append(out, WidthCase{Symbol: r.Symbol, RustType: rt, Bits: r.Bits})
	}
	return out, len(out) > 0
}

// ExpandWidthCases turns one parameter list into one per register width a
// width-specifier position accepts. Lists with no such position come back
// unchanged; more than one is not expanded, since the product would multiply
// impls without a caller ever needing it.
func ExpandWidthCases(params []Param) [][]Param {
	var idxs []int
	for i := range params {
		if len(params[i].WidthCases) > 0 {
			idxs = append(idxs, i)
		}
	}
	if len(idxs) == 0 {
		return [][]Param{params}
	}
	if len(idxs) > 1 {
		// Two width specifiers means the product of their widths. Expand the
		// first and recurse, so "<R><n>, <R><m>" yields all four combinations.
		head := idxs[0]
		var out [][]Param
		for _, v := range expandWidthAt(params, head) {
			rest := ExpandWidthCases(v)
			if rest == nil {
				return nil
			}
			out = append(out, rest...)
		}
		return out
	}
	return expandWidthAt(params, idxs[0])
}

// expandWidthAt produces one parameter list per register width at one position.
func expandWidthAt(params []Param, idx int) [][]Param {
	var out [][]Param
	for _, wc := range params[idx].WidthCases {
		variant := make([]Param, len(params))
		copy(variant, params)
		p := variant[idx]
		p.RustType = wc.RustType
		p.WidthFields = p.Arr.Fields
		p.WidthBits = wc.Bits
		p.WidthCases = nil
		p.Arr = nil
		p.Arrangement = false
		switch wc.RustType {
		case "WReg":
			p.Class = ClassGpr32
		case "XReg":
			p.Class = ClassGpr64
		}
		variant[idx] = p
		out = append(out, variant)
	}
	return out
}

// ArrSpec is an operand's arrangement table: the fields the arrangement spans
// and one row per legal spelling.
type ArrSpec struct {
	Fields []string
	Rows   []ArrRow
}

// ArrRow is one legal arrangement and the bits it sets, per field in order.
type ArrRow struct {
	Symbol string
	Bits   []string
}

// rustTypeFor maps an operand class to the crate's operand type.
var rustTypeFor = map[OperandClass]string{
	ClassGpr32:   "WReg",
	ClassGpr32Sp: "WSpReg",
	ClassGpr64:   "XReg",
	ClassGpr64Sp: "XSpReg",
	ClassSimdB:   "BReg",
	ClassSimdH:   "HReg",
	ClassSimdS:   "SReg",
	ClassSimdD:   "DReg",
	ClassSimdQ:   "QReg",
	ClassSimdVec: "VReg",
	ClassCond:    "Cond",
	ClassSysReg:  "SysReg",
	ClassShift:   "Shift",
	ClassExtend:  "Extend",
	ClassLabel:   "Label",
	ClassSveZ:    "ZReg",
	ClassSveP:    "PReg",
	ClassSvePN:   "PnReg",
	ClassSmeTile: "ZaTile",
	ClassFpImm:   "FpImm8",
}

// sizedTypeFor maps a register type to the variant that carries an arrangement.
var sizedTypeFor = map[string]string{
	"VReg":   "VecOp",
	"ZReg":   "ZOp",
	"PReg":   "POp",
	"PnReg":  "PnOp",
	"ZaTile": "ZaOp",
}

// registerClass reports whether a class denotes a register operand, whose value
// is a register number rather than an immediate.
func registerClass(c OperandClass) bool {
	switch c {
	case ClassGpr32, ClassGpr32Sp, ClassGpr64, ClassGpr64Sp,
		ClassSimdB, ClassSimdH, ClassSimdS, ClassSimdD, ClassSimdQ,
		ClassSimdVec, ClassSveZ, ClassSveP, ClassSvePN, ClassSmeTile:
		return true
	}
	return false
}

// TypedParams converts an encoding's asmtemplate operands into typed Rust
// parameters. ok is false when any operand cannot be typed or placed, in which
// case the encoding is reachable only through the field-level API.
func TypedParams(ops []AsmOperand) (params []Param, ok bool) {
	return TypedParamsWith(ops, nil)
}

// TypedParamsWith converts operands to Rust parameters using ARM's
// <explanations> entries for field binding and enumerated value tables.
func TypedParamsWith(ops []AsmOperand, exps map[string]AsmExplanation) (params []Param, ok bool) {
	params, reason := typedParams(ops, exps)
	return params, reason == ""
}

// TypedParamsReason is TypedParamsWith with the reason the operands could not be
// typed, so the gap between "typed" and "exact only" is attributable per
// encoding rather than reported as one bucket.
func TypedParamsReason(ops []AsmOperand, exps map[string]AsmExplanation) ([]Param, string) {
	return typedParams(ops, exps)
}

// TypedParamsFor is TypedParamsReason with the asmtemplate, which is needed to
// recognise ARM's alternation syntax.
func TypedParamsFor(asmTemplate string, ops []AsmOperand, exps map[string]AsmExplanation) ([]Param, string) {
	return typedParamsIn(asmTemplate, ops, exps)
}

func typedParams(ops []AsmOperand, exps map[string]AsmExplanation) (params []Param, reason string) {
	return typedParamsIn("", ops, exps)
}

func typedParamsIn(asmTemplate string, ops []AsmOperand, exps map[string]AsmExplanation) (params []Param, reason string) {
	alt := AlternativeOperands(asmTemplate)
	used := map[string]bool{}
	// claimed tracks which encoding fields an earlier operand already writes.
	// Two asm operands cannot both choose one field, so a later operand naming a
	// claimed field is derived from the earlier one — the second register of a
	// pair or list, or the far end of a slice range. ARM says so in prose for
	// some ("encoded as \"Zt\" plus 1 modulo 32") and leaves it implicit for
	// others, so the field collision is the reliable signal.
	claimed := map[string]bool{}
	// bySymbol records the operand symbols already given a parameter, so a
	// symbol written twice is recognised as one operand.
	bySymbol := map[string]bool{}
	// pending is a size specifier that appeared before the register it sizes,
	// as in "SADDLV <V><d>".
	var pending *ClassifiedOperand

	for i, o := range ops {
		if alt[i] {
			continue
		}
		c := ClassifyOperandWith(o, exps[o.Symbol])

		if c.Class == ClassArrangement {
			// A specifier written immediately before the next operand, with no
			// separator, sizes that operand: "<V><d>". Written after a register
			// and a dot, it sizes the register before it: "<Vn>.<T>".
			if i+1 < len(ops) && ops[i+1].Prefix == "" {
				spec := c
				pending = &spec
				continue
			}
			n := len(params)
			// ARM repeats the specifier on every member of a register list —
			// "ST4 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }". The members
			// after the first are derived and contribute no parameter, so their
			// copies of the specifier land back on the register already sized.
			// They say the same thing, so there is nothing to do.
			if n > 0 && params[n-1].Arr != nil && params[n-1].ArrSymbol == o.Symbol {
				continue
			}
			if n > 0 && params[n-1].Arr == nil && registerClass(params[n-1].Class) {
				if !attachSpecifier(&params[n-1], c, claimed) {
					return nil, "specifier " + o.Symbol + " is not a usable size table"
				}
				continue
			}
			// Nothing to size: ARM writes the element size on a literal, as in
			// "SMLALL ZA.<T>[...]" where ZA is not an operand. The specifier is
			// then an operand in its own right, spelled from its own table.
			prm, why := enumParam(c, o, i, used, claimed)
			if why != "" {
				return nil, why
			}
			params = append(params, prm)
			continue
		}
		if c.Class == ClassDerived {
			continue
		}
		if c.Class == ClassUnsupported {
			return nil, "operand " + o.Symbol + " has no known type"
		}
		if c.Algorithmic {
			return nil, "operand " + o.Symbol + " is computed from its fields"
		}
		if c.ResolvedField == "" {
			return nil, "operand " + o.Symbol + " names no field"
		}
		fields := c.Fields
		if len(fields) == 0 {
			fields = []string{c.ResolvedField}
		}
		// Sharing a field with an earlier operand is not on its own a reason to
		// drop this one. UMOV's <Ts> and <index> both name imm5 — the specifier
		// picks which slice of it the index occupies — and treating the index as
		// a consequence of the specifier would silently encode index 0 with no
		// way to change it.
		//
		// It is a reason when ARM also describes the operand by its position in
		// a group: the second register of a list is written out but not encoded,
		// because the first one fixes it.
		if anyClaimed(fields, claimed) {
			// The same symbol twice is the same operand, not two. ARM writes
			// destructive instructions with the destination repeated as the first
			// source — "ADD <Zdn>.<T>, <Pg>/M, <Zdn>.<T>, <Zm>.<T>" — and one
			// parameter fills both positions.
			if bySymbol[o.Symbol] {
				continue
			}
			// A later list member can reuse the first member's fields while
			// inserting a different literal slice: T:'1':Zt follows
			// T:'0':Zt.  The literal fixes its position; accepting a second
			// parameter would let callers request an inconsistent list.
			literalMember := false
			for _, part := range c.Split {
				if _, ok := LiteralBits(part); ok {
					literalMember = true
					break
				}
			}
			if literalMember {
				continue
			}
			if OrdinalMember(exps[o.Symbol].Prose + " " + o.Hover) {
				continue
			}
			return nil, "operand " + o.Symbol + " shares a field with an earlier operand"
		}

		prm := Param{
			Field: c.ResolvedField, Class: c.Class,
			Lo: c.Lo, Hi: c.Hi, HasRange: c.HasRange, Scale: c.Scale,
			Default: c.Default, HasDefault: c.HasDefault,
			DefaultSymbol: c.DefaultSymbol,
			Mirrors:       append([]string(nil), c.Mirrors...),
			InvertLSB:     c.InvertLSB,
			RegLo:         c.RegLo, RegHi: c.RegHi, HasRegRange: c.HasRegRange,
			RegMultiple: c.RegMultiple,
			RegRanges:   append([]RegRange(nil), c.RegRanges...),
			Bias:        c.Bias, Negate: c.Negate,
		}
		if m := operandSelectorRE.FindStringSubmatch(exps[o.Symbol].Prose + " " + o.Hover); m != nil {
			bit, err := strconv.Atoi(m[2])
			if err == nil {
				prm.SelectorField = m[1]
				prm.SelectorBit = bit
				if m[3] == "1" {
					prm.SelectorValue = 1
				}
				prm.HasSelector = true
			}
		}
		if c.Class == ClassExtend {
			prm.Choices = exactValueChoices(c.Explanation.Values)
		}
		// A value table maps whole bit combinations to spellings, so it needs no
		// concatenation order even when it spans several fields. Test it before
		// requiring one.
		if tableTyped(c) {
			spec, ok := enumSpecFrom(c)
			if !ok {
				return nil, "operand " + o.Symbol + " has an unusable value table"
			}
			prm.Class = ClassEnum
			prm.Enum = spec
			prm.RustType = spec.Name
		} else {
			if len(c.Split) > 1 {
				prm.Split = c.Split
			} else if len(fields) > 1 {
				// Multi-field with no stated concatenation order: not placeable.
				return nil, "operand " + o.Symbol + " spans " + strings.Join(fields, ":") + " with no stated order"
			}
			rt, known := rustTypeFor[c.Class]
			if !known {
				if c.Class != ClassImm {
					return nil, "operand " + o.Symbol + " has class " + string(c.Class) + " with no Rust type"
				}
				rt = immRustType(c)
			}
			prm.RustType = rt
		}

		prm.Name = paramName(o.Symbol, i, used)
		used[prm.Name] = true
		bySymbol[o.Symbol] = true
		for _, f := range fields {
			claimed[f] = true
		}
		params = append(params, prm)

		if pending != nil {
			if !attachSpecifier(&params[len(params)-1], *pending, claimed) {
				return nil, "specifier " + pending.Symbol + " is not a usable size table"
			}
			pending = nil
		}
	}
	if pending != nil {
		return nil, "specifier " + pending.Symbol + " sizes nothing"
	}
	// No operands at all is legitimate (NOP, RET without Xn): still typed.
	return params, ""
}

func exactValueChoices(rows []SymbolValue) []ValueChoice {
	var out []ValueChoice
	for _, row := range rows {
		if row.Reserved() || len(row.Bits) != 1 || row.Bits[0] == "" ||
			strings.ContainsAny(row.Bits[0], "xXzZN") {
			continue
		}
		v, err := strconv.ParseUint(row.Bits[0], 2, 32)
		if err == nil {
			out = append(out, ValueChoice{Symbol: row.Symbol, Value: uint32(v)})
		}
	}
	return out
}

// ApplySelectorConstraints intersects shared operand tables with conditions on
// parenthesized alternatives.  In "[Xn, (Wm|Xm){, extend}]", Wm fixes
// option<0> to zero, so LSL/SXTX are not legal rows for that concrete form.
func ApplySelectorConstraints(params []Param) {
	for _, selector := range params {
		if !selector.HasSelector {
			continue
		}
		for i := range params {
			p := &params[i]
			if p.Field != selector.SelectorField || len(p.Choices) == 0 {
				continue
			}
			filtered := p.Choices[:0]
			for _, choice := range p.Choices {
				if (choice.Value>>uint(selector.SelectorBit))&1 == selector.SelectorValue {
					filtered = append(filtered, choice)
				}
			}
			p.Choices = filtered
			if p.DefaultSymbol == "" {
				continue
			}
			defaultLegal := false
			for _, choice := range filtered {
				if strings.EqualFold(choice.Symbol, p.DefaultSymbol) {
					p.Default, p.HasDefault = int64(choice.Value), true
					defaultLegal = true
					break
				}
			}
			if !defaultLegal {
				// The braces describe the union grammar.  This concrete
				// alternative cannot omit the operand when its documented
				// default selects the other alternative.
				p.Optional = false
				p.HasDefault = false
			}
		}
	}
}

// attachSpecifier binds a size specifier's value table to a register parameter.
func attachSpecifier(p *Param, c ClassifiedOperand, claimed map[string]bool) bool {
	spec, ok := arrSpecFrom(c)
	if !ok {
		// A specifier with no usable table would silently encode as zero.
		return false
	}
	if p.Arr != nil {
		// Two specifiers on one operand cannot both drive it.
		return false
	}
	if !registerClass(p.Class) {
		return false
	}
	p.Arrangement = true
	p.Arr = spec
	p.ArrSymbol = c.Symbol
	switch {
	case sizedTypeFor[p.RustType] != "":
		p.RustType = sizedTypeFor[p.RustType]
	case p.Class == ClassSimdVec:
		// A SIMD&FP register written as a bare number takes its width from the
		// specifier, so it becomes a sized vector operand.
		p.RustType = "VecOp"
	default:
		// A general-purpose register whose width ARM writes as a specifier: the
		// form expands into one impl per width instead.
		cases, ok := widthCasesFrom(spec)
		if !ok {
			return false
		}
		p.WidthCases = cases
	}
	for _, f := range spec.Fields {
		claimed[f] = true
	}
	return true
}

func anyClaimed(fields []string, claimed map[string]bool) bool {
	for _, f := range fields {
		if claimed[f] {
			return true
		}
	}
	return false
}

// immRustType picks the integer type covering ARM's stated range.
func immRustType(c ClassifiedOperand) string {
	if c.HasRange && c.Lo < 0 {
		return "i32"
	}
	if !c.HasRange {
		return "u32"
	}
	return "u32"
}

// paramName turns an ARM operand symbol into a Rust identifier.
func paramName(symbol string, idx int, used map[string]bool) string {
	s := strings.Trim(symbol, "<>")
	// "<Xn|SP>" -> xn ; "<Wd>" -> wd ; "<pimm>" -> pimm
	if i := strings.IndexByte(s, '|'); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		name = fmt.Sprintf("op%d", idx)
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "n" + name
	}
	if isRustKeyword(name) {
		name += "_"
	}
	for used[name] {
		name += "_"
	}
	return name
}

func isRustKeyword(s string) bool {
	switch s {
	case "as", "break", "const", "continue", "crate", "else", "enum", "extern",
		"false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
		"move", "mut", "pub", "ref", "return", "self", "static", "struct",
		"super", "trait", "true", "type", "unsafe", "use", "where", "while",
		"abstract", "become", "box", "do", "final", "macro", "override", "priv",
		"typeof", "unsized", "virtual", "yield", "async", "await", "dyn", "try":
		return true
	}
	return false
}

// AsmMnemonic extracts the assembler mnemonic from an asmtemplate.
//
// The registry's Mnemonic field is a *group* name — CRC32CB, CRC32CH and
// CRC32CW all carry "CRC32C", and LDUMINH/LDUMINLH/LDUMINAH all carry
// "LDUMINH". Naming methods from it would merge distinct instructions. The
// asmtemplate's leading literal is the actual assembler spelling.
func AsmMnemonic(asmTemplate string) string {
	t := strings.TrimSpace(asmTemplate)
	if t == "" {
		return ""
	}
	// Stop at the first operand placeholder or separator.
	if i := strings.IndexAny(t, " \t<,["); i >= 0 {
		t = t[:i]
	}
	// "ADDHN{" -> ADDHN: the {2} variant is selected by the operand
	// arrangement, not by a different method.
	if i := strings.IndexByte(t, '{'); i >= 0 {
		t = t[:i]
	}
	// "B." comes from "B.<cond>", where ARM spells the condition as part of the
	// mnemonic. Name it b_cond: plain B is a different instruction and must keep
	// the bare name.
	if strings.HasSuffix(t, ".") {
		return strings.TrimSuffix(t, ".") + "_cond"
	}
	return t
}

// MethodName maps an assembler mnemonic to a snake_case Rust method name.
func MethodName(mnemonic string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(mnemonic) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return ""
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "i" + out
	}
	if isRustKeyword(out) {
		out += "_"
	}
	return out
}

// arrSpecFrom builds an arrangement table from ARM's value table. RESERVED rows
// are dropped: those bit combinations are unallocated, not spellings.
func arrSpecFrom(c ClassifiedOperand) (*ArrSpec, bool) {
	rows, fields, ok := tableRows(c)
	if !ok {
		return nil, false
	}
	return &ArrSpec{Fields: fields, Rows: rows}, true
}

// enumSpecFrom builds a generated Rust enum from ARM's value table.
func enumSpecFrom(c ClassifiedOperand) (*EnumSpec, bool) {
	rows, fields, ok := tableRows(c)
	if !ok {
		return nil, false
	}
	name := enumTypeName(c)
	if name == "" {
		return nil, false
	}
	return &EnumSpec{Name: name, Fields: fields, Rows: rows}, true
}

// tableRows extracts the fully-determined rows of an operand's value table.
func tableRows(c ClassifiedOperand) ([]ArrRow, []string, bool) {
	exp := c.Explanation
	fields := tableFieldNames(exp)
	if len(fields) == 0 || len(exp.Values) == 0 {
		return nil, nil, false
	}
	var rows []ArrRow
	seen := map[string]bool{}
	// A table row may leave bits unconstrained — DUP's "xxxx1 0" selects 8B for
	// any imm5 ending in 1. Encoding needs one representative, and zero is the
	// canonical choice, but only when it does not land on another row's bits:
	// two spellings encoding alike would make one of them unreachable.
	takenBits := map[string]string{}
	for _, v := range exp.Values {
		if v.Reserved() || len(v.Bits) != len(fields) || seen[v.Symbol] {
			continue
		}
		bits := make([]string, len(v.Bits))
		empty := false
		for i, b := range v.Bits {
			if b == "" {
				empty = true
				break
			}
			bits[i] = strings.Map(func(r rune) rune {
				if r == 'x' || r == 'X' {
					return '0'
				}
				return r
			}, b)
		}
		if empty {
			continue
		}
		key := strings.Join(bits, ":")
		if other, dup := takenBits[key]; dup && other != v.Symbol {
			continue
		}
		takenBits[key] = v.Symbol
		seen[v.Symbol] = true
		rows = append(rows, ArrRow{Symbol: v.Symbol, Bits: bits})
	}
	if len(rows) == 0 {
		return nil, nil, false
	}
	return rows, fields, true
}

// enumTypeName names the generated enum after ARM's operand-class link id, so
// every instruction using the same operand class shares one type.
func enumTypeName(c ClassifiedOperand) string {
	src := c.Link
	if src == "" {
		src = strings.Trim(c.Symbol, "<>")
	}
	// "prfop", "pattern", "sve_pattern__2", "cond_option" -> Prfop, Pattern.
	src = trimLinkSuffix(src)
	var b strings.Builder
	upper := true
	for _, r := range src {
		switch {
		case r == '_' || r == '-':
			upper = true
		case r >= 'a' && r <= 'z':
			if upper {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			upper = false
		case r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			upper = false
		}
	}
	out := b.String()
	if out == "" || out[0] >= '0' && out[0] <= '9' {
		return ""
	}
	return out
}

// trimLinkSuffix drops ARM's disambiguating suffixes from a link id so
// "sve_pattern__3" and "sve_pattern" name one type.
func trimLinkSuffix(s string) string {
	for {
		if i := strings.LastIndex(s, "__"); i > 0 && allDigits(s[i+2:]) {
			s = s[:i]
			continue
		}
		break
	}
	return strings.TrimSuffix(s, "_option")
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

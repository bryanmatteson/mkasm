package arm

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// The disassembly print model.
//
// The typed assembler surface (rust_asm_model.go) answers "which bits does this
// operand set"; printing needs the inverse, "what does this operand read as".
// The two are not the same question. An operand the assembler declines to type
// — a register whose number is fixed by another operand, an arrangement that is
// a modifier rather than a parameter — still prints, and prints from the same
// ARM data. So this model is built beside that one rather than derived from it,
// and shares only the field-placement helpers (lookupField, freeSubRange).
//
// A form is emitted only when every one of its operands resolves. Printing an
// operand whose encoding relation is not understood would produce text that
// reads like assembly and assembles to a different instruction, which is worse
// than declining: DisasmSurface.Skipped records what was declined and why.

// DisasmKind is how an operand slot turns bits into text.
type DisasmKind string

const (
	// DisasmReg prints a register name from a bank chosen by the operand class.
	DisasmReg DisasmKind = "reg"
	// DisasmNum prints a number, after undoing the encoding's scale/bias/negate.
	DisasmNum DisasmKind = "num"
	// DisasmFpImm prints ARM's VFPExpandImm 8-bit constant.
	DisasmFpImm DisasmKind = "fpimm8"
	// DisasmSysReg prints the generic architectural S<op0>_<op1>_C... name.
	DisasmSysReg DisasmKind = "sysreg"
	// DisasmTable prints the assembler spelling ARM's value table gives for the
	// bits — a condition code, an element arrangement, a prefetch operation.
	DisasmTable DisasmKind = "table"
	// DisasmDerived prints a register whose number follows from another
	// operand's field: the second of a pair, the second of a list.
	DisasmDerived DisasmKind = "derived"
	// DisasmFormula evaluates one of ARM's small decode-table expressions, such
	// as 64-UInt(immh:immb) or UInt(H:L:M).
	DisasmFormula DisasmKind = "formula"
	// DisasmLogicalImm inverts A64's N:immr:imms logical-bitmask encoding.
	DisasmLogicalImm DisasmKind = "logical-imm"
	// DisasmBitfieldWidth inverts a BFM/SBFM/UBFM alias width.
	DisasmBitfieldWidth DisasmKind = "bitfield-width"
	// DisasmByteMaskImm expands MOVI's a:h selector bits into eight 00/FF bytes.
	DisasmByteMaskImm DisasmKind = "byte-mask-imm"
	// DisasmMoveWideImm reconstructs MOV's shifted MOVZ/MOVN alias immediate.
	DisasmMoveWideImm DisasmKind = "move-wide-imm"
	// DisasmLiteral prints an operand whose value ARM states directly in prose,
	// such as the fixed H destination-width specifier on half reductions.
	DisasmLiteral DisasmKind = "literal"
	// DisasmElementIndex removes the unary element-size marker from packed
	// index fields such as imm2:tsz and i1:tszh:tszl.
	DisasmElementIndex DisasmKind = "element-index"
	// DisasmTileMask expands ZERO's imm8 mask to a legal list of ZA*.D names.
	DisasmTileMask DisasmKind = "tile-mask"
)

// DisasmSurface is the whole print model: one form per printable encoding.
type DisasmSurface struct {
	Forms []DisasmForm
	// Skipped names the encodings that have no printable form, with the operand
	// and reason that stopped them. It is a census, not a log — a bar can be
	// asserted against it.
	Skipped []DisasmSkip
}

// DisasmSkip is one encoding that cannot be printed, and why.
type DisasmSkip struct {
	EncodingID string
	Symbol     string
	Reason     string
}

// DisasmForm is how one encoding prints.
type DisasmForm struct {
	EncodingID string
	Mnemonic   string
	Parts      []DisasmPart

	// ConstraintMask/Value and EqualFields are the alias predicate that selects
	// this spelling. They are part of decoding, not merely sample-generation
	// metadata: a word that does not satisfy them must not print as the alias.
	ConstraintMask  uint32
	ConstraintValue uint32
	EqualFields     []DisasmFieldEquality
	UnequalFields   []DisasmFieldInequality
	OneHotMasks     []uint32
	Forbidden       []DisasmForbidden
	// SVEMoveMaskField carries the imm13 selected by ARM's
	// SVEMoveMaskPreferred alias predicate.
	SVEMoveMaskField            *BitPart
	MoveWideZeroGuard           *DisasmMoveWideZeroGuard
	LogicalMoveGuard            *DisasmLogicalMoveGuard
	GroupParent                 map[int]int
	RequiredGroups              map[int]bool
	PreferOmittedSystemRegister bool
}

type DisasmMoveWideZeroGuard struct {
	Imm16 BitPart
	HW    BitPart
}

type DisasmLogicalMoveGuard struct {
	SF, N, Imms, Immr BitPart
}

// DisasmForbidden is one conjunction of field values that Decode classifies
// as UNDEFINED. Mutable contains the non-fixed bits a legal representative can
// change without leaving the encoding.
type DisasmForbidden struct {
	Mask, Value uint32
	Mutable     uint32
}

// DisasmFieldEquality says two complete encoding fields must have the same
// value for an alias spelling to apply.
type DisasmFieldEquality struct {
	LeftStart, LeftEnd   int
	RightStart, RightEnd int
	// Add is applied to the left value modulo the field width.
	Add uint32
}

// DisasmFieldInequality records an architectural register-overlap constraint.
// RightMutable is the portion of the right field that a representative-word
// solver may alter without changing fixed opcode bits.
type DisasmFieldInequality struct {
	LeftStart, LeftEnd   int
	RightStart, RightEnd int
	RightMutable         uint32
}

// DisasmPart is one piece of an instruction's printed text.
type DisasmPart struct {
	// Literal is emitted verbatim when Op is nil, spacing included.
	Literal string
	Op      *DisasmOperand
	// Group is the optional-brace group this part belongs to, 0 for parts that
	// always print. ARM writes an omittable operand and its leading separator
	// inside one brace group — "[<Xn|SP>{, #<pimm>}]" — so the separator must be
	// dropped with the operand it introduces, never on its own.
	Group int
}

// DisasmOperand is one operand slot, resolved to the bits it reads from.
type DisasmOperand struct {
	Symbol string
	Class  OperandClass
	Kind   DisasmKind

	// Parts are the bit runs holding the value, most significant first. A
	// single-field operand has exactly one.
	Parts []BitPart
	// Scale, Bias and Negate undo the encoding relation: the printed value is
	// Negate-raw when Negate is set, otherwise raw+Bias, then times Scale.
	Scale  int64
	Bias   int64
	Negate int64
	// RawMul applies after decoding signedness/bias and before Scale. A PAC
	// immediate label is PC-(UInt(imm16)*4), represented by RawMul=-1.
	RawMul       int64
	Signed       bool
	RegRanges    []RegRange
	Lo, Hi       int64
	HasRange     bool
	RegLo, RegHi int64
	HasRegRange  bool
	RegMultiple  int64
	// NumPrefix is assembler syntax attached to a numeric field, such as the
	// architectural control-register names C0-C15.
	NumPrefix string
	// NumConstant is the written value for a presence bit. Register-offset
	// byte accesses encode S=0 when the optional "#0" is omitted and S=1 when
	// that same value is present; S is not the numeric shift amount.
	NumConstant    int64
	HasNumConstant bool
	// WhenMask/Value select one operand from ARM's parenthesized alternative
	// syntax, such as (Wm|Xm) selected by option<0>.
	WhenMask  uint32
	WhenValue uint32

	// Cols and Rows carry ARM's value table for DisasmTable operands. Each row
	// holds one bit pattern per column, in the table's own column order, with
	// 'x' as a don't-care.
	Cols []BitPart
	Rows []DisasmRow
	// Formulas aligns with Rows for a formula table. The row selects an
	// expression whose Parts are concatenated most-significant first.
	Formulas []DisasmFormulaExpr
	// FormulaIgnoredZero aligns with formula rows and identifies the portion of
	// their parent fields ARM explicitly says is ignored and should be zero.
	FormulaIgnoredZero []uint32
	// IgnoredShouldZero records ARM's explicit canonical-encoding instruction
	// for selector don't-cares.
	IgnoredShouldZero bool
	MoveWideInvert    bool
	LogicalInvert     bool
	// DataSize bounds coupled bitfield alias operands. In a 32-bit extract,
	// imms[5] is unallocated even when imms-immr+1 happens to look like a
	// plausible width.
	DataSize int64
	Literal  string
	// IndexSizeParts is the number of trailing Parts that form the unary size
	// selector for DisasmElementIndex.
	IndexSizeParts int
	// Xor is applied to the encoded selector before its table lookup. Alias
	// operands such as <invcond> store cond<0> inverted while printing the
	// caller-facing condition.
	Xor uint64

	// Default is the encoded value that means "omitted". An optional group whose
	// operands all read as their default is not printed.
	Default    int64
	HasDefault bool

	// Mul, Add and Mod carry the derivation of a DisasmDerived operand, whose
	// value is (Parts × Mul + Add) mod Mod, or the constant Add when it has no
	// Parts.
	Mul, Add, Mod int64
}

type DisasmFormulaExpr struct {
	Parts     []BitPart
	RawMul    int64
	Add       int64
	Negate    int64
	SizeParts int
	ESizeBase int64
	ESizeMul  int64
}

// DisasmRow is one row of an operand's value table.
type DisasmRow struct {
	Bits   []string
	Symbol string
}

// BuildDisasmSurface projects resolved IR into the print model.
func BuildDisasmSurface(instrs []*ir.InstructionIR, load func(*ir.InstructionIR) *ParsedIForm) *DisasmSurface {
	s := &DisasmSurface{}
	for _, instr := range instrs {
		if instr == nil || instr.EncodingID == "" {
			continue
		}
		p := load(instr)
		if p == nil || p.AsmTemplate == "" {
			s.Skipped = append(s.Skipped, DisasmSkip{instr.EncodingID, "", "no asmtemplate"})
			continue
		}
		form, skip := buildDisasmForm(instr, p)
		if skip != nil {
			s.Skipped = append(s.Skipped, *skip)
			continue
		}
		s.Forms = append(s.Forms, *form)
	}
	sort.Slice(s.Forms, func(i, j int) bool { return s.Forms[i].EncodingID < s.Forms[j].EncodingID })
	sort.Slice(s.Skipped, func(i, j int) bool { return s.Skipped[i].EncodingID < s.Skipped[j].EncodingID })
	return s
}

func buildDisasmForm(instr *ir.InstructionIR, p *ParsedIForm) (*DisasmForm, *DisasmSkip) {
	byName := make(map[string]ir.BitField, len(instr.Encoding.Fields))
	for _, f := range instr.Encoding.Fields {
		if f.Name != "" {
			byName[f.Name] = f
		}
	}
	fixedMask, fixedValue := ir.FixedBitsFromPattern(instr.BitPattern)
	exps := ExplanationsFor(p.Explanations, instr.EncodingID)
	negates := decodeFieldNegates(p.Pseudocode)
	regRestrictions := decodeRegisterRestrictions(p.Pseudocode)
	regSuccessors := decodeRegisterSuccessors(p.Pseudocode)

	form := &DisasmForm{
		EncodingID: instr.EncodingID, Mnemonic: instr.AsmMnemonic,
		GroupParent:                 map[int]int{},
		RequiredGroups:              map[int]bool{},
		PreferOmittedSystemRegister: systemOperationPrefersOmittedRegister(p.AliasCond),
	}
	form.Forbidden = decodeForbiddenConstraints(p.Pseudocode, byName, fixedMask)
	memoryForbidden, memoryUnequal := decodeMemoryOperationRegisterConstraints(
		p.Pseudocode, byName, fixedMask,
	)
	form.Forbidden = append(form.Forbidden, memoryForbidden...)
	form.UnequalFields = append(form.UnequalFields, memoryUnequal...)
	if err := addDisasmAliasConstraints(form, p.AliasCond, byName); err != nil {
		return nil, &DisasmSkip{instr.EncodingID, "", err.Error()}
	}
	depth := 0
	group, nextGroup := 0, 0
	// A brace group is optional only when it opens with a separator. ARM spells a
	// register list in braces too — "LD1 { <Vt>.<T> }, [<Xn|SP>]" — and dropping
	// its first register would delete a required operand.
	optional := map[int]bool{}
	parentGroup := map[int]int{}
	seenOperandField := map[string]bool{}

	// Braces delimit the template, they are not part of the syntax: an assembler
	// is given "add x0, x1, x2" or "add x0, x1, x2, lsl #4", never the braces
	// ARM writes around the part that may be left out.
	addLiteral := func(text string) {
		var lit strings.Builder
		flush := func() {
			if lit.Len() > 0 {
				form.Parts = append(form.Parts, DisasmPart{Literal: lit.String(), Group: group})
				lit.Reset()
			}
		}
		for i := 0; i < len(text); i++ {
			switch text[i] {
			case '{':
				flush()
				depth++
				nextGroup++
				// ARM's literal register-list syntax always opens "{ " with a
				// space. Documentation-only optional groups are compact:
				// "{2}", "{, #<imm>}", "{#<imm>}". A brace at the end of this
				// text chunk is likewise followed by an operand anchor, so it
				// is the compact optional form.
				optional[depth] = i+1 >= len(text) || text[i+1] != ' '
				if optional[depth] {
					parentGroup[depth] = group
					form.GroupParent[nextGroup] = group
					group = nextGroup
				} else {
					// Braces around a register list are real assembler syntax,
					// unlike separator-led braces that only document an
					// optional continuation.
					form.Parts = append(form.Parts, DisasmPart{Literal: "{", Group: group})
				}
			case '}':
				flush()
				if depth > 0 {
					if optional[depth] {
						group = parentGroup[depth]
					} else {
						form.Parts = append(form.Parts, DisasmPart{Literal: "}", Group: group})
					}
					delete(optional, depth)
					delete(parentGroup, depth)
					depth--
				}
			default:
				lit.WriteByte(text[i])
			}
		}
		flush()
	}

	for _, ao := range p.AsmOperands {
		addLiteral(ao.Prefix)
		c := ClassifyOperandWith(ao, exps[ao.Symbol])
		if restriction, ok := regRestrictions[c.ResolvedField]; ok {
			c.RegMultiple = restriction.Multiple
			if restriction.HasRange {
				c.RegLo, c.RegHi, c.HasRegRange =
					restriction.Lo, restriction.Hi, true
			}
		}
		if arity := systemOperationRegisterArity(p.AliasCond); arity != 0 &&
			c.ResolvedField == "Rt" && registerClass(c.Class) {
			c.HasDefault = false
			if arity == 2 {
				c.RegMultiple = 2
				c.RegLo, c.RegHi, c.HasRegRange = 0, 30, true
			}
			if group != 0 {
				form.RequiredGroups[group] = true
			}
		}
		prose := exps[ao.Symbol].Prose + " " + ao.Hover
		if offset, ordinal := ordinalMemberOffset(prose); ordinal && c.Class != ClassDerived &&
			len(c.Split) == 0 && len(c.Fields) == 1 && c.ResolvedField != "" && seenOperandField[c.ResolvedField] {
			if successor, explicit := regSuccessors[c.ResolvedField]; OrdinalMember(prose) || explicit {
				if explicit {
					offset = successor.Add
				} else {
					successor = DerivedRel{Field: c.ResolvedField, Mul: 1, Add: offset, Mod: 32}
				}
				c.Class = ClassDerived
				c.Derived = &successor
			}
		}
		if n, ok := negates[c.ResolvedField]; ok {
			c.Negate = n
			c.Bias = 0
		}
		for _, m := range aliasNextEqRE.FindAllStringSubmatch(p.AliasCond, -1) {
			if right, ok := lookupField(m[2], byName); ok && c.ResolvedField == right.Name {
				width := right.End - right.Start + 1
				if c.HasRange && c.Lo == 0 {
					if n, ok := exactPowerOfTwo(c.Hi + 1); ok {
						width = n
					}
				}
				c.Negate = int64(1) << uint(width)
				c.Bias = 0
			}
		}
		op, err := disasmOperandWithContext(
			c, byName, fixedMask, fixedValue, p.Pseudocode, p.AliasCond,
		)
		if err != nil {
			return nil, &DisasmSkip{instr.EncodingID, ao.Symbol, err.Error()}
		}
		if err := applyDisasmOperandCondition(op, prose, byName); err != nil {
			return nil, &DisasmSkip{instr.EncodingID, ao.Symbol, err.Error()}
		}
		if op.Kind == DisasmLogicalImm &&
			equivalentOperandInverts(ao, p.EquivalentOperands, p.EquivalentSuffix) {
			op.LogicalInvert = true
		}
		form.Parts = append(form.Parts, DisasmPart{Op: op, Group: group})
		if c.ResolvedField != "" && c.Class != ClassDerived {
			seenOperandField[c.ResolvedField] = true
		}
	}
	addLiteral(p.AsmSuffix)
	if err := addEquivalentOperandDefaults(
		form, p.EquivalentOperands, byName, seenOperandField,
	); err != nil {
		return nil, &DisasmSkip{instr.EncodingID, "", err.Error()}
	}

	if len(p.AsmOperands) == 0 {
		// A bare mnemonic — CLREX, ISB, NOP. The template is the whole text.
		form.Parts = []DisasmPart{{Literal: p.AsmTemplate}}
	}
	return form, nil
}

// systemOperationRegisterArity decodes register requirements carried by the
// shared-pseudocode category in an alias condition. The generic SYS/SYSP
// templates expose optional registers because the base instruction permits
// omission; a selected category can narrow that syntax. Sys_GIC consumes one
// Xt, while SysOp128 selects a consecutive pair.
func systemOperationRegisterArity(aliasCond string) int {
	switch {
	case strings.Contains(aliasCond, "SysOp128("):
		return 2
	case strings.Contains(aliasCond, "== Sys_GIC"):
		return 1
	default:
		return 0
	}
}

func systemOperationPrefersOmittedRegister(aliasCond string) bool {
	return strings.Contains(aliasCond, "== Sys_IC") ||
		strings.Contains(aliasCond, "== Sys_TLBI")
}

func equivalentOperandInverts(
	visible AsmOperand,
	equivalent []AsmOperand,
	suffix string,
) bool {
	if !strings.HasPrefix(strings.TrimSpace(suffix), "- 1)") {
		return false
	}
	for _, operand := range equivalent {
		same := operand.Link != "" && operand.Link == visible.Link ||
			operand.Symbol != "" && operand.Symbol == visible.Symbol
		if same && strings.HasSuffix(strings.TrimSpace(operand.Prefix), "#(-") {
			return true
		}
	}
	return false
}

func addEquivalentOperandDefaults(
	form *DisasmForm,
	operands []AsmOperand,
	byName map[string]ir.BitField,
	claimed map[string]bool,
) error {
	for _, operand := range operands {
		classified := ClassifyOperand(operand)
		if !classified.HasDefault || classified.ResolvedField == "" ||
			classified.Default < 0 || claimed[classified.ResolvedField] {
			continue
		}
		field, ok := lookupField(classified.ResolvedField, byName)
		if !ok {
			return fmt.Errorf("equivalent default field %q absent from encoding", classified.ResolvedField)
		}
		width := field.End - field.Start + 1
		if width <= 0 || width > 31 ||
			uint64(classified.Default) >= uint64(1)<<uint(width) {
			return fmt.Errorf("equivalent default for %s does not fit %s",
				operand.Symbol, classified.ResolvedField)
		}
		mask := fieldRangeMask(field.Start, field.End)
		form.ConstraintMask |= mask
		form.ConstraintValue = form.ConstraintValue&^mask |
			uint32(classified.Default)<<uint(field.Start)
	}
	return nil
}

func exactPowerOfTwo(v int64) (int, bool) {
	if v <= 0 || v&(v-1) != 0 {
		return 0, false
	}
	width := 0
	for v > 1 {
		v >>= 1
		width++
	}
	return width, true
}

var operandSelectorRE = regexp.MustCompile(`(?i)\b([A-Za-z_][A-Za-z0-9_]*)<(\d+)>(?:[^.]{0,80})\b(?:is )?set to ([01])`)

func applyDisasmOperandCondition(op *DisasmOperand, prose string, byName map[string]ir.BitField) error {
	m := operandSelectorRE.FindStringSubmatch(prose)
	if m == nil {
		return nil
	}
	bf, ok := lookupField(m[1], byName)
	if !ok {
		return fmt.Errorf("alternative selector field %q absent from encoding", m[1])
	}
	bit, err := strconv.Atoi(m[2])
	if err != nil || bit < 0 || bit > bf.End-bf.Start {
		return fmt.Errorf("alternative selector %s<%s> is outside field", m[1], m[2])
	}
	op.WhenMask = uint32(1) << uint(bf.Start+bit)
	if m[3] == "1" {
		op.WhenValue = op.WhenMask
	}
	return nil
}

// addDisasmAliasConstraints decodes the mechanically checkable portion of
// ARM's alias condition. These are the same field equalities and bit literals
// that make hidden assembler placements in applyAliasConstraints.
func addDisasmAliasConstraints(form *DisasmForm, cond string, byName map[string]ir.BitField) error {
	if strings.Contains(cond, "IsZero(imm16)") && strings.Contains(cond, "hw != '00'") {
		imm16, iok := lookupField("imm16", byName)
		hw, hok := lookupField("hw", byName)
		if !iok || !hok {
			return fmt.Errorf("move-wide zero predicate requires imm16 and hw")
		}
		part := func(field ir.BitField) BitPart {
			return BitPart{
				Field: field.Name, Start: field.Start, End: field.End,
				Width: field.End - field.Start + 1,
			}
		}
		form.MoveWideZeroGuard = &DisasmMoveWideZeroGuard{
			Imm16: part(imm16),
			HW:    part(hw),
		}
	}
	if strings.Contains(cond, "!MoveWidePreferred") {
		var fields [4]ir.BitField
		for i, name := range []string{"sf", "N", "imms", "immr"} {
			field, ok := lookupField(name, byName)
			if !ok {
				return fmt.Errorf("MoveWidePreferred field %q absent from encoding", name)
			}
			fields[i] = field
		}
		part := func(field ir.BitField) BitPart {
			return BitPart{
				Field: field.Name, Start: field.Start, End: field.End,
				Width: field.End - field.Start + 1,
			}
		}
		form.LogicalMoveGuard = &DisasmLogicalMoveGuard{
			SF: part(fields[0]), N: part(fields[1]),
			Imms: part(fields[2]), Immr: part(fields[3]),
		}
	}
	if strings.Contains(cond, "SVEMoveMaskPreferred") {
		field, ok := lookupField("imm13", byName)
		if !ok || field.End-field.Start+1 != 13 {
			return fmt.Errorf("SVEMoveMaskPreferred requires a 13-bit imm13 field")
		}
		form.SVEMoveMaskField = &BitPart{
			Field: field.Name, Start: field.Start, End: field.End, Width: 13,
		}
	}
	for _, m := range aliasBitsEqRE.FindAllStringSubmatch(cond, -1) {
		bf, ok := lookupField(m[1], byName)
		if !ok {
			return fmt.Errorf("alias condition field %q absent from encoding", m[1])
		}
		width := bf.End - bf.Start + 1
		if len(m[2]) != width {
			return fmt.Errorf("alias condition %s width %d does not fit field %s width %d",
				m[2], len(m[2]), bf.Name, width)
		}
		v, err := strconv.ParseUint(m[2], 2, 32)
		if err != nil {
			return err
		}
		mask := fieldRangeMask(bf.Start, bf.End)
		form.ConstraintMask |= mask
		form.ConstraintValue = form.ConstraintValue&^mask | uint32(v)<<uint(bf.Start)
	}
	for _, m := range aliasFieldEqRE.FindAllStringSubmatch(cond, -1) {
		left, lok := lookupField(m[1], byName)
		right, rok := lookupField(m[2], byName)
		if !lok || !rok {
			missing := m[1]
			if lok {
				missing = m[2]
			}
			return fmt.Errorf("alias condition field %q absent from encoding", missing)
		}
		if left.End-left.Start != right.End-right.Start {
			return fmt.Errorf("alias fields %s and %s have different widths", left.Name, right.Name)
		}
		form.EqualFields = append(form.EqualFields, DisasmFieldEquality{
			LeftStart: left.Start, LeftEnd: left.End,
			RightStart: right.Start, RightEnd: right.End,
		})
	}
	for _, m := range aliasNextEqRE.FindAllStringSubmatch(cond, -1) {
		left, lok := lookupField(m[1], byName)
		right, rok := lookupField(m[2], byName)
		if !lok || !rok || left.End-left.Start != right.End-right.Start {
			return fmt.Errorf("alias successor fields %s and %s are absent or differ in width", m[1], m[2])
		}
		form.EqualFields = append(form.EqualFields, DisasmFieldEquality{
			LeftStart: left.Start, LeftEnd: left.End,
			RightStart: right.Start, RightEnd: right.End, Add: 1,
		})
	}
	for _, match := range aliasBitCountOneRE.FindAllStringSubmatch(cond, -1) {
		var mask uint32
		for _, name := range splitFieldList(match[1]) {
			field, ok := lookupField(name, byName)
			if !ok {
				return fmt.Errorf("alias BitCount field %q absent from encoding", name)
			}
			mask |= fieldRangeMask(field.Start, field.End)
		}
		if mask != 0 {
			form.OneHotMasks = append(form.OneHotMasks, mask)
		}
	}
	return nil
}

// disasmOperand resolves one classified operand to the bits it reads.
func disasmOperand(c ClassifiedOperand, byName map[string]ir.BitField, fixedMask uint32) (*DisasmOperand, error) {
	return disasmOperandWithContext(c, byName, fixedMask, 0, nil, "")
}

func disasmOperandWithContext(
	c ClassifiedOperand,
	byName map[string]ir.BitField,
	fixedMask, fixedValue uint32,
	pseudocode []string,
	aliasCond string,
) (*DisasmOperand, error) {
	if strings.Trim(c.Symbol, "<>") == "lsb" &&
		strings.Contains(aliasCond, "UInt(imms) < UInt(immr)") {
		if field, ok := lookupField("immr", byName); ok {
			c.Negate = int64(1) << uint(field.End-field.Start+1)
			if c.HasRange && c.Lo == 0 {
				if width, ok := exactPowerOfTwo(c.Hi + 1); ok {
					c.Negate = int64(1) << uint(width)
				}
			}
			c.Bias = 0
		}
	}
	prose := strings.ToLower(c.Explanation.Prose + " " + c.Hover)
	op := &DisasmOperand{
		Symbol: c.Symbol, Class: c.Class,
		Scale: c.Scale, Bias: c.Bias, Negate: c.Negate,
		Default: c.Default, HasDefault: c.HasDefault,
		Signed: c.Lo < 0, Xor: uint64(boolXor(c.InvertLSB)),
		RegRanges: append([]RegRange(nil), c.RegRanges...),
		Lo:        c.Lo, Hi: c.Hi, HasRange: c.HasRange,
		RegLo: c.RegLo, RegHi: c.RegHi, HasRegRange: c.HasRegRange,
		RegMultiple: c.RegMultiple,
		IgnoredShouldZero: strings.Contains(
			strings.ToLower(c.Explanation.Prose),
			"ignored but should be set to zero by an assembler",
		),
	}
	if value, ok := documentedFixedImmediate(prose); ok {
		op.NumConstant, op.HasNumConstant = value, true
	}
	if op.Scale == 0 {
		op.Scale = 1
	}
	if rows := printableRows(c.Explanation.Values); isFormulaTable(rows) {
		return formulaOperand(op, c, rows, byName)
	}
	if strings.Contains(prose, "64-bit immediate") &&
		strings.Contains(prose, "aaaaaaaabbbbbbbb") &&
		hasFields(c.Fields, "a", "b", "c", "d", "e", "f", "g", "h") {
		parts, err := bitPartsFor(
			[]string{"a", "b", "c", "d", "e", "f", "g", "h"},
			byName, fixedMask,
		)
		if err != nil {
			return nil, err
		}
		op.Kind, op.Parts = DisasmByteMaskImm, parts
		return op, nil
	}
	if strings.Contains(prose, `encoded in "imm16:hw"`) &&
		(strings.Contains(prose, "32-bit immediate") ||
			strings.Contains(prose, "64-bit immediate")) {
		parts, err := columnsFor([]string{"imm16", "hw", "sf"}, byName)
		if err != nil {
			return nil, err
		}
		op.Kind, op.Parts = DisasmMoveWideImm, parts
		op.MoveWideInvert = strings.Contains(prose, "bitwise inverse")
		return op, nil
	}
	if c.Class == ClassArrangement && len(fieldNames(c)) == 0 {
		if literal, ok := fixedSpecifierLiteral(prose); ok {
			op.Kind, op.Literal = DisasmLiteral, literal
			return op, nil
		}
	}
	if strings.Contains(prose, "list of up to eight 64-bit element tile names") {
		parts, err := columnsFor(fieldNames(c), byName)
		if err == nil && len(parts) == 1 && parts[0].Width == 8 {
			op.Kind, op.Parts = DisasmTileMask, parts
			return op, nil
		}
	}
	if strings.Contains(prose, "bitmask") {
		parts, err := logicalImmediateParts(c, byName)
		if err == nil {
			op.Kind, op.Parts = DisasmLogicalImm, parts
			return op, nil
		}
	}
	if c.Algorithmic && c.Class == ClassImm && c.Field != "" &&
		strings.Contains(prose, `encoded in the "`+strings.ToLower(c.Field)+`" field`) {
		if parts, err := columnsFor([]string{c.Field}, byName); err == nil {
			op.Kind, op.Parts = DisasmNum, parts
			return op, nil
		}
	}
	if c.Algorithmic {
		if c.Class == ClassLabel {
			if label, ok := pcRelativeLabelOperand(op, c, byName, prose); ok {
				return label, nil
			}
		}
		if parts, sizeParts, ok := elementIndexParts(c, byName, prose); ok {
			op.Kind, op.Parts = DisasmElementIndex, parts
			op.IndexSizeParts = sizeParts
			return op, nil
		}
		if formula, ok := compileElementSizeFormula(c.Fields, pseudocode, byName); ok {
			op.Kind = DisasmFormula
			op.Rows = []DisasmRow{{}}
			op.Formulas = []DisasmFormulaExpr{formula}
			return op, nil
		}
		if strings.Trim(c.Symbol, "<>") == "width" &&
			hasFields(c.Fields, "imms", "immr") {
			// Alias width expressions read UInt(imms) and UInt(immr), including
			// any bit the enclosing encoding pins. They are decoder inputs, not
			// encoder placements, so narrowing them to writable bits changes
			// the arithmetic on 32-bit variants.
			parts, err := columnsFor([]string{"imms", "immr"}, byName)
			if err != nil {
				return nil, err
			}
			op.Kind, op.Parts = DisasmBitfieldWidth, parts
			op.DataSize = bitfieldOperandSize(prose)
			if strings.Contains(aliasCond, "UInt(imms) < UInt(immr)") {
				op.Add = 1 // insert aliases encode width-1 directly in imms.
			}
			return op, nil
		}
	}

	// A value table decides the text outright, so it outranks the operand's
	// class: <T> is an arrangement to the assembler and a plain spelling lookup
	// here, and the same is true of conditions, prefetch operations and the
	// shift and extend selectors.
	rows, cols, err := valueTableFor(c, byName)
	if err != nil {
		return nil, err
	}
	if rows != nil {
		op.Kind, op.Cols, op.Rows = DisasmTable, cols, rows
		if len(c.Explanation.Values) > 0 {
			// An authoritative operand table already maps encoded bits to the
			// caller-facing spelling. Inverted-condition tables, for example,
			// explicitly say cond=0100 prints PL. Xor is needed only when the
			// generic condition table stands in for missing per-page rows.
			op.Xor = 0
		}
		if c.HasDefault && c.DefaultSymbol != "" {
			for _, row := range rows {
				if !strings.EqualFold(strings.TrimPrefix(row.Symbol, "#"), strings.TrimPrefix(c.DefaultSymbol, "#")) {
					continue
				}
				var raw uint64
				exact := true
				for _, bits := range row.Bits {
					for _, bit := range bits {
						raw <<= 1
						switch bit {
						case '1':
							raw |= 1
						case '0':
						default:
							exact = false
						}
					}
				}
				if exact {
					op.Default, op.HasDefault = int64(raw), true
				}
				break
			}
		}
		if !op.HasDefault {
			for _, row := range rows {
				if !strings.EqualFold(strings.TrimSpace(row.Symbol), "[absent]") {
					continue
				}
				var raw uint64
				exact := true
				for _, bits := range row.Bits {
					for _, bit := range bits {
						raw <<= 1
						switch bit {
						case '1':
							raw |= 1
						case '0':
						default:
							exact = false
						}
					}
				}
				if exact {
					op.Default, op.HasDefault = int64(raw), true
				}
				break
			}
		}
		return op, nil
	}
	if rows, cols, ok := proseSingletonTable(c, byName, prose); ok {
		op.Kind, op.Cols, op.Rows = DisasmTable, cols, rows
		return op, nil
	}
	if c.Class == ClassSysReg {
		cols, err := columnsFor(fieldNames(c), byName)
		if err != nil {
			return nil, err
		}
		op.Kind = DisasmSysReg
		op.Parts = append(op.Parts, cols...)
		return op, nil
	}

	if c.Class == ClassDerived {
		if c.Derived == nil {
			return nil, fmt.Errorf("derived operand states no relation")
		}
		// The class of a derived register is the class of the operand it follows,
		// which the classifier does not carry across. The bank letter in ARM's
		// symbol is the remaining signal: <Zt2> is a scalable vector, while the
		// lowercase <offs2> and <immp1> are numbers and stay unclassed.
		op.Class = derivedClassOf(c.Symbol)
		op.Kind = DisasmDerived
		op.Mul, op.Add, op.Mod = c.Derived.Mul, c.Derived.Add, c.Derived.Mod
		if c.Derived.Field == "" {
			op.Add = c.Derived.Const
			return op, nil
		}
		var parts []BitPart
		var err error
		if registerClass(op.Class) {
			parts, err = semanticPartsFor(
				[]string{c.Derived.Field}, byName, fixedMask, fixedValue,
			)
		} else {
			parts, err = bitPartsFor([]string{c.Derived.Field}, byName, fixedMask)
		}
		if err != nil {
			return nil, err
		}
		op.Parts = parts
		return op, nil
	}
	if c.Class == ClassUnsupported {
		return nil, fmt.Errorf("operand class %s has no print rule", c.Class)
	}
	symbolName := strings.Trim(c.Symbol, "<>")
	if isRegNumberSymbol(symbolName) || isRegNumberAlternativeSymbol(symbolName) {
		// ARM writes the width as a literal or a specifier and the register as a
		// bare number: "ABS  D<d>, D<n>" and "ADD <Xd|SP>, <Xn|SP>, <R><m>". The
		// prose says so — "Is the number of", against "Is the name of" for the
		// operands that carry their own bank letter — so printing a bank here
		// would double it, as "Dd22".
		op.Kind = DisasmNum
		var parts []BitPart
		var err error
		if registerClass(c.Class) {
			parts, err = semanticPartsFor(fieldNames(c), byName, fixedMask, fixedValue)
		} else {
			parts, err = bitPartsFor(fieldNames(c), byName, fixedMask)
		}
		if err != nil {
			return nil, err
		}
		op.Parts = parts
		op.Class = ""
		return op, nil
	}
	if c.Algorithmic && c.Class != ClassSysReg {
		// The value is some computation over its fields that this generator does
		// not model — a bitmask immediate held as N:immr:imms, an element index
		// folded together with its element size. Reading the bits back as a plain
		// integer would print a number that is not the operand's value.
		return nil, fmt.Errorf("operand is algorithmic over %v", c.Fields)
	}

	names := fieldNames(c)
	if len(names) == 0 {
		return nil, fmt.Errorf("no encoding field")
	}
	var parts []BitPart
	if c.Negate != 0 {
		// Relations such as 128-UInt(immh:immb) consume the complete encoded
		// integer. A pinned high bit still contributes to UInt even though a
		// generated encoder correctly omits it from its writable placement.
		parts, err = columnsFor(names, byName)
	} else if registerClass(c.Class) {
		parts, err = semanticPartsFor(names, byName, fixedMask, fixedValue)
	} else {
		parts, err = bitPartsFor(names, byName, fixedMask)
	}
	if err != nil {
		return nil, err
	}
	op.Parts = parts
	total := 0
	for _, part := range parts {
		total += part.Width
	}

	// Mirror the encoder's range inference. ARM often states the semantic range
	// without separately spelling out the subtraction used by the encoding.
	// When that range exactly fills the available bits, the only lossless
	// interpretation is an offset from its lower bound.
	if c.HasRegRange && registerClass(c.Class) && op.Bias == 0 {
		count := c.RegHi - c.RegLo + 1
		switch {
		case c.RegLo == 0 && count <= int64(1)<<uint(total):
			// The raw register number already has the documented value.
		case count == int64(1)<<uint(total):
			op.Bias = c.RegLo
		}
	}
	if c.Class == ClassImm && c.HasRange && op.Bias == 0 && op.Negate == 0 && c.Lo > 0 {
		scale := op.Scale
		if scale < 1 {
			scale = 1
		}
		if (c.Hi-c.Lo)%scale == 0 &&
			(c.Hi-c.Lo)/scale+1 == int64(1)<<uint(total) {
			op.Bias = c.Lo
		}
	}

	switch c.Class {
	case ClassImm, ClassLabel:
		op.Kind = DisasmNum
		if symbolName == "Cn" || symbolName == "Cm" {
			op.NumPrefix = "c"
		} else if !strings.HasSuffix(strings.TrimSpace(c.Prefix), "#") &&
			strings.Contains(strings.ToLower(prose), "must be #") {
			op.NumPrefix = "#"
		}
	case ClassFpImm:
		op.Kind = DisasmFpImm
	default:
		if registerBank(c.Class) == "" {
			return nil, fmt.Errorf("operand class %s has no register bank", c.Class)
		}
		op.Kind = DisasmReg
	}
	return op, nil
}

func proseSingletonTable(
	c ClassifiedOperand,
	byName map[string]ir.BitField,
	prose string,
) ([]DisasmRow, []BitPart, bool) {
	values := strings.Index(prose, "values are:")
	encoded := strings.Index(prose, "encoded as ")
	equalBits := strings.Index(prose, "= 0b")
	if values < 0 || encoded < 0 || equalBits < encoded {
		return nil, nil, false
	}
	i := values + len("values are:")
	for i < len(prose) && (prose[i] == ' ' || prose[i] == ':') {
		i++
	}
	start := i
	for i < len(prose) && (prose[i] >= 'a' && prose[i] <= 'z' ||
		prose[i] >= '0' && prose[i] <= '9') {
		i++
	}
	if start == i {
		return nil, nil, false
	}
	symbol := prose[start:i]
	i = equalBits + len("= 0b")
	start = i
	for i < len(prose) && (prose[i] == '0' || prose[i] == '1') {
		i++
	}
	if start == i {
		return nil, nil, false
	}
	bits := prose[start:i]
	names := fieldNames(c)
	if len(names) != 1 {
		return nil, nil, false
	}
	cols, err := columnsFor(names, byName)
	if err != nil || len(cols) != 1 || cols[0].Width != len(bits) {
		return nil, nil, false
	}
	return []DisasmRow{{Bits: []string{bits}, Symbol: symbol}}, cols, true
}

func elementIndexParts(
	c ClassifiedOperand,
	byName map[string]ir.BitField,
	prose string,
) ([]BitPart, int, bool) {
	if !strings.Contains(prose, "element index") &&
		!strings.Contains(prose, "immediate index") {
		return nil, 0, false
	}
	firstSize := -1
	for i, name := range c.Fields {
		base, _, _, sliced := parseFieldSlice(name)
		if !sliced {
			base = name
		}
		if strings.HasPrefix(strings.ToLower(base), "tsz") {
			firstSize = i
			break
		}
	}
	if firstSize <= 0 {
		return nil, 0, false
	}
	parts, err := columnsFor(c.Fields, byName)
	if err != nil {
		return nil, 0, false
	}
	return parts, len(parts) - firstSize, true
}

func fixedSpecifierLiteral(prose string) (string, bool) {
	marker := "specifier,"
	i := strings.LastIndex(prose, marker)
	if i < 0 {
		return "", false
	}
	value := strings.Trim(strings.TrimSpace(prose[i+len(marker):]), " .,;:")
	if len(value) != 1 || !strings.Contains("bhsdq", value) {
		return "", false
	}
	return value, true
}

func pcRelativeLabelOperand(
	op *DisasmOperand,
	c ClassifiedOperand,
	byName map[string]ir.BitField,
	prose string,
) (*DisasmOperand, bool) {
	if len(c.Fields) == 0 {
		return nil, false
	}
	signedConcat := len(c.Fields) > 1 &&
		strings.Contains(prose, "offset from") &&
		strings.Contains(prose, "encoded as")
	negativeUnsigned := len(c.Fields) == 1 &&
		strings.Contains(prose, "negative offset") &&
		strings.Contains(prose, "encoded as an unsigned value")
	if !signedConcat && !negativeUnsigned {
		return nil, false
	}
	parts, err := columnsFor(c.Fields, byName)
	if err != nil {
		return nil, false
	}
	op.Kind, op.Parts = DisasmNum, parts
	op.Class = ClassLabel
	op.Signed = signedConcat
	if negativeUnsigned {
		op.RawMul = -1
	}
	return op, true
}

func bitfieldOperandSize(prose string) int64 {
	lower := strings.ToLower(prose)
	marker := "range 1 to "
	i := strings.Index(lower, marker)
	if i < 0 {
		return 0
	}
	i += len(marker)
	start := i
	for i < len(lower) && lower[i] >= '0' && lower[i] <= '9' {
		i++
	}
	if start == i || !strings.HasPrefix(lower[i:], "-<lsb>") {
		return 0
	}
	n, err := strconv.ParseInt(lower[start:i], 10, 64)
	if err != nil || n != 32 && n != 64 {
		return 0
	}
	return n
}

func documentedFixedImmediate(prose string) (int64, bool) {
	lower := strings.ToLower(prose)
	if !strings.Contains(lower, "if omitted") || !strings.Contains(lower, "if present") {
		return 0, false
	}
	marker := "must be #"
	i := strings.Index(lower, marker)
	if i < 0 {
		return 0, false
	}
	i += len(marker)
	start := i
	for i < len(lower) && lower[i] >= '0' && lower[i] <= '9' {
		i++
	}
	if start == i {
		return 0, false
	}
	n, err := strconv.ParseInt(lower[start:i], 10, 64)
	return n, err == nil
}

func hasFields(fields []string, wanted ...string) bool {
	seen := map[string]bool{}
	for _, field := range baseFields(fields) {
		seen[field] = true
	}
	for _, field := range wanted {
		if !seen[field] {
			return false
		}
	}
	return true
}

func logicalImmediateParts(c ClassifiedOperand, byName map[string]ir.BitField) ([]BitPart, error) {
	parts := make([]BitPart, 0, 4)
	if len(c.Fields) == 1 {
		if field, ok := lookupField(c.Fields[0], byName); ok &&
			field.End-field.Start+1 == 13 {
			return []BitPart{{
				Field: field.Name, Start: field.Start, End: field.End, Width: 13,
			}}, nil
		}
	}
	for _, name := range []string{"N", "immr", "imms", "sf"} {
		field, ok := lookupField(name, byName)
		if !ok {
			return nil, fmt.Errorf("logical immediate field %q absent from encoding", name)
		}
		parts = append(parts, BitPart{
			Field: field.Name, Start: field.Start, End: field.End,
			Width: field.End - field.Start + 1,
		})
	}
	return parts, nil
}

func compileElementSizeFormula(
	fields []string,
	pseudocode []string,
	byName map[string]ir.BitField,
) (DisasmFormulaExpr, bool) {
	var out DisasmFormulaExpr
	if len(fields) < 2 {
		return out, false
	}
	expressions := []string{strings.Join(fields, "::")}
	aliased := "tsize::" + fields[len(fields)-1]
	if aliased != expressions[0] {
		expressions = append(expressions, aliased)
	}
	var found bool
	for _, text := range pseudocode {
		for _, expression := range expressions {
			switch {
			case strings.Contains(text, "UInt("+expression+") - esize"):
				out.RawMul, out.ESizeMul = 1, -1
				found = true
			default:
				suffix := " * esize) - UInt(" + expression + ")"
				if end := strings.Index(text, suffix); end >= 0 {
					start := strings.LastIndexByte(text[:end], '(')
					if start >= 0 {
						if n, ok := parseDecimal(strings.TrimSpace(text[start+1 : end])); ok {
							out.RawMul, out.ESizeMul = -1, int64(n)
							found = true
						}
					}
				}
			}
		}
	}
	if !found {
		return DisasmFormulaExpr{}, false
	}
	for _, name := range fields {
		field, ok := lookupField(name, byName)
		if !ok {
			return DisasmFormulaExpr{}, false
		}
		out.Parts = append(out.Parts, BitPart{
			Field: field.Name, Start: field.Start, End: field.End,
			Width: field.End - field.Start + 1,
		})
	}
	out.SizeParts = len(out.Parts) - 1
	out.ESizeBase = 8
	return out, true
}

func formulaOperand(
	op *DisasmOperand,
	c ClassifiedOperand,
	rows []DisasmRow,
	byName map[string]ir.BitField,
) (*DisasmOperand, error) {
	selectorNames := tableFieldNames(c.Explanation)
	if len(rows) == 0 || len(rows[0].Bits) == 0 ||
		len(rows[0].Bits) > len(selectorNames) {
		return nil, fmt.Errorf("formula table has no selector fields")
	}
	selectorNames = selectorNames[:len(rows[0].Bits)]
	cols, err := columnsFor(selectorNames, byName)
	if err != nil {
		return nil, err
	}
	op.Kind, op.Cols, op.Rows = DisasmFormula, cols, rows
	for _, row := range rows {
		formula, err := compileDisasmFormula(row.Symbol, byName)
		if err != nil {
			return nil, fmt.Errorf("decode formula %q: %w", row.Symbol, err)
		}
		op.Formulas = append(op.Formulas, formula)
		var whole, used uint32
		for _, name := range c.Explanation.Fields {
			if field, ok := lookupField(name, byName); ok {
				whole |= fieldRangeMask(field.Start, field.End)
			}
		}
		for _, part := range formula.Parts {
			if !part.IsLit {
				used |= fieldRangeMask(part.Start, part.End)
			}
		}
		for i, pattern := range row.Bits {
			for j, bit := range pattern {
				if bit != 'x' && bit != 'X' {
					used |= uint32(1) << uint(cols[i].End-j)
				}
			}
		}
		op.FormulaIgnoredZero = append(op.FormulaIgnoredZero, whole&^used)
	}
	return op, nil
}

func compileDisasmFormula(text string, byName map[string]ir.BitField) (DisasmFormulaExpr, error) {
	text = strings.TrimSpace(text)
	out := DisasmFormulaExpr{RawMul: 1}
	var expression string
	switch {
	case strings.HasPrefix(text, "UInt("):
		close := strings.LastIndexByte(text, ')')
		if close < len("UInt(") {
			return out, fmt.Errorf("missing closing parenthesis")
		}
		expression = text[len("UInt("):close]
		rest := strings.TrimSpace(text[close+1:])
		if rest != "" {
			if !strings.HasPrefix(rest, "- ") {
				return out, fmt.Errorf("unsupported suffix %q", rest)
			}
			n, ok := parseDecimal(strings.TrimSpace(rest[2:]))
			if !ok {
				return out, fmt.Errorf("invalid subtraction %q", rest)
			}
			out.Add = -int64(n)
		}
	default:
		marker := " - UInt("
		i := strings.Index(text, marker)
		if i <= 0 || !strings.HasSuffix(text, ")") {
			return out, fmt.Errorf("unsupported expression")
		}
		n, ok := parseDecimal(strings.TrimSpace(text[:i]))
		if !ok {
			return out, fmt.Errorf("invalid negate constant")
		}
		out.Negate = int64(n)
		expression = text[i+len(marker) : len(text)-1]
	}

	for _, item := range strings.Split(expression, "::") {
		item = strings.TrimSpace(item)
		if bits, literal := LiteralBits(item); literal {
			out.Parts = append(out.Parts, BitPart{
				Literal: bits, IsLit: true, Width: len(bits),
			})
			continue
		}
		field, ok := lookupField(item, byName)
		if !ok {
			return out, fmt.Errorf("field %q absent from encoding", item)
		}
		out.Parts = append(out.Parts, BitPart{
			Field: field.Name, Start: field.Start, End: field.End,
			Width: field.End - field.Start + 1,
		})
	}
	if len(out.Parts) == 0 {
		return out, fmt.Errorf("empty UInt expression")
	}
	return out, nil
}

func isRegNumberAlternativeSymbol(symbol string) bool {
	if bar := strings.IndexByte(symbol, '|'); bar > 0 {
		return isRegNumberSymbol(symbol[:bar])
	}
	return false
}

// valueTableFor returns the spelling table an operand prints from, or nil when
// it does not print from one.
//
// ARM's own table is used when the page carries one. The condition, shift and
// extend selectors are the exception: those spellings are architectural rather
// than per-instruction, and most pages state them in prose only, so a builtin
// table stands in. Without it every conditional branch and every shifted
// register operand would be unprintable.
func valueTableFor(c ClassifiedOperand, byName map[string]ir.BitField) ([]DisasmRow, []BitPart, error) {
	rows := printableRows(c.Explanation.Values)
	if isFormulaTable(rows) {
		return nil, nil, fmt.Errorf("operand is computed per row of a decode table over %v",
			c.Explanation.Fields)
	}
	names := tableFieldNames(c.Explanation)
	if len(rows) == 0 || len(names) == 0 {
		builtin, ok := builtinTables[c.Class]
		if !ok {
			return nil, nil, nil
		}
		names = c.Fields
		if len(names) == 0 && c.ResolvedField != "" {
			names = []string{c.ResolvedField}
		}
		if len(names) != 1 {
			return nil, nil, nil
		}
		rows = builtin
	}
	cols, err := columnsFor(names, byName)
	if err != nil {
		return nil, nil, err
	}
	if err := checkRowWidths(rows, cols); err != nil {
		return nil, nil, err
	}
	return rows, cols, nil
}

func tableFieldNames(exp AsmExplanation) []string {
	if len(exp.ValueFields) > 0 {
		return exp.ValueFields
	}
	return exp.Fields
}

// builtinTables hold the selector spellings ARM defines once for the whole
// architecture rather than per instruction page.
var builtinTables = map[OperandClass][]DisasmRow{
	ClassCond: bitTable(4, "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
		"HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"),
	ClassShift:  bitTable(2, "LSL", "LSR", "ASR", "ROR"),
	ClassExtend: bitTable(3, "UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"),
}

// bitTable builds a single-column table whose nth row is selected by n.
func bitTable(width int, symbols ...string) []DisasmRow {
	rows := make([]DisasmRow, 0, len(symbols))
	for i, sym := range symbols {
		bits := make([]byte, width)
		for b := 0; b < width; b++ {
			if i>>(width-1-b)&1 == 1 {
				bits[b] = '1'
			} else {
				bits[b] = '0'
			}
		}
		rows = append(rows, DisasmRow{Bits: []string{string(bits)}, Symbol: sym})
	}
	return rows
}

// derivedClassOf reads the register bank from ARM's symbol for a derived
// operand: <Wt2> is a W register, <Zt2> a scalable vector, <Vt2> a SIMD vector.
func derivedClassOf(symbol string) OperandClass {
	s := strings.TrimLeft(strings.Trim(symbol, "<>"), "(")
	if s == "" {
		return ""
	}
	switch s[0] {
	case 'W':
		return ClassGpr32
	case 'X':
		return ClassGpr64
	case 'Z':
		return ClassSveZ
	case 'P':
		return ClassSveP
	case 'V':
		return ClassSimdVec
	case 'Q':
		return ClassSimdQ
	case 'D':
		return ClassSimdD
	case 'S':
		return ClassSimdS
	case 'H':
		return ClassSimdH
	case 'B':
		return ClassSimdB
	}
	return ""
}

// fieldNames lists the fields holding an operand's value, most significant
// first. Split is preferred: it is the order ARM's prose states, which for TBZ's
// bit number and the logical immediate is the transpose of `encodedin`.
func fieldNames(c ClassifiedOperand) []string {
	if len(c.Split) > 0 {
		return c.Split
	}
	if len(c.Fields) > 0 {
		return c.Fields
	}
	if c.ResolvedField != "" {
		return []string{c.ResolvedField}
	}
	return nil
}

func bitPartsFor(names []string, byName map[string]ir.BitField, fixedMask uint32) ([]BitPart, error) {
	parts := make([]BitPart, 0, len(names))
	for _, n := range names {
		if bits, isLit := LiteralBits(n); isLit {
			parts = append(parts, BitPart{Literal: bits, IsLit: true, Width: len(bits)})
			continue
		}
		bf, ok := lookupField(n, byName)
		if !ok {
			return nil, fmt.Errorf("field %q absent from encoding", n)
		}
		free, err := freeSubRange(bf, fixedMask)
		if err != nil {
			return nil, err
		}
		parts = append(parts, free)
	}
	return parts, nil
}

// semanticPartsFor retains fixed bits that are part of the operand's written
// value. A paired-register field such as Rt=xxxx0 still denotes X0, X2, ...,
// X30; its low zero is an architectural restriction, not a bit to remove and
// compact away. Literal parts let both the decoder reconstruct the complete
// register number and the encoder verify that callers supplied an even one.
func semanticPartsFor(
	names []string,
	byName map[string]ir.BitField,
	fixedMask, fixedValue uint32,
) ([]BitPart, error) {
	var parts []BitPart
	for _, name := range names {
		if bits, isLit := LiteralBits(name); isLit {
			parts = append(parts, BitPart{Literal: bits, IsLit: true, Width: len(bits)})
			continue
		}
		field, ok := lookupField(name, byName)
		if !ok {
			return nil, fmt.Errorf("field %q absent from encoding", name)
		}
		parts = append(parts, semanticFieldParts(field, fixedMask, fixedValue)...)
	}
	return parts, nil
}

func semanticFieldParts(field ir.BitField, fixedMask, fixedValue uint32) []BitPart {
	var parts []BitPart
	for hi := field.End; hi >= field.Start; {
		isFixed := fixedMask&(uint32(1)<<uint(hi)) != 0
		lo := hi
		for lo > field.Start {
			nextFixed := fixedMask&(uint32(1)<<uint(lo-1)) != 0
			if nextFixed != isFixed {
				break
			}
			lo--
		}
		width := hi - lo + 1
		if !isFixed {
			parts = append(parts, BitPart{
				Field: field.Name, Start: lo, End: hi, Width: width,
			})
		} else {
			literal := make([]byte, 0, width)
			for bit := hi; bit >= lo; bit-- {
				if fixedValue&(uint32(1)<<uint(bit)) != 0 {
					literal = append(literal, '1')
				} else {
					literal = append(literal, '0')
				}
			}
			parts = append(parts, BitPart{
				Field: field.Name, Literal: string(literal), IsLit: true, Width: width,
			})
		}
		hi = lo - 1
	}
	return parts
}

// columnsFor resolves a value table's columns. Unlike an operand's own bits,
// a table column is read whole: the pinned bits are what select the row.
func columnsFor(names []string, byName map[string]ir.BitField) ([]BitPart, error) {
	cols := make([]BitPart, 0, len(names))
	for _, n := range names {
		bf, ok := lookupField(n, byName)
		if !ok {
			return nil, fmt.Errorf("table field %q absent from encoding", n)
		}
		cols = append(cols, BitPart{
			Field: bf.Name, Start: bf.Start, End: bf.End, Width: bf.End - bf.Start + 1,
		})
	}
	return cols, nil
}

// printableRows drops the rows that name no spelling. ARM lists unallocated
// combinations in the same table, and a word landing on one is not a legal
// instruction rather than one that prints as "RESERVED".
func printableRows(vals []SymbolValue) []DisasmRow {
	var out []DisasmRow
	for _, v := range vals {
		if v.Reserved() {
			continue
		}
		out = append(out, DisasmRow{Bits: v.Bits, Symbol: v.Symbol})
	}
	return out
}

// isFormulaTable reports whether a table gives decode arithmetic rather than
// assembler spellings.
//
// ARM uses one <table> element for both. SHL's shift amount is listed as
// "UInt(immh:immb) - 8" against each immh value, and FMLA's element index as
// "UInt(H:L)" — a different computation per row, not a name to print. Reading
// those as spellings would print the formula text as though it were the operand.
func isFormulaTable(rows []DisasmRow) bool {
	for _, r := range rows {
		if strings.Contains(r.Symbol, "UInt(") {
			return true
		}
	}
	return false
}

func checkRowWidths(rows []DisasmRow, cols []BitPart) error {
	for _, r := range rows {
		if len(r.Bits) != len(cols) {
			return fmt.Errorf("value table row %q has %d columns, encoding has %d",
				r.Symbol, len(r.Bits), len(cols))
		}
		for i, b := range r.Bits {
			if len(b) != cols[i].Width {
				return fmt.Errorf("value table row %q column %s is %d bits, field is %d",
					r.Symbol, cols[i].Field, len(b), cols[i].Width)
			}
		}
	}
	return nil
}

// registerBank names the register file an operand class prints from, and is the
// single place the spelling of each bank is decided. Empty means the class does
// not print as a register.
func registerBank(c OperandClass) string {
	switch c {
	case ClassGpr32, ClassGpr32Sp:
		return "w"
	case ClassGpr64, ClassGpr64Sp:
		return "x"
	case ClassSimdB:
		return "b"
	case ClassSimdH:
		return "h"
	case ClassSimdS:
		return "s"
	case ClassSimdD:
		return "d"
	case ClassSimdQ:
		return "q"
	case ClassSimdVec:
		return "v"
	case ClassSveZ:
		return "z"
	case ClassSveP:
		return "p"
	case ClassSvePN:
		return "pn"
	case ClassSmeTile:
		return "za"
	}
	return ""
}

// RegisterName spells one register of a bank. Register 31 is the case that
// matters: the same five bits read as wzr/xzr in most positions and as wsp/sp
// in the positions ARM types "or stack pointer", and the two are different
// registers.
func RegisterName(class OperandClass, n uint64) string {
	bank := registerBank(class)
	if bank == "" {
		return ""
	}
	if n == 31 {
		switch class {
		case ClassGpr32:
			return "wzr"
		case ClassGpr64:
			return "xzr"
		case ClassGpr32Sp:
			return "wsp"
		case ClassGpr64Sp:
			return "sp"
		}
	}
	return fmt.Sprintf("%s%d", bank, n)
}

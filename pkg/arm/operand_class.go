package arm

import (
	"regexp"
	"strconv"
	"strings"
)

// OperandClass is the semantic type of an assembler operand, derived from ARM's
// own operand prose and operand-class link ids rather than guessed from names.
type OperandClass string

const (
	ClassGpr32   OperandClass = "gpr32"   // W0-W30, WZR
	ClassGpr32Sp OperandClass = "gpr32sp" // W0-W30, WSP
	ClassGpr64   OperandClass = "gpr64"   // X0-X30, XZR
	ClassGpr64Sp OperandClass = "gpr64sp" // X0-X30, SP
	ClassSimdB   OperandClass = "simdb"
	ClassSimdH   OperandClass = "simdh"
	ClassSimdS   OperandClass = "simds"
	ClassSimdD   OperandClass = "simdd"
	ClassSimdQ   OperandClass = "simdq"
	ClassSimdVec OperandClass = "simdvec" // <Vd>.<T>
	ClassSveZ    OperandClass = "svez"
	ClassSveP    OperandClass = "svep"
	ClassSvePN   OperandClass = "svepn"   // SME predicate-as-counter PN8-PN15
	ClassSmeTile OperandClass = "smetile" // <ZAda>, <ZAn>: ZA0-ZA15
	ClassImm     OperandClass = "imm"
	// ClassFpImm is ARM's VFPExpandImm 8-bit floating-point constant. It is
	// deliberately distinct from a numeric immediate: the field stores the
	// compact FP encoding, not the integer value written after '#'.
	ClassFpImm  OperandClass = "fpimm8"
	ClassLabel  OperandClass = "label"
	ClassCond   OperandClass = "cond"
	ClassSysReg OperandClass = "sysreg"
	ClassShift  OperandClass = "shift"  // LSL/LSR/ASR/ROR selector
	ClassExtend OperandClass = "extend" // UXTB…SXTX selector
	// ClassEnum is an operand ARM defines by a value table of assembler
	// spellings that is not a register arrangement: prefetch operations, SVE
	// count patterns, index-extend modifiers, slice direction. Each becomes a
	// generated Rust enum whose variants are exactly ARM's spellings.
	ClassEnum OperandClass = "enum"
	// ClassArrangement is a type modifier, not a parameter: <T> selects the
	// element arrangement of the register operand it attaches to.
	ClassArrangement OperandClass = "arrangement"
	// ClassDerived is an operand whose value is fixed by another operand: the
	// second register of a pair or list, or the end of a slice range. It
	// contributes no parameter because supplying it could only introduce an
	// inconsistency the assembler would have to reject.
	ClassDerived OperandClass = "derived"
	// ClassUnsupported marks operands this generator will not place on a guess.
	ClassUnsupported OperandClass = "unsupported"
)

// ClassifiedOperand is an AsmOperand resolved to a class and encoding field.
type ClassifiedOperand struct {
	AsmOperand
	Class OperandClass
	// ResolvedField is the first field this operand encodes into. Empty means
	// the operand cannot be placed.
	ResolvedField string
	// Fields holds every field the operand spans, as ARM's `encodedin` lists
	// them. Length > 1 means the value does not live in a single field.
	Fields []string
	// Split holds the fields in the order the value's bits occupy them, most
	// significant first, and is set only when ARM's prose states that the value
	// is simply the concatenation of those fields.
	//
	// The order comes from the prose, not from `encodedin`: TBZ's bit number is
	// `encodedin="b40:b5"` but reads "encoded in \"b5:b40\"", and the logical
	// immediate is `encodedin="immr:imms"` but reads "imms:immr". Taking the
	// attribute order would transpose the halves of both.
	Split []string
	// Algorithmic marks an operand that spans several fields by a computation
	// rather than a concatenation — a bitmask immediate, a shift amount encoded
	// as 128 - UInt(immh:immb), an element index folded together with its
	// element size. Placing such a value by concatenation encodes the wrong
	// word, so these are not given an operand-typed signature.
	Algorithmic bool
	// Explanation is ARM's entry for this operand, including any value table.
	Explanation AsmExplanation
	// Range is the inclusive value range for immediates when ARM states one.
	Lo, Hi   int64
	HasRange bool
	// RegLo/RegHi bound a register operand ARM restricts to part of its bank:
	// "the vector select register W12-W15", "predicate register P0-P7". Without
	// them a caller could pass W0 and have the field silently truncate.
	RegLo, RegHi int64
	HasRegRange  bool
	// RegMultiple restricts a register number to a stated alignment. Pair
	// instructions use 2 for the first even-numbered register.
	RegMultiple int64
	// RegRanges maps disjoint written register runs into one consecutive field.
	RegRanges []RegRange
	// Default is the encoded value when the operand is omitted.
	Default    int64
	HasDefault bool
	// DefaultSymbol is the assembler spelling of an omitted table operand,
	// such as SVE's ALL pattern.
	DefaultSymbol string
	// Mirrors are additional whole fields that receive this operand's value.
	Mirrors []string
	// InvertLSB is ARM's <invcond> alias transformation.
	InvertLSB bool
	// Scale is the encoding multiplier: a byte offset of 8 held in a scaled
	// imm12 encodes as 1, and a multi-vector group base written Z4 encodes as 2.
	// 1 when unscaled.
	Scale int64
	// Bias is what the encoding subtracts from the written value before storing
	// it: "encoded as \"imm6\" plus 1" holds value-1. Negative adds.
	Bias int64
	// Negate is set when the field counts down from a constant: a right shift
	// "encoded as 128 - UInt(immh:immb)" is held as 128 minus the amount.
	Negate int64
	// Derived is how a ClassDerived operand's value follows from the encoding.
	// The assembler must not accept such an operand — supplying it could only
	// introduce an inconsistency — but a disassembler still has to print it.
	Derived *DerivedRel
}

// DerivedRel states a derived operand's value as (field × Mul + Add) mod Mod,
// or as the constant Const when Field is empty.
//
// These are the only shapes ARM uses: the second register of a pair is "Rt" +1,
// the second of a list is "Zt" plus 1 modulo 32, the second of a strided
// multi-vector group is "Zn" times 2 plus 1, and a slice index ARM fixes
// outright has "implicit value 0".
type DerivedRel struct {
	Field string
	Mul   int64
	Add   int64
	Mod   int64
	Const int64
}

// RegRange maps raw = written register - Bias for one accepted run.
type RegRange struct {
	Lo, Hi int64
	Bias   int64
}

var (
	// imm26_offset, imm19_offset: the link id names the field ARM's prose omits.
	linkImmOffsetRE = regexp.MustCompile(`^(imm\d+)_offset`)
	// "in the range 0 to 4095", "in the range -256 to 255"
	rangeRE = regexp.MustCompile(`in the range (-?\d+) to (-?\d+)`)
	// "is the optional positive immediate byte offset, a multiple of 8"
	multipleRE = regexp.MustCompile(`multiple of (\d+)`)
	// "Defaults to X30 if absent", "defaulting to LSL #0"
	defaultRE      = regexp.MustCompile(`(?i)default(?:s|ing) to ['"]?([A-Za-z][A-Za-z0-9]*|#?-?\d+)['"]?`)
	defaultBitsRE  = regexp.MustCompile(`(?i)default(?:s|ing) to '([01]+)'`)
	mirrorFieldsRE = regexp.MustCompile(`(?i)encoded in (?:the )?"([A-Za-z0-9_]+)" and "([A-Za-z0-9_]+)" fields`)
	// `encoded in "immhi:immlo"`, `encoded in the "i3h:i3l" fields`: the quoted
	// list is the concatenation order.
	// Items may name a bit slice of a field: ST1's element index for the 16-bit
	// variant is "Q:S:size<1>", where only the top bit of size takes part.
	splitOrderRE = regexp.MustCompile(`encoded in (?:the )?"([A-Za-z0-9_]+(?:<[\d:]+>)?(?::[A-Za-z0-9_]+(?:<[\d:]+>)?)+)"`)
	// "the vector select register W12-W15", "predicate register P0-P7",
	// "the ZA tile ZA0-ZA3".
	// PN8-PN15 is the predicate-as-counter bank, whose two-letter prefix must be
	// matched or the operand looks unrestricted and encodes eight registers low.
	regRangeRE = regexp.MustCompile(`\b(ZA|PN|[VWXZPBHSDQ])(\d+)\s*-\s*(?:ZA|PN|[VWXZPBHSDQ])(\d+)\b`)
	// ARM's own link ids mark some derived operands: <W(s+1)> links "WsPlus1".
	linkPlusRE = regexp.MustCompile(`Plus(\d+)(?:__\d+)?$`)

	// The complete set of "encoded as" relations ARM uses between an operand's
	// written value and the field holding it. There are only fourteen shapes in
	// the whole spec, so each is matched exactly rather than approximated.
	//
	//	"Zn" times 2 plus 1     the second register of a multi-vector group
	//	"Zt" plus 1 modulo 32   the second register of a list
	//	"Rt" +1                 the second register of a pair
	// Each names a value another operand already fixes.
	encAsDerivedRE = regexp.MustCompile(`encoded as "[A-Za-z0-9_:']+"(?: field)? (?:times \d+ plus \d+|plus \d+(?: modulo \d+)?|\+\d+)`)
	// The same shapes with the field and the constants captured, so a printer can
	// reproduce the value the assembler refuses to accept.
	encAsDerivedCapRE  = regexp.MustCompile(`encoded as "([A-Za-z0-9_:']+)"(?: field)? (?:times (\d+) )?(?:plus (\d+)|\+(\d+))(?: modulo (\d+))?`)
	implicitValueCapRE = regexp.MustCompile(`implicit value (\d+)`)
	//	"Zn" times 2            a multi-vector group base: field holds n/2
	//	"off2" field times 2    a slice offset in units of two
	encAsScaledRE = regexp.MustCompile(`encoded as "[A-Za-z0-9_:']+"(?: field)? times (\d+)\s*(?:\.|$|,)`)
	//	"imm6" plus 1           field holds value-1
	//	"imm6" minus 1          field holds value+1
	//	UInt("immh:immb") - 64  field holds value+64
	encAsOffsetRE  = regexp.MustCompile(`encoded as "[A-Za-z0-9_:']+"(?: field)? (plus|minus) (\d+)\s*(?:\.|$|,)`)
	encAsUIntSubRE = regexp.MustCompile(`encoded as UInt\("[A-Za-z0-9_:']+"\) - (\d+)`)
	// A bare field expression: the value is exactly those bits, with any quoted
	// run being literal bits it must contain. "T:'00':Zt" is the base register
	// of a strided multi-vector group — bit 4 in T, bits 3:2 fixed at 00, bits
	// 1:0 in Zt, which is why the group is Z0-Z7 or Z16-Z23 in steps of four.
	encAsExprRE = regexp.MustCompile(`encoded as "([A-Za-z0-9_:']+)"\s*(?:\.|$|,)`)
	//	128 - UInt("immh:immb")   field holds 128 minus the value
	//	64 minus "scale"          field holds 64 minus the value
	encAsNegRE = regexp.MustCompile(`encoded as (\d+) (?:- UInt\("[A-Za-z0-9_:']+"\)|minus "[A-Za-z0-9_:']+")`)
	// Any other "encoded as" relation is a computation this generator does not
	// implement — 128 - UInt("immh:immb"), "D:'0':Zd" — so the operand is not
	// placed by concatenation or offset.
	encAsAnyRE = regexp.MustCompile(`encoded as `)
	// "is the name of the second scalable vector register", "the fourth vector
	// select offset": a member of a group, positioned relative to the first.
	// "with implicit value 0": the operand has no encoding of its own.
	implicitValueRE = regexp.MustCompile(`implicit value \d+`)
	ordinalMemberRE = regexp.MustCompile(`\bthe (second|third|fourth|fifth|sixth|seventh|eighth)\b`)
)

// linkFieldFallback maps operand-class link ids to the field they encode for
// the cases where ARM's prose does not say. Kept small and explicit on purpose:
// anything not listed stays unbound and its encoding falls back to the raw API
// rather than being placed on a guess.
var linkFieldFallback = map[string]string{
	"cond_option":  "cond",
	"cond":         "cond",
	"shift_option": "sh",
}

// ClassifyOperand resolves one asmtemplate operand reference from its hover
// prose alone. Prefer ClassifyOperandWith, which also consults ARM's
// <explanations> section.
func ClassifyOperand(o AsmOperand) ClassifiedOperand {
	return ClassifyOperandWith(o, AsmExplanation{})
}

// ClassifyOperandWith resolves an operand using ARM's <explanations> entry when
// one is available.
//
// The explanation is the authoritative source: it states the encoding field in
// `encodedin` for 99.7% of operands — including multi-field placements like
// "size:Q" and "immh:immb" that the hover prose never mentions — and it carries
// the value table for enumerated operands.
func ClassifyOperandWith(o AsmOperand, exp AsmExplanation) ClassifiedOperand {
	c := ClassifiedOperand{AsmOperand: o, Scale: 1}
	c.Explanation = exp
	sym := strings.Trim(o.Symbol, "<>")
	link := o.Link
	baseLink := strings.TrimSuffix(stripNumericVariant(link), "_option")

	if len(exp.Fields) > 0 {
		c.Fields = exp.Fields
		c.ResolvedField = exp.Fields[0]
	}
	if c.ResolvedField == "" {
		c.ResolvedField = o.Field
		if c.ResolvedField != "" {
			c.Fields = []string{c.ResolvedField}
		}
	}
	if c.ResolvedField == "" {
		if m := linkImmOffsetRE.FindStringSubmatch(link); m != nil {
			c.ResolvedField = m[1]
		} else if f, ok := linkFieldFallback[link]; ok {
			c.ResolvedField = f
		} else if f, ok := linkFieldFallback[baseLink+"_option"]; ok {
			c.ResolvedField = f
		}
		if c.ResolvedField != "" {
			c.Fields = []string{c.ResolvedField}
		}
	}

	// ARM's prose is the operand's description; the hover text repeats it in
	// abbreviated form. Both are consulted so an operand missing one still
	// classifies.
	prose := o.Hover
	if exp.Prose != "" {
		prose = exp.Prose + " " + o.Hover
	}
	h := strings.ToLower(prose)

	c.classifySpan(prose)
	// Some operands occupy only a slice of the field named by their
	// <account>. Arm records that distinction in the operand prose:
	// "Vm ... encoded in the Rm<2:0> field". The remaining Rm bit can belong
	// to a different operand, such as an element index, so treating Vm as the
	// whole field changes both the printed register and the encoded call.
	if slice, ok := operandFieldSlice(prose, c.ResolvedField); ok {
		c.ResolvedField = slice
		c.Fields = []string{slice}
		c.Split = nil
	}
	c.Class = classOf(sym, h, link)
	if strings.Contains(h, "floating-point immediate") ||
		strings.Contains(h, "floating-point constant") {
		c.Class = ClassFpImm
	}
	if c.Class == ClassSimdVec && isRegNumberSymbol(sym) {
		// "SSHR D<d>, D<n>, #<shift>": the width is a literal in the template,
		// not a specifier, so the operand is a scalar of that width rather than
		// a vector.
		if w, ok := literalWidthClass(o.Prefix); ok {
			c.Class = w
		}
	}
	if c.Class == ClassUnsupported && c.ResolvedField != "" && rangeRE.MatchString(prose) {
		// ARM states a numeric range and a field but no familiar type name —
		// "Is a name 'Cn', with 'n' in the range 0 to 15, encoded in the CRn
		// field". It is a number in a field, which is all the encoder needs.
		c.Class = ClassImm
	}
	if c.Class == ClassUnsupported && len(c.Explanation.Values) > 0 && len(c.Fields) > 0 {
		// ARM enumerates this operand's legal spellings, so the table is an
		// exact encoding even when the prose does not name a familiar type.
		c.Class = ClassEnum
	}
	c.classifyRelation(prose, link)
	if m := mirrorFieldsRE.FindStringSubmatch(prose); m != nil {
		c.ResolvedField = m[1]
		c.Fields = []string{m[1]}
		c.Mirrors = []string{m[2]}
		c.Algorithmic = false
		c.Split = nil
	}
	c.InvertLSB = strings.Contains(strings.ToLower(prose), "least significant bit inverted")

	if m := defaultBitsRE.FindStringSubmatch(prose); m != nil {
		if v, err := strconv.ParseInt(m[1], 2, 64); err == nil {
			c.Default, c.HasDefault = v, true
		}
	} else if m := defaultRE.FindStringSubmatch(prose); m != nil {
		// A table spelling is encoding-relative.  LSL is zero in the shared
		// Extend enum only by convention, while this register-offset table
		// encodes it as option=011.  Preserve the symbol so the table, and any
		// selector imposed by an alternative operand, resolves it correctly.
		tableSymbol := false
		for _, row := range c.Explanation.Values {
			if strings.EqualFold(strings.TrimPrefix(row.Symbol, "#"), strings.TrimPrefix(m[1], "#")) {
				c.DefaultSymbol, c.HasDefault = strings.ToUpper(m[1]), true
				tableSymbol = true
				break
			}
		}
		if tableSymbol {
			// Resolved by the table-owning model.
		} else if v, ok := parseDefaultValue(m[1]); ok {
			c.Default, c.HasDefault = v, true
		} else {
			c.DefaultSymbol, c.HasDefault = strings.ToUpper(m[1]), true
		}
	}

	switch c.Class {
	case ClassImm:
		if m := rangeRE.FindStringSubmatch(prose); m != nil {
			lo, e1 := strconv.ParseInt(m[1], 10, 64)
			hi, e2 := strconv.ParseInt(m[2], 10, 64)
			if e1 == nil && e2 == nil {
				c.Lo, c.Hi, c.HasRange = lo, hi, true
			}
		}
		if m := multipleRE.FindStringSubmatch(prose); m != nil {
			if s, err := strconv.ParseInt(m[1], 10, 64); err == nil && s > 0 {
				c.Scale = s
			}
		}
		if divisor, ok := encodedDivisor(prose); ok {
			c.Scale = divisor
		}
	case ClassGpr32, ClassGpr32Sp, ClassGpr64, ClassGpr64Sp,
		ClassSimdB, ClassSimdH, ClassSimdS, ClassSimdD, ClassSimdQ, ClassSimdVec,
		ClassSveZ, ClassSveP, ClassSvePN, ClassSmeTile:
		// An explicit expression such as D:'1':Zd already inserts the gap
		// between two written register runs.  A separate packed-range mapping
		// would apply that gap twice.
		hasLiteral := false
		for _, part := range c.Split {
			if _, ok := LiteralBits(part); ok {
				hasLiteral = true
				break
			}
		}
		if !hasLiteral {
			if ranges, ok := parseDisjointRegRanges(prose); ok {
				c.RegRanges = ranges
			} else {
				c.RegLo, c.RegHi, c.HasRegRange = parseRegRange(prose)
			}
		}
		if strings.Contains(strings.ToLower(prose), "even-numbered register") {
			c.RegMultiple = 2
		}
	}
	return c
}

// encodedDivisor recognizes ARM's direct scaled-field relation:
// "encoded in hw as <shift>/16". This is intentionally a small scanner rather
// than a permissive expression parser; other slashes in descriptive prose must
// not silently change operand semantics.
func encodedDivisor(prose string) (int64, bool) {
	lower := strings.ToLower(prose)
	as := strings.LastIndex(lower, " encoded ")
	if as < 0 {
		as = strings.LastIndex(lower, "encoded ")
	}
	if as < 0 {
		return 0, false
	}
	slash := strings.LastIndexByte(lower[as:], '/')
	if slash < 0 {
		return 0, false
	}
	slash += as
	i := slash + 1
	for i < len(lower) && lower[i] == ' ' {
		i++
	}
	start := i
	for i < len(lower) && lower[i] >= '0' && lower[i] <= '9' {
		i++
	}
	if start == i {
		return 0, false
	}
	endDigits := i
	for i < len(lower) && (lower[i] == ' ' || lower[i] == '.' || lower[i] == ',') {
		i++
	}
	if i != len(lower) {
		return 0, false
	}
	value, err := strconv.ParseInt(lower[start:endDigits], 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}

// stripNumericVariant removes ARM's generated "__<number>" collision suffix.
// Checking the suffix directly is both clearer and cheaper than running a
// regular expression for every operand in the ISA.
func stripNumericVariant(s string) string {
	i := strings.LastIndex(s, "__")
	if i < 0 || i+2 == len(s) {
		return s
	}
	for _, c := range s[i+2:] {
		if c < '0' || c > '9' {
			return s
		}
	}
	return s[:i]
}

func parseDisjointRegRanges(prose string) ([]RegRange, bool) {
	matches := regRangeRE.FindAllStringSubmatch(prose, -1)
	if len(matches) < 2 || !strings.Contains(strings.ToLower(prose), " or ") {
		return nil, false
	}
	var out []RegRange
	var encodedLo int64
	for _, m := range matches {
		lo, e1 := strconv.ParseInt(m[2], 10, 64)
		hi, e2 := strconv.ParseInt(m[3], 10, 64)
		if e1 != nil || e2 != nil || hi < lo {
			return nil, false
		}
		duplicate := false
		for _, r := range out {
			if r.Lo == lo && r.Hi == hi {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		out = append(out, RegRange{Lo: lo, Hi: hi, Bias: lo - encodedLo})
		encodedLo += hi - lo + 1
	}
	return out, len(out) > 1
}

// classifySpan decides how a value that spans several fields is placed.
func (c *ClassifiedOperand) classifySpan(prose string) {
	if len(c.Fields) < 2 {
		return
	}
	// A value table already maps whole bit combinations to spellings, so the
	// table drives the encoding and no concatenation is involved.
	if len(c.Explanation.Values) > 0 {
		return
	}
	m := splitOrderRE.FindStringSubmatch(prose)
	if m == nil {
		c.Algorithmic = true
		return
	}
	order := splitFieldList(m[1])
	if !sameFieldSet(baseFields(order), baseFields(c.Fields)) || isComputedSpan(prose, c.Fields) {
		c.Algorithmic = true
		return
	}
	c.Split = order
}

// isComputedSpan reports whether a multi-field value is a computation of the
// fields rather than their concatenation, on ARM's own wording.
func isComputedSpan(prose string, fields []string) bool {
	p := strings.ToLower(prose)
	switch {
	case strings.Contains(p, "bitmask immediate"):
		// N:immr:imms holds a rotated run-length, not the immediate's bits.
		return true
	case strings.Contains(p, "can be encoded in"):
		// MOVZ's alias: a 32-bit value expressible as a shifted 16-bit lane.
		return true
	case strings.Contains(p, "encoded as"):
		return true
	}
	for _, f := range fields {
		// These fields carry the element size, folded together with the index or
		// shift amount rather than concatenated with it. ARM states the range as
		// "0 to number of bits per element minus 1" — element-dependent, so the
		// value is not the fields' concatenation.
		switch f {
		case "tsz", "tszh", "tszl", "tsize":
			return true
		}
	}
	return false
}

// baseFields drops any bit-slice suffix, so "size<1>" compares equal to "size".
func baseFields(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if i := strings.IndexByte(f, '<'); i > 0 {
			f = f[:i]
		}
		out = append(out, f)
	}
	return out
}

func sameFieldSet(a, b []string) bool {
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, y := range b {
		if !seen[y] {
			return false
		}
		delete(seen, y)
	}
	return len(seen) == 0
}

// classifyRelation reads the relation ARM states between the value written in
// assembly and the value the field holds.
//
// Getting this wrong is silent: a multi-vector group base is written Z0, Z2, Z4
// and held as 0, 1, 2, so placing the register number directly would encode
// half the intended register with no error anywhere.
func (c *ClassifiedOperand) classifyRelation(prose, link string) {
	if implicitValueRE.MatchString(prose) {
		// "Is the slice index offset, with implicit value 0": ARM states the
		// value instead of encoding a choice, so there is nothing to pass.
		c.Class = ClassDerived
		if m := implicitValueCapRE.FindStringSubmatch(prose); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			c.Derived = &DerivedRel{Const: n}
		}
		return
	}
	if m := encAsDerivedCapRE.FindStringSubmatch(prose); m != nil &&
		m[1] == c.ResolvedField &&
		strings.Trim(c.Symbol, "<>") == c.ResolvedField &&
		m[2] == "" && m[5] == "" {
		add := m[3]
		if add == "" {
			add = m[4]
		}
		if n, err := strconv.ParseInt(add, 10, 64); err == nil {
			// A primary operand can be stored relative to its own named field:
			// PN8-PN15 is "encoded as PNd plus 8". That is a bias, not a
			// second operand derived from itself.
			c.Bias = n
			return
		}
	}
	if linkPlusRE.MatchString(link) || encAsDerivedRE.MatchString(prose) {
		c.Class = ClassDerived
		c.Derived = derivedRelation(prose, link, c.ResolvedField)
		return
	}
	if m := encAsScaledRE.FindStringSubmatch(prose); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > 1 {
			c.Scale = n
			return
		}
	}
	if m := encAsOffsetRE.FindStringSubmatch(prose); m != nil {
		if n, err := strconv.ParseInt(m[2], 10, 64); err == nil {
			// "encoded as \"imm6\" plus 1": the value is the field plus one, so
			// the field is the value minus one.
			if m[1] == "plus" {
				c.Bias = n
			} else {
				c.Bias = -n
			}
			return
		}
	}
	if m := encAsNegRE.FindStringSubmatch(prose); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			// "encoded as 128 - UInt(\"immh:immb\")": the field counts down from
			// 128, so a shift of 1 is held as 127.
			c.Negate = n
			c.Algorithmic = false
			return
		}
	}
	if m := encAsUIntSubRE.FindStringSubmatch(prose); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			// "encoded as UInt(\"immh:immb\") - 64": field holds value plus 64.
			c.Bias = -n
			return
		}
	}
	if m := encAsExprRE.FindStringSubmatch(prose); m != nil {
		items := strings.Split(m[1], ":")
		if len(items) == 1 && !isLiteralBits(items[0]) {
			// "encoded as \"Zn\"": the field holds the value unchanged.
			c.ResolvedField, c.Fields, c.Split = items[0], items[:1], nil
			c.Algorithmic = false
			return
		}
		fields := make([]string, 0, len(items))
		for _, it := range items {
			if !isLiteralBits(it) {
				fields = append(fields, it)
			}
		}
		if len(fields) > 0 {
			c.Split = items
			c.Fields = fields
			c.ResolvedField = fields[0]
			// classifySpan ran first and saw several fields with no stated order.
			// The expression is that order.
			c.Algorithmic = false
			return
		}
	}
	if encAsAnyRE.MatchString(prose) {
		// An unimplemented relation. Placing the value as though it were the
		// field would be wrong, so the operand is left untyped.
		c.Algorithmic = true
	}
}

// derivedRelation reads how a derived operand follows from an encoding field.
//
// The prose states it when there is one. When only the link id does — "WsPlus1"
// on an operand ARM writes <W(s+1)> — the field is the one the operand's own
// explanation resolved to, which is the register the pair starts at.
func derivedRelation(prose, link, resolvedField string) *DerivedRel {
	if m := encAsDerivedCapRE.FindStringSubmatch(prose); m != nil {
		rel := &DerivedRel{Field: m[1], Mul: 1}
		if m[2] != "" {
			rel.Mul, _ = strconv.ParseInt(m[2], 10, 64)
		}
		add := m[3]
		if add == "" {
			add = m[4]
		}
		rel.Add, _ = strconv.ParseInt(add, 10, 64)
		if m[5] != "" {
			rel.Mod, _ = strconv.ParseInt(m[5], 10, 64)
		}
		return rel
	}
	if m := linkPlusRE.FindStringSubmatch(link); m != nil && resolvedField != "" {
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil
		}
		return &DerivedRel{Field: resolvedField, Mul: 1, Add: n}
	}
	return nil
}

// OrdinalMember reports whether ARM describes an operand by its position in a
// group — "the name of the second scalable vector register". Together with the
// operand naming a field an earlier operand already writes, that is ARM saying
// this one follows from that one: only the first member of a list or pair is
// encoded.
func OrdinalMember(prose string) bool {
	p := strings.ToLower(prose)
	return ordinalMemberRE.MatchString(p) &&
		(strings.Contains(p, " group") || strings.Contains(p, " list"))
}

func ordinalMemberOffset(prose string) (int64, bool) {
	p := strings.ToLower(prose)
	m := ordinalMemberRE.FindStringSubmatch(p)
	if m == nil {
		return 0, false
	}
	offsets := map[string]int64{
		"second": 1, "third": 2, "fourth": 3, "fifth": 4,
		"sixth": 5, "seventh": 6, "eighth": 7,
	}
	n, ok := offsets[m[1]]
	return n, ok
}

// operandFieldSlice finds a single quoted field slice belonging to the
// operand's resolved field. It deliberately ignores concatenations such as
// H:L:M:Rm<3>; those are handled by classifySpan as multi-field algorithms.
func operandFieldSlice(prose, resolved string) (string, bool) {
	for i := 0; i < len(prose); i++ {
		if prose[i] != '"' {
			continue
		}
		start := i + 1
		end := start
		for end < len(prose) && prose[end] != '"' {
			end++
		}
		if end == len(prose) {
			return "", false
		}
		candidate := prose[start:end]
		base, _, _, sliced := parseFieldSlice(candidate)
		if sliced && (resolved == "" || strings.EqualFold(base, resolved)) {
			return candidate, true
		}
		i = end
	}
	return "", false
}

// isLiteralBits reports whether a field-expression item is a quoted run of
// constant bits rather than a field name.
func isLiteralBits(s string) bool {
	return len(s) > 2 && s[0] == '\'' && s[len(s)-1] == '\''
}

// LiteralBits returns the constant bits of a field-expression item.
func LiteralBits(s string) (string, bool) {
	if !isLiteralBits(s) {
		return "", false
	}
	return s[1 : len(s)-1], true
}

// parseRegRange reads a register bank restriction such as "W12-W15" or "P0-P7".
// A bank written as two disjoint runs ("Z0-Z7 or Z16-Z23") is not a range and is
// rejected, since encoding it needs ARM's own bit layout rather than an offset.
func parseRegRange(prose string) (lo, hi int64, ok bool) {
	m := regRangeRE.FindStringSubmatchIndex(prose)
	if m == nil {
		return 0, 0, false
	}
	rest := prose[m[1]:]
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rest)), "or ") &&
		regRangeRE.MatchString(rest) {
		return 0, 0, false
	}
	l, e1 := strconv.ParseInt(prose[m[4]:m[5]], 10, 64)
	h, e2 := strconv.ParseInt(prose[m[6]:m[7]], 10, 64)
	if e1 != nil || e2 != nil || h <= l {
		return 0, 0, false
	}
	return l, h, true
}

func classOf(sym, hover, link string) OperandClass {
	switch {
	// Arrangement and size specifiers modify the register they attach to.
	case sym == "T" || sym == "Ta" || sym == "Tb" || sym == "Ts" || sym == "V" ||
		(sym == "Va" || sym == "Vb" || sym == "R") &&
			!strings.Contains(hover, "name of") &&
			!strings.Contains(hover, "register"):
		return ClassArrangement

	// Test label before condition: a conditional branch's label reads "to be
	// conditionally branched to", and "conditionally" contains "condition".
	case strings.Contains(hover, "program label") || strings.Contains(hover, "label to be"):
		return ClassLabel
	case sym == "cond" || strings.HasPrefix(link, "cond") ||
		strings.Contains(hover, "standard conditions") ||
		strings.Contains(hover, "condition code"):
		return ClassCond
	case strings.Contains(hover, "system register") || strings.Contains(hover, "systemreg"):
		return ClassSysReg

	case strings.Contains(hover, "za tile") || strings.HasPrefix(sym, "ZA"):
		return ClassSmeTile
	case strings.Contains(hover, "predicate-as-counter"):
		return ClassSvePN
	case strings.Contains(hover, "scalable predicate") || strings.Contains(hover, "predicate register"):
		return ClassSveP
	case strings.Contains(hover, "scalable vector register") ||
		strings.Contains(hover, "control vector register") ||
		strings.Contains(hover, "table vector register"):
		return ClassSveZ

	case strings.Contains(hover, "general-purpose") ||
		strings.Contains(hover, "vector select register") ||
		strings.Contains(hover, "slice index register"):
		sp := strings.Contains(hover, "stack pointer") || strings.Contains(sym, "SP")
		if is64BitGpr(sym, hover) {
			if sp {
				return ClassGpr64Sp
			}
			return ClassGpr64
		}
		if sp {
			return ClassGpr32Sp
		}
		return ClassGpr32

	case strings.Contains(hover, "simd") && strings.Contains(hover, "fp"):
		// Scalar SIMD&FP operands are named by width: <Bd> <Hd> <Sd> <Dd> <Qd>.
		// A bare number (<d>, <n>, <m>) takes its width from the specifier or
		// literal that precedes it in the template, resolved by the caller.
		if len(sym) >= 2 {
			switch sym[0] {
			case 'B':
				return ClassSimdB
			case 'H':
				return ClassSimdH
			case 'S':
				return ClassSimdS
			case 'D':
				return ClassSimdD
			case 'Q':
				return ClassSimdQ
			case 'V':
				return ClassSimdVec
			}
		}
		if isRegNumberSymbol(sym) {
			return ClassSimdVec
		}
		return ClassUnsupported

	case (strings.HasPrefix(link, "shift") || sym == "shift") &&
		!strings.Contains(hover, "shift amount") &&
		!strings.Contains(hover, "immediate") &&
		!rangeRE.MatchString(hover):
		return ClassShift
	case strings.HasPrefix(link, "extend") || sym == "extend":
		return ClassExtend

	case strings.Contains(hover, "immediate") || strings.Contains(hover, "offset") ||
		strings.Contains(hover, "shift amount") || strings.Contains(hover, "number of bits") ||
		strings.Contains(hover, "bit number") || strings.Contains(hover, "index") ||
		strings.HasPrefix(strings.ToLower(sym), "imm"):
		return ClassImm

	default:
		return ClassUnsupported
	}
}

// literalWidthClass reads a scalar SIMD&FP width written as a literal letter
// immediately before a bare register number, as in "D<d>".
func literalWidthClass(prefix string) (OperandClass, bool) {
	t := strings.TrimRight(prefix, " \t")
	if t == "" {
		return "", false
	}
	last := t[len(t)-1]
	// A mnemonic ending in the same letter must not be mistaken for a width, so
	// the letter has to stand alone.
	if len(t) > 1 {
		prev := t[len(t)-2]
		if prev >= 'A' && prev <= 'Z' || prev >= 'a' && prev <= 'z' {
			return "", false
		}
	}
	switch last {
	case 'B':
		return ClassSimdB, true
	case 'H':
		return ClassSimdH, true
	case 'S':
		return ClassSimdS, true
	case 'D':
		return ClassSimdD, true
	case 'Q':
		return ClassSimdQ, true
	}
	return "", false
}

// isRegNumberSymbol matches the bare register-number placeholders <d>, <n>,
// <m>, <a>, <t>: a single lower-case letter naming a SIMD&FP register whose
// width comes from a separate specifier.
func isRegNumberSymbol(sym string) bool {
	// One or two lower-case letters: <d>, <n>, <m>, and the source-and-
	// destination <dn> of a destructive SIMD&FP instruction.
	if len(sym) < 1 || len(sym) > 2 {
		return false
	}
	for i := 0; i < len(sym); i++ {
		if sym[i] < 'a' || sym[i] > 'z' {
			return false
		}
	}
	return true
}

// is64BitGpr distinguishes X from W operands. ARM's prose states the width.
func is64BitGpr(sym, hover string) bool {
	if strings.Contains(hover, "64-bit") {
		return true
	}
	if strings.Contains(hover, "32-bit") {
		return false
	}
	return strings.HasPrefix(sym, "X")
}

// parseDefaultValue reads ARM's default operand spelling as an encoded value.
// Register names encode as their number; XZR and WZR encode as 31.
func parseDefaultValue(s string) (int64, bool) {
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	up := strings.ToUpper(t)
	switch up {
	case "XZR", "WZR", "SP", "WSP":
		return 31, true
	case "LSL":
		return 0, true
	}
	if len(up) > 1 && (up[0] == 'X' || up[0] == 'W' || up[0] == 'V') {
		if n, err := strconv.ParseInt(up[1:], 10, 64); err == nil && n >= 0 && n <= 31 {
			return n, true
		}
	}
	if n, err := strconv.ParseInt(t, 10, 64); err == nil {
		return n, true
	}
	return 0, false
}

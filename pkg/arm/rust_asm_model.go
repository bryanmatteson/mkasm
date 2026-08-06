package arm

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// AddressingMode is the memory operand form an encoding accepts.
type AddressingMode string

const (
	AddrNone   AddressingMode = ""        // no memory operand
	AddrBase   AddressingMode = "base"    // [Xn]
	AddrOffset AddressingMode = "offset"  // [Xn, #imm]
	AddrPre    AddressingMode = "pre"     // [Xn, #imm]!
	AddrPost   AddressingMode = "post"    // [Xn], #imm
	AddrRegOff AddressingMode = "reg_off" // [Xn, Xm{, extend}]
)

// BitPart is one field a split value occupies, or a run of constant bits the
// value must contain.
type BitPart struct {
	Field      string
	Start, End int
	Width      int
	// Literal holds the constant bits when this part is not a field: the base
	// register of a strided multi-vector group is "T:'00':Zt", and a register
	// outside that group is simply not encodable here.
	Literal string
	IsLit   bool
}

// Placement binds a method parameter to a bit range in the instruction word.
type Placement struct {
	Param string // Rust parameter expression, e.g. "rn" or "mem.base"
	Field string
	Start int // low bit
	End   int // high bit
	Width int
	// Parts is set when the value spans several fields: one entry per field,
	// most significant first. Width is then the total across all parts.
	Parts []BitPart
	// Scale is the encoding multiplier: a byte offset divides by Scale.
	Scale int64
	// Signed marks a two's-complement field.
	Signed bool
	// Lo/Hi bound the accepted value before scaling.
	Lo, Hi   int64
	HasRange bool
	// Bias is subtracted before encoding: the SME vector-select register is
	// written W12-W15 and held in a 2-bit field as v-12.
	Bias int64
	// Negate is the constant the field counts down from, 0 when it counts up.
	Negate int64
	// Default is what ARM encodes when the operand is omitted (RET's Rn = 30).
	Default    int64
	HasDefault bool
	// Xor is applied to the raw caller value before placement.
	Xor uint32
	// RegRanges maps disjoint written register banks into consecutive field
	// values.
	RegRanges []RegRange
}

// ArrCase is one legal arrangement of a form, resolved to the bits it sets.
type ArrCase struct {
	// Symbol is the assembler spelling, e.g. "8B" or "S".
	Symbol string
	// Or is the value to OR into the word for this arrangement.
	Or uint32
}

// ArrDispatch is the arrangement match emitted for one sized register operand.
type ArrDispatch struct {
	Param string
	// Mask covers every bit the arrangement controls, so the fixed word's bits
	// there can be cleared before the arrangement's value is applied.
	Mask  uint32
	Cases []ArrCase
	// Shared is the subset of Mask an earlier operand already committed. Those
	// bits must agree rather than being written twice.
	Shared uint32
	// Lead names the local holding the earlier operand's selected bits.
	Lead string
}

// EnumDispatch is the match emitted for an operand ARM defines by a value table
// of assembler spellings.
type EnumDispatch struct {
	Param      string
	Type       string
	Mask       uint32
	Cases      []ArrCase
	Exhaustive bool
	DefaultOr  uint32
	HasDefault bool
}

// AsmForm is one concrete operand shape of one mnemonic: exactly one Rust trait
// impl, encoding exactly one ARM encoding.
type AsmForm struct {
	Method     string
	EncodingID string
	Mnemonic   string
	AsmSyntax  string
	FixedWord  uint32
	Pattern    string
	Params     []Param
	Tuple      []string
	Placements []Placement
	Mode       AddressingMode
	IsAlias    bool
	AliasOf    string
	// ModeVariants holds sibling encodings that share this form's parameter
	// types and differ only in addressing mode: `ldr x0,[x1],#8` (post),
	// `ldr x0,[x1,#8]!` (pre) and `ldr x0,[x1,#8]` (offset) are one Rust
	// method that matches on the Mem operand's mode.
	ModeVariants []ModeVariant
	// RequiredArity is how many leading parameters are mandatory; the rest are
	// optional operands the plain method omits.
	RequiredArity int
	// Arrangements is the arrangement dispatch for sized vector operands.
	Arrangements []ArrDispatch
	// Enums is the dispatch for enumerated operands.
	Enums []EnumDispatch
	// BaseISA marks a base or SIMD&FP encoding rather than an SVE or SME one.
	//
	// ARM capitalises base and SIMD&FP encoding ids ("ADR_only_pcreladdr") and
	// writes SVE and SME ones in lower case ("adr_z_az_sd_same_scaled"). That
	// holds for every encoding in the spec — no iclass mixes the two — so it is
	// a reliable way to let the common scalar form keep the bare method name
	// when an SVE form of the same mnemonic has more operands.
	BaseISA bool
}

// ModeVariant is one addressing-mode alternative of a form.
type ModeVariant struct {
	Mode       AddressingMode
	EncodingID string
	FixedWord  uint32
	Pattern    string
	Placements []Placement
}

// ExactEncoding is the field-level encoder generated for every encoding in the
// ISA, whether or not its operands could be given a typed signature. It is what
// makes the crate complete: each of ARM's encodings has one named function that
// sets exactly its settable fields over its fixed word.
type ExactEncoding struct {
	// Fn is the Rust function name, derived from the ARM encoding id.
	Fn         string
	EncodingID string
	Mnemonic   string
	AsmSyntax  string
	FixedWord  uint32
	Pattern    string
	Fields     []RawField
	// FixedLegal reports whether the zeroed settable fields satisfy this
	// encoding's bitdiff constraints. Some exact encoders have no legal zero
	// base (for example, SIMD shifts require immh != 0).
	FixedLegal bool
	// AliasOf names the encoding this one is an alias of, empty when canonical.
	AliasOf string
	// Typed is true when this encoding also has an operand-typed method.
	Typed bool
}

// AsmSurface is the whole generated assembler API.
type AsmSurface struct {
	// Methods maps a Rust method name to its overload set (one trait impl each).
	Methods map[string][]AsmForm
	// MethodOrder is Methods' keys, sorted, for deterministic output.
	MethodOrder []string
	// Exact holds one field-level encoder per ARM encoding, in id order.
	Exact []ExactEncoding
	// Raw holds encodings with no typed signature, reachable via the exact API.
	Raw []RawEncoding
	// Enums are the generated value-table types, keyed by Rust type name.
	Enums map[string]*EnumSpec
	// Dropped records encodings excluded from every surface, with the reason.
	Dropped map[string]string
}

// RawEncoding is an encoding exposed only through the field-level exact API.
type RawEncoding struct {
	EncodingID string
	Mnemonic   string
	AsmSyntax  string
	FixedWord  uint32
	Pattern    string
	Fields     []RawField
	Reason     string
}

// RawField is one settable field of an encoding.
type RawField struct {
	Name       string
	Start, End int
	Width      int
	// Free masks the bits of this field the encoding leaves settable. A field
	// can be partly pinned — UMOV's 64-bit form fixes imm5 to x1000 — and
	// writing the whole field would erase the bits that select the element size.
	Free uint32
}

// memImmSymbols are the operand symbols that appear inside [] brackets as the
// offset rather than as a standalone immediate.
func isMemOffsetSymbol(sym string) bool {
	switch strings.Trim(sym, "<>") {
	case "pimm", "simm", "imm", "offset":
		return true
	}
	return false
}

// detectAddressingMode reads the bracket syntax of an asmtemplate.
func detectAddressingMode(asm string) AddressingMode {
	if !strings.Contains(asm, "[") {
		return AddrNone
	}
	// Normalised templates keep spaces around punctuation, so match loosely.
	compact := strings.ReplaceAll(asm, " ", "")
	switch {
	case strings.Contains(compact, "]!"):
		return AddrPre
	case strings.Contains(compact, "],#"):
		return AddrPost
	}
	// Distinguish [Xn, Xm] from [Xn, #imm] and bare [Xn].
	open := strings.Index(compact, "[")
	close := strings.Index(compact[open:], "]")
	if close < 0 {
		return AddrBase
	}
	inner := compact[open+1 : open+close]
	switch {
	case strings.Contains(inner, "#"):
		return AddrOffset
	case strings.Count(inner, ",") > 0:
		return AddrRegOff
	default:
		return AddrBase
	}
}

// BuildAsmSurface projects resolved IR into the typed assembler API plus the
// field-level encoders that make every encoding reachable exactly.
func BuildAsmSurface(instrs []*ir.InstructionIR, load func(*ir.InstructionIR) *ParsedIForm) *AsmSurface {
	s := &AsmSurface{
		Methods: map[string][]AsmForm{},
		Enums:   map[string]*EnumSpec{},
		Dropped: map[string]string{},
	}
	// Two encodings reaching the same (method, tuple) would be conflicting Rust
	// impls. When they differ only in addressing mode they merge into one impl
	// that dispatches on the Mem operand; otherwise the later one keeps its own
	// typed method under a name derived from its encoding id.
	claimed := map[string]*AsmForm{}
	// usedNames reserves every Rust function name on Assembler. The field-level
	// encoders are named from encoding ids, which are unique, and the typed
	// methods must not collide with them.
	usedNames := map[string]bool{}
	// Forms are built first and named second, so the naming can prefer the form
	// that fits each signature exactly.
	type pendingForm struct {
		form   *AsmForm
		method string
		instr  *ir.InstructionIR
	}
	var pending []pendingForm

	sorted := append([]*ir.InstructionIR(nil), instrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].EncodingID < sorted[j].EncodingID })

	// Pass 1: one exact encoder per encoding. This is unconditional, so the
	// generated crate covers the whole ISA regardless of how many operand
	// shapes get a friendlier signature below.
	exactOf := map[string]int{}
	for _, instr := range sorted {
		fw, hasFixed := ir.FixedWord(instr)
		if !hasFixed {
			s.Dropped[instr.EncodingID] = "no fixed bits"
			continue
		}
		p := load(instr)
		asm, mnem := "", instr.Mnemonic
		if p != nil {
			asm = p.AsmTemplate
			if m := AsmMnemonic(p.AsmTemplate); m != "" {
				mnem = m
			}
		}
		// The exact encoders take positional field values, so they live in their
		// own `enc_` namespace: it says so at the call site, and it leaves the
		// encoding-id-derived names free for the typed methods that need one to
		// distinguish two instructions reading alike.
		fn := uniqueName("enc_"+MethodName(instr.EncodingID), usedNames)
		exactOf[instr.EncodingID] = len(s.Exact)
		s.Exact = append(s.Exact, ExactEncoding{
			Fn: fn, EncodingID: instr.EncodingID, Mnemonic: mnem,
			AsmSyntax: asm, FixedWord: fw, Pattern: instr.BitPattern,
			Fields: rawFields(instr), FixedLegal: ir.MatchWord(instr, fw), AliasOf: instr.AliasOf,
		})
	}

	// Pass 2: operand-typed methods for every encoding whose operands ARM
	// describes well enough to place without guessing.
	for _, instr := range sorted {
		if _, dropped := s.Dropped[instr.EncodingID]; dropped {
			continue
		}
		p := load(instr)
		fw, _ := ir.FixedWord(instr)
		if p == nil {
			s.Raw = append(s.Raw, rawOf(instr, "", fw, "iform unavailable"))
			continue
		}
		raw := func(reason string) {
			s.Raw = append(s.Raw, rawOf(instr, p.AsmTemplate, fw, reason))
		}

		method := MethodName(AsmMnemonic(p.AsmTemplate))
		exps := ExplanationsFor(p.Explanations, instr.EncodingID)
		params, why := TypedParamsFor(p.AsmTemplate, p.AsmOperands, exps)
		negates := decodeFieldNegates(p.Pseudocode)
		regRestrictions := decodeRegisterRestrictions(p.Pseudocode)
		for i := range params {
			if n, ok := negates[params[i].Field]; ok {
				params[i].Negate = n
				params[i].Bias = 0
			}
			if r, ok := regRestrictions[params[i].Field]; ok && registerClass(params[i].Class) {
				params[i].RegMultiple = r.Multiple
				params[i].RegLo, params[i].RegHi, params[i].HasRegRange = r.Lo, r.Hi, r.HasRange
			}
		}
		if why == "" && method == "" {
			why = "no mnemonic in the asm template"
		}
		if why != "" {
			raw(why)
			continue
		}
		MarkOptional(p.AsmTemplate, params, p.AsmOperands, exps)
		if arity := systemOperationRegisterArity(p.AliasCond); arity != 0 {
			for i := range params {
				base, _, _, sliced := parseFieldSlice(params[i].Field)
				if !sliced {
					base = params[i].Field
				}
				if base != "Rt" || !registerClass(params[i].Class) {
					continue
				}
				params[i].Optional = false
				params[i].HasDefault = false
				if arity == 2 {
					params[i].RegMultiple = 2
					params[i].RegLo, params[i].RegHi, params[i].HasRegRange = 0, 30, true
				}
			}
		}
		ApplySelectorConstraints(params)
		// Intern value-table types before the form captures their names: a link
		// id whose table differs from an earlier one is renamed here, and the
		// dispatch must reference the name that is actually emitted.
		for i := range params {
			if params[i].Enum != nil {
				s.registerEnum(params[i].Enum)
				// registerEnum may have renamed the type; the parameter must
				// name the type that is actually emitted.
				params[i].RustType = params[i].Enum.Name
			}
		}

		mode := detectAddressingMode(p.AsmTemplate)
		// One encoding can present as several operand shapes when ARM writes a
		// register's width as a separate specifier.
		variants := ExpandWidthCases(params)
		if variants == nil {
			raw("more than one width specifier")
			continue
		}
		var built []*AsmForm
		var buildErr error
		for _, v := range variants {
			form, err := buildForm(instr, p, method, v, mode, fw)
			if err != nil {
				buildErr = err
				break
			}
			built = append(built, form)
		}
		if buildErr != nil {
			raw(buildErr.Error())
			continue
		}
		for _, form := range built {
			pending = append(pending, pendingForm{form: form, method: method, instr: instr})
		}
	}

	// Placement order decides which encoding owns a shared signature, so it is
	// by fit rather than by name: a form whose whole parameter list matches the
	// call is a better answer than one that reaches the same arity by leaving
	// operands out. MOVI's plain byte form and its shifted-immediate form are
	// both callable as (VecOp, u32), and only the first accepts .8B.
	sort.SliceStable(pending, func(i, j int) bool {
		oi := len(pending[i].form.Params) - pending[i].form.RequiredArity
		oj := len(pending[j].form.Params) - pending[j].form.RequiredArity
		if oi != oj {
			return oi < oj
		}
		return pending[i].instr.EncodingID < pending[j].instr.EncodingID
	})
	for _, pf := range pending {
		if s.place(pf.form, pf.method, pf.instr, claimed, usedNames) {
			s.Exact[exactOf[pf.instr.EncodingID]].Typed = true
		}
	}
	for _, pf := range pending {
		if !s.Exact[exactOf[pf.instr.EncodingID]].Typed {
			s.Raw = append(s.Raw, rawOf(pf.instr, pf.form.AsmSyntax, pf.form.FixedWord, "operand shape already taken"))
		}
	}

	for m := range s.Methods {
		s.MethodOrder = append(s.MethodOrder, m)
		forms := s.Methods[m]
		// Same preference as placement, so the impl the emitter keeps for a
		// shared signature is the one that claimed it.
		sort.SliceStable(forms, func(i, j int) bool {
			oi := len(forms[i].Params) - forms[i].RequiredArity
			oj := len(forms[j].Params) - forms[j].RequiredArity
			if oi != oj {
				return oi < oj
			}
			return forms[i].EncodingID < forms[j].EncodingID
		})
		s.Methods[m] = forms
	}
	sort.Strings(s.MethodOrder)
	sort.Slice(s.Raw, func(i, j int) bool { return s.Raw[i].EncodingID < s.Raw[j].EncodingID })
	return s
}

// place installs one form in the surface, merging it into a sibling that differs
// only in addressing mode, or naming it after its encoding when another
// instruction already reads the same way at the call site.
func (s *AsmSurface) place(form *AsmForm, method string, instr *ir.InstructionIR, claimed map[string]*AsmForm, usedNames map[string]bool) bool {
	keys := formKeys(method, form)
	free := make([]string, 0, len(keys))
	var prev *AsmForm
	for _, k := range keys {
		if p, ok := claimed[k]; ok {
			if prev == nil {
				prev = p
			}
			continue
		}
		free = append(free, k)
	}
	// A form callable at two arities may lose one of them to another encoding and
	// still be reachable at the other, which is how MOVI's shifted-immediate form
	// keeps the name `movi` for its three-operand call while the plain byte form
	// owns the two-operand one.
	if prev != nil && len(free) > 0 {
		keys = free
		prev = nil
	}
	if prev != nil {
		// Same parameter types, different addressing mode: one method that
		// matches on the Mem operand covers both.
		if form.Mode != AddrNone && prev.Mode != AddrNone && !prev.hasMode(form.Mode) {
			prev.ModeVariants = append(prev.ModeVariants, ModeVariant{
				Mode:       form.Mode,
				EncodingID: form.EncodingID,
				FixedWord:  form.FixedWord,
				Pattern:    form.Pattern,
				Placements: form.Placements,
			})
			return true
		}
		// Genuinely distinct instructions that read the same at the call site —
		// the scalar and fp16 SIMD forms. Give the later one its own method named
		// after its encoding, rather than hiding it.
		alt := disambiguatedMethod(method, instr.EncodingID, usedNames)
		if alt == "" {
			return false
		}
		form.Method = alt
		method = alt
		keys = formKeys(method, form)
		for _, k := range keys {
			if _, ok := claimed[k]; ok {
				return false
			}
		}
	}
	usedNames[method] = true
	form.ModeVariants = []ModeVariant{{
		Mode: form.Mode, EncodingID: form.EncodingID, FixedWord: form.FixedWord,
		Pattern: form.Pattern, Placements: form.Placements,
	}}
	s.Methods[method] = append(s.Methods[method], *form)
	stored := &s.Methods[method][len(s.Methods[method])-1]
	for _, k := range keys {
		claimed[k] = stored
	}
	return true
}

// formKeys lists the Rust impls a form will occupy: one per arity it is callable
// at, since a method with optional trailing operands is emitted twice.
//
// Keying on the full parameter tuple alone is not enough. PMOV's byte form takes
// (PReg, ZReg) and its doubleword form takes (PReg, ZReg, u32) with the index
// optional, so both are callable as two arguments — one impl, two encodings, and
// whichever lost would be silently unreachable while still counted as covered.
func formKeys(method string, f *AsmForm) []string {
	arities := []int{len(f.Params)}
	if f.RequiredArity != len(f.Params) {
		arities = append(arities, f.RequiredArity)
	}
	out := make([]string, 0, len(arities))
	for _, n := range arities {
		if n > len(f.Params) {
			n = len(f.Params)
		}
		ts := make([]string, 0, n)
		for _, p := range f.Params[:n] {
			ts = append(ts, p.RustType)
		}
		out = append(out, fmt.Sprintf("%s/%d(%s)", method, n, strings.Join(ts, ",")))
	}
	return out
}

// registerEnum interns a value-table type. Two instructions sharing an operand
// class share the Rust enum; a link id whose table differs gets its own type so
// no spelling is silently encoded with another instruction's bits.
func (s *AsmSurface) registerEnum(spec *EnumSpec) {
	if rustReservedEnumTypes[spec.Name] {
		spec.Name += "Value"
	}
	if prev, ok := s.Enums[spec.Name]; ok {
		if sameEnumTable(prev, spec) {
			return
		}
		for i := 2; ; i++ {
			alt := fmt.Sprintf("%s%d", spec.Name, i)
			p2, ok := s.Enums[alt]
			if !ok {
				spec.Name = alt
				s.Enums[alt] = spec
				return
			}
			if sameEnumTable(p2, spec) {
				spec.Name = alt
				return
			}
		}
	}
	s.Enums[spec.Name] = spec
}

var rustReservedEnumTypes = map[string]bool{
	"Assembler": true, "Arrangement": true, "Cond": true, "Extend": true,
	"Shift": true, "Mem": true, "Label": true, "SysReg": true, "FpImm8": true,
	"WReg": true, "WSpReg": true, "XReg": true, "XSpReg": true,
	"VReg": true, "ZReg": true, "PReg": true, "PnReg": true, "ZaTile": true,
}

func sameEnumTable(a, b *EnumSpec) bool {
	if len(a.Rows) != len(b.Rows) || len(a.Fields) != len(b.Fields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i] != b.Fields[i] {
			return false
		}
	}
	for i := range a.Rows {
		if a.Rows[i].Symbol != b.Rows[i].Symbol || len(a.Rows[i].Bits) != len(b.Rows[i].Bits) {
			return false
		}
		for j := range a.Rows[i].Bits {
			if a.Rows[i].Bits[j] != b.Rows[i].Bits[j] {
				return false
			}
		}
	}
	return true
}

func rawOf(instr *ir.InstructionIR, asm string, fw uint32, reason string) RawEncoding {
	return RawEncoding{
		EncodingID: instr.EncodingID,
		Mnemonic:   instr.Mnemonic,
		AsmSyntax:  asm,
		FixedWord:  fw,
		Pattern:    instr.BitPattern,
		Fields:     rawFields(instr),
		Reason:     reason,
	}
}

func uniqueName(base string, used map[string]bool) string {
	if base == "" {
		base = "enc"
	}
	name := base
	for used[name] {
		name += "_"
	}
	used[name] = true
	return name
}

// disambiguatedMethod names a second instruction that reads identically at the
// call site, after the part of its encoding id that distinguishes it.
func disambiguatedMethod(method, encodingID string, used map[string]bool) string {
	tail := MethodName(encodingID)
	if tail == "" {
		return ""
	}
	if !strings.HasPrefix(tail, method+"_") {
		// Aliases and group names do not always share the method's spelling.
		tail = method + "_" + tail
	}
	if used[tail] {
		return ""
	}
	return tail
}

// buildForm resolves parameters to bit placements, folding a memory operand's
// base register and offset into one Mem parameter.
func buildForm(instr *ir.InstructionIR, p *ParsedIForm, method string, params []Param, mode AddressingMode, fw uint32) (*AsmForm, error) {
	byName := map[string]ir.BitField{}
	for _, f := range instr.Encoding.Fields {
		byName[f.Name] = f
	}
	fixedMask, fixedValue := ir.FixedBitsFromPattern(instr.BitPattern)

	f := &AsmForm{
		Method:     method,
		EncodingID: instr.EncodingID,
		Mnemonic:   AsmMnemonic(p.AsmTemplate),
		AsmSyntax:  p.AsmTemplate,
		FixedWord:  fw,
		Pattern:    instr.BitPattern,
		Mode:       mode,
		IsAlias:    instr.AliasOf != "",
		AliasOf:    instr.AliasOf,
		BaseISA:    instr.EncodingID != "" && instr.EncodingID[0] >= 'A' && instr.EncodingID[0] <= 'Z',
	}

	var memBase, memOff *Param
	for i := range params {
		prm := params[i]
		if mode != AddrNone && mode != AddrRegOff {
			// The base register is the Xn|SP operand inside the brackets.
			if memBase == nil && prm.Class == ClassGpr64Sp && strings.Contains(prm.Name, "n") {
				memBase = &params[i]
				continue
			}
			if memBase != nil && memOff == nil && prm.Class == ClassImm && isMemOffsetSymbol(prm.Name) {
				memOff = &params[i]
				continue
			}
		}
		f.Params = append(f.Params, prm)
	}

	if memBase != nil {
		// One Mem parameter replaces base+offset at the base's position.
		f.Params = append(f.Params, Param{
			Name: "mem", RustType: "Mem", Class: ClassGpr64Sp, Field: memBase.Field,
		})
	}

	for i := range f.Params {
		prm := &f.Params[i]
		if len(prm.WidthFields) > 0 {
			// The width specifier's bits are constant for this variant, so they
			// belong in the fixed word rather than in a runtime match.
			cases, mask, err := resolveTable(prm.WidthFields, []ArrRow{{Symbol: "", Bits: prm.WidthBits}}, byName, fw, fixedMask)
			if err != nil {
				return nil, err
			}
			f.FixedWord = f.FixedWord&^mask | cases[0].Or
		}
		if prm.RustType == "Mem" {
			bf, ok := lookupField(memBase.Field, byName)
			if !ok {
				return nil, fmt.Errorf("memory base field %q absent from encoding", memBase.Field)
			}
			f.Placements = append(f.Placements, Placement{
				Param: "mem.base.raw()", Field: bf.Name,
				Start: bf.Start, End: bf.End, Width: bf.End - bf.Start + 1, Scale: 1,
			})
			if memOff != nil {
				pl, err := placementFor(memOff, "mem.offset", byName, fixedMask, fixedValue)
				if err != nil {
					return nil, err
				}
				f.Placements = append(f.Placements, *pl)
			}
			continue
		}
		if prm.Enum != nil {
			d, err := resolveEnum(prm, byName, fw, fixedMask)
			if err != nil {
				return nil, err
			}
			f.Enums = append(f.Enums, *d)
			continue
		}
		pl, err := placementFor(prm, encodeExpr(*prm), byName, fixedMask, fixedValue)
		if err != nil {
			return nil, err
		}
		f.Placements = append(f.Placements, *pl)
		for _, field := range prm.Mirrors {
			mirror := *prm
			mirror.Field = field
			mirror.Split = nil
			mirror.Mirrors = nil
			mpl, err := placementFor(&mirror, encodeExpr(mirror), byName, fixedMask, fixedValue)
			if err != nil {
				return nil, err
			}
			f.Placements = append(f.Placements, *mpl)
		}
	}
	if err := applyAliasConstraints(f, p.AliasCond, byName); err != nil {
		return nil, err
	}
	if err := applyEquivalentDefaults(f, p.EquivalentOperands, byName); err != nil {
		return nil, err
	}

	// Resolve arrangement tables to concrete bit values. Several operands of one
	// instruction usually share the arrangement (ABS <Vd>.<T>, <Vn>.<T>), so the
	// first drives the encoding and the rest only have to agree on the bits they
	// have in common with it.
	var committed uint32
	var leads []ArrDispatch
	for i := range f.Params {
		prm := &f.Params[i]
		if prm.Arr == nil {
			continue
		}
		d, err := resolveArrangement(prm, byName, fw, fixedMask)
		if err != nil {
			return nil, err
		}
		if d.Mask&committed == 0 {
			inferLeadingElementSize(prm, d, byName, fixedMask)
		}
		d.Shared = d.Mask & committed
		if d.Shared != 0 {
			for _, l := range leads {
				if l.Mask&d.Mask != 0 {
					d.Lead = "arr_" + l.Param
					break
				}
			}
		}
		committed |= d.Mask
		leads = append(leads, *d)
		prm.ArrDispatch = d
		f.Arrangements = append(f.Arrangements, *d)
	}

	for _, prm := range f.Params {
		f.Tuple = append(f.Tuple, prm.RustType)
	}
	if len(f.Params) == 0 {
		f.Tuple = nil
	}
	// Optional operands are only omittable from the tail: once a required
	// parameter follows an optional one, the earlier one must be supplied.
	f.RequiredArity = len(f.Params)
	for i := len(f.Params) - 1; i >= 0; i-- {
		if !f.Params[i].Optional {
			break
		}
		f.RequiredArity = i
	}
	return f, nil
}

// applyEquivalentDefaults fixes fields omitted by an alias's entire visible
// template. The equivalent instruction still documents their architectural
// default in its operand hover text.
func applyEquivalentDefaults(f *AsmForm, ops []AsmOperand, byName map[string]ir.BitField) error {
	claimed := map[string]bool{}
	for _, p := range f.Placements {
		if p.Field != "" {
			claimed[p.Field] = true
		}
	}
	for _, op := range ops {
		c := ClassifyOperand(op)
		if !c.HasDefault || c.ResolvedField == "" || claimed[c.ResolvedField] {
			continue
		}
		bf, ok := lookupField(c.ResolvedField, byName)
		if !ok {
			return fmt.Errorf("equivalent default field %q absent from encoding", c.ResolvedField)
		}
		raw := c.Default
		if c.Negate != 0 {
			raw = c.Negate - c.Default
		} else {
			scale := c.Scale
			if scale < 1 {
				scale = 1
			}
			if c.Default%scale != 0 {
				return fmt.Errorf("equivalent default %d is not aligned to scale %d", c.Default, scale)
			}
			raw = c.Default/scale - c.Bias
		}
		width := bf.End - bf.Start + 1
		if raw < 0 || uint64(raw) > uint64(mask(width)) {
			return fmt.Errorf("equivalent default %d does not fit field %s", raw, bf.Name)
		}
		fieldMask := fieldRangeMask(bf.Start, bf.End)
		f.FixedWord = f.FixedWord&^fieldMask | uint32(raw)<<uint(bf.Start)
		claimed[bf.Name] = true
	}
	return nil
}

var (
	aliasFieldEqRE     = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*==\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	aliasBitsEqRE      = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*==\s*'([01]+)'`)
	aliasNextEqRE      = regexp.MustCompile(`(?i)UInt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\+\s*1\s*==\s*UInt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`)
	aliasBitCountOneRE = regexp.MustCompile(`BitCount\s*\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*\)\s*==\s*1`)
)

// applyAliasConstraints supplies the fields an alias template intentionally
// hides. ARM states these relations in <aliascond>, for example Rm == Rn for
// MOV's ORR expansion and Pn == Pm && Pm == Pg for predicate MOV. The visible
// operand owns one placement; every free field in its equality component must
// receive the same value.
func applyAliasConstraints(f *AsmForm, cond string, byName map[string]ir.BitField) error {
	if strings.TrimSpace(cond) == "" {
		return nil
	}

	graph := map[string][]string{}
	for _, m := range aliasFieldEqRE.FindAllStringSubmatch(cond, -1) {
		graph[m[1]] = append(graph[m[1]], m[2])
		graph[m[2]] = append(graph[m[2]], m[1])
	}
	for _, m := range aliasBitsEqRE.FindAllStringSubmatch(cond, -1) {
		bf, ok := lookupField(m[1], byName)
		if !ok {
			return fmt.Errorf("alias condition field %q absent from encoding", m[1])
		}
		if len(m[2]) != bf.End-bf.Start+1 {
			return fmt.Errorf("alias condition %s width %d does not fit field %s width %d",
				m[2], len(m[2]), bf.Name, bf.End-bf.Start+1)
		}
		v, err := strconv.ParseUint(m[2], 2, 32)
		if err != nil {
			return err
		}
		mask := fieldRangeMask(bf.Start, bf.End)
		f.FixedWord = f.FixedWord&^mask | uint32(v)<<uint(bf.Start)
	}
	for _, m := range aliasNextEqRE.FindAllStringSubmatch(cond, -1) {
		left, lok := lookupField(m[1], byName)
		right, rok := lookupField(m[2], byName)
		if !lok || !rok || left.End-left.Start != right.End-right.Start {
			return fmt.Errorf("alias successor fields %s and %s are absent or differ in width", m[1], m[2])
		}
		for i := range f.Placements {
			p := &f.Placements[i]
			if p.Field != right.Name || len(p.Parts) != 0 {
				continue
			}
			width := p.Width
			if p.HasRange && p.Lo == 0 {
				if n, ok := exactPowerOfTwo(p.Hi + 1); ok {
					width = n
				}
			}
			// The 32-bit UBFM encoding allocates six physical bits to immr and
			// imms, but the alias arithmetic is modulo 32 and therefore owns
			// only their low five bits.  Clear any fixed high bits before the
			// narrowed placements are applied; they are constrained by the
			// alias relation, not inherited from the parent encoding pattern.
			if width < p.Width {
				rightWhole := fieldRangeMask(right.Start, right.End)
				rightLow := fieldRangeMask(right.Start, right.Start+width-1)
				leftWhole := fieldRangeMask(left.Start, left.End)
				leftLow := fieldRangeMask(left.Start, left.Start+width-1)
				f.FixedWord &^= (rightWhole &^ rightLow) | (leftWhole &^ leftLow)
				p.End = p.Start + width - 1
				p.Width = width
			}
			p.Negate = int64(1) << uint(width)
			p.Bias = 0
			mirror := *p
			mirror.Field, mirror.Start, mirror.End, mirror.Width =
				left.Name, left.Start, left.Start+width-1, width
			mirror.Negate = (int64(1) << uint(width)) - 1
			f.Placements = append(f.Placements, mirror)
			break
		}
	}

	claimed := map[string]bool{}
	for _, p := range f.Placements {
		if len(p.Parts) == 0 && p.Field != "" {
			claimed[p.Field] = true
		}
	}
	original := append([]Placement(nil), f.Placements...)
	for _, p := range original {
		if len(p.Parts) != 0 || p.Field == "" || len(graph[p.Field]) == 0 {
			continue
		}
		seen := map[string]bool{p.Field: true}
		queue := []string{p.Field}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range graph[cur] {
				if seen[next] {
					continue
				}
				seen[next] = true
				queue = append(queue, next)
				if claimed[next] {
					continue
				}
				bf, ok := lookupField(next, byName)
				if !ok {
					return fmt.Errorf("alias condition field %q absent from encoding", next)
				}
				width := bf.End - bf.Start + 1
				if width != p.Width {
					return fmt.Errorf("alias fields %s and %s have widths %d and %d",
						p.Field, next, p.Width, width)
				}
				mirror := p
				mirror.Field, mirror.Start, mirror.End, mirror.Width = bf.Name, bf.Start, bf.End, width
				f.Placements = append(f.Placements, mirror)
				claimed[next] = true
			}
		}
	}
	return nil
}

// encodeExpr renders the Rust expression that yields a parameter's raw value.
func encodeExpr(prm Param) string {
	switch {
	case registerClass(prm.Class):
		if prm.Arr != nil {
			// A sized operand carries its arrangement alongside the register.
			return prm.Name + ".reg.raw()"
		}
		return prm.Name + ".raw()"
	case prm.Class == ClassSysReg:
		// A system register is a newtype over the 16-bit encoding, which the
		// split placement spreads over o0:op1:CRn:CRm:op2.
		return prm.Name + ".raw()"
	case prm.Class == ClassCond:
		return prm.Name + " as u32"
	case prm.Class == ClassFpImm:
		return prm.Name + ".raw()"
	default:
		return prm.Name
	}
}

// placementFor resolves one parameter to the bits it occupies, spanning several
// fields when ARM states the value is their concatenation.
func placementFor(
	prm *Param,
	expr string,
	byName map[string]ir.BitField,
	fixedMask, fixedValue uint32,
) (*Placement, error) {
	pl := &Placement{
		Param: expr, Scale: prm.Scale, Signed: prm.Lo < 0,
		Lo: prm.Lo, Hi: prm.Hi, HasRange: prm.HasRange,
		Bias:    prm.Bias,
		Negate:  prm.Negate,
		Default: prm.Default, HasDefault: prm.HasDefault,
		Xor:       boolXor(prm.InvertLSB),
		RegRanges: append([]RegRange(nil), prm.RegRanges...),
	}
	names := prm.Split
	if len(names) == 0 {
		names = []string{prm.Field}
	}
	total := 0
	for _, n := range names {
		if bits, isLit := LiteralBits(n); isLit {
			pl.Parts = append(pl.Parts, BitPart{Literal: bits, IsLit: true, Width: len(bits)})
			total += len(bits)
			continue
		}
		bf, ok := lookupField(n, byName)
		if !ok {
			return nil, fmt.Errorf("field %q absent from encoding", n)
		}
		// An operand occupies the bits of its field the encoding leaves free.
		// UMOV's element index is written "encoded in imm5", but the X variant
		// pins imm5 to x1000, so the index is the one free bit — and writing the
		// whole field would erase the pinned bits that select the element size.
		if registerClass(prm.Class) {
			parts := semanticFieldParts(bf, fixedMask, fixedValue)
			pl.Parts = append(pl.Parts, parts...)
			for _, part := range parts {
				total += part.Width
			}
		} else {
			free, err := freeSubRange(bf, fixedMask)
			if err != nil {
				return nil, err
			}
			pl.Parts = append(pl.Parts, free)
			total += free.Width
		}
	}
	pl.Width = total
	for _, part := range pl.Parts {
		if !part.IsLit {
			pl.Field, pl.Start, pl.End = part.Field, part.Start, part.End
			break
		}
	}
	if len(pl.Parts) == 1 && !pl.Parts[0].IsLit {
		pl.Parts = nil
	}

	// A register ARM restricts to part of its bank is held as an offset from the
	// bottom of that range when the field is exactly wide enough for it. An
	// explicit decode bias already describes that mapping (PN8-PN15 is stored
	// as 0-7), so its validation range must remain the architectural register
	// numbers rather than the raw field range.
	if prm.HasRegRange && registerClass(prm.Class) {
		count := prm.RegHi - prm.RegLo + 1
		switch {
		case pl.Bias != 0:
			pl.Lo, pl.Hi, pl.HasRange = prm.RegLo, prm.RegHi, true
		case prm.RegLo == 0 && count <= int64(1)<<uint(total):
			pl.Lo, pl.Hi, pl.HasRange = 0, prm.RegHi, true
		case count == int64(1)<<uint(total):
			pl.Bias = prm.RegLo
			pl.Lo, pl.Hi, pl.HasRange = prm.RegLo, prm.RegHi, true
		default:
			// ARM's stated bank is wider than the field, so the prose range does
			// not describe this encoding's operand. The field width is the hard
			// constraint; leave that to bound it rather than inventing a layout.
		}
	}
	// A complete positive range that exactly fills the field implies an offset
	// encoding even when ARM states the relation only in decode pseudocode.
	// SVE's optional multiplier is 1..16 in imm4 and therefore stores v-1.
	if prm.Class == ClassImm && pl.HasRange && pl.Bias == 0 && pl.Negate == 0 && pl.Lo > 0 {
		scale := pl.Scale
		if scale < 1 {
			scale = 1
		}
		if (pl.Hi-pl.Lo)%scale == 0 &&
			(pl.Hi-pl.Lo)/scale+1 == int64(1)<<uint(total) {
			pl.Bias = pl.Lo
		}
	}
	return pl, nil
}

func (f *AsmForm) hasMode(m AddressingMode) bool {
	for _, v := range f.ModeVariants {
		if v.Mode == m {
			return true
		}
	}
	return f.Mode == m
}

// freeSubRange narrows a field to the bits its encoding does not pin.
//
// Non-contiguous free bits are refused rather than guessed at: the operand's
// layout within the field would be this generator's invention, and the encoding
// stays reachable through its exact encoder either way.
func freeSubRange(bf ir.BitField, fixedMask uint32) (BitPart, error) {
	full := fieldRangeMask(bf.Start, bf.End)
	free := full & ^fixedMask
	if free == 0 {
		return BitPart{}, fmt.Errorf("field %q is fully pinned by the encoding", bf.Name)
	}
	lo := bf.Start
	for free&(1<<uint(lo)) == 0 {
		lo++
	}
	hi := bf.End
	for free&(1<<uint(hi)) == 0 {
		hi--
	}
	if fieldRangeMask(lo, hi) != free {
		return BitPart{}, fmt.Errorf("field %q has non-contiguous free bits", bf.Name)
	}
	return BitPart{Field: bf.Name, Start: lo, End: hi, Width: hi - lo + 1}, nil
}

// lookupField resolves a field reference, including a reference to a bit slice
// of a field. ARM uses angle brackets in prose and square brackets in
// definition tables: cmode<1>, CRm<2:1>, cmode[2:1]. Both describe the same
// least-significant-bit-relative slice.
func lookupField(name string, byName map[string]ir.BitField) (ir.BitField, bool) {
	if bf, ok := byName[name]; ok {
		return bf, true
	}
	base, hi, lo, ok := parseFieldSlice(name)
	if !ok {
		return ir.BitField{}, false
	}
	bf, ok := byName[base]
	if !ok {
		return ir.BitField{}, false
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	width := bf.End - bf.Start + 1
	if hi >= width {
		return ir.BitField{}, false
	}
	return ir.BitField{Name: name, Start: bf.Start + lo, End: bf.Start + hi}, true
}

func parseFieldSlice(s string) (base string, hi, lo int, ok bool) {
	open := strings.IndexAny(s, "<[")
	if open <= 0 || len(s) < open+3 {
		return "", 0, 0, false
	}
	close := byte('>')
	if s[open] == '[' {
		close = ']'
	}
	if s[len(s)-1] != close {
		return "", 0, 0, false
	}
	for i := 0; i < open; i++ {
		if !isFieldNameByte(s[i]) {
			return "", 0, 0, false
		}
	}
	body := s[open+1 : len(s)-1]
	colon := strings.IndexByte(body, ':')
	hiText, loText := body, body
	if colon >= 0 {
		if strings.IndexByte(body[colon+1:], ':') >= 0 {
			return "", 0, 0, false
		}
		hiText, loText = body[:colon], body[colon+1:]
	}
	hi, ok = parseDecimal(hiText)
	if !ok {
		return "", 0, 0, false
	}
	lo, ok = parseDecimal(loText)
	if !ok {
		return "", 0, 0, false
	}
	return s[:open], hi, lo, true
}

func parseDecimal(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func rawFields(instr *ir.InstructionIR) []RawField {
	fixedMask, _ := ir.FixedBitsFromPattern(instr.BitPattern)
	var out []RawField
	seen := map[string]bool{}
	for _, f := range instr.Encoding.Fields {
		if f.Name == "" || strings.HasPrefix(f.Name, "_const_") {
			continue
		}
		if f.Start < 0 || f.End < f.Start {
			continue
		}
		if fieldRangeMask(f.Start, f.End)&^fixedMask == 0 {
			continue // nothing settable
		}
		if seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		out = append(out, RawField{
			Name: f.Name, Start: f.Start, End: f.End, Width: f.End - f.Start + 1,
			Free: fieldRangeMask(f.Start, f.End) &^ fixedMask,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start > out[j].Start })
	return out
}

// resolveArrangement turns an arrangement table into the mask and per-spelling
// OR values for this encoding's field layout.
func resolveArrangement(prm *Param, byName map[string]ir.BitField, fixedWord, fixedMask uint32) (*ArrDispatch, error) {
	d := &ArrDispatch{Param: prm.Name}
	cases, mask, err := resolveTable(prm.Arr.Fields, prm.Arr.Rows, byName, fixedWord, fixedMask)
	if err != nil {
		return nil, err
	}
	d.Cases, d.Mask = cases, mask
	return d, nil
}

// inferLeadingElementSize fills constant parent-field bits omitted from a size
// specifier's table. ARM sometimes defines <T> only over size<0> even though
// the spelling S/D also implies size<1> = 1. The first arrangement using that
// parent field drives the full field; later related specifiers (<Tb>, etc.)
// retain their documented slice so their different spelling scale does not
// conflict with the lead operand.
func inferLeadingElementSize(prm *Param, d *ArrDispatch, byName map[string]ir.BitField, fixedMask uint32) {
	if prm.Arr == nil || len(prm.Arr.Fields) != 1 {
		return
	}
	parentName, _, _, sliced := parseFieldSlice(prm.Arr.Fields[0])
	if !sliced {
		return
	}
	parent, ok := byName[parentName]
	if !ok || parent.End-parent.Start+1 > 3 {
		return
	}
	fullMask := fieldRangeMask(parent.Start, parent.End) &^ fixedMask
	extra := fullMask &^ d.Mask
	if extra == 0 {
		return
	}
	codes := map[string]uint32{"B": 0, "H": 1, "S": 2, "D": 3, "Q": 4}
	for _, c := range d.Cases {
		code, ok := codes[strings.ToUpper(strings.TrimSpace(c.Symbol))]
		if !ok {
			return
		}
		want := code << uint(parent.Start)
		if want&d.Mask != c.Or&d.Mask {
			return
		}
	}
	for i := range d.Cases {
		code := codes[strings.ToUpper(strings.TrimSpace(d.Cases[i].Symbol))]
		d.Cases[i].Or |= (code << uint(parent.Start)) & extra
	}
	d.Mask |= extra
}

// resolveEnum turns a value table into the match arms for an enumerated operand.
func resolveEnum(prm *Param, byName map[string]ir.BitField, fixedWord, fixedMask uint32) (*EnumDispatch, error) {
	cases, mask, err := resolveTable(prm.Enum.Fields, prm.Enum.Rows, byName, fixedWord, fixedMask)
	if err != nil {
		return nil, err
	}
	// The generated enum type can be shared by several encodings. Some accept
	// every variant and some pin part of the table, accepting only a subset.
	// Emit a fallback arm only for the latter: Rust warns (and -D warnings
	// rejects the crate) when a match already names every enum variant.
	all := make(map[string]struct{}, len(prm.Enum.Rows))
	for _, row := range prm.Enum.Rows {
		all[enumVariantIdent(row.Symbol)] = struct{}{}
	}
	covered := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		covered[enumVariantIdent(c.Symbol)] = struct{}{}
	}
	d := &EnumDispatch{
		Param: prm.Name, Type: prm.Enum.Name, Mask: mask, Cases: cases,
		Exhaustive: len(all) == len(covered),
	}
	if prm.HasDefault && prm.DefaultSymbol != "" {
		for _, c := range cases {
			if strings.EqualFold(strings.TrimPrefix(c.Symbol, "#"), strings.TrimPrefix(prm.DefaultSymbol, "#")) {
				d.DefaultOr, d.HasDefault = c.Or, true
				break
			}
		}
	}
	return d, nil
}

func boolXor(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

// resolveTable maps each row of an ARM value table to the word bits it sets.
func resolveTable(fields []string, rows []ArrRow, byName map[string]ir.BitField, fixedWord, fixedMask uint32) ([]ArrCase, uint32, error) {
	type slot struct{ start, width int }
	slots := make([]slot, 0, len(fields))
	var mask uint32
	for _, name := range fields {
		bf, ok := lookupField(name, byName)
		if !ok {
			return nil, 0, fmt.Errorf("table field %q absent from encoding", name)
		}
		w := bf.End - bf.Start + 1
		slots = append(slots, slot{bf.Start, w})
		mask |= fieldRangeMask(bf.Start, bf.End)
	}
	var cases []ArrCase
	for _, row := range rows {
		var or uint32
		bad := false
		for i, bits := range row.Bits {
			if i >= len(slots) || len(bits) != slots[i].width {
				bad = true
				break
			}
			var v uint32
			for _, ch := range bits {
				v <<= 1
				if ch == '1' {
					v |= 1
				}
			}
			or |= v << uint(slots[i].start)
		}
		if bad {
			continue
		}
		// A row whose bits contradict what this encoding pins is not one of its
		// spellings: PTRUE's predicate-as-counter form pins the size bits that
		// the shared pattern table also ranges over.
		if pinned := mask & fixedMask; or&pinned != fixedWord&pinned {
			continue
		}
		cases = append(cases, ArrCase{Symbol: row.Symbol, Or: or})
	}
	if len(cases) == 0 {
		return nil, 0, fmt.Errorf("value table has no usable rows")
	}
	return cases, mask, nil
}

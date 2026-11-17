package arm

import (
	"fmt"
	"sort"
	"strings"
)

// The generated A64 text assembler (templates/rust/assembler.rs.tmpl) is the
// inverse of the generated formatter: it reads the formatter's own Form and
// OperandDef tables. This file emits only what that inversion needs and the
// formatter does not carry: the operand value classes, the mapping from an
// operand definition to its class, the symbol vocabulary of each symbolic
// class, and the deterministic sample words the generated tests use.

// textAsmClass is one value class of the text assembler's uniform operand
// value model. Register classes reuse the formatter's class strings so the
// formatter's register_name spells their values.
type textAsmClass struct {
	Name    string // stable lower-case name, OperandClass::name
	Variant string // Rust enum variant
	Doc     string // one line: what the class is and how its value is numbered; also OperandClass::summary
	Integer bool   // the value is a plain integer the user reads as a number (OperandClass::is_integer)
}

// textAsmClasses is the closed, ordered list of classes. Its order is the
// enum order and therefore part of the generated API.
var textAsmClasses = []textAsmClass{
	{"gpr32", "Gpr32", "W0-W30 and WZR (`<Wn>`); value 31 is WZR.", false},
	{"gpr32sp", "Gpr32Sp", "W0-W30 and WSP (`<Wn|WSP>`); value 31 is WSP.", false},
	{"gpr64", "Gpr64", "X0-X30 and XZR (`<Xn>`); value 31 is XZR.", false},
	{"gpr64sp", "Gpr64Sp", "X0-X30 and SP (`<Xn|SP>`); value 31 is SP.", false},
	{"simdb", "SimdB", "B0-B31.", false},
	{"simdh", "SimdH", "H0-H31.", false},
	{"simds", "SimdS", "S0-S31.", false},
	{"simdd", "SimdD", "D0-D31.", false},
	{"simdq", "SimdQ", "Q0-Q31.", false},
	{"simdvec", "SimdVec", "V0-V31 (the arrangement is a separate operand).", false},
	{"svez", "SveZ", "Z0-Z31.", false},
	{"svep", "SveP", "P0-P15.", false},
	{"svepn", "SvePn", "PN0-PN15.", false},
	{"smetile", "SmeTile", "ZA tiles ZA0-ZA15 (the element size is a separate operand).", false},
	{"imm", "Imm", "An integer printed in decimal: immediates, amounts, indices, register numbers printed after a separate bank letter.", true},
	{"imm_hex", "ImmHex", "An integer printed in hexadecimal: bitmask, byte-mask and move-wide immediates.", true},
	{"label", "Label", "A PC-relative target as a byte displacement from the instruction (`.+N`, `.-N`).", true},
	{"fpimm", "FpImm", "A floating-point immediate; the value is the IEEE-754 binary64 bit pattern.", false},
	{"sysreg", "SysReg", "A system register as `op0<<14 | op1<<11 | CRn<<7 | CRm<<3 | op2`, spelled `S<op0>_<op1>_C<n>_C<m>_<op2>`.", false},
	{"creg", "CReg", "A system control register name C0-C15.", false},
	{"cond", "Cond", "A condition code; the value is the 4-bit condition encoding (EQ=0 ... NV=15).", false},
	{"arrangement", "Arrangement", "An element arrangement or size specifier (8B, 4S, D, W, ...); the value indexes `OperandClass::symbols`.", false},
	{"extend", "Extend", "An extend kind (UXTB ... SXTX); the value indexes `OperandClass::symbols`.", false},
	{"shift", "Shift", "A shift kind (LSL, LSR, ASR, ROR, MSL); the value indexes `OperandClass::symbols`.", false},
	{"enum", "Enum", "Any other named option (barrier, prefetch, pattern, system operation, ...); the value indexes `OperandClass::symbols`.", false},
	{"tilemask", "TileMask", "A ZA tile list as an 8-bit mask of ZA0.D-ZA7.D.", false},
}

var textAsmConditions = []string{
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
}

var textAsmRegisterClasses = map[OperandClass]bool{
	ClassGpr32: true, ClassGpr32Sp: true, ClassGpr64: true, ClassGpr64Sp: true,
	ClassSimdB: true, ClassSimdH: true, ClassSimdS: true, ClassSimdD: true,
	ClassSimdQ: true, ClassSimdVec: true, ClassSveZ: true, ClassSveP: true,
	ClassSvePN: true, ClassSmeTile: true,
}

// textAsmBaseClass is the class of an operand's value, or of the symbols of
// a value table. Numeric table rows are classified per row at run time (imm or
// fpimm), so this is the symbolic class of a table operand.
func textAsmBaseClass(op *DisasmOperand) (string, error) {
	switch op.Kind {
	case DisasmReg:
		if textAsmRegisterClasses[op.Class] {
			return string(op.Class), nil
		}
	case DisasmDerived:
		if textAsmRegisterClasses[op.Class] {
			return string(op.Class), nil
		}
		if op.Class == "" || op.Class == ClassImm {
			return "imm", nil
		}
	case DisasmNum:
		switch {
		case op.Class == ClassLabel:
			return "label", nil
		case op.NumPrefix == "c":
			return "creg", nil
		case op.NumPrefix == "" || op.NumPrefix == "#":
			if op.Class == "" || op.Class == ClassImm {
				return "imm", nil
			}
		}
	case DisasmFpImm:
		return "fpimm", nil
	case DisasmSysReg:
		return "sysreg", nil
	case DisasmTileMask:
		return "tilemask", nil
	case DisasmFormula, DisasmBitfieldWidth, DisasmElementIndex:
		return "imm", nil
	case DisasmLogicalImm, DisasmByteMaskImm, DisasmMoveWideImm:
		return "imm_hex", nil
	case DisasmLiteral, DisasmTable:
		switch op.Class {
		case ClassArrangement, ClassGpr32:
			return "arrangement", nil
		case ClassCond:
			return "cond", nil
		case ClassExtend:
			return "extend", nil
		case ClassShift:
			return "shift", nil
		case ClassFpImm:
			return "fpimm", nil
		case ClassEnum, ClassImm, ClassUnsupported:
			return "enum", nil
		}
	}
	return "", fmt.Errorf("text assembler: no value class for %s operand %s (class %q, prefix %q)",
		op.Kind, op.Symbol, op.Class, op.NumPrefix)
}

func textAsmVariant(name string) string {
	for _, class := range textAsmClasses {
		if class.Name == name {
			return class.Variant
		}
	}
	panic("text assembler: unknown class " + name)
}

// textAsmRowSymbol returns the canonical spelling of a symbolic table row,
// exactly as the generated formatter prints it, and false for numeric rows
// (which carry an imm or fpimm value instead of a symbol).
func textAsmRowSymbol(op *DisasmOperand, symbol string) (string, bool) {
	if numericTablePlaceholder(symbol) {
		return "", false
	}
	lower := strings.ToLower(strings.TrimSpace(symbol))
	switch lower {
	case "[absent]":
		return "", true
	case "[present]":
		return strings.ToLower(op.Symbol), true
	}
	canonical := textAsmCanonicalSymbol(symbol)
	if textAsmNumericSymbol(canonical) {
		return "", false
	}
	return canonical, true
}

// textAsmCanonicalSymbol mirrors the generated formatter's canonical_symbol.
func textAsmCanonicalSymbol(symbol string) string {
	lower := strings.ToLower(strings.TrimSpace(symbol))
	if strings.HasPrefix(lower, "(") && strings.HasSuffix(lower, ")") {
		if bar := strings.IndexByte(lower, '|'); bar >= 0 {
			return strings.TrimSpace(lower[1:bar])
		}
	}
	if bar := strings.IndexByte(lower, '|'); bar >= 0 {
		if lower[:bar] == "lsl" {
			return strings.TrimSpace(lower[bar+1:])
		}
		return strings.TrimSpace(lower[:bar])
	}
	return lower
}

// textAsmNumericSymbol mirrors the generated assembler's numeric_symbol: a
// row printed as a plain or '#'-prefixed integer or decimal number.
func textAsmNumericSymbol(canonical string) bool {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(canonical), "#"))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	digits := func(text string, hex bool) bool {
		if text == "" {
			return false
		}
		for _, c := range text {
			if !(c >= '0' && c <= '9' || hex && (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	if rest, ok := strings.CutPrefix(s, "0x"); ok {
		return digits(rest, true)
	}
	if whole, frac, ok := strings.Cut(s, "."); ok {
		return digits(whole, false) && digits(frac, false)
	}
	return digits(s, false)
}

type rustTextAsmData struct {
	ClassVariants string
	ClassNames    string
	ClassAll      string
	ClassNameList string
	ClassDocs     string
	ClassSummary  string
	ClassInteger  string
	BaseClassArms string
	SymbolTables  string
}

type rustTextAsmTestData struct {
	Samples     string
	SampleForms int
	SampleWords int
}

func rustKindVariant(kind DisasmKind) string {
	return strings.TrimPrefix(rustDisasmKind(kind), "Kind::")
}

// buildRustTextAsmData derives the class enum, the operand-to-class mapping
// and the symbol vocabularies from the same print model the formatter tables
// are emitted from.
func buildRustTextAsmData(surface *DisasmSurface) (rustTextAsmData, error) {
	type armKey struct {
		kind   DisasmKind
		class  string
		prefix string
	}
	arms := map[armKey]string{}
	symbols := map[string]map[string]bool{}
	for _, class := range []string{"arrangement", "extend", "shift", "enum"} {
		symbols[class] = map[string]bool{}
	}
	for i := range surface.Forms {
		form := &surface.Forms[i]
		for _, part := range form.Parts {
			op := part.Op
			if op == nil {
				continue
			}
			class, err := textAsmBaseClass(op)
			if err != nil {
				return rustTextAsmData{}, fmt.Errorf("%s: %w", form.EncodingID, err)
			}
			key := armKey{op.Kind, string(op.Class), ""}
			if op.Kind == DisasmNum {
				key.prefix = op.NumPrefix
			}
			arms[key] = class
			switch op.Kind {
			case DisasmTable:
				for _, row := range op.Rows {
					symbol, ok := textAsmRowSymbol(op, row.Symbol)
					if !ok {
						continue
					}
					if class == "cond" {
						if !containsString(textAsmConditions, symbol) {
							return rustTextAsmData{}, fmt.Errorf("%s: condition %q is not a condition code", form.EncodingID, symbol)
						}
						continue
					}
					if symbols[class] == nil {
						return rustTextAsmData{}, fmt.Errorf("%s: symbolic row %q in non-symbolic class %s", form.EncodingID, symbol, class)
					}
					symbols[class][symbol] = true
				}
			case DisasmLiteral:
				symbols[class][strings.ToLower(op.Literal)] = true
			}
		}
	}

	var variants, names, all, nameList, docs, summaries, integers strings.Builder
	for _, class := range textAsmClasses {
		fmt.Fprintf(&variants, "    /// `%s`: %s\n    %s,\n", class.Name, class.Doc, class.Variant)
		fmt.Fprintf(&names, "        OperandClass::%s => %s,\n", class.Variant, rustStringLiteral(class.Name))
		fmt.Fprintf(&all, "OperandClass::%s, ", class.Variant)
		fmt.Fprintf(&nameList, "%s, ", rustStringLiteral(class.Name))
		fmt.Fprintf(&docs, "//! | `%s` | %s |\n", class.Name, class.Doc)
		fmt.Fprintf(&summaries, "            OperandClass::%s => %s,\n", class.Variant, rustStringLiteral(class.Doc))
		if class.Integer {
			if integers.Len() > 0 {
				integers.WriteString(" | ")
			}
			fmt.Fprintf(&integers, "OperandClass::%s", class.Variant)
		}
	}

	keys := make([]armKey, 0, len(arms))
	for key := range arms {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.class != b.class {
			return a.class < b.class
		}
		return a.prefix < b.prefix
	})
	var armText strings.Builder
	for _, key := range keys {
		prefix := "_"
		if key.kind == DisasmNum {
			prefix = rustStringLiteral(key.prefix)
		}
		fmt.Fprintf(&armText, "        (Kind::%s, %s, %s) => Some(OperandClass::%s),\n",
			rustKindVariant(key.kind), rustStringLiteral(key.class), prefix, textAsmVariant(arms[key]))
	}

	var tables strings.Builder
	emitTable := func(variant string, list []string) {
		quoted := make([]string, len(list))
		for i, symbol := range list {
			quoted[i] = rustStringLiteral(symbol)
		}
		fmt.Fprintf(&tables, "        OperandClass::%s => &[%s],\n", variant, strings.Join(quoted, ", "))
	}
	emitTable("Cond", textAsmConditions)
	for _, class := range []string{"arrangement", "extend", "shift", "enum"} {
		list := make([]string, 0, len(symbols[class]))
		for symbol := range symbols[class] {
			list = append(list, symbol)
		}
		sort.Strings(list)
		emitTable(textAsmVariant(class), list)
	}
	return rustTextAsmData{
		ClassVariants: variants.String(),
		ClassNames:    names.String(),
		ClassAll:      all.String(),
		ClassNameList: nameList.String(),
		ClassDocs:     docs.String(),
		ClassSummary:  summaries.String(),
		ClassInteger:  integers.String(),
		BaseClassArms: armText.String(),
		SymbolTables:  tables.String(),
	}, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// buildRustTextAsmTestData chooses deterministic sample words for every
// printable form: the formatter-test probe, a second probe with a different
// field pattern, and a backward label sample. Each is legalized against the
// form's own constraints and kept only when the reference model prints it.
func buildRustTextAsmTestData(catalog *Catalog, surface *DisasmSurface) rustTextAsmTestData {
	entries := make(map[string]CatalogEntry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		entries[entry.EncodingID] = entry
	}
	forms := append([]DisasmForm(nil), surface.Forms...)
	sort.Slice(forms, func(i, j int) bool { return forms[i].EncodingID < forms[j].EncodingID })
	var out strings.Builder
	sampleForms, sampleWords := 0, 0
	for i := range forms {
		form := &forms[i]
		entry, ok := entries[form.EncodingID]
		if !ok || entry.Mask == 0 {
			continue
		}
		var words []uint32
		add := func(word uint32) {
			if word&entry.Mask != entry.Value || !form.matchesConstraints(word) {
				return
			}
			if _, ok := form.Render(word); !ok {
				return
			}
			for _, have := range words {
				if have == word {
					return
				}
			}
			words = append(words, word)
		}
		for variant, multiplier := range []int{7, 5} {
			word := entry.FixedWord
			for fieldIndex, field := range entry.Fields {
				if field.Fixed || field.Free == 0 {
					continue
				}
				low := freeLowBit(field.Free, field.Start)
				probe := uint32(fieldIndex*multiplier+1+2*variant) << uint(low) & field.Free
				if probe == 0 {
					probe = field.Free & (^field.Free + 1)
				}
				word = word&^field.Free | probe
			}
			word = legalConformanceWord(word, entry.Mask, entry.Value, form)
			add(word)
			if negative, ok := labelSignSample(form, entry, word); ok {
				add(negative)
			}
		}
		if len(words) == 0 {
			fmt.Fprintf(&out, "    (%s, &[]),\n", rustStringLiteral(form.EncodingID))
			continue
		}
		hex := make([]string, len(words))
		for j, word := range words {
			hex[j] = fmt.Sprintf("0x%08X", word)
		}
		fmt.Fprintf(&out, "    (%s, &[%s]),\n", rustStringLiteral(form.EncodingID), strings.Join(hex, ", "))
		sampleForms++
		sampleWords += len(words)
	}
	return rustTextAsmTestData{Samples: out.String(), SampleForms: sampleForms, SampleWords: sampleWords}
}

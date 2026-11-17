package arm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/pkg/semantics"
	"github.com/bryanmatteson/mkasm/templates"
)

// generateARM32Rust shares the exact encoder and decision tree with A64. The
// instruction-state wrapper keeps the T32 architectural halfword order separate
// from byte order, and its print model uses the same parsed operand explanations.
func (ap *ARMParser) generateARM32Rust(instructions []*ir.InstructionIR) error {
	src := filepath.Join(ap.config.OutputDirectory, "src")
	if err := os.MkdirAll(src, 0755); err != nil {
		return err
	}
	t, err := template.New("arm32").ParseFS(templates.FS, "rust/*.tmpl", "arm32_rust/*.tmpl")
	if err != nil {
		return err
	}
	if err := execTmplWrite(t, "cargo.toml.tmpl", filepath.Join(ap.config.OutputDirectory, "Cargo.toml"), struct{ CrateName string }{"arm32"}); err != nil {
		return err
	}
	if err := writeLicense(ap.config.OutputDirectory); err != nil {
		return err
	}
	if err := semantics.WriteRust(src); err != nil {
		return err
	}
	if err := execTmplWrite(t, "recipes.rs.tmpl", filepath.Join(src, "recipes.rs"), nil); err != nil {
		return err
	}
	all := BuildCatalog(instructions)
	if len(all.Entries) > int(^uint16(0)) {
		return fmt.Errorf("arm32 formatter: %d forms exceed u16 index capacity", len(all.Entries))
	}
	formIndex := make(map[string]int, len(all.Entries))
	for i, entry := range all.Entries {
		formIndex[entry.EncodingID] = i
	}
	var formIndices strings.Builder
	if err := writeRustRequirements(src, all); err != nil {
		return err
	}
	enc := struct{ FixedTable, FieldsTable, ClassTable string }{emitRustFixedTable(all), emitRustFieldsTable(all), emitRustClassTable(all)}
	if err := execTmplWrite(t, "encoders.rs.tmpl", filepath.Join(src, "encoders.rs"), enc); err != nil {
		return err
	}
	for _, bank := range []string{"a32", "t16", "t32"} {
		var selected []*ir.InstructionIR
		for _, insn := range instructions {
			b := "a32"
			if insn.InstructionSet == "T32" {
				b = "t32"
				if insn.Encoding.Width == 16 {
					b = "t16"
				}
			}
			if b == bank {
				selected = append(selected, insn)
			}
		}
		catalog := BuildCatalog(selected)
		fmt.Fprintf(&formIndices, "static %s_FORM_INDICES:&[u16]=&[", strings.ToUpper(bank))
		for _, entry := range catalog.Entries {
			fmt.Fprintf(&formIndices, "%d,", formIndex[entry.EncodingID])
		}
		formIndices.WriteString("];\n")
		data, err := buildRustDecoderData(catalog)
		if err != nil {
			return fmt.Errorf("arm32 %s: %w", bank, err)
		}
		if err := execTmplWrite(t, "decoders.rs.tmpl", filepath.Join(src, bank+".rs"), data); err != nil {
			return err
		}
	}
	var forms strings.Builder
	optionalGroups := 0
	// Width qualification is only useful when the same source family has
	// a narrow spelling. LLVM rejects .w on many inherently wide forms.
	narrowForms := make(map[string]bool)
	for _, instruction := range instructions {
		if instruction.InstructionSet == "T32" && instruction.Encoding.Width == 16 {
			narrowForms[instruction.IFormFile+"|"+instruction.AsmMnemonic] = true
		}
	}
	for _, entry := range all.Entries {
		p := ap.loadIForm(&ir.InstructionIR{IFormFile: entry.IFormFile, EncodingID: entry.EncodingID})
		if p == nil {
			return fmt.Errorf("missing form %s", entry.EncodingID)
		}
		groups := strings.Count(p.AsmSuffix, "{")
		for _, operand := range p.AsmOperands {
			groups += strings.Count(operand.Prefix, "{")
		}
		optionalGroups = max(optionalGroups, groups)
		wide := narrowForms[entry.IFormFile+"|"+entry.AsmMnemonic]
		// These forms already acquire MOVW/ADDW/SUBW spellings below.
		switch entry.EncodingID {
		case "MOV_i_T2", "PUSH_STR_i_T4_pre", "POP_LDR_i_T4_post":
			// Alias pages can point at a different source family. MOV's
			// modified immediate also needs disambiguation from MOVW.
			wide = true
		case "MOV_i_T3", "ADD_i_T4", "ADD_SP_i_T4", "SUB_i_T4", "SUB_SP_i_T3":
			wide = false
		case "SUBS_PC_T5_AS":
			// The exception-return form shares SUB's page, but cannot
			// use its narrow register/immediate syntax or .w qualifier.
			wide = false
		}
		// Signed, pre-index and post-index immediate addresses have no
		// narrow counterpart; their explicit operands determine the width.
		if strings.HasPrefix(entry.AsmMnemonic, "LDR") || strings.HasPrefix(entry.AsmMnemonic, "STR") {
			for _, field := range entry.Fields {
				if field.Name == "P" {
					wide = false
				}
			}
		}
		form, err := arm32PrintForm(entry, p, wide)
		if err != nil {
			return fmt.Errorf("arm32 formatter %s: %w", entry.EncodingID, err)
		}
		forms.WriteString(form)
		forms.WriteString(",\n")
	}
	if err := execTmplWrite(t, "references.rs.tmpl", filepath.Join(src, "references.rs"), nil); err != nil {
		return err
	}
	golden := false
	for _, entry := range all.Entries {
		if entry.EncodingID == "VMOV_i_A2_D" {
			golden = true
		}
	}
	if err := execTmplWrite(t, "arm32_analysis.rs.tmpl", filepath.Join(src, "analysis.rs"), buildRustAnalysisData(all)); err != nil {
		return err
	}
	if err := writeRustEffects(t, src, true); err != nil {
		return err
	}
	return execTmplWrite(t, "arm32_lib.rs.tmpl", filepath.Join(src, "lib.rs"), struct {
		Forms          string
		FormIndices    string
		GoldenTests    bool
		OptionalGroups int
	}{forms.String(), formIndices.String(), golden, optionalGroups})
}

func arm32AllocationConstraints(instr *ir.InstructionIR, p *ParsedIForm) {
	var guards []*ir.BitDiffNode
	if instr.BitDiffsTree != nil {
		guards = append(guards, instr.BitDiffsTree)
	}
	explanations := ExplanationsFor(p.Explanations, instr.EncodingID)
	for _, operand := range p.AsmOperands {
		ex := explanations[operand.Symbol]
		if ex.Symbol != "<dt>" && ex.Symbol != "<dt1>" && ex.Symbol != "<dt2>" && ex.Symbol != "<size>" {
			continue
		}
		selectors := ex.ValueFields
		if len(selectors) == 0 {
			selectors = ex.Fields
		}
		var excluded []*ir.BitDiffNode
		for _, row := range ex.Values {
			if row.Reserved() || len(row.Bits) != len(selectors) {
				continue
			}
			var parts []string
			for i, name := range selectors {
				parts = append(parts, name+" == '"+row.Bits[i]+"'")
			}
			tree, err := ParseBitDiffs(strings.Join(parts, " && "))
			if err != nil || tree == nil {
				continue
			}
			if err := ir.ResolveBitDiffFields(tree, instr.Encoding); err != nil {
				continue
			}
			excluded = append(excluded, &ir.BitDiffNode{Kind: ir.BitDiffNot, Kids: []*ir.BitDiffNode{tree}})
		}
		if len(excluded) > 0 {
			guards = append(guards, &ir.BitDiffNode{Kind: ir.BitDiffNot, Kids: []*ir.BitDiffNode{{Kind: ir.BitDiffAnd, Kids: excluded}}})
		}
	}
	for _, code := range p.Pseudocode {
		for _, m := range arm32UndefinedRE.FindAllStringSubmatch(code, -1) {
			tree, err := ParseBitDiffs(m[1])
			if err != nil {
				continue
			}
			if err := ir.ResolveBitDiffFields(tree, instr.Encoding); err != nil {
				continue
			}
			guards = append(guards, &ir.BitDiffNode{Kind: ir.BitDiffNot, Kids: []*ir.BitDiffNode{tree}})
		}
	}
	if len(guards) > 0 {
		instr.BitDiffsTree = &ir.BitDiffNode{Kind: ir.BitDiffAnd, Kids: guards}
	}
}

var arm32UndefinedRE = regexp.MustCompile(`(?m)^if\s+([^\n;]+?)\s+then\s+Undefined\(\);`)
var arm32SliceRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:[<\[]([0-9]+)(?::([0-9]+))?[>\]])?$`)
var arm32ScaleRE = regexp.MustCompile(`(?:<imm[0-9]*>|<label>|immediate)[ /]+([248]|16|32|64)(?:\D|$)`)
var arm32MultipleScaleRE = regexp.MustCompile(`multiples? of ([248]|16|32|64)(?:\D|$)`)
var arm32SymbolRE = regexp.MustCompile(`<[^>]+>`)

func arm32Slices(names []string, fields []CatalogField) (string, int, bool) {
	var parts []string
	width := 0
	for _, name := range names {
		m := arm32SliceRE.FindStringSubmatch(name)
		if m == nil {
			return "&[]", 0, false
		}
		var f *CatalogField
		for i := range fields {
			if fields[i].Name == m[1] {
				f = &fields[i]
				break
			}
		}
		if f == nil {
			return "&[]", 0, false
		}
		lo, hi := f.Start, f.End
		if m[2] != "" {
			h, _ := strconv.Atoi(m[2])
			l := h
			if m[3] != "" {
				l, _ = strconv.Atoi(m[3])
			}
			lo, hi = f.Start+l, f.Start+h
			if hi > f.End || lo > hi {
				return "&[]", 0, false
			}
		}
		parts = append(parts, fmt.Sprintf("Bits { lo: %d, width: %d }", lo, hi-lo+1))
		width += hi - lo + 1
	}
	return "&[" + strings.Join(parts, ",") + "]", width, true
}

func arm32PrintForm(entry CatalogEntry, p *ParsedIForm, wide bool) (string, error) {
	exps := ExplanationsFor(p.Explanations, entry.EncodingID)
	var parts []string
	// Some AArch32 pages put a documented placeholder inside <text> rather
	// than an operand link. Preserve its binding just like linked operands.
	var operands []AsmOperand
	for _, op := range p.AsmOperands {
		prefix := op.Prefix
		for _, loc := range arm32SymbolRE.FindAllStringIndex(op.Prefix, -1) {
			symbol := op.Prefix[loc[0]:loc[1]]
			before, after, _ := strings.Cut(prefix, symbol)
			operands = append(operands, AsmOperand{Symbol: symbol, Prefix: before})
			prefix = after
		}
		op.Prefix = prefix
		operands = append(operands, op)
	}
	for _, op := range operands {
		symbol := strings.TrimSpace(op.Symbol)
		ex := exps[symbol]
		names := ex.Fields
		if len(names) == 0 && op.Field != "" {
			names = []string{op.Field}
		}
		// Some narrow Thumb explanations name only the low register field;
		// the diagram and decode pseudocode carry its high bit separately.
		if symbol == "<Rdm>" && len(names) == 1 && names[0] == "Rdm" {
			for _, field := range entry.Fields {
				if field.Name == "DM" {
					names = []string{"DM", "Rdm"}
					break
				}
			}
		}
		bits, _, _ := arm32Slices(names, entry.Fields)
		var rows []string
		selectors := ex.ValueFields
		if len(selectors) == 0 {
			selectors = names
		}
		for _, row := range ex.Values {
			if len(row.Bits) != len(selectors) {
				continue
			}
			var checks []string
			valid := true
			for i, pattern := range row.Bits {
				selector, width, ok := arm32Slices([]string{selectors[i]}, entry.Fields)
				pattern = strings.ReplaceAll(strings.TrimSpace(pattern), " ", "")
				if !ok || len(pattern) != width {
					valid = false
					break
				}
				mask, value := ir.FixedBitsFromPattern(pattern)
				// PatternFromEncoding uses a 32-bit word; table selectors are
				// compact concatenations whose first bit is width-1.
				mask >>= 32 - width
				value >>= 32 - width
				checks = append(checks, fmt.Sprintf("Check { bits: %s, mask: 0x%x, value: 0x%x }", selector, mask, value))
			}
			if valid {
				rows = append(rows, fmt.Sprintf("Value { checks: &[%s], text: %s }", strings.Join(checks, ","), rustStringLiteral(strings.ToLower(row.Symbol))))
			}
		}
		scale := 1
		if m := arm32ScaleRE.FindStringSubmatch(ex.Prose); m != nil {
			scale, _ = strconv.Atoi(m[1])
		} else if strings.HasPrefix(symbol, "<imm") {
			if m := arm32MultipleScaleRE.FindStringSubmatch(strings.ToLower(ex.Prose)); m != nil {
				scale, _ = strconv.Atoi(m[1])
			}
		}
		transform := "Plain"
		prose := strings.ToLower(ex.Prose)
		compact := strings.Join(strings.Fields(prose), "")
		switch {
		case symbol == "<const>" && strings.Contains(prose, "modified immediate"):
			if p.InstructionSet == "A32" {
				transform = "ArmImmediate"
			} else {
				transform = "ThumbImmediate"
			}
		case strings.Contains(prose, "<lsb>+<width>-1"):
			transform = "BitfieldWidth"
		case strings.Contains(prose, "<width>-1"):
			transform = "PlusOne"
		case strings.Contains(prose, "<imm>-1"):
			transform = "PlusOne"
		case strings.Contains(prose, "modulo 32"):
			transform = "ShiftAmount"
		case strings.Contains(compact, "<size>/2-<imm>"):
			transform = "NarrowShift"
		case strings.Contains(compact, "<size>-<imm>"):
			transform = "RightShift"
		case strings.Contains(compact, "<imm>-<size>"):
			transform = "LeftShift"
		case symbol == "<fbits>":
			transform = "FractionBits"
		case symbol == "<imm>" && strings.Contains(prose, "imm6<"):
			transform = "LeftShift"
		case symbol == "<Rt2>" && bits == "&[]" || symbol == "<Rt2>" && !strings.Contains(ex.Prose, `"Rt2"`):
			transform = "Successor"
		case strings.Contains(prose, "floating-point constant"):
			transform = "FloatImmediate"
		case symbol == "<imm>" && strings.Contains(prose, "modified immediate constants in a32"):
			transform = "ArmImmediate"
		case symbol == "<imm>" && strings.Contains(prose, "replicated to fill"):
			transform = "SimdImmediate"
		}
		parts = append(parts, fmt.Sprintf("Part { prefix: %s, symbol: %s, bits: %s, values: &[%s], scale: %d, transform: Transform::%s }", rustStringLiteral(op.Prefix), rustStringLiteral(symbol), bits, strings.Join(rows, ","), scale, transform))
	}
	return fmt.Sprintf("Form { id: %s, parts: &[%s], suffix: %s, width: %d, thumb: %t, wide: %t, mask: 0x%x, value: 0x%x }", rustStringLiteral(entry.EncodingID), strings.Join(parts, ","), rustStringLiteral(p.AsmSuffix), p.Width, p.InstructionSet == "T32", wide, entry.Mask, entry.Value), nil
}

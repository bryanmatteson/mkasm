package arm

import (
	"fmt"
	"sort"
	"strings"
)

type rustDisasmData struct {
	Forms string
	Cases string
}

func buildRustDisasmData(catalog *Catalog, surface *DisasmSurface) (rustDisasmData, error) {
	entries := make(map[string]CatalogEntry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		entries[entry.EncodingID] = entry
	}
	forms := append([]DisasmForm(nil), surface.Forms...)
	sort.Slice(forms, func(i, j int) bool { return forms[i].EncodingID < forms[j].EncodingID })
	var out strings.Builder
	for i := range forms {
		entry, ok := entries[forms[i].EncodingID]
		if !ok {
			return rustDisasmData{}, fmt.Errorf("rust formatter: %s absent from catalog", forms[i].EncodingID)
		}
		fmt.Fprintf(&out, "    %s,\n", emitRustDisasmForm(&forms[i], entry))
	}
	var cases strings.Builder
	for i := range forms {
		entry := entries[forms[i].EncodingID]
		word := entry.FixedWord
		for fieldIndex, field := range entry.Fields {
			if field.Fixed || field.Free == 0 {
				continue
			}
			low := freeLowBit(field.Free, field.Start)
			probe := uint32(fieldIndex*7+1) << uint(low) & field.Free
			if probe == 0 {
				probe = field.Free & (^field.Free + 1)
			}
			word = word&^field.Free | probe
		}
		word = legalConformanceWord(word, entry.Mask, entry.Value, &forms[i])
		var best *DisasmForm
		var bestEntry CatalogEntry
		for j := range forms {
			candidateEntry := entries[forms[j].EncodingID]
			if candidateEntry.Mask == 0 || word&candidateEntry.Mask != candidateEntry.Value ||
				!forms[j].matchesConstraints(word) {
				continue
			}
			if best == nil || betterRustDisasmForm(&forms[j], candidateEntry, best, bestEntry) {
				best, bestEntry = &forms[j], candidateEntry
			}
		}
		if best == nil {
			continue
		}
		expected, ok := best.Render(word)
		if !ok {
			continue
		}
		fmt.Fprintf(&cases, "        (0x%08X, %s),\n", word, rustStringLiteral(expected))
	}
	return rustDisasmData{Forms: out.String(), Cases: cases.String()}, nil
}

func betterRustDisasmForm(a *DisasmForm, ae CatalogEntry, b *DisasmForm, be CatalogEntry) bool {
	abits := bitsSet(ae.Mask | a.ConstraintMask)
	bbits := bitsSet(be.Mask | b.ConstraintMask)
	if abits != bbits {
		return abits > bbits
	}
	aalias, balias := ae.AliasOf != "", be.AliasOf != ""
	if aalias != balias {
		return aalias
	}
	return a.EncodingID < b.EncodingID
}

func bitsSet(value uint32) int {
	count := 0
	for value != 0 {
		value &= value - 1
		count++
	}
	return count
}

func emitRustDisasmForm(form *DisasmForm, entry CatalogEntry) string {
	parts := make([]string, len(form.Parts))
	for i := range form.Parts {
		parts[i] = emitRustDisasmPart(form.Parts[i])
	}
	equalities := make([]string, len(form.EqualFields))
	for i, eq := range form.EqualFields {
		equalities[i] = fmt.Sprintf("Equality { left_start: %d, left_end: %d, right_start: %d, right_end: %d, add: %d }",
			eq.LeftStart, eq.LeftEnd, eq.RightStart, eq.RightEnd, eq.Add)
	}
	inequalities := make([]string, len(form.UnequalFields))
	for i, neq := range form.UnequalFields {
		inequalities[i] = fmt.Sprintf("Inequality { left_start: %d, left_end: %d, right_start: %d, right_end: %d }",
			neq.LeftStart, neq.LeftEnd, neq.RightStart, neq.RightEnd)
	}
	oneHot := make([]string, len(form.OneHotMasks))
	for i, mask := range form.OneHotMasks {
		oneHot[i] = fmt.Sprintf("0x%08X", mask)
	}
	forbidden := make([]string, len(form.Forbidden))
	for i, item := range form.Forbidden {
		forbidden[i] = fmt.Sprintf("Forbidden { mask: 0x%08X, value: 0x%08X }", item.Mask, item.Value)
	}
	parents := make([]string, 0, len(form.GroupParent))
	for group, parent := range form.GroupParent {
		parents = append(parents, fmt.Sprintf("(%d, %d)", group, parent))
	}
	sort.Strings(parents)
	required := make([]string, 0, len(form.RequiredGroups))
	for group, yes := range form.RequiredGroups {
		if yes {
			required = append(required, fmt.Sprintf("%d", group))
		}
	}
	sort.Strings(required)
	return fmt.Sprintf("Form { mask: 0x%08X, value: 0x%08X, encoding_id: %s, alias: %t, constraint_mask: 0x%08X, constraint_value: 0x%08X, equalities: %s, inequalities: %s, one_hot: %s, forbidden: %s, move_wide_guard: %s, logical_guard: %s, sve_mask: %s, parts: %s, parents: %s, required: %s }",
		entry.Mask, entry.Value, rustStringLiteral(form.EncodingID), entry.AliasOf != "",
		form.ConstraintMask, form.ConstraintValue, rustSlice(equalities), rustSlice(inequalities),
		rustSlice(oneHot), rustSlice(forbidden), emitRustMoveWideGuard(form.MoveWideZeroGuard),
		emitRustLogicalGuard(form.LogicalMoveGuard), emitRustOptionalPart(form.SVEMoveMaskField),
		rustSlice(parts), rustSlice(parents), rustSlice(required))
}

func emitRustDisasmPart(part DisasmPart) string {
	op := "None"
	if part.Op != nil {
		op = "Some(" + emitRustDisasmOperand(part.Op) + ")"
	}
	return fmt.Sprintf("TextPart { literal: %s, operand: %s, group: %d }",
		rustStringLiteral(part.Literal), op, part.Group)
}

func emitRustDisasmOperand(op *DisasmOperand) string {
	parts := make([]string, len(op.Parts))
	for i, part := range op.Parts {
		parts[i] = emitRustBitPart(part)
	}
	cols := make([]string, len(op.Cols))
	for i, part := range op.Cols {
		cols[i] = emitRustBitPart(part)
	}
	ranges := make([]string, len(op.RegRanges))
	for i, item := range op.RegRanges {
		ranges[i] = fmt.Sprintf("RegRange { lo: %d, hi: %d, bias: %d }", item.Lo, item.Hi, item.Bias)
	}
	rows := make([]string, len(op.Rows))
	for i, row := range op.Rows {
		bits := make([]string, len(row.Bits))
		for j, value := range row.Bits {
			bits[j] = rustStringLiteral(value)
		}
		rows[i] = fmt.Sprintf("Row { bits: %s, symbol: %s }", rustSlice(bits), rustStringLiteral(row.Symbol))
	}
	formulas := make([]string, len(op.Formulas))
	for i, formula := range op.Formulas {
		formulaParts := make([]string, len(formula.Parts))
		for j, part := range formula.Parts {
			formulaParts[j] = emitRustBitPart(part)
		}
		formulas[i] = fmt.Sprintf("Formula { parts: %s, raw_mul: %d, add: %d, negate: %d, size_parts: %d, esize_base: %d, esize_mul: %d }",
			rustSlice(formulaParts), formula.RawMul, formula.Add, formula.Negate,
			formula.SizeParts, formula.ESizeBase, formula.ESizeMul)
	}
	return fmt.Sprintf("OperandDef { symbol: %s, class: %s, kind: %s, parts: %s, scale: %d, bias: %d, negate: %d, raw_mul: %d, signed: %t, ranges: %s, lo: %d, hi: %d, has_range: %t, reg_lo: %d, reg_hi: %d, has_reg_range: %t, reg_multiple: %d, num_prefix: %s, num_constant: %d, has_num_constant: %t, when_mask: 0x%08X, when_value: 0x%08X, cols: %s, rows: %s, formulas: %s, move_wide_invert: %t, logical_invert: %t, data_size: %d, literal: %s, index_size_parts: %d, xor: %d, default: %d, has_default: %t, mul: %d, add: %d, modulo: %d }",
		rustStringLiteral(op.Symbol), rustStringLiteral(string(op.Class)), rustDisasmKind(op.Kind),
		rustSlice(parts), op.Scale, op.Bias, op.Negate, op.RawMul, op.Signed, rustSlice(ranges),
		op.Lo, op.Hi, op.HasRange, op.RegLo, op.RegHi, op.HasRegRange, op.RegMultiple,
		rustStringLiteral(op.NumPrefix), op.NumConstant, op.HasNumConstant, op.WhenMask, op.WhenValue,
		rustSlice(cols), rustSlice(rows), rustSlice(formulas), op.MoveWideInvert, op.LogicalInvert,
		op.DataSize, rustStringLiteral(op.Literal), op.IndexSizeParts, op.Xor, op.Default,
		op.HasDefault, op.Mul, op.Add, op.Mod)
}

func rustDisasmKind(kind DisasmKind) string {
	return map[DisasmKind]string{
		DisasmReg: "Kind::Reg", DisasmNum: "Kind::Num", DisasmFpImm: "Kind::FpImm",
		DisasmSysReg: "Kind::SysReg", DisasmTable: "Kind::Table", DisasmDerived: "Kind::Derived",
		DisasmFormula: "Kind::Formula", DisasmLogicalImm: "Kind::LogicalImm",
		DisasmBitfieldWidth: "Kind::BitfieldWidth", DisasmByteMaskImm: "Kind::ByteMaskImm",
		DisasmMoveWideImm: "Kind::MoveWideImm", DisasmLiteral: "Kind::Literal",
		DisasmElementIndex: "Kind::ElementIndex", DisasmTileMask: "Kind::TileMask",
	}[kind]
}

func emitRustBitPart(part BitPart) string {
	return fmt.Sprintf("BitPart { start: %d, end: %d, width: %d, literal: %s, is_lit: %t }",
		part.Start, part.End, part.Width, rustStringLiteral(part.Literal), part.IsLit)
}

func emitRustOptionalPart(part *BitPart) string {
	if part == nil {
		return "None"
	}
	return "Some(" + emitRustBitPart(*part) + ")"
}

func emitRustMoveWideGuard(guard *DisasmMoveWideZeroGuard) string {
	if guard == nil {
		return "None"
	}
	return fmt.Sprintf("Some(MoveWideGuard { imm16: %s, hw: %s })", emitRustBitPart(guard.Imm16), emitRustBitPart(guard.HW))
}

func emitRustLogicalGuard(guard *DisasmLogicalMoveGuard) string {
	if guard == nil {
		return "None"
	}
	return fmt.Sprintf("Some(LogicalGuard { sf: %s, n: %s, imms: %s, immr: %s })",
		emitRustBitPart(guard.SF), emitRustBitPart(guard.N), emitRustBitPart(guard.Imms), emitRustBitPart(guard.Immr))
}

func rustSlice(items []string) string {
	if len(items) == 0 {
		return "&[]"
	}
	return "&[" + strings.Join(items, ", ") + "]"
}

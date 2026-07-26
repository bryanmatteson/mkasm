package arm

import "sort"

// conformanceForms indexes the independent print model by encoding. Sample
// construction is shared by Go and Rust so their exhaustive ledgers exercise
// the same architectural representative for each exact encoder.
func conformanceForms(surface *DisasmSurface) map[string]*DisasmForm {
	forms := map[string]*DisasmForm{}
	if surface == nil {
		return forms
	}
	for i := range surface.Forms {
		form := &surface.Forms[i]
		forms[form.EncodingID] = form
	}
	return forms
}

// legalConformanceWord adjusts a deterministic non-zero sample to a spelling
// the ARM print model accepts. It never changes fixed encoding bits.
func legalConformanceWord(word, fixedMask, fixedValue uint32, form *DisasmForm) uint32 {
	word = word&^fixedMask | fixedValue&fixedMask
	if form == nil {
		return word
	}
	word = canonicalizeIgnoredOperandBits(form, word)
	word = canonicalizeDocumentedIgnoredBits(form, word, fixedMask, fixedValue)
	if form.PreferOmittedSystemRegister {
		// A defaulted continuation is one semantic unit. Start it from the
		// encoding base so unrelated non-zero selector probes cannot combine an
		// omitted operand with a table row that requires its presence.
		word = fixedValue
	}
	word = canonicalizeOptionalGroupDefaults(form, word, fixedMask, fixedValue)

	// First try the non-zero probe unchanged. It catches field-placement errors
	// without needlessly collapsing every exact call to the zero-bit base.
	if constrained, ok := form.SatisfyConstraints(word); ok {
		constrained = constrained&^fixedMask | fixedValue&fixedMask
		if _, printable := form.Render(constrained); printable {
			return constrained
		}
	}

	// Reserved selector rows are the common reason an otherwise valid bit probe
	// has no assembly spelling. Search the finite ARM tables, preserving fixed
	// bits, and accept only a word the complete form renders.
	const searchLimit = 10000
	tries := 0
	if candidate, ok := legalizeTableOperands(form, word, fixedMask, fixedValue, 0, &tries, searchLimit); ok {
		return candidate
	}

	// Some zeroed bases are legal where the deliberately varied sample is not
	// (register-pair alignment and width-dependent shifts are examples). Keep
	// this as a second independent starting point, still selecting table rows
	// and satisfying the decoded alias constraints.
	tries = 0
	if candidate, ok := legalizeTableOperands(form, fixedValue, fixedMask, fixedValue, 0, &tries, searchLimit); ok {
		return candidate
	}
	return word
}

// canonicalizeOptionalGroupDefaults starts exact-ledger representatives from
// the encoding ARM assigns to omission. System-operation aliases need this:
// an operation-name table row and an optional Rt can each be printable while
// their combination is not architectural.
func canonicalizeOptionalGroupDefaults(
	form *DisasmForm,
	word, fixedMask, fixedValue uint32,
) uint32 {
	for _, part := range form.Parts {
		op := part.Op
		if part.Group == 0 || form.RequiredGroups[part.Group] ||
			op == nil || !op.HasDefault || op.Default < 0 {
			continue
		}
		parts := op.Parts
		if len(parts) == 0 {
			parts = op.Cols
		}
		value := uint64(op.Default)
		for i := len(parts) - 1; i >= 0; i-- {
			field := parts[i]
			width := uint(field.Width)
			mask := ^uint64(0)
			if width < 64 {
				mask = uint64(1)<<width - 1
			}
			raw := value & mask
			value >>= width
			if field.IsLit {
				continue
			}
			fieldMask := fieldRangeMask(field.Start, field.End)
			word = word&^fieldMask | uint32(raw)<<uint(field.Start)
		}
	}
	return word&^fixedMask | fixedValue&fixedMask
}

func canonicalizeDocumentedIgnoredBits(
	form *DisasmForm,
	word, fixedMask, fixedValue uint32,
) uint32 {
	for _, part := range form.Parts {
		op := part.Op
		if op == nil || (op.Kind != DisasmTable && op.Kind != DisasmFormula) ||
			!op.IgnoredShouldZero && len(op.FormulaIgnoredZero) == 0 {
			continue
		}
		got := make([]string, len(op.Cols))
		for i, col := range op.Cols {
			got[i] = bitsOf(word, col.Start, col.End)
		}
		for rowIndex, row := range op.Rows {
			if !rowMatches(row.Bits, got) {
				continue
			}
			if op.IgnoredShouldZero {
				for i, pattern := range row.Bits {
					for j, bit := range pattern {
						if bit == 'x' || bit == 'X' {
							word &^= uint32(1) << uint(op.Cols[i].End-j)
						}
					}
				}
			}
			if rowIndex < len(op.FormulaIgnoredZero) {
				word &^= op.FormulaIgnoredZero[rowIndex]
			}
			break
		}
	}
	return word&^fixedMask | fixedValue&fixedMask
}

func canonicalizeIgnoredOperandBits(form *DisasmForm, word uint32) uint32 {
	for _, part := range form.Parts {
		op := part.Op
		if op == nil || op.Kind != DisasmLogicalImm {
			continue
		}
		var n, imms uint32
		var immr BitPart
		var packed *BitPart
		switch len(op.Parts) {
		case 1:
			if op.Parts[0].Width != 13 {
				continue
			}
			raw := fieldValue(word, op.Parts[0].Start, op.Parts[0].End)
			n, imms = raw>>12, raw&0x3f
			packed = &op.Parts[0]
		case 4:
			n = fieldValue(word, op.Parts[0].Start, op.Parts[0].End)
			imms = fieldValue(word, op.Parts[2].Start, op.Parts[2].End)
			immr = op.Parts[1]
		default:
			continue
		}
		lenValue := n<<6 | (^imms)&0x3f
		length := -1
		for v := lenValue; v != 0; v >>= 1 {
			length++
		}
		if length < 1 {
			continue
		}
		levels := uint32(1<<uint(length)) - 1
		if packed != nil {
			raw := fieldValue(word, packed.Start, packed.End)
			raw = raw&^(uint32(0x3f)<<6) | (raw>>6&levels)<<6
			mask := fieldRangeMask(packed.Start, packed.End)
			word = word&^mask | raw<<uint(packed.Start)
		} else {
			value := fieldValue(word, immr.Start, immr.End) & levels
			mask := fieldRangeMask(immr.Start, immr.End)
			word = word&^mask | value<<uint(immr.Start)
		}
	}
	return word
}

func legalizeTableOperands(
	form *DisasmForm,
	word, fixedMask, fixedValue uint32,
	partIndex int,
	tries *int,
	limit int,
) (uint32, bool) {
	if *tries >= limit {
		return 0, false
	}
	for partIndex < len(form.Parts) {
		op := form.Parts[partIndex].Op
		if op != nil && (op.Kind == DisasmTable || op.Kind == DisasmFormula) &&
			(op.WhenMask == 0 || word&op.WhenMask == op.WhenValue) {
			break
		}
		partIndex++
	}
	if partIndex == len(form.Parts) {
		*tries++
		candidate, ok := form.SatisfyConstraints(word)
		if !ok {
			return 0, false
		}
		candidate = candidate&^fixedMask | fixedValue&fixedMask
		return legalizeSemanticOperands(
			form, candidate, fixedMask, fixedValue, tries, limit, map[uint32]bool{},
		)
	}

	op := form.Parts[partIndex].Op
	if _, ok := op.Render(word); ok {
		if candidate, ok := legalizeTableOperands(
			form, word, fixedMask, fixedValue, partIndex+1, tries, limit,
		); ok {
			return candidate, true
		}
	}
	for _, row := range op.Rows {
		candidate, ok := applyTableRow(word, fixedMask, fixedValue, op.Cols, row)
		if !ok {
			continue
		}
		if candidate, ok := legalizeTableOperands(
			form, candidate, fixedMask, fixedValue, partIndex+1, tries, limit,
		); ok {
			return candidate, true
		}
	}
	return 0, false
}

// legalizeSemanticOperands solves the bounded inverse constraints that are not
// value tables: documented numeric ranges, restricted register numbers,
// bitfield-alias widths, and formula-derived immediates. It explores only the
// bits read by the first invalid operand, never the whole instruction word.
//
// This is deliberately model-driven. Adding an operand range to the decoder
// automatically makes generated conformance representatives obey it; there is
// no instruction-name allowlist to keep in sync with the architecture.
func legalizeSemanticOperands(
	form *DisasmForm,
	word, fixedMask, fixedValue uint32,
	tries *int,
	limit int,
	seen map[uint32]bool,
) (uint32, bool) {
	if *tries >= limit || seen[word] {
		return 0, false
	}
	seen[word] = true
	*tries++

	word = canonicalizeIgnoredOperandBits(form, word)
	word = canonicalizeDocumentedIgnoredBits(form, word, fixedMask, fixedValue)
	word, ok := form.SatisfyConstraints(word)
	if !ok {
		return 0, false
	}
	word = word&^fixedMask | fixedValue&fixedMask
	if _, ok := form.Render(word); ok {
		return word, true
	}

	op := firstInvalidRenderedOperand(form, word)
	if op == nil {
		return 0, false
	}
	positions := mutableOperandBits(op, fixedMask)
	if len(positions) == 0 || len(positions) > 16 {
		return 0, false
	}
	assignments := uint32(1) << uint(len(positions))
	for assignment := uint32(0); assignment < assignments; assignment++ {
		candidate := word
		for i, pos := range positions {
			mask := uint32(1) << uint(pos)
			if assignment&(uint32(1)<<uint(i)) != 0 {
				candidate |= mask
			} else {
				candidate &^= mask
			}
		}
		if candidate == word {
			continue
		}
		candidate = canonicalizeIgnoredOperandBits(form, candidate)
		candidate = canonicalizeDocumentedIgnoredBits(
			form, candidate, fixedMask, fixedValue,
		)
		candidate, ok = form.SatisfyConstraints(candidate)
		if !ok {
			continue
		}
		candidate = candidate&^fixedMask | fixedValue&fixedMask
		if _, valid := op.Render(candidate); !valid {
			continue
		}
		if solved, ok := legalizeSemanticOperands(
			form, candidate, fixedMask, fixedValue, tries, limit, seen,
		); ok {
			return solved, true
		}
	}
	return 0, false
}

func firstInvalidRenderedOperand(form *DisasmForm, word uint32) *DisasmOperand {
	skip := map[int]bool{}
	for _, part := range form.Parts {
		if part.Group != 0 {
			if _, decided := skip[part.Group]; !decided {
				skip[part.Group] = form.groupOmitted(part.Group, word)
			}
		}
	}
	for _, part := range form.Parts {
		if part.Op == nil || groupSkipped(form, skip, part.Group) {
			continue
		}
		if _, ok := part.Op.Render(word); !ok {
			return part.Op
		}
	}
	return nil
}

func groupSkipped(form *DisasmForm, skip map[int]bool, group int) bool {
	for group != 0 {
		if skip[group] {
			return true
		}
		group = form.GroupParent[group]
	}
	return false
}

func mutableOperandBits(op *DisasmOperand, fixedMask uint32) []int {
	seen := map[int]bool{}
	add := func(parts []BitPart) {
		for _, part := range parts {
			if part.IsLit {
				continue
			}
			for pos := part.Start; pos <= part.End; pos++ {
				if fixedMask&(uint32(1)<<uint(pos)) == 0 {
					seen[pos] = true
				}
			}
		}
	}
	add(op.Parts)
	switch op.Kind {
	case DisasmFormula:
		for _, formula := range op.Formulas {
			add(formula.Parts)
		}
	case DisasmTable:
		add(op.Cols)
	}
	positions := make([]int, 0, len(seen))
	for pos := range seen {
		positions = append(positions, pos)
	}
	sort.Ints(positions)
	return positions
}

func applyTableRow(
	word, fixedMask, fixedValue uint32,
	cols []BitPart,
	row DisasmRow,
) (uint32, bool) {
	if len(cols) != len(row.Bits) {
		return 0, false
	}
	for i, col := range cols {
		if len(row.Bits[i]) != col.Width {
			return 0, false
		}
		for j, bit := range row.Bits[i] {
			if bit == 'x' || bit == 'X' {
				continue
			}
			pos := col.End - j
			mask := uint32(1) << uint(pos)
			want := bit == '1'
			if fixedMask&mask != 0 {
				have := fixedValue&mask != 0
				if have != want {
					return 0, false
				}
				continue
			}
			if want {
				word |= mask
			} else {
				word &^= mask
			}
		}
	}
	return word, true
}

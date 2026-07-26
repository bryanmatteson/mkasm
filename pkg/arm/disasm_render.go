package arm

import (
	"fmt"
	"math/bits"
	"strings"
)

// Rendering a decoded word as assembly text.
//
// This is the reference implementation. The generated Go and Rust decoders each
// carry their own copy — they must stand alone — and the parity test asserts all
// three agree, so a divergence in one of the emitted copies is a test failure
// rather than something a user discovers.

// Render prints one decoded word as assembly text.
//
// ok is false when the word does not spell a legal instruction under this form:
// a value table with no row for the bits present means ARM left that combination
// unallocated, and there is no text to print.
func (f *DisasmForm) Render(word uint32) (string, bool) {
	if !f.matchesConstraints(word) {
		return "", false
	}
	var b strings.Builder
	skip := map[int]bool{}
	for _, p := range f.Parts {
		if p.Group == 0 {
			continue
		}
		if _, decided := skip[p.Group]; decided {
			continue
		}
		skip[p.Group] = f.groupOmitted(p.Group, word)
	}
	for _, p := range f.Parts {
		if p.Group != 0 && skip[p.Group] {
			continue
		}
		parentSkipped := false
		if p.Group != 0 {
			for parent := f.GroupParent[p.Group]; parent != 0; parent = f.GroupParent[parent] {
				if skip[parent] {
					parentSkipped = true
					break
				}
			}
		}
		if parentSkipped {
			continue
		}
		if p.Op == nil {
			b.WriteString(p.Literal)
			continue
		}
		text, ok := p.Op.Render(word)
		if !ok {
			return "", false
		}
		b.WriteString(text)
	}
	return strings.TrimRight(canonicalAsmAlternatives(collapseAsmSpace(b.String())), " "), true
}

func (f *DisasmForm) matchesConstraints(word uint32) bool {
	if word&f.ConstraintMask != f.ConstraintValue {
		return false
	}
	for _, eq := range f.EqualFields {
		width := eq.LeftEnd - eq.LeftStart + 1
		mask := uint32((uint64(1) << uint(width)) - 1)
		left := (fieldValue(word, eq.LeftStart, eq.LeftEnd) + eq.Add) & mask
		if left != fieldValue(word, eq.RightStart, eq.RightEnd) {
			return false
		}
	}
	if !f.inequalitiesMatch(word) {
		return false
	}
	for _, mask := range f.OneHotMasks {
		if bits.OnesCount32(word&mask) != 1 {
			return false
		}
	}
	for _, forbidden := range f.Forbidden {
		if word&forbidden.Mask == forbidden.Value {
			return false
		}
	}
	if guard := f.MoveWideZeroGuard; guard != nil &&
		fieldValue(word, guard.Imm16.Start, guard.Imm16.End) == 0 &&
		fieldValue(word, guard.HW.Start, guard.HW.End) != 0 {
		return false
	}
	if guard := f.LogicalMoveGuard; guard != nil &&
		moveWidePreferred(
			fieldValue(word, guard.SF.Start, guard.SF.End),
			fieldValue(word, guard.N.Start, guard.N.End),
			fieldValue(word, guard.Imms.Start, guard.Imms.End),
			fieldValue(word, guard.Immr.Start, guard.Immr.End),
		) {
		return false
	}
	if field := f.SVEMoveMaskField; field != nil {
		raw := fieldValue(word, field.Start, field.End)
		if !sveMoveMaskPreferred(raw) {
			return false
		}
	}
	return true
}

// SatisfyConstraints returns the nearest word satisfying this form's decoded
// alias predicate. It is useful when constructing a legal representative of an
// encoding; Render independently checks the same predicate.
func (f *DisasmForm) SatisfyConstraints(word uint32) (uint32, bool) {
	word = word&^f.ConstraintMask | f.ConstraintValue
	for _, eq := range f.EqualFields {
		width := eq.LeftEnd - eq.LeftStart + 1
		if width != eq.RightEnd-eq.RightStart+1 || width <= 0 || width > 31 {
			return 0, false
		}
		value := fieldValue(word, eq.LeftStart, eq.LeftEnd)
		value += eq.Add
		value &= uint32((uint64(1) << uint(width)) - 1)
		mask := fieldRangeMask(eq.RightStart, eq.RightEnd)
		word = word&^mask | value<<uint(eq.RightStart)
	}
	if candidate, ok := f.satisfyInequalities(word); ok {
		word = candidate
	} else {
		return 0, false
	}
	for _, mask := range f.OneHotMasks {
		if bits.OnesCount32(word&mask) != 1 {
			word &^= mask
			word |= mask & (^mask + 1)
		}
	}
	if guard := f.MoveWideZeroGuard; guard != nil &&
		fieldValue(word, guard.Imm16.Start, guard.Imm16.End) == 0 &&
		fieldValue(word, guard.HW.Start, guard.HW.End) != 0 {
		mask := fieldRangeMask(guard.HW.Start, guard.HW.End)
		word &^= mask
	}
	if guard := f.LogicalMoveGuard; guard != nil &&
		moveWidePreferred(
			fieldValue(word, guard.SF.Start, guard.SF.End),
			fieldValue(word, guard.N.Start, guard.N.End),
			fieldValue(word, guard.Imms.Start, guard.Imms.End),
			fieldValue(word, guard.Immr.Start, guard.Immr.End),
		) {
		sf := fieldValue(word, guard.SF.Start, guard.SF.End)
		n := fieldValue(word, guard.N.Start, guard.N.End)
		immsMask := fieldRangeMask(guard.Imms.Start, guard.Imms.End)
		immrMask := fieldRangeMask(guard.Immr.Start, guard.Immr.End)
		found := false
		for raw := uint32(0); raw < 1<<12; raw++ {
			imms, immr := raw>>6, raw&0x3f
			if moveWidePreferred(sf, n, imms, immr) ||
				!logicalImmediateEncodingValid(sf, n, imms) {
				continue
			}
			word = word&^immsMask | imms<<uint(guard.Imms.Start)
			word = word&^immrMask | immr<<uint(guard.Immr.Start)
			found = true
			break
		}
		if !found {
			return 0, false
		}
	}
	if field := f.SVEMoveMaskField; field != nil &&
		!sveMoveMaskPreferred(fieldValue(word, field.Start, field.End)) {
		mask := fieldRangeMask(field.Start, field.End)
		raw := fieldValue(word, field.Start, field.End)
		found := false
		for step := uint32(1); step < 1<<13; step++ {
			candidate := (raw + step) & ((1 << 13) - 1)
			if !sveMoveMaskPreferred(candidate) {
				continue
			}
			word = word&^mask | candidate<<uint(field.Start)
			found = true
			break
		}
		if !found {
			return 0, false
		}
	}
	if candidate, ok := f.satisfyForbidden(word); ok {
		word = candidate
	} else {
		return 0, false
	}
	return word, f.matchesConstraints(word)
}

func (f *DisasmForm) inequalitiesMatch(word uint32) bool {
	for _, neq := range f.UnequalFields {
		if fieldValue(word, neq.LeftStart, neq.LeftEnd) ==
			fieldValue(word, neq.RightStart, neq.RightEnd) {
			return false
		}
	}
	return true
}

func (f *DisasmForm) satisfyInequalities(word uint32) (uint32, bool) {
	if f.inequalitiesMatch(word) {
		return word, true
	}
	var mutable uint32
	for _, neq := range f.UnequalFields {
		mutable |= neq.RightMutable
	}
	if mutable == 0 || bits.OnesCount32(mutable) > 16 {
		return 0, false
	}
	positions := make([]int, 0, bits.OnesCount32(mutable))
	for pos := 0; pos < 32; pos++ {
		if mutable&(uint32(1)<<uint(pos)) != 0 {
			positions = append(positions, pos)
		}
	}
	for toggles := uint32(1); toggles < uint32(1)<<uint(len(positions)); toggles++ {
		candidate := word
		for i, pos := range positions {
			if toggles&(uint32(1)<<uint(i)) != 0 {
				candidate ^= uint32(1) << uint(pos)
			}
		}
		if f.inequalitiesMatch(candidate) {
			return candidate, true
		}
	}
	return 0, false
}

func (f *DisasmForm) satisfyForbidden(word uint32) (uint32, bool) {
	var mutable uint32
	violated := false
	for _, forbidden := range f.Forbidden {
		if word&forbidden.Mask == forbidden.Value {
			violated = true
			mutable |= forbidden.Mutable
		}
	}
	if !violated {
		return word, true
	}
	if mutable == 0 || bits.OnesCount32(mutable) > 16 {
		return 0, false
	}
	positions := make([]int, 0, bits.OnesCount32(mutable))
	for pos := 0; pos < 32; pos++ {
		if mutable&(uint32(1)<<uint(pos)) != 0 {
			positions = append(positions, pos)
		}
	}
	for toggles := uint32(1); toggles < uint32(1)<<uint(len(positions)); toggles++ {
		candidate := word
		for i, pos := range positions {
			if toggles&(uint32(1)<<uint(i)) != 0 {
				candidate ^= uint32(1) << uint(pos)
			}
		}
		if f.matchesConstraints(candidate) {
			return candidate, true
		}
	}
	return 0, false
}

func moveWidePreferred(sf, n, imms, immr uint32) bool {
	width := uint32(32)
	if sf != 0 {
		width = 64
		if n != 1 {
			return false
		}
	} else if n != 0 || imms&0x20 != 0 {
		return false
	}
	s, r := imms, immr
	if s < 16 {
		negRMod16 := (16 - r%16) % 16
		return negRMod16 <= 15-s
	}
	if s >= width-15 {
		return r%16 <= s-(width-15)
	}
	return false
}

func logicalImmediateEncodingValid(sf, n, imms uint32) bool {
	dataSize := 32
	if sf != 0 {
		dataSize = 64
	}
	lenValue := n<<6 | (^imms)&0x3f
	length := -1
	for v := lenValue; v != 0; v >>= 1 {
		length++
	}
	if length < 1 {
		return false
	}
	levels := uint32(1<<uint(length)) - 1
	return imms&levels != levels && 1<<uint(length) <= dataSize
}

// sveMoveMaskPreferred implements ARM's named preferred-disassembly predicate
// for MOV (alias of DUPM). It rejects logical masks that a single DUP
// immediate can express, because those words must retain the DUPM spelling.
func sveMoveMaskPreferred(raw uint32) bool {
	imm, ok := decodePackedLogicalImmediate(raw)
	if !ok {
		return false
	}
	halves := uint32(imm>>32) == uint32(imm)
	quarters := uint16(imm>>16) == uint16(imm) && halves
	if byte(imm) != 0 {
		if zeroOrOnesRange(imm, 7, 63) {
			return false
		}
		if halves && zeroOrOnesRange(imm, 7, 31) {
			return false
		}
		if quarters && zeroOrOnesRange(imm, 7, 15) {
			return false
		}
		if quarters && byte(imm>>8) == byte(imm) {
			return false
		}
		return true
	}
	if zeroOrOnesRange(imm, 15, 63) {
		return false
	}
	if halves && zeroOrOnesRange(imm, 15, 31) {
		return false
	}
	return !quarters
}

func decodePackedLogicalImmediate(raw uint32) (uint64, bool) {
	n, immr, imms := raw>>12, raw>>6&0x3f, raw&0x3f
	lenValue := n<<6 | (^imms)&0x3f
	length := -1
	for v := lenValue; v != 0; v >>= 1 {
		length++
	}
	if length < 1 {
		return 0, false
	}
	levels := uint32(1<<uint(length)) - 1
	s, r := imms&levels, immr&levels
	if s == levels {
		return 0, false
	}
	elementSize := 1 << uint(length)
	ones := uint64(1)<<uint(s+1) - 1
	elementMask := uint64(1)<<uint(elementSize) - 1
	rotation := int(r) % elementSize
	element := ((ones >> uint(rotation)) | (ones << uint(elementSize-rotation))) & elementMask
	var value uint64
	for shift := 0; shift < 64; shift += elementSize {
		value |= element << uint(shift)
	}
	return value, true
}

func zeroOrOnesRange(value uint64, lo, hi uint) bool {
	width := hi - lo + 1
	mask := uint64(1)<<width - 1
	got := value >> lo & mask
	return got == 0 || got == mask
}

// groupOmitted reports whether an optional group reads as its default and is
// therefore not printed. ARM encodes an omitted operand as zero everywhere it
// does not name another value.
func (f *DisasmForm) groupOmitted(group int, word uint32) bool {
	if f.RequiredGroups[group] {
		return false
	}
	// The 32-bit extended-register ADD/SUB forms overlap the shifted-register
	// syntax when the optional extension is omitted. Preserve the explicit
	// UXT*/SXT* spelling so a round trip selects this encoding family rather
	// than LLVM's shifted-register canonical form.
	if strings.Contains(f.EncodingID, "addsub_ext") {
		return false
	}
	for _, p := range f.Parts {
		if p.Op == nil || !f.groupContains(group, p.Group) {
			continue
		}
		want := uint64(0)
		if p.Op.HasDefault && p.Op.Default >= 0 {
			scale := p.Op.Scale
			if scale < 1 {
				scale = 1
			}
			semantic := p.Op.Default / scale
			if p.Op.Negate != 0 {
				semantic = p.Op.Negate - semantic
			} else {
				semantic -= p.Op.Bias
			}
			if semantic >= 0 {
				want = uint64(semantic)
			}
		}
		if p.Op.rawValue(word) != want {
			return false
		}
	}
	// A documentation-only optional group may contain a fixed literal and no
	// operand at all, for example CAS's "{, #0}". It encodes no choice and its
	// canonical spelling is omission.
	return true
}

func (f *DisasmForm) groupContains(group, candidate int) bool {
	for candidate != 0 {
		if candidate == group {
			return true
		}
		candidate = f.GroupParent[candidate]
	}
	return false
}

// Render prints one operand slot.
func (o *DisasmOperand) Render(word uint32) (string, bool) {
	if o.WhenMask != 0 && word&o.WhenMask != o.WhenValue {
		return "", true
	}
	switch o.Kind {
	case DisasmTable:
		return o.renderTable(word)
	case DisasmReg:
		raw := int64(o.rawValue(word))
		v := raw + o.Bias
		if len(o.RegRanges) > 0 {
			var found bool
			var encodedLo int64
			for _, r := range o.RegRanges {
				count := r.Hi - r.Lo + 1
				if raw >= encodedLo && raw < encodedLo+count {
					v = raw + r.Bias
					found = true
					break
				}
				encodedLo += count
			}
			if !found {
				return "", false
			}
		}
		if o.Negate != 0 {
			v = o.Negate - raw
		}
		v *= o.Scale
		if v < 0 {
			return "", false
		}
		if o.HasRegRange && (v < o.RegLo || v > o.RegHi) {
			return "", false
		}
		if o.RegMultiple > 1 && v%o.RegMultiple != 0 {
			return "", false
		}
		name := RegisterName(o.Class, uint64(v))
		return name, name != ""
	case DisasmNum:
		return o.renderNum(word)
	case DisasmFpImm:
		return o.renderFpImm(word)
	case DisasmSysReg:
		// ARM encodes a system register as o0:op1:CRn:CRm:op2.  The stored
		// o0 field is one bit; architectural generic syntax spells the
		// corresponding two-bit op0 value as 2+o0.
		if len(o.Parts) != 5 ||
			o.Parts[0].Width != 1 || o.Parts[1].Width != 3 ||
			o.Parts[2].Width != 4 || o.Parts[3].Width != 4 ||
			o.Parts[4].Width != 3 {
			return "", false
		}
		values := make([]uint64, len(o.Parts))
		for i, part := range o.Parts {
			values[i] = uint64(word>>uint(part.Start)) & ((uint64(1) << uint(part.Width)) - 1)
		}
		return fmt.Sprintf("s%d_%d_c%d_c%d_%d",
			2+values[0], values[1], values[2], values[3], values[4]), true
	case DisasmDerived:
		return o.renderDerived(word)
	case DisasmFormula:
		return o.renderFormula(word)
	case DisasmLogicalImm:
		return o.renderLogicalImmediate(word)
	case DisasmBitfieldWidth:
		return o.renderBitfieldWidth(word)
	case DisasmByteMaskImm:
		return o.renderByteMaskImmediate(word)
	case DisasmMoveWideImm:
		return o.renderMoveWideImmediate(word)
	case DisasmLiteral:
		return o.Literal, o.Literal != ""
	case DisasmElementIndex:
		return o.renderElementIndex(word)
	case DisasmTileMask:
		return o.renderTileMask(word)
	}
	return "", false
}

func (o *DisasmOperand) renderTileMask(word uint32) (string, bool) {
	if len(o.Parts) != 1 || o.Parts[0].Width != 8 {
		return "", false
	}
	mask := fieldValue(word, o.Parts[0].Start, o.Parts[0].End)
	names := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		if mask&(uint32(1)<<uint(i)) != 0 {
			names = append(names, fmt.Sprintf("za%d.d", i))
		}
	}
	return strings.Join(names, ", "), true
}

func (o *DisasmOperand) renderElementIndex(word uint32) (string, bool) {
	if o.IndexSizeParts <= 0 || o.IndexSizeParts >= len(o.Parts) {
		return "", false
	}
	var raw, size uint64
	sizeStart := len(o.Parts) - o.IndexSizeParts
	for i, part := range o.Parts {
		value := uint64(fieldValue(word, part.Start, part.End))
		raw = raw<<uint(part.Width) | value
		if i >= sizeStart {
			size = size<<uint(part.Width) | value
		}
	}
	if size == 0 {
		return "", false
	}
	lsb := 0
	for size&1 == 0 {
		lsb++
		size >>= 1
	}
	return fmt.Sprintf("%d", raw>>uint(lsb+1)), true
}

func (o *DisasmOperand) renderMoveWideImmediate(word uint32) (string, bool) {
	if len(o.Parts) != 3 {
		return "", false
	}
	imm16 := uint64(fieldValue(word, o.Parts[0].Start, o.Parts[0].End))
	hw := fieldValue(word, o.Parts[1].Start, o.Parts[1].End)
	sf := fieldValue(word, o.Parts[2].Start, o.Parts[2].End)
	dataSize := 32
	if sf != 0 {
		dataSize = 64
	}
	shift := int(hw) * 16
	if shift >= dataSize {
		return "", false
	}
	value := imm16 << uint(shift)
	if o.MoveWideInvert {
		value = ^value
		if dataSize == 32 {
			value &= 0xffffffff
		}
	}
	return fmt.Sprintf("0x%x", value), true
}

func (o *DisasmOperand) renderByteMaskImmediate(word uint32) (string, bool) {
	if len(o.Parts) != 8 {
		return "", false
	}
	var value uint64
	for _, part := range o.Parts {
		value <<= 8
		if fieldValue(word, part.Start, part.End) != 0 {
			value |= 0xff
		}
	}
	return fmt.Sprintf("0x%x", value), true
}

func (o *DisasmOperand) renderLogicalImmediate(word uint32) (string, bool) {
	var n, immr, imms, sf uint32
	packed := false
	switch len(o.Parts) {
	case 1:
		if o.Parts[0].Width != 13 {
			return "", false
		}
		raw := fieldValue(word, o.Parts[0].Start, o.Parts[0].End)
		n, immr, imms, sf = raw>>12, raw>>6&0x3f, raw&0x3f, 1
		packed = true
	case 4:
		n = fieldValue(word, o.Parts[0].Start, o.Parts[0].End)
		immr = fieldValue(word, o.Parts[1].Start, o.Parts[1].End)
		imms = fieldValue(word, o.Parts[2].Start, o.Parts[2].End)
		sf = fieldValue(word, o.Parts[3].Start, o.Parts[3].End)
	default:
		return "", false
	}
	dataSize := 32
	if sf != 0 {
		dataSize = 64
	}
	lenValue := n<<6 | (^imms)&0x3f
	length := -1
	for v := lenValue; v != 0; v >>= 1 {
		length++
	}
	if length < 1 {
		return "", false
	}
	levels := uint32(1<<uint(length)) - 1
	s, r := imms&levels, immr&levels
	if s == levels {
		return "", false
	}
	elementSize := 1 << uint(length)
	if elementSize > dataSize {
		return "", false
	}
	ones := uint64(1)<<uint(s+1) - 1
	elementMask := uint64(1)<<uint(elementSize) - 1
	rotation := int(r) % elementSize
	element := ((ones >> uint(rotation)) | (ones << uint(elementSize-rotation))) & elementMask
	if o.LogicalInvert {
		element = ^element & elementMask
	}
	if packed {
		// SVE's imm13 form prints the value of one element. The vector
		// operation performs replication; spelling the replicated 64-bit mask
		// is not a compatible immediate for .b/.h/.s arrangements.
		return fmt.Sprintf("0x%x", element), true
	}
	var value uint64
	for shift := 0; shift < dataSize; shift += elementSize {
		value |= element << uint(shift)
	}
	return fmt.Sprintf("0x%x", value), true
}

func (o *DisasmOperand) renderBitfieldWidth(word uint32) (string, bool) {
	if len(o.Parts) != 2 {
		return "", false
	}
	imms := fieldValue(word, o.Parts[0].Start, o.Parts[0].End)
	if o.DataSize > 0 && int64(imms) >= o.DataSize {
		return "", false
	}
	if o.Add == 1 {
		immr := fieldValue(word, o.Parts[1].Start, o.Parts[1].End)
		if imms >= immr {
			return "", false
		}
		return fmt.Sprintf("%d", imms+1), true
	}
	immr := fieldValue(word, o.Parts[1].Start, o.Parts[1].End)
	if imms < immr {
		return "", false
	}
	return fmt.Sprintf("%d", imms-immr+1), true
}

func (o *DisasmOperand) renderFormula(word uint32) (string, bool) {
	got := make([]string, len(o.Cols))
	for i, c := range o.Cols {
		got[i] = bitsOf(word, c.Start, c.End)
	}
	for i, row := range o.Rows {
		if i >= len(o.Formulas) || !rowMatches(row.Bits, got) {
			continue
		}
		formula := o.Formulas[i]
		var raw uint64
		var sizeRaw uint64
		for partIndex, part := range formula.Parts {
			raw <<= uint(part.Width)
			if partIndex < formula.SizeParts {
				sizeRaw <<= uint(part.Width)
			}
			if part.IsLit {
				var literal uint64
				for _, bit := range part.Literal {
					literal <<= 1
					if bit == '1' {
						literal |= 1
					}
				}
				raw |= literal
				if partIndex < formula.SizeParts {
					sizeRaw |= literal
				}
				continue
			}
			value := uint64(fieldValue(word, part.Start, part.End))
			raw |= value
			if partIndex < formula.SizeParts {
				sizeRaw |= value
			}
		}
		rawMul := formula.RawMul
		if rawMul == 0 {
			rawMul = 1
		}
		value := int64(raw)*rawMul + formula.Add
		if formula.Negate != 0 {
			value = formula.Negate - int64(raw)
		}
		if formula.ESizeMul != 0 {
			if sizeRaw == 0 {
				return "", false
			}
			highest := 0
			for n := sizeRaw; n > 1; n >>= 1 {
				highest++
			}
			esize := formula.ESizeBase << uint(highest)
			value += formula.ESizeMul * esize
		}
		if value < 0 {
			return "", false
		}
		return fmt.Sprintf("%d", value), true
	}
	return "", false
}

func (o *DisasmOperand) renderFpImm(word uint32) (string, bool) {
	raw := o.rawValue(word)
	if raw > 0xff {
		return "", false
	}
	sign := 1.0
	if raw&0x80 != 0 {
		sign = -1
	}
	n := float64(16 + raw&0x0f)
	exp := int((raw >> 4) & 7)
	r := exp + 1
	if exp >= 4 {
		r = exp - 7
	}
	scale := 1.0
	if r >= 0 {
		for i := 0; i < r; i++ {
			scale *= 2
		}
	} else {
		for i := 0; i < -r; i++ {
			scale /= 2
		}
	}
	return fmt.Sprintf("%g", sign*n/16*scale), true
}

func (o *DisasmOperand) renderDerived(word uint32) (string, bool) {
	v := o.Add
	if len(o.Parts) > 0 {
		v = int64(o.rawValue(word))*o.Mul + o.Add
	}
	if o.Mod > 0 {
		v = ((v % o.Mod) + o.Mod) % o.Mod
	}
	if o.Class == "" {
		return fmt.Sprintf("%d", v), true
	}
	name := RegisterName(o.Class, uint64(v))
	return name, name != ""
}

func (o *DisasmOperand) renderTable(word uint32) (string, bool) {
	got := make([]string, len(o.Cols))
	for i, c := range o.Cols {
		got[i] = bitsOf(word, c.Start, c.End)
	}
	if o.Xor != 0 {
		// Xor is expressed over the concatenated selector with the last table
		// column containing its least-significant bits.
		for bit := uint64(1); bit <= o.Xor; bit <<= 1 {
			if o.Xor&bit == 0 {
				continue
			}
			pos := int(bitIndex(bit))
			for i := len(got) - 1; i >= 0; i-- {
				if pos < len(got[i]) {
					j := len(got[i]) - 1 - pos
					if got[i][j] == '0' {
						got[i] = got[i][:j] + "1" + got[i][j+1:]
					} else {
						got[i] = got[i][:j] + "0" + got[i][j+1:]
					}
					break
				}
				pos -= len(got[i])
			}
		}
	}
	for _, row := range o.Rows {
		if !rowMatches(row.Bits, got) {
			continue
		}
		if numericTablePlaceholder(row.Symbol) {
			return fmt.Sprintf("#%d", o.rawValue(word)), true
		}
		// ARM spells a suffix that is either there or not as a table over the bit
		// that selects it: ADDHN{2}'s <2> reads [absent] for Q=0 and [present]
		// for Q=1. The spelling in that case is the operand's own symbol.
		switch strings.ToLower(row.Symbol) {
		case "[absent]":
			return "", true
		case "[present]":
			return o.Symbol, true
		}
		return canonicalAsmSymbol(row.Symbol), true
	}
	return "", false
}

// numericTablePlaceholder recognizes ARM's table notation for a numeric
// fallback spelling. "#uimm4" is a type-and-width placeholder, not literal
// assembler text; the matching selector bits are the immediate value.
func numericTablePlaceholder(symbol string) bool {
	s := strings.ToLower(strings.TrimSpace(symbol))
	if !strings.HasPrefix(s, "#uimm") || len(s) == len("#uimm") {
		return false
	}
	for _, c := range s[len("#uimm"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func bitIndex(bit uint64) uint {
	var n uint
	for bit > 1 {
		bit >>= 1
		n++
	}
	return n
}

// canonicalAsmSymbol chooses one concrete spelling when ARM's value table
// documents several assembler-equivalent spellings in parentheses. Emitting
// the documentation notation itself, for example "(WZR|XZR)", is not valid
// assembly text.
func canonicalAsmSymbol(symbol string) string {
	s := strings.ToLower(strings.TrimSpace(symbol))
	if len(s) >= 3 && s[0] == '(' && s[len(s)-1] == ')' {
		if bar := strings.IndexByte(s, '|'); bar > 1 {
			return strings.TrimSpace(s[1:bar])
		}
	}
	if bar := strings.IndexByte(s, '|'); bar > 0 {
		if s[:bar] == "lsl" {
			return strings.TrimSpace(s[bar+1:])
		}
		return strings.TrimSpace(s[:bar])
	}
	return s
}

// canonicalAsmAlternatives turns ARM's documentation notation for
// assembler-equivalent literal spellings into one concrete spelling. Some
// templates contain the choice as literal text rather than a value-table
// operand, for example "(WZR|XZR)"; clang quite reasonably rejects the
// parentheses and bar.
func canonicalAsmAlternatives(s string) string {
	for start := 0; start < len(s); {
		relEnd := strings.IndexByte(s[start:], ')')
		if relEnd < 0 {
			break
		}
		end := start + relEnd
		relOpen := strings.LastIndexByte(s[start:end], '(')
		if relOpen < 0 {
			start = end + 1
			continue
		}
		open := start + relOpen
		inside := s[open+1 : end]
		bar := strings.IndexByte(inside, '|')
		if bar < 0 {
			start = end + 1
			continue
		}
		left, right := strings.TrimSpace(inside[:bar]), strings.TrimSpace(inside[bar+1:])
		if left == "" {
			left = right
		}
		s = s[:open] + left + s[end+1:]
		start = open
	}
	for {
		bar := strings.IndexByte(s, '|')
		if bar < 0 {
			break
		}
		left := bar
		for left > 0 && !strings.ContainsRune(" \t,[]{}", rune(s[left-1])) {
			left--
		}
		right := bar + 1
		for right < len(s) && !strings.ContainsRune(" \t,[]{}", rune(s[right])) {
			right++
		}
		choice := strings.TrimSpace(s[left:bar])
		if choice == "" {
			choice = strings.TrimSpace(s[bar+1 : right])
		}
		s = s[:left] + choice + s[right:]
	}
	return s
}

func (o *DisasmOperand) renderNum(word uint32) (string, bool) {
	raw := o.rawValue(word)
	width := o.totalWidth()
	var v int64
	switch {
	case o.HasNumConstant:
		v = o.NumConstant
	case o.Negate != 0:
		v = o.Negate - int64(raw)
	case o.Signed:
		v = signExtend(raw, width) + o.Bias
	default:
		v = int64(raw) + o.Bias
	}
	if o.RawMul != 0 {
		v *= o.RawMul
	}
	v *= o.Scale
	if o.HasRange && (v < o.Lo || v > o.Hi) {
		return "", false
	}
	if o.Class == ClassLabel {
		// A branch target is an offset from this instruction, and the assembler
		// spells "here" as ".". Printing the bare number would read as an
		// absolute address and assemble to a different target.
		if v < 0 {
			return fmt.Sprintf(".-%d", -v), true
		}
		return fmt.Sprintf(".+%d", v), true
	}
	if strings.Contains(o.Symbol, "|SP") && v == 31 {
		return "sp", true
	}
	return fmt.Sprintf("%s%d", o.NumPrefix, v), true
}

// rawValue assembles the operand's bits, most significant part first.
func (o *DisasmOperand) rawValue(word uint32) uint64 {
	if len(o.Cols) > 0 && len(o.Parts) == 0 {
		var v uint64
		for _, c := range o.Cols {
			v = v<<uint(c.Width) | uint64(fieldValue(word, c.Start, c.End))
		}
		return v
	}
	var v uint64
	for _, p := range o.Parts {
		if p.IsLit {
			lit := uint64(0)
			for _, ch := range p.Literal {
				lit = lit << 1
				if ch == '1' {
					lit |= 1
				}
			}
			v = v<<uint(p.Width) | lit
			continue
		}
		v = v<<uint(p.Width) | uint64(fieldValue(word, p.Start, p.End))
	}
	return v
}

func (o *DisasmOperand) totalWidth() int {
	n := 0
	for _, p := range o.Parts {
		n += p.Width
	}
	if n == 0 {
		for _, c := range o.Cols {
			n += c.Width
		}
	}
	return n
}

func fieldValue(word uint32, start, end int) uint32 {
	if start < 0 || end < start || end > 31 {
		return 0
	}
	width := uint(end - start + 1)
	mask := uint32((uint64(1) << width) - 1)
	return (word >> uint(start)) & mask
}

// bitsOf renders a field as a bit string, most significant first, to compare
// against ARM's value tables, which are written that way.
func bitsOf(word uint32, start, end int) string {
	if start < 0 || end < start || end > 31 {
		return ""
	}
	b := make([]byte, 0, end-start+1)
	for i := end; i >= start; i-- {
		if (word>>uint(i))&1 == 1 {
			b = append(b, '1')
		} else {
			b = append(b, '0')
		}
	}
	return string(b)
}

func rowMatches(pattern, got []string) bool {
	if len(pattern) != len(got) {
		return false
	}
	for i := range pattern {
		p, g := pattern[i], got[i]
		if len(p) != len(g) {
			return false
		}
		for j := 0; j < len(p); j++ {
			switch p[j] {
			case '0', '1':
				if p[j] != g[j] {
					return false
				}
			}
		}
	}
	return true
}

func signExtend(v uint64, width int) int64 {
	if width <= 0 || width >= 64 {
		return int64(v)
	}
	sign := uint64(1) << uint(width-1)
	if v&sign != 0 {
		return int64(v | ^(sign<<1 - 1))
	}
	return int64(v)
}

// collapseAsmSpace squeezes the runs of spaces ARM uses to align its templates
// down to the single space an assembler expects.
func collapseAsmSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(s[i])
	}
	return b.String()
}

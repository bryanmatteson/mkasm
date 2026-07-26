package ir

import "fmt"

// FieldValue is a named bitfield extracted from or packed into an instruction word.
type FieldValue struct {
	Name  string
	Start int
	End   int
	Value uint64
	Fixed bool
}

// ExtractFields reads all fields of enc from word (LSB = bit 0).
// Invalid ranges are skipped.
func ExtractFields(word uint32, enc EncodingMask) []FieldValue {
	out := make([]FieldValue, 0, len(enc.Fields))
	for _, f := range enc.Fields {
		if f.Start < 0 || f.End < f.Start || f.Start > 31 {
			continue
		}
		width := f.End - f.Start + 1
		if width <= 0 || width > 32 || f.Start+width > 32 {
			continue
		}
		mask := uint32((uint64(1)<<uint(width))-1) << uint(f.Start)
		v := uint64((word & mask) >> uint(f.Start))
		out = append(out, FieldValue{
			Name:  f.Name,
			Start: f.Start,
			End:   f.End,
			Value: v,
			Fixed: f.Fixed != nil,
		})
	}
	return out
}

// InsertField packs value into word at [Start:End] (LSB = 0). Other bits unchanged.
func InsertField(word uint32, f BitField, value uint64) (uint32, error) {
	if f.Start < 0 || f.End < f.Start || f.Start > 31 {
		return word, fmt.Errorf("invalid field range %s [%d:%d]", f.Name, f.Start, f.End)
	}
	width := f.End - f.Start + 1
	if width <= 0 || width > 32 || f.Start+width > 32 {
		return word, fmt.Errorf("invalid field width %s", f.Name)
	}
	max := uint64(1)<<uint(width) - 1
	if value > max {
		return word, fmt.Errorf("value %d overflows field %s width %d", value, f.Name, width)
	}
	mask := uint32(max) << uint(f.Start)
	word &^= mask
	word |= uint32(value) << uint(f.Start)
	return word, nil
}

// PackFields starts from base and inserts each named value using fields from enc.
// Unknown names are ignored; fixed fields can still be overridden if provided.
func PackFields(base uint32, enc EncodingMask, values map[string]uint64) (uint32, error) {
	byName := make(map[string]BitField, len(enc.Fields))
	for _, f := range enc.Fields {
		if f.Name != "" {
			byName[f.Name] = f
		}
	}
	w := base
	for name, val := range values {
		f, ok := byName[name]
		if !ok {
			continue
		}
		var err error
		w, err = InsertField(w, f, val)
		if err != nil {
			return 0, err
		}
	}
	return w, nil
}

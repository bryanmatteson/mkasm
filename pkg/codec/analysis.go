package codec

import (
	"fmt"
	"strings"
)

// Position retains the exact architectural base, alignment, region and wrapping
// rules of a relative operand. A zero Position is independent of its location.
type Position struct {
	Relative     bool
	Bias         int64
	PreAlignBias int64
	AlignBits    int
	RegionBits   int
	WrapBits     int
	LowWrapBits  int
	BankBits     int
}

func (o Operand) Position() Position {
	if !o.Relative {
		return Position{}
	}
	return Position{true, o.PCBias, o.PCPreAlignBias, o.PCAlignBits, o.PCRegionBits, o.PCWrapBits, o.PCLowWrapBits, o.PCBankBits}
}

func (p Position) operand() (Operand, bool) {
	if !p.Relative || p.AlignBits < 0 || p.AlignBits > 63 || p.RegionBits < 0 || p.RegionBits > 63 || p.WrapBits < 0 || p.WrapBits > 64 || p.LowWrapBits < 0 || p.LowWrapBits > 63 || p.LowWrapBits > p.WrapBits || p.BankBits < 0 || p.BankBits > 63 || (p.BankBits > 0 && (p.RegionBits > 0 || p.BankBits > p.WrapBits)) {
		return Operand{}, false
	}
	return Operand{Relative: true, PCBias: p.Bias, PCPreAlignBias: p.PreAlignBias, PCAlignBits: p.AlignBits, PCRegionBits: p.RegionBits, PCWrapBits: p.WrapBits, PCLowWrapBits: p.LowWrapBits, PCBankBits: p.BankBits}, true
}

func (p Position) IsPositionDependent() bool { return p.Relative }

func (p Position) Target(address uint64, value int64) (uint64, bool) {
	o, ok := p.operand()
	if !ok {
		return 0, false
	}
	return relativeTarget(o, value, address), true
}

// ValueForTarget inverts Target. Encode checks the selected form's field range,
// scaling and relational constraints after this architectural address step.
func (p Position) ValueForTarget(address, target uint64) (int64, bool) {
	o, ok := p.operand()
	if !ok {
		return 0, false
	}
	base := relativeBase(o, address)
	wrap := relativeWrapBits(o, address)
	if wrap > 0 && wrap < 64 {
		mask := uint64(1)<<uint(wrap) - 1
		if target&^mask != 0 {
			return 0, false
		}
		base &= mask
	}
	if p.RegionBits > 0 {
		mask := uint64(1)<<uint(p.RegionBits) - 1
		return int64(target & mask), target&^mask == base&^mask
	}
	if p.BankBits > 0 {
		mask := uint64(1)<<uint(p.BankBits) - 1
		bank := address &^ mask
		if wrap > 0 && wrap < 64 {
			bank &= uint64(1)<<uint(wrap) - 1
		}
		if target&^mask != bank {
			return 0, false
		}
		shift := uint(64 - p.BankBits)
		return int64((target-base)<<shift) >> shift, true
	}
	delta := target - base
	if wrap > 0 && wrap < 64 {
		shift := uint(64 - wrap)
		return int64(delta<<shift) >> shift, true
	}
	return int64(delta), true
}

type OperandSpan struct {
	Start, End   int
	OperandIndex int
	Name, Class  string
	Kind         string
	Value        int64
	Position     Position
}

type Described struct {
	Text     string
	Operands []OperandSpan
}

// Describe returns the formatter's exact text and a replaceable byte range for
// every printed operand occurrence, preserving repeated operands and literals.
func (d *Decoded) Describe(address uint64) Described {
	protected := escapedSyntax(d.Encoding.Syntax)
	var text strings.Builder
	var spans []OperandSpan
	for {
		i := strings.IndexByte(protected, '{')
		if i < 0 {
			text.WriteString(literalSyntax(protected))
			break
		}
		text.WriteString(literalSyntax(protected[:i]))
		protected = protected[i+1:]
		j := strings.IndexByte(protected, '}')
		if j < 0 {
			text.WriteByte('{')
			text.WriteString(protected)
			break
		}
		name := protected[:j]
		protected = protected[j+1:]
		for index, o := range d.Encoding.Operands {
			if o.Name != name {
				continue
			}
			// Format one operand through the same formatter, retaining all bias,
			// name, unsigned-bit-pattern and PC rules instead of reparsing text.
			one := *d.Encoding
			one.Syntax = "{" + name + "}"
			start := text.Len()
			text.WriteString((&Decoded{Encoding: &one, Values: d.Values}).Format(address))
			spans = append(spans, OperandSpan{start, text.Len(), index, o.Name, o.Class, o.Kind, d.Values[o.Name], o.Position()})
			break
		}
	}
	return Described{Text: text.String(), Operands: spans}
}

func (c *Catalog) Describe(src []byte, address uint64, features []string) (Described, error) {
	d, err := c.DecodeWithFeatures(src, features)
	if err != nil {
		return Described{}, err
	}
	return d.Describe(address), nil
}

// Relocated preserves every statically encoded relative target and all other
// fields. Exact-form range errors are returned instead of choosing another form.
func (d *Decoded) Relocated(from, to uint64) (*Decoded, error) {
	next := &Decoded{Encoding: d.Encoding, Length: d.Length, Values: make(map[string]int64, len(d.Values))}
	for name, value := range d.Values {
		next.Values[name] = value
	}
	if from != to {
		for _, o := range d.Encoding.Operands {
			if !o.Relative {
				continue
			}
			target := relativeTarget(o, d.Values[o.Name], from)
			value, ok := o.Position().ValueForTarget(to, target)
			if !ok {
				return nil, fmt.Errorf("%s: relocated target leaves operand %s region", d.Encoding.ID, o.Name)
			}
			next.Values[o.Name] = value
		}
	}
	if _, err := Encode(next.Encoding, next.Values); err != nil {
		return nil, err
	}
	if !addressConstraintsMatch(next.Encoding, next.Values, to) {
		return nil, fmt.Errorf("%s: relocated address constraints", d.Encoding.ID)
	}
	return next, nil
}

// SetOperand commits an edit only when the complete instruction remains valid.
func (d *Decoded) SetOperand(name string, value int64) error {
	next := make(map[string]int64, len(d.Values))
	found := false
	for _, o := range d.Encoding.Operands {
		next[o.Name] = d.Values[o.Name]
		found = found || o.Name == name
	}
	if !found {
		return fmt.Errorf("%s: unknown operand %s", d.Encoding.ID, name)
	}
	next[name] = value
	if _, err := Encode(d.Encoding, next); err != nil {
		return err
	}
	d.Values = next
	return nil
}

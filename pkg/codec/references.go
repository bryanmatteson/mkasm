package codec

import "fmt"

// AddressReferenceKind distinguishes control destinations from addresses used
// as data. Absolute references do not change when an instruction moves.
type AddressReferenceKind string

const (
	ReferenceBranch   AddressReferenceKind = "branch"
	ReferenceData     AddressReferenceKind = "data"
	ReferenceLiteral  AddressReferenceKind = "literal"
	ReferenceAbsolute AddressReferenceKind = "absolute"
)

// AddressReference retains physical bit placement and the complete imported
// address calculation. RawMin/RawMax bound the integer before Scale/Bias.
type AddressReference struct {
	OperandIndex int
	Name         string
	Kind         AddressReferenceKind
	Bits         []BitSlice
	Signed       bool
	Scale        int64
	Bias         int64
	Position     Position
	RawMin       int64
	RawMax       uint64
	Target       uint64
}

func referenceKind(e *Encoding, o Operand) AddressReferenceKind {
	switch e.FlowControl {
	case "branch", "call", "conditional_call", "conditional-call", "conditional_branch", "conditional-branch", "unconditional_branch", "unconditional-branch", "loop":
		return ReferenceBranch
	}
	if !o.Relative {
		return ReferenceAbsolute
	}
	if o.Kind == "address" {
		return ReferenceLiteral
	}
	return ReferenceData
}

// AddressReferences includes explicitly modeled addresses only. Displacements
// from runtime register values cannot be resolved statically.
func (d *Decoded) AddressReferences(address uint64) []AddressReference {
	var refs []AddressReference
	for i, o := range d.Encoding.Operands {
		if !o.Relative && o.Kind != "address" {
			continue
		}
		target := uint64(d.Values[o.Name])
		if o.Relative {
			target = relativeTarget(o, d.Values[o.Name], address)
		}
		if referenceKind(d.Encoding, o) == ReferenceBranch && d.Encoding.TargetMask != 0 {
			target &= d.Encoding.TargetMask
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		width := 0
		for _, b := range o.Bits {
			if b.ValueBit+b.Width > width {
				width = b.ValueBit + b.Width
			}
		}
		var min int64
		var max uint64
		if width > 0 {
			if o.Signed {
				min = -(int64(1) << uint(width-1))
				max = (uint64(1) << uint(width-1)) - 1
			} else if width == 64 {
				max = ^uint64(0)
			} else {
				max = (uint64(1) << uint(width)) - 1
			}
		}
		refs = append(refs, AddressReference{OperandIndex: i, Name: o.Name, Kind: referenceKind(d.Encoding, o), Bits: append([]BitSlice(nil), o.Bits...), Signed: o.Signed, Scale: scale, Bias: o.Bias, Position: o.Position(), RawMin: min, RawMax: max, Target: target})
	}
	return refs
}

// RewriteReference validates every field and address constraint before replacing
// caller storage. References are selected by their stable operand index.
func (d *Decoded) RewriteReference(address uint64, operandIndex int, target uint64, output []byte) (int, error) {
	if operandIndex < 0 || operandIndex >= len(d.Encoding.Operands) {
		return 0, fmt.Errorf("invalid address operand")
	}
	o := d.Encoding.Operands[operandIndex]
	if !o.Relative && o.Kind != "address" {
		return 0, fmt.Errorf("operand is not an encoded address")
	}
	if referenceKind(d.Encoding, o) == ReferenceBranch && d.Encoding.TargetMask != 0 && target & ^d.Encoding.TargetMask != 0 {
		return 0, fmt.Errorf("target is not an architectural destination")
	}
	next := &Decoded{Encoding: d.Encoding, Length: d.Length, Values: make(map[string]int64, len(d.Values))}
	for k, v := range d.Values {
		next.Values[k] = v
	}
	value := int64(target)
	if o.Relative {
		var ok bool
		value, ok = o.Position().ValueForTarget(address, target)
		if !ok {
			return 0, fmt.Errorf("target outside address region")
		}
	}
	next.Values[o.Name] = value
	if !addressConstraintsMatch(next.Encoding, next.Values, address) {
		return 0, fmt.Errorf("address constraints")
	}
	bytes, err := Encode(next.Encoding, next.Values)
	if err != nil {
		return 0, err
	}
	values, err := decodeValues(next.Encoding, bytes)
	if err != nil {
		return 0, err
	}
	back := &Decoded{Encoding: next.Encoding, Length: next.Length, Values: values}
	for _, r := range back.AddressReferences(address) {
		if r.OperandIndex == operandIndex && r.Target != target {
			return 0, fmt.Errorf("target cannot be represented exactly")
		}
	}
	if len(output) < len(bytes) {
		return 0, fmt.Errorf("output buffer too small")
	}
	copy(output, bytes)
	return len(bytes), nil
}

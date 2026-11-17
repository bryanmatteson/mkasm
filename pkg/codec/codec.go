package codec

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ErrTruncated = errors.New("truncated instruction")
var ErrUnknown = errors.New("unknown instruction")

func (o Operand) Width() int {
	n := 0
	for _, b := range o.Bits {
		if b.ValueBit+b.Width > n {
			n = b.ValueBit + b.Width
		}
	}
	return n
}

func (c *Catalog) Validate() error {
	if c.Architecture == "" {
		return errors.New("codec: empty architecture")
	}
	if len(c.Encodings) == 0 {
		return errors.New("codec: empty encoding catalog")
	}
	ids := map[string]bool{}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.ID == "" || ids[e.ID] {
			return fmt.Errorf("codec: missing or duplicate encoding ID %q", e.ID)
		}
		ids[e.ID] = true
		if (e.FixedTarget != nil || e.TargetMask != 0) && !directControlFlow(e.FlowControl) {
			return fmt.Errorf("%s: direct target metadata requires direct control flow", e.ID)
		}
		if e.Mnemonic == "" || strings.TrimSpace(e.Syntax) == "" || e.DelaySlots < 0 || len(e.Mask) == 0 || len(e.Mask) != len(e.Value) || len(e.Mask) > 256 {
			return fmt.Errorf("%s: invalid encoding framing", e.ID)
		}
		used := append([]byte(nil), e.Mask...)
		for j := range e.Mask {
			if e.Value[j] & ^e.Mask[j] != 0 {
				return fmt.Errorf("%s: value outside mask at byte %d", e.ID, j)
			}
		}
		names := map[string]bool{}
		for _, o := range e.Operands {
			if o.Name == "" || names[o.Name] || len(o.Bits) == 0 {
				return fmt.Errorf("%s: invalid/duplicate operand %q", e.ID, o.Name)
			}
			names[o.Name] = true
			if o.Scale < 0 || o.Width() > 64 {
				return fmt.Errorf("%s: invalid operand scale/width for %s", e.ID, o.Name)
			}
			if o.Width() < 64 && uint64(len(o.Lookup)) > uint64(1)<<uint(o.Width()) {
				return fmt.Errorf("%s: operand %s lookup exceeds encoded domain", e.ID, o.Name)
			}
			lookupValues := map[int64]bool{}
			for _, value := range o.Lookup {
				if lookupValues[value] {
					return fmt.Errorf("%s: operand %s has ambiguous lookup values", e.ID, o.Name)
				}
				lookupValues[value] = true
			}
			for _, b := range o.Bits {
				if b.Width <= 0 || b.Width > 64 || b.InstructionBit < 0 || b.ValueBit < 0 || b.InstructionBit > len(e.Mask)*8-b.Width || b.ValueBit > 64-b.Width {
					return fmt.Errorf("%s: operand %s bit slice out of bounds", e.ID, o.Name)
				}
				for k := 0; k < b.Width; k++ {
					p := b.InstructionBit + k
					if used[p/8]&(1<<uint(p%8)) != 0 {
						return fmt.Errorf("%s: overlapping operand bit %d", e.ID, p)
					}
					used[p/8] |= 1 << uint(p%8)
				}
			}
		}
		for j, b := range used {
			if b != 255 {
				return fmt.Errorf("%s: unmodeled bits at byte %d", e.ID, j)
			}
		}
		for _, o := range e.Operands {
			if o.InputSignedBits < 0 || o.InputSignedBits > 63 || o.PCAlignBits < 0 || o.PCAlignBits > 63 || o.PCRegionBits < 0 || o.PCRegionBits > 63 || o.PCWrapBits < 0 || o.PCWrapBits > 64 || o.PCLowWrapBits < 0 || o.PCLowWrapBits > 63 || o.PCLowWrapBits > o.PCWrapBits || o.PCBankBits < 0 || o.PCBankBits > 63 || (o.PCBankBits > 0 && (o.PCRegionBits > 0 || o.PCBankBits > o.PCWrapBits)) {
				return fmt.Errorf("%s: invalid operand width", e.ID)
			}
			if w := o.Width(); w < 64 && o.Xor>>uint(w) != 0 {
				return fmt.Errorf("%s: operand %s XOR exceeds field width", e.ID, o.Name)
			}
			if o.BiasOperand != "" {
				if !names[o.BiasOperand] || o.BiasOperand == o.Name {
					return fmt.Errorf("%s: invalid dependent operand %s", e.ID, o.BiasOperand)
				}
				for _, other := range e.Operands {
					if other.Name == o.BiasOperand && other.BiasOperand != "" {
						return fmt.Errorf("%s: chained operand biases are unsupported", e.ID)
					}
				}
			}
		}
		for _, v := range e.Constraints {
			if v.LeftWhenMask < 0 || v.RightWhenMask < 0 || v.EqualMask < 0 || v.LeftSpan < 0 || v.LeftSpan > 16 || v.RightSpan < 0 || v.RightSpan > 16 || v.Kind != "masked_ne" && (v.LeftWhenMask != 0 || v.RightWhenMask != 0 || v.EqualMask != 0 || v.LeftSpan != 0 || v.RightSpan != 0) {
				return fmt.Errorf("%s: invalid masked relation gates", e.ID)
			}
			if (v.Kind != "tuple_in" && !names[v.Left]) || (v.Right != "" && !names[v.Right]) || (v.UnlessZero != "" && !names[v.UnlessZero]) {
				return fmt.Errorf("%s: constraint references unknown operand", e.ID)
			}
			switch v.Kind {
			case "tuple_in":
				if len(v.Operands) == 0 || len(v.Allowed) == 0 {
					return fmt.Errorf("%s: empty tuple membership domain", e.ID)
				}
				seen := map[string]bool{}
				for _, name := range v.Operands {
					if !names[name] || seen[name] {
						return fmt.Errorf("%s: tuple references unknown or duplicate operand %q", e.ID, name)
					}
					seen[name] = true
				}
				for _, row := range v.Allowed {
					if len(row) != len(v.Operands) {
						return fmt.Errorf("%s: tuple row width differs from operand count", e.ID)
					}
				}
			case "ge", "ne", "eq", "sum_le", "diff_ge", "masked_ne", "encoded_targets_eq":
				if v.Kind == "masked_ne" && v.Limit <= 0 {
					return fmt.Errorf("%s: masked inequality requires a positive bitmask", e.ID)
				}
				if len(v.Operands) != 0 || len(v.Allowed) != 0 {
					return fmt.Errorf("%s: tuple domain on scalar constraint", e.ID)
				}
			default:
				return fmt.Errorf("%s: unknown constraint %s", e.ID, v.Kind)
			}
		}
		for _, part := range syntaxHoles(e.Syntax) {
			if !names[part] {
				return fmt.Errorf("%s: syntax references unknown operand %q", e.ID, part)
			}
		}
	}
	return nil
}

type Decoded struct {
	Encoding *Encoding
	Values   map[string]int64
	Length   int
}

func checkedAdd(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b || b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}

func checkedMul(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a == math.MinInt64 && b == -1 || b == math.MinInt64 && a == -1 {
		return 0, false
	}
	v := a * b
	return v, v/b == a
}

// Keep the common small-field path allocation free. A wide intermediate may
// cancel with a bias or another field, so only the final semantic/raw value is
// required to fit int64. The slow path also avoids silently wrapping a bias.
func operandValue(o Operand, number, dependent int64) (int64, bool) {
	scale := o.Scale
	if scale == 0 {
		scale = 1
	}
	bs := o.BiasScale
	if bs == 0 {
		bs = 1
	}
	a, aok := checkedMul(number, scale)
	b, bok := checkedMul(dependent, bs)
	v, vok := checkedAdd(a, o.Bias)
	if aok && bok && vok {
		if result, ok := checkedAdd(v, b); ok {
			return result, true
		}
	}
	var wide, extra big.Int
	wide.Mul(big.NewInt(number), big.NewInt(scale))
	wide.Add(&wide, big.NewInt(o.Bias))
	extra.Mul(big.NewInt(dependent), big.NewInt(bs))
	wide.Add(&wide, &extra)
	return wide.Int64(), wide.IsInt64()
}

func operandRawNumber(o Operand, value, dependent int64) (int64, bool) {
	scale := o.Scale
	if scale == 0 {
		scale = 1
	}
	bs := o.BiasScale
	if bs == 0 {
		bs = 1
	}
	extra, ok := checkedMul(dependent, bs)
	bias, bok := checkedAdd(o.Bias, extra)
	if ok && bok && !(bias > 0 && value < math.MinInt64+bias || bias < 0 && value > math.MaxInt64+bias) {
		n := value - bias
		return n / scale, n%scale == 0
	}
	var wide, product, remainder big.Int
	wide.Sub(big.NewInt(value), big.NewInt(o.Bias))
	product.Mul(big.NewInt(dependent), big.NewInt(bs))
	wide.Sub(&wide, &product)
	wide.QuoRem(&wide, big.NewInt(scale), &remainder)
	return wide.Int64(), remainder.Sign() == 0 && wide.IsInt64()
}

func specificity(e *Encoding) int {
	n := 0
	for _, b := range e.Mask {
		n += bits.OnesCount8(b)
	}
	return n
}

func (c *Catalog) Decode(src []byte) (*Decoded, error) { return c.DecodeWithFeatures(src, nil) }

// A nil feature set admits every imported extension; a non-nil set admits only
// encodings whose source predicates occur in the supplied set.
func featuresMatch(e *Encoding, features []string) bool {
	if features == nil {
		return true
	}
	for _, required := range e.Features {
		found := false
		for _, f := range features {
			if f == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (c *Catalog) DecodeWithFeatures(src []byte, features []string) (*Decoded, error) {
	var best *Decoded
	short := false
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.AssemblyOnly || !featuresMatch(e, features) {
			continue
		}
		n := len(e.Mask)
		match := true
		for j := 0; j < n && j < len(src); j++ {
			if src[j]&e.Mask[j] != e.Value[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if len(src) < n {
			short = true
			continue
		}
		values, err := decodeValues(e, src)
		if err != nil {
			continue
		}
		if best == nil || specificity(e) > specificity(best.Encoding) {
			best = &Decoded{e, values, n}
		}
	}
	if best == nil {
		if short {
			return nil, ErrTruncated
		}
		return nil, ErrUnknown
	}
	return best, nil
}

func decodeValues(e *Encoding, src []byte) (map[string]int64, error) {
	values := map[string]int64{}
	numbers := make([]int64, len(e.Operands))
	for i, o := range e.Operands {
		var raw, seen uint64
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				p := b.InstructionBit + k
				valueBit := uint(b.ValueBit + k)
				v := uint64((src[p/8] >> uint(p%8)) & 1)
				if seen&(uint64(1)<<valueBit) != 0 && (raw>>valueBit)&1 != v {
					return nil, ErrUnknown
				}
				seen |= uint64(1) << valueBit
				raw |= v << valueBit
			}
		}
		raw ^= o.Xor
		if len(o.Names) > 0 && (raw >= uint64(len(o.Names)) || o.Names[raw] == "") {
			return nil, ErrUnknown
		}
		v, ok := operandNumber(o, raw)
		if !ok {
			return nil, ErrUnknown
		}
		numbers[i] = v
		if o.BiasOperand == "" {
			value, ok := operandValue(o, v, 0)
			if !ok {
				return nil, ErrUnknown
			}
			values[o.Name] = value
		}
	}
	for i, o := range e.Operands {
		if o.BiasOperand != "" {
			value, ok := operandValue(o, numbers[i], values[o.BiasOperand])
			if !ok {
				return nil, ErrUnknown
			}
			values[o.Name] = value
		}
		if o.Implicit && values[o.Name] != 0 {
			return nil, ErrUnknown
		}
	}
	if !constraintsMatch(e, values) {
		return nil, ErrUnknown
	}
	return values, nil
}

func constraintsMatch(e *Encoding, values map[string]int64) bool {
	for _, c := range e.Constraints {
		if c.UnlessZero != "" && values[c.UnlessZero] == 0 {
			continue
		}
		l, r := values[c.Left], values[c.Right]
		switch c.Kind {
		case "tuple_in":
			matched := false
			for _, row := range c.Allowed {
				if len(row) != len(c.Operands) {
					continue
				}
				equal := true
				for i, name := range c.Operands {
					value, exists := values[name]
					if !exists || value != row[i] {
						equal = false
						break
					}
				}
				if equal {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		case "encoded_targets_eq":
			// This constraint needs an instruction address. Exact encoding is
			// context free; text assembly and templates check it separately.
			continue
		case "sum_le":
			sum, ok := checkedAdd(l, r)
			if ok && sum > c.Limit || !ok && r > 0 {
				return false
			}
		case "diff_ge":
			underflow := r > 0 && l < math.MinInt64+r
			overflow := r < 0 && l > math.MaxInt64+r
			if underflow || !overflow && l-r < c.Limit {
				return false
			}
		case "ge":
			if l < r {
				return false
			}
		case "ne":
			if l == r {
				return false
			}
		case "masked_ne":
			if c.LeftWhenMask != 0 && l&c.LeftWhenMask == 0 || c.RightWhenMask != 0 && r&c.RightWhenMask == 0 || c.EqualMask != 0 && l&c.EqualMask == r&c.EqualMask {
				continue
			}
			for i := 0; i < max(1, c.LeftSpan); i++ {
				for j := 0; j < max(1, c.RightSpan); j++ {
					if (uint64(l)+uint64(i))&uint64(c.Limit) == (uint64(r)+uint64(j))&uint64(c.Limit) {
						return false
					}
				}
			}
		case "eq":
			if l != r {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (c *Catalog) Encode(id string, values map[string]int64) ([]byte, error) {
	for i := range c.Encodings {
		if c.Encodings[i].ID == id {
			return Encode(&c.Encodings[i], values)
		}
	}
	return nil, fmt.Errorf("unknown encoding %q", id)
}

func Encode(e *Encoding, values map[string]int64) ([]byte, error) {
	if len(values) != len(e.Operands) {
		expanded := make(map[string]int64, len(e.Operands))
		for k, v := range values {
			expanded[k] = v
		}
		for _, o := range e.Operands {
			if _, ok := expanded[o.Name]; !ok && (o.Implicit || o.Optional) {
				expanded[o.Name] = 0
			}
		}
		values = expanded
	}
	if len(values) != len(e.Operands) {
		return nil, fmt.Errorf("%s: expected %d operands, got %d", e.ID, len(e.Operands), len(values))
	}

	if !constraintsMatch(e, values) {
		return nil, fmt.Errorf("%s: operand constraint violated", e.ID)
	}
	out := append([]byte(nil), e.Value...)
	for _, o := range e.Operands {
		v, ok := values[o.Name]
		if !ok {
			return nil, fmt.Errorf("%s: missing operand %s", e.ID, o.Name)
		}
		if o.Implicit && v != 0 {
			return nil, fmt.Errorf("%s: implicit operand %s must be zero", e.ID, o.Name)
		}
		dependent := int64(0)
		if o.BiasOperand != "" {
			dependent = values[o.BiasOperand]
		}
		n, ok := operandRawNumber(o, v, dependent)
		if !ok {
			return nil, fmt.Errorf("%s: operand %s is unaligned or overflows", e.ID, o.Name)
		}
		if len(o.Lookup) > 0 {
			var found bool
			n, found = operandIndex(o, n)
			if !found {
				return nil, fmt.Errorf("%s: operand %s outside numeric lookup domain", e.ID, o.Name)
			}
		}
		w := o.Width()
		if o.Signed && len(o.Lookup) == 0 {
			if w < 64 && (n < -(int64(1)<<uint(w-1)) || n > (int64(1)<<uint(w-1))-1) {
				return nil, fmt.Errorf("%s: operand %s out of range", e.ID, o.Name)
			}
		} else if w < 64 && (n < 0 || uint64(n) > ((uint64(1)<<uint(w))-1)) {
			return nil, fmt.Errorf("%s: operand %s out of range", e.ID, o.Name)
		}
		if len(o.Names) > 0 && (n < 0 || n >= int64(len(o.Names)) || o.Names[n] == "") {
			return nil, fmt.Errorf("%s: invalid register/enumeration %s", e.ID, o.Name)
		}
		var represented uint64
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				p := b.InstructionBit + k
				bit := uint(b.ValueBit + k)
				represented |= uint64(1) << bit
				out[p/8] |= byte(((uint64(n)^o.Xor)>>bit)&1) << uint(p%8)
			}
		}
		widthMask := ^uint64(0)
		if w < 64 {
			widthMask = (uint64(1) << uint(w)) - 1
		}
		if (uint64(n)^o.Xor)&widthMask & ^represented != 0 {
			return nil, fmt.Errorf("%s: operand %s uses unencoded bits", e.ID, o.Name)
		}
	}
	return out, nil
}

func (d *Decoded) Format(address uint64) string {
	s := escapedSyntax(d.Encoding.Syntax)
	for _, o := range d.Encoding.Operands {
		v := d.Values[o.Name]
		text := strconv.FormatInt(v, 10)
		if !o.Signed && o.Width() == 64 {
			text = strconv.FormatUint(uint64(v), 10)
		}
		dependent := int64(0)
		if o.BiasOperand != "" {
			dependent = d.Values[o.BiasOperand]
		}
		raw, valid := operandRawNumber(o, v, dependent)
		if !valid {
			raw = -1
		}
		if len(o.Lookup) > 0 {
			if index, ok := operandIndex(o, raw); ok {
				raw = index
			} else {
				raw = -1
			}
		}
		if len(o.Names) > 0 && raw >= 0 && raw < int64(len(o.Names)) && o.Names[raw] != "" {
			text = o.Names[raw]
		} else if o.Kind == "register" {
			text = o.RegisterPrefix + text
		} else if o.Kind == "address" && !o.Relative {
			target := uint64(v)
			if d.Encoding.TargetMask != 0 {
				// Retain encoded low bits even when target calculation ignores
				// them for alignment; formatting must still reassemble exactly.
				target &= math.MaxUint64 >> uint(bits.LeadingZeros64(d.Encoding.TargetMask))
			}
			text = fmt.Sprintf("0x%x", target)
		} else if o.Relative {
			target := relativeTarget(o, v, address)
			text = fmt.Sprintf("0x%x", target)
		}
		s = strings.ReplaceAll(s, "{"+o.Name+"}", text)
	}
	return literalSyntax(s)
}

func operandNumber(o Operand, raw uint64) (int64, bool) {
	if len(o.Lookup) > 0 {
		if raw >= uint64(len(o.Lookup)) {
			return 0, false
		}
		return o.Lookup[raw], true
	}
	w := o.Width()
	if o.Signed && w < 64 && raw&(uint64(1)<<uint(w-1)) != 0 {
		return int64(raw | (^uint64(0) << uint(w))), true
	}
	return int64(raw), true
}

func operandIndex(o Operand, number int64) (int64, bool) {
	if len(o.Lookup) == 0 {
		return number, true
	}
	for raw, value := range o.Lookup {
		if value == number {
			return int64(raw), true
		}
	}
	return 0, false
}

// BranchTarget returns the first statically encoded control-flow target.
// Relative operands are resolved against address; direct absolute branch/call
// operands retain their encoded address. Indirect branches have no such target.
func (d *Decoded) BranchTarget(address uint64) (uint64, bool) {
	if !directControlFlow(d.Encoding.FlowControl) {
		return 0, false
	}
	mask := d.Encoding.TargetMask
	if mask == 0 {
		mask = math.MaxUint64
	}
	if d.Encoding.FixedTarget != nil {
		return *d.Encoding.FixedTarget & mask, true
	}
	for _, o := range d.Encoding.Operands {
		if o.Relative {
			return relativeTarget(o, d.Values[o.Name], address) & mask, true
		}
	}
	for _, o := range d.Encoding.Operands {
		if o.Kind == "address" {
			return uint64(d.Values[o.Name]) & mask, true
		}
	}
	return 0, false
}

func directControlFlow(flow string) bool {
	switch flow {
	case "branch", "call", "conditional_call", "conditional-call", "conditional_branch", "conditional-branch", "unconditional_branch", "unconditional-branch", "loop":
		return true
	}
	return false
}

func relativeTarget(o Operand, value int64, address uint64) uint64 {
	base := relativeBase(o, address)
	target := base + uint64(value)
	if o.PCRegionBits > 0 {
		mask := uint64(1)<<uint(o.PCRegionBits) - 1
		target = (base &^ mask) | (uint64(value) & mask)
	}
	if o.PCBankBits > 0 {
		mask := uint64(1)<<uint(o.PCBankBits) - 1
		target = address&^mask | target&mask
	}
	if wrap := relativeWrapBits(o, address); wrap > 0 && wrap < 64 {
		target &= uint64(1)<<uint(wrap) - 1
	}
	return target
}

func relativeBase(o Operand, address uint64) uint64 {
	return ((address + uint64(o.PCPreAlignBias)) &^ (uint64(1)<<uint(o.PCAlignBits) - 1)) + uint64(o.PCBias)
}

func relativeWrapBits(o Operand, address uint64) int {
	if o.PCLowWrapBits > 0 && relativeBase(o, address) < uint64(1)<<uint(o.PCLowWrapBits) {
		return o.PCLowWrapBits
	}
	return o.PCWrapBits
}

func escapedSyntax(s string) string {
	return strings.NewReplacer("{{", "\x01", "}}", "\x02").Replace(s)
}

func literalSyntax(s string) string {
	return strings.NewReplacer("\x01", "{", "\x02", "}").Replace(s)
}

func syntaxHoles(s string) []string {
	s = escapedSyntax(s)
	var out []string
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			return out
		}
		s = s[i+1:]
		j := strings.IndexByte(s, '}')
		if j < 0 {
			return append(out, s)
		}
		out = append(out, s[:j])
		s = s[j+1:]
	}
}

func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.AssembleWithFeatures(text, address, nil)
}

func (c *Catalog) AssembleWithFeatures(text string, address uint64, features []string) ([][]byte, error) {
	var out [][]byte
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty assembly")
	}
	mnemonic := fields[0]
	for i := range c.Encodings {
		e := &c.Encodings[i]
		syntaxFields := strings.Fields(e.Syntax)
		syntaxMnemonic := syntaxFields[0]
		if !strings.Contains(syntaxMnemonic, "{") && !strings.EqualFold(syntaxMnemonic, mnemonic) {
			continue
		}
		if !featuresMatch(e, features) {
			continue
		}
		values, ok := matchSyntax(e, text, address)
		if !ok {
			continue
		}
		b, err := Encode(e, values)
		if err == nil {
			dup := false
			for _, v := range out {
				if string(v) == string(b) {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, b)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no encoding for %q", text)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out, nil
}

func normalize(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), "")) }

func normalizedPattern(s string) string {
	s = escapedSyntax(s)
	var out strings.Builder
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			out.WriteString(normalize(s))
			break
		}
		out.WriteString(normalize(s[:i]))
		s = s[i:]
		j := strings.IndexByte(s, '}')
		if j < 0 {
			out.WriteString(s)
			break
		}
		out.WriteString(s[:j+1])
		s = s[j+1:]
	}
	return out.String()
}

func addressConstraintsMatch(e *Encoding, values map[string]int64, address uint64) bool {
	for _, constraint := range e.Constraints {
		if constraint.Kind != "encoded_targets_eq" {
			continue
		}
		target := func(name string) uint64 {
			for _, o := range e.Operands {
				if o.Name == name {
					value := values[name] - o.Bias
					if o.BiasOperand != "" {
						scale := o.BiasScale
						if scale == 0 {
							scale = 1
						}
						value -= values[o.BiasOperand] * scale
					}
					return relativeTarget(o, value, address)
				}
			}
			return 0
		}
		if target(constraint.Left) != target(constraint.Right) {
			return false
		}
	}
	return true
}

// ParseOperands resolves instruction text to semantic values without validating
// their encoded field widths. Packet backends can then distribute extended
// immediates and context-dependent registers across multiple physical words.
func ParseOperands(e *Encoding, text string, address uint64) (map[string]int64, bool) {
	return matchSyntax(e, text, address)
}

func matchSyntax(e *Encoding, text string, address uint64) (map[string]int64, bool) {
	pattern := normalizedPattern(e.Syntax)
	text = negativeMemoryOffset.ReplaceAllString(normalize(text), "${1}+-${2}")
	values := map[string]int64{}
	var match func(string, string) bool
	match = func(pattern, text string) bool {
		i := strings.IndexByte(pattern, '{')
		if i < 0 {
			if literalSyntax(pattern) != text {
				return false
			}
			for _, o := range e.Operands {
				if _, exists := values[o.Name]; !exists && (o.Implicit || o.Optional) {
					values[o.Name] = 0
				}
			}
			return addressConstraintsMatch(e, values, address)
		}
		prefix := literalSyntax(pattern[:i])
		if !strings.HasPrefix(text, prefix) {
			return false
		}
		text = text[len(prefix):]
		pattern = pattern[i+1:]
		j := strings.IndexByte(pattern, '}')
		if j < 0 {
			return false
		}
		name := pattern[:j]
		pattern = pattern[j+1:]
		var operand *Operand
		for k := range e.Operands {
			if e.Operands[k].Name == name {
				operand = &e.Operands[k]
				break
			}
		}
		if operand == nil {
			return false
		}
		name = operand.Name
		for _, end := range syntaxCandidateEnds(operand, text, pattern) {
			value, ok := parseOperandToken(operand, text[:end], address)
			if !ok {
				continue
			}
			previous, exists := values[name]
			if exists && previous != value {
				continue
			}
			values[name] = value
			if match(pattern, text[end:]) {
				return true
			}
			if exists {
				values[name] = previous
			} else {
				delete(values, name)
			}
		}
		return false
	}
	if !match(pattern, text) {
		return nil, false
	}
	return values, true
}

// Adjacent optional fields (e.g. AMD GPU instruction modifiers) need candidate
// boundaries from their enum spellings, then backtracking through the suffix.
func syntaxCandidateEnds(o *Operand, text, pattern string) []int {
	if pattern == "" {
		return []int{len(text)}
	}
	next := pattern
	if i := strings.IndexByte(next, '{'); i >= 0 {
		next = next[:i]
	}
	next = literalSyntax(next)
	if next != "" {
		var ends []int
		depth := 0
		for i := 0; i < len(text); i++ {
			if depth == 0 && strings.HasPrefix(text[i:], next) {
				ends = append(ends, i)
			}
			switch text[i] {
			case '{', '[', '(':
				depth++
			case '}', ']', ')':
				if depth > 0 {
					depth--
				}
			}
		}
		return ends
	}
	seen := map[int]bool{}
	var ends []int
	add := func(end int) {
		if !seen[end] {
			seen[end] = true
			ends = append(ends, end)
		}
	}
	for _, name := range o.Names {
		if name != "" {
			token := normalize(name)
			if strings.HasPrefix(text, token) {
				add(len(token))
			}
		}
	}
	for alias := range o.RegisterAliases {
		token := normalize(alias)
		if strings.HasPrefix(text, token) {
			add(len(token))
		}
	}
	if o.Kind != "register" || len(o.Names) == 0 {
		prefix := 0
		if o.Kind == "register" {
			p := normalize(o.RegisterPrefix)
			if !strings.HasPrefix(text, p) {
				return ends
			}
			prefix = len(p)
		}
		for end := prefix + 1; end <= len(text); end++ {
			if _, err := parseInteger(text[prefix:end]); err == nil {
				add(end)
			}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ends)))
	return ends
}

func parseOperandToken(o *Operand, token string, address uint64) (int64, bool) {
	var value int64
	found := false
	for k, n := range o.Names {
		if n != "" && normalize(n) == token {
			number, ok := operandNumber(*o, uint64(k))
			if !ok {
				return 0, false
			}
			value, ok = operandValue(*o, number, 0)
			if !ok {
				return 0, false
			}
			found = true
			break
		}
	}
	if !found {
		for alias, raw := range o.RegisterAliases {
			if normalize(alias) == token {
				number, ok := operandNumber(*o, uint64(raw))
				if !ok {
					return 0, false
				}
				value, ok = operandValue(*o, number, 0)
				if !ok {
					return 0, false
				}
				found = true
				break
			}
		}
	}
	if !found {
		if o.Kind == "register" {
			if len(o.Names) != 0 {
				return 0, false
			}
			if !strings.HasPrefix(token, normalize(o.RegisterPrefix)) {
				return 0, false
			}
			token = strings.TrimPrefix(token, normalize(o.RegisterPrefix))
		}
		v, err := parseInteger(token)
		if err != nil {
			u, ue := strconv.ParseUint(token, 0, 64)
			if ue != nil {
				return 0, false
			}
			v = int64(u)
		}
		value = v
		if o.InputSignedBits > 0 {
			modulus := uint64(1) << uint(o.InputSignedBits)
			if o.Signed && value >= 0 && uint64(value) >= modulus>>1 && uint64(value) < modulus {
				value = int64(uint64(value) - modulus)
			} else if !o.Signed && value < 0 && value >= -int64(modulus>>1) {
				value = int64(uint64(value) + modulus)
			}
		}
		if o.Relative {
			if wrap := relativeWrapBits(*o, address); wrap > 0 && wrap < 64 && v < 0 && v >= -int64(uint64(1)<<uint(wrap-1)) {
				// Accept a signed spelling of an architectural address while
				// keeping targets outside the address width invalid.
				v = int64(uint64(v) & (uint64(1)<<uint(wrap) - 1))
			}
			var ok bool
			value, ok = o.Position().ValueForTarget(address, uint64(v))
			if !ok {
				return 0, false
			}
		}
	}
	return value, true
}

// Accept the conventional eBPF (r10-8) spelling for a syntax expressed as
// ({base}+{offset}). Require an address delimiter: after whitespace removal a
// digit-suffixed mnemonic such as "ld.w23 -4[gp],gp" must remain ld.w23-4.
var negativeMemoryOffset = regexp.MustCompile(`(\([rw][0-9]+|\[[rw][0-9]+|\(i[xy])-([0-9])`)

func parseInteger(text string) (int64, error) {
	base := 10
	unsigned := strings.TrimPrefix(strings.TrimPrefix(text, "-"), "+")
	if strings.HasPrefix(unsigned, "0x") || strings.HasPrefix(unsigned, "0b") || strings.HasPrefix(unsigned, "0o") {
		base = 0
	}
	v, err := strconv.ParseInt(text, base, 64)
	if err == nil {
		return v, nil
	}
	u, err := strconv.ParseUint(strings.TrimPrefix(text, "+"), base, 64)
	return int64(u), err
}

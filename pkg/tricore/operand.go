package tricore

import (
	"fmt"
	"strconv"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// restrictOperand absorbs source pattern bits that select a subrange of an
// operand, e.g. the separate positive/negative SH constructors. The remaining
// physical bits stay exposed and exact encoders reject unrepresented gap bits.
func restrictOperand(o codec.Operand, mask, value uint32) (codec.Operand, string, error) {
	original := o
	var bits []codec.BitSlice
	var fixed uint64
	signFixed := false
	didRestrict := false
	for _, b := range o.Bits {
		for k := 0; k < b.Width; k++ {
			p, v := b.InstructionBit+k, b.ValueBit+k
			if mask&(uint32(1)<<p) != 0 {
				didRestrict = true
				if value&(uint32(1)<<p) != 0 {
					fixed |= uint64(1) << v
				}
				if o.Signed && v == o.Width()-1 {
					signFixed = true
				}
			} else {
				bits = append(bits, codec.BitSlice{InstructionBit: p, ValueBit: v, Width: 1})
			}
		}
	}
	scale := o.Scale
	if scale == 0 {
		scale = 1
	}
	bias := int64(fixed)
	if original.Signed && signFixed && fixed&(uint64(1)<<uint(original.Width()-1)) != 0 {
		bias = int64(fixed | (^uint64(0) << uint(original.Width())))
	}
	o.Bias += bias * scale
	o.Bits = bits
	if signFixed {
		o.Signed = false
		o.InputSignedBits = 0
	}
	if len(bits) == 0 {
		literal := strconv.FormatInt(o.Bias, 10)
		if original.Kind == "address" {
			literal = fmt.Sprintf("0x%x", uint64(o.Bias))
		}
		if len(original.Names) > 0 {
			if int(fixed) >= len(original.Names) || original.Names[fixed] == "" {
				return o, "", errConflict
			}
			literal = original.Names[fixed]
		}
		return o, literal, nil
	}
	if didRestrict && len(o.Names) > 0 {
		names := make([]string, 1<<o.Width())
		var represented uint64
		for _, b := range bits {
			represented |= ((uint64(1) << b.Width) - 1) << b.ValueBit
		}
		for i := range names {
			if uint64(i)&^represented != 0 {
				continue
			}
			j := uint64(i) | fixed
			if j < uint64(len(original.Names)) {
				names[i] = original.Names[j]
			}
		}
		o.Names = names
	}
	return o, "", nil
}

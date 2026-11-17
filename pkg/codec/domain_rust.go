package codec

import (
	"math/big"
	"math/bits"
)

// Domains depend only on catalog metadata. Intern their exact i128 values at
// generation time instead of enumerating register sets and dividing in consumers.
type rustOperandDomain struct {
	Min, Max, Step string
	Exact          bool
}

func prepareRustOperandDomain(o Operand) rustOperandDomain {
	domain := func(lo, hi, step *big.Int, exact bool) rustOperandDomain {
		return rustOperandDomain{lo.String(), hi.String(), step.String(), exact}
	}
	one := big.NewInt(1)
	if o.Implicit {
		return rustOperandDomain{"0", "0", "1", true}
	}
	if o.BiasOperand != "" {
		return rustOperandDomain{"-170141183460469231731687303715884105728", "170141183460469231731687303715884105727", "1", false}
	}
	var represented uint64
	for _, b := range o.Bits {
		represented |= (uint64(1)<<uint(b.Width) - 1) << uint(b.ValueBit)
	}
	scale := big.NewInt(o.Scale)
	if o.Scale == 0 {
		scale.SetInt64(1)
	}
	transform := func(v *big.Int) *big.Int { return new(big.Int).Add(new(big.Int).Mul(v, scale), big.NewInt(o.Bias)) }
	if len(o.Names) > 0 || len(o.Lookup) > 0 {
		count := len(o.Names)
		if count == 0 {
			count = len(o.Lookup)
		}
		var lo, hi, first *big.Int
		step := new(big.Int)
		admitted := int64(0)
		for raw := 0; raw < count; raw++ {
			if (uint64(raw)^o.Xor)&^represented != 0 || (len(o.Names) > 0 && o.Names[raw] == "") {
				continue
			}
			v := new(big.Int).SetUint64(uint64(raw))
			if len(o.Lookup) > 0 {
				if raw >= len(o.Lookup) {
					continue
				}
				v.SetInt64(o.Lookup[raw])
			} else if o.Signed && uint64(raw)&(uint64(1)<<uint(o.Width()-1)) != 0 {
				v.Sub(v, new(big.Int).Lsh(one, uint(o.Width())))
			}
			v = transform(v)
			if first == nil {
				first = new(big.Int).Set(v)
				lo = new(big.Int).Set(v)
				hi = new(big.Int).Set(v)
			} else {
				delta := new(big.Int).Sub(v, first)
				step.GCD(nil, nil, step, delta)
				if v.Cmp(lo) < 0 {
					lo.Set(v)
				}
				if v.Cmp(hi) > 0 {
					hi.Set(v)
				}
			}
			admitted++
		}
		if admitted == 0 {
			return rustOperandDomain{"1", "0", "1", true}
		}
		if step.Sign() == 0 {
			step.SetInt64(1)
		}
		n := new(big.Int).Sub(hi, lo)
		n.Quo(n, step)
		n.Add(n, one)
		return domain(lo, hi, step, n.Cmp(big.NewInt(admitted)) == 0)
	}
	sign := uint64(1) << uint(o.Width()-1)
	fixed := o.Xor &^ represented
	lo := new(big.Int).SetUint64(fixed)
	hi := new(big.Int).SetUint64(fixed | represented)
	if o.Signed && represented&sign != 0 {
		lo.Sub(lo, new(big.Int).SetUint64(sign))
		hi.SetUint64(fixed | (represented & (sign - 1)))
	}
	shift := uint(min(bits.TrailingZeros64(represented), 63))
	step := new(big.Int).Lsh(one, shift)
	step.Mul(step, scale)
	if lo.Cmp(hi) == 0 {
		step.SetInt64(1)
	}
	normalized := represented >> shift
	return domain(transform(lo), transform(hi), step, normalized == ^uint64(0) || normalized&(normalized+1) == 0)
}

// Keep domain indices in existing operand padding for ordinary catalogs while
// retaining full range for catalogs with more than 65,536 distinct domains.
func rustOperandDomainIndexType(count int) string {
	if count <= 1<<16 {
		return "u16"
	}
	return "u32"
}

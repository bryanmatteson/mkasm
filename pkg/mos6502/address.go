package mos6502

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type AddressContext struct {
	Processor string
	X, Y      byte
	Read      func(uint16) byte
}
type ResolvedAddress struct {
	Address               uint16
	PageCrossed, Indirect bool
}

// ResolveOperand calculates an operand's effective address. This is address
// arithmetic only: it does not execute the instruction or model bus cycles.
func ResolveOperand(d *codec.Decoded, name string, pc uint16, ctx AddressContext) (ResolvedAddress, bool, error) {
	switch strings.ToLower(ctx.Processor) {
	case "", "mos6502", "6502", "6502x", "65sc02", "65c02", "w65c02", "w65c02+nops":
	default:
		return ResolvedAddress{}, false, fmt.Errorf("unknown processor %q", ctx.Processor)
	}
	var o *codec.Operand
	for i := range d.Encoding.Operands {
		if d.Encoding.Operands[i].Name == name {
			o = &d.Encoding.Operands[i]
			break
		}
	}
	if o == nil {
		return ResolvedAddress{}, false, fmt.Errorf("unknown operand %s", name)
	}
	v := uint16(d.Values[name])
	r := ResolvedAddress{Address: v}
	if o.Relative {
		r.Address = uint16(int64(pc) + o.PCBias + d.Values[name])
		r.PageCrossed = uint16(pc+uint16(d.Length))&0xff00 != r.Address&0xff00
		return r, true, nil
	}
	if o.Kind != "address" {
		return r, false, nil
	}
	readWord := func(pointer, high uint16) (uint16, error) {
		if ctx.Read == nil {
			return 0, fmt.Errorf("indirect address requires memory reader")
		}
		return uint16(ctx.Read(pointer)) | uint16(ctx.Read(high))<<8, nil
	}
	switch o.Class {
	case "DirectX":
		r.Address = uint16(byte(v) + ctx.X)
	case "DirectY":
		r.Address = uint16(byte(v) + ctx.Y)
	case "AbsoluteX":
		r.Address = v + uint16(ctx.X)
		r.PageCrossed = v&0xff00 != r.Address&0xff00
	case "AbsoluteY":
		r.Address = v + uint16(ctx.Y)
		r.PageCrossed = v&0xff00 != r.Address&0xff00
	case "DirectIndirect", "DirectXIndirect", "DirectIndirectY":
		pointer := byte(v)
		if o.Class == "DirectXIndirect" {
			pointer += ctx.X
		}
		base, err := readWord(uint16(pointer), uint16(pointer+1))
		if err != nil {
			return r, false, err
		}
		r.Address = base
		r.Indirect = true
		if o.Class == "DirectIndirectY" {
			r.Address += uint16(ctx.Y)
			r.PageCrossed = base&0xff00 != r.Address&0xff00
		}
	case "JmpAbsoluteIndirect", "AbsoluteXIndirect":
		pointer := v
		if o.Class == "AbsoluteXIndirect" {
			pointer += uint16(ctx.X)
		}
		high := pointer + 1
		if o.Class == "JmpAbsoluteIndirect" && (ctx.Processor == "" || strings.EqualFold(ctx.Processor, "6502") || strings.EqualFold(ctx.Processor, "6502x") || strings.EqualFold(ctx.Processor, "mos6502")) {
			high = pointer&0xff00 | uint16(byte(pointer+1))
		}
		var err error
		r.Address, err = readWord(pointer, high)
		if err != nil {
			return r, false, err
		}
		r.Indirect = true
	}
	return r, true, nil
}

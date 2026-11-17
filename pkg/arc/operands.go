package arc

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"strings"
)

var conditionNames = []string{"al", "eq", "ne", "p", "n", "lo", "hs", "vs", "vc", "gt", "ge", "lt", "le", "hi", "ls", "pnz", "", "", "", "", "", "nj", "", "nm", "nt", "", "", "", "", "", "", ""}

func register(o *codec.Operand) {
	o.Kind = "register"
	o.RegisterPrefix = "r"
	o.Names = make([]string, 1<<uint(o.Width()))
	o.RegisterAliases = map[string]int64{}
	for n := range o.Names {
		if n == 62 {
			continue
		}
		name := fmt.Sprintf("r%d", n)
		switch n {
		case 26:
			name = "gp"
		case 27:
			name = "fp"
		case 28:
			name = "sp"
		case 29:
			name = "ilink"
		case 31:
			name = "blink"
		case 60:
			name = "lp_count"
		case 63:
			name = "pcl"
		}
		o.Names[n] = name
		if name != fmt.Sprintf("r%d", n) {
			o.RegisterAliases[fmt.Sprintf("r%d", n)] = int64(n)
		}
	}
	o.RegisterAliases["ilink1"] = 29
	o.RegisterAliases["ilink2"] = 30
}
func adapt(e *codec.Encoding, r record, get func(string) record) error {
	var out []codec.Operand
	for _, o := range e.Operands {
		if o.Class == "MEMrs9" || o.Class == "MEMrlimm" {
			cut := 9
			if o.Class == "MEMrlimm" {
				cut = 32
			}
			base := codec.Operand{Name: o.Name + "_base", Class: "GPR32", Kind: "register"}
			off := codec.Operand{Name: o.Name + "_offset", Kind: "displacement", Signed: cut == 9}
			for _, b := range o.Bits {
				if b.ValueBit >= cut {
					b.ValueBit -= cut
					base.Bits = append(base.Bits, b)
				} else {
					off.Bits = append(off.Bits, b)
				}
			}
			register(&base)
			if cut == 32 {
				off.InputSignedBits = 32
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", "{"+base.Name+"}, {"+off.Name+"}")
			out = append(out, base, off)
			continue
		}
		cl := get(o.Class)
		method := str(cl["DecoderMethod"])
		switch {
		case o.Class == "GPR32" || o.Class == "GPR32Reduced":
			register(&o)
			if o.Name == "h" && o.Width() == 5 && num(r["Size"]) <= 6 && strings.Contains(str(r["DecoderMethod"]), "MoveHReg") {
				o.Names[30] = ""
			}
		case o.Class == "Signed12" || strings.HasPrefix(method, "DecodeSignedOperand"):
			o.Signed = true
		case strings.HasPrefix(method, "DecodeBranchTargetS"):
			o.Kind = "displacement"
			o.Signed = true
			o.Relative = true
			o.PCWrapBits = 32
			o.PCAlignBits = 2
		case strings.HasPrefix(method, "DecodeFromCyclicRange"):
			o.Class = "Cyclic3"
			o.Names = []string{"0", "1", "2", "3", "4", "5", "6", "-1"}

		case o.Class == "ccond" || o.Class == "CCOp":
			o.Names = append([]string(nil), conditionNames...)
			o.Names = o.Names[:1<<uint(o.Width())]
		case o.Class == "brccond":
			o.Names = []string{"eq", "ne", "lt", "ge", "lo", "hs", "", ""}
		case o.Class == "DelayBit":
			o.Names = []string{"nd", "d"}
			e.Syntax = strings.Replace(e.Syntax, e.Mnemonic, e.Mnemonic+".{"+o.Name+"}", 1)
		}
		if o.Class == "i32imm" && o.Width() == 32 {
			o.InputSignedBits = 32
		}
		out = append(out, o)
	}
	e.Operands = out
	// LLVM declares branch offsets with their low alignment bits omitted. The
	// bit slices already retain architectural value-bit numbers, so no scale is
	// applied a second time; the generic encoder checks their implicit zeros.
	e.Syntax = strings.ReplaceAll(e.Syntax, "%", "")
	if strings.Contains(e.Syntax, ".d ") || strings.Contains(e.Syntax, ".d\t") {
		e.DelaySlots = 1
	}
	for _, p := range []string{"j", "b"} {
		if strings.HasPrefix(e.Mnemonic, p) && e.FlowControl == "next" {
			e.FlowControl = "branch"
		}
	}
	return nil
}
func compactRegisters(e codec.Encoding) []codec.Encoding {
	variants := []codec.Encoding{e}
	for index, o := range e.Operands {
		if o.Kind != "register" || o.Width() != 3 || len(o.Lookup) > 0 {
			continue
		}
		var next []codec.Encoding
		for _, v := range variants {
			for bank := 0; bank < 2; bank++ {
				x := v
				x.Mask = append([]byte(nil), v.Mask...)
				x.Value = append([]byte(nil), v.Value...)
				x.Operands = append([]codec.Operand(nil), v.Operands...)
				operand := x.Operands[index]
				operand.Bits = nil
				for _, b := range o.Bits {
					if b.ValueBit == 2 {
						p := b.InstructionBit
						m := byte(1) << uint(p%8)
						x.Mask[p/8] |= m
						if bank == 1 {
							x.Value[p/8] |= m
						} else {
							x.Value[p/8] &= ^m
						}
					} else {
						operand.Bits = append(operand.Bits, b)
					}
				}
				operand.Bias = int64(bank * 12)
				operand.Names = make([]string, 4)
				operand.RegisterAliases = map[string]int64{}
				for n := range operand.Names {
					reg := n + bank*12
					operand.Names[n] = fmt.Sprintf("r%d", reg)

				}
				x.Operands[index] = operand
				if bank == 1 {
					x.ID += fmt.Sprintf("/r%d-high", index)
				}
				next = append(next, x)
			}
		}
		variants = next
	}
	return variants
}
func conditionVariants(e codec.Encoding) []codec.Encoding {
	forms := []codec.Encoding{e}
	expanded := false
	for _, operand := range e.Operands {
		if operand.Class != "CCOp" && operand.Class != "ccond" && operand.Class != "brccond" && operand.Class != "DelayBit" {
			continue
		}
		expanded = true
		var next []codec.Encoding
		for _, v := range forms {
			for n, name := range operand.Names {
				if name == "" {
					continue
				}
				x := v
				x.Mask = append([]byte(nil), v.Mask...)
				x.Value = append([]byte(nil), v.Value...)
				x.ID += fmt.Sprintf("/%s%d", operand.Name, n)
				x.Syntax = strings.ReplaceAll(v.Syntax, "{"+operand.Name+"}", name)
				x.Mnemonic = strings.Fields(x.Syntax)[0]
				var ops []codec.Operand
				for _, o := range v.Operands {
					if o.Name != operand.Name {
						ops = append(ops, o)
					}
				}
				x.Operands = ops
				for _, b := range operand.Bits {
					for k := 0; k < b.Width; k++ {
						p := b.InstructionBit + k
						m := byte(1) << uint(p%8)
						x.Mask[p/8] |= m
						x.Value[p/8] &= ^m
						if n>>uint(b.ValueBit+k)&1 != 0 {
							x.Value[p/8] |= m
						}
					}
				}
				if operand.Class == "DelayBit" && n == 1 {
					x.DelaySlots = 1
				}
				next = append(next, x)
			}
		}
		forms = next
	}
	if !expanded {
		return nil
	}
	return forms
}

// The compact immediate is a cyclic range (-1, 0..6), rather than a signed
// three-bit integer. Keep the public operand numeric in both portions.
func cyclicImmediates(e codec.Encoding) []codec.Encoding {
	forms := []codec.Encoding{e}
	for _, operand := range e.Operands {
		if operand.Class != "Cyclic3" {
			continue
		}
		var next []codec.Encoding
		for _, v := range forms {
			a := v
			a.Operands = append([]codec.Operand(nil), v.Operands...)
			for i, o := range a.Operands {
				if o.Name == operand.Name {
					o.Names = append([]string(nil), o.Names...)
					o.Names[7] = ""
					a.Operands[i] = o
				}
			}
			next = append(next, a)
			b := v
			b.ID += "/minus-one"
			b.Mask = append([]byte(nil), v.Mask...)
			b.Value = append([]byte(nil), v.Value...)
			b.Operands = append([]codec.Operand(nil), v.Operands...)
			for i, o := range b.Operands {
				if o.Name != operand.Name {
					continue
				}
				var bits []codec.BitSlice
				for _, p := range o.Bits {
					if p.ValueBit == 0 {
						bits = append(bits, p)
					} else {
						for k := 0; k < p.Width; k++ {
							bit := p.InstructionBit + k
							m := byte(1) << uint(bit%8)
							b.Mask[bit/8] |= m
							b.Value[bit/8] |= m
						}
					}
				}
				o.Bits = bits
				o.Signed = false
				o.Bias = -2
				o.Names = []string{"", "-1"}
				b.Operands[i] = o
			}
			next = append(next, b)
		}
		forms = next
	}
	return forms
}

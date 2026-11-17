package amdgpu

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Literal sentinels change instruction framing. Expand each nonempty source
// subset into a fixed-length form; all selected sources share one literal word.
func (p *importer) literals(base codec.Encoding, r *record) []codec.Encoding {
	var choices []int
	for i, o := range base.Operands {
		typ := p.rec(o.Class).OperandType
		if strings.Contains(typ, "REG_IMM") && !strings.Contains(typ, "INLINE") && o.Width() >= 8 {
			choices = append(choices, i)
		}
	}
	if len(choices) == 0 || len(choices) > 4 || len(base.Mask) > 8 {
		return nil
	}
	var out []codec.Encoding
	mandatory := -1
	for i, o := range base.Operands {
		if o.Name == "imm" {
			mandatory = i
		}
	}
	for selected := 1; selected < (1 << len(choices)); selected++ {
		if selected&(selected-1) != 0 && (strings.HasPrefix(base.ID, "V_ASHRREV_I64") || strings.HasPrefix(base.ID, "V_LSHLREV_B64") || strings.HasPrefix(base.ID, "V_LSHRREV_B64")) {
			continue
		}
		narrow, integer16 := false, false
		for k, j := range choices {
			if selected&(1<<k) != 0 {
				typ := p.rec(base.Operands[j].Class).OperandType
				if typ == "OPERAND_REG_IMM_INT16" || typ == "OPERAND_REG_IMM_FP16" || typ == "OPERAND_REG_IMM_BF16" {
					narrow = true
					integer16 = integer16 || typ == "OPERAND_REG_IMM_INT16"
				}
			}
		}
		// True16 half selection is a register property. The assembler
		// clears op_sel for literal sources rather than selecting a half.
		valid := true
		for k, j := range choices {
			if selected&(1<<k) != 0 {
				hi, lo := false, false
				for _, n := range base.Operands[j].Names {
					hi = hi || strings.Contains(n, ".h")
					lo = lo || strings.Contains(n, ".l")
				}
				if hi && !lo {
					valid = false
				}
			}
		}
		if !valid {
			continue
		}
		all64 := true
		for k, j := range choices {
			if selected&(1<<k) != 0 && !strings.HasSuffix(p.rec(base.Operands[j].Class).OperandType, "64") {
				all64 = false
			}
		}
		e := base
		e.ID += fmt.Sprintf("/literal%x", selected)
		e.Mask = append([]byte(nil), base.Mask...)
		e.Value = append([]byte(nil), base.Value...)
		if mandatory < 0 {
			e.Mask = append(e.Mask, 0, 0, 0, 0)
			e.Value = append(e.Value, 0, 0, 0, 0)
		}
		e.Operands = nil
		e.Constraints = nil
		removed := map[string]bool{}
		for k, j := range choices {
			if selected&(1<<k) != 0 {
				removed[base.Operands[j].Name] = true
			}
		}
		for _, c := range base.Constraints {
			if !removed[c.Left] && !removed[c.Right] {
				e.Constraints = append(e.Constraints, c)
			}
		}
		e.Features = append([]string(nil), base.Features...)
		if len(base.Mask) == 4 {
			for _, u := range r.Uses {
				if u.Def == "VCC" || u.Def == "VCC_LO" || u.Def == "VCC_HI" || u.Def == "M0" || u.Def == "FLAT_SCR" {
					e.Features = append(e.Features, "AMDGPU_TwoConstantBus")
					break
				}
			}
		}
		if len(base.Mask) == 8 && mandatory < 0 {
			e.Features = append(e.Features, "HasVOP3Literal")
		}
		literalName := "literal"
		if mandatory >= 0 {
			literalName = "imm"
		}
		for i, o := range base.Operands {
			literal := false
			for k, j := range choices {
				if i == j && selected&(1<<k) != 0 {
					literal = true
					break
				}
			}
			if !literal {
				e.Operands = append(e.Operands, o)
				continue
			}
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					pos := b.InstructionBit + k
					e.Mask[pos/8] |= 1 << uint(pos%8)
					if b.ValueBit+k < 8 {
						e.Value[pos/8] |= 1 << uint(pos%8)
					} else {
						e.Value[pos/8] &= ^(1 << uint(pos%8))
					}
				}
			}
			replacement := "{" + literalName + "}"
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", replacement)
		}
		if mandatory < 0 {
			e.Operands = append(e.Operands, codec.Operand{Name: "literal", Class: "AMDGPU_literal32", Kind: "address", Bits: []codec.BitSlice{{InstructionBit: len(base.Mask) * 8, ValueBit: 0, Width: 32}}})
		}
		if narrow {
			e.Constraints = append([]codec.Constraint(nil), e.Constraints...)
			min := int64(0)
			if integer16 {
				min = -32768
			}
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "diff_ge", Left: literalName, Limit: min}, codec.Constraint{Kind: "sum_le", Left: literalName, Limit: 65535})
			if mandatory < 0 {
				last := &e.Operands[len(e.Operands)-1]
				last.Class = "AMDGPU_literal16"
				if integer16 {
					last.Kind = "immediate"
					last.Signed = true
				}
			}
		}
		if strings.HasPrefix(base.ID, "V_WRITELANE_B32") {
			for i := range e.Operands {
				o := &e.Operands[i]
				if o.Name == "src1" {
					o.Names = append([]string(nil), o.Names...)
					for k, n := range o.Names {
						if k < 128 && n != "m0" && n != "null" {
							o.Names[k] = ""
						}
					}
				}
			}
		}
		out = append(out, e)
		if all64 && mandatory < 0 && len(base.Mask) == 4 {
			wide := e
			wide.ID += "/literal64"
			wide.Mask = append(append([]byte(nil), e.Mask...), 0, 0, 0, 0)
			wide.Value = append(append([]byte(nil), e.Value...), 0, 0, 0, 0)
			wide.Features = append(append([]string(nil), e.Features...), "Has64BitLiterals")
			wide.Operands = append([]codec.Operand(nil), e.Operands...)
			last := &wide.Operands[len(wide.Operands)-1]
			last.Class = "AMDGPU_literal64"
			last.Bits = []codec.BitSlice{{InstructionBit: len(base.Mask) * 8, Width: 64}}
			for k, j := range choices {
				if selected&(1<<k) != 0 {
					for _, b := range base.Operands[j].Bits {
						if b.ValueBit == 0 {
							wide.Value[b.InstructionBit/8] &^= 1 << uint(b.InstructionBit%8)
						}
					}
				}
			}
			out = append(out, wide)
		}
		if mandatory < 0 {
			alias := e
			alias.ID += "/explicit-literal"
			alias.AssemblyOnly = true
			alias.Syntax = strings.ReplaceAll(alias.Syntax, "{literal}", "lit({literal})")
			out = append(out, alias)
		}
	}
	return out
}

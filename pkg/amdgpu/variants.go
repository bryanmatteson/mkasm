package amdgpu

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"regexp"
	"strconv"
	"strings"
)

func variants(base codec.Encoding) []codec.Encoding {
	if strings.HasPrefix(base.ID, "EXP_") {
		var out []codec.Encoding
		for enable := 15; enable >= 0; enable-- {
			e := base
			e.Mask = append([]byte(nil), base.Mask...)
			e.Value = append([]byte(nil), base.Value...)
			e.Operands = nil
			if enable != 15 {
				e.ID += fmt.Sprintf("/enable%x", enable)
			}
			for _, o := range base.Operands {
				if o.Name == "en" {
					for _, b := range o.Bits {
						for k := 0; k < b.Width; k++ {
							pos := b.InstructionBit + k
							e.Mask[pos/8] |= 1 << uint(pos%8)
							if enable&(1<<uint(b.ValueBit+k)) != 0 {
								e.Value[pos/8] |= 1 << uint(pos%8)
							}
						}
					}
					continue
				}
				if strings.HasPrefix(o.Name, "src") && len(o.Name) == 4 && enable&(1<<uint(o.Name[3]-'0')) == 0 {
					e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", "off")
					o.Implicit = true
				}
				e.Operands = append(e.Operands, o)
			}
			out = append(out, e)
		}
		return out
	}
	// True16 op_sel bits select register halves as well as scalar half input.
	// Enumerating these small control fields keeps formatted register suffixes
	// consistent with the physically separate selector bits.
	true16 := false
	opsel := -1
	for i, o := range base.Operands {
		if strings.Contains(o.Class, "VSrcT_") {
			true16 = true
		}
		if o.Name == "op_sel" {
			opsel = i
		}
	}
	if true16 && opsel >= 0 && base.Operands[opsel].Width() <= 4 {
		control := base.Operands[opsel]
		dstLane := control.Width() - 1
		var out []codec.Encoding
		allowed := 0
		srcLane := 0
		for _, o := range base.Operands {
			lane := -1
			if o.Name == "src0" || o.Name == "src1" || o.Name == "src2" {
				lane = srcLane
				srcLane++
			}
			if o.Name == "vdst" {
				continue
			}
			if lane >= 0 {
				for _, name := range o.Names {
					if strings.Contains(name, ".l") {
						allowed |= 1 << lane
						break
					}
				}
			}
		}
		for _, o := range base.Operands {
			if o.Name == "vdst" {
				for _, name := range o.Names {
					if strings.Contains(name, ".l") {
						allowed |= 1 << dstLane
						if srcLane < dstLane {
							allowed |= 1 << srcLane
						}
						break
					}
				}
			}
		}
		for value := 0; value < 1<<control.Width(); value++ {
			if value & ^allowed != 0 {
				continue
			}
			// Accumulating forms tie their hidden final source to vdst.
			if srcLane < dstLane && ((value>>srcLane)&1) != ((value>>dstLane)&1) {
				continue
			}
			e := base
			e.Mask = append([]byte(nil), base.Mask...)
			e.Value = append([]byte(nil), base.Value...)
			e.Operands = nil
			if value != 0 {
				e.ID += fmt.Sprintf("/opsel%x", value)
			}
			var flags []string
			for k := 0; k < control.Width(); k++ {
				flags = append(flags, fmt.Sprint((value>>k)&1))
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "{op_sel}", " op_sel:["+strings.Join(flags, ",")+"]")
			for _, b := range control.Bits {
				for k := 0; k < b.Width; k++ {
					pos := b.InstructionBit + k
					e.Mask[pos/8] |= 1 << uint(pos%8)
					if value&(1<<uint(b.ValueBit+k)) != 0 {
						e.Value[pos/8] |= 1 << uint(pos%8)
					}
				}
			}
			srcs := 0
			for _, o := range base.Operands {
				if o.Name == "src0" || o.Name == "src1" || o.Name == "src2" {
					srcs++
				}
			}
			for i, o := range base.Operands {
				if i == opsel {
					continue
				}
				lane := -1
				switch o.Name {
				case "src0":
					lane = 0
				case "src1":
					lane = 1
				case "src2":
					lane = 2
				case "vdst":
					lane = dstLane
				}
				if lane >= 0 && value&(1<<lane) != 0 {
					o.Names = append([]string(nil), o.Names...)
					for k, n := range o.Names {
						o.Names[k] = strings.ReplaceAll(n, ".l", ".h")
					}
				}
				e.Operands = append(e.Operands, o)
			}
			out = append(out, e)
		}
		return out
	}
	for _, o := range base.Operands {
		if o.Class != "VOPDDstYOperand" {
			continue
		}
		var out []codec.Encoding
		for parity := 0; parity < 2; parity++ {
			e := base
			e.Operands = append([]codec.Operand(nil), base.Operands...)
			if parity == 1 {
				e.ID += "/odd-x"
			}
			for i := range e.Operands {
				op := &e.Operands[i]
				if op.Name == "vdstX" {
					op.Names = append([]string(nil), op.Names...)
					for k := range op.Names {
						if k%2 != parity {
							op.Names[k] = ""
						}
					}
				}
				if op.Class == "VOPDDstYOperand" {
					op.Bias = int64(1 - parity)
					op.Names = make([]string, 1<<op.Width())
					for k := range op.Names {
						if k%2 == 0 {
							op.Names[k] = fmt.Sprintf("v%d", k+1-parity)
						}
					}
				}
			}
			out = append(out, e)
		}
		return out
	}
	return []codec.Encoding{base}
}

// LLVM's optional named immediates omit their source-defined zero default.
// Keep the complete encoding as the formatting form and add text-only aliases.
func (p *importer) omittedZero(base codec.Encoding) []codec.Encoding {
	var choices []string
	for _, o := range base.Operands {
		prefix := numericPrefix(p.rec(o.Class))
		if prefix != "" && len(o.Names) == 0 && strings.Contains(base.Syntax, " "+prefix+":{"+o.Name+"}") {
			choices = append(choices, o.Name)
		}
	}
	if len(choices) == 0 || len(choices) > 5 {
		return nil
	}
	var out []codec.Encoding
	for mask := 1; mask < 1<<len(choices); mask++ {
		e := base
		e.ID += fmt.Sprintf("/omit%x", mask)
		e.AssemblyOnly = true
		e.Mask = append([]byte(nil), base.Mask...)
		e.Value = append([]byte(nil), base.Value...)
		e.Operands = nil
		for _, o := range base.Operands {
			omit := false
			for k, n := range choices {
				if n == o.Name && mask&(1<<k) != 0 {
					omit = true
				}
			}
			if !omit {
				e.Operands = append(e.Operands, o)
				continue
			}
			prefix := numericPrefix(p.rec(o.Class))
			e.Syntax = strings.ReplaceAll(e.Syntax, " "+prefix+":{"+o.Name+"}", "")
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					pos := b.InstructionBit + k
					e.Mask[pos/8] |= 1 << uint(pos%8)
					e.Value[pos/8] &= ^(1 << uint(pos%8))
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// Boolean registers change physical width with the wave size. Some LLVM
// instruction records defer this to decodeBoolReg rather than splitting defs.
func profileVariants(base codec.Encoding) []codec.Encoding {
	var out []codec.Encoding
	for _, image := range r128Variants(base) {
		for _, e := range maiVariants(image) {
			out = append(out, boolVariants(e)...)
		}
	}
	return out
}

// AMDGPUInstPrinter::printR128A16 aliases the legacy resource-size bit to
// A16 only on processors with FeatureR128A16. GFX10 has a distinct A16 bit;
// naming both operands A16 makes their adjacent optional syntax ambiguous.
func r128Variants(base codec.Encoding) []codec.Encoding {
	index := -1
	for i, o := range base.Operands {
		if o.Class == "R128A16" && !o.Implicit && len(o.Names) > 1 {
			index = i
			break
		}
	}
	if index < 0 {
		return []codec.Encoding{base}
	}
	legacy := base
	legacy.Features = append(append([]string(nil), base.Features...), "AMDGPU_NoR128A16")
	aliased := base
	aliased.ID += "/r128-a16"
	aliased.Features = append(append([]string(nil), base.Features...), "HasR128A16")
	aliased.Operands = append([]codec.Operand(nil), base.Operands...)
	aliased.Operands[index].Names = append([]string(nil), base.Operands[index].Names...)
	aliased.Operands[index].Names[1] = " a16"
	return []codec.Encoding{legacy, aliased}
}
func boolVariants(base codec.Encoding) []codec.Encoding {
	needsWave := false
	for _, o := range base.Operands {
		if o.Class == "VOPDstS64orS32" || o.Class == "SSrc_i1" || o.Class == "SDWAVopcDst" {
			needsWave = true
		}
	}
	for _, f := range base.Features {
		if f == "isWave32" || f == "isWave64" {
			needsWave = false
		}
	}
	if !needsWave {
		return variants(base)
	}
	wide := base
	wide.Features = append(append([]string(nil), base.Features...), "isWave64")
	narrow := base
	narrow.ID += "/wave32"
	narrow.Features = append(append([]string(nil), base.Features...), "isWave32")
	narrow.Operands = append([]codec.Operand(nil), base.Operands...)
	for i := range narrow.Operands {
		o := &narrow.Operands[i]
		if o.Class != "VOPDstS64orS32" && o.Class != "SSrc_i1" && o.Class != "SDWAVopcDst" {
			continue
		}
		o.Names = append([]string(nil), o.Names...)
		for k, n := range o.Names {
			raw := k
			if o.Class == "SDWAVopcDst" {
				if k == 0 {
					o.Names[k] = "vcc_lo"
					continue
				}
				if k < 128 {
					continue
				}
				raw -= 128
			}
			if raw < 106 {
				o.Names[k] = fmt.Sprintf("s%d", raw)
				continue
			}
			var start, end int
			if _, err := fmt.Sscanf(n, "s[%d:%d]", &start, &end); err == nil {
				o.Names[k] = fmt.Sprintf("s%d", start)
			}
			if _, err := fmt.Sscanf(n, "ttmp[%d:%d]", &start, &end); err == nil {
				o.Names[k] = fmt.Sprintf("ttmp%d", start)
			}
			if n == "vcc" {
				o.Names[k] = "vcc_lo"
			}
			if n == "exec" {
				o.Names[k] = "exec_lo"
			}
		}
	}
	return append(variants(wide), variants(narrow)...)
}

func alignmentVariants(base codec.Encoding) []codec.Encoding {
	var indices []int
	for i, o := range base.Operands {
		if strings.Contains(base.ID, "DS_READ_B96_TR_B6") || strings.Contains(base.ID, "DS_LOAD_TR6_B96") {
			continue
		}
		if strings.Contains(base.ID, "GLOBAL_LOAD_TR6_B96") && o.Name == "vdst" {
			continue
		}
		for _, n := range o.Names {
			if m := tupleRegister.FindStringSubmatch(n); m != nil {
				start, _ := strconv.Atoi(m[1])
				if start&1 != 0 {
					indices = append(indices, i)
					break
				}
			}
		}
	}
	if len(indices) == 0 {
		return []codec.Encoding{base}
	}
	loose := base
	loose.Features = append(append([]string(nil), base.Features...), "AMDGPU_UnalignedVGPRs")
	aligned := base
	aligned.ID += "/aligned"
	aligned.Features = append(append([]string(nil), base.Features...), "AMDGPU_AlignedVGPRs")
	aligned.Operands = append([]codec.Operand(nil), base.Operands...)
	for _, i := range indices {
		o := &aligned.Operands[i]
		o.Names = append([]string(nil), o.Names...)
		for k, n := range o.Names {
			if m := tupleRegister.FindStringSubmatch(n); m != nil {
				start, _ := strconv.Atoi(m[1])
				if start&1 != 0 {
					o.Names[k] = ""
				}
			}
		}
	}
	return []codec.Encoding{loose, aligned}
}

var tupleRegister = regexp.MustCompile(`[va]\[([0-9]+):([0-9]+)\]`)

func maiVariants(base codec.Encoding) []codec.Encoding {
	if !strings.HasPrefix(base.ID, "V_MFMA_") {
		return []codec.Encoding{base}
	}
	i := operandIndex(base, "src2")
	if i < 0 {
		return []codec.Encoding{base}
	}
	inline := func(n string) bool { n = strings.TrimLeft(n, "-+|"); return len(n) > 0 && n[0] >= '0' && n[0] <= '9' }
	found := false
	for _, n := range base.Operands[i].Names {
		found = found || inline(n)
	}
	if !found {
		return []codec.Encoding{base}
	}
	normal := base
	normal.Features = append(append([]string(nil), base.Features...), "AMDGPU_MFMAInlineAllowed")
	bug := base
	bug.ID += "/no-inline-src2"
	bug.Features = append(append([]string(nil), base.Features...), "AMDGPU_MFMAInlineBug")
	bug.Operands = append([]codec.Operand(nil), base.Operands...)
	bug.Operands[i].Names = append([]string(nil), base.Operands[i].Names...)
	for k, n := range bug.Operands[i].Names {
		if inline(n) {
			bug.Operands[i].Names[k] = ""
		}
	}
	return []codec.Encoding{normal, bug}
}

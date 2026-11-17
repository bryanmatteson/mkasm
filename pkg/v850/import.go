package v850

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"regexp"
	"strconv"
	"strings"
)

func slices(parts ...int) []codec.BitSlice {
	var out []codec.BitSlice
	for i := 0; i < len(parts); i += 3 {
		out = append(out, codec.BitSlice{InstructionBit: parts[i], ValueBit: parts[i+1], Width: parts[i+2]})
	}
	return out
}
func regName(n int) string {
	switch n {
	case 3:
		return "sp"
	case 4:
		return "gp"
	case 30:
		return "ep"
	case 31:
		return "lp"
	}
	return fmt.Sprintf("r%d", n)
}

var lists = func() []string {
	out := make([]string, 4096)
	for mask := range out {
		var runs []string
		for n := 0; n < 12; n++ {
			if mask&(1<<uint(n)) == 0 {
				continue
			}
			first := n
			for n+1 < 12 && mask&(1<<uint(n+1)) != 0 {
				n++
			}
			s := regName(first + 20)
			if first != n {
				s += "-" + regName(n+20)
			}
			runs = append(runs, s)
		}
		out[mask] = "{" + strings.Join(runs, ", ") + "}"
	}
	return out
}()

func namedAliases(section string) map[string]int64 {
	start := strings.Index(assemblerSource, "static const struct reg_name "+section+"[]")
	if start < 0 {
		return nil
	}
	src := assemblerSource[start:]
	end := strings.Index(src, "};")
	if end < 0 {
		return nil
	}
	src = src[:end]
	out := map[string]int64{}
	for _, m := range regexp.MustCompile(`\{\s*"([^"]+)"\s*,\s*(0x[0-9a-f]+|[0-9]+|COND_SA_NUM)`).FindAllStringSubmatch(src, -1) {
		v := int64(13)
		if m[2] != "COND_SA_NUM" {
			v, _ = strconv.ParseInt(m[2], 0, 64)
		}
		out[m[1]] = v
	}
	return out
}
func importForm(index int, name string, op, mask uint32, cpu, mem int, params []operandSpec) (codec.Encoding, error) {
	base := 2
	if op&0x600 == 0x600 {
		base = 4
	}
	hasExtended32 := false
	for _, p := range params {
		hasExtended32 = hasExtended32 || p.Flags&imm32 != 0
	}
	if hasExtended32 && (op&0xffe0 == 0x620 || op&0x1ffe0 == 0x2e0 || op&0x1ffe0 == 0x6e0) {
		base = 2
	}
	n := base
	for _, p := range params {
		switch {
		case p.Flags&(imm16|imm16hi) != 0:
			n = base + 2
		case p.Flags&imm32 != 0:
			n = base + 4
		case p.Flags&imm23 != 0:
			n = 6
		}
	}
	e := codec.Encoding{ID: fmt.Sprintf("%s_%03d", name, index), Mnemonic: name, Mask: make([]byte, n), Value: make([]byte, n), Features: []string{fmt.Sprintf("cpu_%d", cpu&63)}, AssemblyOnly: cpu&128 != 0, FlowControl: "next"}
	if cpu&64 != 0 {
		e.Features = append(e.Features, "extension")
	}
	for j := 0; j < min(n, 4); j++ {
		e.Mask[j] = byte(mask >> uint(j*8))
		e.Value[j] = byte(op >> uint(j*8))
	}
	hasSelector := false
	for _, p := range params {
		hasSelector = hasSelector || p.Name == "SELID"
	}
	text := name
	var position string
	for i, p := range params {
		field := fmt.Sprintf("op%d", i)
		o := codec.Operand{Name: field, Class: p.Name, Kind: "immediate", Signed: p.Flags&signedFlag != 0}
		literal := ""
		if p.Bits > 0 {
			o.Bits = slices(int(p.Shift), 0, p.Bits)
		}
		switch p.Name {
		case "EP":
			literal = "ep"
		case "SP":
			literal = "sp"
		case "LIST12":
			o.Bits = nil
			for bit, physical := range []int{27, 26, 25, 24, 31, 30, 29, 28, 23, 22, 0, 21} {
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: physical, ValueBit: bit, Width: 1})
			}
			o.Names = lists
		case "I5DIV1", "I5DIV2", "I5DIV3":
			o.Bits = slices(18, 0, 4)
			o.Scale = 2
			o.Xor = 15
			o.Bias = 2
			low, high := int64(2), int64(30)
			if p.Name == "I5DIV2" {
				low = 4
			}
			if p.Name == "I5DIV3" {
				high = 32
			}
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "diff_ge", Left: field, Limit: low}, codec.Constraint{Kind: "sum_le", Left: field, Limit: high})
		case "D5_4U":
			o.Bits = slices(0, 1, 4)
		case "D8_7U":
			o.Bits = slices(0, 1, 7)
		case "D8_6U":
			o.Bits = slices(1, 2, 6)
		case "V8", "VECTOR8":
			o.Bits = slices(0, 0, 5, 27, 5, 3)
		case "D9", "D9_RELAX":
			o.Bits = slices(4, 1, 3, 11, 4, 5)
		case "D16_15":
			o.Bits = slices(17, 1, 15)
		case "D16_16":
			o.Bits = slices(5, 0, 1, 17, 1, 15)
		case "D16_LOOP":
			o.Bits = slices(17, 0, 15)
			o.Scale = 2
			o.Xor = 32767
			o.Bias = -65534
		case "D17_16":
			o.Bits = slices(17, 1, 15, 4, 16, 1)
		case "D22":
			o.Bits = slices(17, 1, 15, 0, 16, 6)
		case "D23":
			o.Bits = slices(20, 0, 7, 32, 7, 16)
		case "D23_ALIGN1":
			o.Bits = slices(21, 1, 6, 32, 7, 16)
		case "I9", "U9":
			o.Bits = slices(0, 0, 5, 18, 5, 4)
		case "R4":
			o.Bits = slices(23, 0, 1, 17, 1, 4)
		case "IMM16LO":
			o.Bits = slices(base*8, 0, 16)
		case "IMM16HI":
			o.Bits = slices(base*8, 0, 16)
			o.Scale = 65536
			o.InputSignedBits = 32
		case "IMM32":
			o.Bits = slices(base*8, 0, 32)
			o.InputSignedBits = 32
		case "D32_31", "D32_31_PCREL":
			o.Bits = slices(base*8+1, 1, 31)
		case "POS_U", "POS_M", "POS_L":
			o.Bits = slices(17, 0, 3, 27, 3, 1)
			if p.Name == "POS_U" {
				o.Bias = 16
			}
			position = field
		case "WIDTH_U", "WIDTH_M", "WIDTH_L":
			o.Bits = slices(28, 0, 4)
			o.Bias = 17
			if p.Name == "WIDTH_L" {
				o.Bias = 1
			}
			o.BiasOperand = position
			o.BiasScale = -1
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "diff_ge", Left: field, Limit: 1}, codec.Constraint{Kind: "sum_le", Left: field, Right: position, Limit: 32})
		case "SELID":
			o.Bits = slices(27, 0, 5)
		case "VECTOR5":
			o.Bits = slices(0, 0, 5)
		case "CACHEOP":
			o.Bits = slices(27, 0, 5, 11, 5, 2)
		case "PREFOP":
			o.Bits = slices(27, 0, 5)
		case "IMM10U":
			o.Bits = slices(0, 0, 5, 27, 5, 5)
		case "SR1":
			o.Bits = slices(0, 0, 5)
			if !hasSelector {
				o.Bits = append(o.Bits, slices(27, 5, 5)...)
			}
		case "SR2":
			o.Bits = slices(11, 0, 5)
			if !hasSelector {
				o.Bits = append(o.Bits, slices(27, 5, 5)...)
			}
		}
		if p.Flags&reg != 0 && literal == "" {
			o.Kind = "register"
			o.RegisterPrefix = "r"
			o.Names = make([]string, 32)
			o.RegisterAliases = map[string]int64{}
			if p.Flags&even != 0 {
				for j := range o.Bits {
					o.Bits[j].ValueBit++
				}
			}
			for r := 0; r < 32; r++ {
				if p.Flags&even != 0 && r%2 != 0 || p.Flags&notr0 != 0 && r == 0 {
					continue
				}
				o.Names[r] = regName(r)
				o.RegisterAliases[fmt.Sprintf("r%d", r)] = int64(r)
			}
			for alias, v := range namedAliases("pre_defined_registers") {
				if v < 32 && o.Names[v] != "" {
					o.RegisterAliases[alias] = v
				}
			}
		}
		if p.Flags&srg != 0 {
			o.Kind = "register"
			count := 32
			if !hasSelector && (p.Name == "SR1" || p.Name == "SR2") {
				count = 1024
			}
			o.Names = make([]string, count)
			o.RegisterAliases = namedAliases("system_registers")
			for r := range o.Names {
				o.Names[r] = strconv.Itoa(r)
				if r < 32 {
					o.Names[r] = fmt.Sprintf("sr%d", r)
					o.RegisterAliases[strconv.Itoa(r)] = int64(r)
				}
			}
		}
		if p.Flags&vreg != 0 {
			o.Kind = "register"
			o.RegisterPrefix = "vr"
			o.Names = make([]string, 32)
			for r := range o.Names {
				o.Names[r] = fmt.Sprintf("vr%d", r)
			}
		}
		if p.Flags&cc != 0 {
			o.Names = []string{"v", "c", "z", "nh", "s", "t", "lt", "le", "nv", "nc", "nz", "h", "ns", "sa", "ge", "gt"}
			o.RegisterAliases = namedAliases("cc_names")
			if p.Flags&notsa != 0 {
				o.Names[13] = ""
				delete(o.RegisterAliases, "sa")
			}
		}
		if p.Flags&floatcc != 0 {
			o.Names = []string{"f", "un", "eq", "ueq", "olt", "ult", "ole", "ule", "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt"}
			o.RegisterAliases = namedAliases("float_cc_names")
		}
		if p.Flags&(cacheop|prefop) != 0 {
			count, section := 128, "cacheop_names"
			if p.Flags&prefop != 0 {
				count, section = 32, "prefop_names"
			}
			o.Names = make([]string, count)
			for r := range o.Names {
				o.Names[r] = strconv.Itoa(r)
			}
			o.RegisterAliases = namedAliases(section)
			for alias, v := range o.RegisterAliases {
				o.Names[v] = alias
			}
		}
		if p.Flags&disp != 0 {
			o.Kind = "displacement"
		}
		if p.Flags&pcrel != 0 {
			o.Relative = true
			o.PCWrapBits = 32
		}
		if p.Flags&notimm0 != 0 {
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: field, Limit: 0})
		}
		if literal == "" {
			if len(o.Bits) == 0 {
				return e, fmt.Errorf("no mapping for %s", p.Name)
			}
			e.Operands = append(e.Operands, o)
			literal = "{" + field + "}"
		}
		prefix := ""
		if p.Flags&bang != 0 {
			prefix = "!"
		}
		if p.Flags&percent != 0 {
			prefix = "%"
		}
		bracket := false
		separator := ", "
		if i == 0 {
			separator = " "
		}
		if mem == i+1 && (i == 0 || i > 0 && params[i-1].Flags&disp != 0) {
			if i > 0 {
				separator = ""
			}
			bracket = true
		} else if name == "dispose" && mem == i+1 {
			bracket = true
		} else if i == 1 && (name == "stc.w" || name == "cache" || name == "pref") && mem == 2 {
			bracket = true
		} else if i == 1 && (name == "clr1" || name == "not1" || name == "set1" || name == "tst1") && len(params) == 2 {
			bracket = true
		}
		if i == 1 && (name == "pushsp" || name == "popsp" || name == "dbpush") {
			separator = "-"
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ge", Left: field, Right: "op0", Limit: 0})
		}
		text += separator + prefix
		if bracket {
			text += "["
		}
		text += literal
		if bracket {
			text += "]"
		}
	}
	e.Syntax = text
	switch name {
	case "jarl", "jarlr", "jarl22", "jarl32", "jarlw", "callt":
		e.FlowControl = "call"
	case "jr", "jr22", "jr32", "jmp", "jmp22", "jmp32", "jmpw", "br", "br17", "jbr", "switch":
		e.FlowControl = "branch"
	case "reti", "ctret", "dbret", "eiret", "feret":
		e.FlowControl = "return"
	case "halt", "snooze":
		e.FlowControl = "stop"
	case "trap", "fetrap", "hvtrap", "hvcall", "syscall", "rie", "breakpoint", "dbtrap", "dbhvtrap", "rmtrap":
		e.FlowControl = "trap"
	default:
		for _, o := range e.Operands {
			if o.Relative {
				e.FlowControl = "conditional_branch"
			}
		}
		if name == "dispose" && mem != 0 {
			e.FlowControl = "return"
		}
	}
	// Upstream masks occasionally omit bits that have no assembler operand.
	// Those bits are reserved zero in this instruction form.
	used := make([]byte, n)
	for _, o := range e.Operands {
		for _, s := range o.Bits {
			for j := 0; j < s.Width; j++ {
				p := s.InstructionBit + j
				if p >= n*8 {
					return e, fmt.Errorf("field %s outside frame", o.Name)
				}
				if e.Mask[p/8]&(1<<uint(p%8)) != 0 {
					return e, fmt.Errorf("source mask overlaps %s bit%d", o.Class, p)
				}
				used[p/8] |= 1 << uint(p%8)
			}
		}
	}
	for j := range e.Mask {
		e.Mask[j] |= ^used[j]
		e.Value[j] &= e.Mask[j]
	}
	return e, nil
}

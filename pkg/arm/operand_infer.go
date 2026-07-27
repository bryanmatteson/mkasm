package arm

import (
	"strings"
	"unicode"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// InferOperandType maps ARM field/operand names to OperandType.
// Cherry-picked from improved-parser-design encoding_handlers.inferOperandTypeFromName
// and arm-encoding-parser operand_parser heuristics.
func InferOperandType(name string) ir.OperandType {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ir.Special
	}

	switch {
	case n == "cond" || n == "condition" || strings.HasPrefix(n, "cond"):
		return ir.Cond
	case n == "nzcv" || n == "pstate" || strings.HasPrefix(n, "pstate"):
		return ir.PState
	case strings.Contains(n, "sysreg") || n == "systemreg":
		return ir.SysReg
	case isSIMDName(n):
		return ir.SIMD
	case isGPRName(n):
		return ir.Reg
	case strings.HasPrefix(n, "imm") || strings.HasPrefix(n, "uimm") ||
		strings.HasPrefix(n, "simm") || n == "rotate" || n == "shift" ||
		n == "amount" || n == "scale" || n == "len" || n == "size" ||
		n == "crm" || n == "crn" || n == "op1" || n == "op2" || n == "op0" ||
		n == "option" || n == "hw" || n == "immr" || n == "imms":
		return ir.Imm
	case n == "mask" || n == "opcode" || n == "opc" || n == "op" ||
		n == "s" || n == "sf" || n == "a" || n == "r" || n == "o0" || n == "o1" || n == "o2" || n == "n":
		return ir.Flag
	default:
		// short alphabetic fields often immediates / enums
		if len(n) <= 2 && unicode.IsLetter(rune(n[0])) {
			return ir.Imm
		}
		return ir.Special
	}
}

func isSIMDName(n string) bool {
	// Vd/Vn/Vm/Va, or V0..V31 / Qd / Dd etc.
	if len(n) >= 2 && (n[0] == 'v' || n[0] == 'q') {
		rest := n[1:]
		if rest == "d" || rest == "n" || rest == "m" || rest == "a" || rest == "t" {
			return true
		}
		return isRegIndexName(rest)
	}
	if len(n) >= 2 && (n[0] == 'd' || n[0] == 's' || n[0] == 'h' || n[0] == 'b') && isRegIndexName(n[1:]) && len(n) <= 3 {
		return true
	}
	return false
}

func isGPRName(n string) bool {
	// Rd, Rn, Rm, Ra, Rt, Rt2, Rs, …
	if len(n) < 2 {
		return false
	}
	if n[0] != 'r' && n[0] != 'w' && n[0] != 'x' {
		// still allow classic Rd/Rn without width prefix
		if n[0] == 'r' || (len(n) >= 2 && n[0] == 'r') {
			// fallthrough
		}
	}
	switch {
	case strings.HasPrefix(n, "rd"), strings.HasPrefix(n, "rn"), strings.HasPrefix(n, "rm"),
		strings.HasPrefix(n, "ra"), strings.HasPrefix(n, "rt"), strings.HasPrefix(n, "rs"),
		strings.HasPrefix(n, "xd"), strings.HasPrefix(n, "xn"), strings.HasPrefix(n, "xm"),
		strings.HasPrefix(n, "wd"), strings.HasPrefix(n, "wn"), strings.HasPrefix(n, "wm"):
		return true
	}
	return false
}

func isRegIndexName(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

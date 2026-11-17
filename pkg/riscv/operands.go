package riscv

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func slice(i, v, w int) codec.BitSlice {
	return codec.BitSlice{InstructionBit: i, ValueBit: v, Width: w}
}

// semantic reunites upstream disjoint field tokens into architectural operands.
// Bit indices below are after removing the implicit low bits represented by Scale.
func semantic(arg string, f field) (string, []codec.BitSlice, bool, int64) {
	switch arg {
	case "imm12hi":
		return "imm", []codec.BitSlice{slice(25, 5, 7)}, true, 1
	case "imm12lo":
		return "imm", []codec.BitSlice{slice(7, 0, 5)}, true, 1
	case "imm12":
		return "imm", []codec.BitSlice{slice(20, 0, 12)}, true, 1
	case "bimm12hi":
		return "offset", []codec.BitSlice{slice(31, 11, 1), slice(25, 4, 6)}, true, 2
	case "bimm12lo":
		return "offset", []codec.BitSlice{slice(8, 0, 4), slice(7, 10, 1)}, true, 2
	case "jimm20":
		return "offset", []codec.BitSlice{slice(31, 19, 1), slice(21, 0, 10), slice(20, 10, 1), slice(12, 11, 8)}, true, 2
	case "zimm6hi":
		return "zimm", []codec.BitSlice{slice(26, 5, 1)}, false, 1
	case "zimm6lo":
		return "zimm", []codec.BitSlice{slice(15, 0, 5)}, false, 1
	case "c_uimm2":
		return "imm", []codec.BitSlice{slice(5, 0, 2)}, false, 1
	case "c_uimm1":
		return "imm", []codec.BitSlice{slice(5, 0, 1)}, false, 2
	case "c_nzuimm10":
		return "imm", []codec.BitSlice{slice(11, 2, 2), slice(7, 4, 4), slice(6, 0, 1), slice(5, 1, 1)}, false, 4
	case "c_uimm7lo":
		return "imm", []codec.BitSlice{slice(6, 0, 1), slice(5, 4, 1)}, false, 4
	case "c_uimm7hi":
		return "imm", []codec.BitSlice{slice(10, 1, 3)}, false, 4
	case "c_uimm8lo":
		return "imm", []codec.BitSlice{slice(5, 3, 2)}, false, 8
	case "c_uimm8hi":
		return "imm", []codec.BitSlice{slice(10, 0, 3)}, false, 8
	case "c_uimm9lo":
		return "imm", []codec.BitSlice{slice(5, 3, 2)}, false, 16
	case "c_uimm9hi":
		return "imm", []codec.BitSlice{slice(10, 0, 3)}, false, 16
	case "c_nzimm6lo", "c_imm6lo":
		return "imm", []codec.BitSlice{slice(2, 0, 5)}, true, 1
	case "c_nzimm6hi", "c_imm6hi":
		return "imm", []codec.BitSlice{slice(12, 5, 1)}, true, 1
	case "c_nzuimm6lo", "c_nzuimm5":
		return "shamt", []codec.BitSlice{slice(2, 0, 5)}, false, 1
	case "c_nzuimm6hi":
		return "shamt", []codec.BitSlice{slice(12, 5, 1)}, false, 1
	case "c_nzimm10hi":
		return "imm", []codec.BitSlice{slice(12, 5, 1)}, true, 16
	case "c_nzimm10lo":
		return "imm", []codec.BitSlice{slice(6, 0, 1), slice(5, 2, 1), slice(3, 3, 2), slice(2, 1, 1)}, true, 16
	case "c_nzimm18hi":
		return "imm", []codec.BitSlice{slice(12, 5, 1)}, true, 1
	case "c_nzimm18lo":
		return "imm", []codec.BitSlice{slice(2, 0, 5)}, true, 1
	case "c_imm12":
		return "offset", []codec.BitSlice{slice(12, 10, 1), slice(11, 3, 1), slice(9, 7, 2), slice(8, 9, 1), slice(7, 5, 1), slice(6, 6, 1), slice(3, 0, 3), slice(2, 4, 1)}, true, 2
	case "c_bimm9hi":
		return "offset", []codec.BitSlice{slice(12, 7, 1), slice(10, 2, 2)}, true, 2
	case "c_bimm9lo":
		return "offset", []codec.BitSlice{slice(5, 5, 2), slice(3, 0, 2), slice(2, 4, 1)}, true, 2
	case "c_uimm8sphi":
		return "imm", []codec.BitSlice{slice(12, 3, 1)}, false, 4
	case "c_uimm8splo":
		return "imm", []codec.BitSlice{slice(4, 0, 3), slice(2, 4, 2)}, false, 4
	case "c_uimm8sp_s":
		return "imm", []codec.BitSlice{slice(9, 0, 4), slice(7, 4, 2)}, false, 4
	case "c_uimm9sphi":
		return "imm", []codec.BitSlice{slice(12, 2, 1)}, false, 8
	case "c_uimm9splo":
		return "imm", []codec.BitSlice{slice(5, 0, 2), slice(2, 3, 3)}, false, 8
	case "c_uimm9sp_s":
		return "imm", []codec.BitSlice{slice(10, 0, 3), slice(7, 3, 3)}, false, 8
	case "c_uimm10sphi":
		return "imm", []codec.BitSlice{slice(12, 1, 1)}, false, 16
	case "c_uimm10splo":
		return "imm", []codec.BitSlice{slice(6, 0, 1), slice(2, 2, 4)}, false, 16
	case "c_uimm10sp_s":
		return "imm", []codec.BitSlice{slice(11, 0, 2), slice(7, 2, 4)}, false, 16
	}
	name := arg
	if strings.HasPrefix(arg, "shamt") {
		name = "shamt"
	}
	return name, []codec.BitSlice{slice(f.lo, 0, f.hi-f.lo+1)}, arg == "simm5", 1
}

var integerABI = []string{"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"}
var floatABI = []string{"ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"}

func configureRegister(o *codec.Operand, arg, mnemonic string, value uint32, width int) {
	prefix := ""
	base, scale := 0, 1
	switch {
	case strings.HasPrefix(arg, "vd") || strings.HasPrefix(arg, "vs"):
		prefix = "v"
	case strings.HasPrefix(arg, "rd") || strings.HasPrefix(arg, "rs") || arg == "rt" || strings.HasPrefix(arg, "c_rs") || strings.HasPrefix(arg, "p_rd") || strings.HasPrefix(arg, "p_rs"):
		prefix = "x"
	case arg == "c_sreg1" || arg == "c_sreg2":
		prefix = "x"
	}
	if prefix == "x" && floatingRegister(arg, mnemonic, value) {
		prefix = "f"
	}
	if prefix != "" {
		o.Kind = "register"
		o.RegisterPrefix = prefix
		if strings.HasSuffix(arg, "_p") || strings.HasSuffix(arg, "_p_e") {
			base = 8
		}
		if strings.HasSuffix(arg, "_e") {
			scale = 2
		}
		if strings.HasPrefix(arg, "p_") && strings.HasSuffix(arg, "_p") {
			base = 0
			scale = 2
		}
		if arg == "vs2x8" {
			scale = 8
		}
		o.Bias = int64(base)
		o.Scale = int64(scale)
		o.Names = make([]string, 1<<uint(width))
		// Bits are appended by the caller after register configuration; source width
		// is known from the operand class for all upstream register fields.
		o.RegisterAliases = map[string]int64{}
		for i := range o.Names {
			reg := base + i*scale
			if arg == "c_sreg1" || arg == "c_sreg2" {
				reg = []int{8, 9, 18, 19, 20, 21, 22, 23}[i]
			}
			if (strings.Contains(arg, "_n0") && reg == 0) || (arg == "rd_n2" && (reg == 0 || reg == 2)) {
				continue
			}
			o.Names[i] = fmt.Sprintf("%s%d", prefix, reg)
			if prefix == "x" && reg < 32 {
				o.RegisterAliases[integerABI[reg]] = int64(i)
				if reg == 8 {
					o.RegisterAliases["fp"] = int64(i)
				}
			}
			if prefix == "f" && reg < 32 {
				o.RegisterAliases[floatABI[reg]] = int64(i)
			}
		}
	}
	switch arg {
	case "rm":
		o.Names = []string{"rne", "rtz", "rdn", "rup", "rmm", "", "", "dyn"}
	case "pred", "succ":
		o.Names = make([]string, 16)
		for i := 1; i < 16; i++ {
			for j, c := range "iorw" {
				if i&(1<<uint(3-j)) != 0 {
					o.Names[i] += string(c)
				}
			}
		}
		o.Names[0] = "0"
	case "csr": /* numeric CSR values remain legal, symbolic aliases are supplemental */
	}
}

// Upstream reuses integer register field tokens for floating point operands.
// The scalar major opcode and conversion spelling determine the register bank.
func floatingRegister(arg, m string, value uint32) bool {
	if strings.HasPrefix(m, "c.f") {
		return arg != "rs1_p"
	}
	opcode := value & 0x7f
	if opcode == 0x07 {
		return arg == "rd"
	}
	if opcode == 0x27 {
		return arg == "rs2"
	}
	if opcode == 0x43 || opcode == 0x47 || opcode == 0x4b || opcode == 0x4f {
		return true
	}
	if opcode == 0x57 && arg == "rs1" && (strings.HasSuffix(m, ".vf") || strings.HasSuffix(m, ".wf") || strings.HasSuffix(m, ".vfm") || m == "vfmv.v.f" || m == "vfmv.s.f") {
		return true
	}
	if opcode == 0x57 && arg == "rd" && m == "vfmv.f.s" {
		return true
	}
	if opcode != 0x53 {
		return false
	}
	if arg == "rd" {
		major := value >> 27
		if major == 0x14 || major == 0x18 || major == 0x1c {
			return false
		}
		if strings.HasPrefix(m, "feq.") || strings.HasPrefix(m, "flt.") || strings.HasPrefix(m, "fle.") || strings.HasPrefix(m, "fclass.") || strings.HasPrefix(m, "fmv.x.") {
			return false
		}
		if strings.HasPrefix(m, "fcvt.") {
			parts := strings.Split(m, ".")
			if len(parts) > 1 && (parts[1] == "w" || parts[1] == "wu" || parts[1] == "l" || parts[1] == "lu") {
				return false
			}
		}
	} else if arg == "rs1" {
		major := value >> 27
		if major == 0x1a || major == 0x1e {
			return false
		}
		if strings.HasSuffix(m, ".x") {
			return false
		}
		if strings.HasPrefix(m, "fcvt.") {
			parts := strings.Split(m, ".")
			if len(parts) > 2 && (parts[2] == "w" || parts[2] == "wu" || parts[2] == "l" || parts[2] == "lu") {
				return false
			}
		}
	}
	return true
}
func syntax(e *codec.Encoding, order []string, value uint32) string {
	holes := make([]string, len(order))
	for i, n := range order {
		holes[i] = "{" + n + "}"
	}
	m := e.Mnemonic
	if m == "fcvtmod.w.d" {
		return m + " {rd}, {rs1}, rtz"
	}
	if m == "vsetvli" || m == "vsetivli" || m == "vsetvl" {
		return vectorSyntax(*e)
	}
	if len(order) > 1 && order[0] == "offset" {
		holes = append(append([]string{}, holes[1:]...), "{offset}")
	}
	if strings.HasPrefix(m, "csrr") && len(order) == 3 {
		source := "rs1"
		if strings.HasSuffix(m, "i") {
			source = "zimm5"
		}
		holes = []string{"{rd}", "{csr}", "{" + source + "}"}
	}
	opcode := value & 0x7f
	if m == "csrw" || m == "csrs" || m == "csrc" {
		holes = []string{"{csr}", "{rs1}"}
	}
	has := func(n string) bool {
		for _, x := range order {
			if x == n {
				return true
			}
		}
		return false
	}
	reg := func() string {
		for _, n := range order {
			if n != "imm" && n != "rs1" && n != "rs1_p" {
				return "{" + n + "}"
			}
		}
		return ""
	}
	if !strings.HasPrefix(m, "c.") && (opcode == 0x03 || opcode == 0x07 || opcode == 0x23 || opcode == 0x27) && has("imm") && has("rs1") && len(order) == 3 {
		return m + " " + reg() + ", {imm}({rs1})"
	}
	if m == "jalr" && has("imm") {
		return m + " {rd}, {imm}({rs1})"
	}
	if strings.HasPrefix(m, "c.") && has("imm") {
		if has("rs1_p") && (strings.HasPrefix(m, "c.l") || strings.HasPrefix(m, "c.s") || strings.HasPrefix(m, "c.fl") || strings.HasPrefix(m, "c.fs")) {
			return m + " " + reg() + ", {imm}({rs1_p})"
		}
		if strings.HasSuffix(m, "sp") && m != "c.addi16sp" && m != "c.addi4spn" && len(order) == 2 {
			return m + " " + reg() + ", {imm}(sp)"
		}
		if m == "c.addi4spn" {
			return m + " {rd_p}, sp, {imm}"
		}
		if m == "c.addi16sp" {
			return m + " sp, {imm}"
		}
	}
	for i := range e.Operands {
		if e.Operands[i].Name == "offset" {
			e.Operands[i].Kind = "displacement"
			e.Operands[i].Relative = true
		}
	}
	if len(holes) == 0 {
		return m
	}
	return m + " " + strings.Join(holes, ", ")
}
func configureSpecialOperands(e *codec.Encoding) {
	if hasOperand(*e, "c_rlist") && hasOperand(*e, "c_spimm") {
		e.AssemblyOnly = true
	}
	for i := range e.Operands {
		o := &e.Operands[i]
		if e.Mnemonic == "c.lui" && o.Name == "imm" {
			// Bias and XOR preserve a signed six-bit value while naming its unsigned
			// 20-bit assembler spelling (e.g. -1 is written 1048575 by LLVM/GNU).
			o.Signed = false
			o.Xor = 32
			o.Bias = -32
			o.Names = make([]string, 64)
			for n := range o.Names {
				v := n - 32
				if v < 0 {
					v += (1 << 20)
				}
				o.Names[n] = fmt.Sprint(v)
			}
		}
		if strings.HasPrefix(e.Mnemonic, "vset") && (o.Name == "zimm10" || o.Name == "zimm11") {
			o.Names = make([]string, 1<<uint(o.Width()))
			for n := 0; n < 256; n++ {
				lmul := []string{"m1", "m2", "m4", "m8", "", "mf8", "mf4", "mf2"}[n&7]
				if lmul == "" {
					continue
				}
				tail := "tu"
				if n&64 != 0 {
					tail = "ta"
				}
				mask := "mu"
				if n&128 != 0 {
					mask = "ma"
				}
				o.Names[n] = fmt.Sprintf("e%d,%s,%s,%s", 8<<uint((n>>3)&7), lmul, tail, mask)
			}
		}
		if strings.HasPrefix(e.Mnemonic, "fli.") && o.Name == "rs1" {
			o.Kind = "immediate"
			o.RegisterPrefix = ""
			o.RegisterAliases = nil
			o.Names = []string{"-1.0", "min", "0x1p-16", "0x1p-15", "0x1p-8", "0x1p-7", "0.0625", "0.125", "0.25", "0.3125", "0.375", "0.4375", "0.5", "0.625", "0.75", "0.875", "1.0", "1.25", "1.5", "1.75", "2.0", "2.5", "3.0", "4.0", "8.0", "16.0", "128.0", "256.0", "32768.0", "65536.0", "inf", "nan"}
		}
	}
}

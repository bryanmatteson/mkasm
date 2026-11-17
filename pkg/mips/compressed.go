package mips

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"strings"
)

func prepareCompressed(r record, is16 bool) {
	if str(r["!name"]) == "RDHWR_MM" {
		r["AsmString"] = literalHole(str(r["AsmString"]), "sel", "0")
	}
	if str(r["DecoderMethod"]) == "DecodeMovePOperands" {
		inst := r["Inst"].([]any)
		for i := 7; i <= 9; i++ {
			inst[i] = map[string]any{"var": "rdpair", "kind": "varbit", "index": float64(i - 7)}
		}
		r["AsmString"] = strings.Replace(str(r["AsmString"]), "$rd1, $rd2", "$rdpair", 1)
		r["OutOperandList"] = map[string]any{"args": []any{[]any{map[string]any{"def": "micromips_regpair"}, "rdpair"}}}
	}
	if !is16 {
		// LLVM 22's microMIPS DSP records contain five incorrect fixed
		// opcodes. GNU gas and its independent disassembler agree on the
		// architectural POOL32A layouts (micromips-opc.c, binutils 2.44).
		// Preserve the source operands/features while correcting those bits.
		inst := r["Inst"].([]any)
		switch str(r["!name"]) {
		case "CMPGU_EQ_QB_MM", "CMPGU_LT_QB_MM", "CMPGU_LE_QB_MM":
			for bit := 26; bit < 32; bit++ {
				inst[bit] = float64(0)
			}
		case "SHLLV_PH_MM", "SHLLV_S_PH_MM":
			fixed := uint32(0x38d)
			if str(r["!name"]) == "SHLLV_S_PH_MM" {
				fixed = 0x78d
			}
			for bit := 0; bit < 11; bit++ {
				inst[bit] = float64(fixed >> uint(bit) & 1)
			}
		}
		return
	}
	// Correct compiler-only TableGen layout defects against the retained GNU
	// machine rows before they can shadow architectural MIPS16 encodings.
	// These values are independently checked against the real GNU decoder.
	inst := r["Inst"].([]any)
	var corrected uint32
	switch str(r["!name"]) {
	case "AddiuSpImmX16":
		corrected = 0xf0006300
	case "BteqzX16":
		corrected = 0xf0006000
	case "BtnezX16":
		corrected = 0xf0006100
	case "LbRxRyOffMemX16":
		corrected = 0xf0008000
	case "LhRxRyOffMemX16":
		corrected = 0xf0008800
	case "LhuRxRyOffMemX16":
		corrected = 0xf000a800
	case "JrcRa16":
		corrected = 0xe8a0
	case "JrcRx16":
		corrected = 0xe880
	case "JumpLinkReg16":
		corrected = 0xe8c0
	case "NegRxRy16":
		corrected = 0xe80b
	}
	if corrected != 0 {
		for bit := range inst {
			if _, fixed := inst[bit].(float64); fixed {
				inst[bit] = float64(corrected >> uint(bit) & 1)
			}
		}
	}
	switch str(r["!name"]) {
	case "LwRxSpImmX16", "SwRxSpImmX16":
		// SP-relative transfers use RX for the data register; RY is zero.
		for bit := 5; bit < 11; bit++ {
			inst[bit] = float64(0)
			if bit >= 8 {
				inst[bit] = map[string]any{"var": "ry", "kind": "varbit", "index": float64(bit - 8)}
			}
		}
	case "SllvRxRy16", "SrlvRxRy16", "SravRxRy16":
		// Variable shifts write/read RY and take their shift count from RX.
		for bit := 5; bit < 11; bit++ {
			name, index := "rz", bit-5
			if bit >= 8 {
				name, index = "ry", bit-8
			}
			inst[bit] = map[string]any{"var": name, "kind": "varbit", "index": float64(index)}
		}
	case "SllX16", "SrlX16", "SraX16":
		// Word shifts have five shift bits. Bit21 is not a sixth amount bit.
		inst[21] = float64(0)
	}
	if str(r["!name"]) == "MoveR3216" {
		// LLVM's FI8_MOVR3216 layout carries a FIXME: ry was declared as
		// four bits and r32 as four. GNU's architectural y,X form has a
		// three-bit compact destination and five-bit full source register.
		inst := r["Inst"].([]any)
		for bit := 0; bit < 8; bit++ {
			name, index := "r32", bit
			if bit >= 5 {
				name, index = "ry", bit-5
			}
			inst[bit] = map[string]any{"var": name, "kind": "varbit", "index": float64(index)}
		}
	}
	if str(r["!name"]) == "LiRxImmAlignX16" {
		r["AsmString"] = strings.TrimPrefix(str(r["AsmString"]), ".align 2\n\t")
	}
	// These LLVM emission records include a separately printed delay-slot NOP
	// in Size/AsmString, while Inst describes the four-byte JAL itself. Keep
	// the physical JAL here; program assembly owns the separate delay slot.
	if num(r["Size"]) == 6 && len(r["Inst"].([]any)) == 32 {
		r["Size"] = float64(4)
		r["AsmString"] = strings.Split(str(r["AsmString"]), "\n")[0]
	}
	for _, key := range []string{"InOperandList", "OutOperandList"} {
		dag, _ := r[key].(map[string]any)
		if dag == nil {
			continue
		}
		flat := []any{}
		for _, pair := range args(r[key]) {
			children := args(pair[0])
			if len(children) == 0 {
				flat = append(flat, pair)
				continue
			}
			mem, _ := pair[0].(map[string]any)
			kind := def(mem["operator"])
			base, imm := "", ""
			for _, child := range children {
				name := str(child[1])
				cl := "simm16"
				if strings.HasPrefix(name, "r") {
					cl = "CPU16Regs"
					base = name
				} else {
					imm = name
				}
				flat = append(flat, []any{map[string]any{"def": cl}, name})
			}
			replacement := "$" + imm + "($" + base + ")"
			if kind == "mem16sp" {
				replacement = "$" + imm + "(\x01sp)"
			}
			if kind == "mem16_ea" {
				replacement = "$" + base + ", $" + imm
			}
			r["AsmString"] = placeholder.ReplaceAllStringFunc(str(r["AsmString"]), func(s string) string {
				m := placeholder.FindStringSubmatch(s)
				n := m[1]
				if n == "" {
					n = m[2]
				}
				if n == str(pair[1]) {
					return replacement
				}
				return s
			})
		}
		dag["args"] = flat
	}
}

// The lookup tables follow the primary MC emitter/disassembler. These are
// semantic immediates, not identities inferred from the width of Inst fields.
func compressedOperand(o *codec.Operand, rec, class record) bool {
	micro := has(predicates(rec), "InMicroMips") || strings.HasPrefix(str(rec["DecoderNamespace"]), "MicroMips")
	is16 := has(predicates(rec), "InMips16Mode")
	if !micro && !is16 {
		return false
	}
	// LLVM's compiler-facing MIPS16 classes reuse generic immediates for
	// architectural PC-relative data operands and condition-register branches.
	// GNU's actual operand descriptors distinguish their scaling/base rules.
	if is16 && strings.HasPrefix(o.Name, "imm") {
		switch str(rec["!name"]) {
		case "LwRxPcTcp16", "LwRxPcTcpX16":
			o.Kind, o.Relative, o.PCAlignBits = "address", true, 2
			o.Signed, o.Scale = o.Width() == 16, 1
			if o.Width() == 8 {
				o.Scale = 4
			}
			return true
		case "Bteqz16", "BteqzX16", "Btnez16", "BtnezX16":
			o.Kind, o.Relative, o.Signed = "displacement", true, true
			o.Scale, o.PCBias = 2, int64(num(rec["Size"]))
			return true
		case "LiRxImm16", "LiRxImmX16", "LiRxImmAlignX16", "CmpiRxImm16", "CmpiRxImmX16", "SltiRxImm16", "SltiuRxImm16":
			o.Signed = false
			return true
		case "AddiuSpImm16":
			o.Scale = 8
			return true
		}
	}
	switch o.Class {
	case "micromips_regpair":
		o.Names = []string{"$a1, $a2", "$a1, $a3", "$a2, $a3", "$a0, $s5", "$a0, $s6", "$a0, $a1", "$a0, $a2", "$a0, $a3"}
	case "reglist", "reglist16":
		o.Names = make([]string, 1<<o.Width())
		for i := range o.Names {
			n := i & 15
			ra := i&16 != 0
			if o.Class == "reglist16" {
				n = i + 1
				ra = true
			}
			if n > 9 || n == 0 && !ra {
				continue
			}
			parts := []string{}
			for k := 0; k < n; k++ {
				name := fmt.Sprintf("$s%d", k)
				if k == 8 {
					name = "$fp"
				}
				parts = append(parts, name)
			}
			if ra {
				parts = append(parts, "$ra")
			}
			o.Names[i] = strings.Join(parts, ", ")
		}
	case "simm3_lsa2":
		o.Lookup = []int64{1, 4, 8, 12, 16, 20, 24, -1}
		o.Scale = 1
		o.Signed = false
	case "simm9_addiusp":
		o.Lookup = make([]int64, 512)
		for i := range o.Lookup {
			v := int64(i)
			if i >= 256 {
				v -= 512
			}
			switch i {
			case 0:
				v = 256
			case 1:
				v = 257
			case 510:
				v = -258
			case 511:
				v = -257
			}
			o.Lookup[i] = v * 4
		}
		o.Scale = 1
		o.Signed = false
	case "uimm4_andi":
		o.Lookup = []int64{128, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 255, 32768, 65535}
		o.Scale = 1
	case "li16_imm":
		o.Lookup = make([]int64, 128)
		for i := range o.Lookup {
			o.Lookup[i] = int64(i)
		}
		o.Lookup[127] = -1
	case "uimm3_shift":
		o.Lookup = []int64{8, 1, 2, 3, 4, 5, 6, 7}
	case "brtarget7_mm", "brtarget10_mm", "brtarget_mm", "brtargetr6", "brtarget1SImm16", "brtarget26_mm":
		o.Scale = 2
		o.Relative = true
		o.Signed = true
		o.PCBias = 4
		if len(rec["Inst"].([]any)) == 16 {
			o.PCBias = 2
		}
	case "brtarget21_mm", "brtarget_lsl2_mm":
		o.Scale = 4
		o.Relative = true
		o.Signed = true
		o.PCBias = 4
	case "jmptarget_mm", "calltarget_mm":
		o.Scale = 2
		o.Relative = true
		o.PCBias = 4
		o.PCRegionBits = 27
		o.Kind = "address"
	case "simm23_lsl2", "uimm6_lsl2", "uimm5_lsl2":
		o.Scale = 4
	case "brtarget":
		if is16 {
			o.Scale = 2
			o.PCBias = int64(num(rec["Size"]))
		}
	case "uimm26":
		if !is16 {
			return false
		}
		o.Kind = "address"
		o.Scale = 4
		o.Relative = true
		o.PCRegionBits = 28
		o.PCBias = 4
	default:
		return false
	}
	return true
}

func adaptCompressed(e *codec.Encoding, rec record, get func(string) record, is16 bool) error {
	if is16 && (str(rec["!name"]) == "Jal16" || str(rec["!name"]) == "JalB16") {
		e.DelaySlots = 1
		e.FlowControl = "call"
	}
	if is16 {
		switch str(rec["!name"]) {
		case "JrcRa16", "JrcRx16", "JumpLinkReg16", "SebRx16", "SehRx16":
			e.Features = append(e.Features, "HasMips32")
		}
	}
	for i := range e.Operands {
		o := &e.Operands[i]
		// Keep source-defined ignored fields in the exact spelling, including
		// MIPS16 memory forms whose printer suppresses an encoded register.
		if !strings.Contains(e.Syntax, "{"+o.Name+"}") && !o.Implicit {
			e.Syntax += " " + o.Name + ":{" + o.Name + "}"
		}
	}
	return nil
}

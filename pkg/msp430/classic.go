package msp430

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// completeClassic covers addressing modes omitted by LLVM's compiler-oriented
// instruction selection. The additional opcodes and operand tables come from
// the bundled Ghidra TI430Common.sinc, rather than an invented input dialect.
func completeClassic(base []codec.Encoding) ([]codec.Encoding, error) {
	if !strings.Contains(commonSource, ":PUSH^\".B\" REG_B_AS") || !strings.Contains(commonSource, ":POP^\".B\" DEST_B_AD") {
		return nil, fmt.Errorf("MSP430 source lacks PUSH/POP addressing constructors")
	}
	out := append([]codec.Encoding(nil), base...)
	for _, e := range base {
		if strings.HasPrefix(e.ID, "RRA16m_") || e.ID == "RRA16n" || e.ID == "RRA16p" {
			v := cloneEncoding(e)
			v.ID = "GHIDRA_PUSH_" + e.ID
			v.Value[1] = 0x12
			v.Mnemonic = "push"
			v.Syntax = strings.Replace(v.Syntax, "rra", "push", 1)
			out = append(out, v)
		}
		// The read/modify/write immediate mode is explicitly described by
		// REG_W_AS_DEST (including its undocumented behavior). GNU accepts
		// these physical encodings although LLVM's compiler table omits them.
		if e.ID == "PUSH16i" || strings.HasPrefix(e.ID, "PUSH16c_") {
			for _, op := range []struct {
				name string
				code uint16
			}{{"rrc", 0x1000}, {"rra", 0x1100}, {"swpb", 0x1080}, {"sxt", 0x1180}} {
				for _, byteForm := range []bool{false, true} {
					if byteForm && (op.name == "swpb" || op.name == "sxt") {
						continue
					}
					v := cloneEncoding(e)
					v.ID = "GHIDRA_" + op.name + "_" + e.ID
					v.Mnemonic = op.name
					v.Value[1] = byte(op.code >> 8)
					v.Value[0] = (v.Value[0] & 0x3f) | byte(op.code&0x80)
					if byteForm {
						v.ID += "_byte"
						v.Mnemonic += ".b"
						v.Value[0] |= 0x40
					}
					v.Syntax = strings.Replace(v.Syntax, "push", v.Mnemonic, 1)
					out = append(out, v)
				}
			}
		}
		if strings.HasPrefix(e.ID, "PUSH16c_") {
			v := cloneEncoding(e)
			v.ID = "GHIDRA_CALL_" + e.ID
			v.Value[0] |= 0x80
			v.Mnemonic = "call"
			v.Syntax = strings.Replace(v.Syntax, "push", "call", 1)
			v.FlowControl = "call"
			out = append(out, v)
		}
		if strings.HasPrefix(e.ID, "ADD16mp_") || strings.HasPrefix(e.ID, "ADD8mp_") {
			mov := cloneEncoding(e)
			mov.ID = "GHIDRA_MOV_" + e.ID
			mov.Value[1] = (mov.Value[1] & 15) | 0x40
			mov.Mnemonic = strings.Replace(mov.Mnemonic, "add", "mov", 1)
			mov.Syntax = strings.Replace(mov.Syntax, "add", "mov", 1)
			out = append(out, mov)
			v := cloneEncoding(e)
			v.ID = "GHIDRA_POP_" + e.ID
			v.Mask[1] |= 15
			v.Value[1] = 0x41
			v.Mnemonic = "pop"
			if strings.HasPrefix(e.ID, "ADD8") {
				v.Mnemonic += ".b"
			}
			if i := strings.Index(v.Syntax, ","); i >= 0 {
				v.Syntax = v.Mnemonic + " " + strings.TrimSpace(v.Syntax[i+1:])
			} else {
				return nil, fmt.Errorf("MSP430 malformed MOV source %s", e.ID)
			}
			var operands []codec.Operand
			for _, o := range v.Operands {
				if o.Name != "rs" {
					operands = append(operands, o)
				}
			}
			v.Operands = operands
			out = append(out, v)
		}
	}
	for _, e := range append([]codec.Encoding(nil), out...) {
		if (e.Mnemonic == "push" && e.ID != "PUSH16r") || e.ID == "POP16r" {
			v := cloneEncoding(e)
			v.ID = "GHIDRA_BYTE_" + e.ID
			v.Value[0] |= 0x40
			v.Mnemonic += ".b"
			v.Syntax = strings.Replace(v.Syntax, e.Mnemonic, v.Mnemonic, 1)
			out = append(out, v)
		}
	}
	return out, nil
}

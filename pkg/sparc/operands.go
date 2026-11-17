package sparc

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func adapt(e *codec.Encoding, rec record, get func(string) record, is64 bool) error {
	for i := range e.Operands {
		o := &e.Operands[i]
		cl := get(o.Class)
		if cl["MemberList"] != nil {
			if err := register(o, cl, get, is64); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(o.Name, "simm") || strings.HasPrefix(o.Class, "simm") {
			o.Signed = true
		}
		method := str(cl["EncoderMethod"])
		switch method {
		case "getCallTargetOpValue", "getBranchTargetOpValue", "getBranchPredTargetOpValue", "getBranchOnRegTargetOpValue", "getCompareAndBranchTargetOpValue":
			o.Kind = "displacement"
			o.Scale = 4
			o.Signed = true
			o.Relative = true
			if !is64 {
				o.PCWrapBits = 32
			}
		case "", "getSImm5OpValue", "getSImm13OpValue":
		default:
			return fmt.Errorf("unhandled encoder %s", method)
		}
		switch o.Class {
		case "CCOp":
			o.Names = []string{"n", "e", "le", "l", "leu", "cs", "neg", "vs", "a", "ne", "g", "ge", "gu", "cc", "pos", "vc"}
			id := str(rec["!name"])
			if strings.Contains(id, "FCC") || strings.HasPrefix(id, "FB") {
				o.Names = []string{"n", "ne", "lg", "ul", "l", "ug", "g", "u", "a", "e", "ue", "ge", "uge", "le", "ule", "o"}
			}
			if strings.HasPrefix(id, "CWBCOND") || strings.HasPrefix(id, "CXBCOND") {
				o.Names[0] = ""
				o.Names[8] = ""
			}
			if strings.HasPrefix(id, "CPB") {
				o.Names = []string{"n", "123", "12", "13", "1", "23", "2", "3", "a", "0", "03", "02", "023", "01", "013", "012"}
			}
		case "RegCCOp":
			o.Names = []string{"", "z", "lez", "lz", "", "nz", "gz", "gez"}
		}
		if o.Class == "i32imm" && o.Name == "imm22" {
			o.InputSignedBits = 22
		}
	}
	e.DelaySlots = num(rec["hasDelaySlot"])
	// Alias IDs are anonymous; the target record keeps its original !name and
	// therefore retains register-class, floating condition and delay semantics.
	if strings.HasPrefix(e.Mnemonic, "t") && num(rec["isTrap"]) != 0 {
		e.FlowControl = "trap"
	}
	return nil
}
func register(o *codec.Operand, class record, get func(string) record, is64 bool) error {
	var members func(any) ([]string, error)
	members = func(v any) ([]string, error) {
		if n := def(v); n != "" {
			if cl := get(n); cl["MemberList"] != nil {
				return members(cl["MemberList"])
			}
			return []string{n}, nil
		}
		d, _ := v.(map[string]any)
		a := args(v)
		switch def(d["operator"]) {
		case "add":
			var out []string
			for _, p := range a {
				ns, err := members(p[0])
				if err != nil {
					return nil, err
				}
				out = append(out, ns...)
			}
			return out, nil
		case "sequence":
			if len(a) != 3 {
				return nil, fmt.Errorf("invalid register sequence")
			}
			var out []string
			for i := num(a[1][0]); i <= num(a[2][0]); i++ {
				out = append(out, fmt.Sprintf(strings.ReplaceAll(str(a[0][0]), "%u", "%d"), i))
			}
			return out, nil
		case "sub":
			ns, err := members(a[0][0])
			if err != nil {
				return nil, err
			}
			excluded := map[string]bool{}
			for _, p := range a[1:] {
				xs, err := members(p[0])
				if err != nil {
					return nil, err
				}
				for _, x := range xs {
					excluded[x] = true
				}
			}
			var out []string
			for _, n := range ns {
				if !excluded[n] {
					out = append(out, n)
				}
			}
			return out, nil
		}
		return nil, fmt.Errorf("unsupported register class %s", o.Class)
	}
	ns, err := members(class["MemberList"])
	if err != nil {
		return err
	}
	wideFP := o.Class == "DFPRegs" || o.Class == "QFPRegs" || o.Class == "LowDFPRegs" || o.Class == "LowQFPRegs"
	if wideFP {
		for i := range o.Bits {
			if o.Bits[i].ValueBit == 0 {
				o.Bits[i].ValueBit = 5
			}
		}
	}
	o.Kind = "register"
	o.RegisterPrefix = "%"
	o.Names = make([]string, 1<<uint(o.Width()))
	o.RegisterAliases = map[string]int64{}
	for _, n := range ns {
		r := get(n)
		bits, _ := r["HWEncoding"].([]any)
		enc := 0
		for i, b := range bits {
			enc |= num(b) << uint(i)
		}
		if wideFP {
			enc = ((enc & 1) << 5) | (enc & 30)
		}
		if enc >= len(o.Names) {
			continue
		}
		name := str(r["AsmName"])
		if name == "" {
			continue
		}
		o.Names[enc] = "%" + name
		if alt, ok := r["AltNames"].([]any); ok {
			for _, a := range alt {
				if str(a) != "" {
					o.RegisterAliases["%"+str(a)] = int64(enc)
				}
			}
		}
		if o.Class == "IntRegs" || o.Class == "I64Regs" || o.Class == "IntPair" {
			o.RegisterAliases[fmt.Sprintf("%%r%d", enc)] = int64(enc)
			o.RegisterAliases[fmt.Sprintf("%%%c%d", "goli"[enc/8], enc%8)] = int64(enc)
		}
	}
	o.RegisterPrefix = "%"
	return nil
}
func profiles(is64 bool) map[string][]string {
	base := []string{"HasFMULS", "HasFSMULD", "HasNoFdivSqrtFix"}
	if !is64 {
		base = append(base, "Is32Bit")
	}
	v8 := append(append([]string{}, base...), "HasNoV9")
	v9 := append(append([]string{}, base...), "HasV9")
	if is64 {
		v9 = append(v9, "Is64Bit")
	}
	all := append(append([]string{}, v9...), "HasHardQuad", "HasVIS", "HasVIS2", "HasVIS3", "HasCrypto", "HasUA2005", "HasUA2007", "HasOSA2011", "HasCASA", "HasPWRPSR", "HasUMAC_SMAC")
	if is64 {
		return map[string][]string{"v9": v9, "v9-all": all}
	}
	return map[string][]string{"v8": v8, "v9": v9, "v9-all": all}
}

func conditionVariants(e codec.Encoding) []codec.Encoding {
	var out []codec.Encoding
	for _, o := range e.Operands {
		if o.Class != "CCOp" && o.Class != "RegCCOp" {
			continue
		}
		for n, name := range o.Names {
			if name == "" {
				continue
			}
			v := e
			v.Mask = append([]byte(nil), e.Mask...)
			v.Value = append([]byte(nil), e.Value...)
			v.ID += fmt.Sprintf("/cc%d", n)
			v.Syntax = strings.ReplaceAll(v.Syntax, "{"+o.Name+"}", name)
			v.Mnemonic = strings.Fields(v.Syntax)[0]
			var ops []codec.Operand
			for _, p := range e.Operands {
				if p.Name != o.Name {
					ops = append(ops, p)
				}
			}
			v.Operands = ops
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					p := b.InstructionBit + k
					mask := byte(1) << uint(p%8)
					v.Mask[p/8] |= mask
					v.Value[p/8] &= ^mask
					if n>>uint(b.ValueBit+k)&1 != 0 {
						v.Value[p/8] |= mask
					}
				}
			}
			out = append(out, v)
		}
	}
	return out
}

// V8 has 32 physical FP registers. V9 doubles that bank for double/quad
// instructions without changing their opcodes. Separate predicate-bearing
// forms let profile-aware assembly and decode enforce the bank distinction.
func registerBankVariants(e codec.Encoding) (codec.Encoding, codec.Encoding, bool) {
	low, full := e, e
	low.Operands = append([]codec.Operand(nil), e.Operands...)
	needed := false
	for i, o := range e.Operands {
		if o.Kind != "register" || len(o.Names) <= 32 {
			continue
		}
		upper := false
		for n := 32; n < len(o.Names); n++ {
			if strings.HasPrefix(o.Names[n], "%f") {
				upper = true
			}
		}
		if !upper {
			continue
		}
		needed = true
		low.Operands[i].Names = append([]string(nil), o.Names...)
		for n := 32; n < len(o.Names); n++ {
			low.Operands[i].Names[n] = ""
		}
	}
	full.ID += "/v9-registers"
	full.Features = append(append([]string(nil), e.Features...), "HasV9")
	return low, full, needed
}

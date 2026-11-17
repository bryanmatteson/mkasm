package riscv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func hasOperand(e codec.Encoding, name string) bool {
	for _, o := range e.Operands {
		if o.Name == name {
			return true
		}
	}
	return false
}
func fixOperand(e codec.Encoding, name string, value int64) codec.Encoding {
	e.Mask = append([]byte(nil), e.Mask...)
	e.Value = append([]byte(nil), e.Value...)
	var ops []codec.Operand
	for _, o := range e.Operands {
		if o.Name != name {
			ops = append(ops, o)
			continue
		}
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				p := b.InstructionBit + k
				mask := byte(1) << uint(p%8)
				e.Mask[p/8] |= mask
				e.Value[p/8] &= ^mask
				if uint64(value)>>uint(b.ValueBit+k)&1 != 0 {
					e.Value[p/8] |= mask
				}
			}
		}
	}
	e.Operands = ops
	return e
}

// Assembly variants bind implicit control fields (atomic ordering, vector masks,
// vector segment counts, dynamic rounding) while retaining the source encoding.
func assemblyVariants(e codec.Encoding) []codec.Encoding {
	var out []codec.Encoding
	if hasOperand(e, "aq") && hasOperand(e, "rl") {
		for n := 0; n < 4; n++ {
			v := fixOperand(fixOperand(e, "aq", int64(n>>1)), "rl", int64(n&1))
			v.ID = e.ID + fmt.Sprintf("/order%d", n)
			suffix := []string{"", ".rl", ".aq", ".aqrl"}[n]
			v.Mnemonic += suffix
			v.Syntax = v.Mnemonic + " {rd}, "
			if hasOperand(v, "rs2") {
				v.Syntax += "{rs2}, "
			}
			v.Syntax += "({rs1})"
			out = append(out, v)
		}
	}
	if hasOperand(e, "rm") {
		v := fixOperand(e, "rm", 7)
		v.ID = e.ID + "/dyn"
		v.Syntax = strings.TrimSuffix(e.Syntax, ", {rm}")
		out = append(out, v)
	}
	if e.Mnemonic == "c.nop" {
		v := fixOperand(e, "imm", 0)
		v.Constraints = nil
		v.ID = e.ID + "/zero"
		v.Syntax = "c.nop"
		out = append(out, v)
	}
	if e.Mnemonic == "fence" && hasOperand(e, "fm") {
		v := fixOperand(fixOperand(fixOperand(e, "fm", 0), "rd", 0), "rs1", 0)
		v.ID = e.ID + "/standard"
		v.Syntax = "fence {pred}, {succ}"
		out = append(out, v)
		v = fixOperand(fixOperand(v, "pred", 15), "succ", 15)
		v.ID = e.ID + "/default"
		v.Syntax = "fence"
		out = append(out, v)
	}
	if e.Mnemonic == "fence.tso" {
		v := fixOperand(fixOperand(e, "rd", 0), "rs1", 0)
		v.ID = e.ID + "/standard"
		v.Syntax = "fence.tso"
		out = append(out, v)
	}
	if strings.HasPrefix(e.Mnemonic, "v") {
		vs := []codec.Encoding{e}
		expanded := false
		if hasOperand(e, "nf") {
			vs = nil
			for n := 0; n < 8; n++ {
				v := fixOperand(e, "nf", int64(n))
				v.ID += fmt.Sprintf("/nf%d", n)
				if n > 0 {
					v.Mnemonic = segmentMnemonic(v.Mnemonic, n+1)
				}
				vs = append(vs, v)
			}
			expanded = true
		}
		if hasOperand(e, "vm") {
			var masked []codec.Encoding
			for _, v := range vs {
				for n := 0; n < 2; n++ {
					m := fixOperand(v, "vm", int64(n))
					m.ID += fmt.Sprintf("/vm%d", n)
					m.Syntax = vectorSyntax(m)
					if n == 0 {
						m.Syntax += ", v0.t"
					}
					masked = append(masked, m)
				}
			}
			vs = masked
			expanded = true
		} else {
			for i := range vs {
				vs[i].Syntax = vectorSyntax(vs[i])
				vs[i].ID += "/syntax"
			}
		}
		if expanded || len(vs) > 0 {
			out = append(out, vs...)
		}
	}
	return out
}
func segmentMnemonic(m string, n int) string {
	for _, r := range []struct{ prefix, replacement string }{{"vluxei", "vluxseg"}, {"vsoxei", "vsoxseg"}, {"vloxei", "vloxseg"}, {"vsuxei", "vsuxseg"}, {"vlse", "vlsseg"}, {"vsse", "vssseg"}, {"vle", "vlseg"}, {"vse", "vsseg"}} {
		if strings.HasPrefix(m, r.prefix) {
			rest := strings.TrimPrefix(m, r.prefix)
			suffix := "e"
			if strings.Contains(r.prefix, "xei") {
				suffix = "ei"
			}
			return fmt.Sprintf("%s%d%s%s", r.replacement, n, suffix, rest)
		}
	}
	return m
}
func vectorSyntax(e codec.Encoding) string {
	m := e.Mnemonic
	if m == "vsetvli" {
		return m + " {rd}, {rs1}, {zimm11}"
	}
	if m == "vsetivli" {
		return m + " {rd}, {zimm5}, {zimm10}"
	}
	if m == "vsetvl" {
		return m + " {rd}, {rs1}, {rs2}"
	}
	// Vector memory instructions have an integer address base, and an optional
	// integer stride or vector index after the parenthesized address.
	if hasOperand(e, "rs1") && (hasOperand(e, "vd") || hasOperand(e, "vs3")) && len(e.Value) >= 4 && (e.Value[0]&0x7f == 0x07 || e.Value[0]&0x7f == 0x27) {
		dest := "vd"
		if hasOperand(e, "vs3") {
			dest = "vs3"
		}
		s := m + " {" + dest + "}, ({rs1})"
		if hasOperand(e, "rs2") {
			s += ", {rs2}"
		}
		if hasOperand(e, "vs2") {
			s += ", {vs2}"
		}
		return s
	}
	var order []string
	for _, n := range []string{"vd", "rd", "vs2", "vs1", "rs1", "rs2", "simm5", "zimm5"} {
		if hasOperand(e, n) {
			order = append(order, "{"+n+"}")
		}
	}
	for _, o := range e.Operands {
		found := false
		for _, s := range order {
			if s == "{"+o.Name+"}" {
				found = true
			}
		}
		if !found {
			order = append(order, "{"+o.Name+"}")
		}
	}
	if len(order) == 0 {
		return m
	}
	suffix := ""
	if strings.HasSuffix(m, ".vvm") || strings.HasSuffix(m, ".vxm") || strings.HasSuffix(m, ".vim") || strings.HasSuffix(m, ".vfm") {
		suffix = ", v0"
	}
	return m + " " + strings.Join(order, ", ") + suffix
}

func stackVariants(e codec.Encoding, architecture string) []codec.Encoding {
	if !hasOperand(e, "c_rlist") || !hasOperand(e, "c_spimm") {
		return nil
	}
	var out []codec.Encoding
	xlenBytes := 4
	if architecture == "riscv64" {
		xlenBytes = 8
	}
	for r := 4; r <= 15; r++ {
		saved := r - 3
		if r == 15 {
			saved = 13
		}
		base := ((saved*xlenBytes + 15) / 16) * 16
		list := "{ra}"
		if r == 5 {
			list = "{ra,s0}"
		} else if r > 5 {
			last := r - 5
			if r == 15 {
				last = 11
			}
			list = fmt.Sprintf("{ra,s0-s%d}", last)
		}
		v := e
		v.Operands = append([]codec.Operand(nil), e.Operands...)
		v.AssemblyOnly = false
		v.ID += fmt.Sprintf("/rlist%d", r)
		for i := range v.Operands {
			switch v.Operands[i].Name {
			case "c_rlist":
				v.Operands[i].Names = make([]string, 16)
				v.Operands[i].Names[r] = list
			case "c_spimm":
				v.Operands[i].Scale = 16
				v.Operands[i].Bias = int64(base)
				if e.Mnemonic == "cm.push" {
					v.Operands[i].Xor = 3
					v.Operands[i].Bias = int64(-base - 48)
				}
			}
		}
		v.Syntax = e.Mnemonic + " {c_rlist}, {c_spimm}"
		out = append(out, v)
	}
	return out
}
func addFeatureProfiles(c *codec.Catalog) {
	c.FeatureSets = map[string][]string{}
	common := strings.TrimPrefix(c.Architecture, "riscv")
	for _, profile := range []string{"i", "im", "imac", "gc", "gcv"} {
		allowed := map[string]bool{}
		letters := profile
		if strings.Contains(profile, "g") {
			letters = strings.ReplaceAll(letters, "g", "imafd")
			allowed["zicsr"] = true
			allowed["zifencei"] = true
		}
		for _, r := range letters {
			allowed[string(r)] = true
		}
		set := map[string]bool{}
		for _, e := range c.Encodings {
			if len(e.Features) != 1 {
				continue
			}
			f := e.Features[0]
			parts := strings.Split(f, "_")
			ok := len(parts) > 1
			for _, p := range parts[1:] {
				if !allowed[p] {
					ok = false
				}
			}
			if ok {
				set[f] = true
			}
		}
		var features []string
		for f := range set {
			features = append(features, f)
		}
		sort.Strings(features)
		c.FeatureSets["rv"+common+profile] = features
	}
}

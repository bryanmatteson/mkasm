package xtensa

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// registerFeature is LLVM's Xtensa::checkRegister access contract. Processor
// profiles expand timer/interrupt levels so its alternatives become simple
// feature predicates in the portable instruction catalog.
func registerFeature(name, op string) (string, bool) {
	read := op == "rsr" || op == "rur"
	write := op == "wsr" || op == "wur"
	switch name {
	case "configid0":
		return "", op != "xsr"
	case "configid1":
		return "", read
	case "interrupt":
		return "HasInterrupt", read
	case "intset", "intclear":
		return "HasInterrupt", write
	case "prid":
		return "HasPRID", read
	case "debugcause":
		return "HasDebug", read
	case "ccount", "ccompare0":
		return "HasTimers1", true
	case "ccompare1":
		return "HasTimers2", true
	case "ccompare2":
		return "HasTimers3", true
	case "br":
		return "HasBoolean", true
	case "cpenable":
		return "HasCoprocessor", true
	case "depc", "epc1", "exccause", "excsave1", "excvaddr":
		return "HasException", true
	case "intenable":
		return "HasInterrupt", true
	case "icount", "icountlevel", "ibreakenable", "ddr", "ibreaka0", "ibreaka1", "dbreaka0", "dbreaka1", "dbreakc0", "dbreakc1":
		return "HasDebug", true
	case "lbeg", "lend", "lcount":
		return "HasLoop", true
	case "litbase":
		return "HasExtendedL32R", true
	case "memctl":
		return "HasDataCache", true
	case "acclo", "acchi", "m0", "m1", "m2", "m3":
		return "HasMAC16", true
	case "misc0", "misc1", "misc2", "misc3":
		return "HasMiscSR", true
	case "threadptr":
		return "HasTHREADPTR", true
	case "vecbase":
		return "HasRelocatableVector", true
	case "fcr", "fsr":
		return "HasSingleFloat", true
	case "f64r_lo", "f64r_hi", "f64s":
		return "HasDFPAccel", true
	case "windowbase", "windowstart":
		return "HasWindowed", true
	case "atomctl", "scompare1":
		return "HasS32C1I", true
	}
	for _, prefix := range []string{"epc", "eps", "excsave"} {
		if strings.HasPrefix(name, prefix) {
			level := strings.TrimPrefix(name, prefix)
			if level == "2" {
				return "HasHighPriInterrupts", true
			}
			if level >= "3" && level <= "7" {
				return "HasHighPriInterruptsLevel" + level, true
			}
		}
	}
	return "", true
}
func partitionRegisters(c *codec.Catalog) {
	var forms []codec.Encoding
	for _, e := range c.Encodings {
		oi := -1
		for n, o := range e.Operands {
			if o.Class == "SR" || o.Class == "UR" {
				oi = n
				break
			}
		}
		if oi < 0 {
			forms = append(forms, e)
			continue
		}
		o := e.Operands[oi]
		if o.Class == "SR" {
			if e.Mnemonic == "rsr" {
				o.Names[226] = "interrupt"
			} else if e.Mnemonic == "wsr" {
				o.Names[226] = "intset"
			} else {
				o.Names[226] = ""
			}
		}
		groups := map[string][]string{}
		for n, name := range o.Names {
			if name == "" {
				continue
			}
			feature, valid := registerFeature(name, e.Mnemonic)
			if !valid {
				continue
			}
			if groups[feature] == nil {
				groups[feature] = make([]string, len(o.Names))
			}
			groups[feature][n] = name
		}
		var keys []string
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for n, key := range keys {
			v := e
			v.Operands = append([]codec.Operand(nil), e.Operands...)
			v.Operands[oi] = o
			v.Operands[oi].Names = groups[key]
			v.Operands[oi].RegisterAliases = map[string]int64{}
			for a, index := range o.RegisterAliases {
				if index >= 0 && int(index) < len(groups[key]) && groups[key][index] != "" {
					v.Operands[oi].RegisterAliases[a] = index
				}
			}
			v.Features = append([]string{}, e.Features...)
			if key != "" {
				v.Features = append(v.Features, key)
			}
			if n > 0 {
				v.ID = fmt.Sprintf("%s_%s", e.ID, key)
			}
			forms = append(forms, v)
		}
	}
	c.Encodings = forms
}
func expandProfile(features []string) []string {
	set := map[string]bool{}
	for _, f := range features {
		if f != "" {
			set[f] = true
		}
	}
	for i := 2; i <= 3; i++ {
		if set[fmt.Sprintf("HasTimers%d", i)] {
			for j := 1; j < i; j++ {
				set[fmt.Sprintf("HasTimers%d", j)] = true
			}
		}
	}
	for i := 3; i <= 7; i++ {
		if set[fmt.Sprintf("HasHighPriInterruptsLevel%d", i)] {
			set["HasHighPriInterrupts"] = true
			for j := 3; j < i; j++ {
				set[fmt.Sprintf("HasHighPriInterruptsLevel%d", j)] = true
			}
		}
	}
	out := []string{}
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

package x86

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func rustEffectsData(c *Catalog) struct{ Types, FlagRules, AddressRules string } {
	var b, addresses strings.Builder
	for i, e := range c.Encodings {
		for j, o := range e.Operands {
			if len(o.AddressRegisters) > 0 {
				fmt.Fprintf(&addresses, "(%d,%d)=>&[", i, j)
				for _, r := range o.AddressRegisters {
					fmt.Fprintf(&addresses, "(%s,%s,%s,%t,%t),", rustString(r.Symbol), rustString(r.Value), rustString(r.EncodedIn), r.Read, r.Write)
				}
				addresses.WriteString("],\n")
			}
		}
		if len(e.IFlags) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%d=>&[", i)
		var names []string
		for n := range e.IFlags {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			read, conditional := false, false
			action := "Unknown"
			switch e.IFlags[n] {
			case "R":
				read = true
				action = "Preserve"
			case "W":
				action = "Write"
			case "X":
				read = true
				action = "Write"
			case "U":
				action = "Undefined"
			case "Z":
				action = "Clear"
			case "S":
				action = "Set"
			case "CW":
				conditional = true
				action = "Write"
			case "RCW":
				read = true
				conditional = true
				action = "Write"
			}
			name := strings.ToUpper(strings.TrimPrefix(n, "_"))
			fmt.Fprintf(&b, "FlagEffect{name:%s,read:%t,action:FlagAction::%s,conditional:%t},", rustString(name), read, action, conditional)
		}
		b.WriteString("],\n")
	}
	return struct{ Types, FlagRules, AddressRules string }{codec.RustEffectTypes(), b.String(), addresses.String()}
}

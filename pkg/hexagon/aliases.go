package hexagon

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// LLVM InstAlias DAGs bind each machine operand to a named assembler operand,
// an immediate, or a physical register. Keep the exact underlying bit layout.
func (c *Catalog) importAliases(records map[string]any, instances map[string]any) {
	ids, _ := instances["InstAlias"].([]any)
	for _, v := range ids {
		id, _ := v.(string)
		r, _ := records[id].(map[string]any)
		dag, _ := r["ResultInst"].(map[string]any)
		target := def(dag["operator"])
		base, err := c.entry(target)
		reject := func(reason string) { c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: reason}) }
		if err != nil {
			reject("alias target unavailable: " + target)
			continue
		}
		tr, _ := records[target].(map[string]any)
		ops := operands(tr)
		args, _ := dag["args"].([]any)
		if len(args) != len(ops) {
			omitted := map[string]bool{}
			constraint, _ := tr["Constraints"].(string)
			for _, m := range tiedRE.FindAllStringSubmatch(constraint, -1) {
				omitted[m[2]] = true
			}
			var untied []namedOperand
			for _, op := range ops {
				if !omitted[op.name] {
					untied = append(untied, op)
				}
			}
			ops = untied
		}
		if len(args) != len(ops) {
			reject("alias result operand count differs from target")
			continue
		}
		e := *base
		e.ID = id
		e.Mask = append([]byte{}, base.Mask...)
		e.Value = append([]byte{}, base.Value...)
		e.Operands = nil
		e.Constraints = nil
		e.AssemblyOnly = number(r["EmitPriority"]) == 0
		if predicates, ok := r["Predicates"].([]any); ok {
			e.Features = append([]string{}, e.Features...)
			for _, p := range predicates {
				n := def(p)
				found := false
				for _, old := range e.Features {
					found = found || old == n
				}
				if !found {
					e.Features = append(e.Features, n)
				}
			}
		}
		rename := map[string]string{}
		fixed := map[string]int64{}
		classes := map[string]string{}
		for n, a := range args {
			p, _ := a.([]any)
			if len(p) != 2 {
				err = fmt.Errorf("malformed result argument")
				break
			}
			name, _ := p[1].(string)
			if name != "" {
				rename[ops[n].name] = name
				classes[name] = def(p[0])
				continue
			}
			if x, ok := p[0].(float64); ok {
				fixed[ops[n].name] = int64(x)
			} else {
				reg, _ := records[def(p[0])].(map[string]any)
				if reg == nil {
					err = fmt.Errorf("unknown fixed register")
					break
				}
				fixed[ops[n].name] = int64(number(reg["HWEncoding"]))
			}
		}
		if err != nil {
			reject(err.Error())
			continue
		}
		for _, o := range base.Operands {
			if value, ok := fixed[o.Name]; ok {
				for _, b := range o.Bits {
					for k := 0; k < b.Width; k++ {
						p := b.InstructionBit + k
						e.Mask[p/8] |= 1 << uint(p%8)
						e.Value[p/8] &= ^(1 << uint(p%8))
						e.Value[p/8] |= byte((uint64(value)>>uint(b.ValueBit+k))&1) << uint(p%8)
					}
				}
				continue
			}
			name, ok := rename[o.Name]
			if !ok {
				err = fmt.Errorf("unbound target operand %s", o.Name)
				break
			}
			o.Name = name
			if cls := classes[name]; cls != "" {
				o.Class = cls
			}
			found := false
			for n := range e.Operands {
				if e.Operands[n].Name == name {
					e.Operands[n].Bits = append(e.Operands[n].Bits, o.Bits...)
					found = true
					break
				}
			}
			if !found {
				e.Operands = append(e.Operands, o)
			}
		}
		if err != nil {
			reject(err.Error())
			continue
		}
		asm, _ := r["AsmString"].(string)
		e.Syntax = asmOperandRE.ReplaceAllString(asm, "{$1$2}")
		e.Mnemonic = strings.Fields(e.Syntax)[0]
		m := c.Metadata[target]
		if m.ExtendOperand != "" {
			if n := rename[m.ExtendOperand]; n != "" {
				m.ExtendOperand = n
			} else {
				m.Extendable = false
				m.MustExtend = false
				m.ExtendOperand = ""
			}
		}
		if m.NewValueUse != "" {
			m.NewValueUse = rename[m.NewValueUse]
		}
		m.Producers = append([]string{}, m.Producers...)
		for n, p := range m.Producers {
			if _, ok := fixed[p]; ok {
				e.AssemblyOnly = true
			}
			m.Producers[n] = rename[p]
		}
		c.Metadata[id] = m
		for n := range e.Operands {
			if err = mapOperand(records, &e.Operands[n], m.NewValueUse == e.Operands[n].Name); err != nil {
				break
			}
		}
		immediateDomains(&e)
		if err == nil {
			err = (&codec.Catalog{Architecture: "hexagon", Encodings: []codec.Encoding{e}}).Validate()
		}
		if err != nil {
			reject("alias: " + err.Error())
			delete(c.Metadata, id)
			continue
		}
		c.Words.Encodings = append(c.Words.Encodings, e)
	}
}

func predicateValue(records map[string]any, v any, active map[string]bool) bool {
	node, _ := v.(map[string]any)
	if n := def(node); n != "" {
		return active[n]
	}
	args, _ := node["args"].([]any)
	op := def(node["operator"])
	result := op != "any_of"
	for _, a := range args {
		p, _ := a.([]any)
		if len(p) != 2 {
			return false
		}
		yes := predicateValue(records, p[0], active)
		if op == "any_of" {
			result = result || yes
		} else {
			result = result && yes
		}
	}
	if op == "not" {
		return !result
	}
	return result
}
func (c *Catalog) importProfiles(records map[string]any, instances map[string]any) {
	c.FeatureSets = map[string][]string{}
	ids, _ := instances["Processor"].([]any)
	predicates, _ := instances["Predicate"].([]any)
	for _, v := range ids {
		r, _ := records[v.(string)].(map[string]any)
		name, _ := r["Name"].(string)
		active := map[string]bool{}
		var add func(string)
		add = func(n string) {
			if active[n] {
				return
			}
			active[n] = true
			f, _ := records[n].(map[string]any)
			implies, _ := f["Implies"].([]any)
			for _, i := range implies {
				add(def(i))
			}
		}
		fs, _ := r["Features"].([]any)
		for _, f := range fs {
			add(def(f))
		}
		save := func(profile string) {
			var selected []string
			for _, p := range predicates {
				n, _ := p.(string)
				pr, _ := records[n].(map[string]any)
				if dag, ok := pr["AssemblerCondDag"]; ok && predicateValue(records, dag, active) {
					selected = append(selected, n)
				}
			}
			c.FeatureSets[profile] = selected
		}
		save(name)
		version := 0
		for n := range active {
			if strings.HasPrefix(n, "ArchV") {
				v, _ := strconv.Atoi(strings.TrimPrefix(n, "ArchV"))
				if v > version {
					version = v
				}
			}
		}
		hvx := fmt.Sprintf("ExtensionHVXV%d", version)
		if _, ok := records[hvx]; ok {
			add(hvx)
			for _, length := range []string{"64B", "128B"} {
				delete(active, "ExtensionHVX64B")
				delete(active, "ExtensionHVX128B")
				add("ExtensionHVX" + length)
				profile := name + "+hvx-length" + strings.ToLower(length)
				save(profile)
				add("ExtensionHVXIEEEFP")
				save(profile + "+hvx-ieee-fp")
				delete(active, "ExtensionHVXIEEEFP")
				add("ExtensionHVXQFloat")
				save(profile + "+hvx-qfloat")
				delete(active, "ExtensionHVXQFloat")
			}
		}

	}
	c.Words.FeatureSets = c.FeatureSets
	c.Subinstructions.FeatureSets = c.FeatureSets
}

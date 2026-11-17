// Package msp430 imports MSP430 machine descriptions and reconstructs their
// addressing modes, extension words and constant generator encodings.
package msp430

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]any

func number(v any) int         { n, _ := v.(float64); return int(n) }
func stringValue(v any) string { s, _ := v.(string); return s }
func definition(v any) string  { m, _ := v.(map[string]any); return stringValue(m["def"]) }
func dagArgs(v any) [][]any {
	m, _ := v.(map[string]any)
	a, _ := m["args"].([]any)
	var out [][]any
	for _, v := range a {
		if p, ok := v.([]any); ok && len(p) == 2 {
			out = append(out, p)
		}
	}
	return out
}

var sourceHole = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)
var tiedOperands = regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)

func substitute(s, name, value string) string {
	return sourceHole.ReplaceAllStringFunc(s, func(v string) string {
		m := sourceHole.FindStringSubmatch(v)
		n := m[1]
		if n == "" {
			n = m[2]
		}
		if n == name {
			return value
		}
		return v
	})
}

// Parse accepts resolved LLVM --dump-json descriptions. For msp430x the classic
// input is augmented from the bundled, pinned Ghidra MSP430X specification.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	if architecture != "msp430" && architecture != "msp430x" {
		return nil, fmt.Errorf("unsupported MSP430 architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("MSP430 TableGen: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("MSP430 TableGen: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("MSP430 TableGen missing !instanceof: %w", err)
	}
	records := map[string]record{}
	get := func(id string) record {
		if v, ok := records[id]; ok {
			return v
		}
		var v record
		_ = json.Unmarshal(raw[id], &v)
		records[id] = v
		return v
	}
	var ids []string
	for _, id := range instances["Instruction"] {
		rec := get(id)
		syntax := stringValue(rec["AsmString"])
		if rec["Namespace"] != "MSP430" || number(rec["isPseudo"]) != 0 || number(rec["isAsmParserOnly"]) != 0 || syntax == "" || strings.HasPrefix(syntax, "#") {
			continue
		}
		// These braces group assembly dialects; MSP430 has one dialect.
		syntax = strings.ReplaceAll(strings.ReplaceAll(syntax, "{", ""), "}", "")
		encoded := map[string]bool{}
		inst, _ := rec["Inst"].([]any)
		for _, b := range inst {
			if m, ok := b.(map[string]any); ok {
				encoded[stringValue(m["var"])] = true
			}
		}
		for _, m := range tiedOperands.FindAllStringSubmatch(stringValue(rec["Constraints"]), -1) {
			a, b := m[1], m[2]
			if encoded[a] && !encoded[b] {
				a, b = b, a
			}
			if encoded[b] {
				syntax = substitute(syntax, a, "$"+b)
				if encoded[a] {
					for _, bit := range inst {
						if ref, ok := bit.(map[string]any); ok && stringValue(ref["var"]) == a {
							ref["var"] = b
						}
					}
				}
			}
		}
		rec["AsmString"] = syntax
		ids = append(ids, id)
	}
	machine := map[string]bool{}
	for _, id := range ids {
		machine[id] = true
	}
	for _, id := range instances["InstAlias"] {
		alias := get(id)
		result, _ := alias["ResultInst"].(map[string]any)
		target := definition(result["operator"])
		if !machine[target] {
			continue
		}
		clone, err := bindAlias(alias, records[target], get)
		if err != nil {
			return nil, fmt.Errorf("MSP430 alias %s: %w", id, err)
		}
		records[id] = clone
		ids = append(ids, id)
	}
	var expanded []string
	cg := []struct{ value, encoded int }{{0, 3}, {1, 0x13}, {2, 0x23}, {4, 0x22}, {8, 0x32}, {-1, 0x33}}
	for _, id := range ids {
		rec := records[id]
		name := ""
		for _, key := range []string{"OutOperandList", "InOperandList"} {
			for _, a := range dagArgs(rec[key]) {
				if strings.HasPrefix(definition(a[0]), "cg") {
					name = stringValue(a[1])
				}
			}
		}
		if name == "" {
			expanded = append(expanded, id)
			continue
		}
		for _, v := range cg {
			clone := copyRecord(rec)
			inst, _ := clone["Inst"].([]any)
			for i, b := range inst {
				if ref, ok := b.(map[string]any); ok && stringValue(ref["var"]) == name {
					inst[i] = (v.encoded >> number(ref["index"])) & 1
				}
			}
			clone["AsmString"] = substitute(stringValue(clone["AsmString"]), name, "#"+strconv.Itoa(v.value))
			key := id + "_cg" + strconv.Itoa(v.value)
			records[key] = clone
			expanded = append(expanded, key)
		}
	}
	selected := map[string]any{"!instanceof": map[string]any{"Instruction": expanded}}
	for _, id := range expanded {
		selected[id] = records[id]
	}
	b, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	c, err := codec.ParseTableGen(bytes.NewReader(b), codec.TableGenOptions{Architecture: architecture, LittleEndian: true})
	if err != nil {
		return nil, err
	}
	c.Source += "; LLVM data (Apache-2.0 WITH LLVM-exception); Ghidra TI_MSP430 68270ac6d9fb523574fc36470b4ea2e0aee210eb (Apache-2.0)"
	var out []codec.Encoding
	for _, e := range c.Encodings {
		variants, err := addressing(e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID, err)
		}
		out = append(out, variants...)
	}
	out, err = completeClassic(out)
	if err != nil {
		return nil, err
	}
	// Fixed condition encodings keep the condition suffix independent from
	// the following target operand in text assembly.
	var branches []codec.Encoding
	for _, e := range out {
		index := -1
		for i, o := range e.Operands {
			if o.Class == "cc" {
				index = i
			}
		}
		if index < 0 {
			branches = append(branches, e)
			continue
		}
		o := e.Operands[index]
		for n, name := range o.Names {
			if name == "" {
				continue
			}
			v := cloneEncoding(e)
			v.ID += "_" + name
			v.Syntax = strings.ReplaceAll(v.Syntax, "{"+o.Name+"}", name)
			v.Mnemonic = strings.ReplaceAll(v.Mnemonic, "{"+o.Name+"}", name)
			v.FlowControl = "conditional_branch"
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					p := b.InstructionBit + k
					v.Mask[p/8] |= 1 << uint(p%8)
					if (n>>uint(b.ValueBit+k))&1 != 0 {
						v.Value[p/8] |= 1 << uint(p%8)
					}
				}
			}
			v.Operands = append(v.Operands[:index], v.Operands[index+1:]...)
			branches = append(branches, v)
			aliases := map[string]string{"ne": "nz", "eq": "z", "lo": "nc", "hs": "c"}
			if alternative := aliases[name]; alternative != "" {
				a := cloneEncoding(v)
				a.ID += "_alias"
				a.Syntax = strings.Replace(a.Syntax, "j"+name, "j"+alternative, 1)
				a.Mnemonic = "j" + alternative
				a.AssemblyOnly = true
				branches = append(branches, a)
			}
		}
	}
	out = branches
	c.Encodings = out
	// .w is the explicit spelling of the default word operation.
	for _, e := range out {
		if !strings.Contains(e.Mnemonic, ".") && e.Mnemonic != "jmp" && !strings.HasPrefix(e.Mnemonic, "j") && e.Mnemonic != "ret" && e.Mnemonic != "reti" {
			alias := cloneEncoding(e)
			alias.ID += "_word"
			alias.Syntax = strings.Replace(alias.Syntax, alias.Mnemonic, alias.Mnemonic+".w", 1)
			alias.Mnemonic += ".w"
			alias.AssemblyOnly = true
			c.Encodings = append(c.Encodings, alias)
		}
	}
	if architecture == "msp430x" {
		for i := range c.Encodings {
			for j := range c.Encodings[i].Operands {
				o := &c.Encodings[i].Operands[j]
				if o.Relative {
					o.PCWrapBits = 20
					if o.Class != "jmptarget" {
						o.PCLowWrapBits = 16
					}
				}
			}
		}
		if err := extend(c); err != nil {
			return nil, err
		}
		// Classic emulated memory shifts can cross CPUX's lower-memory PC
		// boundary between their two displacement words. Decode these as
		// canonical ADD/ADDC; assembly admits the alias only when both raw
		// physical displacements resolve to the same effective address.
		for i := range c.Encodings {
			e := &c.Encodings[i]
			if len(e.Features) != 0 {
				continue
			}
			for j := range e.Operands {
				o := &e.Operands[j]
				if o.Implicit && o.BiasOperand != "" {
					o.PCBias = int64(o.Bits[0].InstructionBit / 16 * 2)
					o.PCWrapBits, o.PCLowWrapBits = 20, 16
					e.Constraints = append(e.Constraints, codec.Constraint{Kind: "encoded_targets_eq", Left: o.BiasOperand, Right: o.Name})
					e.AssemblyOnly = true
				}
			}
		}
	}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.FlowControl != "call" && e.FlowControl != "branch" {
			continue
		}
		operandText := strings.TrimSpace(strings.TrimPrefix(e.Syntax, e.Mnemonic))
		if strings.HasPrefix(operandText, "#") {
			// An immediate source is the destination itself. Memory and
			// register sources instead supply the destination indirectly.
			if strings.TrimSuffix(e.Mnemonic, ".w") == "call" {
				e.TargetMask = 0xfffe
			}
			if len(e.Operands) == 0 {
				value, err := strconv.ParseInt(strings.TrimPrefix(operandText, "#"), 0, 64)
				if err != nil {
					return nil, fmt.Errorf("%s: invalid fixed call target: %w", e.ID, err)
				}
				target := uint64(value)
				if e.TargetMask != 0 {
					target &= e.TargetMask
				}
				e.FixedTarget = &target
			}
			for j := range e.Operands {
				o := &e.Operands[j]
				if o.Kind == "immediate" {
					o.Kind, o.Signed = "address", false
				}
			}
		} else if !strings.HasPrefix(strings.ToLower(e.Mnemonic), "j") {
			e.FlowControl = "indirect_" + e.FlowControl
		}
	}
	c.FeatureSets = map[string][]string{"msp430": {}, "msp430x": {"msp430x"}}
	sort.SliceStable(c.Encodings, func(i, j int) bool { return c.Encodings[i].ID < c.Encodings[j].ID })
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
func copyRecord(r record) record {
	b, _ := json.Marshal(r)
	var clone record
	_ = json.Unmarshal(b, &clone)
	return clone
}
func cloneEncoding(e codec.Encoding) codec.Encoding {
	b, _ := json.Marshal(e)
	var clone codec.Encoding
	_ = json.Unmarshal(b, &clone)
	return clone
}
func registers(o *codec.Operand, source bool) {
	o.Kind = "register"
	o.RegisterPrefix = "r"
	o.Names = make([]string, 16)
	o.RegisterAliases = map[string]int64{"pc": 0, "sp": 1, "sr": 2, "cg": 3}
	for i := range o.Names {
		o.Names[i] = "r" + strconv.Itoa(i)
	}
	if source {
		o.Names[3] = ""
	}
}

func addressing(e codec.Encoding) ([]codec.Encoding, error) {
	var operands []codec.Operand
	var memories []string
	for _, o := range e.Operands {
		switch o.Class {
		case "GR8", "GR16":
			registers(&o, o.Name == "rs")
		case "indreg", "postreg":
			registers(&o, true)
			if o.Class == "postreg" {
				o.Names[0] = ""
			}
			o.Names[2] = ""
			replacement := "@{" + o.Name + "}"
			if o.Class == "postreg" {
				replacement += "+"
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", replacement)
		case "memsrc", "memdst":
			base := codec.Operand{Name: o.Name + "_base", Class: o.Class + "_base"}
			registers(&base, false)
			// Alias operands may drive both hardware register fields.
			source := e.Value[1]>>4 == 1
			for _, b := range o.Bits {
				if b.InstructionBit >= 8 && b.InstructionBit < 12 {
					source = true
				}
			}
			if source {
				base.Class = "memsrc_base"
			}
			off := codec.Operand{Name: o.Name + "_offset", Class: o.Class + "_offset", Kind: "displacement", Signed: true, InputSignedBits: 16}
			for _, b := range o.Bits {
				if b.ValueBit < 4 {
					base.Bits = append(base.Bits, b)
				} else {
					b.ValueBit -= 4
					off.Bits = append(off.Bits, b)
				}
			}
			if len(base.Bits) == 0 || len(off.Bits) == 0 {
				return nil, fmt.Errorf("incomplete memory operand %s", o.Name)
			}
			operands = append(operands, base, off)
			memories = append(memories, o.Name)
			continue
		case "i8imm", "i16imm":
			o.Signed = true
			o.InputSignedBits = 16
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", "#{"+o.Name+"}")
		case "jmptarget":
			o.Kind = "displacement"
			o.Signed = true
			o.Scale = 2
			o.Relative = true
			o.PCBias = 2
			o.PCWrapBits = 16
		case "cc":
			o.Names = []string{"ne", "eq", "lo", "hs", "n", "ge", "l", ""}
		default:
			return nil, fmt.Errorf("unrecognized operand class %s", o.Class)
		}
		operands = append(operands, o)
	}
	e.Operands = operands
	variants := []codec.Encoding{e}
	for _, name := range memories {
		var next []codec.Encoding
		for _, v := range variants {
			for _, mode := range []string{"indexed", "absolute", "symbolic"} {
				clone := cloneEncoding(v)
				clone.ID += "_" + name + "_" + mode
				var base, off *codec.Operand
				for i := range clone.Operands {
					o := &clone.Operands[i]
					if o.Name == name+"_base" {
						base = o
					}
					if o.Name == name+"_offset" {
						off = o
					}
				}
				replacement := "{" + name + "_offset}({" + name + "_base})"
				switch mode {
				case "indexed":
					base.Names[0] = ""
					base.Names[2] = ""
					if base.Class == "memsrc_base" {
						base.Names[3] = ""
					}
				case "absolute", "symbolic":
					fixed := 2
					if mode == "symbolic" {
						fixed = 0
					}
					for _, b := range base.Bits {
						for k := 0; k < b.Width; k++ {
							p := b.InstructionBit + k
							clone.Mask[p/8] |= 1 << uint(p%8)
							if (fixed>>uint(b.ValueBit+k))&1 != 0 {
								clone.Value[p/8] |= 1 << uint(p%8)
							}
						}
					}
					replacement = "&{" + name + "_offset}"
					off.Kind = "address"
					off.Signed = false
					if mode == "symbolic" {
						replacement = "{" + name + "_offset}"
						off.Kind = "displacement"
						off.Signed = true
						off.Relative = true
						off.PCWrapBits = 16
						off.PCBias = int64(off.Bits[0].InstructionBit / 16 * 2)
						// An emulated RLA/RLC memory operand appears in two
						// extension words, whose symbolic PC bases differ.
						firstWord := off.Bits[0].InstructionBit / 16
						var first, second []codec.BitSlice
						for _, b := range off.Bits {
							if b.InstructionBit/16 == firstWord {
								first = append(first, b)
							} else {
								second = append(second, b)
							}
						}
						if len(second) > 0 {
							off.Bits = first
							off.Class = "memsrc_offset"
							implicit := *off
							implicit.Name += "_repeated"
							implicit.Class = "memdst_offset"
							implicit.Bits = second
							implicit.Relative = false
							implicit.PCBias = 0
							implicit.Implicit = true
							implicit.Bias = int64(second[0].InstructionBit/16-firstWord) * 2
							implicit.BiasOperand = off.Name
							implicit.BiasScale = -1
							clone.Operands = append(clone.Operands, implicit)
							clone.Constraints = append(clone.Constraints, codec.Constraint{Kind: "eq", Left: implicit.Name})
						}
					}
					var os []codec.Operand
					for _, o := range clone.Operands {
						if o.Name != base.Name {
							os = append(os, o)
						}
					}
					clone.Operands = os
				}
				clone.Syntax = strings.ReplaceAll(clone.Syntax, "{"+name+"}", replacement)
				next = append(next, clone)
			}
		}
		variants = next
	}
	var framed []codec.Encoding
	for _, v := range variants {
		normal := cloneEncoding(v)
		var wrapped *codec.Encoding
		for _, o := range v.Operands {
			if o.Implicit && o.BiasOperand != "" && o.Bias > 0 {
				normal.Constraints = append(normal.Constraints, codec.Constraint{Kind: "diff_ge", Left: o.BiasOperand, Limit: -(1 << 15) + o.Bias})
				w := cloneEncoding(v)
				w.ID += "_wrapped"
				for i := range w.Operands {
					if w.Operands[i].Name == o.Name {
						w.Operands[i].Bias -= 1 << 16
					}
				}
				w.Constraints = append(w.Constraints, codec.Constraint{Kind: "sum_le", Left: o.BiasOperand, Limit: -(1 << 15) + o.Bias - 1})
				wrapped = &w
			}
		}
		framed = append(framed, normal)
		if wrapped != nil {
			framed = append(framed, *wrapped)
		}
	}
	return framed, nil
}
func bindAlias(alias, target record, get func(string) record) (record, error) {
	clone := copyRecord(target)
	var original [][]any
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		original = append(original, dagArgs(target[key])...)
	}
	actual := dagArgs(alias["ResultInst"])
	equal := map[string]string{}
	for _, m := range tiedOperands.FindAllStringSubmatch(stringValue(target["Constraints"]), -1) {
		equal[m[1]] = m[2]
		equal[m[2]] = m[1]
	}
	if len(original) != len(actual) {
		var expanded [][]any
		byName := map[string][]any{}
		n := 0
		for _, a := range original {
			name := stringValue(a[1])
			if old, ok := byName[equal[name]]; ok {
				expanded = append(expanded, old)
				byName[name] = old
				continue
			}
			if n >= len(actual) {
				return nil, fmt.Errorf("result arity")
			}
			expanded = append(expanded, actual[n])
			byName[name] = actual[n]
			n++
		}
		if n != len(actual) {
			return nil, fmt.Errorf("result arity")
		}
		actual = expanded
	}
	type binding struct {
		name     string
		fixed    int
		constant bool
	}
	bindings := map[string]binding{}
	seen := map[string]bool{}
	var operands []any
	for i, a := range original {
		src := stringValue(a[1])
		name := stringValue(actual[i][1])
		v := actual[i][0]
		bind := binding{name: name}
		if name == "" {
			bind.constant = true
			if n, ok := v.(float64); ok {
				bind.fixed = int(n)
				if strings.HasPrefix(definition(a[0]), "cg") {
					switch bind.fixed {
					case 0:
						bind.fixed = 3
					case 1:
						bind.fixed = 0x13
					case 2:
						bind.fixed = 0x23
					case 4:
						bind.fixed = 0x22
					case 8:
						bind.fixed = 0x32
					case -1:
						bind.fixed = 0x33
					}
				}
			} else {
				reg := get(definition(v))
				if reg == nil {
					return nil, fmt.Errorf("nonconstant binding")
				}
				bits, _ := reg["HWEncoding"].([]any)
				for i, b := range bits {
					bind.fixed |= number(b) << i
				}
			}
		} else if !seen[name] {
			operands = append(operands, []any{a[0], name})
			seen[name] = true
		}
		bindings[src] = bind
	}
	inst, _ := clone["Inst"].([]any)
	for i, v := range inst {
		if ref, ok := v.(map[string]any); ok {
			bind, exists := bindings[stringValue(ref["var"])]
			if !exists {
				return nil, fmt.Errorf("missing binding %s", stringValue(ref["var"]))
			}
			if bind.constant {
				inst[i] = (bind.fixed >> number(ref["index"])) & 1
			} else {
				ref["var"] = bind.name
			}
		}
	}
	clone["AsmString"] = alias["AsmString"]
	clone["OutOperandList"] = map[string]any{"args": []any{}}
	clone["InOperandList"] = map[string]any{"args": operands}
	return clone, nil
}

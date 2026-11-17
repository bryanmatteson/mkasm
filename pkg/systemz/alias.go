package systemz

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func addressSyntax(a address) string {
	s := "{" + a.Children[1] + "}("
	if len(a.Children) == 3 {
		s += "{" + a.Children[2] + "},"
	}
	return s + "{" + a.Children[0] + "})"
}
func importAlias(id string, r record, records map[string]record, encodings []codec.Encoding) (codec.Encoding, error) {
	var result dag
	if err := json.Unmarshal(r["ResultInst"], &result); err != nil {
		return codec.Encoding{}, err
	}
	var e codec.Encoding
	found := false
	for _, base := range encodings {
		if base.ID == result.Operator.Def {
			e = base
			found = true
			break
		}
	}
	if !found {
		return e, fmt.Errorf("missing target instruction %s", result.Operator.Def)
	}
	e.ID = "alias_" + id
	e.AssemblyOnly = true
	e.Mask = append([]byte(nil), e.Mask...)
	e.Value = append([]byte(nil), e.Value...)
	e.Operands = append([]codec.Operand(nil), e.Operands...)
	target := records[result.Operator.Def]
	_, _, addresses, err := operandSpecs(target, records)
	if err != nil {
		return e, err
	}
	addressByName := map[string]address{}
	for _, a := range addresses {
		addressByName[a.Name] = a
	}
	var top []string
	seen := map[string]bool{}
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		var d dag
		_ = json.Unmarshal(target[key], &d)
		for _, a := range d.Args {
			name := str(a[1])
			if seen[name] {
				continue
			}
			present := false
			for _, o := range e.Operands {
				if o.Name == name {
					present = true
				}
			}
			if _, ok := addressByName[name]; ok {
				present = true
			}
			if present {
				top = append(top, name)
				seen[name] = true
			}
		}
	}
	if len(top) != len(result.Args) {
		return e, fmt.Errorf("alias target operand count %d != %d", len(top), len(result.Args))
	}
	syntax := canonicalSyntax(str(r["AsmString"]))
	rename := map[string]string{}
	fixed := map[string]int64{}
	for i, arg := range result.Args {
		if len(arg) != 2 {
			return e, fmt.Errorf("invalid alias operand")
		}
		name := top[i]
		newName := str(arg[1])
		if newName != "" {
			if address, ok := addressByName[name]; ok {
				syntax = replaceHole(syntax, newName, addressSyntax(address))
				for _, child := range address.Children {
					rename[child] = child
				}
			} else {
				rename[name] = newName
			}
			continue
		}
		var value int64
		if err := json.Unmarshal(arg[0], &value); err != nil {
			return e, fmt.Errorf("unsupported fixed alias operand")
		}
		fixed[name] = value
	}
	var ops []codec.Operand
	byName := map[string]int{}
	for _, o := range e.Operands {
		if v, ok := fixed[o.Name]; ok {
			if err := fixOperand(&e, o, v); err != nil {
				return e, err
			}
			continue
		}
		name, ok := rename[o.Name]
		if !ok {
			return e, fmt.Errorf("unbound alias operand %s", o.Name)
		}
		o.Name = name
		if at, exists := byName[name]; exists {
			ops[at].Bits = append(append([]codec.BitSlice(nil), ops[at].Bits...), o.Bits...)
		} else {
			byName[name] = len(ops)
			ops = append(ops, o)
		}
	}
	e.Operands = ops
	for _, name := range holes(syntax) {
		if _, ok := byName[name]; !ok {
			return e, fmt.Errorf("unencoded alias syntax operand %s", name)
		}
		syntax = replaceHole(syntax, name, "{"+name+"}")
	}
	e.Syntax = syntax
	e.Mnemonic = strings.Fields(syntax)[0]
	var predicates []reference
	_ = json.Unmarshal(r["Predicates"], &predicates)
	for _, p := range predicates {
		e.Features = append(e.Features, p.Def)
	}
	return e, nil
}
func fixOperand(e *codec.Encoding, o codec.Operand, value int64) error {
	one := *e
	one.Operands = []codec.Operand{o}
	out, err := codec.Encode(&one, map[string]int64{o.Name: value})
	if err != nil {
		return err
	}
	e.Value = out
	for _, b := range o.Bits {
		for k := 0; k < b.Width; k++ {
			p := b.InstructionBit + k
			e.Mask[p/8] |= 1 << uint(p%8)
		}
	}
	return nil
}

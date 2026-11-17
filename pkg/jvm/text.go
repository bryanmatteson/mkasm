package jvm

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

var arrayTypes = map[int64]string{4: "boolean", 5: "char", 6: "float", 7: "double", 8: "byte", 9: "short", 10: "int", 11: "long"}

type textSwitch struct {
	Default int64      `json:"default"`
	Low     int32      `json:"low,omitempty"`
	Targets []int64    `json:"targets,omitempty"`
	Pairs   []textPair `json:"pairs,omitempty"`
}
type textPair struct {
	Match  int32 `json:"match"`
	Target int64 `json:"target"`
}

// Format returns text with constant-pool indices prefixed by # and branch
// targets expressed as absolute byte offsets within the containing method.
func (in *Instruction) Format() string {
	text := in.Mnemonic
	if in.Wide {
		text = "wide " + text
	}
	if in.Switch != nil {
		s := in.Switch
		t := textSwitch{Default: int64(in.Offset) + int64(s.Default), Low: s.Low}
		for _, v := range s.Targets {
			t.Targets = append(t.Targets, int64(in.Offset)+int64(v))
		}
		for _, p := range s.Pairs {
			t.Pairs = append(t.Pairs, textPair{p.Match, int64(in.Offset) + int64(p.Target)})
		}
		b, _ := json.Marshal(t)
		return text + " " + string(b)
	}
	for _, o := range in.Operands {
		v := o.Value
		if o.Kind == "branch" {
			v += int64(in.Offset)
		}
		value := strconv.FormatInt(v, 10)
		if o.Kind == "constant_pool" {
			value = "#" + value
		}
		if o.Kind == "array_type" {
			if name, ok := arrayTypes[v]; ok {
				value = name
			}
		}
		text += " " + value
	}
	return text
}
func (c *Catalog) Assemble(text string, offset uint32) ([]byte, error) {
	text = strings.TrimSpace(strings.SplitN(text, "//", 2)[0])
	wide := false
	if strings.HasPrefix(text, "wide ") {
		wide = true
		text = strings.TrimSpace(strings.TrimPrefix(text, "wide "))
	}
	split := strings.IndexAny(text, " \t")
	name, args := text, ""
	if split >= 0 {
		name, args = text[:split], strings.TrimSpace(text[split:])
	}
	var d *Definition
	for i := range c.Instructions {
		if c.Instructions[i].Mnemonic == name {
			d = &c.Instructions[i]
			break
		}
	}
	if d == nil {
		return nil, malformed("unknown JVM mnemonic " + name)
	}
	in := &Instruction{Opcode: d.Opcode, Mnemonic: name, Offset: offset, Wide: wide}
	if d.Opcode == 0xaa || d.Opcode == 0xab {
		var t textSwitch
		dec := json.NewDecoder(strings.NewReader(args))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return nil, malformed("switch JSON: " + err.Error())
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, malformed("trailing switch text")
		}
		convert := func(target int64) (int32, error) {
			v := target - int64(offset)
			if target < math.MinInt32+int64(offset) || target > math.MaxInt32+int64(offset) {
				return 0, malformed("switch target out of range")
			}
			return int32(v), nil
		}
		def, err := convert(t.Default)
		if err != nil {
			return nil, err
		}
		in.Switch = &Switch{Default: def, Low: t.Low}
		for _, target := range t.Targets {
			v, err := convert(target)
			if err != nil {
				return nil, err
			}
			in.Switch.Targets = append(in.Switch.Targets, v)
		}
		for _, p := range t.Pairs {
			v, err := convert(p.Target)
			if err != nil {
				return nil, err
			}
			in.Switch.Pairs = append(in.Switch.Pairs, LookupPair{p.Match, v})
		}
		return c.Encode(in, offset)
	}
	tokens := strings.Fields(strings.ReplaceAll(args, ",", " "))
	if len(tokens) != len(d.Operands) {
		return nil, malformed(fmt.Sprintf("%s expects %d operands", name, len(d.Operands)))
	}
	for i, o := range d.Operands {
		token := strings.TrimPrefix(tokens[i], "#")
		var value int64
		found := false
		if o.Kind == "array_type" {
			for v, name := range arrayTypes {
				if token == name {
					value = v
					found = true
					break
				}
			}
		}
		if !found {
			v, err := parseNumber(token)
			if err != nil {
				return nil, malformed("invalid operand " + token)
			}
			value = v
		}
		if o.Kind == "branch" {
			if value < math.MinInt32+int64(offset) || value > math.MaxInt32+int64(offset) {
				return nil, malformed("branch target out of range")
			}
			value -= int64(offset)
		}
		in.Operands = append(in.Operands, Operand{o.Name, o.Kind, value})
	}
	return c.Encode(in, offset)
}

func parseNumber(token string) (int64, error) {
	digits := strings.TrimPrefix(strings.TrimPrefix(token, "-"), "+")
	base := 10
	if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0b") || strings.HasPrefix(digits, "0o") {
		base = 0
	}
	return strconv.ParseInt(token, base, 64)
}

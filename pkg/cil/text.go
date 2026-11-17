package cil

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func targetText(v int64) string {
	if v < 0 {
		return fmt.Sprintf("IL_-%04x", -v)
	}
	return fmt.Sprintf("IL_%04x", v)
}
func parseTarget(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "il_") {
		return strconv.ParseInt(s[3:], 16, 64)
	}
	return strconv.ParseInt(s, 0, 64)
}
func (c *Catalog) Format(in *Instruction) (string, error) {
	d, err := c.resolve(in)
	if err != nil {
		return "", err
	}
	b, err := c.Encode(in, in.Offset)
	if err != nil {
		return "", err
	}
	text := d.Mnemonic
	if in.Operand == nil {
		return text, nil
	}
	o := in.Operand
	base := int64(in.Offset) + int64(len(b))
	switch o.Kind {
	case "integer", "variable":
		return text + " " + strconv.FormatInt(o.Value, 10), nil
	case "token":
		return fmt.Sprintf("%s 0x%08x", text, uint32(o.Value)), nil
	case "float32":
		return fmt.Sprintf("%s bits(0x%08x)", text, uint32(o.Bits)), nil
	case "float64":
		return fmt.Sprintf("%s bits(0x%016x)", text, o.Bits), nil
	case "branch":
		return text + " " + targetText(base+o.Value), nil
	case "switch":
		targets := make([]string, len(o.Targets))
		for i, v := range o.Targets {
			targets[i] = targetText(base + int64(v))
		}
		return text + " (" + strings.Join(targets, ", ") + ")", nil
	}
	return "", malformed("unknown operand kind")
}
func splitInstruction(text string) (string, string) {
	text = strings.TrimSpace(text)
	p := strings.IndexAny(text, " \t\r\n")
	if p < 0 {
		return strings.ToLower(text), ""
	}
	return strings.ToLower(text[:p]), strings.TrimSpace(text[p:])
}
func switchTokens(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return nil, malformed("switch requires parenthesized targets")
	}
	s = strings.TrimSpace(s[1 : len(s)-1])
	if s == "" {
		return []string{}, nil
	}
	a := strings.Split(s, ",")
	for i := range a {
		a[i] = strings.TrimSpace(a[i])
		if a[i] == "" {
			return nil, malformed("empty switch target")
		}
	}
	return a, nil
}
func (c *Catalog) Assemble(text string, offset uint32) ([]byte, error) {
	name, s := splitInstruction(text)
	d := c.Lookup(name)
	if d == nil {
		return nil, malformed("unknown mnemonic " + name)
	}
	in := &Instruction{Opcode: d.Opcode, Mnemonic: d.Mnemonic, Offset: offset}
	if d.OperandKind == "none" {
		if s != "" {
			return nil, malformed("unexpected operand")
		}
		return c.Encode(in, offset)
	}
	if s == "" {
		return nil, malformed("missing operand")
	}
	o := &Operand{Kind: d.OperandKind}
	in.Operand = o
	var err error
	switch o.Kind {
	case "integer", "variable":
		o.Value, err = strconv.ParseInt(s, 0, 64)
	case "token":
		var n uint64
		n, err = strconv.ParseUint(s, 0, 32)
		o.Value = int64(n)
	case "float32", "float64":
		if strings.HasPrefix(s, "bits(") && strings.HasSuffix(s, ")") {
			bits := 64
			if o.Kind == "float32" {
				bits = 32
			}
			o.Bits, err = strconv.ParseUint(strings.TrimSpace(s[5:len(s)-1]), 0, bits)
		} else {
			bits := 64
			if o.Kind == "float32" {
				bits = 32
			}
			var v float64
			v, err = strconv.ParseFloat(s, bits)
			if bits == 32 {
				o.Bits = uint64(math.Float32bits(float32(v)))
			} else {
				o.Bits = math.Float64bits(v)
			}
		}
	case "branch":
		var target int64
		target, err = parseTarget(s)
		base := int64(offset) + int64(d.Size+operandBytes(d))
		if target < math.MinInt64+base {
			err = malformed("branch displacement out of range")
		} else {
			o.Value = target - base
		}
	case "switch":
		var a []string
		a, err = switchTokens(s)
		if err == nil {
			base := int64(offset) + int64(d.Size+4+4*len(a))
			o.Targets = make([]int32, len(a))
			for i, token := range a {
				var v int64
				v, err = parseTarget(token)
				if err != nil {
					break
				}
				if v < math.MinInt64+base {
					err = malformed("switch displacement out of range")
					break
				}
				v -= base
				if v < math.MinInt32 || v > math.MaxInt32 {
					err = malformed("switch displacement out of range")
					break
				}
				o.Targets[i] = int32(v)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: operand %q: %v", ErrMalformed, s, err)
	}
	return c.Encode(in, offset)
}
func (c *Catalog) FormatMethod(in []Instruction) (string, error) {
	var text strings.Builder
	at := uint32(0)
	for _, x := range in {
		x.Offset = at
		b, err := c.Encode(&x, at)
		if err != nil {
			return "", err
		}
		x.Length = len(b)
		s, err := c.Format(&x)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&text, "IL_%04x: %s\n", at, s)
		at += uint32(len(b))
	}
	return text.String(), nil
}
func (c *Catalog) AssembleMethod(text string) ([]byte, error) {
	type line struct {
		text   string
		offset uint32
	}
	var lines []line
	labels := map[string]uint32{}
	at := uint64(0)
	for _, s := range strings.Split(text, "\n") {
		if i := strings.Index(s, "//"); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if i := strings.IndexByte(s, ':'); i >= 0 {
			label := strings.TrimSpace(s[:i])
			if label == "" || strings.ContainsAny(label, " \t(),") {
				return nil, malformed("invalid label")
			}
			if _, ok := labels[label]; ok {
				return nil, malformed("duplicate label " + label)
			}
			labels[label] = uint32(at)
			s = strings.TrimSpace(s[i+1:])
			if s == "" {
				continue
			}
		}
		name, operand := splitInstruction(s)
		d := c.Lookup(name)
		if d == nil {
			return nil, malformed("unknown mnemonic " + name)
		}
		n := operandBytes(d)
		if n < 0 {
			targets, err := switchTokens(operand)
			if err != nil {
				return nil, err
			}
			n = 4 + 4*len(targets)
		}
		lines = append(lines, line{s, uint32(at)})
		at += uint64(d.Size + n)
		if at > math.MaxInt32 {
			return nil, malformed("method code too large")
		}
	}
	var code []byte
	for _, l := range lines {
		name, operand := splitInstruction(l.text)
		d := c.Lookup(name)
		replace := func(s string) string {
			if target, ok := labels[s]; ok {
				return targetText(int64(target))
			}
			return s
		}
		if d.OperandKind == "branch" {
			operand = replace(operand)
		} else if d.OperandKind == "switch" {
			a, err := switchTokens(operand)
			if err != nil {
				return nil, err
			}
			for i := range a {
				a[i] = replace(a[i])
			}
			operand = "(" + strings.Join(a, ", ") + ")"
		}
		b, err := c.Assemble(name+" "+operand, l.offset)
		if err != nil {
			return nil, err
		}
		code = append(code, b...)
	}
	if _, err := c.DecodeMethod(code); err != nil {
		return nil, err
	}
	return code, nil
}

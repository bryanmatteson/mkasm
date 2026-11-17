package dex

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func poolName(k string) string {
	switch k {
	case "String":
		return "string"
	case "Type":
		return "type"
	case "Field":
		return "field"
	case "Method", "MethodAndProto":
		return "method"
	case "Proto":
		return "proto"
	case "CallSite":
		return "call_site"
	case "MethodHandle":
		return "method_handle"
	}
	return k
}
func (c *Catalog) Format(in *Instruction) string {
	d := c.definition(in.Opcode)
	if d == nil {
		return "<unknown>"
	}
	args := []string{}
	if in.Payload != nil {
		p := in.Payload
		var entries []string
		switch in.Opcode {
		case 0x100:
			for _, v := range p.Targets {
				entries = append(entries, fmt.Sprintf("%+d", v))
			}
			return fmt.Sprintf("%s %d, {%s}", d.Mnemonic, p.FirstKey, strings.Join(entries, ", "))
		case 0x200:
			for i, v := range p.Targets {
				entries = append(entries, fmt.Sprintf("%d:%+d", p.Keys[i], v))
			}
			return fmt.Sprintf("%s {%s}", d.Mnemonic, strings.Join(entries, ", "))
		case 0x300:
			w := int(p.ElementWidth)
			if w == 0 {
				return "<invalid array>"
			}
			for i := 0; i+w <= len(p.Data); i += w {
				var v uint64
				for j := 0; j < w; j++ {
					v |= uint64(p.Data[i+j]) << uint(j*8)
				}
				entries = append(entries, fmt.Sprintf("0x%x", v))
			}
			return fmt.Sprintf("%s %d, {%s}", d.Mnemonic, w, strings.Join(entries, ", "))
		}
	}
	if d.Format == "35c" || d.Format == "45cc" {
		var regs []string
		for _, r := range in.Registers {
			regs = append(regs, fmt.Sprintf("v%d", r))
		}
		args = append(args, "{"+strings.Join(regs, ", ")+"}")
	}
	if in.Range != nil {
		r := in.Range
		s := "{}"
		if r.Count > 0 {
			s = fmt.Sprintf("{v%d .. v%d}", r.Start, uint32(r.Start)+uint32(r.Count)-1)
		} else if r.Start != 0 {
			s = fmt.Sprintf("{v%d .. v%d}", r.Start, int(r.Start)-1)
		}
		args = append(args, s)
	}
	for _, f := range d.Fields {
		v := in.Values[f.Name]
		s := strconv.FormatInt(v, 10)
		switch f.Kind {
		case "register":
			s = "v" + s
		case "literal":
			s = "#" + s
		case "target":
			if target := int64(in.Offset) + v; target < 0 {
				s = strconv.FormatInt(target, 10)
			} else {
				s = fmt.Sprintf("0x%x", target)
			}
		default:
			s = poolName(f.Kind) + "@" + s
		}
		args = append(args, s)
	}
	if len(args) > 0 {
		return d.Mnemonic + " " + strings.Join(args, ", ")
	}
	return d.Mnemonic
}
func number(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	digits := strings.TrimLeft(s, "+-")
	base := 10
	if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0b") {
		base = 0
	}
	return strconv.ParseInt(s, base, 64)
}
func splitArgs(s string) ([]string, error) {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '{':
			depth++
			if depth > 1 {
				return nil, malformed("nested operands")
			}
		case '}':
			depth--
			if depth < 0 {
				return nil, malformed("unexpected brace")
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, malformed("unclosed operand list")
	}
	if strings.TrimSpace(s) != "" {
		out = append(out, strings.TrimSpace(s[start:]))
	}
	return out, nil
}
func listBody(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return "", malformed("expected braces")
	}
	return s[1 : len(s)-1], nil
}
func register(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return 0, malformed("expected v register")
	}
	n, e := strconv.ParseUint(s[1:], 10, 16)
	if e != nil {
		return 0, malformed("invalid register")
	}
	return uint16(n), nil
}
func (c *Catalog) Assemble(text string, offset uint32) ([]byte, error) {
	return c.AssembleVersion(text, offset, LatestVersion)
}
func (c *Catalog) AssembleVersion(text string, offset uint32, version int) ([]byte, error) {
	text = strings.TrimSpace(strings.SplitN(text, "//", 2)[0])
	name, args := text, ""
	if i := strings.IndexAny(text, " \t"); i >= 0 {
		name, args = text[:i], strings.TrimSpace(text[i:])
	}
	var d *Definition
	for i := range c.Instructions {
		if c.Instructions[i].Mnemonic == name {
			d = &c.Instructions[i]
			break
		}
	}
	if d == nil {
		return nil, malformed("unknown mnemonic " + name)
	}
	in := &Instruction{Opcode: d.Opcode, Mnemonic: d.Mnemonic, Offset: offset, Values: map[string]int64{}}
	tokens, err := splitArgs(args)
	if err != nil {
		return nil, err
	}
	if d.Opcode >= 256 {
		p := &Payload{}
		in.Payload = p
		body := ""
		switch d.Opcode {
		case 0x100:
			if len(tokens) != 2 {
				return nil, malformed("packed payload expects first key and targets")
			}
			v, e := number(tokens[0])
			if e != nil || v < -2147483648 || v > 2147483647 {
				return nil, malformed("invalid first key")
			}
			p.FirstKey = int32(v)
			body, err = listBody(tokens[1])
		case 0x200:
			if len(tokens) != 1 {
				return nil, malformed("sparse payload expects pairs")
			}
			body, err = listBody(tokens[0])
		case 0x300:
			if len(tokens) != 2 {
				return nil, malformed("array payload expects width and values")
			}
			v, e := number(tokens[0])
			if e != nil || (v != 1 && v != 2 && v != 4 && v != 8) {
				return nil, malformed("invalid array width")
			}
			p.ElementWidth = uint16(v)
			body, err = listBody(tokens[1])
		}
		if err != nil {
			return nil, err
		}
		items, e := splitArgs(body)
		if e != nil {
			return nil, e
		}
		for _, item := range items {
			if d.Opcode == 0x300 {
				s := strings.TrimSpace(item)
				v, e := strconv.ParseUint(s, 0, 64)
				if e != nil {
					v2, e2 := number(s)
					if e2 != nil {
						return nil, malformed("invalid array value")
					}
					v = uint64(v2)
				}
				w := int(p.ElementWidth)
				if w < 8 && v >= (uint64(1)<<uint(w*8)) {
					return nil, malformed("array value out of range")
				}
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, v)
				p.Data = append(p.Data, b[:w]...)
				continue
			}
			if d.Opcode == 0x200 {
				pair := strings.Split(item, ":")
				if len(pair) != 2 {
					return nil, malformed("invalid sparse pair")
				}
				k, e := number(pair[0])
				if e != nil || k < -2147483648 || k > 2147483647 {
					return nil, malformed("invalid sparse key")
				}
				p.Keys = append(p.Keys, int32(k))
				item = pair[1]
			}
			v, e := number(item)
			if e != nil || v < -2147483648 || v > 2147483647 {
				return nil, malformed("invalid payload target")
			}
			p.Targets = append(p.Targets, int32(v))
		}
		return c.EncodeVersion(in, offset, version)
	}
	invoke := d.Format == "35c" || d.Format == "45cc"
	rng := d.Format == "3rc" || d.Format == "4rcc"
	extra := 0
	if invoke || rng {
		extra = 1
	}
	if len(tokens) != len(d.Fields)+extra {
		return nil, malformed("incorrect operand count")
	}
	if extra == 1 {
		body, e := listBody(tokens[0])
		if e != nil {
			return nil, e
		}
		if rng {
			r := &RegisterRange{}
			if strings.TrimSpace(body) != "" {
				parts := strings.Split(body, "..")
				if len(parts) != 2 {
					return nil, malformed("expected register range")
				}
				a, e := register(parts[0])
				if e != nil {
					return nil, e
				}
				last, e := number(strings.TrimPrefix(strings.TrimSpace(parts[1]), "v"))
				if e != nil || last < int64(a)-1 || last > 65535 || last-int64(a)+1 > 255 {
					return nil, malformed("invalid range end")
				}
				r.Start = a
				r.Count = uint16(last - int64(a) + 1)
			}
			in.Range = r
		} else {
			items, e := splitArgs(body)
			if e != nil {
				return nil, e
			}
			for _, s := range items {
				r, e := register(s)
				if e != nil {
					return nil, e
				}
				in.Registers = append(in.Registers, r)
			}
		}
	}
	for i, f := range d.Fields {
		s := tokens[i+extra]
		var v int64
		var e error
		switch f.Kind {
		case "register":
			var r uint16
			r, e = register(s)
			v = int64(r)
		case "literal":
			v, e = number(s)
		case "target":
			v, e = number(s)
			if e == nil {
				if v < -2147483648+int64(offset) || v > 2147483647+int64(offset) {
					return nil, malformed("target out of range")
				}
				v -= int64(offset)
			}
		default:
			prefix := poolName(f.Kind) + "@"
			if !strings.HasPrefix(s, prefix) {
				return nil, malformed("expected " + prefix)
			}
			v, e = number(strings.TrimPrefix(s, prefix))
		}
		if e != nil {
			return nil, malformed("invalid operand " + s)
		}
		in.Values[f.Name] = v
	}
	return c.EncodeVersion(in, offset, version)
}

type Template struct {
	Mnemonic string `json:"mnemonic"`
	Format   string `json:"format"`
	Text     string `json:"text"`
}

func (c *Catalog) Templates() []Template {
	var out []Template
	for _, d := range c.Instructions {
		if d.Reserved {
			continue
		}
		in := &Instruction{Opcode: d.Opcode, Values: map[string]int64{}}
		for _, f := range d.Fields {
			in.Values[f.Name] = 0
			if f.Kind == "target" {
				in.Values[f.Name] = 1
			}
		}
		if d.Format == "35c" || d.Format == "45cc" {
			in.Registers = []uint16{0}
		}
		if d.Format == "3rc" || d.Format == "4rcc" {
			in.Range = &RegisterRange{0, 1}
		}
		if d.Opcode >= 256 {
			in.Payload = &Payload{}
			if d.Opcode == 0x300 {
				in.Payload.ElementWidth = 1
			}
		}
		out = append(out, Template{d.Mnemonic, d.Format, c.Format(in)})
	}
	return out
}

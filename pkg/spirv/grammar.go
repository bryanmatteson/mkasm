// Package spirv imports Khronos' normative SPIR-V JSON grammar.
package spirv

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Requirements struct {
	Capabilities []string `json:"capabilities,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
	Version      string   `json:"version,omitempty"`
	LastVersion  string   `json:"lastVersion,omitempty"`
}
type OperandSpec struct {
	Kind       string `json:"kind"`
	Name       string `json:"name,omitempty"`
	Quantifier string `json:"quantifier,omitempty"`
}
type InstructionDef struct {
	Requirements
	Name     string        `json:"opname"`
	Class    string        `json:"class,omitempty"`
	Opcode   uint16        `json:"opcode"`
	Aliases  []string      `json:"aliases,omitempty"`
	Operands []OperandSpec `json:"operands,omitempty"`
}
type Enumerant struct {
	Requirements
	Name       string          `json:"enumerant"`
	Value      json.RawMessage `json:"value"`
	Aliases    []string        `json:"aliases,omitempty"`
	Parameters []OperandSpec   `json:"parameters,omitempty"`
	Number     uint32          `json:"-"`
}
type OperandKind struct {
	Kind       string      `json:"kind"`
	Category   string      `json:"category"`
	Bases      []string    `json:"bases,omitempty"`
	Enumerants []Enumerant `json:"enumerants,omitempty"`
}
type Catalog struct {
	Schema       string           `json:"schema"`
	Architecture string           `json:"architecture"`
	Copyright    []string         `json:"copyright,omitempty"`
	Magic        string           `json:"magic_number"`
	Major        int              `json:"major_version"`
	Minor        int              `json:"minor_version"`
	Revision     int              `json:"revision"`
	Instructions []InstructionDef `json:"instructions"`
	OperandKinds []OperandKind    `json:"operand_kinds"`
	ops          map[uint16]*InstructionDef
	names        map[string]*InstructionDef
	kinds        map[string]*OperandKind
}

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "spirv" && architecture != "spirv32" && architecture != "spirv64" {
		return nil, fmt.Errorf("spirv: unsupported architecture %q", architecture)
	}
	c := &Catalog{}
	d := json.NewDecoder(r)
	if err := d.Decode(c); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("spirv: trailing JSON input")
	}
	c.Schema = "mkasm.spirv.v1"
	c.Architecture = architecture
	if c.Magic != "0x07230203" || len(c.Instructions) == 0 || len(c.OperandKinds) == 0 {
		return nil, fmt.Errorf("spirv: not a Khronos core grammar")
	}
	c.ops = map[uint16]*InstructionDef{}
	c.names = map[string]*InstructionDef{}
	c.kinds = map[string]*OperandKind{}
	for i := range c.OperandKinds {
		k := &c.OperandKinds[i]
		if c.kinds[k.Kind] != nil {
			return nil, fmt.Errorf("duplicate operand kind %s", k.Kind)
		}
		c.kinds[k.Kind] = k
		switch k.Category {
		case "Id", "Literal", "Composite", "BitEnum", "ValueEnum":
		default:
			return nil, fmt.Errorf("unknown operand category %s", k.Category)
		}
		for j := range k.Enumerants {
			e := &k.Enumerants[j]
			var number uint64
			var err error
			if len(e.Value) > 0 && e.Value[0] == '"' {
				var s string
				json.Unmarshal(e.Value, &s)
				number, err = strconv.ParseUint(s, 0, 32)
			} else {
				number, err = strconv.ParseUint(string(e.Value), 10, 32)
			}
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", k.Kind, e.Name, err)
			}
			e.Number = uint32(number)
		}
	}
	for i := range c.Instructions {
		op := &c.Instructions[i]
		if c.ops[op.Opcode] != nil {
			return nil, fmt.Errorf("duplicate opcode %d", op.Opcode)
		}
		c.ops[op.Opcode] = op
		for _, name := range append([]string{op.Name}, op.Aliases...) {
			if c.names[name] != nil {
				return nil, fmt.Errorf("duplicate opname %s", name)
			}
			c.names[name] = op
		}
		if err := c.checkSpecs(op.Operands); err != nil {
			return nil, fmt.Errorf("%s: %w", op.Name, err)
		}
	}
	for _, k := range c.OperandKinds {
		for _, base := range k.Bases {
			if c.kinds[base] == nil {
				return nil, fmt.Errorf("unknown composite base %s", base)
			}
		}
		for _, e := range k.Enumerants {
			if err := c.checkSpecs(e.Parameters); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}
func (c *Catalog) checkSpecs(specs []OperandSpec) error {
	for _, s := range specs {
		if c.kinds[s.Kind] == nil {
			return fmt.Errorf("unknown operand kind %s", s.Kind)
		}
		if s.Quantifier != "" && s.Quantifier != "?" && s.Quantifier != "*" {
			return fmt.Errorf("invalid quantifier %s", s.Quantifier)
		}
	}
	return nil
}
func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }

// Environment optionally restricts instructions and enumerants to a declared
// module version, extensions and capabilities. A nil environment is the grammar
// union. Capability lists in the Khronos grammar are alternatives.
type Environment struct {
	Version      uint32
	Capabilities map[string]bool
	Extensions   map[string]bool
}

func version(s string) uint32 {
	var major, minor uint32
	fmt.Sscanf(s, "%d.%d", &major, &minor)
	return major<<16 | minor<<8
}
func allowed(r Requirements, env *Environment) bool {
	if env == nil {
		return true
	}
	core := r.Version != "None" && (r.Version == "" || version(r.Version) <= env.Version) && (r.LastVersion == "" || env.Version <= version(r.LastVersion))
	if r.Version == "None" && len(r.Extensions) == 0 && len(r.Capabilities) > 0 {
		core = true
	}
	ext := false
	for _, x := range r.Extensions {
		ext = ext || env.Extensions[x]
	}
	if !core && !ext {
		return false
	}
	if len(r.Capabilities) > 0 {
		for _, x := range r.Capabilities {
			if env.Capabilities[x] {
				return true
			}
		}
		return false
	}
	return true
}
func findEnum(k *OperandKind, n uint32) *Enumerant {
	for i := range k.Enumerants {
		if k.Enumerants[i].Number == n {
			return &k.Enumerants[i]
		}
	}
	return nil
}
func enumName(k *OperandKind, n uint32) string {
	if e := findEnum(k, n); e != nil {
		return e.Name
	}
	return strconv.FormatUint(uint64(n), 10)
}
func enumValue(k *OperandKind, text string) (uint32, error) {
	for _, e := range k.Enumerants {
		if e.Name == text {
			return e.Number, nil
		}
		for _, a := range e.Aliases {
			if a == text {
				return e.Number, nil
			}
		}
	}
	n, err := strconv.ParseUint(text, 0, 32)
	return uint32(n), err
}
func enumParams(k *OperandKind, n uint32, env *Environment) ([]OperandSpec, error) {
	if k.Category == "ValueEnum" {
		e := findEnum(k, n)
		if e == nil {
			return nil, fmt.Errorf("unknown %s enumerant %d", k.Kind, n)
		}
		if !allowed(e.Requirements, env) {
			return nil, fmt.Errorf("unavailable %s.%s", k.Kind, e.Name)
		}
		return e.Parameters, nil
	}
	remaining := n
	var out []OperandSpec
	seen := map[uint32]bool{}
	for _, e := range k.Enumerants {
		if seen[e.Number] {
			continue
		}
		seen[e.Number] = true
		if (e.Number == 0 && n == 0) || (e.Number != 0 && n&e.Number == e.Number) {
			remaining &^= e.Number
			if !allowed(e.Requirements, env) {
				return nil, fmt.Errorf("unavailable %s.%s", k.Kind, e.Name)
			}
			out = append(out, e.Parameters...)
		}
	}
	if remaining != 0 {
		return nil, fmt.Errorf("unknown %s mask bits %#x", k.Kind, remaining)
	}
	return out, nil
}
func enumText(k *OperandKind, n uint32) string {
	if k.Category != "BitEnum" || n == 0 {
		return enumName(k, n)
	}
	var names []string
	seen := map[uint32]bool{}
	for _, e := range k.Enumerants {
		if e.Number != 0 && !seen[e.Number] && n&e.Number == e.Number {
			names = append(names, e.Name)
			seen[e.Number] = true
		}
	}
	return strings.Join(names, "|")
}

// Package systemz imports LLVM's complete SystemZ/zArchitecture instruction
// records, including physical bit fields and assembler aliases.
package systemz

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]json.RawMessage
type reference struct {
	Def string `json:"def"`
}
type dag struct {
	Operator reference           `json:"operator"`
	Args     [][]json.RawMessage `json:"args"`
}
type instBit struct {
	Kind  string `json:"kind"`
	Var   string `json:"var"`
	Index int    `json:"index"`
}
type address struct {
	Name     string
	Class    string
	Children []string
	Types    []string
}

var sourceHole = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]*)?\}|\$([A-Za-z0-9_]+)`)
var dialect = regexp.MustCompile(`\{([^{}|]*)\|[^{}]*\}`)

func str(v json.RawMessage) string { var s string; _ = json.Unmarshal(v, &s); return s }
func num(v json.RawMessage) int    { var n int; _ = json.Unmarshal(v, &n); return n }
func ref(v json.RawMessage) string { var r reference; _ = json.Unmarshal(v, &r); return r.Def }
func canonicalSyntax(s string) string {
	for dialect.MatchString(s) {
		s = dialect.ReplaceAllString(s, "$1")
	}
	return strings.Join(strings.Fields(s), " ")
}
func holes(s string) []string {
	var out []string
	for _, m := range sourceHole.FindAllStringSubmatch(s, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		out = append(out, name)
	}
	return out
}
func replaceHole(s, name, replacement string) string {
	return sourceHole.ReplaceAllStringFunc(s, func(v string) string {
		m := sourceHole.FindStringSubmatch(v)
		if m[1] == name || m[2] == name {
			return replacement
		}
		return v
	})
}

// Parse consumes unmodified llvm-tblgen --dump-json output for SystemZ.td.
// Numeric operands use their assembler values; PC-relative offsets are signed
// byte displacements, scaled by two from the architectural halfword fields.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	switch strings.ToLower(architecture) {
	case "systemz", "s390x":
		architecture = "systemz"
	default:
		return nil, fmt.Errorf("unsupported SystemZ architecture %q", architecture)
	}
	var entries map[string]json.RawMessage
	dec := json.NewDecoder(r)
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("SystemZ TableGen JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("SystemZ TableGen JSON trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(entries["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("SystemZ input requires LLVM TableGen --dump-json: %w", err)
	}
	records := map[string]record{}
	for id, raw := range entries {
		if strings.HasPrefix(id, "!") {
			continue
		}
		var rec record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, err
		}
		records[id] = rec
	}
	ids := append([]string(nil), instances["Instruction"]...)
	sort.Strings(ids)
	c := &codec.Catalog{Schema: codec.Schema, Architecture: architecture, Source: "LLVM SystemZ.td --dump-json", FeatureSets: profiles(records, instances)}
	for _, id := range ids {
		r := records[id]
		if str(r["Namespace"]) != "SystemZ" || num(r["isPseudo"]) != 0 || str(r["AsmString"]) == "" {
			continue
		}
		e, err := importInstruction(id, r, records)
		if err != nil {
			return nil, fmt.Errorf("SystemZ %s: %w", id, err)
		}
		c.Encodings = append(c.Encodings, e)
		_, _, addresses, err := operandSpecs(r, records)
		if err != nil {
			return nil, err
		}
		variants, err := memoryVariants(e, addresses)
		if err != nil {
			return nil, err
		}
		c.Encodings = append(c.Encodings, variants...)
	}
	aliasIDs := append([]string(nil), instances["InstAlias"]...)
	sort.Strings(aliasIDs)
	for _, id := range aliasIDs {
		e, err := importAlias(id, records[id], records, c.Encodings)
		if err != nil {
			return nil, fmt.Errorf("SystemZ alias %s: %w", id, err)
		}
		c.Encodings = append(c.Encodings, e)
		var result dag
		_ = json.Unmarshal(records[id]["ResultInst"], &result)
		_, _, addresses, err := operandSpecs(records[result.Operator.Def], records)
		if err != nil {
			return nil, err
		}
		variants, err := memoryVariants(e, addresses)
		if err != nil {
			return nil, err
		}
		c.Encodings = append(c.Encodings, variants...)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
func operandSpecs(r record, records map[string]record) (map[string]string, []string, []address, error) {
	types := map[string]string{}
	var order []string
	var addresses []address
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		var d dag
		if err := json.Unmarshal(r[key], &d); err != nil {
			return nil, nil, nil, err
		}
		for _, arg := range d.Args {
			if len(arg) != 2 {
				return nil, nil, nil, fmt.Errorf("invalid operand DAG")
			}
			name := str(arg[1])
			typ := ref(arg[0])
			if typ != "" {
				if _, ok := types[name]; !ok {
					order = append(order, name)
				}
				types[name] = typ
				continue
			}
			var nested dag
			if err := json.Unmarshal(arg[0], &nested); err != nil {
				return nil, nil, nil, err
			}
			var info dag
			if err := json.Unmarshal(records[nested.Operator.Def]["MIOperandInfo"], &info); err != nil {
				return nil, nil, nil, fmt.Errorf("address %s has no component definitions", nested.Operator.Def)
			}
			if len(info.Args) != len(nested.Args) {
				return nil, nil, nil, fmt.Errorf("address component mismatch")
			}
			a := address{Name: name, Class: nested.Operator.Def}
			for i, child := range nested.Args {
				if len(child) != 2 || len(info.Args[i]) != 2 {
					return nil, nil, nil, fmt.Errorf("address component DAG")
				}
				childName := str(child[1])
				childType := ref(info.Args[i][0])
				// .insn ss is parsed as BDX, even though its TableGen printer reuses
				// the BDR class. In this directive the third field is a nullable index.
				if str(r["!name"]) == "InsnSS" && name == "RBD1" && i == 2 {
					childType = "ADDR64"
				}
				a.Children = append(a.Children, childName)
				a.Types = append(a.Types, childType)
				types[childName] = childType
				order = append(order, childName)
			}
			addresses = append(addresses, a)
		}
	}
	return types, order, addresses, nil
}
func importInstruction(id string, r record, records map[string]record) (codec.Encoding, error) {
	size := num(r["Size"])
	if size != 2 && size != 4 && size != 6 {
		return codec.Encoding{}, fmt.Errorf("unsupported instruction size %d", size)
	}
	var bits []json.RawMessage
	if err := json.Unmarshal(r["Inst"], &bits); err != nil || len(bits) != size*8 {
		return codec.Encoding{}, fmt.Errorf("Inst/Size mismatch")
	}
	e := codec.Encoding{ID: id, Mask: make([]byte, size), Value: make([]byte, size), AssemblyOnly: num(r["isAsmParserOnly"]) != 0 || strings.HasPrefix(id, "Insn")}
	types, order, addresses, err := operandSpecs(r, records)
	if err != nil {
		return e, err
	}
	fields := map[string][]codec.BitSlice{}
	for i, v := range bits {
		p := (size-1-i/8)*8 + i%8
		if string(v) == "0" || string(v) == "1" || string(v) == "null" {
			e.Mask[p/8] |= 1 << uint(p%8)
			if string(v) == "1" {
				e.Value[p/8] |= 1 << uint(p%8)
			}
			continue
		}
		var b instBit
		if err := json.Unmarshal(v, &b); err != nil || b.Kind != "varbit" {
			return e, fmt.Errorf("unresolved instruction bit %d", i)
		}
		fields[b.Var] = append(fields[b.Var], codec.BitSlice{InstructionBit: p, ValueBit: b.Index, Width: 1})
	}
	syntax := canonicalSyntax(str(r["AsmString"]))
	numericConditional := false
	if raw, ok := records[id+"Asm"]; ok {
		for _, typ := range types {
			if typ == "cond4" {
				syntax = canonicalSyntax(str(raw["AsmString"]))
				numericConditional = true
				break
			}
		}
	}
	// Numeric masks retain every encoded bit. Some integer-comparison suffix
	// aliases discard condition bits that cannot be set by that comparison.
	// Concrete named alias records remain available for normal assembler use.
	if id == "InsnVRS" { // The upstream directive parser supplies two operands omitted by AsmString.
		syntax = ".insn vrs,$enc,$R1,$V3,$BD2,$M4"
	}
	for _, a := range addresses {
		if len(a.Children) < 2 || len(a.Children) > 3 {
			return e, fmt.Errorf("unsupported address %s", a.Class)
		}
		base, disp := a.Children[0], a.Children[1]
		replacement := "{" + disp + "}("
		if len(a.Children) == 3 {
			replacement += "{" + a.Children[2] + "},"
		}
		replacement += "{" + base + "})"
		syntax = replaceHole(syntax, a.Name, replacement)
	}
	// Tied machine operands have one field even when the compiler DAG has an
	// input and output name. Repeated placeholders enforce the equality in text.
	ties := regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)
	for _, m := range ties.FindAllStringSubmatch(str(r["Constraints"]), -1) {
		a, b := m[1], m[2]
		if len(fields[a]) > 0 && len(fields[b]) == 0 {
			syntax = replaceHole(syntax, b, "$"+a)
		} else if len(fields[b]) > 0 && len(fields[a]) == 0 {
			syntax = replaceHole(syntax, a, "$"+b)
		}
	}
	seen := map[string]bool{}
	for _, name := range order {
		if seen[name] || len(fields[name]) == 0 {
			continue
		}
		seen[name] = true
		o, err := operand(name, types[name], fields[name], records)
		if err != nil {
			return e, err
		}
		if numericConditional && types[name] == "cond4" {
			o.Names = nil
		}
		// Some instruction format fields are wider than the operand's source
		// assembler class (for example vector element indices). Their unused high
		// bits are reserved zero, not additional accepted immediate values.
		print := str(records[types[name]]["PrintMethod"])
		m := regexp.MustCompile(`^print[SU]([0-9]+)ImmOperand$`).FindStringSubmatch(print)
		if len(m) > 0 {
			width, _ := strconv.Atoi(m[1])
			var keep []codec.BitSlice
			for _, b := range o.Bits {
				if b.ValueBit >= width {
					e.Mask[b.InstructionBit/8] |= 1 << uint(b.InstructionBit%8)
				} else {
					keep = append(keep, b)
				}
			}
			o.Bits = keep
		}
		e.Operands = append(e.Operands, o)
	}
	var rest []string
	for name := range fields {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	if len(rest) > 0 {
		return e, fmt.Errorf("unclassified machine fields %v", rest)
	}
	for _, name := range holes(syntax) {
		if !seen[name] {
			return e, fmt.Errorf("syntax operand %s has no encoded field", name)
		}
		syntax = replaceHole(syntax, name, "{"+name+"}")
	}
	e.Syntax = syntax
	e.Mnemonic = strings.Fields(syntax)[0]
	var preds []reference
	_ = json.Unmarshal(r["Predicates"], &preds)
	for _, p := range preds {
		e.Features = append(e.Features, p.Def)
	}
	switch {
	case num(r["isReturn"]) != 0:
		e.FlowControl = "return"
	case num(r["isCall"]) != 0:
		e.FlowControl = "call"
	case num(r["isBranch"]) != 0:
		if num(r["isBarrier"]) != 0 {
			e.FlowControl = "branch"
		} else {
			e.FlowControl = "conditional_branch"
		}
	default:
		e.FlowControl = "next"
	}
	return e, nil
}
func operand(name, typ string, bits []codec.BitSlice, records map[string]record) (codec.Operand, error) {
	o := codec.Operand{Name: name, Class: typ, Kind: "immediate", Bits: bits}
	switch {
	case typ == "cond4":
		o.Names = []string{"", "o", "h", "nle", "l", "nhe", "lh", "ne", "e", "nlh", "he", "nl", "le", "nh", "no", ""}
	case strings.HasPrefix(typ, "GR") || strings.HasPrefix(typ, "ADDR") || strings.HasPrefix(typ, "FP") || strings.HasPrefix(typ, "VR") || typ == "AR32" || typ == "CR64" || typ == "AnyReg":
		o.Kind = "register"
		prefix := "%r"
		count := 16
		switch {
		case strings.HasPrefix(typ, "FP"):
			prefix = "%f"
		case strings.HasPrefix(typ, "VR"):
			prefix = "%v"
			count = 32
		case typ == "AR32":
			prefix = "%a"
		case typ == "CR64":
			prefix = "%c"
		}
		o.RegisterPrefix = prefix
		o.Names = make([]string, count)
		o.RegisterAliases = map[string]int64{}
		for i := range o.Names {
			if typ == "GR128" && i%2 != 0 || typ == "FP128" && i%4 >= 2 {
				continue
			}
			o.Names[i] = fmt.Sprintf("%s%d", prefix, i)
			if typ == "AnyReg" {
				o.RegisterAliases[fmt.Sprintf("%%f%d", i)] = int64(i)
				o.RegisterAliases[fmt.Sprintf("%%v%d", i)] = int64(i)
				o.RegisterAliases[fmt.Sprint(i)] = int64(i)
			}
			if strings.HasPrefix(typ, "ADDR") && i == 0 {
				o.Names[i] = "0"
			}
			if (typ == "VR32" || typ == "VR64" || typ == "VR16") && i < 16 {
				o.Names[i] = fmt.Sprintf("%%f%d", i)
				o.RegisterAliases[fmt.Sprintf("%%v%d", i)] = int64(i)
			}
		}
	case strings.HasPrefix(typ, "brtarget") || typ == "pcrel32":
		o.Kind = "displacement"
		o.Signed = true
		o.Scale = 2
		o.Relative = true
	case strings.HasPrefix(typ, "disp20"):
		o.Kind = "displacement"
		o.Signed = true
	case strings.HasPrefix(typ, "disp12"):
		o.Kind = "displacement"
	case strings.HasPrefix(typ, "len"):
		o.Bias = 1
	default:
		print := str(records[typ]["PrintMethod"])
		if strings.HasPrefix(print, "printS") {
			o.Signed = true
		}
		if typ == "imm32zx4even_timm" {
			o.Names = make([]string, 16)
			for i := 0; i < 16; i += 2 {
				o.Names[i] = fmt.Sprint(i)
			}
		}
		if print == "" && typ != "uimm32" && typ != "simm32" {
			return o, fmt.Errorf("unknown operand class %q", typ)
		}
		if typ == "simm32" {
			o.Signed = true
		}
	}
	return o, nil
}
func profiles(records map[string]record, instances map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, id := range instances["ProcessorModel"] {
		r := records[id]
		name := str(r["Name"])
		if name == "" {
			continue
		}
		var refs []reference
		_ = json.Unmarshal(r["Features"], &refs)
		for _, f := range refs {
			out[name] = append(out[name], f.Def)
		}
		if out[name] == nil {
			out[name] = []string{}
		}
	}
	return out
}

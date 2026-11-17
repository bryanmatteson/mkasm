package codec

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var tableGenOperand = regexp.MustCompile(`\$\{([[:alnum:]_]+)(?::[^}]+)?\}|\$([[:alnum:]_]+)`)

// ParseTableGen imports resolved --dump-json output, never TableGen source text.
// Architecture adapters supply operand transforms and instruction framing that
// the declarative Inst bits alone cannot specify. Unrepresentable real records
// are reported explicitly; pseudo instructions are not machine encodings.
func ParseTableGen(r io.Reader, options TableGenOptions) (*Catalog, error) {
	var records map[string]json.RawMessage
	d := json.NewDecoder(r)
	if err := d.Decode(&records); err != nil {
		return nil, fmt.Errorf("TableGen JSON: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("TableGen JSON: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(records["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("TableGen JSON missing !instanceof: %w", err)
	}
	ids, ok := instances["Instruction"]
	if !ok {
		return nil, fmt.Errorf("TableGen JSON has no Instruction records")
	}
	sort.Strings(ids)
	c := &Catalog{Schema: Schema, Architecture: options.Architecture, Source: "LLVM TableGen --dump-json"}
	for _, id := range ids {
		var record map[string]any
		if err := json.Unmarshal(records[id], &record); err != nil {
			return nil, fmt.Errorf("TableGen record %s: %w", id, err)
		}
		if number(record["isPseudo"]) != 0 || number(record["isAsmParserOnly"]) != 0 || record["Namespace"] == "TargetOpcode" {
			continue
		}
		asm, _ := record["AsmString"].(string)
		if asm == "" {
			continue
		}
		e, err := tableGenEncoding(id, record, options)
		if err != nil {
			c.Unsupported = append(c.Unsupported, Unsupported{id, err.Error()})
			continue
		}
		c.Encodings = append(c.Encodings, e)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func number(v any) int {
	if n, ok := v.(float64); ok {
		return int(n)
	}
	return 0
}
func defName(v any) string {
	if m, ok := v.(map[string]any); ok {
		s, _ := m["def"].(string)
		return s
	}
	return ""
}

func tableGenEncoding(id string, record map[string]any, opts TableGenOptions) (Encoding, error) {
	inst, ok := record["Inst"].([]any)
	if !ok || len(inst) == 0 || len(inst)%8 != 0 {
		return Encoding{}, fmt.Errorf("missing or non-byte Inst bits")
	}
	n := number(record["Size"])
	if n == 0 {
		n = len(inst) / 8
	}
	if n < 0 || n*8 > len(inst) || n > 256 || opts.WordBytes < 0 || (opts.WordBytes > 0 && n%opts.WordBytes != 0) {
		return Encoding{}, fmt.Errorf("Inst/Size mismatch")
	}
	e := Encoding{ID: id, Mask: make([]byte, n), Value: make([]byte, n)}
	e.Effects = tableGenEffects(record)
	if number(record["hasDelaySlot"]) != 0 {
		e.DelaySlots = 1
	}
	classes := map[string]string{}
	var order []string
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		if dag, ok := record[key].(map[string]any); ok {
			if args, ok := dag["args"].([]any); ok {
				for _, a := range args {
					pair, ok := a.([]any)
					if !ok || len(pair) != 2 {
						continue
					}
					name, _ := pair[1].(string)
					if _, exists := classes[name]; !exists {
						order = append(order, name)
					}
					classes[name] = defName(pair[0])
				}
			}
		}
	}
	operands := map[string]*Operand{}
	for bit := 0; bit < n*8; bit++ {
		physical := bit
		if !opts.LittleEndian {
			physical = (n-1-bit/8)*8 + bit%8
		} else if opts.WordBytes > 0 && n > opts.WordBytes {
			word := bit / (opts.WordBytes * 8)
			physical = (n/opts.WordBytes-1-word)*opts.WordBytes*8 + bit%(opts.WordBytes*8)
		}
		v := inst[bit]
		if num, ok := v.(float64); ok {
			if num != 0 && num != 1 {
				return Encoding{}, fmt.Errorf("invalid fixed bit")
			}
			e.Mask[physical/8] |= 1 << uint(physical%8)
			if num == 1 {
				e.Value[physical/8] |= 1 << uint(physical%8)
			}
			continue
		}
		if v == nil {
			e.Mask[physical/8] |= 1 << uint(physical%8)
			continue
		}
		ref, ok := v.(map[string]any)
		if !ok {
			return Encoding{}, fmt.Errorf("unresolved Inst bit %d", bit)
		}
		name, _ := ref["var"].(string)
		kind, _ := ref["kind"].(string)
		if name == "" || (kind != "varbit" && kind != "var") {
			return Encoding{}, fmt.Errorf("unresolved Inst bit %d", bit)
		}
		o := operands[name]
		if o == nil {
			o = &Operand{Name: name, Class: classes[name], Kind: "immediate"}
			operands[name] = o
			if _, exists := classes[name]; !exists {
				order = append(order, name)
			}
		}
		o.Bits = append(o.Bits, BitSlice{InstructionBit: physical, ValueBit: number(ref["index"]), Width: 1})
	}
	for _, name := range order {
		if o := operands[name]; o != nil {
			e.Operands = append(e.Operands, *o)
			delete(operands, name)
		}
	}
	asm, _ := record["AsmString"].(string)
	// LLVM's escaped dollar is a literal register sigil, not a placeholder.
	asm = strings.ReplaceAll(asm, "$$", "\x00")
	e.Syntax = tableGenOperand.ReplaceAllStringFunc(asm, func(s string) string {
		m := tableGenOperand.FindStringSubmatch(s)
		name := m[1]
		if name == "" {
			name = m[2]
		}
		return "{" + name + "}"
	})
	e.Syntax = strings.ReplaceAll(e.Syntax, "\x00", "$")
	e.Syntax = strings.Join(strings.Fields(e.Syntax), " ")
	if strings.Contains(e.Syntax, "|") {
		return Encoding{}, fmt.Errorf("unresolved assembly dialect alternatives")
	}
	fields := strings.Fields(e.Syntax)
	if len(fields) == 0 {
		return Encoding{}, fmt.Errorf("empty assembly syntax")
	}
	e.Mnemonic = fields[0]
	if predicates, ok := record["Predicates"].([]any); ok {
		for _, p := range predicates {
			if name := defName(p); name != "" {
				e.Features = append(e.Features, name)
				e.SourcePredicates = append(e.SourcePredicates, name)
			}
		}
	}
	switch {
	case number(record["isReturn"]) != 0:
		e.FlowControl = "return"
	case number(record["isCall"]) != 0:
		e.FlowControl = "call"
	case number(record["isConditionalBranch"]) != 0:
		e.FlowControl = "conditional_branch"
	case number(record["isBranch"]) != 0:
		e.FlowControl = "branch"
	default:
		e.FlowControl = "next"
	}
	for _, hole := range syntaxHoles(e.Syntax) {
		found := false
		for _, o := range e.Operands {
			if o.Name == hole {
				found = true
				break
			}
		}
		if !found {
			return Encoding{}, fmt.Errorf("syntax operand %s has no declarative encoding", hole)
		}
	}
	return e, nil
}

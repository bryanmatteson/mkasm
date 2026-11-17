// Package avr imports the AVR target's LLVM TableGen JSON instruction records.
package avr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Parse reads llvm-tblgen --dump-json output for AVR.td. LLVM's AVR encoder
// contains two addressing-mode postprocessors; these are expanded into fixed
// pointer variants before importing the ordinary instruction bit descriptions.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	if architecture != "avr" {
		return nil, fmt.Errorf("avr: unsupported architecture %q", architecture)
	}
	var records map[string]any
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("avr: decode TableGen JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("avr: trailing input after TableGen JSON")
	}
	if err := expandAddressing(records); err != nil {
		return nil, err
	}
	if err := expandAliases(records); err != nil {
		return nil, err
	}
	data, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	c, err := codec.ParseTableGen(bytes.NewReader(data), codec.TableGenOptions{Architecture: architecture, LittleEndian: true, WordBytes: 2})
	if err != nil {
		return nil, err
	}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		record, _ := records[e.ID].(map[string]any)
		if priority, exists := record["EmitPriority"].(float64); exists && priority == 0 {
			e.AssemblyOnly = true
		}
		classes := operandClasses(record)
		for j := range e.Operands {
			o := &e.Operands[j]
			class := classes[o.Name]
			if class == "" {
				class = o.Class
			}
			applyOperandClass(o, class)
		}
	}
	c.Encodings = expandTinyRegisters(c.Encodings)
	c.FeatureSets = deviceFeatureSets(records, c.Encodings)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Reduced-core Tiny devices physically omit r0-r15. LLVM enforces this in its
// assembly parser rather than its GPR8 TableGen class. Split those forms by
// device encoding so the generated codec enforces the same register domain.
func expandTinyRegisters(encodings []codec.Encoding) []codec.Encoding {
	var out []codec.Encoding
	for _, e := range encodings {
		classic := false
		for _, f := range e.Features {
			if f == "HasNonTinyEncoding" {
				classic = true
			}
		}
		restrict := false
		for _, o := range e.Operands {
			if o.Class == "GPR8" {
				restrict = true
			}
		}
		if classic || !restrict {
			out = append(out, e)
			continue
		}
		tiny := e
		tiny.ID += "_Tiny"
		tiny.Features = append(append([]string{}, e.Features...), "HasTinyEncoding")
		tiny.Operands = append([]codec.Operand{}, e.Operands...)
		for i, o := range tiny.Operands {
			if o.Class != "GPR8" {
				continue
			}
			names := append([]string{}, o.Names...)
			for n := 0; n < 16 && n < len(names); n++ {
				names[n] = ""
			}
			tiny.Operands[i].Names = names
		}
		e.Features = append(append([]string{}, e.Features...), "HasNonTinyEncoding")
		out = append(out, e, tiny)
	}
	return out
}

// Device profiles are derived from LLVM Processor records and their transitive
// SubtargetFeature implications. Predicate evaluation preserves negative
// conditions such as HasNonTinyEncoding rather than treating them as features.
func deviceFeatureSets(records map[string]any, encodings []codec.Encoding) map[string][]string {
	instances, _ := records["!instanceof"].(map[string]any)
	processors, _ := instances["Processor"].([]any)
	if len(processors) == 0 {
		return nil
	}
	required := map[string]bool{}
	for _, e := range encodings {
		for _, f := range e.Features {
			required[f] = true
		}
	}
	profiles := map[string][]string{}
	for _, id := range processors {
		key, _ := id.(string)
		processor, _ := records[key].(map[string]any)
		name, _ := processor["Name"].(string)
		if name == "" {
			continue
		}
		enabled := map[string]bool{}
		var enable func(string)
		enable = func(feature string) {
			if enabled[feature] {
				return
			}
			enabled[feature] = true
			record, _ := records[feature].(map[string]any)
			implies, _ := record["Implies"].([]any)
			for _, implied := range implies {
				if ref, ok := implied.(map[string]any); ok {
					if n, ok := ref["def"].(string); ok {
						enable(n)
					}
				}
			}
		}
		features, _ := processor["Features"].([]any)
		for _, feature := range features {
			if ref, ok := feature.(map[string]any); ok {
				if n, ok := ref["def"].(string); ok {
					enable(n)
				}
			}
		}
		predicates := []string{}
		for predicate := range required {
			record, _ := records[predicate].(map[string]any)
			if featureCondition(record["AssemblerCondDag"], enabled) {
				predicates = append(predicates, predicate)
			}
		}
		sort.Strings(predicates)
		profiles[name] = predicates
	}
	return profiles
}

func featureCondition(value any, enabled map[string]bool) bool {
	node, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if name, ok := node["def"].(string); ok {
		return enabled[name]
	}
	op, _ := node["operator"].(map[string]any)
	name, _ := op["def"].(string)
	args, _ := node["args"].([]any)
	all, anyMatch := true, false
	for _, arg := range args {
		pair, _ := arg.([]any)
		if len(pair) == 0 {
			return false
		}
		match := featureCondition(pair[0], enabled)
		all, anyMatch = all && match, anyMatch || match
	}
	switch name {
	case "all_of":
		return all
	case "any_of":
		return anyMatch
	case "not":
		return len(args) == 1 && !anyMatch
	}
	return false
}

func applyOperandClass(o *codec.Operand, class string) {
	width := 0
	for _, b := range o.Bits {
		if n := b.ValueBit + b.Width; n > width {
			width = n
		}
	}
	switch class {
	case "GPR8", "GPR8lo", "GPR8NOZ":
		o.Kind, o.RegisterPrefix, o.Names = "register", "r", registers(0, 1, 1<<width)
	case "LD8", "LD8lo":
		o.Kind, o.RegisterPrefix, o.Names = "register", "r", registers(16, 1, 1<<width)
	case "DREGS", "DREGSMOVW", "DREGSlo":
		o.Kind, o.RegisterPrefix, o.Names = "register", "r", registers(0, 2, 1<<width)
		o.RegisterAliases = pairAliases(0, 1<<width)
	case "IWREGS":
		o.Kind, o.RegisterPrefix, o.Names = "register", "r", registers(24, 2, 1<<width)
		o.RegisterAliases = pairAliases(24, 1<<width)
	case "DLDREGS", "DREGSLD8lo":
		o.Kind, o.RegisterPrefix, o.Names = "register", "r", registers(16, 2, 1<<width)
		o.RegisterAliases = pairAliases(16, 1<<width)
	case "relbrtarget_7", "brtarget_13", "rcalltarget_13":
		o.Kind, o.Signed, o.Scale, o.Relative, o.PCBias = "displacement", true, 2, true, 2
	case "call_target":
		o.Kind, o.Scale = "address", 2
	case "imm16", "imm7tiny":
		o.Kind = "address"
	case "imm_com8":
		o.Xor = 255
	}
}

func pairAliases(start, count int) map[string]int64 {
	aliases := map[string]int64{}
	for i := 0; i < count; i++ {
		lo := start + 2*i
		aliases[fmt.Sprintf("r%d:r%d", lo+1, lo)] = int64(i)
		if lo >= 26 {
			aliases[[]string{"X", "Y", "Z"}[(lo-26)/2]] = int64(i)
		}
	}
	return aliases
}

func registers(start, step, count int) []string {
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("r%d", start+i*step)
	}
	return names
}

func operandClasses(record map[string]any) map[string]string {
	classes := map[string]string{}
	for _, field := range []string{"OutOperandList", "InOperandList"} {
		dag, _ := record[field].(map[string]any)
		args, _ := dag["args"].([]any)
		for _, arg := range args {
			pair, _ := arg.([]any)
			if len(pair) != 2 {
				continue
			}
			def, _ := pair[0].(map[string]any)
			name, _ := pair[1].(string)
			class, _ := def["def"].(string)
			classes[name] = class
		}
	}
	return classes
}

func expandAddressing(records map[string]any) error {
	instances, _ := records["!instanceof"].(map[string]any)
	instructions, ok := instances["Instruction"].([]any)
	if !ok {
		return fmt.Errorf("avr: missing TableGen Instruction records")
	}
	var expanded []any
	for _, id := range instructions {
		name, _ := id.(string)
		record, _ := records[name].(map[string]any)
		if record == nil {
			return fmt.Errorf("avr: missing instruction %s", name)
		}
		classes := operandClasses(record)
		asm, _ := record["AsmString"].(string)
		for operand, class := range classes {
			if class == "ZREG" {
				asm = replaceOperand(asm, operand, "Z")
			}
		}
		record["AsmString"] = asm
		post, _ := record["PostEncoderMethod"].(string)
		if post == "loadStorePostEncoder" {
			bits, _ := record["Inst"].([]any)
			if len(bits) != 16 {
				return fmt.Errorf("avr: %s: invalid load/store width", name)
			}
			mode0, _ := bits[0].(float64)
			mode1, _ := bits[1].(float64)
			for _, p := range []struct {
				name string
				code int
			}{{"X", 12}, {"Y", 8}, {"Z", 0}} {
				variant := clone(record)
				inst := append([]any(nil), bits...)
				inst[2], inst[3] = (p.code>>2)&1, (p.code>>3)&1
				inst[12] = 0
				if mode0 != 0 || mode1 != 0 || p.name == "X" {
					inst[12] = 1
				}
				variant["Inst"] = inst
				variant["AsmString"] = replaceOperand(asm, "ptrreg", p.name)
				variant["PostEncoderMethod"] = ""
				newName := name + "_" + p.name
				variant["!name"] = newName
				records[newName] = variant
				expanded = append(expanded, newName)
			}
			continue
		}
		if name == "LDDRdPtrQ" || name == "STDPtrQRr" {
			bits, _ := record["Inst"].([]any)
			for _, p := range []struct {
				name string
				code int
			}{{"Z", 0}, {"Y", 1}} {
				variant := clone(record)
				inst := append([]any(nil), bits...)
				for i, bit := range inst {
					ref, _ := bit.(map[string]any)
					if ref["var"] == "memri" && ref["index"] == float64(6) {
						inst[i] = p.code
					}
				}
				variant["Inst"] = inst
				variant["AsmString"] = replaceOperand(asm, "memri", p.name+"+$memri")
				newName := name + "_" + p.name
				variant["!name"] = newName
				records[newName] = variant
				expanded = append(expanded, newName)
			}
			continue
		}
		expanded = append(expanded, id)
	}
	instances["Instruction"] = expanded
	return nil
}

func clone(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// LLVM InstAlias ResultInst operands may be constants, renamed operands, or
// repeated operands (e.g. CLR rd -> EOR rd,rd). Resolve all three directly into
// Inst bits so aliases use the same checked codec as ordinary machine forms.
func expandAliases(records map[string]any) error {
	instances := records["!instanceof"].(map[string]any)
	aliases, _ := instances["InstAlias"].([]any)
	instructions := instances["Instruction"].([]any)
	for _, id := range aliases {
		name, _ := id.(string)
		alias, _ := records[name].(map[string]any)
		result, _ := alias["ResultInst"].(map[string]any)
		op, _ := result["operator"].(map[string]any)
		target, _ := op["def"].(string)
		base, _ := records[target].(map[string]any)
		if base == nil {
			return fmt.Errorf("avr: alias %s has missing target %s", name, target)
		}
		bits, _ := base["Inst"].([]any)
		if len(bits) == 0 {
			return fmt.Errorf("avr: alias %s targets a non-machine instruction", name)
		}
		encoded := map[string]bool{}
		for _, bit := range bits {
			if ref, ok := bit.(map[string]any); ok {
				if v, ok := ref["var"].(string); ok {
					encoded[v] = true
				}
			}
		}
		var ordered []string
		seen := map[string]bool{}
		for _, field := range []string{"OutOperandList", "InOperandList"} {
			dag, _ := base[field].(map[string]any)
			args, _ := dag["args"].([]any)
			for _, arg := range args {
				pair, _ := arg.([]any)
				if len(pair) != 2 {
					continue
				}
				n, _ := pair[1].(string)
				if encoded[n] && !seen[n] {
					ordered = append(ordered, n)
					seen[n] = true
				}
			}
		}
		args, _ := result["args"].([]any)
		if len(args) != len(ordered) {
			return fmt.Errorf("avr: alias %s operand count %d differs from machine fields %d", name, len(args), len(ordered))
		}
		mapping := map[string][]any{}
		for i, arg := range args {
			pair, _ := arg.([]any)
			if len(pair) != 2 {
				return fmt.Errorf("avr: malformed alias %s operand", name)
			}
			mapping[ordered[i]] = pair
		}
		variant := clone(base)
		inst := append([]any(nil), bits...)
		for i, bit := range inst {
			ref, ok := bit.(map[string]any)
			if !ok {
				continue
			}
			old, _ := ref["var"].(string)
			pair := mapping[old]
			if pair == nil {
				return fmt.Errorf("avr: alias %s unresolved field %s", name, old)
			}
			if n, ok := pair[0].(float64); ok {
				index, _ := ref["index"].(float64)
				inst[i] = (int64(n) >> uint(index)) & 1
				continue
			}
			newName, _ := pair[1].(string)
			if newName == "" {
				return fmt.Errorf("avr: alias %s unnamed field", name)
			}
			newRef := clone(ref)
			newRef["var"] = newName
			inst[i] = newRef
		}
		variant["Inst"], variant["AsmString"], variant["!name"] = inst, alias["AsmString"], name
		variant["EmitPriority"] = alias["EmitPriority"]
		variant["OutOperandList"] = map[string]any{"args": []any{}}
		variant["InOperandList"] = map[string]any{"args": args}
		records[name] = variant
		instructions = append(instructions, name)
	}
	instances["Instruction"] = instructions
	return nil
}

func replaceOperand(s, name, value string) string {
	s = strings.ReplaceAll(s, "${"+name+"}", value)
	return strings.ReplaceAll(s, "$"+name, value)
}

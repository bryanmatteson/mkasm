// Package powerpc imports resolved LLVM PowerPC TableGen instruction records.
package powerpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]any

func object(v any) record {
	if m, ok := v.(record); ok {
		return m
	}
	m, _ := v.(map[string]any)
	return m
}
func list(v any) []any    { a, _ := v.([]any); return a }
func str(v any) string    { s, _ := v.(string); return s }
func num(v any) int       { n, _ := v.(float64); return int(n) }
func def(v any) string    { return str(object(v)["def"]) }
func args(v any) []any    { return list(object(v)["args"]) }
func ref(s string) record { return record{"def": s, "kind": "def"} }

// Parse accepts llvm-tblgen --dump-json output generated from PPC.td. Both
// instruction modes retain extension predicates; DecodeWithFeatures and
// AssembleWithFeatures can select a concrete CPU's enabled extensions.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	switch architecture {
	case "powerpc32", "powerpc64", "powerpc32le", "powerpc64le":
	default:
		return nil, fmt.Errorf("powerpc: unsupported architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("powerpc TableGen JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("powerpc: trailing JSON input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("powerpc: missing TableGen instances: %w", err)
	}
	records := map[string]record{}
	get := func(name string) record {
		if m, ok := records[name]; ok {
			return m
		}
		var m record
		_ = json.Unmarshal(raw[name], &m)
		records[name] = m
		return m
	}
	rejected := expandAliases(raw, instances, get)
	for _, id := range instances["Instruction"] {
		m := get(id)
		if num(m["isPseudo"]) != 0 || num(m["isAsmParserOnly"]) != 0 || str(m["AsmString"]) == "" {
			continue
		}
		skip := false
		for _, superclass := range list(m["!superclasses"]) {
			if str(superclass) == "PPCEmitTimePseudo" {
				skip = true
			}
		}
		if strings.Contains(str(m["AsmString"]), "\n") {
			skip = true
		}
		for _, p := range list(m["Predicates"]) {
			if def(p) == "IsPPC64" && !strings.Contains(architecture, "64") || def(p) == "IsPPC32" && strings.Contains(architecture, "64") {
				skip = true
			}
		}
		if skip {
			delete(raw, id)
			m["isPseudo"] = float64(1)
			raw[id], _ = json.Marshal(m)
			continue
		}
		// PPC's isLittleEndianEncoding=0 makes the JSON Inst array MSB-first.
		inst := list(m["Inst"])
		for i, j := 0, len(inst)-1; i < j; i, j = i+1, j-1 {
			inst[i], inst[j] = inst[j], inst[i]
		}
		if n := num(m["Size"]); n != 4 && n != 8 {
			rejected = append(rejected, codec.Unsupported{ID: id, Reason: "compiler expansion is not a single 4-byte or prefixed 8-byte instruction"})
			m["isPseudo"] = float64(1)
		}
		asm := str(m["AsmString"])
		switch id {
		case "EVFSCTUF", "EVFSCTUIZ":
			// PPCInstrSPE.td prints the signed conversion mnemonic for these
			// unsigned physical opcodes. Keep both instructions distinct.
			asm = "enc[" + id + "] $RT, $RB"
		case "EVSEL":
			// The source printer contains literal crD instead of $crD.
			asm = "enc[EVSEL] $RT, $RA, $RB, $crD"
		case "MFTB":
			// LLVM rewrites MFTB to MFSPR on newer CPUs. The exact
			// spelling retains this legacy instruction's physical identity.
			asm = "enc[" + id + "] " + asm
		case "TAILBA", "TAILBA8":
			asm = "enc[" + id + "] $LI"
		}
		if id == "WAITP10" {
			asm = "wait $L, $PL"
		}
		for _, key := range []string{"OutOperandList", "InOperandList"} {
			dag := object(m[key])
			var flat []any
			for _, a := range args(dag) {
				pair := list(a)
				if len(pair) != 2 {
					continue
				}
				operand := object(pair[0])
				name := str(pair[1])
				if str(operand["kind"]) != "dag" {
					flat = append(flat, a)
					continue
				}
				class := def(operand["operator"])
				members := args(get(class)["MIOperandInfo"])
				children := args(operand)
				if len(children) != len(members) || len(children) == 0 {
					rejected = append(rejected, codec.Unsupported{ID: id, Reason: "composite operand " + class + " requires non-declarative assembly lowering"})
					m["isPseudo"] = float64(1)
					continue
				}
				names := make([]string, len(children))
				for i, child := range children {
					cp := list(child)
					mp := list(members[i])
					names[i] = str(cp[1])
					flat = append(flat, []any{mp[0], names[i]})
				}
				if class == "pred" {
					// The compiler predicate packs BO and BI's low two bits in
					// BIBO, with CR supplying BI's upper three bits. Its custom
					// printer cannot be represented by a literal mnemonic, so
					// expose both original fields in an exact source spelling.
					asm = "enc[" + id + "] $" + strings.Join(names, ", $")
					for _, other := range args(dag) {
						p := list(other)
						if len(p) == 2 && str(p[1]) != name {
							asm += ", $" + str(p[1])
						}
					}
					continue
				}
				replacement := "$" + names[0]
				switch class {
				case "memrr":
					replacement += ", $" + names[1]
				case "memr":
				default:
					if len(names) == 2 {
						replacement += "($" + names[1] + ")"
					}
				}
				asm = strings.ReplaceAll(asm, "$"+name, replacement)
			}
			dag["args"] = flat
		}
		m["AsmString"] = asm
		raw[id], _ = json.Marshal(m)
	}
	prepared, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	c, err := codec.ParseTableGen(bytes.NewReader(prepared), codec.TableGenOptions{Architecture: architecture, LittleEndian: strings.HasSuffix(architecture, "le"), WordBytes: 4})
	if err != nil {
		return nil, err
	}
	c.Unsupported = append(c.Unsupported, rejected...)
	var encodings []codec.Encoding
	for _, e := range c.Encodings {
		if e.ID == "TAILBA" || e.ID == "TAILBA8" {
			// Compiler tail-call annotations do not change this instruction's
			// physical unconditional relative branch or its target calculation.
			e.FlowControl = "branch"
		}
		if strings.HasPrefix(architecture, "powerpc32") && (e.FlowControl == "branch" || e.FlowControl == "call" || e.FlowControl == "conditional_branch") {
			e.TargetMask = 0xffffffff
		}
		failure := ""
		for i := range e.Operands {
			o := &e.Operands[i]
			cl := get(o.Class)
			if err := configure(o, cl, get, architecture); err != nil {
				failure = err.Error()
				break
			}
			if (e.ID == "TAILBA" || e.ID == "TAILBA8") && o.Name == "LI" {
				// IForm<18,0,0> has AA=0: the encoded target is relative,
				// regardless of the compiler record's abscalltarget class.
				o.Kind, o.Relative, o.InputSignedBits = "displacement", true, 0
				if strings.HasPrefix(architecture, "powerpc32") {
					o.PCWrapBits = 32
				}
			}
		}
		if failure != "" {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: e.ID, Reason: failure})
			continue
		}
		if e.ID == "MFTB" || strings.HasPrefix(e.Syntax, "enc[alias_") && strings.Contains(e.Syntax, " mftb") {
			// PPCAsmParser.cpp rewrites MFTB's XO=371 to MFSPR's XO=339
			// when FeatureMFTB is enabled. Preserve that ordinary LLVM
			// dialect alongside the exact legacy instruction and aliases.
			modern := e
			modern.ID += "_modern_mfspr"
			modern.Syntax = strings.TrimPrefix(e.Syntax, "enc["+e.ID+"] ")
			modern.Mnemonic = strings.Fields(modern.Syntax)[0]
			modern.AssemblyOnly = true
			modern.Value = append([]byte(nil), e.Value...)
			index := 3
			if strings.HasSuffix(architecture, "le") {
				index = 0
			}
			modern.Value[index] ^= 0x40
			encodings = append(encodings, modern)
		}
		// PowerPC's lexer treats a minus immediately after the mnemonic as a
		// branch hint. Parentheses disambiguate DQUAI's first signed immediate.
		// Keep ordinary bare syntax available to the assembler as an alias.
		if strings.HasPrefix(e.ID, "DQUAI") {
			bare := e
			bare.ID += "_bare_syntax"
			bare.AssemblyOnly = true
			first := strings.Index(e.Syntax, "{")
			last := strings.Index(e.Syntax, "}")
			if first >= 0 && last > first {
				e.Syntax = e.Syntax[:first] + "(" + e.Syntax[first:last+1] + ")" + e.Syntax[last+1:]
			}
			encodings = append(encodings, e, bare)
			continue
		}
		encodings = append(encodings, e)
		// GNU-compatible addis/lis syntax accepts every 17-bit signed input,
		// truncating to the low 16 bits. Preserve canonical signed decoding
		// while admitting the extra positive and negative textual ranges.
		for index, operand := range e.Operands {
			if operand.Class != "s17imm" && operand.Class != "s17imm64" {
				continue
			}
			for _, bias := range []int64{0, -65536} {
				alternate := e
				alternate.ID += fmt.Sprintf("_gnu_s17_%d", bias)
				alternate.Operands = append([]codec.Operand(nil), e.Operands...)
				alternate.Operands[index].Signed = false
				alternate.Operands[index].Bias = bias
				encodings = append(encodings, alternate)
			}
		}
	}
	c.Encodings = encodings
	sort.Slice(c.Unsupported, func(i, j int) bool { return c.Unsupported[i].ID < c.Unsupported[j].ID })
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func configure(o *codec.Operand, cl record, get func(string) record, architecture string) error {
	class := o.Class
	if class == "" {
		return fmt.Errorf("operand %s lacks source class", o.Name)
	}
	switch class {
	case "directbrtarget", "condbrtarget", "calltarget":
		o.Kind = "displacement"
		o.Signed = true
		o.Scale = 4
		o.Relative = true
		if strings.HasPrefix(architecture, "powerpc32") {
			o.PCWrapBits = 32
		}
		return nil
	case "absdirectbrtarget", "abscondbrtarget", "abscalltarget":
		o.Kind = "address"
		o.Signed = true
		o.Scale = 4
		if strings.HasPrefix(architecture, "powerpc32") {
			o.InputSignedBits = 32
		}
		return nil
	case "dispRIX":
		o.Kind = "displacement"
		o.Signed = true
		o.Scale = 4
		return nil
	case "dispRIX16":
		o.Kind = "displacement"
		o.Signed = true
		o.Scale = 16
		return nil
	case "dispRIHash":
		o.Kind = "displacement"
		o.Scale = 8
		o.Bias = -512
		return nil
	case "dispSPE8":
		o.Kind = "displacement"
		o.Scale = 8
		return nil
	case "dispSPE4":
		o.Kind = "displacement"
		o.Scale = 4
		return nil
	case "dispSPE2":
		o.Kind = "displacement"
		o.Scale = 2
		return nil
	case "dispRI", "dispRI34", "dispRI34_pcrel":
		o.Kind = "displacement"
		o.Signed = true
		return nil
	case "crbitm":
		o.Names = make([]string, 256)
		o.RegisterAliases = map[string]int64{}
		for i := 0; i < 8; i++ {
			v := 1 << uint(7-i)
			o.Names[v] = strconv.Itoa(v)
			o.RegisterAliases[fmt.Sprintf("cr%d", i)] = int64(v)
		}
		return nil
	case "immZero":
		o.Names = []string{"0"}
		return nil
	case "tlsreg", "tlsreg32", "tlsgd", "tlsgd32", "tlscall", "tlscall32", "tocentry", "tocentry32":
		return fmt.Errorf("operand %s requires relocation/symbol context", class)
	}
	if strings.HasPrefix(class, "s") && strings.Contains(class, "imm") {
		o.Signed = true
		return nil
	}
	if strings.HasPrefix(class, "u") && strings.Contains(class, "imm") || class == "i32imm" || class == "i64imm" || class == "i1imm" {
		return nil
	}
	regclass := def(cl["RegClass"])
	if class == "ptr_rc_nor0" || class == "ptr_rc_idx" {
		if strings.Contains(architecture, "64") {
			if class == "ptr_rc_nor0" {
				regclass = "G8RC_NOX0"
			} else {
				regclass = "G8RC"
			}
		} else {
			if class == "ptr_rc_nor0" {
				regclass = "GPRC_NOR0"
			} else {
				regclass = "GPRC"
			}
		}
	}
	if regclass == "" && get(class)["MemberList"] != nil {
		regclass = class
	}
	if regclass == "" {
		return fmt.Errorf("unmodeled operand class %s", class)
	}
	regs, err := registers(ref(regclass), get, 0)
	if err != nil {
		return err
	}
	o.Kind = "register"
	o.RegisterAliases = map[string]int64{}
	o.Names = make([]string, 1<<uint(o.Width()))
	if class == "vsrprc" {
		o.Scale = 2
	}
	for _, reg := range regs {
		rr := get(reg)
		bits := list(rr["HWEncoding"])
		value := 0
		for i, b := range bits {
			value |= num(b) << uint(i)
		}
		if class == "vsrpevenrc" {
			value *= 2
		}
		value &= len(o.Names) - 1
		name := str(rr["AsmName"])
		numeric := strings.TrimLeft(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
		if class == "vsrprc" || class == "vsrpevenrc" {
			numeric = strconv.Itoa(value)
			if class == "vsrprc" {
				numeric = strconv.Itoa(value * 2)
			}
		}
		if numeric == "" {
			numeric = strconv.Itoa(value)
		}
		// LLVM's default PowerPC syntax prints register numbers, accepting names
		// through the aliases map. Preserve named condition fields for readability.
		if class == "crrc" {
			numeric = name
		}
		if class == "vsrc" || class == "vsfrc" || class == "vssrc" {
			numeric = strconv.Itoa(value)
		}
		if o.Names[value] == "" {
			o.Names[value] = numeric
		}
		o.RegisterAliases[name] = int64(value)
		o.RegisterAliases["%"+name] = int64(value)
		o.RegisterAliases[strconv.Itoa(value)] = int64(value)
	}
	return nil
}

func registers(v any, get func(string) record, depth int) ([]string, error) {
	if depth > 20 {
		return nil, fmt.Errorf("recursive register class")
	}
	m := object(v)
	if name := def(m); name != "" {
		r := get(name)
		if r["HWEncoding"] != nil {
			return []string{name}, nil
		}
		if r["MemberList"] != nil {
			return registers(r["MemberList"], get, depth+1)
		}
		return nil, fmt.Errorf("unsupported register class %s", name)
	}
	a := args(m)
	op := def(m["operator"])
	if op == "sequence" && len(a) >= 3 {
		pattern := strings.ReplaceAll(str(list(a[0])[0]), "%u", "%d")
		start, end := num(list(a[1])[0]), num(list(a[2])[0])
		step := 1
		if start > end {
			step = -1
		}
		var out []string
		for i := start; ; i += step {
			out = append(out, fmt.Sprintf(pattern, i))
			if i == end {
				break
			}
		}
		return out, nil
	}
	if op == "add" || op == "sub" {
		var out []string
		for i, arg := range a {
			set, err := registers(list(arg)[0], get, depth+1)
			if err != nil {
				return nil, err
			}
			if op == "sub" && i > 0 {
				remove := map[string]bool{}
				for _, s := range set {
					remove[s] = true
				}
				filtered := out[:0]
				for _, s := range out {
					if !remove[s] {
						filtered = append(filtered, s)
					}
				}
				out = filtered
			} else {
				out = append(out, set...)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported register set expression %s", op)
}

// Package hexagon imports LLVM Hexagon instruction records and implements the
// packet framing absent from their individual TableGen Inst bit descriptions.
package hexagon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Metadata struct {
	Type          string   `json:"type"`
	SubGroup      string   `json:"sub_group,omitempty"`
	Extendable    bool     `json:"extendable,omitempty"`
	MustExtend    bool     `json:"must_extend,omitempty"`
	ExtendOperand string   `json:"extend_operand,omitempty"`
	ExtentBits    int      `json:"extent_bits,omitempty"`
	ExtentAlign   int      `json:"extent_align,omitempty"`
	ExtentSigned  bool     `json:"extent_signed,omitempty"`
	NewValueUse   string   `json:"new_value_use,omitempty"`
	Producers     []string `json:"producers,omitempty"`
	Vector        bool     `json:"vector,omitempty"`
	Solo          bool     `json:"solo,omitempty"`
}
type Catalog struct {
	Schema          string              `json:"schema"`
	Architecture    string              `json:"architecture"`
	Source          string              `json:"source"`
	Words           *codec.Catalog      `json:"words"`
	Subinstructions *codec.Catalog      `json:"subinstructions"`
	Metadata        map[string]Metadata `json:"metadata"`
	FeatureSets     map[string][]string `json:"feature_sets,omitempty"`
	Unsupported     []codec.Unsupported `json:"unsupported,omitempty"`
}

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }

type namedOperand struct{ name, class string }

func operands(r map[string]any) []namedOperand {
	var out []namedOperand
	for _, f := range []string{"OutOperandList", "InOperandList"} {
		dag, _ := r[f].(map[string]any)
		args, _ := dag["args"].([]any)
		for _, a := range args {
			p, _ := a.([]any)
			if len(p) != 2 {
				continue
			}
			n, _ := p[1].(string)
			d, _ := p[0].(map[string]any)
			cls, _ := d["def"].(string)
			out = append(out, namedOperand{n, cls})
		}
	}
	return out
}
func number(v any) int {
	if n, ok := v.(float64); ok {
		return int(n)
	}
	bits, _ := v.([]any)
	n := 0
	for i, b := range bits {
		if b == float64(1) {
			n |= 1 << uint(i)
		}
	}
	return n
}
func def(v any) string { r, _ := v.(map[string]any); s, _ := r["def"].(string); return s }

var tiedRE = regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)
var asmOperandRE = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)
var immediateRE = regexp.MustCompile(`^([suba])(\d+)_(\d+)Imm$`)

func Parse(reader io.Reader, architecture string) (*Catalog, error) {
	if architecture != "hexagon" {
		return nil, fmt.Errorf("hexagon: unsupported architecture %s", architecture)
	}
	var records map[string]any
	d := json.NewDecoder(reader)
	if err := d.Decode(&records); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("hexagon: trailing JSON input")
	}
	instances, _ := records["!instanceof"].(map[string]any)
	ids, ok := instances["Instruction"].([]any)
	if !ok {
		return nil, fmt.Errorf("hexagon: missing LLVM Instruction records")
	}
	c := &Catalog{Schema: "mkasm.hexagon.v1", Architecture: architecture, Source: "LLVM Hexagon TableGen --dump-json", Metadata: map[string]Metadata{}}
	var wordIDs, subIDs []any
	for _, id := range ids {
		n, _ := id.(string)
		r, _ := records[n].(map[string]any)
		if r == nil {
			return nil, fmt.Errorf("missing instruction %s", n)
		}
		if r["Namespace"] != "Hexagon" || number(r["isPseudo"]) != 0 {
			continue
		}
		kind := def(r["Type"])
		if kind == "TypeDUPLEX" {
			if n == "DuplexIClassF" {
				c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: n, Reason: "reserved duplex class 15 has no legal subinstruction group pairing"})
			}
			continue
		}
		if n == "invalid_decode" || n == "HI" || n == "LO" {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: n, Reason: "LLVM internal decoder sentinel or relocation fragment; not a standalone physical instruction"})
			continue
		}
		if n == "CONST32" || n == "CONST64" {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: n, Reason: "LLVM assembler pseudo has no declarative operand encoding; requires constant-pool lowering"})
			continue
		}
		// These records deliberately have no operand fields in Inst despite
		// isPseudo=0. HexagonAsmParser::processInstruction rewrites them before
		// emission; importing their unset bits would invent a new opcode.
		if n == "TFRI64_V2_ext" || n == "TFRI64_V4" {
			if number(r["isAsmParserOnly"]) != 1 {
				return nil, fmt.Errorf("%s: expected LLVM assembler-only rewrite record", n)
			}
			bits, _ := r["Inst"].([]any)
			for _, bit := range bits {
				if field, ok := bit.(map[string]any); ok && field["var"] != nil {
					return nil, fmt.Errorf("%s: unexpected physical operand encoding in LLVM assembler-only rewrite record", n)
				}
			}
		}
		if n == "TFRI64_V2_ext" {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: n, Reason: "LLVM assembler-only rewrite to A2_combineii, not a distinct opcode; combine(##high32,#low8) is already supported by AssemblePacket; symbolic operands require complete-program object assembly"})
			continue
		}
		if n == "TFRI64_V4" {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: n, Reason: "LLVM assembler-only rewrite, not a distinct opcode: split a 64-bit constant into signed high32 (must fit int8) and unsigned low32, then emit A4_combineii with an optional A4_ext; use the physical combine form or complete-program object assembly for the register-pair constant spelling and symbolic operands"})
			continue
		}
		bits, _ := r["Inst"].([]any)
		if len(bits) != 32 {
			return nil, fmt.Errorf("%s: expected 32 Inst bits", n)
		}
		if kind != "TypeSUBINSN" {
			bits[14], bits[15] = float64(1), float64(1)
		}
		encoded := map[string]bool{}
		for _, b := range bits {
			if ref, ok := b.(map[string]any); ok {
				v, _ := ref["var"].(string)
				encoded[v] = true
			}
		}
		aliases := map[string]string{}
		constraint, _ := r["Constraints"].(string)
		for _, match := range tiedRE.FindAllStringSubmatch(constraint, -1) {
			a, b := match[1], match[2]
			if encoded[a] && !encoded[b] {
				aliases[b] = a
			} else if encoded[b] && !encoded[a] {
				aliases[a] = b
			}
		}
		asm, _ := r["AsmString"].(string)
		ops := operands(r)
		classes := map[string]string{}
		for _, o := range ops {
			classes[o.name] = o.class
		}
		asm = asmOperandRE.ReplaceAllStringFunc(asm, func(s string) string {
			m := asmOperandRE.FindStringSubmatch(s)
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if a := aliases[name]; a != "" {
				name = a
			}
			if !encoded[name] {
				if classes[name] == "n1Const" {
					return "-1"
				}
				if classes[name] == "sgp10Const" {
					return "sgp1:0"
				}
			}
			return "$" + name
		})
		r["AsmString"] = strings.ReplaceAll(asm, "|", "__hexagon_literal_or__")
		r["isAsmParserOnly"] = float64(0)
		meta := Metadata{Type: kind, SubGroup: strings.TrimPrefix(fmt.Sprint(r["DecoderNamespace"]), "SUBINSN_"), Extendable: number(r["isExtendable"]) != 0, MustExtend: number(r["isExtended"]) != 0, ExtentBits: number(r["opExtentBits"]), ExtentAlign: number(r["opExtentAlign"]), ExtentSigned: number(r["isExtentSigned"]) != 0, Vector: number(r["isCVI"]) != 0, Solo: number(r["isSolo"]) != 0}
		operandName := func(index int) string {
			if index >= len(ops) {
				return ""
			}
			n := ops[index].name
			if a := aliases[n]; a != "" {
				n = a
			}
			return n
		}
		if meta.Extendable || meta.MustExtend {
			meta.ExtendOperand = operandName(number(r["opExtendable"]))
		}
		if number(r["hasNewValue"]) != 0 {
			meta.Producers = append(meta.Producers, operandName(number(r["opNewValue"])))
		}
		if number(r["hasNewValue2"]) != 0 {
			meta.Producers = append(meta.Producers, operandName(number(r["opNewValue2"])))
		}
		if number(r["isNewValue"]) != 0 {
			meta.NewValueUse = operandName(number(r["opNewValue"]))
		}
		c.Metadata[n] = meta
		if kind == "TypeSUBINSN" {
			subIDs = append(subIDs, n)
		} else {
			wordIDs = append(wordIDs, n)
		}
	}
	importIDs := func(ids []any) (*codec.Catalog, error) {
		imported := map[string]any{"!instanceof": map[string]any{"Instruction": ids}}
		for _, id := range ids {
			name, _ := id.(string)
			imported[name] = records[name]
		}
		data, err := json.Marshal(imported)
		if err != nil {
			return nil, err
		}
		return codec.ParseTableGen(bytes.NewReader(data), codec.TableGenOptions{Architecture: architecture, LittleEndian: true})
	}
	var err error
	c.Words, err = importIDs(wordIDs)
	if err != nil {
		return nil, err
	}
	c.Subinstructions, err = importIDs(subIDs)
	if err != nil {
		return nil, err
	}
	for _, table := range []*codec.Catalog{c.Words, c.Subinstructions} {
		c.Unsupported = append(c.Unsupported, table.Unsupported...)
		for i := range table.Encodings {
			e := &table.Encodings[i]
			// LLVM return/call bookkeeping records share the physical opcode but
			// carry compiler-only flow and operand names. Keep them encodable,
			// while decoding the physical instruction. Mandatory extended loop
			// records are selected by the preceding extender and remain decodable.
			record, _ := records[e.ID].(map[string]any)
			if number(record["isCodeGenOnly"]) != 0 && !c.Metadata[e.ID].MustExtend {
				e.AssemblyOnly = true
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "__hexagon_literal_or__", "|")
			e.Mnemonic = strings.ReplaceAll(e.Mnemonic, "__hexagon_literal_or__", "|")
			for j := range e.Operands {
				o := &e.Operands[j]
				if err := mapOperand(records, o, c.Metadata[e.ID].NewValueUse == o.Name); err != nil {
					return nil, fmt.Errorf("%s.%s: %w", e.ID, o.Name, err)
				}
				// LLVM's MC call operand is an absolute a30_2Imm, but the
				// physical direct-call field is a signed packet-PC displacement.
				// Keep this instruction context here: the same immediate class
				// also describes genuinely absolute non-call operands.
				if e.FlowControl == "call" && o.Kind == "address" {
					o.Kind = "displacement"
					o.Signed = true
					o.InputSignedBits = 0
					o.Relative = true
					o.PCWrapBits = 32
				}
			}
			immediateDomains(e)
		}
		if err := table.Validate(); err != nil {
			return nil, err
		}
	}
	c.importAliases(records, instances)
	c.importProfiles(records, instances)
	sort.Slice(c.Unsupported, func(i, j int) bool { return c.Unsupported[i].ID < c.Unsupported[j].ID })
	return c, nil
}

func mapOperand(records map[string]any, o *codec.Operand, newValue bool) error {
	r, _ := records[o.Class].(map[string]any)
	if _, isRegister := r["MemberList"]; isRegister {
		o.Kind = "register"
		prefix := "r"
		if strings.HasPrefix(o.Class, "Hvx") {
			prefix = "v"
		}
		if o.Class == "PredRegs" {
			prefix = "p"
		}
		if o.Class == "HvxQR" {
			prefix = "q"
		}
		o.RegisterPrefix = prefix
		size := 1 << uint(o.Width())
		if size > 4096 {
			return fmt.Errorf("register field too wide")
		}
		o.Names = make([]string, size)
		o.RegisterAliases = map[string]int64{}
		if newValue {
			o.Names = make([]string, 32)
			for n := range o.Names {
				o.Names[n] = fmt.Sprintf("%s%d", prefix, n)
			}
			return nil
		}
		names, err := registerMembers(records, r["MemberList"])
		if err != nil {
			return err
		}
		for _, name := range names {
			if name == "VTMP" {
				continue
			}
			reg, _ := records[name].(map[string]any)
			encoding := number(reg["HWEncoding"])
			if o.Class == "GeneralSubRegs" {
				if encoding >= 16 {
					encoding -= 8
				}
			}
			if o.Class == "GeneralDoubleLow8Regs" {
				encoding /= 2
				if encoding >= 8 {
					encoding -= 4
				}
			}
			if o.Class == "ModRegs" {
				encoding &= size - 1
			}
			if encoding >= size {
				continue
			}
			asm, _ := reg["AsmName"].(string)
			if asm == "" {
				continue
			}
			if old := o.Names[encoding]; old != "" && old != asm {
				o.RegisterAliases[old] = int64(encoding)
			}
			o.Names[encoding] = asm
			o.RegisterAliases[asm] = int64(encoding)
			alts, _ := reg["AltNames"].([]any)
			for _, a := range alts {
				if n, ok := a.(string); ok {
					o.RegisterAliases[n] = int64(encoding)
				}
			}
		}
		return nil
	}
	if m := immediateRE.FindStringSubmatch(o.Class); m != nil {
		o.Signed = m[1] == "s" || m[1] == "b"
		decl, align := parseSignedClass(o.Class)
		if m[1] != "b" && decl+align == 32 {
			o.InputSignedBits = 32
		}
		if m[1] == "b" {
			o.Kind = "displacement"
			o.Relative = true
			o.PCWrapBits = 32
		}
		if m[1] == "a" {
			o.Kind = "address"
		}
		return nil
	}
	if o.Class == "i32imm" || o.Class == "i64imm" {
		o.Signed = true
		return nil
	}
	return fmt.Errorf("unrecognized operand class %q", o.Class)
}
func registerMembers(records map[string]any, value any) ([]string, error) {
	node, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid register class DAG")
	}
	if n := def(node); n != "" {
		return []string{n}, nil
	}
	op := def(node["operator"])
	args, _ := node["args"].([]any)
	if op == "sequence" {
		if len(args) != 3 {
			return nil, fmt.Errorf("bad register sequence")
		}
		a := args[0].([]any)
		b := args[1].([]any)
		c := args[2].([]any)
		pattern, _ := a[0].(string)
		pattern = strings.ReplaceAll(pattern, "%u", "%d")
		var out []string
		for i := number(b[0]); i <= number(c[0]); i++ {
			out = append(out, fmt.Sprintf(pattern, i))
		}
		return out, nil
	}
	if op != "add" {
		return nil, fmt.Errorf("unsupported register DAG operator %s", op)
	}
	var out []string
	for _, arg := range args {
		pair, _ := arg.([]any)
		if len(pair) != 2 {
			return nil, fmt.Errorf("malformed register DAG argument")
		}
		members, err := registerMembers(records, pair[0])
		if err != nil {
			return nil, err
		}
		out = append(out, members...)
	}
	return out, nil
}

func parseSignedClass(class string) (int, int) {
	m := immediateRE.FindStringSubmatch(class)
	if m == nil {
		return 0, 0
	}
	a, _ := strconv.Atoi(m[2])
	b, _ := strconv.Atoi(m[3])
	return a, b
}

func immediateDomains(e *codec.Encoding) {
	for _, o := range e.Operands {
		decl, align := parseSignedClass(o.Class)
		w := decl + align
		if w <= 0 || w >= o.Width() || w >= 63 {
			continue
		}
		low, high := int64(0), int64(1)<<uint(w)-1
		if o.Signed {
			low = -(int64(1) << uint(w-1))
			high = (int64(1) << uint(w-1)) - 1
		}
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "diff_ge", Left: o.Name, Limit: low}, codec.Constraint{Kind: "sum_le", Left: o.Name, Limit: high})
	}
}

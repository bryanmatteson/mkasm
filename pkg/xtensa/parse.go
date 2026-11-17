// Package xtensa imports Xtensa instructions from resolved LLVM TableGen JSON.
package xtensa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]any

func s(v any) string   { x, _ := v.(string); return x }
func n(v any) int      { x, _ := v.(float64); return int(x) }
func def(v any) string { x, _ := v.(map[string]any); return s(x["def"]) }
func args(v any) [][]any {
	m, _ := v.(map[string]any)
	a, _ := m["args"].([]any)
	var out [][]any
	for _, v := range a {
		if p, ok := v.([]any); ok && len(p) == 2 {
			out = append(out, p)
		}
	}
	return out
}
func ref(v string) any { return map[string]any{"kind": "def", "def": v} }

var hole = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)
var ties = regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)

func replace(text, from, to string) string {
	return hole.ReplaceAllStringFunc(text, func(v string) string {
		m := hole.FindStringSubmatch(v)
		if m[1] == from || m[2] == from {
			return to
		}
		return v
	})
}

// Parse accepts an actual llvm-tblgen --dump-json document. Both byte orders
// share the resolved semantic records; the big-endian layout follows Xtensa's
// individual instruction formats rather than reversing complete instructions.
func Parse(r io.Reader, architecture string) (codec.Backend, error) {
	if architecture != "xtensa" && architecture != "xtensaeb" {
		return nil, fmt.Errorf("Xtensa: unsupported architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	d := json.NewDecoder(r)
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("Xtensa: trailing JSON")
	}
	if bytes.Equal(raw["schema"], []byte(`"mkasm.xtensa.v1"`)) {
		b, _ := json.Marshal(raw)
		var c Catalog
		if e := json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		if c.Architecture != architecture {
			return nil, fmt.Errorf("Xtensa configuration architecture mismatch")
		}
		if e := c.ValidateConfiguration(); e != nil {
			return nil, e
		}
		return &c, nil
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, err
	}
	if len(instances["Instruction"]) == 0 {
		return nil, fmt.Errorf("Xtensa: missing Instruction records")
	}
	records := map[string]record{}
	get := func(id string) record {
		if v := records[id]; v != nil {
			return v
		}
		var v record
		_ = json.Unmarshal(raw[id], &v)
		records[id] = v
		return v
	}
	var ids []string
	for _, id := range instances["Instruction"] {
		v := get(id)
		if s(v["Namespace"]) != "Xtensa" || n(v["isPseudo"]) != 0 || s(v["AsmString"]) == "" {
			continue
		}
		prepare(v)
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := map[string]any{"!instanceof": map[string]any{"Instruction": ids}}
	for _, id := range ids {
		out[id] = records[id]
	}
	data, _ := json.Marshal(out)
	c, err := codec.ParseTableGen(bytes.NewReader(data), codec.TableGenOptions{Architecture: architecture, LittleEndian: true})
	if err != nil {
		return nil, err
	}
	c.Source = "LLVM 22.1.8 Xtensa TableGen; GNU binutils 2.44 configuration; Ghidra 12.1.2 endian layouts"
	c.SourceLicense = "Apache-2.0 WITH LLVM-exception; GPL-2.0-or-later (GNU configuration); Apache-2.0 (Ghidra layouts)"
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if err := adapt(e, get); err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID, err)
		}
		if architecture == "xtensaeb" {
			bigEndian(e, records[e.ID])
		}
	}
	partitionRegisters(c)
	importAliases(c, instances["InstAlias"], get)
	c.FeatureSets = profiles(instances, get)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	backend := newBackend(c)
	if err := importGNU(backend); err != nil {
		return nil, err
	}
	return backend, nil
}

func prepare(r record) {
	inst, _ := r["Inst"].([]any)
	syntax := s(r["AsmString"])
	encoded := map[string]bool{}
	for _, v := range inst {
		if m, ok := v.(map[string]any); ok {
			encoded[s(m["var"])] = true
		}
	}
	for _, m := range ties.FindAllStringSubmatch(s(r["Constraints"]), -1) {
		a, b := m[1], m[2]
		if encoded[a] && !encoded[b] {
			a, b = b, a
		}
		if encoded[b] {
			syntax = replace(syntax, a, "$"+b)
		}
	}
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		dag, _ := r[key].(map[string]any)
		if dag == nil {
			continue
		}
		var aa []any
		for _, a := range args(dag) {
			cl, name := def(a[0]), s(a[1])
			if strings.HasPrefix(cl, "mem") {
				aa = append(aa, []any{ref("AR"), name + "_base"}, []any{ref(cl + "_offset"), name + "_offset"})
				syntax = replace(syntax, name, "$"+name+"_base, $"+name+"_offset")
				for _, v := range inst {
					if m, ok := v.(map[string]any); ok && s(m["var"]) == name {
						ix := n(m["index"])
						if ix < 4 {
							m["var"] = name + "_base"
						} else {
							m["var"] = name + "_offset"
							m["index"] = float64(ix - 4)
						}
					}
				}
			} else {
				aa = append(aa, a)
			}
		}
		dag["args"] = aa
	}
	r["AsmString"] = syntax
}

func width(o codec.Operand) int {
	w := 0
	for _, b := range o.Bits {
		if b.ValueBit+b.Width > w {
			w = b.ValueBit + b.Width
		}
	}
	return w
}
func adapt(e *codec.Encoding, get func(string) record) error {
	r := get(e.ID)
	if n(r["isBranch"]) != 0 && n(r["isBarrier"]) == 0 {
		e.FlowControl = "conditional_branch"
	}
	if strings.HasPrefix(e.Mnemonic, "break") || strings.HasPrefix(e.Mnemonic, "ill") || e.Mnemonic == "syscall" {
		e.FlowControl = "trap"
	}
	if strings.HasPrefix(e.Mnemonic, "loop") {
		e.FlowControl = "loop"
	}

	for i := range e.Operands {
		o := &e.Operands[i]
		switch o.Class {
		case "AR", "FPR", "BR":
			o.Kind = "register"
			prefix := map[string]string{"AR": "a", "FPR": "f", "BR": "b"}[o.Class]
			o.Names = make([]string, 16)
			for j := range o.Names {
				o.Names[j] = fmt.Sprintf("%s%d", prefix, j)
			}
			if o.Class == "AR" {
				o.RegisterAliases = map[string]int64{"sp": 1}
			}
		case "MR", "MR01", "MR23":
			o.Kind = "register"
			count, start := 1<<uint(width(*o)), 0
			if o.Class != "MR" {
				count = 2
			}
			if o.Class == "MR23" {
				start = 2
			}
			o.Names = make([]string, count)
			for j := range o.Names {
				o.Names[j] = fmt.Sprintf("m%d", start+j)
			}
		case "SR", "UR":
			o.Kind = "register"
			o.Names = make([]string, 256)
			o.RegisterAliases = map[string]int64{}
			for _, r := range registerRecords(get, o.Class) {
				hw := r.hw
				o.Names[hw] = r.name
				for _, a := range r.aliases {
					o.RegisterAliases[strings.ToLower(a)] = int64(hw)
				}
			}
		case "mem8_offset":
		case "mem16_offset":
			o.Scale = 2
		case "mem32_offset", "mem32n_offset":
			o.Scale = 4
		case "imm8", "imm8_sh8", "imm8n_7", "imm12m":
			o.Signed = true
			o.InputSignedBits = 32
		case "imm64n_4n":
			o.Bias = -64
		case "imm1_16":
			o.Bias = 1
		case "imm1n_15":
			o.Lookup = []int64{-1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		case "imm32n_95":
			for j := 0; j < 128; j++ {
				v := j
				if j >= 96 {
					v = j - 128
				}
				o.Lookup = append(o.Lookup, int64(v))
			}
		case "shimm1_31":
			for j := 0; j < 32; j++ {
				o.Lookup = append(o.Lookup, int64(32-j))
			}
			o.Names = make([]string, 32)
			for j := 1; j < 32; j++ {
				o.Names[j] = fmt.Sprint(32 - j)
			}
		case "entry_imm12", "uimm4", "uimm5":
		case "b4const":
			o.Lookup = []int64{-1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256}
		case "b4constu":
			o.Lookup = []int64{32768, 65536, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256}
		case "imm7_22":
			o.Bias = 7
		case "brtarget", "jumptarget", "ltarget", "pcrel32call", "L32Rtarget":
			o.Kind = "displacement"
			o.Relative = true
			o.PCWrapBits = 32
			o.PCBias = 4
			o.Signed = o.Class != "ltarget" && o.Class != "L32Rtarget" && width(*o) != 6
			if o.Class == "pcrel32call" {
				o.Scale = 4
				o.PCAlignBits = 2
			}
			if o.Class == "L32Rtarget" {
				o.Scale = 4
				o.Bias = -262144
				o.PCBias = 0
				o.PCAlignBits = 2
				setPreAlignBias(o, 3)
			}
		default:
			return fmt.Errorf("unknown semantic operand class %q", o.Class)
		}
	}
	if e.ID == "LEA_ADD" {
		for i := range e.Operands {
			if strings.HasSuffix(e.Operands[i].Name, "_offset") {
				e.Operands[i].Scale = 0
				e.Operands[i].Signed = true
				e.Operands[i].InputSignedBits = 32
			}
		}
	}
	if e.Mnemonic == "extui" {
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "sum_le", Left: "imm1", Right: "imm2", Limit: 32})
	}
	if e.Mnemonic == "all4" || e.Mnemonic == "any4" || e.Mnemonic == "all8" || e.Mnemonic == "any8" {
		group := 4
		if strings.HasSuffix(e.Mnemonic, "8") {
			group = 8
		}
		for i := range e.Operands {
			if e.Operands[i].Name == "s" {
				for j := range e.Operands[i].Names {
					if j%group != 0 {
						e.Operands[i].Names[j] = ""
					}
				}
			}
		}
	}
	return nil
}

type reg struct {
	hw      int
	name    string
	aliases []string
}

func registerRecords(get func(string) record, class string) []reg {
	r := get(class)
	var names []string
	var walk func(any)
	walk = func(v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		if id := def(m); id != "" {
			if member := get(id)["MemberList"]; member != nil {
				walk(member)
			} else if s(get(id)["AsmName"]) != "" {
				names = append(names, id)
			}
		}
		for _, a := range args(m) {
			walk(a[0])
		}
	}
	walk(r["MemberList"])
	var out []reg
	for _, id := range names {
		v := get(id)
		bits, _ := v["HWEncoding"].([]any)
		hw := 0
		for i, b := range bits {
			hw |= n(b) << uint(i)
		}
		rr := reg{hw: hw, name: s(v["AsmName"])}
		if a, ok := v["AltNames"].([]any); ok {
			for _, a := range a {
				rr.aliases = append(rr.aliases, s(a))
			}
		}
		out = append(out, rr)
	}
	return out
}

func setPreAlignBias(o *codec.Operand, v int64) { o.PCPreAlignBias = v }

func profiles(inst map[string][]string, get func(string) record) map[string][]string {
	out := map[string][]string{}
	var all []string
	for _, id := range inst["SubtargetFeature"] {
		v := get(id)
		if val := s(v["Value"]); val == "true" {
			all = append(all, s(v["FieldName"]))
		}
	}
	sort.Strings(all)
	out["all"] = all
	for _, id := range inst["Processor"] {
		v := get(id)
		var features []string
		if ff, ok := v["Features"].([]any); ok {
			for _, f := range ff {
				features = append(features, s(get(def(f))["FieldName"]))
			}
		}
		sort.Strings(features)
		out[s(v["Name"])] = expandProfile(features)
	}
	return out
}

func importAliases(c *codec.Catalog, ids []string, get func(string) record) {
	base := map[string]codec.Encoding{}
	for _, e := range c.Encodings {
		base[e.ID] = e
	}
	for _, id := range ids {
		r := get(id)
		dag, _ := r["ResultInst"].(map[string]any)
		e, ok := base[def(dag["operator"])]
		if !ok {
			continue
		}
		a := args(dag)
		if len(a) != len(e.Operands) {
			continue
		}
		old := e.Operands
		e.Operands = nil
		e.ID = id
		e.Syntax = hole.ReplaceAllStringFunc(s(r["AsmString"]), func(v string) string { m := hole.FindStringSubmatch(v); return "{" + m[1] + m[2] + "}" })
		e.Syntax = strings.Join(strings.Fields(e.Syntax), " ")
		e.Mnemonic = strings.Fields(e.Syntax)[0]
		seen := map[string]int{}
		for i, o := range old {
			name := s(a[i][1])
			if j, ok := seen[name]; ok {
				e.Operands[j].Bits = append(e.Operands[j].Bits, o.Bits...)
			} else {
				o.Name = name
				seen[name] = len(e.Operands)
				e.Operands = append(e.Operands, o)
			}
		}
		e.AssemblyOnly = true
		c.Encodings = append(c.Encodings, e)
	}
}

func bigEndian(e *codec.Encoding, r record) {
	super, _ := r["!superclasses"].([]any)
	has := func(v string) bool {
		for _, s := range super {
			if s == v {
				return true
			}
		}
		return false
	}
	size := len(e.Mask)
	mapping := func(bit int) int {
		token := 0
		switch {
		case size == 2:
			token = (bit/4)*-4 + 12 + bit%4 // reverse nibble positions
		case has("CALL_Inst"):
			if bit < 4 {
				token = 20 + bit
			} else if bit < 6 {
				token = 18 + bit - 4
			} else {
				token = bit - 6
			}
		case has("CALLX_Inst") || has("BRI8_Inst") || has("BRI12_Inst"):
			switch {
			case bit < 4:
				token = 20 + bit
			case bit < 6:
				token = 18 + bit - 4
			case bit < 8:
				token = 16 + bit - 6
			case bit < 12:
				token = 12 + bit - 8
			case has("BRI12_Inst"):
				token = bit - 12
			case bit < 16:
				token = 8 + bit - 12
			default:
				token = bit - 16
			}
		case has("RI16_Inst"):
			if bit < 4 {
				token = 20 + bit
			} else if bit < 8 {
				token = 16 + bit - 4
			} else {
				token = bit - 8
			}
		case has("RRI8_Inst"):
			if bit >= 16 {
				token = bit - 16
			} else if bit >= 4 && bit < 8 && e.Value[0]&15 == 6 {
				if bit < 6 {
					token = 18 + bit - 4
				} else {
					token = 16 + bit - 6
				}
			} else {
				token = 20 - (bit/4)*4 + bit%4
			}
		case has("RSR_Inst") || e.Mnemonic == "wur" || strings.HasPrefix(e.Mnemonic, "wur."):
			if bit >= 8 && bit < 16 {
				token = 8 + bit - 8
			} else {
				token = 20 - (bit/4)*4 + bit%4
			}
		default:
			token = 20 - (bit/4)*4 + bit%4
		}
		return (size-1-token/8)*8 + token%8
	}
	mask, val := make([]byte, size), make([]byte, size)
	for b := 0; b < size*8; b++ {
		p := mapping(b)
		if e.Mask[b/8]&(1<<uint(b%8)) != 0 {
			mask[p/8] |= 1 << uint(p%8)
		}
		if e.Value[b/8]&(1<<uint(b%8)) != 0 {
			val[p/8] |= 1 << uint(p%8)
		}
	}
	for i := range e.Operands {
		var bits []codec.BitSlice
		for _, b := range e.Operands[i].Bits {
			for k := 0; k < b.Width; k++ {
				bits = append(bits, codec.BitSlice{InstructionBit: mapping(b.InstructionBit + k), ValueBit: b.ValueBit + k, Width: 1})
			}
		}
		e.Operands[i].Bits = bits
	}
	e.Mask, e.Value = mask, val
}

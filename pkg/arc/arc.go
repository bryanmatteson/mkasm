// Package arc imports source-backed ARC compact and extended instructions.
package arc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]any

func str(v any) string { s, _ := v.(string); return s }
func num(v any) int    { n, _ := v.(float64); return int(n) }
func def(v any) string { m, _ := v.(map[string]any); return str(m["def"]) }
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
func ref(s string) any { return map[string]any{"def": s, "kind": "def"} }

var tied = regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)
var placeholder = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)

func replaceHole(s, from, to string) string {
	return placeholder.ReplaceAllStringFunc(s, func(v string) string {
		m := placeholder.FindStringSubmatch(v)
		n := m[1]
		if n == "" {
			n = m[2]
		}
		if n == from {
			return to
		}
		return v
	})
}

func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("ARC: empty input")
	}
	if bytes.TrimSpace(data)[0] != '{' {
		return ParseGNU(bytes.NewReader(data), architecture)
	}
	r = bytes.NewReader(data)
	switch architecture {
	case "arc", "arc32", "arcv2":
		architecture = "arc32"
	case "arc32be", "arceb":
		architecture = "arc32be"
	default:
		return nil, fmt.Errorf("unsupported ARC architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	d := json.NewDecoder(r)
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("ARC: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, err
	}
	if len(instances["Instruction"]) == 0 {
		return nil, fmt.Errorf("ARC: no Instruction records")
	}
	records := map[string]record{}
	get := func(id string) record {
		if r, ok := records[id]; ok {
			return r
		}
		var r record
		_ = json.Unmarshal(raw[id], &r)
		records[id] = r
		return r
	}
	var ids []string
	var excluded []codec.Unsupported
	for _, id := range instances["Instruction"] {
		r := get(id)
		if str(r["Namespace"]) != "ARC" || num(r["isPseudo"]) != 0 || str(r["AsmString"]) == "" {
			continue
		}
		if err := prepare(r, architecture); err != nil {
			excluded = append(excluded, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	instances["Instruction"] = ids
	out := map[string]any{"!instanceof": instances}
	for _, id := range ids {
		out[id] = records[id]
	}
	data, err = json.Marshal(out)
	if err != nil {
		return nil, err
	}
	c, err := codec.ParseTableGen(bytes.NewReader(data), codec.TableGenOptions{Architecture: architecture, LittleEndian: true})
	if err != nil {
		return nil, err
	}
	c.Source = "LLVM ARC TableGen --dump-json"
	c.Unsupported = append(c.Unsupported, excluded...)
	var forms []codec.Encoding
	for _, e := range c.Encodings {
		if err := adapt(&e, records[e.ID], get); err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: e.ID, Reason: err.Error()})
			continue
		}
		variants := compactRegisters(e)
		for _, v := range variants {
			for _, v := range cyclicImmediates(v) {
				forms = append(forms, v)
				forms = append(forms, conditionVariants(v)...)
			}
		}
	}
	c.Encodings = forms
	compressBits(c)
	c.FeatureSets = map[string][]string{"arcv2": {}, "arcv2-norm": {"HasNorm"}}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
func physical(bit, size int, big bool) int {
	base := 0
	block := 4
	if size == 2 || size == 6 {
		block = 2
	}
	if bit >= block*8 {
		base = block * 8
		bit -= base
		block = 4
	}
	if big {
		return base + (block-1-bit/8)*8 + bit%8
	}
	if block == 4 {
		bit ^= 16
	}
	return base + bit
}
func prepare(r record, arch string) error {
	size := num(r["Size"])
	if size != 2 && size != 4 && size != 6 && size != 8 {
		return fmt.Errorf("unsupported instruction size %d", size)
	}
	inst, ok := r["Inst"].([]any)
	if !ok || len(inst) < size*8 {
		return fmt.Errorf("missing instruction bits")
	}
	syntax := str(r["AsmString"])
	id := str(r["!name"])
	if id == "POP_S_r" || id == "PUSH_S_r" {
		if num(inst[5]) == 0 {
			inst[5] = float64(1)
		} else {
			inst[5] = float64(0)
		}
	}
	if id == "COMPACT_MOV_S_hreg" || id == "COMPACT_MOV_S_limm" {
		for k := 0; k < 3; k++ {
			inst[8+k] = map[string]any{"kind": "varbit", "var": "g", "index": float64(k)}
		}
		for k := 0; k < 2; k++ {
			inst[3+k] = map[string]any{"kind": "varbit", "var": "g", "index": float64(k + 3)}
		}
		if id == "COMPACT_MOV_S_limm" {
			syntax = replaceHole(syntax, "h", "$LImm")
		}
	}
	remap := map[string]string{}
	if id == "LR_rs12" {
		remap["C"] = "S12"
	}
	if id == "LR_ru6" {
		remap["C"] = "U6"
	}
	if id == "MOV_cc_f_ru6" || id == "MOV_cc_ru6" {
		remap["C"] = "U6"
	}
	for from, to := range remap {
		syntax = replaceHole(syntax, from, "$"+to)
	}

	encoded := map[string]bool{}
	for _, v := range inst[:size*8] {
		if m, ok := v.(map[string]any); ok {
			encoded[str(m["var"])] = true
		}
	}
	for _, m := range tied.FindAllStringSubmatch(str(r["Constraints"]), -1) {
		from, to := m[1], m[2]
		if encoded[from] && !encoded[to] {
			from, to = to, from
		}
		if encoded[to] {
			syntax = replaceHole(syntax, from, "$"+to)
		}
	}
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		var a []any
		for _, p := range args(r[key]) {
			if to := remap[str(p[1])]; to != "" {
				p[1] = to
				if id == "LR_rs12" {
					p[0] = ref("Signed12")
				} else {
					p[0] = ref("i32imm")
				}
			}
			if id == "COMPACT_MOV_S_limm" && str(p[1]) == "h" {
				p[1] = "LImm"
				p[0] = ref("i32imm")
			}
			if def(p[0]) == "MEMii" {
				if !encoded["LImm"] {
					return fmt.Errorf("unresolved absolute long-immediate address")
				}
				syntax = replaceHole(syntax, str(p[1]), "$LImm")
				a = append(a, []any{ref("i32imm"), "LImm"})
				continue
			}
			a = append(a, p)
		}
		r[key] = map[string]any{"args": a}
	}
	// Variables produced by custom decoders are made explicit in the resolved DAG.
	known := map[string]bool{}
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		for _, p := range args(r[key]) {
			known[str(p[1])] = true
		}
	}
	for name := range encoded {
		if !known[name] {
			if name != "N" && replaceHole(syntax, name, "!") == syntax {
				for i, v := range inst[:size*8] {
					if m, ok := v.(map[string]any); ok && str(m["var"]) == name {
						inst[i] = float64(0)
					}
				}
				continue
			}
			cl := "i32imm"
			if name == "N" {
				cl = "DelayBit"
			}
			a := args(r["InOperandList"])
			var anyArgs []any
			for _, p := range a {
				anyArgs = append(anyArgs, p)
			}
			anyArgs = append(anyArgs, []any{ref(cl), name})
			r["InOperandList"] = map[string]any{"args": anyArgs}
		}
	}
	mapped := make([]any, size*8)
	for i, v := range inst[:size*8] {
		mapped[physical(i, size, arch == "arc32be")] = v
	}
	r["Inst"] = mapped
	r["AsmString"] = syntax
	r["isAsmParserOnly"] = float64(0)
	return nil
}

func compressBits(c *codec.Catalog) {
	for i := range c.Encodings {
		for j := range c.Encodings[i].Operands {
			o := &c.Encodings[i].Operands[j]
			var bits []codec.BitSlice
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					bits = append(bits, codec.BitSlice{InstructionBit: b.InstructionBit + k, ValueBit: b.ValueBit + k, Width: 1})
				}
			}
			sort.Slice(bits, func(a, b int) bool { return bits[a].InstructionBit < bits[b].InstructionBit })
			var out []codec.BitSlice
			for _, b := range bits {
				n := len(out)
				if n > 0 && out[n-1].InstructionBit+out[n-1].Width == b.InstructionBit && out[n-1].ValueBit+out[n-1].Width == b.ValueBit {
					out[n-1].Width++
				} else {
					out = append(out, b)
				}
			}
			o.Bits = out
		}
	}
}

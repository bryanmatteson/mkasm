// Package sparc imports LLVM's resolved SPARC V8/V9 instruction descriptions.
package sparc

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
func has(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func predicates(r record) []string {
	a, _ := r["Predicates"].([]any)
	var out []string
	for _, p := range a {
		out = append(out, def(p))
	}
	return out
}

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

// Parse imports llvm-tblgen --dump-json output. sparc32 and sparc64 are big
// endian; sparc32le provides LLVM's sparcel instruction byte ordering.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	switch architecture {
	case "sparc32", "sparc64", "sparc32le":
	default:
		return nil, fmt.Errorf("unsupported SPARC architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("SPARC TableGen: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("SPARC TableGen: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, err
	}
	if len(instances["Instruction"]) == 0 {
		return nil, fmt.Errorf("SPARC TableGen: no Instruction records")
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
	is64 := architecture == "sparc64"
	selected := map[string]bool{}
	var ids []string
	var excluded []codec.Unsupported
	applies := func(rec record) bool {
		ps := predicates(rec)
		return !(!is64 && has(ps, "Is64Bit") || is64 && (has(ps, "HasNoV9") || has(ps, "Is32Bit")))
	}
	for _, id := range instances["Instruction"] {
		rec := get(id)
		if str(rec["Namespace"]) != "SP" || num(rec["isPseudo"]) != 0 || str(rec["AsmString"]) == "" || !applies(rec) {
			continue
		}
		rec["isAsmParserOnly"] = float64(0)
		selected[id] = true
		ids = append(ids, id)
	}
	for _, id := range instances["InstAlias"] {
		a := get(id)
		if !applies(a) {
			continue
		}
		dag, _ := a["ResultInst"].(map[string]any)
		target := def(dag["operator"])
		if !selected[target] {
			continue
		}
		clone, err := aliasRecord(a, get(target), get)
		if err != nil {
			excluded = append(excluded, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		records[id] = clone
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// Flatten LLVM's named address DAG into its individually encoded base/offset.
	for _, id := range ids {
		rec := records[id]
		if err := flatten(rec); err != nil {
			excluded = append(excluded, codec.Unsupported{ID: id, Reason: err.Error()})
			delete(records, id)
		}
	}
	var kept []string
	exported := map[string]any{}
	for _, id := range ids {
		if rec := records[id]; rec != nil {
			kept = append(kept, id)
			exported[id] = rec
		}
	}
	instances["Instruction"] = kept
	exported["!instanceof"] = instances
	b, err := json.Marshal(exported)
	if err != nil {
		return nil, err
	}
	c, err := codec.ParseTableGen(bytes.NewReader(b), codec.TableGenOptions{Architecture: architecture, LittleEndian: architecture == "sparc32le"})
	if err != nil {
		return nil, err
	}
	c.Source = "LLVM SPARC TableGen --dump-json"
	c.Unsupported = append(c.Unsupported, excluded...)
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if err := adapt(e, records[e.ID], get, is64); err != nil {
			return nil, fmt.Errorf("SPARC %s: %w", e.ID, err)
		}
	}
	var expanded []codec.Encoding
	for _, e := range c.Encodings {
		forms := []codec.Encoding{e}
		if !is64 && !has(e.Features, "HasV9") {
			low, full, needed := registerBankVariants(e)
			if needed {
				forms = []codec.Encoding{low, full}
			}
		}
		for _, form := range forms {
			expanded = append(expanded, form)
			expanded = append(expanded, conditionVariants(form)...)
		}
	}
	c.Encodings = expanded
	c.FeatureSets = profiles(is64)
	sort.Slice(c.Unsupported, func(i, j int) bool { return c.Unsupported[i].ID < c.Unsupported[j].ID })
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
func flatten(rec record) error {
	syntax := str(rec["AsmString"])
	encoded := map[string]bool{}
	inst, _ := rec["Inst"].([]any)
	for _, v := range inst {
		if m, ok := v.(map[string]any); ok {
			encoded[str(m["var"])] = true
		}
	}
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		var flat []any
		for _, a := range args(rec[key]) {
			name := str(a[1])
			if d, ok := a[0].(map[string]any); ok && str(d["kind"]) == "dag" {
				op := def(d["operator"])
				if op != "MEMri" && op != "MEMrr" {
					return fmt.Errorf("unsupported composite operand %s", op)
				}
				var holes []string
				for i, sub := range args(d) {
					cl := "IntRegs"
					if i == 1 && op == "MEMri" {
						cl = "simm13Op"
					}
					subname := str(sub[1])
					flat = append(flat, []any{ref(cl), subname})
					holes = append(holes, "$"+subname)
				}
				syntax = replaceHole(syntax, name, strings.Join(holes, " + "))
				continue
			}
			if name != "" && !encoded[name] && strings.Contains(syntax, "$"+name) {
				tiedName := ""
				for _, m := range tied.FindAllStringSubmatch(str(rec["Constraints"]), -1) {
					if m[1] == name && encoded[m[2]] {
						tiedName = m[2]
					}
					if m[2] == name && encoded[m[1]] {
						tiedName = m[1]
					}
				}
				if tiedName != "" {
					syntax = replaceHole(syntax, name, "$"+tiedName)
				} else {
					return fmt.Errorf("phantom operand %s contributes relocation/ABI metadata but no instruction bits", name)
				}
			}
			flat = append(flat, a)
		}
		rec[key] = map[string]any{"args": flat}
	}
	rec["AsmString"] = syntax
	return nil
}

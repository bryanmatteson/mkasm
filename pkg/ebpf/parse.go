// Package ebpf imports LLVM's BPF TableGen instruction records into byte-oriented
// catalogs. It models instruction encoding, not kernel verifier acceptance.
package ebpf

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]json.RawMessage
type bit struct {
	Kind  string `json:"kind"`
	Var   string `json:"var"`
	Index int    `json:"index"`
}
type dag struct {
	Args []json.RawMessage `json:"args"`
}
type definition struct {
	Def string `json:"def"`
}

var placeholder = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z_0-9]*)\}?`)

// Parse reads the unmodified output of llvm-tblgen --dump-json BPF.td. Both
// endian variants use the same records; BPF's code/register/offset/immediate
// fields are rearranged explicitly rather than reversing the whole instruction.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	switch architecture {
	case "ebpf", "bpf", "bpfel":
		architecture = "bpfel"
	case "bpfeb":
	default:
		return nil, fmt.Errorf("unsupported BPF architecture %q", architecture)
	}
	var root map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("BPF TableGen JSON: %w", err)
	}
	var instances map[string][]string
	if err := json.Unmarshal(root["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("BPF input must be LLVM TableGen --dump-json: %w", err)
	}
	ids := append([]string(nil), instances["Instruction"]...)
	sort.Strings(ids)
	var encodings []codec.Encoding
	var unsupported []codec.Unsupported
	for _, id := range ids {
		var rec record
		if err := json.Unmarshal(root[id], &rec); err != nil {
			return nil, err
		}
		if scalarBool(rec["isPseudo"]) || scalarString(rec["Namespace"]) != "BPF" {
			continue
		}
		if strings.HasPrefix(id, "CORE_") {
			unsupported = append(unsupported, codec.Unsupported{ID: id, Reason: "LLVM CO-RE relocation pseudo operation; no standalone machine encoding"})
			continue
		}
		asm := scalarString(rec["AsmString"])
		if asm == "" {
			continue
		}
		var inst []json.RawMessage
		if err := json.Unmarshal(rec["Inst"], &inst); err != nil || len(inst) != 64 {
			return nil, fmt.Errorf("BPF %s has unsupported instruction width", id)
		}
		e, err := importEncoding(id, rec, inst, architecture == "bpfel")
		if err != nil {
			return nil, err
		}
		if id == "LD_pseudo" {
			encodings = append(encodings, pseudoForms(e)...)
		} else {
			encodings = append(encodings, e)
		}
		if id == "JAL" {
			encodings = append(encodings, callForms(e, architecture == "bpfel")...)
		}
	}
	if len(encodings) == 0 {
		return nil, fmt.Errorf("no concrete BPF instructions in TableGen input")
	}
	c, err := codec.NewCatalog(architecture, "LLVM TableGen BPF.td", encodings)
	if err != nil {
		return nil, err
	}
	c.Unsupported = unsupported
	return c, nil
}

func importEncoding(id string, rec record, inst []json.RawMessage, little bool) (codec.Encoding, error) {
	size := 8
	if id == "LD_imm64" || id == "LD_pseudo" {
		size = 16
	}
	e := codec.Encoding{ID: id, Mask: make([]byte, size), Value: make([]byte, size)}
	types := map[string]string{}
	for _, name := range []string{"OutOperandList", "InOperandList"} {
		var d dag
		_ = json.Unmarshal(rec[name], &d)
		for _, arg := range d.Args {
			var pair []json.RawMessage
			if json.Unmarshal(arg, &pair) != nil || len(pair) != 2 {
				continue
			}
			var def definition
			_ = json.Unmarshal(pair[0], &def)
			types[scalarString(pair[1])] = def.Def
		}
	}
	fields := map[string][]codec.BitSlice{}
	for i, raw := range inst {
		physical := physicalBit(i, little)
		var fixed int
		if json.Unmarshal(raw, &fixed) == nil && string(raw) != "null" {
			e.Mask[physical/8] |= 1 << uint(physical%8)
			if fixed != 0 {
				e.Value[physical/8] |= 1 << uint(physical%8)
			}
			continue
		}
		var v bit
		_ = json.Unmarshal(raw, &v)
		if v.Kind == "varbit" {
			fields[v.Var] = append(fields[v.Var], codec.BitSlice{InstructionBit: physical, ValueBit: v.Index, Width: 1})
		} else {
			if v.Kind != "" {
				return e, fmt.Errorf("BPF %s has unresolved TableGen bit %d (%s)", id, i, v.Kind)
			}
			// Unspecified fields in LLVM's BPF records are reserved zero bits, not
			// arbitrary decoder wildcards.
			e.Mask[physical/8] |= 1 << uint(physical%8)
		}
	}
	if size == 16 {
		// LLVM models only the first slot. MCCodeEmitter writes the high immediate
		// word into bytes 12..15 and a zero continuation header in bytes 8..11.
		for i := 8; i < 12; i++ {
			e.Mask[i] = 255
		}
		for i := 0; i < 32; i++ {
			p := 96 + i
			if !little {
				p = 120 - (i/8)*8 + i%8
			}
			fields["imm"] = append(fields["imm"], codec.BitSlice{InstructionBit: p, ValueBit: 32 + i, Width: 1})
		}
	}
	syntax := strings.TrimSpace(scalarString(rec["AsmString"]))
	if id == "NOP" {
		syntax = "nop"
	}
	syntax = strings.ReplaceAll(syntax, "\t", " ")
	// TableGen ties operands that share one machine field. Reuse that field
	// in the syntax so the generic assembler also enforces operand equality.
	ties := regexp.MustCompile(`\$([A-Za-z_0-9]+)\s*=\s*\$([A-Za-z_0-9]+)`)
	for _, m := range ties.FindAllStringSubmatch(scalarString(rec["Constraints"]), -1) {
		a, b := m[1], m[2]
		if len(fields[a]) > 0 && len(fields[b]) == 0 {
			syntax = replacePlaceholder(syntax, b, "$"+a)
		} else if len(fields[b]) > 0 && len(fields[a]) == 0 {
			syntax = replacePlaceholder(syntax, a, "$"+b)
		}
	}
	var names []string
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		slices := fields[name]
		typ := types[name]
		if typ == "MEMri" || name == "addr" {
			base, off := []codec.BitSlice{}, []codec.BitSlice{}
			for _, s := range slices {
				if s.ValueBit >= 16 {
					s.ValueBit -= 16
					base = append(base, s)
				} else {
					off = append(off, s)
				}
			}
			e.Operands = append(e.Operands, registerOperand(name+"_base", base, false), codec.Operand{Name: name + "_offset", Kind: "immediate", Bits: off, Signed: true})
			syntax = replacePlaceholder(syntax, name, "{"+name+"_base} + {"+name+"_offset}")
			continue
		}
		operand := codec.Operand{Name: name, Class: typ, Kind: "immediate", Bits: slices}
		switch {
		case strings.HasPrefix(typ, "GPR") || name == "dst" || name == "src" || name == "src2":
			operand = registerOperand(name, slices, strings.Contains(typ, "32") || id == "MOV_32_64")
		case typ == "calltarget":
			operand.Signed = true
		case typ == "brtarget" || name == "BrDst":
			operand.Kind = "displacement"
			operand.Signed = true
			operand.Relative = true
			operand.Scale = 8
			operand.PCBias = 8
		case name == "pseudo":
			operand.Names = []string{"0", "1", "2", "3", "4", "5", "6"}
		default:
			operand.Signed = true
		}

		operand.Class = typ
		e.Operands = append(e.Operands, operand)
		syntax = replacePlaceholder(syntax, name, "{"+name+"}")
	}
	// Tied two-address inputs are absent from Inst. LLVM's syntax generally only
	// mentions the output; reject future unsupported syntaxes instead of silently
	// producing an unusable encoding.
	if placeholder.MatchString(syntax) {
		return e, fmt.Errorf("BPF %s has unencoded syntax operand in %q", id, syntax)
	}
	e.Syntax = strings.Join(strings.Fields(syntax), " ")
	e.Mnemonic = id
	var predicates []definition
	_ = json.Unmarshal(rec["Predicates"], &predicates)
	for _, p := range predicates {
		switch p.Def {
		case "BPFIsLittleEndian", "BPFIsBigEndian":
			// These select code-generation patterns; both LE and BE conversions
			// are valid machine instructions in either endian ISA.
		default:
			if p.Def != "" {
				e.Features = append(e.Features, p.Def)
			}
		}
	}
	if scalarBool(rec["isCall"]) {
		e.FlowControl = "call"
	} else if scalarBool(rec["isReturn"]) {
		e.FlowControl = "return"
	} else if scalarBool(rec["isBranch"]) {
		e.FlowControl = "branch"
	}
	return e, nil
}
func registerOperand(name string, bits []codec.BitSlice, w bool) codec.Operand {
	prefix := "r"
	if w {
		prefix = "w"
	}
	names := make([]string, 11)
	for i := range names {
		names[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return codec.Operand{Name: name, Kind: "register", Bits: bits, RegisterPrefix: prefix, Names: names}
}
func replacePlaceholder(s, name, replacement string) string {
	return placeholder.ReplaceAllStringFunc(s, func(v string) string {
		m := placeholder.FindStringSubmatch(v)
		if m[1] == name {
			return replacement
		}
		return v
	})
}
func scalarString(v json.RawMessage) string { var s string; _ = json.Unmarshal(v, &s); return s }
func scalarBool(v json.RawMessage) bool {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b
	}
	var n int
	_ = json.Unmarshal(v, &n)
	return n != 0
}
func physicalBit(i int, little bool) int {
	switch {
	case i >= 56:
		return i - 56
	case i >= 48:
		if little {
			return i - 40
		}
		return i - 40 ^ 4
	case i >= 32:
		if little {
			return i - 16
		}
		return 24 - (i-32)/8*8 + i%8
	default:
		if little {
			return i + 32
		}
		return 56 - i/8*8 + i%8
	}
}

// Source subtypes and call tags are specified by the Linux BPF ISA and UAPI:
// https://www.kernel.org/doc/html/latest/bpf/standardization/instruction-set.html
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
func pseudoForms(e codec.Encoding) []codec.Encoding {
	var forms []codec.Encoding
	for tag := 0; tag <= 6; tag++ {
		f := e
		f.ID = fmt.Sprintf("LD_pseudo_%d", tag)
		f.Mnemonic = "ld_pseudo"
		f.Mask = append([]byte(nil), e.Mask...)
		f.Value = append([]byte(nil), e.Value...)
		f.Syntax = strings.ReplaceAll(e.Syntax, "{pseudo}", fmt.Sprint(tag))
		f.Operands = nil
		for _, o := range e.Operands {
			if o.Name == "pseudo" {
				for _, b := range o.Bits {
					f.Mask[b.InstructionBit/8] |= 1 << uint(b.InstructionBit%8)
					if tag&(1<<uint(b.ValueBit)) != 0 {
						f.Value[b.InstructionBit/8] |= 1 << uint(b.InstructionBit%8)
					}
				}
				continue
			}
			if o.Name == "imm" && tag != 0 && tag != 2 && tag != 6 {
				o.Bits = append([]codec.BitSlice(nil), o.Bits[:32]...)
				o.Signed = tag == 4
				for i := 12; i < 16; i++ {
					f.Mask[i] = 255
					f.Value[i] = 0
				}
			}
			f.Operands = append(f.Operands, o)
		}
		forms = append(forms, f)
	}
	return forms
}
func callForms(e codec.Encoding, little bool) []codec.Encoding {
	var forms []codec.Encoding
	for tag := 1; tag <= 2; tag++ {
		f := e
		f.Mask = append([]byte(nil), e.Mask...)
		f.Value = append([]byte(nil), e.Value...)
		shift := uint(4)
		if !little {
			shift = 0
		}
		f.Value[1] |= byte(tag) << shift
		f.Operands = append([]codec.Operand(nil), e.Operands...)
		if tag == 1 {
			f.ID = "JAL_REL"
			f.Mnemonic = "call_rel"
			f.Syntax = "call_rel {BrDst}"
			f.Operands[0].Kind = "displacement"
			f.Operands[0].Relative = true
			f.Operands[0].Scale = 8
			f.Operands[0].PCBias = 8
		} else {
			f.ID = "JAL_KFUNC"
			f.Mnemonic = "call_kfunc"
			f.Syntax = "call_kfunc {BrDst}"
			f.Operands[0].Signed = false
		}
		forms = append(forms, f)
	}
	return forms
}

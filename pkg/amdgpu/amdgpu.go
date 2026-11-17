// Package amdgpu imports the resolved LLVM GCN/RDNA instruction descriptions.
package amdgpu

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed testdata/LICENSE-LLVM.txt
var sourceLicense string

type bit struct {
	Var       string `json:"var"`
	Index     int    `json:"index"`
	Kind      string `json:"kind"`
	Printable string `json:"printable"`
	Fixed     int
	Set       bool
}

func (b *bit) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		b.Fixed = 0
		b.Set = true
		return nil
	}
	if raw[0] != '{' {
		b.Set = true
		return json.Unmarshal(raw, &b.Fixed)
	}
	type plain bit
	return json.Unmarshal(raw, (*plain)(b))
}

type number int

func (n *number) UnmarshalJSON(raw []byte) error {
	var i int
	if json.Unmarshal(raw, &i) == nil {
		*n = number(i)
		return nil
	}
	var bits []int
	if err := json.Unmarshal(raw, &bits); err != nil {
		return err
	}
	for k, b := range bits {
		i |= b << uint(k)
	}
	*n = number(i)
	return nil
}

type ref struct {
	Def string `json:"def"`
}
type dag struct {
	Args []json.RawMessage `json:"args"`
}
type record struct {
	BaseOpcode ref
	imageInfo
	Inst                                                                                        []bit
	Size                                                                                        int
	AsmString, Namespace, AsmVariantName, DecoderNamespace, PostEncoderMethod                   string
	IsPseudo                                                                                    int `json:"isPseudo"`
	IsAsmParserOnly                                                                             int `json:"isAsmParserOnly"`
	InOperandList, OutOperandList                                                               dag
	AssemblerPredicate                                                                          ref
	VOP3P                                                                                       int
	IsAtomicRet                                                                                 int
	Gather4                                                                                     int
	Uses                                                                                        []ref
	HasSrc2AccX                                                                                 int `json:"hasSrc2AccX"`
	HasSrc2AccY                                                                                 int `json:"hasSrc2AccY"`
	Predicates                                                                                  []ref
	IsBranch                                                                                    int      `json:"isBranch"`
	IsCall                                                                                      int      `json:"isCall"`
	IsReturn                                                                                    int      `json:"isReturn"`
	IsConditionalBranch                                                                         int      `json:"isConditionalBranch"`
	Super                                                                                       []string `json:"!superclasses"`
	RegClass                                                                                    ref
	OperandType, PrintMethod, EncoderMethod, DecoderMethod, Name, Prefix, DefaultValue, AsmName string
	HasSGPR, HasVGPR, HasAGPR, BaseClassOrder                                                   int
	MemberList, AssemblerCondDag                                                                map[string]any
	Features, Implies                                                                           []ref
	HWEncoding                                                                                  []int
}
type imageInfo struct {
	NumExtraArgs                                                 number
	Coordinates, Gradients, G16, LodOrClampOrMip, MSAA, BVH, A16 int
}

type importer struct {
	raw        map[string]json.RawMessage
	records    map[string]*record
	names      map[string][]string
	predicates []string
}

func (p *importer) rec(name string) *record {
	if r := p.records[name]; r != nil {
		return r
	}
	r := new(record)
	_ = json.Unmarshal(p.raw[name], r)
	p.records[name] = r
	return r
}

var placeholder = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)
var wordWidth = regexp.MustCompile(`(?:_|^)(16|32|64|96|128|160|192|224|256|288|320|352|384|512|1024)(?:_|$)`)

// Parse accepts llvm-tblgen --dump-json output. The canonical architecture is
// amdgpu; amdgcn is accepted as an alias. Conflicting generations are exposed as
// source-derived FeatureSets and must be selected when decoding shader streams.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	return parseWithInspector(r, architecture, nil)
}

func parseWithInspector(r io.Reader, architecture string, inspect func(*importer)) (*codec.Catalog, error) {
	if architecture != "amdgpu" && architecture != "amdgcn" {
		return nil, fmt.Errorf("amdgpu: unknown architecture %q", architecture)
	}
	p := &importer{records: map[string]*record{}, names: map[string][]string{}}
	d := json.NewDecoder(r)
	if err := d.Decode(&p.raw); err != nil {
		return nil, fmt.Errorf("AMDGPU TableGen: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("AMDGPU TableGen: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(p.raw["!instanceof"], &instances); err != nil {
		return nil, err
	}
	ids, ok := instances["Instruction"]
	if !ok {
		return nil, fmt.Errorf("AMDGPU TableGen has no Instruction records")
	}
	sort.Strings(ids)
	p.predicates = instances["Predicate"]
	c := &codec.Catalog{Schema: codec.Schema, Architecture: "amdgpu", Source: "LLVM TableGen --dump-json (GCN/RDNA)", SourceLicense: sourceLicense, SourceLicenseID: "Apache-2.0 WITH LLVM-exception", FeatureSets: p.profiles(instances["Processor"])}
	for _, id := range ids {
		r := p.rec(id)
		if r.IsPseudo != 0 || r.Namespace == "TargetOpcode" || r.AsmString == "" {
			continue
		}
		e, err := p.encoding(id, r)
		if err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		p.operandDomains(&e, r)
		views, err := p.imageDomains(e, r)
		if err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		availableSource := false
		for _, view := range views {
			p.vopdDomains(&view, r)
			for _, aligned := range alignmentVariants(view) {
				for _, variant := range profileVariants(aligned) {
					for _, framed := range append([]codec.Encoding{variant}, p.literals(variant, r)...) {
						{
							available := false
							for _, fs := range c.FeatureSets {
								if compatible(framed.Features, fs) {
									available = true
									break
								}
							}
							if !available {
								continue
							}
						}
						availableSource = true
						c.Encodings = append(c.Encodings, framed)
						c.Encodings = append(c.Encodings, p.omittedZero(framed)...)
						if strings.Contains(framed.Syntax, "_e64 ") {
							alias := framed
							alias.ID += "/unsuffixed"
							alias.AssemblyOnly = true
							alias.Syntax = strings.Replace(alias.Syntax, "_e64 ", " ", 1)
							alias.Mnemonic = strings.Fields(alias.Syntax)[0]
							c.Encodings = append(c.Encodings, alias)
						}
						if strings.Contains(framed.ID, "_e32_") && !strings.Contains(framed.Syntax, "_dpp") && !strings.Contains(framed.Syntax, "_e32") {
							alias := framed
							alias.ID += "/e32"
							alias.AssemblyOnly = true
							alias.Syntax = strings.Replace(alias.Syntax, alias.Mnemonic, alias.Mnemonic+"_e32", 1)
							c.Encodings = append(c.Encodings, alias)
						}
					}
				}
			}
		}
		if !availableSource {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: "source feature conditions have no compatible processor profile"})
		}
	}
	for i := range c.Encodings {
		for j := range c.Encodings[i].Operands {
			o := &c.Encodings[i].Operands[j]
			var compact []codec.BitSlice
			for _, b := range o.Bits {
				if len(compact) > 0 {
					last := &compact[len(compact)-1]
					if last.InstructionBit+last.Width == b.InstructionBit && last.ValueBit+last.Width == b.ValueBit {
						last.Width += b.Width
						continue
					}
				}
				compact = append(compact, b)
			}
			o.Bits = compact
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if inspect != nil {
		inspect(p)
	}
	return c, nil
}
func classArgs(d dag) [][2]string {
	var out [][2]string
	for _, a := range d.Args {
		var pair []json.RawMessage
		if json.Unmarshal(a, &pair) != nil || len(pair) != 2 {
			continue
		}
		var r ref
		var n string
		_ = json.Unmarshal(pair[0], &r)
		_ = json.Unmarshal(pair[1], &n)
		out = append(out, [2]string{n, r.Def})
	}
	return out
}
func (p *importer) encoding(id string, r *record) (codec.Encoding, error) {
	if strings.Contains(id, "_pad_s_nop_") {
		return codec.Encoding{}, fmt.Errorf("source branch-relaxation composite is not an assembler instruction; use the branch followed by s_nop")
	}
	if strings.Contains(id, "_TFE_") && strings.Contains(r.AsmString, "store") {
		return codec.Encoding{}, fmt.Errorf("source store TFE form has no legal operand domain: LLVM forbids TFE on stores")
	}
	if len(r.Inst) == 0 || r.Size < 4 || r.Size*8 > len(r.Inst) || r.Size%4 != 0 {
		return codec.Encoding{}, fmt.Errorf("non-word instruction framing")
	}
	mnemonic := strings.Fields(strings.Split(strings.Split(r.AsmString, "$")[0], "{")[0])[0]
	e := codec.Encoding{ID: id, Mnemonic: mnemonic, FlowControl: "next"}
	switch {
	case r.IsReturn != 0:
		e.FlowControl = "return"
	case r.IsCall != 0:
		e.FlowControl = "call"
	case r.IsConditionalBranch != 0:
		e.FlowControl = "conditional_branch"
	case r.IsBranch != 0:
		e.FlowControl = "branch"
	}
	if r.AssemblerPredicate.Def != "" {
		e.Features = append(e.Features, r.AssemblerPredicate.Def)
	}
	guards := map[string]string{"GFX90A": "isGFX90APlus", "GFX8": "isGFX8GFX9", "GFX9": "isGFX9Only", "GFX10": "isGFX10Only", "GFX11": "isGFX11Only", "GFX12": "isGFX12Only"}
	if guard := guards[r.DecoderNamespace]; guard != "" {
		e.Features = append(e.Features, guard)
	}
	for _, pred := range r.Predicates {
		e.Features = append(e.Features, pred.Def)
	}
	args := append(classArgs(r.OutOperandList), classArgs(r.InOperandList)...)
	classes := map[string]string{}
	for _, a := range args {
		classes[a[0]] = a[1]
	}
	for name, class := range classes {
		if strings.HasSuffix(name, "_in") && classes[strings.TrimSuffix(name, "_in")] == "" {
			classes[strings.TrimSuffix(name, "_in")] = class
		}
	}
	// Some atomic non-returning forms name the tied data input vdata_in but
	// their physical field and printed syntax use vdata.
	for name, class := range classes {
		if strings.HasSuffix(name, "_in") && classes[strings.TrimSuffix(name, "_in")] == class {
			base := strings.TrimSuffix(name, "_in")
			found := false
			for _, a := range args {
				if a[0] == base {
					found = true
				}
			}
			if !found {
				args = append(args, [2]string{base, class})
			}
		}
	}
	inst := append([]bit(nil), r.Inst[:r.Size*8]...)
	arrayModifiers := p.rec(classes["src0_modifiers"]).PrintMethod == "printOpSel" && p.rec(classes["src1_modifiers"]).PrintMethod == "printOpSelHi"
	if arrayModifiers {
		classes["op_sel"], classes["op_sel_hi"] = "op_sel0", "op_sel_hi0"
		args = append(args, [2]string{"op_sel", "op_sel0"}, [2]string{"op_sel_hi", "op_sel_hi0"})
	}
	for i, b := range inst {
		if b.Kind == "complex" && strings.HasPrefix(b.Printable, "!if(!and(IsGFX9SpecificEncoding,") {
			inst[i] = bit{Set: true}
			if strings.Contains(b.Printable, "Encoding, 1)") && r.DecoderNamespace != "GFX8" {
				inst[i] = bit{Var: "soffset", Index: i - 57}
			}
		}
	}
	// Packed source modifiers are printed in grouped lane vectors rather than
	// as per-source negation/absolute-value decorations.
	for i, b := range inst {
		if !strings.HasSuffix(b.Var, "_modifiers") {
			continue
		}
		m := p.rec(classes[b.Var])
		if !contains(m.Super, "PackedFPInputMods") && !contains(m.Super, "PackedIntInputMods") && !(classes["op_sel"] != "" && b.Index >= 2) {
			continue
		}
		base := strings.TrimSuffix(b.Var, "_modifiers")
		if len(base) != 4 || base[:3] != "src" {
			continue
		}
		lane := int(base[3] - '0')
		if p.rec(classes[b.Var]).EncoderMethod == "getMachineOpValueT16" && b.Index == 3 && base == "src0" && classes["op_sel"] != "" {
			dstLane := 0
			for _, src := range []string{"src0", "src1", "src2"} {
				if classes[src] != "" {
					dstLane++
				}
			}
			inst[i] = bit{Var: "op_sel", Index: dstLane}
			continue
		}
		group := map[int]string{0: "neg_lo", 1: "neg_hi", 2: "op_sel", 3: "op_sel_hi"}[b.Index]
		if group != "" && classes[group] != "" {
			inst[i] = bit{Var: group, Index: lane}
		}
	}
	// MIMG's NSA addresses are individual VGPR bytes after the fixed encoding,
	// padded to a whole dword. Their count is defined by each source record.
	var nsa []string
	for _, a := range args {
		if strings.HasPrefix(a[0], "vaddr") && a[0] != "vaddr" && a[0] != "vaddr0" {
			if selectorWidth(inst, a[0]) == 0 {
				nsa = append(nsa, a[0])
			}
		}
	}
	if len(nsa) > 0 {
		for _, name := range nsa {
			for k := 0; k < 8; k++ {
				inst = append(inst, bit{Var: name, Index: k})
			}
		}
		for len(inst)%32 != 0 {
			inst = append(inst, bit{Set: true})
		}
	}
	// Packed instructions use source modifier bits for op_sel_hi. When the
	// source has no explicit op_sel_hi operand LLVM sets all three implicit bits.
	if (r.VOP3P != 0 || (classes["src0"] != "" && (contains(p.rec(classes["src0_modifiers"]).Super, "PackedFPInputMods") || contains(p.rec(classes["src0_modifiers"]).Super, "PackedIntInputMods")) && !strings.Contains(r.AsmString, "$src0_modifiers")) || id == "V_ACCVGPR_READ_B32_vi" || id == "V_ACCVGPR_WRITE_B32_vi") && classes["matrix_b_fmt"] == "" && classes["matrix_b_scale"] == "" && classes["matrix_b_reuse"] == "" {
		positions := []int{59, 60, 14}
		start := 0
		if classes["op_sel_hi"] != "" {
			start = 3
			if selectorWidth(inst, "src2") == 0 {
				start = 2
				if selectorWidth(inst, "src1") == 0 {
					start = 1
				}
			}
		}
		for _, pos := range positions[start:] {
			if pos < len(inst) {
				inst[pos] = bit{Set: true, Fixed: 1}
			}
		}
	}
	e.Mask = make([]byte, len(inst)/8)
	e.Value = make([]byte, len(inst)/8)
	asm := r.AsmString
	if arrayModifiers {
		asm = strings.ReplaceAll(strings.ReplaceAll(asm, "$src0_modifiers", "$op_sel"), "$src1_modifiers", "$op_sel_hi")
	}
	for _, suffix := range []string{"_e32", "_e64", "_sdwa", "_dpp", "_e64_dpp"} {
		asm = strings.ReplaceAll(asm, "${"+suffix+"}", suffix)
		asm = strings.ReplaceAll(asm, "{"+suffix+"}", suffix)
	}
	syntax := placeholder.ReplaceAllStringFunc(asm, func(s string) string {
		m := placeholder.FindStringSubmatch(s)
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if strings.HasPrefix(name, "_e") || name == "_sdwa" || name == "_dpp" {
			return name
		}
		return "{" + name + "}"
	})
	syntax = strings.ReplaceAll(syntax, "{format}{soffset}", "{soffset}{format}")
	syntax = strings.ReplaceAll(syntax, "{format} {soffset}", "{soffset}{format}")
	if strings.HasPrefix(syntax, e.Mnemonic+"{") {
		syntax = e.Mnemonic + " " + strings.TrimPrefix(syntax, e.Mnemonic)
	}
	if r.AsmVariantName == "VOP3" && !strings.Contains(syntax, e.Mnemonic+"_e64") {
		syntax = strings.Replace(syntax, e.Mnemonic, e.Mnemonic+"_e64", 1)
	}
	if (strings.HasPrefix(r.AsmVariantName, "DPP") || r.AsmVariantName == "VOP3_DPP") && !strings.Contains(syntax, "_dpp") {
		suffix := "_dpp"
		if r.AsmVariantName == "VOP3_DPP" {
			suffix = "_e64_dpp"
		}
		syntax = strings.Replace(syntax, e.Mnemonic, e.Mnemonic+suffix, 1)
	}
	if strings.HasPrefix(r.AsmVariantName, "SDWA") && !strings.Contains(syntax, e.Mnemonic+"_sdwa") {
		syntax = strings.Replace(syntax, e.Mnemonic, e.Mnemonic+"_sdwa", 1)
	}
	// Source input modifiers print the following source operand, so merge their
	// scattered bits and register/inline selector into one enumeration.
	merged := map[string]string{}
	modWidth := map[string]int{}
	for name, class := range classes {
		if strings.Contains(p.rec(class).PrintMethod, "InputMods") && (!(contains(p.rec(class).Super, "PackedFPInputMods") || contains(p.rec(class).Super, "PackedIntInputMods")) || strings.Contains(syntax, "{"+name+"}")) {
			base := strings.TrimSuffix(name, "_modifiers")
			if base == name || classes[base] == "" {
				return e, fmt.Errorf("unresolved input modifier %s", name)
			}
			merged[name] = base
			modWidth[base] = selectorWidth(inst, base)
			syntax = strings.ReplaceAll(syntax, "{"+name+"}", "{"+base+"}")
		}
	}
	fields := map[string]*codec.Operand{}
	for i, b := range inst {
		if b.Set {
			e.Mask[i/8] |= 1 << uint(i%8)
			if b.Fixed != 0 {
				e.Value[i/8] |= 1 << uint(i%8)
			}
			continue
		}
		if b.Var == "" {
			return e, fmt.Errorf("unresolved source bit %d", i)
		}
		name := b.Var
		valuebit := b.Index
		if base, ok := merged[name]; ok {
			name = base
			valuebit += modWidth[base]
		}
		o := fields[name]
		if o == nil {
			o = &codec.Operand{Name: name, Class: classes[name], Kind: "immediate"}
			fields[name] = o
		}
		o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: i, ValueBit: valuebit, Width: 1})
	}
	// AMD's assembler patches the implicit CMPX destination to EXEC.
	if r.PostEncoderMethod == "postEncodeVOPCX" {
		for i := 0; i < 7; i++ {
			if e.Mask[i/8]&(1<<uint(i%8)) != 0 {
				if 126&(1<<uint(i)) != 0 {
					e.Value[i/8] |= 1 << uint(i%8)
				} else {
					e.Value[i/8] &= ^(1 << uint(i%8))
				}
			}
		}
	}
	for _, a := range args {
		name := a[0]
		if _, ok := merged[name]; ok {
			continue
		}
		o := fields[name]
		if o == nil {
			replacement := ""
			if strings.HasPrefix(name, "imm") && fields["imm"] != nil {
				replacement = "{imm}"
			}
			if name == "cpol" && strings.Contains(id, "_RTN_") && strings.Contains(r.DecoderNamespace, "GFX12") {
				replacement = " th:TH_ATOMIC_RETURN"
			}
			if name == "cpol" && strings.Contains(id, "_RTN_") && !strings.Contains(r.DecoderNamespace, "GFX12") {
				replacement = " glc"
				if strings.Contains(id, "gfx940") || sourceGFX940(r) {
					replacement = " sc0"
				}
			}
			syntax = strings.ReplaceAll(syntax, "{"+name+"}", replacement)
			continue
		}
		meta := p.rec(o.Class)
		if meta.PrintMethod == "printDPP8" {
			var tokens []string
			for lane := 0; lane < 8; lane++ {
				part := codec.Operand{Name: fmt.Sprintf("%s_%d", name, lane), Class: "dpp8_lane", Kind: "immediate"}
				for _, b := range o.Bits {
					if b.ValueBit/3 == lane {
						b.ValueBit %= 3
						part.Bits = append(part.Bits, b)
					}
				}
				e.Operands = append(e.Operands, part)
				tokens = append(tokens, "{"+part.Name+"}")
			}
			syntax = strings.ReplaceAll(syntax, "{"+name+"}", " dpp8:["+strings.Join(tokens, ",")+"]")
			delete(fields, name)
			continue
		}
		numeric := numericPrefix(meta)
		if numeric != "" && o.Width() > 6 {
			syntax = strings.ReplaceAll(syntax, "{"+name+"}", " "+numeric+":{"+name+"}")
		}
		if err := p.operand(o, r, modWidth[name]); err != nil {
			return e, err
		}
		if name == "cpol" && strings.Contains(id, "_RTN_") && !strings.Contains(r.DecoderNamespace, "GFX12") {
			var hasGLC bool
			for _, b := range o.Bits {
				if b.ValueBit == 0 {
					hasGLC = true
				}
			}
			if !hasGLC {
				label := " glc"
				if strings.Contains(id, "gfx940") || sourceGFX940(r) {
					label = " sc0"
				}
				o.Names = append([]string(nil), o.Names...)
				for k, n := range o.Names {
					if n != "" {
						o.Names[k] = label + n
					}
				}
			}
		}
		if !strings.Contains(syntax, "{"+name+"}") {
			o.Implicit = true
		}
		e.Operands = append(e.Operands, *o)
		delete(fields, name)
	}
	var extra []string
	for n := range fields {
		extra = append(extra, n)
	}
	sort.Strings(extra)
	for _, n := range extra {
		o := fields[n]
		o.Implicit = true
		e.Operands = append(e.Operands, *o)
	}
	e.Syntax = strings.TrimSpace(syntax)
	// LLVM deliberately supplies disassembler-only variants for alternative
	// physical encodings. Preserve their otherwise unprinted fields and give
	// them an exact spelling, rather than dropping valid instruction bytes or
	// silently normalizing them to the assembler's preferred encoding.
	if r.AsmVariantName == "NonParsable" {
		e.Syntax = "enc[" + id + "] " + e.Syntax
		for i := range e.Operands {
			o := &e.Operands[i]
			if !strings.Contains(e.Syntax, "{"+o.Name+"}") {
				e.Syntax += " " + o.Name + ":{" + o.Name + "}"
			}
			o.Implicit = false
		}
	}
	for _, m := range regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`).FindAllStringSubmatch(e.Syntax, -1) {
		found := false
		for _, o := range e.Operands {
			if o.Name == m[1] {
				found = true
			}
		}
		if !found {
			return e, fmt.Errorf("unresolved syntax operand %s", m[1])
		}
	}
	return e, nil
}
func selectorWidth(bits []bit, name string) int {
	w := 0
	for _, b := range bits {
		if b.Var == name && b.Index >= w {
			w = b.Index + 1
		}
	}
	return w
}
func (p *importer) operand(o *codec.Operand, r *record, mergedWidth int) error {
	meta := p.rec(o.Class)
	regclass := meta.RegClass.Def
	if regclass == "" && contains(meta.Super, "RegisterClassLike") {
		regclass = o.Class
	}
	if regclass != "" {
		o.Kind = "register"
		width := o.Width()
		selectorBits := width
		if mergedWidth != 0 {
			selectorBits = mergedWidth
		}
		names, err := p.registerNames(regclass, meta, selectorBits, r)
		if err != nil {
			return err
		}
		if mergedWidth != 0 {
			base := names
			names = make([]string, 1<<width)
			for i := range names {
				s := base[i&((1<<mergedWidth)-1)]
				if s == "" {
					continue
				}
				mods := i >> mergedWidth
				if mods&2 != 0 {
					s = "|" + s + "|"
				}
				if mods&1 != 0 {
					s = "-" + s
				}
				if strings.Contains(o.Class, "Int") {
					if mods&16 != 0 {
						s = "sext(" + base[i&((1<<mergedWidth)-1)] + ")"
					}
					if mods&^16 != 0 {
						continue
					}
				} else if mods&^3 != 0 {
					continue
				}
				if mods&1 != 0 && mods&2 == 0 && (base[i&((1<<mergedWidth)-1)][0] == '-' || base[i&((1<<mergedWidth)-1)][0] >= '0' && base[i&((1<<mergedWidth)-1)][0] <= '9') {
					s = "neg(" + base[i&((1<<mergedWidth)-1)] + ")"
				}
				names[i] = s
			}
		}
		if meta.EncoderMethod == "getAVOperandEncoding" {
			hasBank := false
			for _, b := range o.Bits {
				if b.ValueBit == 8 {
					hasBank = true
				}
			}
			if hasBank {
				shifted := make([]string, len(names))
				for k, n := range names {
					if k+256 < len(names) {
						shifted[k+256] = n
					}
				}
				names = shifted
			}
		}
		o.Names = names
		return nil
	}
	if meta.OperandType == "OPERAND_INLINE_SPLIT_BARRIER_INT32" {
		o.Names = make([]string, 1<<o.Width())
		for k := 128; k <= 192 && k < len(o.Names); k++ {
			o.Names[k] = fmt.Sprint(k - 128)
		}
		return nil
	}
	if meta.EncoderMethod == "getSOPPBrEncoding" {
		o.Signed = true
		o.Scale = 4
		o.Relative = true
		o.PCBias = 4
		o.Kind = "address"
		return nil
	}
	if strings.Contains(meta.OperandType, "PCREL") {
		o.Signed = true
		o.Scale = 4
		o.Relative = true
		o.PCBias = 4
		o.Kind = "address"
		return nil
	}
	if numericPrefix(meta) != "" && o.Width() > 6 {
		if meta.PrintMethod == "printFlatOffset" && (strings.Contains(r.DecoderNamespace, "GFX12") || strings.Contains(r.AsmString, "global_") || strings.Contains(r.AsmString, "scratch_")) {
			o.Signed = true
		}
		return nil
	}
	if o.Width() <= 16 {
		if names, ok := p.suffixNames(o, meta, r); ok {
			o.Names = names
			if prefix := numericPrefix(meta); prefix != "" {
				def, _ := strconv.ParseInt(meta.DefaultValue, 0, 64)
				o.RegisterAliases = map[string]int64{fmt.Sprintf("%s:%d", prefix, def): def}
			}
			return nil
		}
	}
	if strings.Contains(meta.OperandType, "KIMM") || strings.HasPrefix(o.Class, "i") || strings.Contains(o.Class, "imm") || meta.PrintMethod == "printOperand" || meta.PrintMethod == "printSWaitCnt" || meta.PrintMethod == "printSMEMOffset" || meta.PrintMethod == "printSMRDOffset8" || meta.PrintMethod == "printSMRDLiteralOffset" || meta.PrintMethod == "printU16ImmOperand" {
		return nil
	}
	if meta.PrintMethod == "printSwizzle" || meta.PrintMethod == "printSendMsg" || meta.PrintMethod == "printDepCtr" || meta.PrintMethod == "printSDelayALU" || meta.PrintMethod == "printGPRIdxMode" {
		return nil
	}
	if meta.Prefix != "" {
		return nil
	}
	if meta.PrintMethod != "" {
		return fmt.Errorf("operand %s uses unimplemented %s printer %s", o.Name, o.Class, meta.PrintMethod)
	}
	return nil
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

func compatible(required, active []string) bool {
	for _, r := range required {
		if !contains(active, r) {
			return false
		}
	}
	return true
}

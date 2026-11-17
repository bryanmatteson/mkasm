// Package mips imports LLVM's resolved MIPS instruction descriptions.
// Standard MIPS32/MIPS64, microMIPS, and MIPS16 use separate mode catalogs in
// either byte order; selecting a compressed catalog does not switch mode at run time.
// The catalog retains LLVM predicates, allowing callers to select ISA revisions
// and extensions with codec's feature-aware assembly/disassembly methods.
package mips

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
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
func predicates(r record) []string {
	a, _ := r["Predicates"].([]any)
	var out []string
	for _, p := range a {
		out = append(out, def(p))
	}
	return out
}
func has(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

var tied = regexp.MustCompile(`\$([A-Za-z0-9_]+)\s*=\s*\$([A-Za-z0-9_]+)`)
var placeholder = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::[^}]+)?\}|\$([A-Za-z0-9_]+)`)

// Parse consumes real llvm-tblgen --dump-json output. Each architecture selects
// one physical execution mode; compressed MIPS16 and microMIPS records must not
// shadow instructions from another mode.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	switch architecture {
	case "mips32", "mips32el", "mips64", "mips64el", "micromips32", "micromips32el", "micromips64", "micromips64el", "mips16", "mips16el", "mips16-64", "mips16-64el":
	default:
		return nil, fmt.Errorf("unsupported MIPS architecture %q", architecture)
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("MIPS TableGen: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("MIPS TableGen: trailing input")
	}
	var instances map[string][]string
	if err := json.Unmarshal(raw["!instanceof"], &instances); err != nil {
		return nil, fmt.Errorf("MIPS TableGen missing !instanceof: %w", err)
	}
	records := map[string]record{}
	get := func(id string) record {
		if v, ok := records[id]; ok {
			return v
		}
		var v record
		_ = json.Unmarshal(raw[id], &v)
		records[id] = v
		return v
	}
	is64 := strings.Contains(architecture, "64")
	micro := strings.HasPrefix(architecture, "micromips")
	mips16 := strings.HasPrefix(architecture, "mips16")
	var ids []string
	var excluded []codec.Unsupported
	for _, id := range instances["Instruction"] {
		rec := get(id)
		if str(rec["Namespace"]) != "Mips" || num(rec["isPseudo"]) != 0 || num(rec["isAsmParserOnly"]) != 0 || str(rec["AsmString"]) == "" {
			continue
		}
		ps := predicates(rec)
		isMicro := has(ps, "InMicroMips") || strings.HasPrefix(str(rec["DecoderNamespace"]), "MicroMips")
		is16 := has(ps, "InMips16Mode")
		if isMicro != micro || is16 != mips16 {
			continue
		}
		if !is64 && (has(ps, "IsGP64bit") || has(ps, "IsPTR64bit") || has(ps, "HasMips3") || has(ps, "HasMips64") || has(ps, "HasMips64r2") || has(ps, "HasMips64r5") || has(ps, "HasMips64r6")) {
			continue
		}
		if is64 && (has(ps, "IsGP32bit") || has(ps, "IsPTR32bit")) {
			continue
		}
		if !is64 {
			needs64 := false
			for _, key := range []string{"InOperandList", "OutOperandList"} {
				for _, a := range args(rec[key]) {
					if strings.HasPrefix(def(a[0]), "GPR64") {
						needs64 = true
					}
				}
			}
			if needs64 {
				continue
			}
		}
		if micro || mips16 {
			prepareCompressed(rec, mips16)
		}
		// TableGen custom decoders reconstruct some tied operands omitted from Inst.
		syntax := str(rec["AsmString"])
		if mips16 {
			syntax = strings.Split(syntax, "#")[0]
			// Literal registers use $$ in TableGen printer strings.
			for _, name := range []string{"sp", "pc", "ra", "zero"} {
				syntax = strings.ReplaceAll(syntax, "$$"+name, "\x01"+name)
			}
		}
		encoded := map[string]bool{}
		inst, _ := rec["Inst"].([]any)
		for _, v := range inst {
			if m, ok := v.(map[string]any); ok {
				encoded[str(m["var"])] = true
			}
		}
		for _, m := range tied.FindAllStringSubmatch(str(rec["Constraints"]), -1) {
			from, to := m[1], m[2]
			if encoded[from] && !encoded[to] {
				from, to = to, from
			}
			if encoded[to] {
				syntax = replaceHole(syntax, from, to)
			}
		}
		if str(rec["DecoderMethod"]) == "DecodeCRC" {
			syntax = replaceHole(syntax, "rd", "rt")
		}
		for _, key := range []string{"InOperandList", "OutOperandList"} {
			for _, a := range args(rec[key]) {
				if def(a[0]) == "uimmz" {
					syntax = literalHole(syntax, str(a[1]), "0")
				}
			}
		}
		rec["AsmString"] = syntax
		ids = append(ids, id)
	}
	// Keep source records available for register and operand class information,
	// but feed only explicitly selected machine instructions to the generic importer.
	// LLVM aliases targeting a real selected machine instruction are also
	// declarative encodings: bind constant/tied result operands in its Inst bits.
	selectedIDs := map[string]bool{}
	for _, id := range ids {
		selectedIDs[id] = true
	}
	for _, aliasID := range instances["InstAlias"] {
		alias := get(aliasID)
		ps := predicates(alias)
		if !is64 && (has(ps, "IsGP64bit") || has(ps, "IsPTR64bit") || has(ps, "HasMips3") || has(ps, "HasMips64") || has(ps, "HasMips64r2") || has(ps, "HasMips64r5") || has(ps, "HasMips64r6")) {
			continue
		}
		if is64 && (has(ps, "IsGP32bit") || has(ps, "IsPTR32bit")) {
			continue
		}
		dag, _ := alias["ResultInst"].(map[string]any)
		targetID := def(dag["operator"])
		if !selectedIDs[targetID] {
			continue
		}
		clone, err := aliasRecord(alias, records[targetID], get)
		if err != nil {
			excluded = append(excluded, codec.Unsupported{ID: aliasID, Reason: err.Error()})
			continue
		}
		records[aliasID] = clone
		ids = append(ids, aliasID)
	}
	instances["Instruction"] = ids
	selected := map[string]any{"!instanceof": instances}
	for _, id := range ids {
		selected[id] = records[id]
	}
	b, err := json.Marshal(selected)
	if err != nil {
		return nil, err
	}
	wordBytes := 0
	if micro || mips16 {
		wordBytes = 2
	}
	c, err := codec.ParseTableGen(bytes.NewReader(b), codec.TableGenOptions{Architecture: architecture, LittleEndian: strings.HasSuffix(architecture, "el"), WordBytes: wordBytes})
	if err != nil {
		return nil, err
	}
	c.Unsupported = append(c.Unsupported, excluded...)
	var out []codec.Encoding
	for _, e := range c.Encodings {
		if mips16 {
			e.Syntax = strings.ReplaceAll(e.Syntax, "\x01", "$")
		}
		if err := adapt(&e, records[e.ID], get, is64); err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: e.ID, Reason: err.Error()})
			continue
		}
		if micro || mips16 {
			if err := adaptCompressed(&e, records[e.ID], get, mips16); err != nil {
				c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: e.ID, Reason: err.Error()})
				continue
			}
		}
		out = append(out, e)
		// Symmetric comparisons can commute to satisfy the register partition
		// selecting the physical opcode (LLVM's BEQC/BNEC parser omits this).
		// Preserve exact structured operands while admitting both text orders.
		switch str(records[e.ID]["!name"]) {
		case "BOVC_MMR6", "BNVC_MMR6", "BEQC_MMR6", "BNEC_MMR6":
			if strings.Contains(e.Syntax, "{rs}") && strings.Contains(e.Syntax, "{rt}") {
				e.ID += "_commuted"
				e.Syntax = strings.NewReplacer("{rs}", "{rt}", "{rt}", "{rs}").Replace(e.Syntax)
				e.AssemblyOnly = true
				out = append(out, e)
			}
		}
		// GNU uses unsuffixed mnemonics for these short physical memory forms.
		// Keep LLVM's exact spelling for decode and accept both for assembly.
		switch e.ID {
		case "LBU16_MM", "LHU16_MM", "LW16_MM", "SB16_MM", "SH16_MM", "SW16_MM":
			e.ID += "_generic_spelling"
			e.Mnemonic = strings.TrimSuffix(e.Mnemonic, "16")
			e.Syntax = strings.Replace(e.Syntax, strings.Fields(e.Syntax)[0], e.Mnemonic, 1)
			e.AssemblyOnly = true
			out = append(out, e)
		}
	}
	c.Encodings = out
	if micro && is64 {
		if err := addGNUMicro64(c); err != nil {
			return nil, err
		}
		c.SourceLicense += "; GPL-3.0-or-later (GNU microMIPS64 machine rows)"
	}
	if mips16 {
		if err := addGNUMips16(c); err != nil {
			return nil, err
		}
		// Prefer GNU's architectural address aliases over compiler-facing
		// displacement spellings for equal-specificity MIPS16 decodings.
		sort.SliceStable(c.Encodings, func(i, j int) bool {
			return strings.HasPrefix(c.Encodings[i].ID, "GNU_MIPS16_ROW_") && !strings.HasPrefix(c.Encodings[j].ID, "GNU_MIPS16_ROW_")
		})
		for _, e := range c.Encodings {
			fp := strings.ReplaceAll(e.Syntax, "$s8", "$fp")
			if fp != e.Syntax {
				alias := e
				alias.ID += "_fp_literals"
				alias.Syntax = fp
				alias.AssemblyOnly = true
				c.Encodings = append(c.Encodings, alias)
			}
			numeric := strings.NewReplacer("$ra", "$31", "$sp", "$29", "$zero", "$0").Replace(e.Syntax)
			if numeric != e.Syntax {
				e.ID += "_numeric_literals"
				e.Syntax = numeric
				e.AssemblyOnly = true
				c.Encodings = append(c.Encodings, e)
			}
		}
	}
	sort.Slice(c.Unsupported, func(i, j int) bool { return c.Unsupported[i].ID < c.Unsupported[j].ID })
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Catalog{Catalog: c}, nil
}
func replaceHole(s, from, to string) string {
	return placeholder.ReplaceAllStringFunc(s, func(v string) string {
		m := placeholder.FindStringSubmatch(v)
		n := m[1]
		if n == "" {
			n = m[2]
		}
		if n == from {
			return "$" + to
		}
		return v
	})
}

func adapt(e *codec.Encoding, rec record, get func(string) record, is64 bool) error {
	var out []codec.Operand
	for _, o := range e.Operands {
		class := get(o.Class)
		if strings.HasPrefix(o.Class, "mem") {
			// LLVM getMemEncoding packs base in value bits 16..20 independently
			// of the offset width and physical position of instruction fields.
			base := codec.Operand{Name: o.Name + "_base", Class: "GPR32Opnd", Kind: "register"}
			off := codec.Operand{Name: o.Name + "_offset", Kind: "displacement", Signed: true}
			baseShift := 16
			if strings.HasPrefix(o.Class, "mem_mm_4") && o.Class != "mem_mm_4sp" {
				baseShift = 4
				base.Class = "GPRMM16Opnd"
				off.Signed = false
			}
			for _, b := range o.Bits {
				if b.ValueBit >= baseShift {
					b.ValueBit -= baseShift
					base.Bits = append(base.Bits, b)
				} else {
					off.Bits = append(off.Bits, b)
				}
			}
			fixedBase := ""
			if o.Class == "mem_mm_gp_simm7_lsl2" {
				fixedBase = "$gp"
			}
			if o.Class == "mem_mm_sp_imm5_lsl2" || o.Class == "mem_mm_4sp" {
				fixedBase = "$sp"
				off.Signed = false
			}
			if (len(base.Bits) == 0 && fixedBase == "") || len(off.Bits) == 0 {
				return fmt.Errorf("memory class %s has unsupported composite encoding", o.Class)
			}
			if strings.Contains(o.Class, "_lsl") {
				i := strings.LastIndex(o.Class, "_lsl")
				shift, err := strconv.Atoi(o.Class[i+4:])
				if err != nil {
					return fmt.Errorf("unknown memory scale %s", o.Class)
				}
				off.Scale = 1 << shift
			}
			if fixedBase == "" {
				if err := register(&base, get(base.Class), get, is64); err != nil {
					return err
				}
			}
			if o.Class == "mem_mm_4sp" {
				off.Scale = 4
			}
			// DecodeMemMMImm4 reserves raw offset 15 for -1 on LBU16;
			// the otherwise identical SB16 field remains unsigned.
			if str(rec["!name"]) == "LBU16_MM" {
				off.Lookup = []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, -1}
			}
			replacement := "{" + off.Name + "}({" + base.Name + "})"
			if fixedBase != "" {
				replacement = "{" + off.Name + "}(" + fixedBase + ")"
			}
			if o.Class == "mem_ea" {
				replacement = "{" + base.Name + "}, {" + off.Name + "}"
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", replacement)
			out = append(out, off)
			if fixedBase == "" {
				out = append(out, base)
			}
			continue
		}
		if def(class["RegClass"]) != "" || class["MemberList"] != nil || o.Class == "PtrRC" {
			if o.Class == "PtrRC" {
				class = get("GPR32Opnd")
			}
			if err := register(&o, class, get, is64); err != nil {
				return err
			}
		} else {
			if o.Class == "" {
				return fmt.Errorf("encoding variable %s lacks an operand class", o.Name)
			}
			if strings.HasPrefix(o.Class, "simm") || strings.HasPrefix(o.Class, "vsplat_simm") {
				o.Signed = true
			}
			if o.Class == "simm16_relaxed" || o.Class == "uimm16_relaxed" || o.Class == "uimm16_64_relaxed" {
				o.InputSignedBits = 16
			}
			switch {
			case o.Class == "condcode":
				o.Names = []string{"f", "un", "eq", "ueq", "olt", "ult", "ole", "ule", "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt"}
			case strings.HasPrefix(o.Class, "brtarget"):
				o.Kind = "displacement"
				o.Signed = true
				o.Scale = 4
				o.Relative = true
				o.PCBias = 4
			case o.Class == "jmptarget" || o.Class == "calltarget":
				o.Kind = "address"
				o.Scale = 4
				o.Relative = true
				o.PCRegionBits = 28
				o.PCBias = 4
			case o.Class == "jmpoffset16" || o.Class == "calloffset16":
				o.Signed = true
			case strings.Contains(o.Class, "_lsl"):
				i := strings.LastIndex(o.Class, "_lsl")
				shift, err := strconv.Atoi(o.Class[i+4:])
				if err != nil {
					return fmt.Errorf("unknown immediate scale %s", o.Class)
				}
				o.Scale = 1 << shift
			case strings.Contains(o.Class, "inssize") || o.Class == "uimm_range_2_64":
				o.Bias = 1
				if str(rec["!name"]) == "DINSM" || str(rec["!name"]) == "DINSU" {
					o.Bias = 33
				}
				o.BiasOperand = "pos"
				o.BiasScale = -1
			case strings.Contains(o.Class, "plus33"):
				o.Bias = 33
			case strings.Contains(o.Class, "plus32"):
				o.Bias = 32
			case strings.Contains(o.Class, "plus1"):
				o.Bias = 1
			}
			// An unhandled encoder is a real behavior gap, not an identity transform.
			method := str(class["EncoderMethod"])
			compressedHandled := compressedOperand(&o, rec, class)
			if method != "" && !compressedHandled && !strings.HasPrefix(method, "getBranchTarget") && !strings.HasPrefix(method, "getUImmWithOffsetEncoding") && method != "getJumpTargetOpValue" && method != "getJumpOffset16OpValue" && method != "getSimm19Lsl2Encoding" && method != "getSimm18Lsl3Encoding" && method != "getSizeInsEncoding" {
				return fmt.Errorf("operand %s requires custom encoder %s", o.Class, method)
			}
		}
		if aliasClasses, ok := rec["mkasmAliasClasses"].(map[string]string); ok {
			switch cl := aliasClasses[o.Name]; {
			case strings.HasPrefix(cl, "InvertedImOperand"):
				o.Signed = true
				o.InputSignedBits = 0
				o.Bias = 1
				o.Xor = (uint64(1) << o.Width()) - 1
			case strings.HasPrefix(cl, "uimm5_plus32_normalize"):
				o.Bias = 32
			}
		}
		if o.Relative && !is64 {
			o.PCWrapBits = 32
		}
		out = append(out, o)
	}
	e.Operands = out
	for _, o := range out {
		if o.BiasOperand != "" {
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: o.Name, Right: ""}, codec.Constraint{Kind: "ge", Left: o.Name, Right: ""})
		}
	}
	switch str(rec["!name"]) {
	case "EXT", "INS":
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "sum_le", Left: "pos", Right: "size", Limit: 32})
	case "DEXT", "DEXTM", "DEXTU", "DINS", "DINSM", "DINSU":
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "sum_le", Left: "pos", Right: "size", Limit: 64})
	}
	// Release 6 compact branches have opcode sharing constraints, checked during
	// both encode and decode rather than relying solely on overlapping bit masks.
	switch strings.TrimSuffix(str(rec["!name"]), "_MMR6") {
	case "BOVC", "BNVC":
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ge", Left: "rs", Right: "rt"})
	case "BEQC", "BNEC":
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: "rs", Right: ""}, codec.Constraint{Kind: "ne", Left: "rt", Right: "rs"}, codec.Constraint{Kind: "ge", Left: "rt", Right: "rs"})
	case "BGEC", "BLTC", "BGEUC", "BLTUC":
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: "rs", Right: ""}, codec.Constraint{Kind: "ne", Left: "rt", Right: ""}, codec.Constraint{Kind: "ne", Left: "rs", Right: "rt"})
	case "BEQZALC", "BNEZALC", "BLEZC", "BGTZC", "BGEZC", "BLTZC", "BLEZALC", "BGTZALC", "BGEZALC", "BLTZALC":
		name := "rt"
		for _, o := range e.Operands {
			if o.Kind == "register" {
				name = o.Name
				break
			}
		}
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: name, Right: ""})
	}
	return nil
}

func register(o *codec.Operand, class record, get func(string) record, is64 bool) error {
	rc := def(class["RegClass"])
	if rc != "" {
		class = get(rc)
	}
	var members func(any) ([]string, error)
	members = func(v any) ([]string, error) {
		if name := def(v); name != "" {
			return []string{name}, nil
		}
		dag, _ := v.(map[string]any)
		a := args(v)
		switch def(dag["operator"]) {
		case "add":
			var out []string
			for _, p := range a {
				n, err := members(p[0])
				if err != nil {
					return nil, err
				}
				out = append(out, n...)
			}
			return out, nil
		case "sequence":
			if len(a) != 3 {
				return nil, fmt.Errorf("invalid register sequence")
			}
			var out []string
			for i := num(a[1][0]); i <= num(a[2][0]); i++ {
				out = append(out, fmt.Sprintf(strings.ReplaceAll(str(a[0][0]), "%u", "%d"), i))
			}
			return out, nil
		}
		return nil, fmt.Errorf("unsupported register set %s", o.Class)
	}
	names, err := members(class["MemberList"])
	if err != nil {
		return err
	}
	o.Kind = "register"
	o.RegisterPrefix = "$"
	o.Names = make([]string, 1<<o.Width())
	o.RegisterAliases = map[string]int64{}
	for index, name := range names {
		rec := get(name)
		bits, _ := rec["HWEncoding"].([]any)
		n := 0
		for i, b := range bits {
			n |= num(b) << i
		}
		hardware := n
		if o.Width() <= 3 && strings.HasPrefix(rc, "GPRMM16") {
			n = index
		} else if o.Width() <= 3 && (rc == "CPU16Regs" || o.Class == "CPU16Regs") {
			// CPU16Regs is ordered for allocation, unlike the microMIPS
			// decoder classes. MIPS16 encodes s0/s1 as 0/1 and v0..a3 as
			// 2..7, i.e. the low three hardware register-number bits.
			n = hardware & 7
		}
		if n >= len(o.Names) || rc == "MSACtrl" && n > 7 {
			continue
		}
		spelling := str(rec["AsmName"])
		if spelling == "" {
			continue
		}
		// LLVM's register records carry O32 names. N64 names differ for 8..15.
		if is64 && (strings.HasPrefix(rc, "GPR") || strings.HasPrefix(o.Class, "GPR") || o.Class == "PtrRC") && n >= 8 && n <= 15 {
			if n < 12 {
				spelling = fmt.Sprintf("a%d", n-4)
			} else {
				spelling = fmt.Sprintf("t%d", n-12)
			}
		}
		o.Names[n] = "$" + spelling
		o.RegisterAliases[fmt.Sprintf("$%d", hardware)] = int64(n)
		if n == 30 && (strings.HasPrefix(rc, "GPR") || strings.HasPrefix(o.Class, "GPR")) {
			o.RegisterAliases["$s8"] = 30
		}
	}
	return nil
}

func literalHole(s, name, value string) string {
	return placeholder.ReplaceAllStringFunc(s, func(v string) string {
		m := placeholder.FindStringSubmatch(v)
		n := m[1]
		if n == "" {
			n = m[2]
		}
		if n == name {
			return value
		}
		return v
	})
}

func aliasRecord(alias, target record, get func(string) record) (record, error) {
	syntax := str(alias["AsmString"])
	mnemonic := strings.Fields(syntax)
	if len(mnemonic) == 0 || strings.Contains(mnemonic[0], ",") {
		return nil, fmt.Errorf("malformed source alias mnemonic")
	}
	if strings.Contains(syntax, "$$rs") {
		return nil, fmt.Errorf("source alias spells a variable as a literal register")
	}

	// Clone through JSON so bindings never modify another instruction's DAG/bits.
	b, _ := json.Marshal(target)
	var clone record
	_ = json.Unmarshal(b, &clone)
	var sourceArgs [][]any
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		sourceArgs = append(sourceArgs, args(target[key])...)
	}
	actual := args(alias["ResultInst"])
	if len(sourceArgs) != len(actual) {
		// InstAlias omits tied input operands in forms such as DINSM/DINSU.
		equal := map[string]string{}
		for _, m := range tied.FindAllStringSubmatch(str(target["Constraints"]), -1) {
			equal[m[1]] = m[2]
			equal[m[2]] = m[1]
		}
		expanded := [][]any{}
		byName := map[string][]any{}
		next := 0
		for _, a := range sourceArgs {
			name := str(a[1])
			if previous, ok := byName[equal[name]]; ok {
				expanded = append(expanded, previous)
				byName[name] = previous
				continue
			}
			if next >= len(actual) {
				return nil, fmt.Errorf("alias result arity requires custom reconstruction")
			}
			expanded = append(expanded, actual[next])
			byName[name] = actual[next]
			next++
		}
		if next != len(actual) {
			return nil, fmt.Errorf("alias result arity requires custom reconstruction")
		}
		actual = expanded
	}
	type binding struct {
		name    string
		fixed   int
		isFixed bool
		class   any
	}
	bindings := map[string]binding{}
	aliasClasses := map[string]string{}
	var dagArgs []any
	seen := map[string]bool{}
	for i, a := range sourceArgs {
		src := str(a[1])
		value := actual[i][0]
		name := str(actual[i][1])
		bind := binding{name: name, class: a[0]}
		if name == "" {
			bind.isFixed = true
			if v, ok := value.(float64); ok {
				bind.fixed = int(v)
			} else if r := get(def(value)); r["HWEncoding"] != nil {
				bits, _ := r["HWEncoding"].([]any)
				for i, v := range bits {
					bind.fixed |= num(v) << i
				}
			} else {
				return nil, fmt.Errorf("alias requires a non-constant operand transform")
			}
		} else if !seen[name] {
			dagArgs = append(dagArgs, []any{a[0], name})
			seen[name] = true
		}
		bindings[src] = bind
		if name != "" {
			aliasClasses[name] = def(value)
		}
	}
	inst, _ := clone["Inst"].([]any)
	for i, v := range inst {
		bit, ok := v.(map[string]any)
		if !ok {
			continue
		}
		bind, ok := bindings[str(bit["var"])]
		if !ok {
			return nil, fmt.Errorf("alias cannot bind encoding variable %s", str(bit["var"]))
		}
		if bind.isFixed {
			inst[i] = (bind.fixed >> num(bit["index"])) & 1
		} else {
			bit["var"] = bind.name
		}
	}
	clone["mkasmAliasClasses"] = aliasClasses
	clone["AsmString"] = alias["AsmString"]
	clone["OutOperandList"] = map[string]any{"args": []any{}}
	clone["InOperandList"] = map[string]any{"args": dagArgs}
	ps, _ := clone["Predicates"].([]any)
	aps, _ := alias["Predicates"].([]any)
	clone["Predicates"] = append(ps, aps...)
	clone["Constraints"] = ""
	return clone, nil
}

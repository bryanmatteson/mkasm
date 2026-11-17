package arc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// ParseGNU imports GNU binutils' ARC C tables and operand definitions from a
// tar or tar.gz archive. Macro-based ARCv3 and extension tables must first be
// resolved with the source exporters. Importing never invokes a C compiler.
func ParseGNU(r io.Reader, architecture string) (*codec.Catalog, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(b) > 2 && b[0] == 31 && b[1] == 139 {
		z, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		b, e = io.ReadAll(z)
		z.Close()
		if e != nil {
			return nil, e
		}
	}
	files := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		n := path.Base(h.Name)
		if n == "arc-ext-tbl.h" || n == "arc-nps400-tbl.h" || n == "arc-tbl.h" || n == "arc-opc.c" || n == "arc-fxi.h" || n == "COPYING3" {
			d, e := io.ReadAll(tr)
			if e != nil {
				return nil, e
			}
			files[n] = string(d)
		}
	}
	for _, n := range []string{"arc-tbl.h", "arc-opc.c", "arc-fxi.h"} {
		if files[n] == "" {
			return nil, fmt.Errorf("ARC GNU source archive missing %s", n)
		}
	}
	if architecture == "arceb" {
		architecture = "arc32be"
	}
	big := strings.HasSuffix(architecture, "be")
	cpu := "ARC_OPCODE_ARCv2HS"
	switch strings.TrimSuffix(architecture, "be") {
	case "arc600":
		cpu = "ARC_OPCODE_ARC600"
	case "arc700", "arcnps400":
		cpu = "ARC_OPCODE_ARC700"
	case "arc64":
		cpu = "ARC_OPCODE_ARC64"
	case "arcv3-32":
		cpu = "ARC_OPCODE_ARC32"
	case "arcem":
		cpu = "ARC_OPCODE_ARCv2EM"
	case "archs", "arc", "arc32", "arcv2":
	default:
		return nil, fmt.Errorf("unsupported ARC architecture %q", architecture)
	}
	src := files["arc-opc.c"]
	defs := cArray(src, "arc_operands")
	flags := cArray(src, "arc_flag_operands")
	classes := cArray(src, "arc_flag_classes")
	funcs := src + "\n" + files["arc-fxi.h"]
	c := &codec.Catalog{Schema: codec.Schema, Architecture: architecture, Source: "GNU binutils opcodes/arc-tbl.h + arc-opc.c + arc-fxi.h", FeatureSets: map[string][]string{"base": {}}}
	c.SourceLicense = "GNU binutils ARC opcode metadata, GPL-3.0-or-later.\nGenerated runtime implementation: MIT; see LICENSE.\n\n" + files["COPYING3"]
	c.SourceLicenseID = "GPL-3.0-or-later"
	tableSource := files["arc-tbl.h"]
	if strings.HasPrefix(architecture, "arcnps400") {
		if files["arc-nps400-tbl.h"] == "" {
			return nil, fmt.Errorf("NPS400 source table missing")
		}
		tableSource += "\n" + files["arc-nps400-tbl.h"]
	}
	// A partially literal table can contain valid rows alongside unexpanded
	// macros. Accepting only its literal rows silently loses instructions.
	for _, name := range []string{"arc-ext-tbl.h", "arc-nps400-tbl.h"} {
		if name == "arc-nps400-tbl.h" && !strings.HasPrefix(architecture, "arcnps400") {
			continue
		}
		if unresolvedTableDirective.MatchString(comments.ReplaceAllString(files[name], "")) {
			return nil, fmt.Errorf("%s macros require the complete resolved export from scripts/export-arc-nps400.py", name)
		}
	}
	tableSource += "\n" + files["arc-ext-tbl.h"]
	rows := gnuRow.FindAllStringSubmatch(tableSource, -1)
	if len(rows) == 0 {
		return nil, fmt.Errorf("ARC GNU source has no opcode records")
	}
	for i, m := range rows {
		cpuMask := map[string]uint64{"ARC_OPCODE_ARC600": 1, "ARC_OPCODE_ARC700": 2, "ARC_OPCODE_ARCv2EM": 4, "ARC_OPCODE_ARCv2HS": 8, "ARC_OPCODE_ARC64": 16, "ARC_OPCODE_ARC32": 32}[cpu]
		if !strings.Contains(m[4], cpu) && uint64(integer(m[4]))&cpuMask == 0 {
			continue
		}
		id := fmt.Sprintf("gnu/%s/%d", m[1], i)
		forms, err := gnuEncoding(m, id, big, defs, flags, classes, funcs)
		if strings.HasPrefix(architecture, "arc64") {
			for j := range forms {
				for k := range forms[j].Operands {
					if forms[j].Operands[k].Kind == "register" && !strings.HasPrefix(forms[j].Operands[k].RegisterPrefix, "f") && len(forms[j].Operands[k].Names) > 60 {
						forms[j].Operands[k].Names[60] = ""
					}
					if forms[j].Operands[k].Relative {
						forms[j].Operands[k].PCWrapBits = 64
					}
				}
			}
		}
		if err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		c.Encodings = append(c.Encodings, forms...)
	}
	features := map[string]bool{}
	for _, e := range c.Encodings {
		for _, f := range e.Features {
			features[f] = true
		}
	}
	var all []string
	for f := range features {
		all = append(all, f)
	}
	sort.Strings(all)
	c.FeatureSets["all"] = all
	if len(c.Encodings) == 0 {
		return nil, fmt.Errorf("ARC GNU source has no supported encodings")
	}
	compressBits(c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

var comments = regexp.MustCompile(`(?s)/\*.*?\*/`)

// cArray keeps source symbolic aliases, rather than depending on numeric enum
// indices that change between binutils releases.
func cArray(src, name string) map[string]string {
	out := map[string]string{}
	p := strings.Index(src, " "+name+"[]")
	if p < 0 {
		return out
	}
	src = comments.ReplaceAllString(src[p:], "")
	p = strings.Index(src, "{")
	src = src[p+1:]
	if p = strings.Index(src, "\n};"); p >= 0 {
		src = src[:p]
	}
	var names []string
	for len(src) > 0 {
		src = strings.TrimSpace(src)
		if strings.HasPrefix(src, "#define") {
			n := strings.IndexByte(src, '\n')
			if n < 0 {
				break
			}
			f := strings.Fields(src[:n])
			if len(f) > 1 {
				names = append(names, f[1])
			}
			src = src[n+1:]
			continue
		}
		if src[0] != '{' {
			p := strings.IndexByte(src, '\n')
			if p < 0 {
				break
			}
			src = src[p+1:]
			continue
		}
		depth := 0
		end := 0
		for i, ch := range src {
			if ch == '{' {
				depth++
			}
			if ch == '}' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end == 0 {
			break
		}
		v := src[1:end]
		for _, n := range names {
			out[n] = v
		}
		names = nil
		src = strings.TrimLeft(src[end+1:], ", \t\r\n")
	}
	return out
}

var gnuRow = regexp.MustCompile(`\{\s*"([^"]+)",\s*(0x[\dA-Fa-f]+)(?:[uUlL]+)?,\s*(0x[\dA-Fa-f]+)(?:[uUlL]+)?,\s*([^,]+),\s*(\w+),\s*(\w+),\s*\{([^}]+)\},\s*\{([^}]+)\}`)
var unresolvedTableDirective = regexp.MustCompile(`(?m)^[\t ]*#[\t ]*(?:define|include)\b`)
var insertSlice = regexp.MustCompile(`insn\s*\|=\s*\(\(value\s*>>\s*(\d+)\)\s*&\s*(0x[0-9a-fA-F]+)\)\s*<<\s*(\d+)`)

func integer(s string) int64 {
	if v, e := strconv.ParseInt(strings.TrimSpace(s), 0, 64); e == nil {
		return v
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
	return int64(v)
}
func fields(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		out = append(out, strings.TrimSpace(v))
	}
	return out
}
func function(src, name string) string {
	p := strings.Index(src, "\n"+name+" (")
	if p < 0 {
		return ""
	}
	src = src[p:]
	p = strings.Index(src, "\n}")
	if p < 0 {
		return ""
	}
	return src[:p+2]
}
func gnuOperand(name, s, funcs string) (codec.Operand, string, error) {
	if o, literal, ok, err := npsOperand(name, s, funcs); ok {
		return o, literal, err
	}
	o := codec.Operand{Class: name, Kind: "immediate"}
	f := fields(s)
	if len(f) < 6 {
		return o, "", fmt.Errorf("unknown source operand %s", name)
	}
	width := int(integer(f[0]))
	shift := int(integer(f[1]))
	fl := f[3]
	insert := f[4]
	fixed := map[string]string{"insert_za": "0", "insert_r0": "r0", "insert_r1": "r1", "insert_r2": "r2", "insert_r3": "r3", "insert_sp": "sp", "insert_gp": "gp", "insert_pcl": "pcl", "insert_blink": "blink", "insert_ilink1": "ilink1", "insert_ilink2": "ilink2"}
	if v, ok := fixed[insert]; ok {
		return o, v, nil
	}
	if strings.Contains(fl, "ARC_OPERAND_LIMM") {
		o.InputSignedBits = 32
		o.Signed = strings.Contains(fl, "ARC_OPERAND_SIGNED")
		o.Relative = strings.Contains(fl, "ARC_OPERAND_PCREL")
		if o.Relative {
			o.Kind = "address"
			o.PCWrapBits = 32
			o.PCAlignBits = 2
		}
		if width == 34 {
			o.Scale = 4
		}
		return o, "", nil
	}
	if strings.Contains(fl, "ARC_OPERAND_BRAKET") {
		return o, "[]", nil
	}
	if strings.Contains(fl, "ARC_OPERAND_FAKE") {
		return o, "", fmt.Errorf("fixup-dependent operand %s", name)
	}
	if strings.Contains(fl, "ARC_OPERAND_IR") {
		o.Kind = "register"
	}
	o.Signed = strings.Contains(fl, "ARC_OPERAND_SIGNED")
	o.Relative = strings.Contains(fl, "ARC_OPERAND_PCREL")
	if o.Relative {
		o.Kind = "displacement"
		o.PCWrapBits = 32
		o.PCAlignBits = 2
	}
	add := func(i, v, n int) {
		for k := 0; k < n; k++ {
			o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: i + k, ValueBit: v + k, Width: 1})
		}
	}
	switch insert {
	case "0", "NULL":
		add(shift, 0, width)
	case "insert_ra_chk", "insert_rad":
		add(0, 0, 6)
	case "insert_fs2":
		add(24, 0, 3)
		add(12, 3, 2)
	case "insert_rbb", "insert_rbb_chk":
		add(8, 0, 3)
		add(1, 3, 3)
	case "insert_rb", "insert_rb_chk", "insert_rbd":
		add(24, 0, 3)
		add(12, 3, 3)
	case "insert_rcd":
		add(6, 0, 6)
	case "insert_ras":
		add(0, 0, 3)
	case "insert_rbs":
		add(8, 0, 3)
	case "insert_rcs":
		add(5, 0, 3)
	case "insert_rhv2":
		add(5, 0, 3)
		add(0, 3, 2)
	case "insert_rhv1":
		add(5, 0, 3)
		add(0, 3, 3)
	case "insert_rrange":
		add(1, 0, 4)
		o.Kind = "register"
		o.Bias = 12
		o.Names = make([]string, 16)
		for i := 1; i <= 14; i++ {
			o.Names[i] = fmt.Sprintf("r%d", i+12)
		}
	case "insert_r13el", "insert_fpel", "insert_blinkel", "insert_pclel":
		bit, reg, name := 1, 13, "r13"
		switch insert {
		case "insert_fpel":
			bit, reg, name = 8, 27, "fp"
		case "insert_blinkel":
			bit, reg, name = 9, 31, "blink"
		case "insert_pclel":
			bit, reg, name = 10, 63, "pcl"
		}
		add(bit, 0, 1)
		o.Class = "OptionalRegister"
		o.Kind = "register"
		o.Bias = int64(reg - 1)
		o.Names = []string{"", name}
	case "insert_simm3s":
		add(8, 0, 3)
		o.Signed = false
		o.Class = "Cyclic3"
		o.Names = []string{"0", "1", "2", "3", "4", "5", "6", "-1"}
	default:
		body := function(funcs, insert)
		for _, m := range insertSlice.FindAllStringSubmatch(body, -1) {
			mask := uint64(integer(m[2]))
			for k := 0; k < 64; k++ {
				if mask>>uint(k)&1 != 0 {
					add(int(integer(m[3]))+k, int(integer(m[1]))+k, 1)
				}
			}
		}
		if len(o.Bits) == 0 {
			return o, "", fmt.Errorf("unmodeled source insertion function %s (%s)", insert, name)
		}
	}
	if o.Kind == "register" && len(o.Names) == 0 {
		register(&o)
		if strings.Contains(fl, "ARC_OPERAND_FP") {
			o.RegisterPrefix = "f"
			o.RegisterAliases = nil
			for i := range o.Names {
				o.Names[i] = fmt.Sprintf("f%d", i)
			}
			if strings.Contains(fl, "ARC_OPERAND_TRUNCATE") {
				for i := range o.Names {
					if i%2 != 0 {
						o.Names[i] = ""
					}
				}
			}
		}
		if insert == "insert_rhv2" {
			o.Names[30] = ""
		}
		if strings.Contains(insert, "chk") || insert == "insert_rad" || insert == "insert_rbd" {
			if len(o.Names) > 60 {
				o.Names[60] = ""
			}
		}
		if insert == "insert_rad" || insert == "insert_rcd" || insert == "insert_rbd" || insert == "insert_rbb_chk" {
			for n := range o.Names {
				if n%2 != 0 {
					o.Names[n] = ""
				}
			}
		}
	}
	return o, "", nil
}
func gnuEncoding(m []string, id string, big bool, defs, flags, classes map[string]string, funcs string) ([]codec.Encoding, error) {
	value, mask := uint64(integer(m[2])), uint64(integer(m[3]))
	// Binutils 2.44's NPS400 wkup register row accidentally masks RC as
	// constant. Its operand definition and assembler both insert the six RC
	// bits. Keep that encoder behavior and make those bits decodable too.
	if m[1] == "wkup" && value == 0x385b003e && mask == 0xf8ff8fff && strings.TrimSpace(m[7]) == "ZA, RC" {
		mask &^= 0xfc0
	}
	size := 4
	if mask <= 65535 {
		size = 2
	}
	if mask > 0xffffffff {
		size = 6
	}
	if mask > 0xffffffffffff {
		size = 8
	}
	baseSize := size
	ops := fields(m[7])
	for _, n := range ops {
		if strings.Contains(defs[n], "ARC_OPERAND_LIMM") {
			size += 4
			break
		}
	}
	physicalBit := func(bit int) int {
		base, block := 0, baseSize
		if bit >= baseSize*8 {
			base = baseSize
			block = 4
			bit -= baseSize * 8
		}
		if big {
			return base*8 + (block-1-bit/8)*8 + bit%8
		}
		return base*8 + (block-2-(bit/16)*2+(bit/8)%2)*8 + bit%8
	}
	e := codec.Encoding{ID: id, Mnemonic: m[1], Syntax: m[1], FlowControl: "next", Mask: make([]byte, size), Value: make([]byte, size)}
	if m[6] != "NONE" {
		e.Features = []string{m[6]}
	}
	if m[1] == "bl" || m[1] == "bl_s" || m[1] == "jl" || m[1] == "jl_s" {
		e.FlowControl = "call"
	}
	switch m[5] {
	case "BRANCH", "BRCC", "BBIT0", "BBIT1", "BI", "BIH", "DBNZ", "LOOP":
		if e.FlowControl != "call" {
			e.FlowControl = "branch"
		}
	case "JUMP":
		if e.FlowControl != "call" {
			e.FlowControl = "indirect-branch"
		}
	case "JLI", "SJLI":
		e.FlowControl = "call"
	}
	set := func(e *codec.Encoding, bit int, v int) {
		p := physicalBit(bit)
		b := byte(1) << uint(p%8)
		e.Mask[p/8] |= b
		e.Value[p/8] &= ^b
		if v != 0 {
			e.Value[p/8] |= b
		}
	}
	for bit := 0; bit < baseSize*8; bit++ {
		if mask>>uint(bit)&1 != 0 {
			set(&e, bit, int(value>>uint(bit)&1))
		}
	}
	var syntax []string
	seen := map[string]string{}
	bracket := false
	for i, n := range ops {
		if n == "0" {
			continue
		}
		o, literal, err := gnuOperand(n, defs[n], funcs)
		if err != nil {
			return nil, err
		}
		if literal == "[]" {
			if !bracket {
				syntax = append(syntax, "[")
				bracket = true
			} else {
				syntax = append(syntax, "]")
				bracket = false
			}
			continue
		}
		if literal != "" {
			syntax = append(syntax, literal)
			continue
		}
		key := strings.ReplaceAll(strings.TrimSuffix(n, "dup"), "_CHK", "")
		if key == "RBD" {
			key = "RB"
		}
		if key == "NPS_RBdouble_64" {
			key = "NPS_RB_64"
		}
		if strings.Contains(defs[n], "ARC_OPERAND_DUPLICATE") {
			if strings.HasPrefix(n, "NPS_R_SRC1") {
				key = strings.Replace(n, "SRC1", "DST", 1)
			}
			if n == "NPS_RBdup_64" {
				key = "NPS_RB_64"
			}
			prev := seen[key]
			if prev == "" && key == "LIMM" {
				prev = seen["LIMM_S"]
			}
			if prev == "" {
				return nil, fmt.Errorf("unresolved duplicate operand %s", n)
			}
			syntax = append(syntax, "{"+prev+"}")
			continue
		}
		o.Name = fmt.Sprintf("op%d", i)
		if strings.Contains(defs[n], "ARC_OPERAND_LIMM") {
			for bit := 0; bit < 32; bit++ {
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: baseSize*8 + bit, ValueBit: bit, Width: 1})
			}
		}
		var physicalBits []codec.BitSlice
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				physicalBits = append(physicalBits, codec.BitSlice{InstructionBit: physicalBit(b.InstructionBit + k), ValueBit: b.ValueBit + k, Width: 1})
			}
		}
		o.Bits = physicalBits
		if strings.HasPrefix(n, "NPS_") {
			tied := ""
			for _, p := range e.Operands {
				if fmt.Sprint(p.Bits) == fmt.Sprint(o.Bits) && fmt.Sprint(p.Lookup) == fmt.Sprint(o.Lookup) {
					tied = p.Name
					break
				}
			}
			if tied != "" {
				seen[key] = tied
				syntax = append(syntax, "{"+tied+"}")
				continue
			}
		}
		seen[key] = o.Name
		e.Operands = append(e.Operands, o)
		if n == "NPS_BITOP_DST_POS_SZ" {
			mirror := codec.Operand{Name: o.Name + "_size", Kind: "immediate", Implicit: true, Bias: -31, BiasOperand: o.Name, BiasScale: 1}
			for bit := 0; bit < 5; bit++ {
				mirror.Bits = append(mirror.Bits, codec.BitSlice{InstructionBit: physicalBit(10 + bit), ValueBit: bit, Width: 1})
			}
			e.Operands = append(e.Operands, mirror)
		}
		part := "{" + o.Name + "}"
		if n == "RRANGE_EL" {
			part = "r13-" + part
		}
		syntax = append(syntax, part)
	}
	text := strings.Join(syntax, ", ")
	text = strings.ReplaceAll(text, "[, ", "[")
	text = strings.ReplaceAll(text, ", ]", "]")
	text = strings.ReplaceAll(text, ", :", ":")
	text = strings.ReplaceAll(text, ":, ", ":")
	if text != "" {
		e.Syntax += " " + text
	}
	forms := []codec.Encoding{e}
	flagBits := map[int]bool{}
	for _, cl := range fields(m[8]) {
		if cl == "0" {
			continue
		}
		cs := classes[cl]
		if cs == "" {
			return nil, fmt.Errorf("unknown source flag class %s", cl)
		}
		if strings.Contains(cs, "F_CLASS_IMPLICIT") {
			continue
		}
		p := strings.IndexByte(cs, '{')
		q := strings.IndexByte(cs, '}')
		if p < 0 || q < p {
			return nil, fmt.Errorf("malformed flag class %s", cl)
		}
		flagBit := func(shift, bit int) int {
			if strings.Contains(cs, "insert_fs2") {
				if bit < 3 {
					return 24 + bit
				}
				return 12 + bit - 3
			}
			if strings.Contains(cs, "insert_qq") {
				if bit == 0 {
					return 11
				}
				return 6
			}
			return shift + bit
		}
		type flag struct {
			name               string
			value, bits, shift int
		}
		var choices []flag
		if strings.Contains(cs, "F_CLASS_OPTIONAL") {
			choices = append(choices, flag{})
		}
		for _, n := range fields(cs[p+1 : q]) {
			if n == "F_NULL" {
				continue
			}
			f := fields(flags[n])
			if len(f) < 5 {
				return nil, fmt.Errorf("unknown source flag %s", n)
			}
			choices = append(choices, flag{strings.Trim(f[0], "\""), int(integer(f[1])), int(integer(f[2])), int(integer(f[3]))})
		}
		var next []codec.Encoding
		var newBits []int
		for _, ch := range choices {
			for bit := 0; bit < ch.bits; bit++ {
				p := flagBit(ch.shift, bit)
				if !flagBits[p] {
					newBits = append(newBits, p)
					flagBits[p] = true
				}
			}
		}
		for _, v := range forms {
			for ci, ch := range choices {
				if ci == 0 && len(choices) == 2 && choices[1].bits == 0 {
					continue
				}
				x := v
				x.Mask = append([]byte(nil), v.Mask...)
				x.Value = append([]byte(nil), v.Value...)
				x.ID += fmt.Sprintf("/%s%d", cl, ci)
				suffix := ""
				if ch.name != "" {
					suffix = "." + ch.name
				}
				x.Syntax = strings.Replace(v.Syntax, v.Mnemonic, v.Mnemonic+suffix, 1)
				x.Mnemonic = v.Mnemonic + suffix
				for _, p := range newBits {
					set(&x, p, 0)
				}
				for bit := 0; bit < ch.bits; bit++ {
					if ch.value>>uint(bit)&1 != 0 {
						set(&x, flagBit(ch.shift, bit), 1)
					}
				}
				if ch.name == "d" {
					x.DelaySlots = 1
				}
				if cl == "C_T" && ch.name != "" {
					var target string
					for _, o := range x.Operands {
						if o.Relative {
							target = o.Name
						}
					}
					if target == "" {
						return nil, fmt.Errorf("prediction flag without relative target")
					}
					for sign := 0; sign < 2; sign++ {
						z := x
						z.Mask = append([]byte(nil), x.Mask...)
						z.Value = append([]byte(nil), x.Value...)
						z.ID += fmt.Sprintf("/direction%d", sign)
						z.Operands = append([]codec.Operand(nil), x.Operands...)
						for i, o := range z.Operands {
							if o.Name != target {
								continue
							}
							width := o.Width()
							var bits []codec.BitSlice
							for _, p := range o.Bits {
								if p.ValueBit == width-1 {
									mask := byte(1) << uint(p.InstructionBit%8)
									z.Mask[p.InstructionBit/8] |= mask
									z.Value[p.InstructionBit/8] &= ^mask
									if sign == 1 {
										z.Value[p.InstructionBit/8] |= mask
									}
								} else {
									bits = append(bits, p)
								}
							}
							o.Bits = bits
							o.Signed = false
							if sign == 1 {
								o.Bias = -(1 << uint(width-1))
							}
							z.Operands[i] = o
						}

						if sign == 0 {
							z.Constraints = append(z.Constraints, codec.Constraint{Kind: "ne", Left: target})
						}
						n := ch.value ^ sign
						if m[5] == "BBIT0" || m[5] == "BBIT1" {
							n ^= 1
						}
						set(&z, ch.shift, n)
						next = append(next, z)
						if sign == 0 {
							zero := z
							zero.ID += "/zero"
							zero.Mask = append([]byte(nil), z.Mask...)
							zero.Value = append([]byte(nil), z.Value...)
							zero.Constraints = nil
							zero.Operands = append([]codec.Operand(nil), z.Operands...)
							for i, o := range zero.Operands {
								if o.Name == target {
									o.Implicit = true
									zero.Operands[i] = o
								}
							}
							set(&zero, ch.shift, 0)
							next = append(next, zero)
						}
					}
				} else {
					next = append(next, x)
				}
			}
		}
		forms = next
	}
	var out []codec.Encoding
	for _, v := range forms {
		for _, v := range optionalRegisters(v) {
			for _, x := range cyclicImmediates(v) {
				for _, x := range compactRegisters(x) {
					var used []byte = make([]byte, size)
					for _, o := range x.Operands {
						for _, b := range o.Bits {
							for k := 0; k < b.Width; k++ {
								p := b.InstructionBit + k
								if p < 0 || p >= size*8 {
									return nil, fmt.Errorf("operand %s has bit %d outside %d byte instruction", o.Class, p, size)
								}
								used[p/8] |= 1 << uint(p%8)
							}
						}
					}
					for i := range x.Mask {
						x.Mask[i] |= ^used[i]
					}
					if strings.HasSuffix(x.Syntax, "[]") {
						x.Syntax = strings.TrimSuffix(x.Syntax, "[]") + "0"
					}
					out = append(out, x)
				}
			}
		}
	}
	return out, nil
}

func optionalRegisters(e codec.Encoding) []codec.Encoding {
	forms := []codec.Encoding{e}
	for _, operand := range e.Operands {
		if operand.Class != "OptionalRegister" {
			continue
		}
		var next []codec.Encoding
		for _, v := range forms {
			for n := 0; n < 2; n++ {
				x := v
				x.Mask = append([]byte(nil), v.Mask...)
				x.Value = append([]byte(nil), v.Value...)
				x.ID += fmt.Sprintf("/%s%d", operand.Name, n)
				x.Syntax = strings.ReplaceAll(x.Syntax, "{"+operand.Name+"}", operand.Names[n])
				x.Syntax = strings.ReplaceAll(x.Syntax, "[, ", "[")
				x.Syntax = strings.ReplaceAll(x.Syntax, ", ]", "]")
				x.Syntax = strings.ReplaceAll(x.Syntax, ", ,", ",")
				var ops []codec.Operand
				for _, o := range x.Operands {
					if o.Name != operand.Name {
						ops = append(ops, o)
					}
				}
				x.Operands = ops
				for _, b := range operand.Bits {
					p := b.InstructionBit
					m := byte(1) << uint(p%8)
					x.Mask[p/8] |= m
					x.Value[p/8] &= ^m
					if n == 1 {
						x.Value[p/8] |= m
					}
				}
				next = append(next, x)
			}
		}
		forms = next
	}
	return forms
}

// Package mcs51 imports the complete Ghidra MCS-51 Sleigh constructor source.
package mcs51

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

const Revision = "c0f584bf229fffba61b36431f3ce30c0c3e4e682"

//go:embed data/8051_main.sinc
var source string

//go:embed data/LICENSE-Ghidra
var license string

//go:embed data/8051.pspec
var processorSpec string

type Catalog struct{ *codec.Catalog }

func Default() *Catalog {
	c, e := Parse(strings.NewReader(source), "mcs51")
	if e != nil {
		panic(e)
	}
	return c
}
func CanonicalArchitecture(s string) string {
	switch strings.ToLower(s) {
	case "mcs51", "mcs-51", "8051":
		return "mcs51"
	case "mcs80390", "80390", "ds390":
		return "mcs80390"
	default:
		return ""
	}
}
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	arch := CanonicalArchitecture(architecture)
	if arch == "" {
		return nil, fmt.Errorf("unsupported MCS-51 architecture %q", architecture)
	}
	raw, e := io.ReadAll(r)
	if e != nil {
		return nil, e
	}
	mode := "MCS51"
	if arch == "mcs80390" {
		mode = "MCS80390"
	}
	text, e := preprocess(string(raw), mode)
	if e != nil {
		return nil, e
	}
	fields, e := tokenFields(text)
	if e != nil {
		return nil, e
	}
	var encodings []codec.Encoding
	re := regexp.MustCompile(`(?m)^:([A-Z][A-Z0-9]*)\s*(.*?)\s+is\s+([^\{]+)\{`)
	constructors := re.FindAllStringSubmatch(text, -1)
	if len(constructors) == 0 {
		return nil, fmt.Errorf("MCS-51: no instruction constructors; pass 8051_main.sinc, not its include-only .slaspec")
	}
	for _, m := range constructors {
		// Specialized SFR-bit p-code constructors have the same bytes and displayed
		// bit operand as the unrestricted constructor; the latter covers their union.
		if strings.Contains(m[3], "bitaddr57=7") && strings.Contains(m[3], "sfrbit3=0") {
			continue
		}
		enc, e := constructor(m[1], strings.TrimSpace(m[2]), strings.TrimSpace(m[3]), fields, arch)
		if e != nil {
			return nil, fmt.Errorf("MCS-51 %s %s: %w", m[1], m[2], e)
		}
		encodings = append(encodings, enc)
		if strings.Contains(enc.Syntax, "CY") {
			alias := enc
			alias.ID += "_C"
			alias.Syntax = strings.ReplaceAll(alias.Syntax, "CY", "C")
			alias.AssemblyOnly = true
			encodings = append(encodings, alias)
		}
	}
	c, e := codec.NewCatalog(arch, "Ghidra 12.1.2 8051_main.sinc @ "+Revision, encodings)
	if e != nil {
		return nil, e
	}
	c.SourceLicense = license
	c.SourceLicenseID = "Apache-2.0"
	c.FeatureSets = map[string][]string{arch: {arch}}
	return &Catalog{c}, nil
}

type field struct{ lo, hi, size int }

func tokenFields(s string) (map[string]field, error) {
	re := regexp.MustCompile(`(?s)define token\s+\w+\s*\((\d+)\)(.*?);`)
	f := map[string]field{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		if n%8 != 0 {
			return nil, fmt.Errorf("non-byte token")
		}
		for _, x := range regexp.MustCompile(`(\w+)\s*=\s*\((\d+),(\d+)\)`).FindAllStringSubmatch(m[2], -1) {
			lo, _ := strconv.Atoi(x[2])
			hi, _ := strconv.Atoi(x[3])
			if lo > hi || hi >= n {
				return nil, fmt.Errorf("invalid token field %s", x[1])
			}
			f[x[1]] = field{lo, hi, n / 8}
		}
	}
	if len(f) == 0 {
		return nil, fmt.Errorf("no token fields")
	}
	return f, nil
}
func bits(f field, at int) []codec.BitSlice {
	var out []codec.BitSlice
	for b := f.lo; b <= f.hi; b++ {
		physical := (f.size-1-b/8)*8 + b%8 + at*8
		out = append(out, codec.BitSlice{InstructionBit: physical, ValueBit: b - f.lo, Width: 1})
	}
	return out
}

var knownOperands = map[string]string{"Areg": "A", "ABreg": "AB", "DPTRreg": "DPTR", "CY": "CY", "ADPTR": "@A+DPTR", "APC": "@A+PC", "ATDPTR": "@DPTR", "rn": "register", "Ri": "indirect", "RiX": "external-indirect", "Data": "immediate", "Data16": "immediate", "Data24": "immediate", "Direct": "direct", "Direct2": "direct", "BitAddr": "bit", "BitAddr2": "complement-bit", "Rel8": "relative", "Addr11": "page", "Addr19": "page", "Addr16": "code-address", "Addr24": "code-address"}

func constructor(mnemonic, display, pattern string, fields map[string]field, arch string) (codec.Encoding, error) {
	e := codec.Encoding{Mnemonic: strings.ToLower(mnemonic), ID: mnemonic + "_" + strings.NewReplacer(",", "_", " ", "", "@", "").Replace(display), Features: []string{arch}}
	segments := strings.Split(pattern, ";")
	length := len(segments)
	if strings.Contains(display, "Addr11") {
		length = 2
	}
	if strings.Contains(display, "Addr19") {
		length = 3
	}
	for _, s := range strings.Split(display, ",") {
		switch strings.TrimSpace(s) {
		case "Addr16", "Data16":
			length += 1
		case "Addr24", "Data24":
			length += 2
		}
	}
	e.Mask = make([]byte, length)
	e.Value = make([]byte, length)
	assigns := regexp.MustCompile(`\b(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\b`)
	for at, segment := range segments {
		for _, m := range assigns.FindAllStringSubmatch(segment, -1) {
			f, ok := fields[m[1]]
			if !ok {
				return e, fmt.Errorf("unknown pattern field %s", m[1])
			}
			v, _ := strconv.ParseUint(m[2], 0, 64)
			if v >= uint64(1)<<uint(f.hi-f.lo+1) {
				return e, fmt.Errorf("pattern value range")
			}
			for _, b := range bits(f, at) {
				p := b.InstructionBit
				if p/8 >= length {
					return e, fmt.Errorf("pattern exceeds instruction")
				}
				mask := byte(1) << uint(p%8)
				value := byte((v>>uint(b.ValueBit))&1) << uint(p%8)
				if e.Mask[p/8]&mask != 0 && e.Value[p/8]&mask != value {
					return e, fmt.Errorf("conflicting pattern bits")
				}
				e.Mask[p/8] |= mask
				e.Value[p/8] |= value
			}
		}
	}
	if mnemonic == "CALL" || mnemonic == "ACALL" || mnemonic == "LCALL" {
		e.FlowControl = "call"
	} else if mnemonic == "RET" || mnemonic == "RETI" {
		e.FlowControl = "return"
	} else if mnemonic == "JMP" {
		e.FlowControl = "indirect-branch"
	} else if mnemonic == "AJMP" || mnemonic == "LJMP" || mnemonic == "SJMP" {
		e.FlowControl = "branch"
	} else if strings.HasPrefix(mnemonic, "J") || mnemonic == "CJNE" || mnemonic == "DJNZ" {
		e.FlowControl = "conditional-branch"
	}
	var syntax []string
	if display != "" {
		for _, name := range strings.Split(display, ",") {
			name = strings.TrimSpace(name)
			class, ok := knownOperands[name]
			if !ok {
				return e, fmt.Errorf("unsupported operand constructor %q", name)
			}
			if class != "register" && class != "indirect" && class != "external-indirect" && class != "immediate" && class != "direct" && class != "bit" && class != "complement-bit" && class != "relative" && class != "page" && class != "code-address" {
				syntax = append(syntax, class)
				continue
			}
			o := codec.Operand{Name: strings.ToLower(name), Class: name, Kind: "immediate"}
			prefix := ""
			at := -1
			for i, s := range segments {
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(s) {
					at = i
					break
				}
			}
			switch name {
			case "rn", "Ri", "RiX":
				f := "rn"
				count := 8
				if name != "rn" {
					f = "ri"
					count = 2
					prefix = "@"
				}
				o.Kind = "register"
				o.Bits = bits(fields[f], 0)
				for n := 0; n < count; n++ {
					o.Names = append(o.Names, fmt.Sprintf("R%d", n))
				}
			case "Data", "Data16", "Data24":
				f := map[string]string{"Data": "data", "Data16": "data16", "Data24": "data24"}[name]
				o.Bits = bits(fields[f], at)
				prefix = "#"
				o.InputSignedBits = fields[f].size * 8
			case "Direct", "Direct2":
				o.Kind = "address"
				o.Bits = bits(fields[strings.ToLower(name)], at)
				o.RegisterAliases = directAliases()
			case "BitAddr", "BitAddr2":
				o.Kind = "address"
				o.Bits = []codec.BitSlice{{InstructionBit: at * 8, Width: 8}}
				o.RegisterAliases = bitAliases()
				if name == "BitAddr2" {
					prefix = "/"
				}
			case "Rel8":
				o.Kind = "displacement"
				o.Bits = bits(fields["rel8"], at)
				o.Signed = true
				o.Relative = true
				o.PCBias = int64(length)
				o.PCWrapBits = 16
				if arch == "mcs80390" {
					o.PCWrapBits = 24
				}
			case "Addr11", "Addr19":
				o.Kind = "address"
				lowBits := 8
				if name == "Addr19" {
					lowBits = 16
				}
				o.Bits = bits(fields["adata"], 0)
				for _, b := range bits(fields["aopaddr"], 0) {
					b.ValueBit += lowBits
					o.Bits = append(o.Bits, b)
				}
				o.Relative = true
				o.PCBias = int64(length)
				o.PCRegionBits = lowBits + 3
				o.PCWrapBits = 16
				if arch == "mcs80390" {
					o.PCWrapBits = 24
				}
			case "Addr16", "Addr24":
				o.Kind = "address"
				o.Bits = bits(fields[strings.ToLower(name)], at)
			}
			if at < 0 {
				return e, fmt.Errorf("operand %s absent from pattern", name)
			}
			e.Operands = append(e.Operands, o)
			syntax = append(syntax, prefix+"{"+o.Name+"}")
		}
	}
	e.Syntax = e.Mnemonic
	if len(syntax) > 0 {
		e.Syntax += " " + strings.Join(syntax, ",")
	}
	for _, o := range e.Operands {
		for _, b := range o.Bits {
			if b.InstructionBit < 0 || b.InstructionBit/8 >= length {
				return e, fmt.Errorf("operand layout outside instruction")
			}
		}
	}
	return e, nil
}

func preprocess(s, mode string) (string, error) {
	defines := map[string]string{mode: ""}
	type frame struct{ parent, hit, active bool }
	var stack []frame
	active := true
	var out strings.Builder
	scan := bufio.NewScanner(strings.NewReader(s))
	scan.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scan.Scan() {
		line++
		v := strings.TrimSpace(scan.Text())
		if strings.HasPrefix(v, "#") {
			continue
		}
		if !strings.HasPrefix(v, "@") {
			if active {
				out.WriteString(scan.Text())
				out.WriteByte('\n')
			}
			continue
		}
		cmd, arg, _ := strings.Cut(v, " ")
		arg = strings.TrimSpace(arg)
		cond := false
		var err error
		switch cmd {
		case "@if":
			cond, err = condition(arg, defines)
		case "@ifdef":
			_, cond = defines[arg]
		case "@ifndef":
			_, cond = defines[arg]
			cond = !cond
		case "@elif":
			cond, err = condition(arg, defines)
		}
		if err != nil {
			return "", fmt.Errorf("Sleigh line %d: %w", line, err)
		}
		switch cmd {
		case "@if", "@ifdef", "@ifndef":
			stack = append(stack, frame{active, cond, active && cond})
			active = active && cond
		case "@elif":
			if len(stack) == 0 {
				return "", fmt.Errorf("unmatched elif")
			}
			f := &stack[len(stack)-1]
			active = f.parent && !f.hit && cond
			f.active = active
			f.hit = f.hit || cond
		case "@else":
			if len(stack) == 0 {
				return "", fmt.Errorf("unmatched else")
			}
			f := &stack[len(stack)-1]
			active = f.parent && !f.hit
			f.active = active
			f.hit = true
		case "@endif":
			if len(stack) == 0 {
				return "", fmt.Errorf("unmatched endif")
			}
			active = stack[len(stack)-1].parent
			stack = stack[:len(stack)-1]
		case "@define":
			if active {
				name, value, _ := strings.Cut(arg, " ")
				if strings.ContainsAny(name, "\t") {
					name, value, _ = strings.Cut(arg, "\t")
				}
				value = strings.TrimSpace(value)
				if strings.HasPrefix(value, "\"") {
					q, e := strconv.Unquote(value)
					if e != nil {
						return "", e
					}
					value = q
				}
				defines[name] = value
			}
		default:
			if active {
				return "", fmt.Errorf("unsupported Sleigh directive %s", cmd)
			}
		}
	}
	if e := scan.Err(); e != nil {
		return "", e
	}
	if len(stack) != 0 {
		return "", fmt.Errorf("unterminated Sleigh conditional")
	}
	return out.String(), nil
}
func condition(s string, d map[string]string) (bool, error) {
	if strings.Contains(s, "||") {
		v := false
		for _, part := range strings.Split(s, "||") {
			b, e := condition(strings.TrimSpace(part), d)
			if e != nil {
				return false, e
			}
			v = v || b
		}
		return v, nil
	}
	if strings.Contains(s, "&&") {
		v := true
		for _, part := range strings.Split(s, "&&") {
			b, e := condition(strings.TrimSpace(part), d)
			if e != nil {
				return false, e
			}
			v = v && b
		}
		return v, nil
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "defined(") && strings.HasSuffix(s, ")") {
		_, ok := d[s[8:len(s)-1]]
		return ok, nil
	}
	if a, b, ok := strings.Cut(s, "=="); ok {
		v, e := strconv.Unquote(strings.TrimSpace(b))
		if e != nil {
			return false, e
		}
		return d[strings.TrimSpace(a)] == v, nil
	}
	return false, fmt.Errorf("unsupported conditional %q", s)
}

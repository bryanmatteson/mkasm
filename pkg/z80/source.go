// Package z80 imports a complete primary Z80 opcode corpus and adds unbounded
// prefix framing while retaining exact physical encodings.
package z80

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed data/z80.lst
var Source string

//go:embed data/z80-dis.c
var GNUDescription string

//go:embed data/z80.slaspec
var GhidraDescription string

//go:embed data/z180ed.hxx
var Z180EDDescription string

const MAMERevision = "47d7645d814fdf93b5ffda7df1593070554438c7"

type Catalog struct {
	*codec.Catalog
	Framing      string `json:"framing"`
	SourceSHA256 string `json:"source_sha256"`
}

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }

var recordRE = regexp.MustCompile(`(?m)^([0-9a-f]{4})\s+#\s*(.*)$`)
var operandToken = regexp.MustCompile(`\b[anwo]\b`)

type record struct{ id, text, body string }

// Parse imports MAME's actual z80.lst, or resolved JSON emitted by WriteJSON.
// A nil reader uses the bundled source. Targets are z80 and z180.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "z80" && architecture != "z180" {
		return nil, fmt.Errorf("Z80: unsupported architecture %q", architecture)
	}
	source := []byte(Source)
	if r != nil {
		var err error
		source, err = io.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(strings.TrimSpace(string(source)), "{") {
		var c Catalog
		if err := json.Unmarshal(source, &c); err != nil {
			return nil, err
		}
		if c.Catalog == nil || c.Architecture != architecture || c.Framing != "z80-prefix-train-v1" {
			return nil, fmt.Errorf("invalid Z80 catalog framing")
		}
		if err := c.Validate(); err != nil {
			return nil, err
		}
		return &c, nil
	}
	matches := recordRE.FindAllStringSubmatchIndex(string(source), -1)
	records := map[string]record{}
	for i, m := range matches {
		id := string(source[m[2]:m[3]])
		if _, exists := records[id]; exists {
			return nil, fmt.Errorf("duplicate opcode source %s", id)
		}
		end := len(source)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		records[id] = record{id, string(source[m[4]:m[5]]), string(source[m[1]:end])}
	}
	for _, space := range []string{"00", "cb", "ed", "dd", "fd", "fe"} {
		for op := 0; op < 256; op++ {
			id := fmt.Sprintf("%s%02x", space, op)
			if _, ok := records[id]; !ok {
				return nil, fmt.Errorf("incomplete primary opcode source: missing %s", id)
			}
		}
	}
	if len(records) != 1536 {
		return nil, fmt.Errorf("unexpected primary source spaces (%d records)", len(records))
	}
	c := &Catalog{Catalog: &codec.Catalog{Schema: "mkasm.z80.v1", Architecture: architecture, Source: "MAME z80.lst " + MAMERevision + "; GNU binutils 2.44 z80-dis.c; Ghidra 42db038f3c88c6bd7e9bedbb919138111f8b77fd", SourceLicenseID: "BSD-3-Clause AND GPL-3.0-or-later AND Apache-2.0", FeatureSets: map[string][]string{"default": {architecture}, architecture: {architecture}}}, Framing: "z80-prefix-train-v1", SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source))}
	// These variants share their parent's actual instruction SLA in z80.ldefs.
	if architecture == "z80" {
		c.FeatureSets["z8401x"] = []string{"z80"}
	} else {
		c.FeatureSets["z182"] = []string{"z180"}
	}
	keys := make([]string, 0, len(records))
	for id := range records {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		row := records[id]
		if strings.HasPrefix(row.text, "**") {
			continue
		}
		if (id[:2] == "dd" || id[:2] == "fd") && strings.HasPrefix(row.text, "DB") {
			continue
		}
		if id[:2] == "fe" {
			for _, index := range []string{"dd", "fd"} {
				e, err := makeEncoding(row, index, architecture)
				if err != nil {
					return nil, err
				}
				if e.ID != "" {
					c.Encodings = append(c.Encodings, e)
				}
			}
			continue
		}
		e, err := makeEncoding(row, "", architecture)
		if err != nil {
			return nil, err
		}
		if e.ID != "" {
			c.Encodings = append(c.Encodings, e)
		}
	}
	if architecture == "z180" {
		var err error
		c.Encodings, err = z180Extensions(c.Encodings)
		if err != nil {
			return nil, err
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func makeEncoding(row record, index, architecture string) (codec.Encoding, error) {
	var fixed []byte
	text := strings.TrimSpace(row.text)
	if row.id[:2] == "00" {
		fixed, _ = hex.DecodeString(row.id[2:])
	} else if row.id[:2] == "fe" {
		fixed, _ = hex.DecodeString(index + "cb00" + row.id[2:])
		register := "IX"
		if index == "fd" {
			register = "IY"
		}
		text = strings.ReplaceAll(text, "XY", register)
		if p := strings.Index(text, " = "); p >= 0 {
			left := strings.Fields(text[:p])
			mnemonic := left[0]
			args := strings.Join(left[1:], "")
			dest := args
			before := ""
			if comma := strings.LastIndexByte(args, ','); comma >= 0 {
				before = args[:comma+1]
				dest = args[comma+1:]
			}
			text = mnemonic + " " + before + text[p+3:] + "," + dest
		}
	} else {
		fixed, _ = hex.DecodeString(row.id)
	}
	if strings.HasPrefix(text, "DB") {
		if architecture == "z180" {
			return codec.Encoding{}, nil
		}
		text = "NOP"
	}
	text = strings.NewReplacer("HX", "IXH", "LX", "IXL", "HY", "IYH", "LY", "IYL").Replace(text)
	if architecture == "z180" {
		if strings.Contains(text, "IXH") || strings.Contains(text, "IXL") || strings.Contains(text, "IYH") || strings.Contains(text, "IYL") || strings.HasPrefix(text, "SLL") {
			return codec.Encoding{}, nil
		}
		if row.id[:2] == "fe" {
			op, _ := strconv.ParseUint(row.id[2:], 16, 8)
			if op&7 != 6 {
				return codec.Encoding{}, nil
			}
		}
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return codec.Encoding{}, fmt.Errorf("empty source opcode %s", row.id)
	}
	mnemonic := strings.ToLower(fields[0])
	args := strings.Join(fields[1:], "")
	if mnemonic == "ex" && args == "HL,(SP)" {
		args = "(SP),HL"
	}
	// RLD/RRD have an implicit (HL) access, not an assembly operand.
	if mnemonic == "rrd" || mnemonic == "rld" {
		args = ""
	}
	if mnemonic == "in" && args == "0,(C)" {
		args = "F,(C)"
	}
	if mnemonic == "rst" {
		n, err := strconv.Atoi(args)
		if err != nil {
			return codec.Encoding{}, err
		}
		args = fmt.Sprintf("0x%x", n*8)
	}
	id := row.id
	if row.id[:2] == "fe" {
		id = index + "cb" + row.id[2:]
	}
	e := codec.Encoding{ID: id, Mnemonic: mnemonic, Mask: make([]byte, len(fixed)), Value: append([]byte(nil), fixed...), Features: []string{architecture}, FlowControl: flow(mnemonic, args)}
	// Direct destinations live in the architectural 16-bit address space.
	switch e.FlowControl {
	case "branch", "call", "conditional_branch", "conditional_call", "loop":
		e.TargetMask = 0xffff
	}
	for i := range e.Mask {
		e.Mask[i] = 255
	}
	if row.id[:2] == "fe" {
		e.Mask[2] = 0
		e.Value[2] = 0
		e.Operands = append(e.Operands, codec.Operand{Name: "disp", Class: "signed_index_displacement", Kind: "displacement", Signed: true, Bits: []codec.BitSlice{{InstructionBit: 16, Width: 8}}})
		args = strings.ReplaceAll(args, "o", "{disp}")
	}
	// Source placeholders are case-sensitive: lowercase a is a 16-bit address;
	// uppercase A is the accumulator, and lowercase i/r are special registers.
	for _, token := range operandToken.FindAllString(args, -1) {
		name, kind, width, signed, relative := "imm8", "immediate", 8, false, false
		switch token {
		case "w":
			name = "imm16"
			width = 16
			if strings.Contains(args, "(w)") {
				kind = "address"
			}
		case "a":
			name = "target"
			kind = "address"
			width = 16
		case "o":
			name = "disp"
			kind = "displacement"
			signed = true
			relative = !strings.Contains(args, "IX+") && !strings.Contains(args, "IY+")
			if relative {
				name = "target"
			}
		}
		pos := len(e.Mask)
		for i := 0; i < width/8; i++ {
			e.Mask = append(e.Mask, 0)
			e.Value = append(e.Value, 0)
		}
		o := codec.Operand{Name: name, Class: token, Kind: kind, Signed: signed, Relative: relative, Bits: []codec.BitSlice{{InstructionBit: pos * 8, Width: width}}}
		if relative {
			o.PCWrapBits = 16
		} else if !signed {
			o.InputSignedBits = width
		}
		e.Operands = append(e.Operands, o)
		args = regexp.MustCompile(`\b`+token+`\b`).ReplaceAllString(args, "{"+name+"}")
	}
	for i := range e.Operands {
		if e.Operands[i].Relative {
			e.Operands[i].PCBias = int64(len(e.Mask))
		}
	}
	list := strings.Split(args, ",")
	opcode := int(fixed[len(fixed)-1])
	opPos := len(fixed) - 1
	if row.id[:2] == "fe" {
		opcode = int(fixed[3])
		opPos = 3
	}
	add := func(arg, shift, width int, name, kind string) {
		if arg < 0 || arg >= len(list) {
			return
		}
		raw := (opcode >> shift) & ((1 << width) - 1)
		names := make([]string, 1<<width)
		names[raw] = strings.ToLower(list[arg])
		o := codec.Operand{Name: name, Class: kind, Kind: kind, Names: names, Bits: []codec.BitSlice{{InstructionBit: opPos*8 + shift, Width: width}}}
		for k := 0; k < width; k++ {
			e.Mask[opPos] &^= 1 << uint(shift+k)
			e.Value[opPos] &^= 1 << uint(shift+k)
		}
		e.Operands = append(e.Operands, o)
		list[arg] = "{" + name + "}"
	}
	x, y, z := opcode>>6, (opcode>>3)&7, opcode&7
	switch row.id[:2] {
	case "cb", "fe":
		if x != 0 {
			add(0, 3, 3, "bit", "immediate")
		}
		if row.id[:2] == "cb" {
			add(len(list)-1, 0, 3, "reg", "register")
		} else if x != 1 && z != 6 {
			add(len(list)-1, 0, 3, "reg", "register")
		}
	case "ed":
		if mnemonic == "im" {
			mode, err := strconv.Atoi(args)
			if err != nil {
				return codec.Encoding{}, err
			}
			add(0, 3, 3, "mode", "immediate")
			// Duplicate raw selectors all expose the actual interrupt mode.
			e.Operands[len(e.Operands)-1].Bias = int64(mode - y)
		}
		if architecture == "z180" {
			if opcode < 0x40 && (opcode&0xc7 == 0 || opcode&0xc7 == 1 || opcode&0xc7 == 4) {
				arg := 0
				if opcode&0xc7 == 1 {
					arg = 1
				}
				add(arg, 3, 3, "reg", "register")
			}
			if opcode&0xcf == 0x4c {
				add(0, 4, 2, "pair", "register")
			}
		}
		if opcode&0xc7 == 0x40 || opcode&0xc7 == 0x41 {
			arg := 0
			if opcode&1 != 0 {
				arg = 1
			}
			if y != 6 {
				add(arg, 3, 3, "reg", "register")
			}
		}
		if opcode&0xcf == 0x42 || opcode&0xcf == 0x4a || opcode&0xcf == 0x43 || opcode&0xcf == 0x4b {
			arg := 1
			if opcode&0xcf == 0x4b {
				arg = 0
			}
			add(arg, 4, 2, "pair", "register")
		}
	default:
		if x == 1 && opcode != 0x76 {
			if y != 6 {
				add(0, 3, 3, "dst", "register")
			}
			if z != 6 {
				add(1, 0, 3, "src", "register")
			}
		}
		if x == 2 && z != 6 {
			add(len(list)-1, 0, 3, "src", "register")
		}
		if x == 0 && (z == 4 || z == 5 || z == 6) && y != 6 {
			add(0, 3, 3, "reg", "register")
		}
		if x == 0 && (z == 1 || z == 3) {
			arg := 0
			if z == 1 && y&1 != 0 {
				arg = 1
			}
			add(arg, 4, 2, "pair", "register")
		}
		if x == 3 && (z == 1 && y&1 == 0 || z == 5 && y&1 == 0) {
			add(0, 4, 2, "pair", "register")
		}
		if x == 3 && (z == 0 || z == 2 || z == 4) {
			add(0, 3, 3, "condition", "condition")
		}
		if x == 0 && z == 0 && y >= 4 {
			add(0, 3, 2, "condition", "condition")
		}
		if mnemonic == "rst" {
			add(0, 3, 3, "vector", "address")
			e.Operands[len(e.Operands)-1].Scale = 8
		}
	}
	e.Syntax = mnemonic
	if args != "" {
		e.Syntax += " " + strings.ToLower(strings.Join(list, ","))
	}
	return e, nil
}
func flow(mnemonic, args string) string {
	switch mnemonic {
	case "ret":
		if args != "" {
			return "conditional_return"
		}
		return "return"
	case "retn", "reti":
		return "return"
	case "call":
		if strings.Contains(args, ",") {
			return "conditional_call"
		}
		return "call"
	case "rst":
		return "call"
	case "jp", "jr":
		if strings.Contains(args, ",") {
			return "conditional_branch"
		}
		return "branch"
	case "djnz", "ldir", "lddr", "cpir", "cpdr", "inir", "indr", "otir", "otdr", "otimr", "otdmr":
		return "conditional_branch"
	case "halt", "slp":
		return "halt"
	}
	return "next"
}

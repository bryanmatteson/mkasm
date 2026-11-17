// Package mos6502 imports the complete cc65 6502-family opcode tables.
package mos6502

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type Catalog struct{ *codec.Catalog }
type sourceRow struct {
	Name, Handler string
	Length        int
}

var profiles = []string{"6502", "6502x", "65sc02", "65c02", "w65c02", "w65c02+nops"}
var tables = regexp.MustCompile(`(?s)const\s+OpcDesc\s+OpcTable_(6502X|6502|65SC02|65C02)\[256\]\s*=\s*\{(.*?)\n\};`)
var rows = regexp.MustCompile(`\{\s*"([^"]*)",\s*([123]),\s*[^,]+,\s*(OH_\w+),?\s*\}\s*,?\s*/\*\s*\$([0-9a-fA-F]{2})\s*\*/`)

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	switch architecture {
	case "mos6502", "6502", "6502x", "65sc02", "65c02", "w65c02":
	default:
		return nil, fmt.Errorf("unsupported 6502 architecture %q", architecture)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	source := map[string][]sourceRow{}
	for _, table := range tables.FindAllSubmatch(raw, -1) {
		name := strings.ToLower(string(table[1]))
		if source[name] != nil {
			return nil, fmt.Errorf("duplicate table %s", name)
		}
		for _, row := range rows.FindAllSubmatch(table[2], -1) {
			opcode, _ := strconv.ParseInt(string(row[4]), 16, 16)
			if int(opcode) != len(source[name]) {
				return nil, fmt.Errorf("nonsequential %s table", name)
			}
			n, _ := strconv.Atoi(string(row[2]))
			source[name] = append(source[name], sourceRow{string(row[1]), string(row[3]), n})
		}
		if len(source[name]) != 256 {
			return nil, fmt.Errorf("incomplete %s table: %d records", name, len(source[name]))
		}
	}
	if len(source) != 4 {
		return nil, fmt.Errorf("input must contain all four complete cc65 V2.19 da65 tables: 6502,6502X,65SC02,65C02")
	}
	expected := map[string]int{"6502": 151, "6502x": 256, "65sc02": 178, "65c02": 212}
	for name, want := range expected {
		n := 0
		for _, row := range source[name] {
			if row.Name != "" {
				n++
			}
		}
		if n != want {
			return nil, fmt.Errorf("%s legal opcode count %d != %d", name, n, want)
		}
	}
	c := &codec.Catalog{Schema: codec.Schema, Architecture: "mos6502", Source: "cc65 V2.19 da65 opcode tables; WDC W65C02S datasheet 2024-02-16 tables 4-1 and 7-1", SourceLicense: sourceNotice, SourceLicenseID: "MIT AND Zlib", FeatureSets: map[string][]string{}}
	type form struct {
		row          sourceRow
		opcode, mask int
		status       string
	}
	var forms []form
	keys := map[string]int{}
	add := func(row sourceRow, opcode, mask int, status string) {
		row.Handler = canonicalMode(row.Handler)
		key := fmt.Sprintf("%02x/%s/%s/%s", opcode, row.Name, row.Handler, status)
		if index, ok := keys[key]; ok {
			forms[index].mask |= mask
			return
		}
		keys[key] = len(forms)
		forms = append(forms, form{row, opcode, mask, status})
	}
	for profile, name := range profiles {
		table := name
		if name == "w65c02" || name == "w65c02+nops" {
			table = "65c02"
		}
		for op, row := range source[table] {
			if row.Name == "" {
				if name == "w65c02+nops" {
					length, ok := reservedNOP(byte(op))
					if !ok {
						return nil, fmt.Errorf("unaccounted reserved WDC opcode %02x", op)
					}
					mode := "OH_Implicit"
					if length == 2 {
						mode = "Padding8"
					}
					if length == 3 {
						mode = "Padding16"
					}
					add(sourceRow{"nop", mode, length}, op, 1<<profile, "reserved-nop")
				}
				continue
			}
			if name == "65c02" && (row.Name == "wai" || row.Name == "stp") {
				continue
			}
			status := "documented"
			if name == "6502x" && source["6502"][op].Name == "" {
				status = "undocumented"
			}
			// WDC table 4-1 note 5: BRK skips a real second signature byte.
			// da65's one-byte disassembler convention is intentionally corrected.
			if row.Name == "brk" {
				row.Length = 2
				row.Handler = "Signature"
			}
			add(row, op, 1<<profile, status)
		}
	}
	for _, f := range forms {
		e, err := importForm(f.row, byte(f.opcode), f.mask, f.status)
		if err != nil {
			return nil, err
		}
		c.Encodings = append(c.Encodings, e)
		for i, name := range profiles {
			if f.mask&(1<<i) != 0 {
				c.FeatureSets[name] = appendUnique(c.FeatureSets[name], e.Features[0])
				if f.status != "documented" {
					c.FeatureSets[name] = appendUnique(c.FeatureSets[name], f.status)
				}
			}
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Catalog{c}, nil
}
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
func canonicalMode(s string) string {
	switch s {
	case "OH_JsrAbsolute", "OH_JmpAbsolute":
		return "OH_Absolute"
	case "OH_Rts":
		return "OH_Implicit"
	}
	return s
}

// The complete reserved-opcode groups from WDC table 7-1, not guessed
// instruction behavior from NMOS undocumented encodings.
func reservedNOP(op byte) (int, bool) {
	switch op {
	case 0x02, 0x22, 0x42, 0x62, 0x82, 0xc2, 0xe2, 0x44, 0x54, 0xd4, 0xf4:
		return 2, true
	case 0x5c, 0xdc, 0xfc:
		return 3, true
	}
	if op&15 == 3 || op&15 == 11 && (op <= 0xbb || op == 0xeb || op == 0xfb) {
		return 1, true
	}
	return 0, false
}

func importForm(row sourceRow, opcode byte, mask int, status string) (codec.Encoding, error) {
	e := codec.Encoding{ID: fmt.Sprintf("%s_%02x_%s", row.Name, opcode, strings.TrimPrefix(row.Handler, "OH_")), Mnemonic: row.Name, Syntax: row.Name, Mask: make([]byte, row.Length), Value: make([]byte, row.Length), Features: []string{fmt.Sprintf("mos_%d", mask)}, FlowControl: "next"}
	e.Mask[0] = 255
	e.Value[0] = opcode
	if status != "documented" {
		e.Features = append(e.Features, status)
	}
	operand := func(name, kind string, bits, start int, relative bool) {
		o := codec.Operand{Name: name, Kind: kind, Class: strings.TrimPrefix(row.Handler, "OH_"), Bits: []codec.BitSlice{{InstructionBit: start, Width: bits}}, Relative: relative}
		if relative {
			o.Signed = true
			o.PCBias = int64(row.Length)
			o.PCWrapBits = 16
		} else if kind == "immediate" {
			o.InputSignedBits = bits
		}
		e.Operands = append(e.Operands, o)
	}
	syntax := ""
	switch row.Handler {
	case "OH_Implicit":
	case "OH_Accumulator":
		syntax = "a"
	case "OH_Immediate":
		operand("value", "immediate", 8, 8, false)
		syntax = "#{value}"
	case "Signature":
		operand("signature", "immediate", 8, 8, false)
		syntax = "#{signature}"
	case "Padding8":
		operand("padding", "immediate", 8, 8, false)
		syntax = "#{padding}"
	case "Padding16":
		operand("padding", "immediate", 16, 8, false)
		syntax = "{padding}"
	case "OH_Relative":
		operand("target", "address", 8, 8, true)
		syntax = "{target}"
	case "OH_BitBranch":
		operand("address", "address", 8, 8, false)
		operand("target", "address", 8, 16, true)
		syntax = "{address}, {target}"
	case "OH_Direct", "OH_DirectX", "OH_DirectY", "OH_DirectIndirect", "OH_DirectXIndirect", "OH_DirectIndirectY":
		operand("address", "address", 8, 8, false)
		switch row.Handler {
		case "OH_Direct":
			syntax = "{address}"
		case "OH_DirectX":
			syntax = "{address},x"
		case "OH_DirectY":
			syntax = "{address},y"
		case "OH_DirectIndirect":
			syntax = "({address})"
		case "OH_DirectXIndirect":
			syntax = "({address},x)"
		case "OH_DirectIndirectY":
			syntax = "({address}),y"
		}
	case "OH_Absolute", "OH_AbsoluteX", "OH_AbsoluteY", "OH_JmpAbsoluteIndirect", "OH_AbsoluteXIndirect":
		operand("address", "address", 16, 8, false)
		switch row.Handler {
		case "OH_Absolute":
			syntax = "{address}"
		case "OH_AbsoluteX":
			syntax = "{address},x"
		case "OH_AbsoluteY":
			syntax = "{address},y"
		case "OH_JmpAbsoluteIndirect":
			syntax = "({address})"
		case "OH_AbsoluteXIndirect":
			syntax = "({address},x)"
		}
	default:
		return e, fmt.Errorf("unknown addressing mode %s", row.Handler)
	}
	if syntax != "" {
		e.Syntax += " " + syntax
	}
	switch row.Name {
	case "brk":
		e.FlowControl = "trap"
	case "jsr":
		e.FlowControl = "call"
	case "jmp", "bra":
		e.FlowControl = "branch"
	case "rts", "rti":
		e.FlowControl = "return"
	case "jam", "stp", "wai":
		e.FlowControl = "stop"
	default:
		for _, o := range e.Operands {
			if o.Relative {
				e.FlowControl = "conditional_branch"
			}
		}
	}
	return e, nil
}
func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c.Catalog) }

var hexLiteral = regexp.MustCompile(`\$([0-9a-fA-F]+)\b`)
var binaryLiteral = regexp.MustCompile(`%([01]+)`)

func normalize(text string) string {
	text = hexLiteral.ReplaceAllString(text, "0x${1}")
	text = binaryLiteral.ReplaceAllString(text, "0b${1}")
	fields := strings.Fields(text)
	if len(fields) > 0 {
		switch strings.ToLower(fields[0]) {
		case "ane":
			text = "xaa" + text[strings.Index(text, fields[0])+len(fields[0]):]
		case "sha":
			text = "ahx" + text[strings.Index(text, fields[0])+len(fields[0]):]
		}
	}
	if len(fields) == 1 {
		switch strings.ToLower(fields[0]) {
		case "brk":
			text += " #0"
		case "asl", "lsr", "rol", "ror", "inc", "dec":
			text += " a"
		}
	}
	return text
}
func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.Catalog.Assemble(normalize(text), address)
}
func (c *Catalog) AssembleWithFeatures(text string, address uint64, features []string) ([][]byte, error) {
	return c.Catalog.AssembleWithFeatures(normalize(text), address, features)
}

// OpcodeStatus distinguishes source-defined legality from implementation support.
func (c *Catalog) OpcodeStatus(profile string, opcode byte) (string, error) {
	active, ok := c.FeatureSets[profile]
	if !ok {
		return "", fmt.Errorf("unknown processor profile %q", profile)
	}
	d, err := c.DecodeWithFeatures([]byte{opcode, 0, 0}, active)
	if err != nil {
		return "invalid", nil
	}
	for _, f := range d.Encoding.Features {
		if f == "undocumented" || f == "reserved-nop" {
			return f, nil
		}
	}
	return "documented", nil
}

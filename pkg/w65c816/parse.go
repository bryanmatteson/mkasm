// Package w65c816 imports the full 256-opcode W65C816 instruction stream.
// Immediate framing depends on the supplied E/M/X state, never the host CPU.
package w65c816

import (
	_ "embed"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed testdata/CC65-LICENSE
var license string

type Catalog struct{ *codec.Catalog }

var table = regexp.MustCompile(`(?s)const\s+OpcDesc\s+OpcTable_65816\[256\]\s*=\s*\{(.*?)\n\};`)
var rows = regexp.MustCompile(`\{\s*"([^"]+)",\s*([1234]),\s*[^,]+,\s*(OH_\w+)\s*\}\s*,?\s*/\*\s*\$([0-9a-fA-F]{2})\s*\*/`)

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "w65c816" && architecture != "65816" {
		return nil, fmt.Errorf("unsupported 65816 target %q", architecture)
	}
	b, e := io.ReadAll(r)
	if e != nil {
		return nil, e
	}
	matches := table.FindAllSubmatch(b, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("expected one complete cc65 OpcTable_65816")
	}
	source := rows.FindAllSubmatch(matches[0][1], -1)
	if len(source) != 256 {
		return nil, fmt.Errorf("65816 opcode table has %d rows, want 256", len(source))
	}
	c := &codec.Catalog{Schema: codec.Schema, Architecture: "w65c816", Source: "cc65 V2.19 da65 OpcTable_65816; ca65 instruction emitter; WDC W65C816S datasheet 2024-03-13 tables 5-1 and 5-7", SourceLicenseID: "Zlib", SourceLicense: "cc65 opcode metadata, Copyright Ullrich von Bassewitz and cc65 contributors. Original table notice retained in testdata/opc65816.c. WDC instruction framing facts are not redistributed specification text.\n" + license, FeatureSets: map[string][]string{}}
	for _, m := range []int{8, 16} {
		for _, x := range []int{8, 16} {
			c.FeatureSets[fmt.Sprintf("m%dx%d", m, x)] = []string{fmt.Sprintf("accumulator%d", m), fmt.Sprintf("index%d", x)}
		}
	}
	c.FeatureSets["emulation"] = c.FeatureSets["m8x8"]
	for op, row := range source {
		n, _ := strconv.ParseUint(string(row[4]), 16, 8)
		if int(n) != op {
			return nil, fmt.Errorf("out-of-order opcode %02x", op)
		}
		name, mode := string(row[1]), strings.TrimPrefix(string(row[3]), "OH_")
		length, _ := strconv.Atoi(string(row[2]))
		// da65 has historical display-only mistakes; physical framing follows
		// the CPU reference and is independently checked against ca65.
		if name == "brk" || name == "cop" || name == "wdm" {
			mode = "Signature"
			length = 2
		}
		if mode == "AbsoluteLong" || mode == "AbsoluteLongX" {
			length = 4
		}
		if op == 0xdc {
			mode = "AbsoluteIndirectLong"
		}
		if name == "pei" {
			mode = "DirectIndirect"
		}
		widths := []int{8}
		feature := ""
		if mode == "Immediate" {
			switch name {
			case "ora", "and", "eor", "adc", "bit", "lda", "cmp", "sbc":
				feature = "accumulator"
				widths = []int{8, 16}
			case "ldx", "ldy", "cpx", "cpy":
				feature = "index"
				widths = []int{8, 16}
			}
		}
		for _, w := range widths {
			n := length
			if feature != "" {
				n = 1 + w/8
			}
			enc, err := form(byte(op), name, mode, n)
			if err != nil {
				return nil, err
			}
			if feature != "" {
				enc.ID += fmt.Sprintf("_%d", w)
				enc.Features = []string{fmt.Sprintf("%s%d", feature, w)}
			}
			c.Encodings = append(c.Encodings, enc)
		}
	}
	if e = c.Validate(); e != nil {
		return nil, e
	}
	return &Catalog{c}, nil
}

func form(op byte, name, mode string, length int) (codec.Encoding, error) {
	e := codec.Encoding{ID: fmt.Sprintf("%s_%02x_%s", name, op, mode), Mnemonic: name, Syntax: name, Mask: make([]byte, length), Value: make([]byte, length), FlowControl: "next"}
	e.Mask[0] = 255
	e.Value[0] = op
	arg := func(name, kind string, bits, start int, relative bool) {
		o := codec.Operand{Name: name, Kind: kind, Class: mode, Bits: []codec.BitSlice{{InstructionBit: start, Width: bits}}}
		if relative {
			o.Relative = true
			o.Signed = true
			o.PCBias = int64(length)
			o.PCWrapBits = 24
			o.PCBankBits = 16
		}
		if kind == "immediate" {
			o.InputSignedBits = bits
		}
		e.Operands = append(e.Operands, o)
	}
	syntax := ""
	switch mode {
	case "Implicit", "Rts":
	case "Accumulator":
		syntax = "a"
	case "Immediate":
		arg("value", "immediate", (length-1)*8, 8, false)
		syntax = "#{value}"
	case "Signature":
		arg("signature", "immediate", 8, 8, false)
		syntax = "#{signature}"
	case "Relative", "RelativeLong":
		arg("target", "displacement", (length-1)*8, 8, true)
		syntax = "{target}"
	case "BlockMove":
		arg("source", "immediate", 8, 16, false)
		arg("destination", "immediate", 8, 8, false)
		syntax = "#{source},#{destination}"
	case "Direct", "DirectX", "DirectY", "DirectIndirect", "DirectXIndirect", "DirectIndirectY", "DirectIndirectLong", "DirectIndirectLongY", "StackRelative", "StackRelativeIndirectY":
		arg("address", "address", 8, 8, false)
		syntax = map[string]string{"Direct": "{address}", "DirectX": "{address},x", "DirectY": "{address},y", "DirectIndirect": "({address})", "DirectXIndirect": "({address},x)", "DirectIndirectY": "({address}),y", "DirectIndirectLong": "[{address}]", "DirectIndirectLongY": "[{address}],y", "StackRelative": "{address},s", "StackRelativeIndirectY": "({address},s),y"}[mode]
	case "Absolute", "JmpAbsolute", "JsrAbsolute", "AbsoluteX", "AbsoluteY", "AbsoluteXIndirect", "JmpAbsoluteIndirect", "AbsoluteIndirect", "AbsoluteIndirectLong", "AbsoluteLong", "AbsoluteLongX":
		arg("address", "address", (length-1)*8, 8, false)
		syntax = map[string]string{"Absolute": "{address}", "JmpAbsolute": "{address}", "JsrAbsolute": "{address}", "AbsoluteX": "{address},x", "AbsoluteY": "{address},y", "AbsoluteXIndirect": "({address},x)", "JmpAbsoluteIndirect": "({address})", "AbsoluteIndirect": "({address})", "AbsoluteIndirectLong": "[{address}]", "AbsoluteLong": "{address}", "AbsoluteLongX": "{address},x"}[mode]
		if (name == "jmp" || name == "jsr") && (mode == "JmpAbsolute" || mode == "JsrAbsolute" || mode == "Absolute") {
			o := &e.Operands[0]
			o.Relative = true
			o.PCRegionBits = 16
			o.PCWrapBits = 24
		}
	default:
		return e, fmt.Errorf("unknown 65816 mode %s", mode)
	}
	if syntax != "" {
		e.Syntax += " " + syntax
	}
	switch name {
	case "brk", "cop":
		e.FlowControl = "trap"
	case "jsl", "jsr":
		e.FlowControl = "call"
	case "jmp", "jml", "bra", "brl":
		e.FlowControl = "branch"
	case "rts", "rtl", "rti":
		e.FlowControl = "return"
	case "stp", "wai":
		e.FlowControl = "stop"
	case "bpl", "bmi", "bvc", "bvs", "bcc", "bcs", "bne", "beq":
		e.FlowControl = "conditional_branch"
	}
	if strings.Contains(mode, "Indirect") && (name == "jmp" || name == "jml" || name == "jsr") {
		e.FlowControl = "indirect_" + e.FlowControl
	}
	return e, nil
}

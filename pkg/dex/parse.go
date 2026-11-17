package dex

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Parse reads the complete unmodified AOSP ART dex_instruction_list.h source.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "dex" {
		return nil, fmt.Errorf("unsupported DEX architecture %q", architecture)
	}
	src, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*V\(0x([0-9A-Fa-f]{2}),\s*([A-Z0-9_]+),\s*"([a-z0-9/-]+)",\s*k([a-z0-9]+),\s*kIndex([A-Za-z]+),\s*([^,]+),\s*([^,]+),\s*([^\)]+)\)`)
	rows := re.FindAllSubmatch(src, -1)
	if len(rows) != 256 {
		return nil, fmt.Errorf("DEX requires complete AOSP 256-opcode corpus, got %d", len(rows))
	}
	c := &Catalog{Schema: Schema, Architecture: "dex", Source: "AOSP ART libdexfile/dex/dex_instruction_list.h"}
	for i, m := range rows {
		op, _ := strconv.ParseUint(string(m[1]), 16, 16)
		if int(op) != i {
			return nil, fmt.Errorf("DEX opcode sequence at %d", i)
		}
		d := Definition{Opcode: uint16(op), Mnemonic: string(m[3]), Format: string(m[4]), IndexKind: strings.TrimSuffix(string(m[5]), "Ref"), Flags: strings.TrimSpace(string(m[6])), Verify: strings.TrimSpace(string(m[8])), MinVersion: 35, Reserved: strings.HasPrefix(string(m[3]), "unused-")}
		if op >= 0xfa {
			d.MinVersion = 38
		}
		if op >= 0xfe {
			d.MinVersion = 39
		}
		if d.IndexKind == "None" || d.IndexKind == "Unknown" {
			d.IndexKind = ""
		}
		fields, ok := formatFields(d.Format, d.Opcode, d.IndexKind)
		if !ok {
			return nil, fmt.Errorf("DEX unknown source format %s", d.Format)
		}
		d.Fields = fields
		for j := range d.Fields {
			f := &d.Fields[j]
			if f.Kind == "register" {
				f.Wide = strings.Contains(d.Verify, "kVerifyReg"+strings.ToUpper(f.Name)+"Wide")
			}
		}
		c.Instructions = append(c.Instructions, d)
	}
	for i, n := range []string{"packed-switch-payload", "sparse-switch-payload", "array-data-payload"} {
		c.Instructions = append(c.Instructions, Definition{Opcode: uint16((i + 1) << 8), Mnemonic: n, Format: "payload", MinVersion: 35})
	}
	if c.Instructions[0].Mnemonic != "nop" || c.Instructions[0xff].Mnemonic != "const-method-type" {
		return nil, fmt.Errorf("unsupported AOSP opcode metadata")
	}
	return c, nil
}
func formatFields(form string, op uint16, index string) ([]Field, bool) {
	reg := func(n string, b, w int) Field { return Field{Name: n, Kind: "register", Bit: b, Width: w} }
	val := func(n, k string, b, w int, s bool) Field { return Field{Name: n, Kind: k, Bit: b, Width: w, Signed: s} }
	a4, a8 := reg("a", 8, 4), reg("a", 8, 8)
	b4 := reg("b", 12, 4)
	idx := func(b, w int) Field { return val("index", index, b, w, false) }
	lit := func(b, w int) Field { return val("literal", "literal", b, w, true) }
	target := func(b, w int) Field { return val("target", "target", b, w, true) }
	switch form {
	case "10x":
		return nil, true
	case "12x":
		return []Field{a4, b4}, true
	case "11n":
		return []Field{a4, lit(12, 4)}, true
	case "11x":
		return []Field{a8}, true
	case "10t":
		return []Field{target(8, 8)}, true
	case "20t":
		return []Field{target(16, 16)}, true
	case "22x":
		return []Field{a8, reg("b", 16, 16)}, true
	case "21t":
		return []Field{a8, target(16, 16)}, true
	case "21s":
		return []Field{a8, lit(16, 16)}, true
	case "21h":
		f := lit(16, 16)
		f.Shift = 16
		if op == 0x19 {
			f.Shift = 48
		}
		return []Field{a8, f}, true
	case "21c":
		return []Field{a8, idx(16, 16)}, true
	case "23x":
		return []Field{a8, reg("b", 16, 8), reg("c", 24, 8)}, true
	case "22b":
		return []Field{a8, reg("b", 16, 8), lit(24, 8)}, true
	case "22t":
		return []Field{a4, b4, target(16, 16)}, true
	case "22s":
		return []Field{a4, b4, lit(16, 16)}, true
	case "22c":
		return []Field{a4, b4, idx(16, 16)}, true
	case "32x":
		return []Field{reg("a", 16, 16), reg("b", 32, 16)}, true
	case "30t":
		return []Field{target(16, 32)}, true
	case "31t":
		return []Field{a8, target(16, 32)}, true
	case "31i":
		return []Field{a8, lit(16, 32)}, true
	case "31c":
		return []Field{a8, idx(16, 32)}, true
	case "35c", "3rc":
		return []Field{idx(16, 16)}, true
	case "45cc", "4rcc":
		return []Field{idx(16, 16), val("proto", "Proto", 48, 16, false)}, true
	case "51l":
		return []Field{a8, lit(16, 64)}, true
	}
	return nil, false
}

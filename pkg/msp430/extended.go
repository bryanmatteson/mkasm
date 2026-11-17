package msp430

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Pinned Ghidra source, Apache-2.0, commit
// 68270ac6d9fb523574fc36470b4ea2e0aee210eb.
//
//go:embed data/TI430X.sinc
var extendedSource string

//go:embed data/TI430Common.sinc
var commonSource string
var constructor = regexp.MustCompile(`(?m)^:([A-Z][A-Z0-9]*(?:\.[ABW])?)\s+(.*?)\s+is\s+(.*?)\s*\{`)
var tokenField = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=\s*\(([0-9]+),\s*([0-9]+)\)`)
var fixedField = regexp.MustCompile(`\b([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|[0-9]+)\b`)

func extend(c *codec.Catalog) error {
	allowed := map[string]bool{}
	for _, m := range constructor.FindAllStringSubmatch(extendedSource, -1) {
		allowed[strings.ToLower(m[1])] = true
	}
	base := append([]codec.Encoding(nil), c.Encodings...)
	for _, e := range base {
		if e.AssemblyOnly {
			continue
		}
		name := strings.TrimSuffix(e.Mnemonic, ".b") + "x.w"
		if strings.HasSuffix(e.Mnemonic, ".b") {
			name = strings.TrimSuffix(e.Mnemonic, ".b") + "x.b"
		}
		if !allowed[name] {
			continue
		}
		for _, size := range []string{"w", "a", "b"} {
			if size == "b" && !strings.HasSuffix(e.Mnemonic, ".b") || size != "b" && strings.HasSuffix(e.Mnemonic, ".b") {
				continue
			}
			mnemonic := strings.TrimSuffix(strings.TrimSuffix(name, ".w"), ".b") + "." + size
			if !allowed[mnemonic] {
				continue
			}
			ext := extendEncoding(e, mnemonic, size)
			c.Encodings = append(c.Encodings, ext)
			// A bare x mnemonic denotes its word form.
			if size == "w" {
				alias := cloneEncoding(ext)
				alias.ID += "_default"
				alias.Mnemonic = strings.TrimSuffix(mnemonic, ".w")
				alias.Syntax = strings.Replace(alias.Syntax, mnemonic, alias.Mnemonic, 1)
				alias.AssemblyOnly = true
				c.Encodings = append(c.Encodings, alias)
			}
			// TI register-mode extension words support repetition: As=0 and,
			// for Format I, Ad=0. Merely having no extra word is insufficient.
			if len(e.Mask) == 2 && e.Mask[0]&0x30 == 0x30 && e.Value[0]&0x30 == 0 && (e.Value[1]>>4 == 1 || e.Value[0]&0x80 == 0) {
				for _, reg := range []bool{false, true} {
					repeat := cloneEncoding(ext)
					repeat.ID += "_repeat_imm"
					o := codec.Operand{Name: "repeat", Kind: "immediate", Bits: []codec.BitSlice{{InstructionBit: 0, ValueBit: 0, Width: 4}}, Bias: 1}
					prefix := "rpt #{repeat} {{ "
					repeat.Mask[0] &= 0xf0
					repeat.Value[0] &= 0xf0
					if reg {
						repeat.ID = ext.ID + "_repeat_reg"
						repeat.Value[0] |= 0x80
						repeat.Mask[0] |= 0x80
						o.Kind = "register"
						o.Bias = 0
						registers(&o, false)
						prefix = "rpt {repeat} {{ "
					}
					repeat.Operands = append(repeat.Operands, o)
					repeat.Syntax = prefix + ext.Syntax
					repeat.Mnemonic = "rpt"
					c.Encodings = append(c.Encodings, repeat)
				}
			}

		}
	}
	// ZC selects RRUx only in the register form; in memory forms that bit
	// belongs to the source address high nibble. Include repeated spellings.
	for _, e := range append([]codec.Encoding(nil), c.Encodings...) {
		if len(e.Mask) == 4 && e.Mask[2]&0x30 == 0x30 && e.Value[2]&0x30 == 0 && strings.Contains(e.Syntax, "rrcx.") {
			rru := cloneEncoding(e)
			rru.ID += "_zero_carry"
			rru.Value[1] |= 1
			rru.Mnemonic = strings.Replace(rru.Mnemonic, "rrcx", "rrux", 1)
			rru.Syntax = strings.Replace(rru.Syntax, "rrcx", "rrux", 1)
			c.Encodings = append(c.Encodings, rru)
			if strings.HasSuffix(rru.Mnemonic, ".w") {
				alias := cloneEncoding(rru)
				alias.ID += "_default"
				alias.Mnemonic = strings.TrimSuffix(alias.Mnemonic, ".w")
				alias.Syntax = strings.ReplaceAll(alias.Syntax, "rrux.w", "rrux")
				alias.AssemblyOnly = true
				c.Encodings = append(c.Encodings, alias)
			}
		}
	}
	additions, err := addressInstructions()
	if err != nil {
		return err
	}
	c.Encodings = append(c.Encodings, additions...)
	for _, e := range additions {
		if strings.HasSuffix(e.Mnemonic, ".w") {
			a := cloneEncoding(e)
			a.ID += "_default"
			a.Mnemonic = strings.TrimSuffix(a.Mnemonic, ".w")
			a.Syntax = strings.Replace(a.Syntax, e.Mnemonic, a.Mnemonic, 1)
			a.AssemblyOnly = true
			c.Encodings = append(c.Encodings, a)
		}
	}
	for _, e := range append([]codec.Encoding(nil), c.Encodings...) {
		if e.Mnemonic == "rpt" && strings.Contains(e.Syntax, ".w ") {
			a := cloneEncoding(e)
			a.ID += "_default"
			a.Syntax = strings.Replace(a.Syntax, ".w ", " ", 1)
			a.AssemblyOnly = true
			c.Encodings = append(c.Encodings, a)
		}
	}
	return nil
}
func extendEncoding(e codec.Encoding, mnemonic, size string) codec.Encoding {
	ext := cloneEncoding(e)
	ext.ID = "X_" + e.ID + "_" + size
	ext.Mnemonic = mnemonic
	ext.Syntax = strings.Replace(ext.Syntax, e.Mnemonic, mnemonic, 1)
	ext.Features = []string{"msp430x"}
	ext.Mask = append([]byte{0xff, 0xff}, ext.Mask...)
	ext.Value = append([]byte{0x40, 0x18}, ext.Value...)
	if size == "a" {
		ext.Value[0] &= ^byte(0x40)
		if !strings.HasPrefix(mnemonic, "swpbx") && !strings.HasPrefix(mnemonic, "sxtx") {
			ext.Value[2] |= 0x40
		}
	}
	opcode := e.Value[1] >> 4
	as := (e.Value[0] >> 4) & 3
	rs := (e.Value[1]) & 15
	fixedSource := e.Mask[1]&15 == 15
	hasSourceWord := opcode >= 4 && (as == 1 && !(fixedSource && rs == 3) || as == 3 && fixedSource && rs == 0)
	for i := range ext.Operands {
		o := &ext.Operands[i]
		// The extension word has two address-high fields: destination at bit
		// zero and source at bit seven. Record them in physical order so an
		// operand shared by both addresses has reproducible bit slices.
		var fields [2]bool
		for j := range o.Bits {
			b := &o.Bits[j]
			if b.InstructionBit >= 16 {
				field := 0
				if opcode == 1 {
					field = 1
				}
				if opcode >= 4 && hasSourceWord && b.InstructionBit < 32 {
					field = 1
				}
				fields[field] = true
			}
			b.InstructionBit += 16
		}
		if fields[0] || fields[1] {
			// Every extension word address has four additional high bits. Keeping
			// immediate high bits also preserves all physically encoded input bits.
			for field, present := range fields {
				if !present {
					continue
				}
				high := field * 7
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: high, ValueBit: 16, Width: 4})
				for b := high; b < high+4; b++ {
					ext.Mask[b/8] &= ^(1 << uint(b%8))
					ext.Value[b/8] &= ^(1 << uint(b%8))
				}
			}
			if o.InputSignedBits > 0 {
				o.InputSignedBits = 20
			}
		}
		if o.Relative {
			o.PCWrapBits = 20
			o.PCLowWrapBits = 0
			o.PCBias += 2
		}
	}
	// The wrapped symbolic alias partition scales with the extended address
	// field width, while the difference between extension-word PC bases stays2.
	for i := range ext.Operands {
		o := &ext.Operands[i]
		if o.Implicit && o.Bias < 0 {
			o.Bias -= (1 << 20) - (1 << 16)
		}
	}
	for i := range ext.Constraints {
		con := &ext.Constraints[i]
		if con.Kind == "diff_ge" && con.Limit < 0 {
			con.Limit -= (1 << 19) - (1 << 15)
		}
		if con.Kind == "sum_le" && con.Limit < 0 {
			con.Limit -= (1 << 19) - (1 << 15)
		}
	}
	return ext
}

func addressInstructions() ([]codec.Encoding, error) {
	type span struct{ start, width int }
	fields := map[string]span{}
	source := commonSource[strings.Index(commonSource, "define token instr16"):]
	for _, m := range tokenField.FindAllStringSubmatch(source, -1) {
		a, _ := strconv.Atoi(m[2])
		b, _ := strconv.Atoi(m[3])
		fields[m[1]] = span{a, b - a + 1}
	}
	// Ghidra's imm_0_4 spelling accidentally declares five bits. The hardware
	// field is the low nibble, independently verified with GNU binutils.
	fields["imm_0_4"] = span{0, 4}
	var out []codec.Encoding
	seen := map[string]bool{}
	for line, m := range constructor.FindAllStringSubmatch(extendedSource, -1) {
		mnemonic, display, pattern := strings.ToLower(m[1]), m[2], m[3]
		if !strings.Contains(pattern, "ctx_haveext=0") {
			continue
		}
		if seen[mnemonic+"|"+display] {
			continue
		}
		seen[mnemonic+"|"+display] = true
		e := codec.Encoding{ID: fmt.Sprintf("X_address_%s_%d", strings.ReplaceAll(mnemonic, ".", "_"), line), Mnemonic: mnemonic, Mask: []byte{0xff, 0xff}, Value: []byte{0, 0}, Features: []string{"msp430x"}, FlowControl: "next"}
		fix := func(start, width, value int) {
			for i := 0; i < width; i++ {
				p := start + i
				e.Mask[p/8] |= 1 << uint(p%8)
				e.Value[p/8] &= ^(1 << uint(p%8))
				e.Value[p/8] |= byte((value>>i)&1) << uint(p%8)
			}
		}
		for _, f := range fixedField.FindAllStringSubmatch(pattern, -1) {
			if span, ok := fields[f[1]]; ok && span.start+span.width <= 16 && f[1] != "imm_0_16" {
				n, _ := strconv.ParseInt(f[2], 0, 32)
				fix(span.start, span.width, int(n))
			}
		}
		add := func(o codec.Operand) {
			for _, b := range o.Bits {
				for i := 0; i < b.Width; i++ {
					p := b.InstructionBit + i
					for p/8 >= len(e.Mask) {
						e.Mask = append(e.Mask, 0xff)
						e.Value = append(e.Value, 0)
					}
					e.Mask[p/8] &= ^(1 << uint(p%8))
					e.Value[p/8] &= ^(1 << uint(p%8))
				}
			}
			e.Operands = append(e.Operands, o)
		}
		syntax := strings.ReplaceAll(strings.ReplaceAll(display, "^", ""), "\"", "")
		if strings.Contains(syntax, "src_8_4") {
			o := codec.Operand{Name: "src", Bits: []codec.BitSlice{{InstructionBit: 8, Width: 4}}}
			registers(&o, false)
			add(o)
			syntax = strings.ReplaceAll(syntax, "src_8_4", "{src}")
		}
		if strings.Contains(syntax, "dest_0_4") {
			o := codec.Operand{Name: "dst", Bits: []codec.BitSlice{{InstructionBit: 0, Width: 4}}}
			registers(&o, false)
			add(o)
			syntax = strings.ReplaceAll(syntax, "dest_0_4", "{dst}")
		}
		if strings.Contains(syntax, "Abs20") {
			token := "Abs20"
			signed := strings.Contains(syntax, "Abs20s")
			if signed {
				token = "Abs20s"
			} else if strings.Contains(syntax, "Abs20add") {
				token = "Abs20add"
			}
			high := 0
			if strings.Contains(pattern, "imm_8_4") {
				high = 8
			}
			o := codec.Operand{Name: "address", Kind: "address", Signed: signed, Bits: []codec.BitSlice{{InstructionBit: 16, Width: 16}, {InstructionBit: high, ValueBit: 16, Width: 4}}, InputSignedBits: 20}
			add(o)
			syntax = strings.ReplaceAll(syntax, token, "{address}")
		}
		if strings.Contains(syntax, "imms_0_16") {
			o := codec.Operand{Name: "offset", Kind: "displacement", Signed: true, InputSignedBits: 16, Bits: []codec.BitSlice{{InstructionBit: 16, Width: 16}}}
			if strings.Contains(syntax, "(PC)") {
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: 0, ValueBit: 16, Width: 4})
				o.InputSignedBits = 20
				o.Relative = true
				o.PCWrapBits = 20
				o.PCBias = 2
				syntax = strings.ReplaceAll(syntax, "(PC)", "")
			}
			add(o)
			syntax = strings.ReplaceAll(syntax, "imms_0_16", "{offset}")
		}
		if strings.Contains(syntax, "IMM4") || strings.Contains(syntax, "NUM2") {
			start, width := 4, 4
			token := "IMM4"
			if strings.Contains(syntax, "NUM2") {
				start, width = 10, 2
				token = "NUM2"
			}
			add(codec.Operand{Name: "count", Kind: "immediate", Bits: []codec.BitSlice{{InstructionBit: start, Width: width}}, Bias: 1})
			syntax = strings.ReplaceAll(syntax, token, "#{count}")
		}
		if strings.Contains(syntax, "ctx_popreg") {
			// The assembly register is the top of the block; the encoded register is
			// its bottom. Numeric rN syntax keeps names in semantic register space.
			o := codec.Operand{Name: "dst", Kind: "register", RegisterPrefix: "r", Bits: []codec.BitSlice{{InstructionBit: 0, Width: 4}}, BiasOperand: "count", Bias: -1}
			add(o)
			syntax = strings.ReplaceAll(syntax, "ctx_popreg", "{dst}")
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "sum_le", Left: "dst", Limit: 15})
		}
		for _, f := range fixedField.FindAllStringSubmatch(pattern, -1) {
			if f[1] == "imm_0_16" {
				if len(e.Mask) == 2 {
					e.Mask = append(e.Mask, 0xff, 0xff)
					e.Value = append(e.Value, 0, 0)
				}
				n, _ := strconv.ParseInt(f[2], 0, 32)
				e.Value[2] = byte(n)
				e.Value[3] = byte(n >> 8)
			}
		}
		if mnemonic == "reta" {
			syntax = ""
			e.Operands = nil
			e.Value = []byte{0x10, 0x01}
			e.Mask = []byte{0xff, 0xff}
			e.FlowControl = "return"
		}
		if mnemonic == "calla" {
			e.FlowControl = "call"
		}
		if mnemonic == "bra" {
			e.FlowControl = "branch"
		}
		e.Syntax = strings.TrimSpace(mnemonic + " " + syntax)
		if strings.Contains(e.Syntax, "Abs") || strings.Contains(e.Syntax, "imm_") || strings.Contains(e.Syntax, "ctx_") {
			return nil, fmt.Errorf("unhandled Ghidra MSP430X addressing constructor %s", e.Syntax)
		}
		out = append(out, e)
	}
	return out, nil
}

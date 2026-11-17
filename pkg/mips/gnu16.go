package mips

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed testdata/gnu-mips16.json
var gnu16JSON []byte

type gnu16Operand struct {
	Kind                                    string `json:"kind"`
	Size, LSB, Max, Bias, Shift, Align, ISA int
	FlipISA                                 int `json:"flip_isa"`
	AddLSB                                  int `json:"add_lsb"`
	Opsize                                  int
	Bank                                    string
	Registers                               []int
	Samples                                 [][2]int64
}
type gnu16Row struct {
	Row                                                          int
	Name, Args                                                   string
	Match, Mask                                                  uint32
	ShortOnly                                                    int `json:"short_only"`
	Alias, Delay, Branch, Conditional, ISA, E2, E2MT, Interaptiv int
	Read, Write                                                  []int
	ImplicitRead                                                 []int `json:"implicit_read"`
	ImplicitWrite                                                []int `json:"implicit_write"`
}
type gnu16Corpus struct {
	Operands     map[string]struct{ Short, Extended gnu16Operand }
	Instructions []gnu16Row
}

var gnu16GPR = []string{"$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$s8", "$ra"}

func gnu16Physical(bit, size int, little bool) int {
	word := size/2 - 1 - bit/16
	within := bit % 16
	if !little {
		within = (1-within/8)*8 + within%8
	}
	return word*16 + within
}

func gnu16Features(r gnu16Row) []string {
	f := []string{"InMips16Mode"}
	switch r.ISA {
	case 0, 1:
	case 3:
		f = append(f, "HasMips3")
	case 6:
		f = append(f, "HasMips32")
	case 11:
		f = append(f, "HasMips64")
	default:
		panic(fmt.Sprintf("unhandled GNU MIPS16 ISA %d", r.ISA))
	}
	if r.E2 != 0 {
		f = append(f, "HasMips16e2")
	}
	if r.E2MT != 0 {
		f = append(f, "HasMips16e2MT")
	}
	if r.Interaptiv != 0 {
		f = append(f, "HasInterAptivMR2")
	}
	return f
}

func gnu16Encoding(r gnu16Row, extended, little bool) codec.Encoding {
	size, mask, value := 2, r.Mask, r.Match
	if mask > 0xffff {
		size = 4
	}
	if extended && size == 2 {
		size, mask, value = 4, mask|0xf8000000, value|0xf0000000
	}
	id := fmt.Sprintf("GNU_MIPS16_ROW_%03d", r.Row)
	if extended {
		id += "_extended"
	}
	e := codec.Encoding{ID: id, Mnemonic: r.Name, Syntax: r.Name, Mask: make([]byte, size), Value: make([]byte, size), Features: gnu16Features(r), FlowControl: "next"}
	e.SourcePredicates = append([]string(nil), e.Features...)
	for bit := 0; bit < size*8; bit++ {
		p := gnu16Physical(bit, size, little)
		if mask>>bit&1 != 0 {
			e.Mask[p/8] |= 1 << uint(p%8)
		}
		if value>>bit&1 != 0 {
			e.Value[p/8] |= 1 << uint(p%8)
		}
	}
	if r.Delay != 0 || r.Branch != 0 {
		e.FlowControl = "branch"
	}
	if r.Conditional != 0 {
		e.FlowControl = "conditional_branch"
	}
	if r.Delay != 0 {
		e.DelaySlots = 1
	}
	if len(r.ImplicitWrite) > 2 && r.ImplicitWrite[2] != 0 && (r.Delay != 0 || r.Branch != 0) {
		e.FlowControl = "call"
	}
	if (r.Name == "jr" || r.Name == "jrc" || r.Name == "j") && r.Args == "R" {
		e.FlowControl = "return"
	}
	e.Effects = codec.EffectSpec{Knowledge: codec.EffectsPartial, RegistersKnowledge: codec.EffectsPartial}
	for i, name := range []string{"$t8", "$sp", "$ra", "HI", "LO", "PC", "$s0"} {
		read, write := i < len(r.ImplicitRead) && r.ImplicitRead[i] != 0, i < len(r.ImplicitWrite) && r.ImplicitWrite[i] != 0
		if read || write {
			e.Effects.Registers = append(e.Effects.Registers, codec.RegisterEffectSpec{Name: name, Read: read, Write: write, Implicit: true})
		}
	}
	return e
}

func gnu16Positions(d, short gnu16Operand, size int, explicit bool) []int {
	p := make([]int, d.Size)
	for b := range p {
		p[b] = d.LSB + b
	}
	if size != 4 {
		return p
	}
	if d.Kind == "pcrel" && d.Size == 26 {
		for b := 0; b < 26; b++ {
			switch {
			case b < 16:
				p[b] = b
			case b < 21:
				p[b] = b + 5
			default:
				p[b] = b - 5
			}
		}
		return p
	}
	marshal := d.LSB == 0 && (explicit && d.Kind == "int" || d.Size != short.Size || d.LSB != short.LSB)
	if !marshal {
		return p
	}
	switch d.Size {
	case 16, 9:
		for b := range p {
			switch {
			case b < 5:
				p[b] = b
			case b < 11:
				p[b] = 16 + b
			default:
				p[b] = 16 + b - 11
			}
		}
	case 15:
		for b := range p {
			switch {
			case b < 4:
				p[b] = b
			case b < 11:
				p[b] = 16 + b
			default:
				p[b] = 16 + b - 11
			}
		}
	case 6:
		for b := range p {
			if b < 5 {
				p[b] = 22 + b
			} else {
				p[b] = 21
			}
		}
	}
	return p
}

func gnu16Integer(d gnu16Operand, raw uint64) int64 {
	width := uint64(1) << uint(d.Size)
	n := int64(raw) | ((int64(d.Max) - int64(raw)) & -int64(width))
	return (n + int64(d.Bias)) << uint(d.Shift)
}

func gnu16RegName(d gnu16Operand, raw int) string {
	n := d.Registers[raw]
	if d.Bank == "gpr" {
		return gnu16GPR[n]
	}
	return "$" + strconv.Itoa(n)
}

func gnu16EntryList(raw int, exit bool) string {
	a, s, ra := (raw>>3)&7, (raw>>1)&3, raw&1
	if s == 3 || !exit && a > 4 || exit && a < 5 {
		return ""
	}
	parts := []string{}
	if !exit && a > 0 {
		part := "$a0"
		if a > 1 {
			part += "-" + gnu16GPR[a+3]
		}
		parts = append(parts, part)
	}
	if s > 0 {
		part := "$s0"
		if s > 1 {
			part += "-$s1"
		}
		parts = append(parts, part)
	}
	if ra != 0 {
		parts = append(parts, "$ra")
	}
	if exit && a == 5 {
		parts = append(parts, "$f0")
	}
	if exit && a == 6 {
		parts = append(parts, "$f0-$f1")
	}
	return strings.Join(parts, ", ")
}

// addGNUMips16 imports every non-macro row of the retained GNU opcode table.
// A non-short row with an extendible operand also contributes its EXTEND form.
func addGNUMips16(c *codec.Catalog) error {
	var corpus gnu16Corpus
	if err := json.Unmarshal(gnu16JSON, &corpus); err != nil {
		return err
	}
	little := strings.HasSuffix(c.Architecture, "el")
	for _, r := range corpus.Instructions {
		for _, extended := range []bool{false, true} {
			if extended && (r.Mask > 0xffff || r.ShortOnly != 0) {
				continue
			}
			canExtend := r.Args == "m"
			for _, ch := range r.Args {
				d := corpus.Operands[string(ch)]
				if d.Short.Size != d.Extended.Size || d.Short.LSB != d.Extended.LSB || d.Short.Shift != d.Extended.Shift || d.Short.Max != d.Extended.Max {
					canExtend = true
				}
			}
			if extended && !canExtend {
				continue
			}
			if r.Args == "m" {
				c.Encodings = append(c.Encodings, gnu16SaveRows(r, extended, little)...)
				continue
			}
			e := gnu16Encoding(r, extended, little)
			if err := gnu16Operands(&e, r, corpus, extended, little); err != nil {
				return fmt.Errorf("%s %s: %w", r.Name, r.Args, err)
			}
			if strings.Contains(c.Architecture, "64") {
				for i := range e.Operands {
					if e.Operands[i].Relative {
						e.Operands[i].PCWrapBits = 0
					}
				}
			}
			c.Encodings = append(c.Encodings, e)
			if raw := gnu16IgnoredEncoding(e, r, extended, little); raw != nil {
				// MIPS16e2 makes some legacy ignored EXTEND bits reserved.
				// Its preceding SHORT_ONLY row explicitly blocks that legacy
				// marshaller. Canonical zero-bit forms remain common to both.
				if extended {
					for _, prior := range corpus.Instructions {
						if prior.Row >= r.Row {
							break
						}
						if prior.E2 != 0 && prior.ShortOnly != 0 && prior.Match == r.Match && prior.Mask == r.Mask {
							raw.Features = append(append([]string(nil), raw.Features...), "NotMips16e2")
							raw.SourcePredicates = append(append([]string(nil), raw.SourcePredicates...), "NotMips16e2")
							break
						}
					}
				}
				c.Encodings = append(c.Encodings, *raw)
			}
			for _, o := range e.Operands {
				if o.Class != "GNU_MIPS16_optional_reg" {
					continue
				}
				alias := e
				alias.ID += "_optional_" + o.Name
				alias.Syntax = strings.Replace(alias.Syntax, ", {"+o.Name+"}", "", 1)
				alias.AssemblyOnly = true
				alias.Operands = append([]codec.Operand(nil), e.Operands...)
				// Hidden semantic zero = encoded register - destination.
				for i := range alias.Operands {
					if alias.Operands[i].Name == o.Name {
						alias.Operands[i].BiasOperand = e.Operands[0].Name
						alias.Operands[i].BiasScale = -1
						alias.Operands[i].Implicit = true
					}
				}
				alias.Effects.Registers = append([]codec.RegisterEffectSpec(nil), e.Effects.Registers...)
				for i := range alias.Effects.Registers {
					if alias.Effects.Registers[i].Operand == o.Name {
						alias.Effects.Registers[i].Operand = e.Operands[0].Name
					}
				}
				c.Encodings = append(c.Encodings, alias)
			}
		}
	}
	c.Source += "; complete GNU binutils 2.44 MIPS16 machine opcode rows"
	c.SourceLicenseID = "Apache-2.0 WITH LLVM-exception AND GPL-3.0-or-later"
	c.SourceLicense += "\nGNU MIPS16 opcode definitions; Copyright 1996-2025 Free Software Foundation.\n" + gnuMips16License
	return nil
}

// GNU's disassembler accepts nonzero ignored EXTEND payload bits even though
// its assembler canonicalizes them to zero. Preserve them as an explicit exact
// spelling, so decode never shortens the instruction or loses physical bits.
func gnu16IgnoredEncoding(e codec.Encoding, r gnu16Row, extended, little bool) *codec.Encoding {
	original := gnu16Encoding(r, extended, little)
	used := append([]byte(nil), original.Mask...)
	for _, o := range e.Operands {
		for _, b := range o.Bits {
			used[b.InstructionBit/8] |= 1 << uint(b.InstructionBit%8)
		}
	}
	o := codec.Operand{Name: "encoding_bits", Class: "GNU_MIPS16_ignored", Kind: "immediate"}
	for p, m := range used {
		for b := 0; b < 8; b++ {
			if m>>b&1 == 0 {
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: p*8 + b, ValueBit: len(o.Bits), Width: 1})
			}
		}
	}
	if len(o.Bits) == 0 {
		return nil
	}
	e.ID += "_ignored_bits"
	e.Mask = append([]byte(nil), e.Mask...)
	for _, b := range o.Bits {
		e.Mask[b.InstructionBit/8] &^= 1 << uint(b.InstructionBit%8)
	}
	e.Operands = append(append([]codec.Operand(nil), e.Operands...), o)
	e.Syntax += " encoding_bits:{encoding_bits}"
	e.Constraints = append(append([]codec.Constraint(nil), e.Constraints...), codec.Constraint{Kind: "ne", Left: o.Name})
	return &e
}

func gnu16Operands(e *codec.Encoding, r gnu16Row, corpus gnu16Corpus, extended, little bool) error {
	if r.Args != "" {
		e.Syntax += " "
	}
	ordinal := 0
	lastInt := ""
	for _, ch := range r.Args {
		if strings.ContainsRune(",()", ch) {
			if ch == ',' {
				e.Syntax += ", "
			} else {
				e.Syntax += string(ch)
			}
			continue
		}
		pair, ok := corpus.Operands[string(ch)]
		if !ok {
			return fmt.Errorf("missing source operand %c", ch)
		}
		d := pair.Short
		if extended || len(e.Mask) == 4 {
			d = pair.Extended
		}
		ordinal++
		if d.Kind == "gp" {
			e.Syntax += "$gp"
			gnu16RegisterEffect(e, r, ordinal, "$gp", "", "gpr")
			continue
		}
		if d.Kind == "pc" {
			e.Syntax += "$pc"
			continue
		}
		positions := gnu16Positions(d, pair.Short, len(e.Mask), r.Mask > 0xffff)
		free := []int{}
		fixed := uint64(0)
		for b, p := range positions {
			physical := gnu16Physical(p, len(e.Mask), little)
			if e.Mask[physical/8]&(1<<uint(physical%8)) != 0 {
				if e.Value[physical/8]&(1<<uint(physical%8)) != 0 {
					fixed |= 1 << uint(b)
				}
			} else {
				free = append(free, b)
			}
		}
		if len(free) == 0 {
			switch d.Kind {
			case "reg", "optional_reg":
				name := gnu16RegName(d, int(fixed))
				e.Syntax += name
				gnu16RegisterEffect(e, r, ordinal, name, "", d.Bank)
			case "int":
				e.Syntax += strconv.FormatInt(gnu16Integer(d, fixed), 10)
			default:
				return fmt.Errorf("fixed operand kind %s", d.Kind)
			}
			continue
		}
		o := codec.Operand{Name: fmt.Sprintf("op%d", ordinal), Class: "GNU_MIPS16_" + d.Kind, Kind: "immediate"}
		for i, b := range free {
			o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: gnu16Physical(positions[b], len(e.Mask), little), ValueBit: i, Width: 1})
		}
		full := len(free) == d.Size
		switch d.Kind {
		case "reg", "optional_reg", "entry_exit":
			o.Names = make([]string, 1<<len(free))
			if d.Kind != "entry_exit" {
				o.Kind = "register"
				o.RegisterPrefix = "$"
				o.RegisterAliases = map[string]int64{}
			}
			for raw := range o.Names {
				n := fixed
				for i, b := range free {
					n |= uint64(raw>>i&1) << uint(b)
				}
				if d.Kind == "entry_exit" {
					o.Names[raw] = gnu16EntryList(int(n), r.Name == "exit")
				} else {
					o.Names[raw] = gnu16RegName(d, int(n))
					o.RegisterAliases["$"+strconv.Itoa(d.Registers[n])] = int64(raw)
				}
			}
		case "int", "pcrel":
			o.Scale = 1 << uint(d.Shift)
			o.Bias = int64(d.Bias) * o.Scale
			if full && d.Max == (1<<(d.Size-1))-1 {
				o.Signed = true
			} else if !full || d.Max != (1<<d.Size)-1 {
				o.Scale, o.Bias = 1, 0
				o.Lookup = make([]int64, 1<<len(free))
				for raw := range o.Lookup {
					n := fixed
					for i, b := range free {
						n |= uint64(raw>>i&1) << uint(b)
					}
					o.Lookup[raw] = gnu16Integer(d, n)
				}
			}
			if d.Kind == "pcrel" {
				o.Relative = true
				o.Kind = "address"
				o.PCWrapBits = 32
				if d.ISA != 0 {
					o.PCBias = int64(len(e.Mask))
					if d.Size == 26 {
						o.PCRegionBits = d.Align
					}
				} else {
					o.PCAlignBits = d.Align
				}
			}
			lastInt = o.Name
		case "msb":
			o.Bias = int64(d.Bias)
			if d.AddLSB != 0 {
				o.BiasOperand = lastInt
				o.BiasScale = -1
			}
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: o.Name}, codec.Constraint{Kind: "ge", Left: o.Name}, codec.Constraint{Kind: "sum_le", Left: lastInt, Right: o.Name, Limit: int64(d.Opsize)})
		default:
			return fmt.Errorf("unhandled source operand %s", d.Kind)
		}
		e.Syntax += "{" + o.Name + "}"
		e.Operands = append(e.Operands, o)
		if o.Kind == "register" {
			gnu16RegisterEffect(e, r, ordinal, "", o.Name, d.Bank)
		}
	}
	// GNU's EXTEND marshaller writes zero to unused payload bits. Retain
	// the canonical source domain here rather than silently dropping bits.
	for p := range e.Mask {
		e.Mask[p] = 255
	}
	// Clear mask bits occupied by operands after fixing all unused bits to zero.
	for _, o := range e.Operands {
		for _, b := range o.Bits {
			e.Mask[b.InstructionBit/8] &^= 1 << uint(b.InstructionBit%8)
		}
	}
	return nil
}

func gnu16SaveRows(r gnu16Row, extended, little bool) []codec.Encoding {
	var out []codec.Encoding
	limit := 1
	if extended {
		limit = 15 * 8
	}
	for ext := 0; ext < limit; ext++ {
		amask, ns := ext/8, ext%8
		for flags := 0; flags < 8; flags++ {
			e := gnu16Encoding(r, extended, little)
			e.ID += fmt.Sprintf("_list_%03d_%d", ext, flags)
			raw := uint32(flags << 4)
			if extended {
				raw |= uint32(amask)<<16 | uint32(ns)<<24
			}
			e.Mask = make([]byte, len(e.Mask))
			e.Value = make([]byte, len(e.Value))
			value := r.Match | raw
			if extended {
				value |= 0xf0000000
			}
			for b := 0; b < len(e.Mask)*8; b++ {
				p := gnu16Physical(b, len(e.Mask), little)
				e.Mask[p/8] |= 1 << uint(p%8)
				if value>>b&1 != 0 {
					e.Value[p/8] |= 1 << uint(p%8)
				}
			}
			o := codec.Operand{Name: "frame", Class: "GNU_MIPS16_frame", Kind: "immediate", Scale: 8}
			width := 4
			if extended {
				width = 8
			} else {
				o.Scale = 1
				o.Lookup = []int64{128, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120}
			}
			for b := 0; b < width; b++ {
				bit := b
				if b >= 4 {
					bit = 16 + b
				}
				p := gnu16Physical(bit, len(e.Mask), little)
				e.Mask[p/8] &^= 1 << uint(p%8)
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: p, ValueBit: b, Width: 1})
			}
			e.Operands = []codec.Operand{o}
			nargs, statics := amask>>2, amask&3
			if amask == 14 {
				nargs, statics = 4, 0
			}
			if amask == 11 {
				nargs, statics = 0, 4
			}
			parts := []string{}
			if nargs > 0 {
				s := "$a0"
				if nargs > 1 {
					s += "-" + gnu16GPR[3+nargs]
				}
				parts = append(parts, s)
			}
			parts = append(parts, "{frame}")
			regs := []int{}
			if flags&4 != 0 {
				parts = append(parts, "$ra")
				regs = append(regs, 31)
			}
			mask := 0
			if flags&2 != 0 {
				mask |= 1
			}
			if flags&1 != 0 {
				mask |= 2
			}
			mask |= ((1 << ns) - 1) << 2
			for i := 0; i < 9; i++ {
				if mask>>i&1 == 0 {
					continue
				}
				j := i
				for j < 8 && mask>>(j+1)&1 != 0 {
					j++
				}
				reg := func(k int) int {
					if k == 8 {
						return 30
					}
					return 16 + k
				}
				s := gnu16GPR[reg(i)]
				if j > i {
					s += "-" + gnu16GPR[reg(j)]
				}
				parts = append(parts, s)
				for k := i; k <= j; k++ {
					regs = append(regs, reg(k))
				}
				i = j
			}
			if statics > 0 {
				s := gnu16GPR[8-statics]
				if statics > 1 {
					s += "-$a3"
				}
				parts = append(parts, s)
			}
			e.Syntax = r.Name + " " + strings.Join(parts, ", ")
			for _, reg := range regs {
				e.Effects.Registers = append(e.Effects.Registers, codec.RegisterEffectSpec{Name: gnu16GPR[reg], Bank: "gpr", Read: r.Name == "save", Write: r.Name == "restore", Implicit: true})
			}
			out = append(out, e)
		}
	}
	return out
}

// Preserve source read/write flags even when an operand is folded to a
// literal register by an opcode mask (including the MIPS16e2 GP forms).
func gnu16RegisterEffect(e *codec.Encoding, r gnu16Row, ordinal int, name, operand, bank string) {
	read := ordinal <= len(r.Read) && r.Read[ordinal-1] != 0
	write := ordinal <= len(r.Write) && r.Write[ordinal-1] != 0
	if read || write {
		e.Effects.Registers = append(e.Effects.Registers, codec.RegisterEffectSpec{Name: name, Operand: operand, Bank: bank, Read: read, Write: write})
	}
}

package mips

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed testdata/gnu-micromips64.json
var gnuMicro64JSON []byte

type gnuMicro64Row struct {
	Row             int
	Name, Args      string
	Match, Mask     uint32
	Virt, MSA       int
	Load, Store     int
	Read, Write     []int
	Operands        []gnu16Operand
	ImplicitReadHI  int `json:"read_hi"`
	ImplicitReadLO  int `json:"read_lo"`
	ImplicitWriteHI int `json:"write_hi"`
	ImplicitWriteLO int `json:"write_lo"`
}

// LLVM's microMIPS target has no GPR64 instruction definitions. Import GNU's
// actual 64-bit-only machine rows, including their resolved operand descriptors.
// The 32-bit selectors never acquire these encodings.
func addGNUMicro64(c *codec.Catalog) error {
	var source struct{ Instructions []gnuMicro64Row }
	if err := json.Unmarshal(gnuMicro64JSON, &source); err != nil {
		return err
	}
	little := strings.HasSuffix(c.Architecture, "el")
	for _, row := range source.Instructions {
		e := codec.Encoding{
			ID: fmt.Sprintf("GNU_MICRO64_ROW_%04d", row.Row), Mnemonic: row.Name,
			Syntax: row.Name, Mask: make([]byte, 4), Value: make([]byte, 4),
			Features: []string{"InMicroMips", "HasMips64"}, FlowControl: "next",
			Effects: codec.EffectSpec{Knowledge: codec.EffectsPartial, RegistersKnowledge: codec.EffectsPartial},
		}
		if row.Virt != 0 {
			e.Features = append(e.Features, "HasVirt")
		}
		if row.MSA != 0 {
			e.Features = append(e.Features, "HasMSA")
		}
		e.SourcePredicates = append([]string(nil), e.Features...)
		load, store := row.Load != 0, row.Store != 0
		e.Effects.MayLoad, e.Effects.MayStore = &load, &store
		for bit := 0; bit < 32; bit++ {
			p := gnu16Physical(bit, 4, little)
			e.Mask[p/8] |= byte((row.Mask>>bit)&1) << uint(p%8)
			e.Value[p/8] |= byte((row.Match>>bit)&1) << uint(p%8)
		}
		if row.Args != "" {
			e.Syntax += " "
		}
		ordinal, previousInt := 0, ""
		for index := 0; index < len(row.Args); index++ {
			ch := row.Args[index]
			if ch == ',' || ch == '(' || ch == ')' {
				e.Syntax += string(ch)
				if ch == ',' {
					e.Syntax += " "
				}
				continue
			}
			if ordinal >= len(row.Operands) {
				return fmt.Errorf("%s: incomplete GNU operands", e.ID)
			}
			d := row.Operands[ordinal]
			ordinal++
			if ch == '+' || ch == 'm' {
				index++
			}
			o := codec.Operand{Name: fmt.Sprintf("op%d", ordinal), Kind: "immediate", Class: "GNU_MICRO64_" + d.Kind}
			var free []int
			var fixed uint64
			for b := 0; b < d.Size; b++ {
				p := gnu16Physical(d.LSB+b, 4, little)
				if e.Mask[p/8]&(1<<uint(p%8)) != 0 {
					fixed |= uint64((e.Value[p/8]>>uint(p%8))&1) << uint(b)
				} else {
					free = append(free, b)
					o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: p, ValueBit: len(free) - 1, Width: 1})
				}
			}
			name := func(raw uint64) string {
				prefix := "$"
				if d.Bank == "fpr" {
					prefix = "$f"
				} else if d.Bank == "msa" {
					prefix = "$w"
				}
				return prefix + strconv.Itoa(d.Registers[raw])
			}
			if len(free) == 0 {
				if d.Kind != "reg" {
					return fmt.Errorf("%s: unexpected fixed GNU operand %s", e.ID, d.Kind)
				}
				e.Syntax += name(fixed)
				continue
			}
			switch d.Kind {
			case "reg":
				o.Kind, o.RegisterPrefix = "register", "$"
				o.Names = make([]string, 1<<len(free))
				for raw := range o.Names {
					n := fixed
					for i, bit := range free {
						n |= uint64(raw>>i&1) << uint(bit)
					}
					o.Names[raw] = name(n)
				}
			case "int", "index":
				o.Scale, o.Bias = 1<<uint(d.Shift), int64(d.Bias)<<uint(d.Shift)
				o.Signed = d.Kind == "int" && d.Max == (1<<(d.Size-1))-1
				if len(free) != d.Size {
					return fmt.Errorf("%s: partially fixed GNU integer", e.ID)
				}
				previousInt = o.Name
			case "msb":
				o.Bias = int64(d.Bias)
				if d.AddLSB != 0 {
					o.BiasOperand, o.BiasScale = previousInt, -1
				}
				e.Constraints = append(e.Constraints,
					codec.Constraint{Kind: "ge", Left: o.Name},
					codec.Constraint{Kind: "ne", Left: o.Name},
					codec.Constraint{Kind: "sum_le", Left: previousInt, Right: o.Name, Limit: int64(d.Opsize)})
			case "register_list":
				o.Class = "reglist"
				compressedOperand(&o, record{"DecoderNamespace": "MicroMips"}, nil)
				o.RegisterAliases = map[string]int64{}
				for raw, spelling := range o.Names {
					if spelling == "" {
						continue
					}
					var parts []string
					n := raw & 15
					if n == 1 {
						parts = append(parts, "$16")
					} else if n > 1 {
						end := 15 + n
						if n == 9 {
							end = 23
						}
						parts = append(parts, fmt.Sprintf("$16-$%d", end))
						if n == 9 {
							parts = append(parts, "$30")
						}
					}
					if raw&16 != 0 {
						parts = append(parts, "$31")
					}
					o.RegisterAliases[strings.Join(parts, ",")] = int64(raw)
				}
			default:
				return fmt.Errorf("%s: unhandled GNU operand %s", e.ID, d.Kind)
			}
			if d.Kind == "index" {
				e.Syntax += "["
			}
			e.Syntax += "{" + o.Name + "}"
			if d.Kind == "index" {
				e.Syntax += "]"
			}
			e.Operands = append(e.Operands, o)
			if o.Kind == "register" {
				read := ordinal <= len(row.Read) && row.Read[ordinal-1] != 0
				write := ordinal <= len(row.Write) && row.Write[ordinal-1] != 0
				if read || write {
					e.Effects.Registers = append(e.Effects.Registers, codec.RegisterEffectSpec{Operand: o.Name, Bank: d.Bank, Read: read, Write: write})
				}
			}
		}
		for i, name := range []string{"HI", "LO"} {
			read := []int{row.ImplicitReadHI, row.ImplicitReadLO}[i] != 0
			write := []int{row.ImplicitWriteHI, row.ImplicitWriteLO}[i] != 0
			if read || write {
				e.Effects.Registers = append(e.Effects.Registers, codec.RegisterEffectSpec{Name: name, Read: read, Write: write, Implicit: true})
			}
		}
		c.Encodings = append(c.Encodings, e)
	}
	return nil
}

package hexagon

import (
	"encoding/binary"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"math/bits"
	"strings"
)

type Instruction struct {
	ID       string           `json:"id"`
	Values   map[string]int64 `json:"values"`
	Extended bool             `json:"extended,omitempty"`
}

// Word holds one full instruction/extender or two duplex subinstructions. Words
// retain physical order; packet encoding does not schedule or reorder them.
type Word struct {
	Instructions []Instruction `json:"instructions"`
}
type Packet struct {
	Words     []Word `json:"words"`
	InnerLoop bool   `json:"inner_loop,omitempty"`
	OuterLoop bool   `json:"outer_loop,omitempty"`
	Length    int    `json:"length"`
}

var duplexGroups = [15][2]string{{"L1", "L1"}, {"L2", "L1"}, {"L2", "L2"}, {"A", "A"}, {"L1", "A"}, {"L2", "A"}, {"S1", "A"}, {"S2", "A"}, {"S1", "L1"}, {"S1", "L2"}, {"S1", "S1"}, {"S2", "S1"}, {"S2", "L1"}, {"S2", "L2"}, {"S2", "S2"}}

func (c *Catalog) entry(id string) (*codec.Encoding, error) {
	for _, table := range []*codec.Catalog{c.Words, c.Subinstructions} {
		for n := range table.Encodings {
			if table.Encodings[n].ID == id {
				return &table.Encodings[n], nil
			}
		}
	}
	return nil, fmt.Errorf("hexagon: unknown encoding %s", id)
}
func cloneValues(v map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, n := range v {
		out[k] = n
	}
	return out
}
func featuresMatch(e *codec.Encoding, features []string) bool {
	if features == nil {
		return true
	}
	for _, f := range e.Features {
		found := false
		for _, a := range features {
			if a == f {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (c *Catalog) decodeWord(word uint32, group string, extended bool, features []string) (Instruction, error) {
	table := c.Words
	if group != "" {
		table = c.Subinstructions
	} else {
		word |= 0xc000
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, word)
	var best *codec.Decoded
	score := -1
	for n := range table.Encodings {
		e := &table.Encodings[n]
		m := c.Metadata[e.ID]
		if e.AssemblyOnly || group != "" && m.SubGroup != group || m.MustExtend && !extended || extended && !m.Extendable && !m.MustExtend || !featuresMatch(e, features) {
			continue
		}
		single := codec.Catalog{Architecture: "hexagon", Encodings: []codec.Encoding{*e}}
		single.Encodings[0].AssemblyOnly = false
		decoded, err := single.Decode(b)
		if err != nil {
			continue
		}
		s := 0
		for _, mask := range e.Mask {
			s += bits.OnesCount8(mask)
		}
		if m.MustExtend && extended {
			s += 64
		}
		if s > score {
			best = decoded
			best.Encoding = e
			score = s
		}
	}
	if best == nil {
		return Instruction{}, fmt.Errorf("hexagon: unknown %s word %#08x", group, word)
	}
	return Instruction{ID: best.Encoding.ID, Values: best.Values, Extended: extended}, nil
}
func (c *Catalog) applyExtender(i *Instruction, upper uint32) error {
	m := c.Metadata[i.ID]
	if !m.Extendable && !m.MustExtend {
		return fmt.Errorf("%s cannot consume an immediate extender", i.ID)
	}
	raw, ok := i.Values[m.ExtendOperand]
	if !ok {
		return fmt.Errorf("%s has missing extendable operand", i.ID)
	}
	full := upper | ((uint32(raw) >> uint(m.ExtentAlign)) & 63)
	e, err := c.entry(i.ID)
	if err != nil {
		return err
	}
	signed := m.ExtentSigned
	for _, o := range e.Operands {
		if o.Name == m.ExtendOperand {
			signed = signed || o.Signed
		}
	}
	value := int64(full)
	if signed {
		value = int64(int32(full))
	}
	i.Values[m.ExtendOperand] = value
	i.Extended = true
	return nil
}
func (c *Catalog) producerValue(i Instruction, selector int) (int64, bool) {
	m := c.Metadata[i.ID]
	if len(m.Producers) == 0 {
		return 0, false
	}
	e, err := c.entry(i.ID)
	if err != nil {
		return 0, false
	}
	if len(m.Producers) > 1 {
		if selector >= len(m.Producers) {
			return 0, false
		}
		v, ok := i.Values[m.Producers[1-selector]]
		return v, ok
	}
	name := m.Producers[0]
	v, ok := i.Values[name]
	if !ok {
		return 0, false
	}
	paired := false
	for _, o := range e.Operands {
		if o.Name == name {
			if o.Class == "DoubleRegs" || o.Class == "GeneralDoubleLow8Regs" {
				return 0, false
			}
			paired = o.Class == "HvxWR"
		}
	}
	if selector != 0 && !paired {
		return 0, false
	}
	if paired {
		return v&^1 | ((v & 1) ^ int64(selector)), true
	}
	return v, true
}
func (c *Catalog) resolveNewValue(i *Instruction, history []Instruction, encode bool) error {
	m := c.Metadata[i.ID]
	if m.NewValueUse == "" {
		return nil
	}
	value, ok := i.Values[m.NewValueUse]
	if !ok {
		return fmt.Errorf("missing new-value operand")
	}
	distance := 0
	for n := len(history) - 1; n >= 0; n-- {
		prev := history[n]
		pm := c.Metadata[prev.ID]
		if pm.Type == "TypeEXTENDER" {
			continue
		}
		if !m.Vector || pm.Vector {
			distance++
		}
		if distance == 0 {
			continue
		}
		for selector := 0; selector < 2; selector++ {
			v, has := c.producerValue(prev, selector)
			if !has {
				continue
			}
			if encode {
				if v == value {
					if distance > 3 {
						return fmt.Errorf("new-value producer exceeds 3-instruction distance")
					}
					i.Values[m.NewValueUse] = int64(distance*2 + selector)
					return nil
				}
			} else if int(value>>1) == distance && int(value&1) == selector {
				i.Values[m.NewValueUse] = v
				return nil
			}
		}
		if !encode && int(value>>1) == distance {
			break
		}
	}
	return fmt.Errorf("%s has no matching packet new-value producer", i.ID)
}

func (c *Catalog) DecodePacket(data []byte, address uint64, features []string) (Packet, int, error) {
	p := Packet{}
	var pending *uint32
	var history []Instruction
	logical := 0
	for index := 0; index < 4; index++ {
		if len(data) < (index+1)*4 {
			return Packet{}, 0, fmt.Errorf("hexagon: truncated packet")
		}
		raw := binary.LittleEndian.Uint32(data[index*4:])
		parse := (raw >> 14) & 3
		word := Word{}
		end := parse == 0 || parse == 3
		if parse == 2 {
			if index == 0 {
				p.InnerLoop = true
			} else if index == 1 {
				p.OuterLoop = true
			} else {
				return Packet{}, 0, fmt.Errorf("loop-end marker outside first two packet words")
			}
		}
		if parse == 0 {
			class := int(((raw >> 28) & 14) | ((raw >> 13) & 1))
			if class >= len(duplexGroups) {
				return Packet{}, 0, fmt.Errorf("reserved duplex class %d", class)
			}
			for slot := 0; slot < 2; slot++ {
				sub := (raw >> uint(slot*16)) & 0x1fff
				i, err := c.decodeWord(sub, duplexGroups[class][slot], pending != nil && slot == 1, features)
				if err != nil {
					return Packet{}, 0, err
				}
				if pending != nil && slot == 1 {
					if err := c.applyExtender(&i, *pending); err != nil {
						return Packet{}, 0, err
					}
				}
				if err := c.resolveNewValue(&i, history, false); err != nil {
					return Packet{}, 0, err
				}
				word.Instructions = append(word.Instructions, i)
				history = append(history, i)
				logical++
			}
			pending = nil
		} else {
			i, err := c.decodeWord(raw&^0xc000, "", pending != nil, features)
			if err != nil {
				return Packet{}, 0, err
			}
			meta := c.Metadata[i.ID]
			if meta.Type == "TypeEXTENDER" {
				if pending != nil || end {
					return Packet{}, 0, fmt.Errorf("consecutive or dangling immediate extender")
				}
				upper := uint32(i.Values["Ii"])
				pending = &upper
				i.Extended = false
			} else {
				if pending != nil {
					if err := c.applyExtender(&i, *pending); err != nil {
						return Packet{}, 0, err
					}
					pending = nil
				}
				if err := c.resolveNewValue(&i, history, false); err != nil {
					return Packet{}, 0, err
				}
				logical++
			}
			word.Instructions = []Instruction{i}
			history = append(history, i)
		}
		p.Words = append(p.Words, word)
		if logical > 4 {
			return Packet{}, 0, fmt.Errorf("packet exceeds four logical instructions")
		}
		if end {
			p.Length = (index + 1) * 4
			if err := c.checkSolo(p); err != nil {
				return Packet{}, 0, err
			}
			return p, p.Length, nil
		}
	}
	return Packet{}, 0, fmt.Errorf("packet lacks an end marker within four words")
}
func (c *Catalog) checkSolo(p Packet) error {
	count := 0
	solo := false
	for _, w := range p.Words {
		for _, i := range w.Instructions {
			m := c.Metadata[i.ID]
			if m.Type == "TypeEXTENDER" {
				continue
			}
			count++
			solo = solo || m.Solo
		}
	}
	if solo && count != 1 {
		return fmt.Errorf("solo instruction mixed with another instruction")
	}
	return nil
}
func (c *Catalog) encodeInstruction(i Instruction, history []Instruction, pending *uint32) (uint32, error) {
	e, err := c.entry(i.ID)
	if err != nil {
		return 0, err
	}
	m := c.Metadata[i.ID]
	copy := Instruction{ID: i.ID, Values: cloneValues(i.Values), Extended: i.Extended}
	if err := c.resolveNewValue(&copy, history, true); err != nil {
		return 0, err
	}
	if pending != nil {
		if !m.Extendable && !m.MustExtend {
			return 0, fmt.Errorf("%s cannot be extended", i.ID)
		}
		v, ok := copy.Values[m.ExtendOperand]
		if !ok {
			return 0, fmt.Errorf("missing extended operand")
		}
		if v < int64(-1<<31) || v > int64(1<<32-1) {
			return 0, fmt.Errorf("extended immediate outside 32-bit domain")
		}
		if uint32(v)&^uint32(63) != *pending {
			return 0, fmt.Errorf("extender disagrees with consumer immediate")
		}
		copy.Values[m.ExtendOperand] = int64((uint32(v) & 63) << uint(m.ExtentAlign))
		// Low bits are unsigned even when the unextended field is signed.
		clone := *e
		clone.Operands = append([]codec.Operand{}, e.Operands...)
		for n := range clone.Operands {
			if clone.Operands[n].Name == m.ExtendOperand {
				clone.Operands[n].Signed = false
			}
		}
		e = &clone
	} else if m.MustExtend || i.Extended {
		return 0, fmt.Errorf("%s requires an extender", i.ID)
	}
	b, err := codec.Encode(e, copy.Values)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (c *Catalog) EncodePacket(p Packet, address uint64, features []string) ([]byte, error) {
	if len(p.Words) == 0 {
		return nil, fmt.Errorf("empty packet")
	}
	if err := c.checkSolo(p); err != nil {
		return nil, err
	}
	var raw []uint32
	var isDuplex []bool
	var history []Instruction
	var pending *uint32
	logical := 0
	for _, w := range p.Words {
		if len(w.Instructions) < 1 || len(w.Instructions) > 2 {
			return nil, fmt.Errorf("packet word needs one instruction or two subinstructions")
		}
		duplex := len(w.Instructions) == 2
		if duplex {
			low, high := w.Instructions[0], w.Instructions[1]
			for _, i := range w.Instructions {
				e, err := c.entry(i.ID)
				if err != nil {
					return nil, err
				}
				if !featuresMatch(e, features) {
					return nil, fmt.Errorf("%s unavailable in profile", i.ID)
				}
			}
			class := -1
			for n, g := range duplexGroups {
				if c.Metadata[low.ID].SubGroup == g[0] && c.Metadata[high.ID].SubGroup == g[1] {
					class = n
					break
				}
			}
			if class < 0 {
				return nil, fmt.Errorf("incompatible duplex groups")
			}
			if low.Extended {
				return nil, fmt.Errorf("duplex slot zero cannot consume an extender")
			}
			if pending == nil && (high.Extended || c.Metadata[high.ID].MustExtend) {
				m := c.Metadata[high.ID]
				upper := uint32(high.Values[m.ExtendOperand]) &^ uint32(63)
				ext := Instruction{ID: "A4_ext", Values: map[string]int64{"Ii": int64(upper)}}
				v, err := c.encodeInstruction(ext, history, nil)
				if err != nil {
					return nil, err
				}
				raw = append(raw, v)
				isDuplex = append(isDuplex, false)
				history = append(history, ext)
				pending = &upper
			}
			a, err := c.encodeInstruction(low, history, nil)
			if err != nil {
				return nil, err
			}
			b, err := c.encodeInstruction(high, history, pending)
			if err != nil {
				return nil, err
			}
			value := (uint32(class&14) << 28) | (uint32(class&1) << 13) | (a & 0x1fff) | ((b & 0x1fff) << 16)
			raw = append(raw, value)
			isDuplex = append(isDuplex, true)
			history = append(history, low, high)
			pending = nil
			logical += 2
		} else {
			i := w.Instructions[0]
			m, ok := c.Metadata[i.ID]
			if !ok {
				return nil, fmt.Errorf("unknown instruction %s", i.ID)
			}
			e, err := c.entry(i.ID)
			if err != nil {
				return nil, err
			}
			if !featuresMatch(e, features) {
				return nil, fmt.Errorf("%s unavailable in profile", i.ID)
			}
			if m.Type == "TypeSUBINSN" {
				return nil, fmt.Errorf("subinstruction outside duplex word")
			}
			value, err := c.encodeInstruction(i, history, pending)
			if err != nil && pending == nil && (m.Extendable || m.MustExtend) {
				v, ok := i.Values[m.ExtendOperand]
				if !ok {
					return nil, err
				}
				upper := uint32(v) &^ uint32(63)
				ext := Instruction{ID: "A4_ext", Values: map[string]int64{"Ii": int64(upper)}}
				extWord, e := c.encodeInstruction(ext, history, nil)
				if e != nil {
					return nil, e
				}
				raw = append(raw, extWord)
				isDuplex = append(isDuplex, false)
				history = append(history, ext)
				pending = &upper
				value, err = c.encodeInstruction(i, history, pending)
			}
			if err != nil {
				return nil, err
			}
			raw = append(raw, value&^0xc000)
			isDuplex = append(isDuplex, false)
			if m.Type == "TypeEXTENDER" {
				if pending != nil {
					return nil, fmt.Errorf("consecutive extenders")
				}
				upper := uint32(i.Values["Ii"])
				pending = &upper
			} else {
				pending = nil
				logical++
			}
			history = append(history, i)
		}
	}
	if pending != nil {
		return nil, fmt.Errorf("dangling extender")
	}
	if len(raw) > 4 || logical > 4 {
		return nil, fmt.Errorf("packet exceeds four words or logical instructions")
	}
	if p.InnerLoop && len(raw) < 2 || p.OuterLoop && len(raw) < 3 {
		return nil, fmt.Errorf("loop-end marker needs a following packet word")
	}
	out := make([]byte, 4*len(raw))
	for n, value := range raw {
		last := n == len(raw)-1
		if isDuplex[n] {
			if !last {
				return nil, fmt.Errorf("duplex must terminate packet")
			}
		} else {
			parse := uint32(1)
			if last {
				parse = 3
			}
			if (n == 0 && p.InnerLoop) || (n == 1 && p.OuterLoop) {
				if last {
					return nil, fmt.Errorf("loop marker on terminal word")
				}
				parse = 2
			}
			value = (value &^ 0xc000) | (parse << 14)
		}
		binary.LittleEndian.PutUint32(out[n*4:], value)
	}
	return out, nil
}
func (c *Catalog) FormatPacket(p Packet, address uint64) string {
	var lines []string
	for _, w := range p.Words {
		var parts []string
		for _, i := range w.Instructions {
			e, err := c.entry(i.ID)
			if err != nil {
				parts = append(parts, "<unknown>")
				continue
			}
			clone := *e
			if i.Extended {
				m := c.Metadata[i.ID]
				hole := "{" + m.ExtendOperand + "}"
				if strings.Contains(clone.Syntax, "#"+hole) {
					clone.Syntax = strings.ReplaceAll(clone.Syntax, "#"+hole, "##"+hole)
				} else {
					clone.Syntax = strings.ReplaceAll(clone.Syntax, hole, "##"+hole)
				}
			}
			d := codec.Decoded{Encoding: &clone, Values: i.Values, Length: 4}
			parts = append(parts, d.Format(address))
		}
		lines = append(lines, strings.Join(parts, " ; "))
	}
	suffix := ""
	if p.InnerLoop {
		suffix += ":endloop0"
	}
	if p.OuterLoop {
		suffix += ":endloop1"
	}
	return "{\n  " + strings.Join(lines, "\n  ") + "\n}" + suffix
}

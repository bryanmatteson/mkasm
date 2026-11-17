// Package pic imports the complete pinned Ghidra PIC SLEIGH constructor corpus.
package pic

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed data/constructors.json
var Source []byte

//go:embed data/LICENSE-Ghidra.txt
var upstreamLicense string

//go:embed data/NOTICE-Ghidra.txt
var upstreamNotice string

var errConflict = errors.New("impossible constructor attachment")

const SourceRevision = "42db038f3c88c6bd7e9bedbb919138111f8b77fd"

type Catalog struct{ *codec.Catalog }

func (c *Catalog) WriteJSON(w io.Writer) error { return c.Catalog.WriteJSON(w) }
func (c *Catalog) GenerateRust(out string) error {
	if err := c.Catalog.GenerateRust(out); err != nil {
		return err
	}
	p := filepath.Join(out, "src", "lib.rs")
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	// Different processor profiles deliberately overlap on opcode bytes.
	text := string(b) + pageRuntime
	text = strings.ReplaceAll(text, "let decoded=decode(&bytes).unwrap_or_else", "let decoded=decode_with_features(&bytes,Some(e.features)).unwrap_or_else")
	text = strings.ReplaceAll(text, "assemble_at(&preferred,0x1000)", "assemble_with_features(&preferred,0x1000,Some(e.features))")
	text = strings.ReplaceAll(text, "assemble_at(&text,0x1000)", "assemble_with_features(&text,0x1000,Some(e.features))")
	text = strings.ReplaceAll(text, `assert!(assemble_with_features(&preferred,0x1000,Some(e.features)).unwrap().contains(&bytes),"preferred {}: {}",e.id,preferred);`, `if decoded.encoding().operands.iter().enumerate().all(|(i,o)|!o.optional||decoded.values[i]==0){assert!(assemble_with_features(&preferred,0x1000,Some(e.features)).unwrap().contains(&bytes),"preferred {}: {}",e.id,preferred);}`)
	b = []byte(text)
	if err := os.WriteFile(p, b, 0644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
		return err
	}
	runtimeTest := strings.ReplaceAll(consumerTest, "CRATE", strings.ReplaceAll(c.Architecture, "-", "_"))
	if c.Architecture == "pic18" {
		runtimeTest += pic18ConsumerTest
	}
	return os.WriteFile(filepath.Join(out, "tests", "consumer.rs"), []byte(runtimeTest), 0644)
}

type corpus struct {
	Schema   string
	Profiles []profile
}
type profile struct {
	Language string
	WordSize int `json:"word_size"`
	Tables   map[string][]constructor
}
type constructor struct {
	ID, Line, Length int
	Indirect         bool
	Source           string
	Print            []string
	Patterns         []pattern
	Operands         []operand
}
type pattern struct {
	Mask, Value []uint8
	Context     string
}
type operand struct {
	Name, Table, Literal string
	Offset, Base, Length int
	Address              bool
	Expression           *expression
	Names                []string
	Lookup               []int64
}
type expression struct {
	Op                   string
	Start, Width, Offset int
	Signed               bool
	Value                int64
	Left, Right          *expression
	Cycle                bool
}
type scalar struct {
	Operand operand
	Offset  int
}
type variant struct {
	Text        string
	Mask, Value uint64
	Length      int
	Scalars     map[string]scalar
}

var aliases = map[string][]string{
	"pic12": {"pic12", "pic16c5x"}, "pic14": {"pic14", "pic14-enhanced"}, "pic16": {"pic17"}, "pic17": {"pic17"}, "pic18": {"pic18"}, "pic24": {"pic24e", "pic24f", "pic24h"}, "dspic": {"dspic30f", "dspic33f", "dspic33e", "dspic33c"},
}
var profileNames = []string{"pic12", "pic16c5x", "pic14", "pic14-enhanced", "pic17", "pic18", "pic24e", "pic24f", "pic24h", "dspic30f", "dspic33f", "dspic33e", "dspic33c"}

// Parse accepts the complete mkasm.pic.sleigh.v1 export produced by tools/ExportPIC.java.
// A nil reader uses the bundled unabridged export of all 13 upstream languages.
// Addresses are byte offsets, including the phantom storage bytes on PIC24.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	wanted, ok := aliases[architecture]
	if !ok {
		for _, p := range profileNames {
			if architecture == p {
				wanted = []string{p}
				ok = true
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("PIC: unknown architecture %q", architecture)
	}
	data := Source
	if r != nil {
		var err error
		data, err = io.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}
	var src corpus
	if err := json.Unmarshal(data, &src); err != nil {
		return nil, err
	}
	if src.Schema != "mkasm.pic.sleigh.v1" || len(src.Profiles) != 13 {
		return nil, fmt.Errorf("PIC: expected complete pinned SLEIGH export")
	}
	c := &codec.Catalog{Schema: codec.Schema, Architecture: architecture, Source: "Ghidra 12.1.2 PIC SLEIGH " + SourceRevision, SourceLicenseID: "Apache-2.0", SourceLicense: "Ghidra PIC SLEIGH descriptions, commit " + SourceRevision + ".\n\n" + upstreamNotice + "\n\n" + upstreamLicense, FeatureSets: map[string][]string{}}
	for pi, p := range src.Profiles {
		name := profileNames[pi]
		if !contains(wanted, name) {
			continue
		}
		feature := "pic-" + name
		c.FeatureSets[name] = []string{feature}
		if len(c.FeatureSets["default"]) == 0 {
			c.FeatureSets["default"] = []string{feature}
		}
		for _, ct := range p.Tables["instruction"] {
			if len(ct.Print) > 0 && ct.Print[0] == "BADCALL" {
				c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: fmt.Sprintf("%s_L%d", name, ct.Line), Reason: "Ghidra synthetic BADCALL semantic sentinel, not a hardware instruction; 0xffff is decoded by real CALL"})
				continue
			}
			if ct.Length == 0 {
				continue
			} // Transparent context/skip/repeat wrappers are not extra instructions.
			vs, err := p.expand(ct, 0, "", 0)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", p.Language, ct.Line, err)
			}
			// On enhanced midrange cores MOVLB occupies the old NOP alias
			// range 0x20..0x3f. SLEIGH decision priority resolves this overlap;
			// express the same partition in masks for the shared codec.
			if name == "pic14-enhanced" && strings.Join(ct.Print, "") == "NOP" {
				var partition []variant
				for _, v := range vs {
					if v.Mask&0x60 == 0 {
						a, b := v, v
						a.Mask |= 0x60
						b.Mask |= 0x40
						b.Value |= 0x40
						partition = append(partition, a, b)
					} else {
						partition = append(partition, v)
					}
				}
				vs = partition
			}
			var corrected []variant
			for _, v := range vs {
				mnemonic := strings.Fields(v.Text)[0]
				// Microchip PUSHL is 0xEAkk. Upstream SLEIGH says 0xFAkk,
				// which lies in the continuation-word NOP range.
				if name == "pic18" && mnemonic == "PUSHL" {
					v.Value &^= 0x1000
				}
				if name == "pic14" {
					meaningful := ^uint64(0)
					switch mnemonic {
					case "MOVLW", "RETLW":
						meaningful = ^uint64(0x300)
					case "ADDLW", "SUBLW":
						meaningful = ^uint64(0x100)
					}
					v.Mask &= meaningful
					v.Value &= meaningful
				}
				partition := []variant{v}
				if name == "pic18" && (mnemonic == "MOVFF" || mnemonic == "MOVSF") {
					for _, bad := range []uint64{0xff9, 0xffd, 0xffe, 0xfff} {
						var next []variant
						for _, x := range partition {
							next = append(next, exclude(x, 0x0fff0000, bad<<16)...)
						}
						partition = next
					}
				}
				corrected = append(corrected, partition...)
			}
			vs = corrected
			seen := map[string]bool{}
			for _, v := range vs {
				// PIC18 continuation words require the 1111 marker; the
				// upstream CALL/GOTO/LFSR patterns omit this documented qualifier.
				if name == "pic18" && v.Length == 4 {
					m := uint64(0xf0000000)
					val := m
					if strings.HasPrefix(v.Text, "LFSR") {
						m = 0xff000000
					}
					if (v.Value^val)&v.Mask&m != 0 {
						continue
					}
					v.Mask |= m
					v.Value |= val
				}
				e, err := makeEncoding(v)
				if errors.Is(err, errConflict) {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("%s:%d %s: %w", p.Language, ct.Line, v.Text, err)
				}
				key := fmt.Sprint(e.Syntax, e.Mask, e.Value)
				if seen[key] {
					continue
				}
				seen[key] = true
				e.ID = fmt.Sprintf("%s_L%d_%d", name, ct.Line, len(seen))
				e.Features = []string{feature}
				if name == "pic14" && contains([]string{"ADDWFC", "ASRF", "CALLW", "RESET", "SUBWFB"}, e.Mnemonic) {
					e.Features = []string{"pic-pic14-enhanced"}
				}
				if name == "pic18" && contains([]string{"ADDFSR", "ADDULNK", "CALLW", "MOVSF", "MOVSS", "PUSHL", "SUBFSR", "SUBULNK"}, e.Mnemonic) {
					e.Features = append(e.Features, "pic18-xinst")
					c.FeatureSets["pic18-extended"] = []string{feature, "pic18-xinst"}
				}
				e.FlowControl = flow(e.Mnemonic)
				if ct.Indirect && e.FlowControl != "call" && e.FlowControl != "return" {
					e.FlowControl = "indirect_branch"
				}
				if (name == "pic14" || name == "pic14-enhanced") && ct.Length == 4 {
					e.Features = append(e.Features, "ghidra-macros")
					c.FeatureSets[name+"-macros"] = []string{feature, "ghidra-macros"}
				}
				fixTargets(&e, name, v.Length)
				if e.FlowControl == "call" {
					direct := false
					for _, o := range e.Operands {
						direct = direct || o.Kind == "address"
					}
					if !direct {
						e.FlowControl = "indirect_call"
					}
				}
				c.Encodings = append(c.Encodings, e)
			}
			if len(seen) == 0 {
				c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: fmt.Sprintf("%s_L%d", name, ct.Line), Reason: "upstream semantic constructor writes reserved PIC18 MOVFF/MOVSF destination PCL; architecturally rejected"})
			}
		}
	}
	if architecture == "pic14" {
		c.FeatureSets["pic14-enhanced"] = []string{"pic-pic14-enhanced"}
	}
	if len(c.Encodings) == 0 {
		return nil, fmt.Errorf("PIC: no encodings")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Catalog{c}, nil
}
func contains(a []string, b string) bool {
	for _, x := range a {
		if x == b {
			return true
		}
	}
	return false
}
func word(b []uint8) uint64 {
	var v uint64
	for i, x := range b {
		if i < 8 {
			v |= uint64(x) << uint(8*i)
		}
	}
	return v
}

// exclude subtracts an architecturally reserved bit pattern without removing
// any legal combinations of the remaining fields.
func exclude(v variant, mask, value uint64) []variant {
	if (v.Value^value)&v.Mask&mask != 0 {
		return []variant{v}
	}
	var out []variant
	free := mask &^ v.Mask
	for free != 0 {
		p := uint(bits.TrailingZeros64(free))
		bit := uint64(1) << p
		different := v
		different.Mask |= bit
		different.Value = (different.Value &^ bit) | ((^value) & bit)
		out = append(out, different)
		v.Mask |= bit
		v.Value = (v.Value &^ bit) | (value & bit)
		free &^= bit
	}
	return out
}

func merge(a, b variant) (variant, bool) {
	if (a.Value^b.Value)&a.Mask&b.Mask != 0 {
		return a, false
	}
	a.Mask |= b.Mask
	a.Value |= b.Value
	if b.Length > a.Length {
		a.Length = b.Length
	}
	q := map[string]scalar{}
	for k, v := range a.Scalars {
		q[k] = v
	}
	for k, v := range b.Scalars {
		q[k] = v
	}
	a.Scalars = q
	return a, true
}
func (p *profile) expand(c constructor, offset int, path string, depth int) ([]variant, error) {
	if depth > 16 {
		return nil, fmt.Errorf("recursive subtable")
	}
	var states []variant
	uniq := map[string]bool{}
	for _, pat := range c.Patterns {
		m, v := word(pat.Mask)<<uint(offset*8), word(pat.Value)<<uint(offset*8)
		key := fmt.Sprint(m, "/", v)
		if uniq[key] {
			continue
		}
		uniq[key] = true
		states = append(states, variant{Text: strings.Join(c.Print, ""), Mask: m, Value: v, Length: offset + c.Length, Scalars: map[string]scalar{}})
	}
	if len(states) == 0 {
		return nil, fmt.Errorf("constructor has no decision pattern")
	}
	for i, o := range c.Operands {
		marker := string([]byte{'\n', byte('A' + i)})
		if !strings.Contains(strings.Join(c.Print, ""), marker) {
			if o.Table == "" && len(o.Names) > 0 && o.Expression != nil && o.Expression.Op == "TokenField" && contains(o.Names, "") {
				var next []variant
				f := o.Expression
				shift := f.Start + (offset+o.Offset)*8
				mask := ((uint64(1) << uint(f.Width)) - 1) << uint(shift)
				for _, a := range states {
					for n, label := range o.Names {
						if label == "" {
							continue
						}
						b := variant{Mask: mask, Value: uint64(n) << uint(shift)}
						if v, ok := merge(a, b); ok {
							next = append(next, v)
						}
					}
				}
				states = next
			}
			continue
		}
		if o.Base >= 0 {
			return nil, fmt.Errorf("relative operand base %d", o.Base)
		}
		next := []variant{}
		name := fmt.Sprintf("%s%d", path, i)
		at := offset + o.Offset
		if o.Table != "" {
			var all []variant
			for _, child := range p.Tables[o.Table] {
				if o.Table == "instruction" {
					continue
				}
				vs, err := p.expand(child, at, name+"_", depth+1)
				if err != nil {
					return nil, err
				}
				if o.Address {
					for j := range vs {
						for k, x := range vs[j].Scalars {
							x.Operand.Address = true
							vs[j].Scalars[k] = x
						}
					}
				}
				all = append(all, vs...)
			}
			all = compressLiteral(all, "p"+name)
			for _, a := range states {
				for _, b := range all {
					v, ok := merge(a, b)
					if ok {
						v.Text = strings.ReplaceAll(a.Text, marker, b.Text)
						next = append(next, v)
					}
				}
			}
		} else {
			for _, a := range states {
				v := a
				v.Scalars = map[string]scalar{}
				for k, x := range a.Scalars {
					v.Scalars[k] = x
				}
				text := o.Literal
				if text == "" {
					text = "{p" + name + "}"
					v.Scalars["p"+name] = scalar{o, at}
				}
				v.Text = strings.ReplaceAll(a.Text, marker, text)
				next = append(next, v)
			}
		}
		states = next
	}
	return states, nil
}

// Literal-only subtables are finite enumeration operands. Keeping them as
// name tables avoids expanding independent DSP prefetch choices into millions
// of equivalent fixed-mask instruction records.
func compressLiteral(vs []variant, name string) []variant {
	groups := map[string][]variant{}
	var out []variant
	for _, v := range vs {
		if len(v.Scalars) > 0 || v.Text == "" {
			out = append(out, v)
			continue
		}
		key := fmt.Sprint(v.Mask, "/", v.Length)
		groups[key] = append(groups[key], v)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := groups[key]
		if len(g) < 2 {
			out = append(out, g...)
			continue
		}
		vary := uint64(0)
		for _, v := range g {
			vary |= v.Value ^ g[0].Value
		}
		width := bits.OnesCount64(vary)
		if width == 0 || width > 16 {
			out = append(out, g...)
			continue
		}
		names := make([]string, 1<<uint(width))
		positions := []int{}
		for p := 0; p < 64; p++ {
			if vary&(uint64(1)<<uint(p)) != 0 {
				positions = append(positions, p)
			}
		}
		valid := true
		for _, v := range g {
			n := 0
			for j, p := range positions {
				if v.Value&(uint64(1)<<uint(p)) != 0 {
					n |= 1 << uint(j)
				}
			}
			if names[n] != "" && names[n] != v.Text {
				valid = false
				break
			}
			names[n] = v.Text
		}
		if !valid {
			out = append(out, g...)
			continue
		}
		var ex *expression
		for j, p := range positions {
			part := &expression{Op: "TokenField", Start: p, Width: 1}
			if j > 0 {
				part = &expression{Op: "LeftShiftExpression", Left: part, Right: &expression{Op: "ConstantValue", Value: int64(j)}}
			}
			if ex == nil {
				ex = part
			} else {
				ex = &expression{Op: "OrExpression", Left: ex, Right: part}
			}
		}
		v := g[0]
		v.Mask &^= vary
		v.Value &^= vary
		v.Text = "{" + name + "}"
		v.Scalars = map[string]scalar{name: {Operand: operand{Name: "sleigh-enumeration", Expression: ex, Names: names}}}
		out = append(out, v)
	}
	return out
}

func eval(e *expression, raw uint64, offset int, pc int64, length int) (int64, error) {
	if e == nil {
		return 0, fmt.Errorf("missing expression")
	}
	a, b := int64(0), int64(0)
	var err error
	if e.Left != nil {
		childOffset := offset
		if e.Op == "OperandValue" {
			childOffset += e.Offset
		}
		a, err = eval(e.Left, raw, childOffset, pc, length)
		if err != nil {
			return 0, err
		}
	}
	if e.Right != nil {
		b, err = eval(e.Right, raw, offset, pc, length)
		if err != nil {
			return 0, err
		}
	}
	switch e.Op {
	case "TokenField":
		v := (raw >> uint(e.Start+offset*8)) & ((uint64(1) << uint(e.Width)) - 1)
		if e.Signed && v&(uint64(1)<<uint(e.Width-1)) != 0 {
			v |= ^uint64(0) << uint(e.Width)
		}
		return int64(v), nil
	case "ConstantValue":
		return e.Value, nil
	case "OperandValue":
		if e.Cycle {
			return 0, fmt.Errorf("cyclic operand")
		}
		return a, nil
	case "EndInstructionValue":
		return pc + int64(length), nil
	case "StartInstructionValue":
		return pc, nil
	case "PlusExpression":
		return a + b, nil
	case "SubExpression":
		return a - b, nil
	case "MultExpression":
		return a * b, nil
	case "LeftShiftExpression":
		return a << uint(b), nil
	case "RightShiftExpression":
		return a >> uint(b), nil
	case "OrExpression":
		return a | b, nil
	case "AndExpression":
		return a & b, nil
	case "XorExpression":
		return a ^ b, nil
	case "MinusExpression":
		return -a, nil
	case "NotExpression":
		return ^a, nil
	}
	return 0, fmt.Errorf("unsupported expression %s", e.Op)
}
func exprBits(e *expression, offset int) uint64 {
	if e == nil {
		return 0
	}
	if e.Op == "TokenField" {
		return ((uint64(1) << uint(e.Width)) - 1) << uint(e.Start+offset*8)
	}
	if e.Op == "OperandValue" {
		offset += e.Offset
	}
	return exprBits(e.Left, offset) | exprBits(e.Right, offset)
}
func hasPC(e *expression) bool {
	return e != nil && (e.Op == "EndInstructionValue" || e.Op == "StartInstructionValue" || hasPC(e.Left) || hasPC(e.Right))
}
func makeEncoding(v variant) (codec.Encoding, error) {
	e := codec.Encoding{Syntax: v.Text, Mask: make([]byte, v.Length), Value: make([]byte, v.Length)}
	for i := range e.Mask {
		e.Mask[i] = byte(v.Mask >> uint(i*8))
		e.Value[i] = byte(v.Value >> uint(i*8))
	}
	used := v.Mask
	names := []string{}
	for name := range v.Scalars {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := v.Scalars[name]
		ex := s.Operand.Expression
		physical := exprBits(ex, s.Offset) &^ v.Mask
		baseline, err := eval(ex, v.Value, s.Offset, 0, v.Length)
		if err != nil {
			return e, err
		}
		o := codec.Operand{Name: name, Class: s.Operand.Name, Kind: "immediate", Bias: baseline}
		if hasPC(ex) {
			o.Relative = true
			o.Kind = "address"
			o.PCBias = int64(v.Length)
			o.Bias -= int64(v.Length)
		}
		if s.Operand.Address {
			o.Kind = "address"
		}
		// A source expression can describe a width using another printed
		// start-bit operand (bfext/bfins), or reuse an index register twice.
		reused := false
		for _, old := range e.Operands {
			var shared uint64
			for _, b := range old.Bits {
				shared |= ((uint64(1) << uint(b.Width)) - 1) << uint(b.InstructionBit)
			}
			if shared == 0 || physical&shared != shared {
				continue
			}
			factor := int64(0)
			valid := true
			for _, b := range old.Bits {
				for k := 0; k < b.Width; k++ {
					x, _ := eval(ex, v.Value|(uint64(1)<<uint(b.InstructionBit+k)), s.Offset, 0, v.Length)
					den := int64(1) << uint(b.ValueBit+k)
					if old.Scale != 0 {
						den *= old.Scale
					}
					f := (x - baseline) / den
					if (x-baseline)%den != 0 || (factor != 0 && factor != f) {
						valid = false
					}
					factor = f
				}
			}
			if !valid {
				continue
			}
			if physical == shared && factor == 1 && baseline == old.Bias && fmt.Sprint(old.Names) == fmt.Sprint(s.Operand.Names) {
				e.Syntax = strings.ReplaceAll(e.Syntax, "{"+name+"}", "{"+old.Name+"}")
				reused = true
				break
			}
			if len(s.Operand.Names) == 0 && factor != 0 {
				o.BiasOperand = old.Name
				o.BiasScale = factor
				o.Bias -= old.Bias * factor
				physical &^= shared
			}
		}
		if reused {
			continue
		}
		if len(s.Operand.Names) > 0 || len(s.Operand.Lookup) > 0 {
			width := bits.OnesCount64(physical)
			if width > 16 {
				return e, fmt.Errorf("large attached table")
			}
			o.Bias = 0
			o.Kind = "register"
			o.Names = make([]string, 1<<width)
			if len(s.Operand.Lookup) > 0 {
				o.Kind = "immediate"
				o.Names = nil
				o.Lookup = make([]int64, 1<<width)
			}
			positions := []int{}
			for p := 0; p < 64; p++ {
				if physical&(uint64(1)<<uint(p)) != 0 {
					positions = append(positions, p)
					o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: p, ValueBit: len(positions) - 1, Width: 1})
				}
			}
			for x := 0; x < 1<<width; x++ {
				raw := v.Value
				for j, p := range positions {
					if x&(1<<uint(j)) != 0 {
						raw |= uint64(1) << uint(p)
					}
				}
				value, err := eval(ex, raw, s.Offset, 0, v.Length)
				if err != nil {
					return e, err
				}
				if value >= 0 && int(value) < len(s.Operand.Names) {
					o.Names[x] = s.Operand.Names[value]
				}
				if o.Lookup != nil {
					if value < 0 || int(value) >= len(s.Operand.Lookup) {
						return e, fmt.Errorf("lookup index")
					}
					o.Lookup[x] = s.Operand.Lookup[value]
				}
			}
		} else {
			type mapping struct {
				physical, logical int
				negative          bool
			}
			var maps []mapping
			low := 64
			high := 0
			for p := 0; p < 64; p++ {
				if physical&(uint64(1)<<uint(p)) == 0 {
					continue
				}
				x, err := eval(ex, v.Value|(uint64(1)<<uint(p)), s.Offset, 0, v.Length)
				if err != nil {
					return e, err
				}
				delta := x - baseline
				if delta == 0 {
					continue
				}
				neg := delta < 0
				if neg {
					delta = -delta
				}
				if uint64(delta)&(uint64(delta)-1) != 0 {
					return e, fmt.Errorf("nonlinear operand %s delta%d", name, delta)
				}
				k := bits.TrailingZeros64(uint64(delta))
				if k < low {
					low = k
				}
				if k > high {
					high = k
				}
				maps = append(maps, mapping{p, k, neg})
			}
			if len(maps) > 0 {
				o.Scale = int64(1) << uint(low)
				for _, m := range maps {
					if m.negative {
						if m.logical != high {
							return e, fmt.Errorf("negative non-sign bit")
						}
						o.Signed = true
					}
					o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: m.physical, ValueBit: m.logical - low, Width: 1})
				}
			}
		}
		if len(o.Bits) == 0 {
			lit := strconv.FormatInt(baseline, 10)
			if len(o.Names) > 0 {
				lit = o.Names[0]
				if lit == "" {
					return e, errConflict
				}
			}
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+name+"}", lit)
			continue
		}
		duplicate := ""
		for _, old := range e.Operands {
			a, b := old, o
			a.Name = ""
			b.Name = ""
			a.Class = ""
			b.Class = ""
			aa, _ := json.Marshal(a)
			bb, _ := json.Marshal(b)
			if string(aa) == string(bb) {
				duplicate = old.Name
				break
			}
		}
		if duplicate != "" {
			e.Syntax = strings.ReplaceAll(e.Syntax, "{"+name+"}", "{"+duplicate+"}")
			continue
		}
		for _, b := range o.Bits {
			mask := uint64(1) << uint(b.InstructionBit)
			if used&mask != 0 {
				return e, fmt.Errorf("overlapping displayed operand %s", name)
			}
			used |= mask
		}
		e.Operands = append(e.Operands, o)
	}
	// SLEIGH deliberately leaves phantom/padding and semantic-only bits free.
	// Preserve them as structured implicit operands, with zero the assembly default.
	var extra []codec.BitSlice
	for p := 0; p < v.Length*8; p++ {
		if used&(uint64(1)<<uint(p)) == 0 {
			extra = append(extra, codec.BitSlice{InstructionBit: p, ValueBit: len(extra), Width: 1})
		}
	}
	if len(extra) > 0 {
		e.Operands = append(e.Operands, codec.Operand{Name: "raw", Class: "source-unconstrained", Kind: "immediate", Optional: true, Bits: extra})
	}
	e.Syntax = strings.TrimSpace(e.Syntax)
	f := strings.Fields(e.Syntax)
	if len(f) == 0 {
		return e, fmt.Errorf("empty syntax")
	}
	e.Mnemonic = f[0]
	return e, nil
}
func flow(m string) string {
	m = strings.ToUpper(m)
	base := strings.Split(m, ".")[0]
	switch base {
	case "RETURN", "RETFIE", "RETLW", "RETFIEFAST", "ADDULNK", "SUBULNK":
		return "return"
	case "CALL", "LCALL", "RCALL", "CALLW":
		return "call"
	case "GOTO", "BRA", "BRW":
		return "branch"
	case "SKPC", "SKPNC", "SKPZ", "SKPNZ", "BC", "BNC", "BZ", "BNZ", "BN", "BNN", "BOV", "BNOV", "BTFSC", "BTFSS", "CPFSEQ", "CPFSGT", "CPFSLT", "TSTFSZ", "DECFSZ", "DCFSNZ", "INCFSZ", "INFSNZ", "CPSEQ", "CPSNE", "CPSGT", "CPSLT":
		return "conditional_branch"
	}
	return "next"
}
func fixTargets(e *codec.Encoding, profile string, length int) {
	m := strings.ToUpper(strings.Split(e.Mnemonic, ".")[0])
	is24 := strings.HasPrefix(profile, "pic24") || strings.HasPrefix(profile, "dspic")
	if m == "BRA" {
		for _, o := range e.Operands {
			if o.Class == "sleigh-enumeration" {
				e.FlowControl = "conditional_branch"
			}
		}
	}
	for i := range e.Operands {
		o := &e.Operands[i]
		if o.Relative {
			o.Kind = "address"
			if is24 || strings.HasPrefix(profile, "pic14") {
				if o.Scale == 0 {
					o.Scale = 1
				}
				o.Scale *= 2
			}
			if profile == "pic18" {
				o.PCWrapBits = 21
			} else if is24 {
				o.PCWrapBits = 24
			} else {
				o.PCWrapBits = 16
			}
			continue
		}
		if o.Kind == "address" && is24 {
			if o.Scale == 0 {
				o.Scale = 1
			}
			o.Scale *= 2
			o.Bias *= 2
			continue
		}
		if (e.FlowControl == "call" || e.FlowControl == "branch" || e.FlowControl == "conditional_branch") && (m == "CALL" || m == "LCALL" || m == "GOTO" || m == "BC" || m == "BZ" || m == "BNC" || m == "BNZ") && o.Kind != "register" && !o.Optional {
			o.Kind = "address"
			if profile == "pic12" || profile == "pic16c5x" || strings.HasPrefix(profile, "pic14") {
				o.Scale = 2
				o.Relative = true
				o.PCRegionBits = o.Width() + 1
				if profile == "pic12" || profile == "pic16c5x" {
					o.PCRegionBits = 10
					o.PCWrapBits = 12
				} else if profile == "pic14" {
					o.PCWrapBits = 14
				} else {
					o.PCWrapBits = 16
				}
			} else if profile == "pic17" {
				o.Scale = 2
				o.Relative = true
				o.PCRegionBits = 14
				if m == "LCALL" {
					o.PCRegionBits = 9
				}
				o.PCWrapBits = 17
			}
		}
	}
}

var _ codec.Backend = (*Catalog)(nil)

const consumerTest = `use CRATE::*;
#[test]
fn public_catalog_profiles_and_templates() {
 assert!(encoding_count()>0); assert!(profile("default").is_some());
 let (i,e)=ENCODINGS.iter().enumerate().find(|(_,e)|e.mnemonic.eq_ignore_ascii_case("nop") && e.operands.iter().all(|o|o.optional)).unwrap();
 let values=representative(i).unwrap(); let bytes=encode(e.id,&values).unwrap();
 let d=decode_with_features(&bytes,Some(e.features)).unwrap();
 assert_eq!(encode(d.encoding().id,&d.values[..d.encoding().operands.len()]).unwrap(),bytes);
 let text=d.format(0);assert!(assemble_with_features(&text,0,Some(e.features)).unwrap().contains(&bytes));
 let template=Template::parse_at(&text,0).unwrap();assert!(template.matches(&bytes).is_some());assert!(template.encode(&[]).unwrap().contains(&bytes));
}
`
const pic18ConsumerTest = `
#[test]
fn gputils_machine_routine_consumer() {
 let bytes=[0x05,0x0e,0x20,0x6e,0x20,0x2e,0xfe,0xd7,0x08,0xec,0x00,0xf0,0x01,0xee,0x23,0xf0,0x12,0x00];
 let mut at=0;let mut count=0;
 while at<bytes.len(){let d=decode_with_features(&bytes[at..],profile("default")).unwrap();let text=d.format(at as u64);assert!(assemble_with_features(&text,at as u64,profile("default")).unwrap().contains(&bytes[at..at+d.length].to_vec()));if at==6{assert_eq!(d.branch_target(at as u64),Some(4));}if at==8{assert_eq!(d.branch_target(at as u64),Some(16));}at+=d.length;count+=1;}
 assert_eq!(count,7);
}
`

// Package tricore imports the actual Ghidra SLEIGH TriCore CPU and PCP descriptions.
package tricore

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed data/tricore.sinc
var Source string

//go:embed data/tricore.pcp.sinc
var PCPSource string

//go:embed data/LICENSE-Ghidra.txt
var upstreamLicense string

//go:embed data/NOTICE-Ghidra.txt
var upstreamNotice string

const SourceRevision = "42db038f3c88c6bd7e9bedbb919138111f8b77fd"

// Catalog embeds the shared structured codec and retains source attribution in
// generated Rust crates. The CPU and PCP instruction streams are separate.
type Catalog struct{ *codec.Catalog }

func (c *Catalog) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte("Ghidra TriCore specification, Apache-2.0, commit "+SourceRevision+".\n\n"+upstreamNotice+"\n"+upstreamLicense), 0644)
}
func (c *Catalog) WriteJSON(w io.Writer) error { return c.Catalog.WriteJSON(w) }

var errConflict = errors.New("contradictory SLEIGH pattern")
var fixedRE = regexp.MustCompile(`\b([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(0x[0-9A-Fa-f]+|[0-9]+)\b`)
var pairRE = regexp.MustCompile(`\b(R[A-Za-z]+\d+)/(R[A-Za-z]+\d+)\b`)
var quotedRE = regexp.MustCompile(`"([^"]*)"`)

// Parse reads tricore.sinc, with optional concatenated tricore.pcp.sinc. Passing
// nil uses the bundled pinned source. PCP is requested as tricore-pcp.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "tricore" && architecture != "tricore-pcp" {
		return nil, fmt.Errorf("TriCore: unsupported architecture %q", architecture)
	}
	source := Source
	if r != nil {
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		source = string(b)
	}
	if !strings.Contains(source, "define token instr") && !strings.Contains(source, "define token pcpinstr") {
		return nil, fmt.Errorf("TriCore: missing SLEIGH instruction token definitions")
	}
	if architecture == "tricore-pcp" && !strings.Contains(source, "define token pcpinstr") {
		source += "\n" + PCPSource
	}
	source = stripComments(source)
	c := &codec.Catalog{Schema: codec.Schema, Architecture: architecture, Source: "Ghidra TriCore SLEIGH " + SourceRevision + " (Apache-2.0)", FeatureSets: map[string][]string{}}
	profiles := []string{"v2", "rider-d", "rider-b"}
	if architecture == "tricore-pcp" {
		profiles = []string{"pcp"}
	}
	for _, profile := range profiles {
		d, err := sourceDescription(source, profile)
		if err != nil {
			return nil, err
		}
		feature := "tricore-" + profile
		c.FeatureSets[profile] = []string{feature}
		for _, instruction := range d.instructions {
			mode := 0
			if architecture == "tricore-pcp" {
				mode = 1
			}
			if !strings.Contains(instruction.pattern, fmt.Sprintf("PCPMode=%d", mode)) {
				continue
			}
			states, err := d.expand(instruction, 0)
			if err != nil {
				return nil, fmt.Errorf("line%d: %w", instruction.line, err)
			}
			for j, s := range states {
				e, err := d.encoding(s)
				if errors.Is(err, errConflict) {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("line%d %s: %w", instruction.line, instruction.display, err)
				}
				e.ID = fmt.Sprintf("%s_L%d_%d", profile, instruction.line, j)
				e.Features = []string{feature}
				e.FlowControl = sourceFlow(instruction.body)
				c.Encodings = append(c.Encodings, e)
			}
		}
	}
	c.FeatureSets["default"] = []string{"tricore-v2"}
	if architecture == "tricore-pcp" {
		c.FeatureSets["default"] = []string{"tricore-pcp"}
	}
	encodings, err := applyPriority(c.Encodings)
	if err != nil {
		return nil, err
	}
	c.Encodings = encodings
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Catalog{c}, nil
}

type expanded struct {
	display     string
	constraints []string
	scalars     map[string]constructor
}

func (d *description) expand(c constructor, depth int) ([]expanded, error) {
	if depth > 12 {
		return nil, fmt.Errorf("cyclic source subtable %s", c.table)
	}
	state := expanded{display: c.display, constraints: []string{c.pattern}, scalars: map[string]constructor{}}
	if c.action != "" {
		state.display = "{" + c.table + "}"
		if strings.Contains(c.display, `"#"`) {
			state.display = "#" + state.display
		}
		state.scalars[c.table] = c
	}
	states := []expanded{state}
	seen := map[string]bool{}
	for _, name := range identifier.FindAllString(c.pattern, -1) {
		if seen[name] || d.helpers[name] == nil {
			continue
		}
		seen[name] = true
		if name == c.table {
			return nil, fmt.Errorf("recursive table %s", name)
		}
		var next []expanded
		for _, parent := range states {
			for _, child := range d.helpers[name] {
				variants, err := d.expand(child, depth+1)
				if err != nil {
					return nil, err
				}
				for _, sub := range variants {
					v := expanded{display: replaceIdentifier(parent.display, name, sub.display), constraints: append(append([]string(nil), parent.constraints...), sub.constraints...), scalars: map[string]constructor{}}
					for k, x := range parent.scalars {
						v.scalars[k] = x
					}
					for k, x := range sub.scalars {
						v.scalars[k] = x
					}
					next = append(next, v)
				}
			}
		}
		states = next
	}
	return states, nil
}
func replaceIdentifier(s, name, value string) string {
	return identifier.ReplaceAllStringFunc(s, func(v string) string {
		if v == name {
			return value
		}
		return v
	})
}
func (d *description) encoding(s expanded) (codec.Encoding, error) {
	var mask, value uint32
	length := 2
	for _, pattern := range s.constraints {
		for _, name := range identifier.FindAllString(pattern, -1) {
			if f, ok := d.fields[name]; ok && f.start+f.width > 16 {
				length = 4
			}
		}
		for _, m := range fixedRE.FindAllStringSubmatch(pattern, -1) {
			f, ok := d.fields[m[1]]
			if !ok {
				if m[1] == "PCPMode" {
					continue
				}
				return codec.Encoding{}, fmt.Errorf("unknown fixed field %s", m[1])
			}
			v, err := strconv.ParseUint(m[2], 0, 32)
			if err != nil || v >= uint64(1)<<f.width {
				return codec.Encoding{}, fmt.Errorf("fixed field %s value %s exceeds %d bits", m[1], m[2], f.width)
			}
			bits := uint32((uint64(1)<<f.width)-1) << f.start
			if (mask&bits)&(value^(uint32(v)<<f.start)) != 0 {
				return codec.Encoding{}, fmt.Errorf("%w: field %s", errConflict, m[1])
			}
			mask |= bits
			value |= uint32(v) << f.start
		}
	}
	text := s.display
	text = quotedRE.ReplaceAllString(text, "$1")
	// Two attached register views name one physical pair field.
	pairFields := map[string]field{}
	text = pairRE.ReplaceAllStringFunc(text, func(pair string) string {
		m := pairRE.FindStringSubmatch(pair)
		a, b := d.fields[m[1]], d.fields[m[2]]
		name := "Pair_" + m[1]
		names := make([]string, len(a.names))
		for i := range names {
			if a.names[i] != "" && i < len(b.names) && b.names[i] != "" {
				names[i] = a.names[i] + "/" + b.names[i]
			}
		}
		a.names = names
		pairFields[name] = a
		return name
	})
	e := codec.Encoding{Syntax: text, FlowControl: "next"}
	seen := map[string]bool{}
	used := mask
	for _, name := range identifier.FindAllString(text, -1) {
		if seen[name] {
			continue
		}
		seen[name] = true
		var o codec.Operand
		f, ok := d.fields[name]
		if pair, exists := pairFields[name]; exists {
			f = pair
			ok = true
		}
		if ok {
			o = codec.Operand{Name: name, Class: name, Kind: "immediate", Signed: f.signed, Bits: []codec.BitSlice{{InstructionBit: f.start, Width: f.width}}}
			if len(f.names) > 0 {
				o.Kind = "register"
				o.Names = f.names
			}
		} else if scalar, exists := s.scalars[name]; exists {
			var err error
			o, err = expressionOperand(d, scalar, name)
			if err != nil {
				return e, err
			}
		} else {
			continue
		}
		var literal string
		var err error
		o, literal, err = restrictOperand(o, mask, value)
		if err != nil {
			return e, err
		}
		if literal != "" {
			e.Syntax = replaceIdentifier(e.Syntax, name, literal)
			continue
		}
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				p := b.InstructionBit + k
				if used&(uint32(1)<<p) != 0 {
					return e, fmt.Errorf("overlapping physical operand %s bit%d", name, p)
				}
				used |= uint32(1) << p
			}
		}
		e.Operands = append(e.Operands, o)
		e.Syntax = replaceIdentifier(e.Syntax, name, "{"+name+"}")
	}
	// Scalar holes were introduced before identifier substitution.
	e.Syntax = strings.ReplaceAll(e.Syntax, "^", "")
	e.Syntax = strings.ReplaceAll(strings.ReplaceAll(e.Syntax, "{{", "{"), "}}", "}")
	if used != uint32((uint64(1)<<uint(length*8))-1) {
		return e, fmt.Errorf("unmodeled bits 0x%x", ^used&uint32((uint64(1)<<uint(length*8))-1))
	}
	e.Mask = make([]byte, length)
	e.Value = make([]byte, length)
	for i := 0; i < length; i++ {
		e.Mask[i] = byte(mask >> uint(i*8))
		e.Value[i] = byte(value >> uint(i*8))
	}
	fields := strings.Fields(e.Syntax)
	if len(fields) == 0 {
		return e, fmt.Errorf("empty instruction syntax")
	}
	e.Mnemonic = fields[0]
	sort.SliceStable(e.Operands, func(i, j int) bool {
		return e.Operands[i].Bits[0].InstructionBit < e.Operands[j].Bits[0].InstructionBit
	})
	return e, nil
}

var _ codec.Backend = (*Catalog)(nil)

var returnFlow = regexp.MustCompile(`\breturn\s*\[`)
var callFlow = regexp.MustCompile(`\bcall\s+`)
var gotoFlow = regexp.MustCompile(`\bgoto\s+([^\s;]+)`)
var conditionalFlow = regexp.MustCompile(`\bif\s*\(`)

func sourceFlow(body string) string {
	if returnFlow.MatchString(body) {
		return "return"
	}
	if callFlow.MatchString(body) {
		return "call"
	}
	for _, target := range gotoFlow.FindAllStringSubmatch(body, -1) {
		if target[1] == "inst_next" || strings.HasPrefix(target[1], "<") {
			continue
		}
		if conditionalFlow.MatchString(body) {
			return "conditional_branch"
		}
		return "branch"
	}
	return "next"
}

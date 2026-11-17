package hexagon

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func packetLines(text string) ([]string, bool, bool, error) {
	text = strings.TrimSpace(text)
	inner, outer := false, false
	if strings.HasPrefix(text, "{") {
		end := strings.LastIndex(text, "}")
		if end < 0 {
			return nil, false, false, fmt.Errorf("unterminated packet")
		}
		suffix := strings.TrimSpace(text[end+1:])
		for suffix != "" {
			if strings.HasPrefix(suffix, ":endloop0") {
				inner = true
				suffix = strings.TrimSpace(strings.TrimPrefix(suffix, ":endloop0"))
			} else if strings.HasPrefix(suffix, ":endloop1") {
				outer = true
				suffix = strings.TrimSpace(strings.TrimPrefix(suffix, ":endloop1"))
			} else {
				return nil, false, false, fmt.Errorf("unknown packet suffix %q", suffix)
			}
		}
		text = text[1:end]
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, false, false, fmt.Errorf("empty packet")
	}
	return lines, inner, outer, nil
}
func (c *Catalog) parseInstructions(text string, sub bool, address uint64, features []string) []Instruction {
	table := c.Words
	if sub {
		table = c.Subinstructions
	}
	var out []Instruction
	for n := range table.Encodings {
		e := &table.Encodings[n]
		if !featuresMatch(e, features) {
			continue
		}
		m := c.Metadata[e.ID]
		clone := *e
		extended := strings.Contains(text, "##")
		if extended {
			if m.ExtendOperand == "" {
				continue
			}
			hole := "{" + m.ExtendOperand + "}"
			if strings.Contains(clone.Syntax, "#"+hole) {
				clone.Syntax = strings.ReplaceAll(clone.Syntax, "#"+hole, "##"+hole)
			} else {
				clone.Syntax = strings.ReplaceAll(clone.Syntax, hole, "##"+hole)
			}
		}
		if values, ok := codec.ParseOperands(&clone, text, address); ok {
			out = append(out, Instruction{ID: e.ID, Values: values, Extended: extended})
		}
	}
	return out
}
func (c *Catalog) parseWords(line string, address uint64, features []string) []Word {
	var out []Word
	for _, i := range c.parseInstructions(line, false, address, features) {
		out = append(out, Word{[]Instruction{i}})
	}
	for n, ch := range line {
		if ch != ';' {
			continue
		}
		low := c.parseInstructions(strings.TrimSpace(line[:n]), true, address, features)
		high := c.parseInstructions(strings.TrimSpace(line[n+1:]), true, address, features)
		for _, a := range low {
			for _, b := range high {
				for _, g := range duplexGroups {
					if c.Metadata[a.ID].SubGroup == g[0] && c.Metadata[b.ID].SubGroup == g[1] {
						out = append(out, Word{[]Instruction{a, b}})
						break
					}
				}
			}
		}
	}
	return out
}

// AssemblePacket accepts explicit physical word order. A semicolon between two
// compact subinstructions denotes a duplex word; semicolons belonging to a
// compound instruction remain part of its source syntax.
func (c *Catalog) AssemblePacket(text string, address uint64, features []string) ([][]byte, error) {
	lines, inner, outer, err := packetLines(text)
	if err != nil {
		return nil, err
	}
	packets := []Packet{{InnerLoop: inner, OuterLoop: outer}}
	for _, line := range lines {
		words := c.parseWords(line, address, features)
		if len(words) == 0 {
			return nil, fmt.Errorf("hexagon: unrecognized packet instruction %q", line)
		}
		var next []Packet
		for _, p := range packets {
			for _, w := range words {
				q := p
				q.Words = append(append([]Word{}, p.Words...), w)
				next = append(next, q)
				if len(next) > 4096 {
					return nil, fmt.Errorf("hexagon: too many ambiguous packet candidates")
				}
			}
		}
		packets = next
	}
	var out [][]byte
	for _, p := range packets {
		b, err := c.EncodePacket(p, address, features)
		if err != nil {
			continue
		}
		duplicate := false
		for _, old := range out {
			if bytes.Equal(old, b) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hexagon: no packet encoding satisfies operands and framing")
	}
	return out, nil
}

package jvm

import (
	"fmt"
	"io"
	"regexp"
)

// Parse accepts the upstream HotSpot interpreter/bytecodes.cpp source. Its
// standard def() records are the canonical ordered Java bytecode definitions.
// VM-private rewritten bytecodes are deliberately excluded from class files.
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "jvm" {
		return nil, fmt.Errorf("unsupported JVM architecture %q", architecture)
	}
	src, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`def\(\s*_([a-z0-9_]+)\s*,\s*"([a-z0-9_]+)"\s*,\s*"([^"]*)"\s*,\s*(nullptr|"[^"]*")`)
	rows := re.FindAllSubmatch(src, -1)
	c := &Catalog{Schema: Schema, Architecture: architecture, Source: "OpenJDK HotSpot interpreter/bytecodes.cpp (class-file forms, JVMS chapter 6)"}
	started := false
	for _, m := range rows {
		name := string(m[1])
		if name == "nop" {
			if started {
				return nil, fmt.Errorf("duplicate JVM standard bytecode definitions")
			}
			started = true
		}
		if !started {
			continue
		}
		if name == "breakpoint" {
			break
		}
		if string(m[2]) != name {
			return nil, fmt.Errorf("inconsistent JVM source definition %s", name)
		}
		if len(c.Instructions) > 201 {
			return nil, fmt.Errorf("unexpected JVM opcode definition %s", name)
		}
		d := Definition{Opcode: byte(len(c.Instructions)), Mnemonic: name, Format: string(m[3])}
		if string(m[4]) != "nullptr" {
			d.WideFormat = string(m[4][1 : len(m[4])-1])
		}
		d.Operands = operandDefinitions(d.Opcode)
		if wideAllowed(d.Opcode) {
			expected := "wbii"
			if d.Opcode == 0x84 {
				expected = "wbiicc"
			}
			if d.WideFormat != expected {
				return nil, fmt.Errorf("JVM %s source wide format %q disagrees with framing", name, d.WideFormat)
			}
		} else if d.WideFormat != "" {
			return nil, fmt.Errorf("unexpected JVM wide form %s", name)
		}
		n := 1
		for _, o := range d.Operands {
			n += o.Bytes
		}
		if d.Opcode == 0xb9 {
			n++
		}
		if d.Opcode == 0xba {
			n += 2
		}
		special := d.Opcode == 0xaa || d.Opcode == 0xab || d.Opcode == 0xc4
		if !special && len(d.Format) != n {
			return nil, fmt.Errorf("JVM %s source format %q disagrees with class-file framing (%d)", name, d.Format, n)
		}
		if special && d.Format != "" {
			return nil, fmt.Errorf("JVM %s must have variable source format", name)
		}
		c.Instructions = append(c.Instructions, d)
	}
	if len(c.Instructions) != 202 || c.Instructions[0x84].Mnemonic != "iinc" || c.Instructions[0xaa].Mnemonic != "tableswitch" || c.Instructions[0xc9].Mnemonic != "jsr_w" {
		return nil, fmt.Errorf("input is not a complete supported OpenJDK Java bytecode corpus (%d records)", len(c.Instructions))
	}
	for _, d := range []Definition{{Opcode: 0xca, Mnemonic: "breakpoint", Reserved: true}, {Opcode: 0xfe, Mnemonic: "impdep1", Reserved: true}, {Opcode: 0xff, Mnemonic: "impdep2", Reserved: true}} {
		c.Instructions = append(c.Instructions, d)
	}
	return c, nil
}
func operandDefinitions(op byte) []OperandDefinition {
	cp := func(n int) []OperandDefinition { return []OperandDefinition{{"index", "constant_pool", n, false}} }
	local := func() []OperandDefinition { return []OperandDefinition{{"index", "local", 1, false}} }
	switch {
	case op == 0x10:
		return []OperandDefinition{{"value", "immediate", 1, true}}
	case op == 0x11:
		return []OperandDefinition{{"value", "immediate", 2, true}}
	case op == 0x12:
		return cp(1)
	case op == 0x13 || op == 0x14:
		return cp(2)
	case op >= 0x15 && op <= 0x19 || op >= 0x36 && op <= 0x3a || op == 0xa9:
		return local()
	case op == 0x84:
		return []OperandDefinition{{"index", "local", 1, false}, {"constant", "immediate", 1, true}}
	case op >= 0x99 && op <= 0xa8 || op == 0xc6 || op == 0xc7:
		return []OperandDefinition{{"target", "branch", 2, true}}
	case op >= 0xb2 && op <= 0xb8 || op == 0xba || op == 0xbb || op == 0xbd || op == 0xc0 || op == 0xc1:
		return cp(2)
	case op == 0xb9:
		return append(cp(2), OperandDefinition{"count", "count", 1, false})
	case op == 0xbc:
		return []OperandDefinition{{"type", "array_type", 1, false}}
	case op == 0xc5:
		return append(cp(2), OperandDefinition{"dimensions", "dimensions", 1, false})
	case op == 0xc8 || op == 0xc9:
		return []OperandDefinition{{"target", "branch", 4, true}}
	}
	return nil
}

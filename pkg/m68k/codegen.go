package m68k

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed README.md
var packageReadme string

//go:embed testdata/COPYING-binutils
var upstreamLicense string

func (c *Catalog) GenerateRust(output string) error {
	if output == "" {
		return fmt.Errorf("empty output directory")
	}
	if e := c.Validate(); e != nil {
		return e
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Generated from GNU binutils 2.44. See UPSTREAM-LICENSE and README.md.\npub const ARCHITECTURE:&str=%q;\npub const DEFAULT_CPU:&str=%q;\n", c.Architecture, c.CPU)
	b.WriteString(rustRuntime + rustAnalysis)
	b.WriteString("\npub static OPCODES:&[Opcode]=&[\n")
	for _, o := range c.Opcodes {
		fmt.Fprintf(&b, "Opcode{id:%s,mnemonic:%s,size:%d,opcode:0x%x,mask:0x%x,args:%s,features:0x%x},\n", strconv.Quote(o.ID), strconv.Quote(o.Mnemonic), o.Size, o.Opcode, o.Mask, strconv.Quote(o.Args), o.Features)
	}
	b.WriteString("];\nstatic EXACT_OPCODES:&[usize]=&[")
	for _, i := range rustExactOpcodeIndices(c.Opcodes, c.Aliases) {
		fmt.Fprintf(&b, "%d,", i)
	}
	b.WriteString("];\npub static ALIASES:&[(&str,&str)]=&[\n")
	for _, a := range c.Aliases {
		fmt.Fprintf(&b, "(%q,%q),\n", a.Alias, a.Primary)
	}
	b.WriteString("];\npub static PROFILES:&[(&str,u32)]=&[\n")
	names := make([]string, 0, len(Profiles))
	for n := range Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "(%q,0x%x),\n", n, Profiles[n])
	}
	b.WriteString("];\npub static CONTROL_REGISTERS:&[(&str,u64)]=&[\n")
	regs := make([]string, 0, len(controlRegisters))
	for n := range controlRegisters {
		regs = append(regs, n)
	}
	sort.Strings(regs)
	for _, n := range regs {
		fmt.Fprintf(&b, "(%q,%d),\n", n, controlRegisters[n])
	}
	b.WriteString("];\npub static MMU_REGISTERS:&[(&str,u64)]=&[\n")
	regs = regs[:0]
	for n := range mmuRegisters {
		regs = append(regs, n)
	}
	sort.Strings(regs)
	for _, n := range regs {
		fmt.Fprintf(&b, "(%q,%d),\n", n, mmuRegisters[n])
	}
	b.WriteString("];\n")
	if e := os.MkdirAll(filepath.Join(output, "src"), 0755); e != nil {
		return e
	}
	if e := os.WriteFile(filepath.Join(output, "src/lib.rs"), b.Bytes(), 0644); e != nil {
		return e
	}
	if e := os.WriteFile(filepath.Join(output, "Cargo.toml"), []byte(fmt.Sprintf("[package]\nname = %q\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"GPL-3.0-or-later\"\n\n[dependencies]\n", strings.ReplaceAll(c.Architecture, "-", "_")+"_codec")), 0644); e != nil {
		return e
	}
	if e := os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte("Opcode metadata: GNU binutils 2.44 opcodes/m68k-opc.c, GPL-3.0-or-later.\nGenerated interpreter implementation: MIT; see LICENSE.\n\n"+upstreamLicense), 0644); e != nil {
		return e
	}
	if e := os.WriteFile(filepath.Join(output, "README.md"), []byte(packageReadme), 0644); e != nil {
		return e
	}
	if err := c.writeConformance(output); err != nil {
		return err
	}
	return codec.WriteLicense(output)
}

type InstructionTemplate struct {
	catalog *Catalog
	opcode  *Opcode
	values  []Value
	set     []bool
}

func (c *Catalog) Template(id string) (*InstructionTemplate, error) {
	var selected *Opcode
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		if o.ID == id || o.Mnemonic == id {
			if selected != nil {
				return nil, fmt.Errorf("template requires unique instruction ID")
			}
			selected = o
		}
	}
	if selected == nil || selected.Features&Profiles[c.CPU] == 0 {
		return nil, fmt.Errorf("unknown or disabled instruction")
	}
	return &InstructionTemplate{c, selected, make([]Value, len(pairs(selected))), make([]bool, len(pairs(selected)))}, nil
}

// Set uses stable zero-based names op0, op1, ... across both generated runtimes.
func (t *InstructionTemplate) Set(name string, v Value) error {
	i, e := strconv.Atoi(strings.TrimPrefix(name, "op"))
	if e != nil || name != "op"+strconv.Itoa(i) || i < 0 || i >= len(t.values) {
		return fmt.Errorf("unknown operand %s", name)
	}
	s := stream{b: make([]byte, fixedSize(t.opcode)), p: fixedSize(t.opcode), encode: true}
	setWord(s.b, 0, uint16(t.opcode.Opcode>>16))
	if len(s.b) >= 4 {
		setWord(s.b, 2, uint16(t.opcode.Opcode))
	}
	if _, e = t.catalog.operand(&s, t.opcode, pairs(t.opcode)[i], v); e != nil {
		return e
	}
	t.values[i] = cloneTemplateValue(v)
	t.set[i] = true
	return nil
}
func (t *InstructionTemplate) Encode() ([]byte, error) {
	for i, v := range t.set {
		if !v {
			return nil, fmt.Errorf("missing operand op%d", i)
		}
	}
	return t.catalog.Encode(t.opcode.ID, t.values)
}

func cloneTemplateValue(v Value) Value {
	if v.Items != nil {
		items := make([]Value, len(v.Items))
		for i, item := range v.Items {
			items[i] = cloneTemplateValue(item)
		}
		v.Items = items
	}
	return v
}

// Match decodes one instruction using this template's source form. Unbound
// operands capture values; bound operands must have the same encoded meaning.
// Bytes after the matched instruction belong to the next instruction.
func (t *InstructionTemplate) Match(src []byte) (*Instruction, bool) {
	in, err := t.catalog.decodeSelected(src, t.opcode.ID)
	if err != nil {
		return nil, false
	}
	values := append([]Value(nil), in.Operands...)
	for i, set := range t.set {
		if set {
			values[i] = t.values[i]
		}
	}
	encoded, err := t.catalog.Encode(t.opcode.ID, values)
	if err != nil || !bytes.Equal(encoded, src[:in.Length]) {
		return nil, false
	}
	return in, true
}

// Only index exact IDs whose normalized/aliased name cannot also select a
// mnemonic. Ambiguous names keep the original catalog-order union search.
func rustExactOpcodeIndices(opcodes []Opcode, aliases []Alias) []int {
	mnemonics := map[string]bool{}
	for _, o := range opcodes {
		mnemonics[o.Mnemonic] = true
	}
	var indices []int
	for i, o := range opcodes {
		name := strings.ReplaceAll(o.ID, ".", "")
		for range aliases {
			found := false
			for _, a := range aliases {
				if a.Alias == name {
					name = a.Primary
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		if !mnemonics[name] {
			indices = append(indices, i)
		}
	}
	sort.Slice(indices, func(i, j int) bool { return opcodes[indices[i]].ID < opcodes[indices[j]].ID })
	return indices
}

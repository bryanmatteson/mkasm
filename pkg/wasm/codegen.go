package wasm

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed testdata/LICENSE-wasm-tools-MIT
var upstreamLicense string

func (c *Catalog) GenerateRust(output string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(output)
		}
	}()

	if output == "" {
		return fmt.Errorf("empty output directory")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if len(c.Opcodes) >= 1<<16 {
		return fmt.Errorf("WebAssembly opcode index requires fewer than 65536 definitions")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Generated from %s (%s). Instruction codec; module validation is separate.\n", c.Source, c.SourceCommit)
	bits := 32
	if c.Architecture == "wasm64" {
		bits = 64
	}
	fmt.Fprintf(&b, "pub const ADDRESS_BITS:u32=%d;\npub const ARCHITECTURE:&str=%q;\n", bits, c.Architecture)
	b.WriteString(rustRuntime + rustAnalysis)
	b.WriteString("\npub static OPCODES:&[Opcode]=&[\n")
	for _, o := range c.Opcodes {
		fmt.Fprintf(&b, "Opcode{id:%s,mnemonic:%s,prefix:%d,code:%d,feature:%s,nullable:%s,fields:&[", strconv.Quote(o.ID), strconv.Quote(o.Mnemonic), o.Prefix, o.Opcode, strconv.Quote(o.Feature), rustNullable(o.Nullable))
		for _, f := range o.Fields {
			fmt.Fprintf(&b, "Field{name:%s,kind:%s},", strconv.Quote(f.Name), strconv.Quote(f.Kind))
		}
		b.WriteString("]},\n")
	}
	b.WriteString("];\n")
	indices := make([]int, 0, len(c.Opcodes))
	for i, o := range c.Opcodes {
		if o.Prefix != 0 {
			indices = append(indices, i)
		}
	}
	sort.Slice(indices, func(i, j int) bool {
		a, b := c.Opcodes[indices[i]], c.Opcodes[indices[j]]
		if a.Prefix != b.Prefix {
			return a.Prefix < b.Prefix
		}
		return a.Opcode < b.Opcode
	})
	b.WriteString("static OPCODE_INDEX:&[u16]=&[")
	for _, i := range indices {
		fmt.Fprintf(&b, "%d,", i)
	}
	b.WriteString("];\n")
	b.WriteString("\n#[cfg(test)] mod generated_tests {use super::*;#[test] fn every_opcode() {let cases:&[(&str,&[u8],&str)]=&[\n")
	for _, o := range c.Opcodes {
		values := representativeValues(o)
		encoded, err := c.Encode(o.ID, values)
		if err != nil {
			return fmt.Errorf("generated sample %s: %w", o.ID, err)
		}
		data, _ := json.Marshal(values)
		text := o.Mnemonic
		if o.Nullable != nil {
			text = o.ID
		}
		if len(values) > 0 {
			text += " " + string(data)
		}
		var literal strings.Builder
		literal.WriteByte('[')
		for _, v := range encoded {
			fmt.Fprintf(&literal, "%d,", v)
		}
		literal.WriteByte(']')
		fmt.Fprintf(&b, "(%q,&%s,%q),\n", o.ID, literal.String(), text)
	}
	b.WriteString("];for &(id,bytes,text)in cases{let i=decode(bytes).unwrap();assert_eq!(i.opcode.id,id);assert_eq!(i.length,bytes.len());assert_eq!(encode(i.opcode.id,&i.operands).unwrap(),bytes);let a=i.describe();assert_eq!(a.text,i.to_string());assert_eq!(a.operands.len(),i.operands.len());for span in &a.operands{assert!(!a.text[span.start..span.end].is_empty());}let mut template=InstructionTemplate::new(i.opcode.id).unwrap();assert_eq!(template.holes().len(),i.opcode.fields.len());assert!(template.could_match(bytes));assert!(template.match_instruction(bytes).is_some());for(field,value)in i.opcode.fields.iter().zip(&i.operands){template.set(field.name,value.clone()).unwrap();}assert!(template.match_instruction(bytes).is_some());assert!(template.holes().is_empty());assert_eq!(template.encode().unwrap(),bytes);assert_eq!(assemble(text).unwrap(),bytes);assert_eq!(assemble(&i.to_string()).unwrap(),bytes);for n in 0..bytes.len(){assert!(decode(&bytes[..n]).is_err());}}\n")
	b.WriteString("}\n#[test] fn template_and_malformed(){let mut t=InstructionTemplate::new(\"I32Const\").unwrap();assert!(t.encode().is_err());t.set(\"value\",Value::I(-1)).unwrap();assert_eq!(t.encode().unwrap(),[0x41,0x7f]);assert!(t.match_instruction(&[0x41,0]).is_none());let mut call=InstructionTemplate::new(\"Call\").unwrap();call.set(\"function_index\",Value::I(1)).unwrap();assert!(call.match_instruction(&[0x10,1]).is_some());assert!(decode(&[0x41,0x80,0x80,0x80,0x80,0x08]).is_err());}\n}\n")

	if err := os.MkdirAll(filepath.Join(output, "src"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "src", "lib.rs"), b.Bytes(), 0644); err != nil {
		return err
	}
	name := strings.ReplaceAll(c.Architecture, "-", "_") + "_codec"
	if err := os.WriteFile(filepath.Join(output, "Cargo.toml"), []byte(fmt.Sprintf("[package]\nname = %q\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n\n[dependencies]\n", name)), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte("Opcode grammar derived from Bytecode Alliance wasm-tools 0.262.0, commit "+c.SourceCommit+".\n\n"+upstreamLicense), 0644); err != nil {
		return err
	}
	return codec.WriteLicense(output)
}
func rustNullable(p *bool) string {
	if p == nil {
		return "None"
	}
	if *p {
		return "Some(true)"
	}
	return "Some(false)"
}

type InstructionTemplate struct {
	catalog *Catalog
	opcode  *Opcode
	values  []Value
	set     []bool
}

func (c *Catalog) Template(id string) (*InstructionTemplate, error) {
	indexes := c.byName[id]
	if len(indexes) != 1 {
		return nil, fmt.Errorf("wasm: template requires unique instruction ID %q", id)
	}
	o := &c.Opcodes[indexes[0]]
	return &InstructionTemplate{c, o, make([]Value, len(o.Fields)), make([]bool, len(o.Fields))}, nil
}
func (t *InstructionTemplate) Set(name string, v Value) error {
	for i, f := range t.opcode.Fields {
		if f.Name == name {
			if _, e := t.catalog.writeValue(nil, v, f.Kind, t.opcode); e != nil {
				return e
			}
			t.values[i] = cloneTemplateValue(v)
			t.set[i] = true
			return nil
		}
	}
	return fmt.Errorf("wasm: unknown operand %q", name)
}
func (t *InstructionTemplate) Encode() ([]byte, error) {
	for i, ok := range t.set {
		if !ok {
			return nil, fmt.Errorf("wasm: missing operand %s", t.opcode.Fields[i].Name)
		}
	}
	return t.catalog.Encode(t.opcode.ID, t.values)
}

func cloneTemplateValue(v Value) Value {
	items := make([]Value, len(v.Items))
	for i, item := range v.Items {
		items[i] = cloneTemplateValue(item)
	}
	v.Items = items
	return v
}

// Match captures the decoded instruction, checking the opcode and every bound
// operand. Comparison uses canonical operand bytes so equivalent numeric or
// type spellings have the same meaning.
func (t *InstructionTemplate) Match(src []byte) (*Instruction, bool) {
	in, err := t.catalog.Decode(src)
	if err != nil || in.Opcode.ID != t.opcode.ID {
		return nil, false
	}
	for i, fixed := range t.set {
		if !fixed {
			continue
		}
		want, err := t.catalog.writeValue(nil, t.values[i], t.opcode.Fields[i].Kind, t.opcode)
		if err != nil {
			return nil, false
		}
		got, err := t.catalog.writeValue(nil, in.Operands[i], t.opcode.Fields[i].Kind, t.opcode)
		if err != nil || !bytes.Equal(want, got) {
			return nil, false
		}
	}
	return in, true
}

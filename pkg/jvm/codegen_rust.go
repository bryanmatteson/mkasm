package jvm

import (
	_ "embed"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

// GenerateRust writes a standalone, dependency-free Rust crate implementing the
// same bytecode framing and text grammar as this Go backend.
func (c *Catalog) GenerateRust(output string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(output)
		}
	}()

	if len(c.Instructions) != 205 {
		return fmt.Errorf("JVM generation requires complete 205-entry opcode catalog")
	}
	if err := os.MkdirAll(filepath.Join(output, "src"), 0755); err != nil {
		return err
	}
	var table strings.Builder
	table.WriteString("// Generated from OpenJDK bytecode metadata; framing follows JVMS chapter 6.\n")
	table.WriteString("pub static INSTRUCTIONS: &[Definition] = &[\n")
	for _, d := range c.Instructions {
		fmt.Fprintf(&table, " Definition { opcode: %d, mnemonic: %s, source_format: %s, source_wide_format: %s, reserved: %t, operands: &[", d.Opcode, strconv.Quote(d.Mnemonic), strconv.Quote(d.Format), strconv.Quote(d.WideFormat), d.Reserved)
		for _, o := range d.Operands {
			fmt.Fprintf(&table, "OperandDefinition { name: %s, kind: %s, bytes: %d, signed: %t },", strconv.Quote(o.Name), strconv.Quote(o.Kind), o.Bytes, o.Signed)
		}
		table.WriteString("] },\n")
	}
	table.WriteString("];\n")
	table.WriteString("#[cfg(test)] mod generated_tests {use super::*;#[test] fn every_opcode_and_alignment(){let cases:&[(&[u8],u32,&str)]=&[\n")
	for _, d := range c.Instructions {
		if d.Reserved || d.Opcode == 0xc4 {
			continue
		}
		for _, wide := range []bool{false, true} {
			if wide && !wideAllowed(d.Opcode) {
				continue
			}
			for _, offset := range []uint32{0, 1, 2, 3} {
				instruction := representativeInstruction(d, wide)
				encoded, err := c.Encode(instruction, offset)
				if err != nil {
					return err
				}
				decoded, err := c.Decode(encoded, offset)
				if err != nil {
					return err
				}
				var literal strings.Builder
				literal.WriteByte('[')
				for _, v := range encoded {
					fmt.Fprintf(&literal, "%d,", v)
				}
				literal.WriteByte(']')
				fmt.Fprintf(&table, "(&%s,%d,%s),\n", literal.String(), offset, strconv.Quote(decoded.Format()))
			}
		}
	}
	table.WriteString("];for &(bytes,offset,text)in cases{let i=decode(bytes,offset).unwrap();assert_eq!(i.format(),text);assert_eq!(encode(&i,offset).unwrap(),bytes);assert_eq!(assemble(&i.format(),offset).unwrap(),bytes);let a=i.describe();assert_eq!(a.text,i.format());for span in &a.operands{assert!(!a.text[span.start..span.end].is_empty());}let mut t=InstructionTemplate::new(i.mnemonic,i.wide).unwrap();assert!(t.could_match(bytes));assert!(t.match_instruction(bytes,offset).is_some());assert_eq!(t.holes().len(),i.operands.len()+usize::from(i.switch.is_some()));for o in &i.operands{t.set(o.name,o.value).unwrap();}if let Some(s)=&i.switch{t.set_switch(s.clone()).unwrap();}assert!(t.holes().is_empty());assert_eq!(t.encode(offset).unwrap(),bytes);assert_eq!(i.relocated(offset).unwrap(),i);if let Ok(moved)=i.relocated(offset+4){assert_eq!(moved.branch_targets(),i.branch_targets());}for n in 0..bytes.len(){assert_eq!(decode(&bytes[..n],offset),Err(Error::Truncated));}}\n}\n#[test] fn malformed_method(){assert!(decode_method(&[0xa7,0,1]).is_err());assert!(decode(&[0xc4,0x60],0).is_err());assert!(assemble(\"ldc #0\",0).is_err());}\n}\n")

	files := map[string]string{"Cargo.toml": "[package]\nname = \"mkasm_jvm\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n[lib]\npath = \"src/lib.rs\"\n", "src/lib.rs": table.String() + rustRuntime + rustAnalysis, "README.md": "# Generated JVM bytecode codec\n\nDependency-free Rust encoding, decoding, method validation and text assembly.\nBranch operands store signed byte displacements; formatted branch targets are absolute method offsets.\nSwitch text uses JSON after the opcode. Class-file constant-pool indices remain numeric.\nThis codec validates instruction framing and branch boundaries, not JVM stack or type safety.\n"}
	for path, body := range files {
		if err := os.WriteFile(filepath.Join(output, path), []byte(body), 0644); err != nil {
			return err
		}
	}
	return codec.WriteLicense(output)
}

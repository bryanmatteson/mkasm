package cil

import (
	_ "embed"
	"encoding/json"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
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

//go:embed verify.rs.tmpl
var rustVerification string

//go:embed public.rs.tmpl
var rustPublicConsumer string

//go:embed testdata/LICENSE-runtime
var runtimeLicense string

//go:embed testdata/oracle.json
var oracleData []byte

func (c *Catalog) GenerateRust(dir string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(dir)
		}
	}()

	for _, p := range []string{"src", "tests"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0755); err != nil {
			return err
		}
	}
	var table strings.Builder
	table.WriteString("pub static DEFINITIONS: &[Definition] = &[\n")
	for _, d := range c.Definitions {
		fmt.Fprintf(&table, "Definition { opcode: %d, mnemonic: %s, id: %s, size: %d, operand: %s, operand_kind: %s, pop: %s, push: %s, pop_count: %d, push_count: %d, kind: %s, flow: %s, prefix: %t },\n", d.Opcode, strconv.Quote(d.Mnemonic), strconv.Quote(d.ID), d.Size, strconv.Quote(d.Operand), strconv.Quote(d.OperandKind), strconv.Quote(d.Pop), strconv.Quote(d.Push), d.PopCount, d.PushCount, strconv.Quote(d.Kind), strconv.Quote(d.Flow), d.Prefix)
	}
	table.WriteString("];\npub static ALIASES: &[(&str,u16)] = &[\n")
	names := make([]string, 0, len(c.Aliases))
	for n := range c.Aliases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&table, "(%s,%d),\n", strconv.Quote(n), c.Aliases[n])
	}
	table.WriteString("];\n")
	var fixtures struct {
		Encodings []struct {
			Code  uint16
			Bytes string
		}
		Methods        []struct{ Name, Body string }
		DynamicMethods []struct{ Name, IL string }
	}
	if e := json.Unmarshal(oracleData, &fixtures); e != nil {
		return e
	}
	table.WriteString("#[cfg(test)] mod corpus { use super::*;\nfn bytes(s:&str)->Vec<u8>{(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}\n#[test] fn reflection_emit_all_public_opcodes(){ let cases: &[(u16,&str)] = &[\n")
	n := 0
	for _, x := range fixtures.Encodings {
		if c.Definition(x.Code) == nil {
			continue
		}
		n++
		fmt.Fprintf(&table, "(%d,%s),\n", x.Code, strconv.Quote(x.Bytes))
	}
	fmt.Fprintf(&table, "]; assert_eq!(cases.len(),%d); assert_eq!(cases.len(),DEFINITIONS.len()); for &(op,s) in cases {let b=bytes(s);for offset in [0,65536] {let x=decode(&b,offset).unwrap(); assert_eq!(x.opcode,op); assert_eq!(x.length,b.len()); assert_eq!(encode(&x,offset).unwrap(),b); assert_eq!(assemble(&format(&x).unwrap(),offset).unwrap(),b); let a=x.describe().unwrap();assert_eq!(a.text,format(&x).unwrap());for span in &a.operands{assert_eq!(span.value,x.operand);assert!(!a.text[span.start..span.end].is_empty());}assert_eq!(x.relocated(offset).unwrap(),x);if let Ok(moved)=x.relocated(offset+1){assert_eq!(moved.branch_targets(),x.branch_targets());}let mut edited=x.clone();edited.set_operand(x.operand.clone()).unwrap();assert_eq!(edited,x);let mut t=Template::new(definition(op).unwrap().mnemonic).unwrap();assert_eq!(t.holes().len(),usize::from(x.operand!=Operand::None));assert!(t.could_match(&b)); assert_eq!(t.encode(Some(x.operand.clone()),offset).unwrap(),b);assert!(t.matches(&b,offset).is_some());t.bind(x.operand.clone()).unwrap();assert_eq!(t.encode(None,offset).unwrap(),b); for n in 0..b.len(){assert!(decode(&b[..n],offset).is_err());}}}}\n", n)
	table.WriteString("#[test] fn compiled_method_bodies(){let cases: &[(&str,&str)] = &[\n")
	for _, x := range fixtures.Methods {
		fmt.Fprintf(&table, "(%s,%s),\n", strconv.Quote(x.Name), strconv.Quote(x.Body))
	}
	table.WriteString("];for &(name,s) in cases {let b=bytes(s);let body=decode_method_body(&b).unwrap_or_else(|e|panic!(\"{}: {}\",name,e));assert_eq!(body.length,b.len());assert_eq!(encode_method_body(&body).unwrap(),b); let ins=decode_method(&body.code).unwrap();assert_eq!(assemble_method(&format_method(&ins).unwrap()).unwrap(),body.code);for n in 0..b.len(){assert!(decode_method_body(&b[..n]).is_err(),\"{} {}\",name,n);}}}\n#[test] fn executed_prefix_methods(){for s in [")
	for _, x := range fixtures.DynamicMethods {
		fmt.Fprintf(&table, "%s,", strconv.Quote(x.IL))
	}
	table.WriteString("]{let b=bytes(s);assert_eq!(encode_method(&decode_method(&b).unwrap()).unwrap(),b);}}\n}\n")
	files := map[string]string{"Cargo.toml": "[package]\nname = \"mkasm-cil\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n[lib]\npath = \"src/lib.rs\"\n", "src/lib.rs": strings.Replace(rustRuntime, "// TABLES", table.String(), 1) + rustAnalysis + rustVerification, "LICENSE": runtimeLicense, "NOTICE": "CIL opcode definitions derived from dotnet/runtime, MIT license.\nPinned revision: " + RuntimeRevision + "\nhttps://github.com/dotnet/runtime/blob/" + RuntimeRevision + "/src/coreclr/inc/opcode.def\nMethod body format: ECMA-335, sixth edition (2012), Partition II section 25.4.\nOracle: .NET SDK 10.0.401, System.Reflection.Emit and System.Reflection.Metadata.\n", "README.md": generatedReadme, "tests/public.rs": rustPublicConsumer}
	for p, s := range files {
		if e := os.WriteFile(filepath.Join(dir, p), []byte(s), 0644); e != nil {
			return e
		}
	}
	return nil
}

const generatedReadme = `# CIL bytecode codec

A standalone Rust library with no dependencies. Run cargo test --lib for the pinned
218-opcode Reflection.Emit corpus and real compiled method-body fixtures.

Public APIs: definitions/lookup; decode/encode; format/assemble;
decode_method/encode_method and format_method/assemble_method; reusable Template;
decode_method_body/encode_method_body with tiny/fat headers and small/fat EH.

Operand float variants carry exact bits; branch and switch values are displacements
from the end of the whole instruction. Text uses absolute IL_ labels and bit literals.
Method validation checks instruction boundaries, prefix groups, token categories,
branch destinations and structural EH bounds. It does not resolve metadata, infer
maxstack, verify stack/type safety, relax branches, or execute managed code. The
surrounding PE/CLI metadata and symbolic resolution belong to a module consumer.
Unknown/reserved opcodes and sections are rejected; lossless accepted method bodies
retain section width, chain, and alignment padding. No opcode FE19 is synthesized:
it is reserved in the pinned runtime's public table.
`

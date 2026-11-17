package spirv

import (
	"bytes"
	_ "embed"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed testdata/LICENSE
var grammarLicense string

// GenerateRust emits a dependency-free Rust crate with the complete imported
// instruction and operand grammar, structured codec, text assembler and tests.
func (c *Catalog) GenerateRust(output string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(output)
		}
	}()

	if output == "" {
		return fmt.Errorf("empty output directory")
	}
	if len(c.Instructions) > 1<<16 {
		return fmt.Errorf("SPIR-V opcode index exceeds 16-bit catalog capacity")
	}
	if err := os.MkdirAll(filepath.Join(output, "src"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(output, "examples"), 0755); err != nil {
		return err
	}
	var b bytes.Buffer
	b.WriteString(rustRuntime + rustAnalysis)
	fmt.Fprintf(&b, "\npub const GRAMMAR_MAJOR:u32=%d;\npub const GRAMMAR_MINOR:u32=%d;\n", c.Major, c.Minor)
	b.WriteString("pub static DEFINITIONS:&[Definition]=&[\n")
	for _, d := range c.Instructions {
		fmt.Fprintf(&b, "Definition{name:%s,opcode:%d,aliases:%s,operands:%s,requirements:%s},\n", strconv.Quote(d.Name), d.Opcode, rustStrings(d.Aliases), rustSpecs(d.Operands), rustReq(d.Requirements))
	}
	b.WriteString("];\nstatic OPCODE_INDEX:&[(u16,u16)]=&[\n")
	indices := make([]int, len(c.Instructions))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool { return c.Instructions[indices[i]].Opcode < c.Instructions[indices[j]].Opcode })
	for _, i := range indices {
		fmt.Fprintf(&b, "(%d,%d),\n", c.Instructions[i].Opcode, i)
	}
	b.WriteString("];\nstatic KINDS:&[Kind]=&[\n")
	for _, k := range c.OperandKinds {
		category := map[string]int{"Id": 0, "Literal": 1, "Composite": 2, "BitEnum": 3, "ValueEnum": 4}[k.Category]
		fmt.Fprintf(&b, "Kind{name:%s,category:%d,bases:%s,enumerants:&[", strconv.Quote(k.Kind), category, rustStrings(k.Bases))
		for _, e := range k.Enumerants {
			fmt.Fprintf(&b, "Enumerant{name:%s,value:%d,aliases:%s,parameters:%s,requirements:%s},", strconv.Quote(e.Name), e.Number, rustStrings(e.Aliases), rustSpecs(e.Parameters), rustReq(e.Requirements))
		}
		b.WriteString("]},\n")
	}
	b.WriteString("];\n")
	b.WriteString(rustTests)
	for path, data := range map[string][]byte{"Cargo.toml": []byte("[package]\nname = \"mkasm-spirv\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n\n[lib]\npath = \"src/lib.rs\"\n"), "src/lib.rs": b.Bytes(), "LICENSE-SPIRV-Headers": []byte(grammarLicense), "examples/roundtrip.rs": []byte(`use mkasm_spirv::{decode_module,encode_module,format_instruction};
fn main(){let args:Vec<_>=std::env::args().collect();if args.len()!=3{eprintln!("usage: roundtrip input.spv output.spv");std::process::exit(2)}let data=std::fs::read(&args[1]).expect("read module");let module=decode_module(&data).expect("decode module");for i in &module.instructions{println!("{}",format_instruction(i).expect("format instruction"))}std::fs::write(&args[2],encode_module(&module).expect("encode module")).expect("write module");}
`)} {
		if err := os.WriteFile(filepath.Join(output, path), data, 0644); err != nil {
			return err
		}
	}
	return codec.WriteLicense(output)
}
func rustStrings(values []string) string {
	var b bytes.Buffer
	b.WriteString("&[")
	for _, s := range values {
		b.WriteString(strconv.Quote(s))
		b.WriteByte(',')
	}
	b.WriteByte(']')
	return b.String()
}
func rustSpecs(specs []OperandSpec) string {
	var b bytes.Buffer
	b.WriteString("&[")
	for _, s := range specs {
		quant := 0
		if s.Quantifier == "?" {
			quant = 1
		}
		if s.Quantifier == "*" {
			quant = 2
		}
		fmt.Fprintf(&b, "Spec{kind:%s,quant:%d},", strconv.Quote(s.Kind), quant)
	}
	b.WriteByte(']')
	return b.String()
}
func rustReq(r Requirements) string {
	v := version(r.Version)
	if r.Version == "None" {
		v = ^uint32(0)
	}
	return fmt.Sprintf("Requirement{version:%d,last:%d,capabilities:%s,extensions:%s}", v, version(r.LastVersion), rustStrings(r.Capabilities), rustStrings(r.Extensions))
}

const rustTests = `
#[cfg(test)]mod generated_tests{
use super::*;
#[test]fn opcode_index_matches_catalog(){for op in 0..=u16::MAX{let expected=DEFINITIONS.iter().find(|d|d.opcode==op);let actual=definition(op);assert!(match(expected,actual){(Some(a),Some(b))=>std::ptr::eq(a,b),(None,None)=>true,_=>false},"opcode {op}");}}
#[test]fn byte_decode_word_storage_boundaries(){for n in [1,48,49,52,53,64,4096]{let text="x".repeat(n);let line=format!("%1 = OpString {:?}",text);let i=assemble(&line,None,None).unwrap();let b=encode(&i,None,None).unwrap();let(d,length)=decode(&b,None,None).unwrap();assert_eq!(d,i);assert_eq!(length,b.len());assert_eq!(encode(&d,None,None).unwrap(),b);for prefix in [0,3,b.len()-1]{assert!(decode(&b[..prefix],None,None).is_err());}}}
fn sample(name:&str,extra:bool)->Operand{let k=kind(name).unwrap();let mut o=Operand::empty(name);if name=="LiteralString"{o.text="hello π \\\"".into()}else if k.category==2{for b in k.bases{o.parameters.push(sample(b,extra))}}else if k.category==0{o.words.push(1)}else if k.category==3||k.category==4{let e=&k.enumerants[0];o.words.push(e.value);for s in e.parameters{if s.quant==0||extra{o.parameters.push(sample(s.kind,extra))}}}else if name=="LiteralSpecConstantOpInteger"{o.words.push(128);o.parameters.push(sample("IdRef",false));o.parameters.push(sample("IdRef",false));}else{o.words.push(0)}o}
#[test]fn complete_instruction_grammar(){let mut count=0;for d in DEFINITIONS{for extra in [false,true]{let mut operands=vec![];for s in d.operands{if s.quant!=0&&!extra{continue}operands.push(sample(s.kind,extra));if extra&&s.quant==2{operands.push(sample(s.kind,extra))}}let i=Instruction{opcode:d.opcode,operands};let b=encode(&i,None,None).unwrap_or_else(|e|panic!("{}: {}",d.name,e));let(j,n)=decode(&b,None,None).unwrap();assert_eq!(n,b.len());assert_eq!(i,j);let text=format_instruction(&i).unwrap();let j=assemble(&text,None,None).unwrap_or_else(|e|panic!("{}: {}",text,e));assert_eq!(i,j);let a=i.describe().unwrap();assert_eq!(a.text,text);for span in &a.operands{assert_eq!(span.value,i.operands[span.index]);assert!(!a.text[span.start..span.end].is_empty());}let names=(0..i.operands.len()).map(|n|format!("op{n}")).collect::<Vec<_>>();let holes=names.iter().enumerate().map(|(n,name)|(n,name.as_str())).collect::<Vec<_>>();let t=InstructionTemplate::new(i.clone(),&holes).unwrap();assert_eq!(t.holes().len(),i.operands.len());assert!(t.could_match(&b));let (captures,length)=t.match_bytes(&b,None,None).unwrap();assert_eq!(length,b.len());assert_eq!(t.encode(&captures,None,None).unwrap(),b);count+=1;}}assert_eq!(count,DEFINITIONS.len()*2);}
#[test]fn complete_enumerant_grammar(){for k in KINDS{for e in k.enumerants{let mut o=Operand::scalar(k.name,e.value);for s in e.parameters{o.parameters.push(sample(s.kind,true))}let w=operand_words(&o).unwrap();let d=Decoder{env:None,number_words:0,switch_words:1};let(p,n)=d.one(k.name,&w,0).unwrap_or_else(|error|panic!("{}.{}: {}",k.name,e.name,error));assert_eq!(n,w.len());assert_eq!(o,p);}}}
#[test]fn wide_context_and_invalid_input(){let mut c=Context::default();for line in ["%1 = OpTypeInt 64 0","%2 = OpConstant %1 18446744073709551615","OpSwitch %2 %4 0x1122334455667788 %5","%6 = OpSpecConstantOp %1 IAdd %2 %2","%7 = OpLoad %1 %8 Aligned 16","OpDecorate %1 LinkageAttributes \"x\" Export"]{let i=assemble(line,Some(&c),None).unwrap();let b=encode(&i,Some(&c),None).unwrap();let(j,_)=decode(&b,Some(&c),None).unwrap();assert_eq!(i,j);c.observe(&i);}for b in [vec![],vec![0,0,0,0],vec![0,0,2,0],vec![255,255,1,0],vec![5,0,3,0,1,0,0,0,65,0,1,0]]{assert!(decode(&b,None,None).is_err());}assert!(assemble("OpName %0 \"x\"",None,None).is_err());}
#[test]fn module_roundtrip(){let lines=["OpCapability Shader","OpMemoryModel Logical GLSL450","OpEntryPoint GLCompute %4 \"main\"","OpExecutionMode %4 LocalSize 1 1 1","%1 = OpTypeVoid","%2 = OpTypeFunction %1","%4 = OpFunction %1 None %2","%5 = OpLabel","OpReturn","OpFunctionEnd"];let mut c=Context::default();let mut instructions=vec![];for line in lines{let i=assemble(line,Some(&c),None).unwrap();c.observe(&i);instructions.push(i)}let m=Module{version:0x10600,generator:0,bound:6,instructions};let b=encode_module(&m).unwrap();let n=decode_module(&b).unwrap();assert_eq!(encode_module(&n).unwrap(),b);}
#[test]fn masks_symbols_and_requirements(){
 for k in KINDS{if k.category!=3{continue}let mask=k.enumerants.iter().fold(0,|v,e|v|e.value);let mut o=Operand::scalar(k.name,mask);for s in enum_parameters(k,mask,None).unwrap(){o.parameters.push(sample(s.kind,true));}let w=operand_words(&o).unwrap();let d=Decoder{env:None,number_words:0,switch_words:1};let(p,n)=d.one(k.name,&w,0).unwrap();assert_eq!(n,w.len());assert_eq!(o,p);}
 let text="OpCapability Shader\nOpMemoryModel Logical GLSL450\nOpEntryPoint GLCompute %main \"main\"\nOpExecutionMode %main LocalSize 1 1 1\n%void = OpTypeVoid\n%fn = OpTypeFunction %void\n%main = OpFunction %void None %fn\n%entry = OpLabel\nOpReturn\nOpFunctionEnd";
 let m=assemble_module(text,0x10600,0).unwrap();let a=encode_module(&m).unwrap();let b=encode_module(&assemble_module(&format_module(&m).unwrap(),0x10600,0).unwrap()).unwrap();assert_eq!(a,b);
 let mut bad=m.clone();bad.instructions.remove(0);assert!(validate_requirements(&bad).is_err());assert!(assemble_module("%0 = OpTypeVoid",0x10600,0).is_err());
 let mut c=Context::default();let t=assemble("%1 = OpTypeFloat 16",Some(&c),None).unwrap();c.observe(&t);let i=assemble("%2 = OpConstant %1 1.5",Some(&c),None).unwrap();assert_eq!(i.operands[2].words,vec![0x3e00]);
}

}
`

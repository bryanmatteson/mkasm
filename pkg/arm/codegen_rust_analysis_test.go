package arm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRustAnalysisIdentityAndCandidateBuckets(t *testing.T) {
	c := &Catalog{Entries: []CatalogEntry{{EncodingID: "base", AsmMnemonic: "ORR", Mask: 0xff000000, Value: 0xaa000000}, {EncodingID: "alias", AsmMnemonic: "MOV", AliasOf: "base", Mask: 0xff000000, Value: 0xaa000000}}}
	d := buildRustAnalysisData(c, &DisasmSurface{Forms: []DisasmForm{{EncodingID: "base"}, {EncodingID: "alias"}}})
	if !strings.Contains(d.Identities, `("alias", "base", "ORR", "MOV")`) {
		t.Fatal(d.Identities)
	}
	orphan := buildRustAnalysisData(&Catalog{Entries: []CatalogEntry{{EncodingID: "orphan", AsmMnemonic: "ALIAS", AliasOf: "missing"}}})
	if !strings.Contains(orphan.Identities, `("orphan", "missing", "", "ALIAS")`) {
		t.Fatal(orphan.Identities)
	}
	tables := strings.Split(d.Buckets, "static BUCKET_FORMS")
	parse := func(text string) []int {
		t.Helper()
		text = text[strings.Index(text, "&[")+2:]
		text = text[strings.Index(text, "&[")+2:]
		var values []int
		for _, token := range regexp.MustCompile(`[0-9]+`).FindAllString(text, -1) {
			n, err := strconv.Atoi(token)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, n)
		}
		return values
	}
	if len(tables) != 2 {
		t.Fatal(d.Buckets)
	}
	offsets, ids := parse(tables[0]), parse(tables[1])
	if len(offsets) != 4097 || len(ids) != 32 {
		t.Fatalf("bucket sizes: %d offsets, %d IDs", len(offsets), len(ids))
	}
	for bucket := 0; bucket < 4096; bucket++ {
		got := ids[offsets[bucket]:offsets[bucket+1]]
		if bucket >= 0xaa0 && bucket <= 0xaaf {
			if len(got) != 2 || got[0] != 0 || got[1] != 1 {
				t.Fatalf("bucket %x: %v", bucket, got)
			}
		} else if len(got) != 0 {
			t.Fatalf("unexpected bucket %x: %v", bucket, got)
		}
	}

}

// These integration checks use the production parser/generator and compile the actual full
// generated crates. Corpus paths are supplied explicitly to avoid network access
// in normal unit tests; run with MKASM_CORPUS and MKASM_ARM32_CORPUS.
func TestRustAnalysisRealCorpus(t *testing.T) {
	for _, tc := range []struct{ name, arch, env, source string }{{"a64", "aarch64", "MKASM_CORPUS", rustAnalysisA64Behavior}, {"a32", "arm32", "MKASM_ARM32_CORPUS", rustAnalysisA32Behavior}} {
		t.Run(tc.name, func(t *testing.T) {
			corpus := os.Getenv(tc.env)
			if corpus == "" {
				t.Skip("set " + tc.env + " to run compiled full-corpus analysis tests")
			}
			corpus, err := filepath.Abs(corpus)
			if err != nil {
				t.Fatal(err)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(home, "Documents", "Developer", "go-mkasm")
			if err = os.MkdirAll(base, 0755); err != nil {
				t.Fatal(err)
			}
			var out string
			if durable := os.Getenv("MKASM_ANALYSIS_OUTPUT"); durable != "" {
				out = filepath.Join(durable, tc.name)
				if err = os.MkdirAll(out, 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				out, err = os.MkdirTemp(base, "analysis-"+tc.name+"-test-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(out) })
			}
			run := func(dir, name string, args ...string) {
				t.Helper()
				cmd := exec.Command(name, args...)
				cmd.Dir = dir
				if b, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s %v: %v\n%s", name, args, err, b)
				}
			}
			source, err := OpenTarXMLCorpus(context.Background(), corpus)
			if err != nil {
				t.Fatal(err)
			}
			arch, err := ParseArch(tc.arch)
			if err != nil {
				t.Fatal(err)
			}
			parser := NewARMParser(ARMParserConfig{Corpus: source, EncodingIndexPath: arch.SpecIndexFile(), Arch: arch, Languages: []CodegenLang{LangRust}, OutputDirectory: out, GenerateTests: true})
			defer parser.Close(time.Second)
			if err = parser.Parse(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(out, "tests", "analysis.rs"), []byte(tc.source), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.arch == "arm32" {
				run(out, "cargo", "test", "--lib", "--test", "analysis", "--", "--test-threads=1")
			} else {
				run(out, "cargo", "test", "--test", "analysis", "--", "--test-threads=1")
			}
		})
	}
}

const rustAnalysisA64Behavior = `use aarch64::analysis::*;
#[test] fn compare_branches_retain_typed_relations_operands_width_and_flow(){
 for (base,width,immediate) in [(0x74000000,32,false),(0xf4000000,64,false),(0x74008000,8,false),(0x7400c000,16,false),(0x75000000,32,true),(0xf5000000,64,true)] {
  for cc in [0,1,2,3,6,7] { for literal in [0,31,32,63] {
   let word=base|cc<<21|if immediate{literal<<15}else{2<<16}|2<<5|31;
   let a=analyze(word,0x1000).unwrap();let flow=a.control_flow;
   assert_eq!(a.coverage,Coverage::Complete,"{word:08x}: {a:?}");assert_eq!(flow.kind,FlowKind::Branch);assert_eq!(flow.target,Some(BranchTarget::Direct(Some(0x1008))));assert_eq!(flow.fallthrough,Some(0x1004));
   let Predicate::RegisterCompare{left,right,width:bits,signed,relation}=flow.predicate else {panic!("{word:08x}: {:?}",flow.predicate)};
   assert_eq!((left.number,left.width,left.role,bits,signed),(31,Some(u16::from(width)),RegisterRole::Zero,width,cc<2));
   match right {CompareOperand::Immediate(value)=>{assert!(immediate);assert_eq!(value,u64::from(literal))},CompareOperand::Register(register)=>{assert!(!immediate);assert_eq!((register.number,register.width),(2,Some(u16::from(width))));}}
   assert_eq!(relation,match cc{0|2=>CompareRelation::GreaterThan,1|3 if immediate=>CompareRelation::LessThan,1|3=>CompareRelation::GreaterOrEqual,6=>CompareRelation::Equal,7=>CompareRelation::NotEqual,_=>unreachable!()});
  }}
 }
 let hbc=analyze(0x54000050,0x1000).unwrap().control_flow;assert_eq!(hbc.kind,FlowKind::Branch);assert_eq!(hbc.predicate,Predicate::Condition(0));assert_eq!(hbc.target,Some(BranchTarget::Direct(Some(0x1008))));assert_eq!(hbc.fallthrough,Some(0x1004));
}
#[test] fn public_register_parser_keeps_bank_bounds_and_complete_names(){
 use aarch64::{parse_register,OperandClass as C};
 for (class,text,expected) in [(C::Gpr64,"x30",Some(30)),(C::Gpr64,"lr",Some(30)),(C::Gpr64,"xzr",Some(31)),(C::Gpr64Sp,"sp",Some(31)),(C::Gpr64,"sp",None),(C::Gpr64,"x31",None),(C::Gpr64,"x0junk",None),(C::Gpr64,"x1, x2",None)] {assert_eq!(parse_register(class,text),expected,"{text}");}
}
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicUsize,Ordering};
struct Alloc;static COUNT:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Alloc {unsafe fn alloc(&self,l:Layout)->*mut u8{COUNT.fetch_add(1,Ordering::Relaxed);unsafe{System.alloc(l)}}unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}}
#[global_allocator]static ALLOC:Alloc=Alloc;
fn a(w:u32)->Analysis{analyze(w,0x1000).unwrap()}
#[test]fn structured_real_words(){
 let alias=a(0xaa0103e0);assert_eq!(alias.canonical.mnemonic,"ORR");assert_ne!(alias.canonical.encoding_id,alias.display.encoding_id);
 let sp=a(0x910023e0);assert!(sp.components().iter().any(|c|matches!(c.value,Value::Register(Register{number:31,role:RegisterRole::StackPointer,..}))));
 let zr=a(0xaa1f03e0);assert!(zr.components().iter().any(|c|matches!(c.value,Value::Register(Register{number:31,role:RegisterRole::Zero,..}))));
 for (word,mode,displacement,post) in [(0xf9400be0,IndexMode::Offset,16,None),(0xf8410fe0,IndexMode::PreIndex,16,None),(0xf84107e0,IndexMode::PostIndex,0,Some(Value::Integer(16)))]{
  let m=a(word).memory.unwrap();assert_eq!(m.mode,mode,"{word:x}");assert_eq!(m.displacement,displacement);assert_eq!(m.post_index,post);assert_eq!(m.base.unwrap().role,RegisterRole::StackPointer);assert_eq!(m.writeback,mode!=IndexMode::Offset);
 }
 let m=a(0xf862d820).memory.unwrap();assert_eq!(m.index.unwrap().width,Some(32));assert_eq!(m.modifier,Some("SXTW"));assert_eq!(m.amount,Some(3));
 let branch=a(0x17ffffff).control_flow;assert_eq!(branch.kind,FlowKind::Branch);assert_eq!(branch.target,Some(BranchTarget::Direct(Some(0xffc))));assert_eq!(branch.fallthrough,None);
 assert_eq!(a(0x54000040).control_flow.predicate,Predicate::Condition(0));assert_eq!(a(0x54000040).control_flow.fallthrough,Some(0x1004));
 assert_eq!(a(0x5400004e).control_flow.fallthrough,None);
 assert_eq!(a(0x94000002).control_flow.kind,FlowKind::Call);assert_eq!(a(0x94000002).control_flow.fallthrough,Some(0x1004));
 assert!(matches!(a(0xb4000040).control_flow.predicate,Predicate::RegisterZero{nonzero:false,..}));
 assert!(matches!(a(0xb7f80041).control_flow.predicate,Predicate::RegisterBit{bit:63,nonzero:true,..}));assert_eq!(a(0xd65f03c0).control_flow.kind,FlowKind::Return);
 let lane=a(0x0e073c20);assert!(lane.memory.is_none());assert!(lane.components().iter().any(|c|c.lane==Some(3)));assert!(lane.components().iter().any(|c|c.symbol.contains("index")&&c.value==Value::Integer(3)));
 let vector=a(0x4e228420);assert!(vector.components().iter().any(|c|c.arrangement==Some("16B")));assert!(vector.components().iter().any(|c|c.value==Value::Symbol("16B")));
 let list=a(0x4c40a020);assert_eq!(list.register_lists().next().unwrap().count,2);assert_eq!(list.components().iter().filter(|c|matches!((c.location,c.value),(Location::RegisterList(_),Value::Register(_)))).count(),2);
 let prefetch=a(0xf980003f);assert!(prefetch.components().iter().any(|c|c.value==Value::Integer(31)));
 let predicate=a(0x2518e3e0);assert!(predicate.components().iter().any(|c|matches!(c.value,Value::Register(Register{role:RegisterRole::Predicate,..}))));
 assert_eq!(analyze(0x14000001,u64::MAX).unwrap().control_flow.target,Some(BranchTarget::Direct(None)));
 // MOPS has two separate updating addresses and a count register, not a post-index offset.
 let copy=a(0x1901c440);assert_eq!(copy.coverage,Coverage::Complete);assert!(copy.memory.is_none());
 assert_eq!(copy.memory_addresses().len(),2);
 for (id,base) in [(0,0),(1,1)]{let m=copy.memory_address(id).unwrap();assert_eq!(m.id,id);assert_eq!(m.base.unwrap().number,base);assert_eq!(m.mode,IndexMode::Updating);assert!(m.writeback);assert!(m.post_index.is_none());}
 assert_eq!(copy.components().iter().map(|c|c.memory_id).collect::<Vec<_>>(),vec![Some(0),Some(1),None]);
 assert!(copy.components().iter().all(|c|c.writeback));assert_eq!(copy.components()[2].location,Location::Operand);
 // Ordinary addressing and its component identity still agree with the singular convenience view.
 let ordinary=a(0xf84107e0);assert_eq!(ordinary.memory_addresses(),&[ordinary.memory.unwrap()]);assert!(ordinary.components().iter().filter(|c|matches!(c.location,Location::Memory|Location::PostIndex)).all(|c|c.memory_id==Some(0)));
 // Fresh analysis must not initialize the text assembler's allocating caches.
 let before=COUNT.load(Ordering::Relaxed);for word in [0xaa0103e0,0xf84107e0,0x0e073c20,0x4c40a020,0x2518e3e0,0x1901c440]{std::hint::black_box(a(word));}assert_eq!(COUNT.load(Ordering::Relaxed),before);
}
`
const rustAnalysisA32Behavior = `use arm32::{decode,Mode,Endian,Register};use arm32::analysis::*;
use std::alloc::{GlobalAlloc,Layout,System};use std::sync::atomic::{AtomicUsize,Ordering};
struct Alloc;static COUNT:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Alloc {unsafe fn alloc(&self,l:Layout)->*mut u8{COUNT.fetch_add(1,Ordering::Relaxed);unsafe{System.alloc(l)}}unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}}
#[global_allocator]static ALLOC:Alloc=Alloc;

fn a(w:u32)->Analysis{decode(&w.to_le_bytes(),Mode::Arm,Endian::Little).unwrap().analyze(0x1000)}
#[test]fn structured_real_words(){
 for (word,mode,displacement,post) in [(0xe5910004,IndexMode::Offset,4,None),(0xe5b10004,IndexMode::PreIndex,4,None),(0xe4910004,IndexMode::PostIndex,0,Some(4))]{let m=a(word).memory.unwrap();assert_eq!(m.base,Some(Register::Gpr(1)));assert_eq!(m.mode,mode,"{word:x}");assert_eq!(m.displacement,displacement);assert_eq!(m.post_index,post);}
 assert_eq!(a(0xea000000).control_flow.target,Some(BranchTarget::Direct(0x1008)));assert_eq!(a(0x1a000000).control_flow.predicate,Predicate::Condition(1));assert_eq!(a(0xe12fff1e).control_flow.kind,FlowKind::Return);
 let stack=a(0xe92d4010).memory.unwrap();assert_eq!(stack.base,Some(Register::Gpr(13)));assert_eq!(stack.block,Some(BlockMode::DecrementBefore));assert_eq!(stack.displacement,-8);assert!(stack.writeback);
 assert!(a(0xe92d4010).components().iter().any(|c|c.value==Value::RegisterMask(0x4010)));
 assert_eq!(a(0xe8bd8010).control_flow.kind,FlowKind::Return);
 let lane=a(0xf4a0000f);assert!(lane.components().iter().any(|c|c.lane==Some(0)));assert!(lane.memory.is_some());
 let vector=a(0xf4622aef);assert!(vector.components().iter().any(|c|matches!(c.value,Value::RegisterSequence{first:Register::D(18),count:2,..})));
 let thumb=decode(&[0x00,0x30],Mode::Thumb,Endian::Little).unwrap();assert_eq!(thumb.analyze(0).control_flow.predicate,Predicate::ThumbItStateRequired);assert_eq!(thumb.analyze_with_thumb_condition(0,Some(14)).control_flow.predicate,Predicate::Always);assert_eq!(thumb.analyze_with_thumb_condition(0,Some(1)).control_flow.predicate,Predicate::Condition(1));
 let branch=decode(&[0xfe,0xd1],Mode::Thumb,Endian::Little).unwrap().analyze(0x1000);assert_eq!(branch.control_flow.predicate,Predicate::Condition(1));assert_eq!(branch.control_flow.target,Some(BranchTarget::Direct(0x1000)));
 let call=decode(&[0,0xf0,0,0xf8],Mode::Thumb,Endian::Little).unwrap().analyze_with_thumb_condition(0x1000,Some(14));assert_eq!(call.control_flow.kind,FlowKind::Call);assert_eq!(call.control_flow.target,Some(BranchTarget::Direct(0x1004)));
}
fn t(w:u32)->Analysis{decode(&[(w>>16)as u8,(w>>24)as u8,w as u8,(w>>8)as u8],Mode::Thumb,Endian::Little).unwrap().analyze_with_thumb_condition(0x1000,Some(14))}
#[test]fn memory_roles_do_not_fabricate_offsets(){
 for (word,shift) in [(0xe7910102,arm32::Shift::Lsl(2)),(0xe7910122,arm32::Shift::Lsr(2)),(0xe7910142,arm32::Shift::Asr(2)),(0xe7910162,arm32::Shift::Ror(2)),(0xe7910062,arm32::Shift::Rrx)]{
  let result=a(word);assert_eq!(result.coverage,Coverage::Complete);let m=result.memory.unwrap();assert_eq!(m.displacement,0,"{word:x}");assert_eq!(m.shift,shift);assert_eq!(m.index,Some(Register::Gpr(2)));
 }
 let m=t(0xf8510022).memory.unwrap();assert_eq!(m.displacement,0);assert_eq!(m.shift,arm32::Shift::Lsl(2));
 let m=a(0xf420071f).memory.unwrap();assert_eq!(m.displacement,0);assert_eq!(m.alignment_bits,Some(64));assert_eq!(a(0xf420070f).memory.unwrap().alignment_bits,None);
 for (word,shift,subtract) in [(0xe6910102,arm32::Shift::Lsl(2),false),(0xe6910122,arm32::Shift::Lsr(2),false),(0xe6110162,arm32::Shift::Ror(2),true)]{
  let result=a(word);assert_eq!(result.coverage,Coverage::Complete);let m=result.memory.unwrap();assert_eq!(m.mode,IndexMode::PostIndex);assert!(m.writeback);assert_eq!(m.post_register,Some(Register::Gpr(2)));assert_eq!(m.post_index,None);assert_eq!(m.index,None);assert_eq!(m.displacement,0);assert_eq!(m.shift,shift);assert_eq!(m.subtract,subtract);
 }
}
#[test]fn exception_returns_keep_address_mode_and_control(){
 for (word,block,displacement) in [(0xf8100a00,BlockMode::DecrementAfter,-4),(0xf9100a00,BlockMode::DecrementBefore,-8),(0xf8900a00,BlockMode::IncrementAfter,0),(0xf9900a00,BlockMode::IncrementBefore,4)]{
  for wb in [false,true]{let result=a(word|if wb{1<<21}else{0});assert_eq!(result.coverage,Coverage::Complete,"{word:x}");let f=result.control_flow;assert_eq!(f.kind,FlowKind::Return);assert!(f.exception_return);assert!(f.exchanges_instruction_set);assert_eq!(f.target,Some(BranchTarget::Memory));assert_eq!(f.fallthrough,None);let m=result.memory.unwrap();assert_eq!(m.block,Some(block));assert_eq!(m.displacement,displacement);assert_eq!(m.writeback,wb);assert_eq!(m.base,Some(Register::Gpr(0)));assert_eq!(m.post_index,if wb{Some(if matches!(block,BlockMode::IncrementBefore|BlockMode::IncrementAfter){8}else{-8})}else{None});}
 }
 for (word,block) in [(0xe811c000,BlockMode::DecrementBefore),(0xe991c000,BlockMode::IncrementAfter)]{let result=t(word);assert_eq!(result.coverage,Coverage::Complete);assert!(result.control_flow.exception_return);assert_eq!(result.control_flow.kind,FlowKind::Return);assert_eq!(result.memory.unwrap().block,Some(block));}
}
#[test]fn analysis_stays_allocation_free_with_address_and_control_metadata(){
 let before=COUNT.load(Ordering::Relaxed);for word in [0xe7910122,0xf420071f,0xe6910102,0xf9100a00]{std::hint::black_box(a(word));}for word in [0xe8d1f002,0xe8d1f012,0xf8510022]{std::hint::black_box(t(word));}assert_eq!(COUNT.load(Ordering::Relaxed),before);
}
#[test]fn table_branches_keep_table_and_target_scaling(){
 for (word,bits,shift) in [(0xe8d1f002,8,arm32::Shift::Lsl(0)),(0xe8d1f012,16,arm32::Shift::Lsl(1))]{
  let result=t(word);assert_eq!(result.coverage,Coverage::Complete);let f=result.control_flow;assert_eq!(f.kind,FlowKind::Branch);assert_eq!(f.fallthrough,None);let m=result.memory.unwrap();assert_eq!(m.shift,shift);assert_eq!(m.displacement,0);assert_eq!(m.base,Some(Register::Gpr(1)));assert_eq!(m.index,Some(Register::Gpr(2)));assert_eq!(f.target,Some(BranchTarget::Table{address:m,entry_bits:bits,base:0x1004,scale:2}));
  let bytes=[(word>>16)as u8,(word>>24)as u8,word as u8,(word>>8)as u8];let d=decode(&bytes,Mode::Thumb,Endian::Little).unwrap();let unknown=d.analyze(0x1000);assert_eq!(unknown.coverage,Coverage::Partial);assert_eq!(unknown.control_flow.kind,FlowKind::Branch);assert_eq!(unknown.control_flow.predicate,Predicate::ThumbItStateRequired);let conditional=d.analyze_with_thumb_condition(0x1000,Some(1));assert_eq!(conditional.control_flow.fallthrough,Some(0x1004));assert_eq!(conditional.control_flow.predicate,Predicate::Condition(1));
 }
}
#[test]fn details_do_not_require_rendering_and_match_presentation(){
 let mut checked=0;let mut rendered=0;let mut failures=Vec::new();
 for index in 0..arm32::encoding_count(){let info=arm32::encoding_info(index).unwrap();for probe in [0_u32,0x55555555,0xaaaaaaaa,u32::MAX]{
  let word=info.value|probe&!info.mask;let bytes=if info.mode==Mode::Thumb && info.length==4{[(word>>16) as u16 as u8,((word>>16) as u16>>8) as u8,word as u8,(word>>8) as u8]}else{word.to_le_bytes()};
  let Ok(d)=decode(&bytes[..info.length],info.mode,Endian::Little)else{continue};
  let presentation=d.presentation(0x1000);if let Ok((text,_))=&presentation{if d.mnemonic_text()!=text.split_whitespace().next().unwrap_or(""){failures.push(format!("mnemonic {} word {word:x}: {:?} vs {:?}",d.encoding_id(),d.mnemonic_text(),text));}}let presentation=presentation.map(|p|p.1);let details=d.details(0x1000);if presentation.is_ok(){rendered+=1}if details!=presentation{failures.push(format!("details {} word {word:x}: {:?} vs {:?}",d.encoding_id(),details,presentation));}checked+=1;
 }}assert!(failures.is_empty(),"{} mismatches:\n{}",failures.len(),failures.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));assert!(checked>5000,"only {checked} decoded corpus samples");assert!(rendered>3000,"only {rendered} printable corpus samples");
}
`

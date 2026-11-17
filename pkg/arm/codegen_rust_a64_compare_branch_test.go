package arm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This focused public-consumer check deliberately uses rustc directly: the
// generated crate has no dependencies, and it does not need a Cargo build slot.
func TestRustA64CompareBranchReviewCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the June A64 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := NewARMParser(ARMParserConfig{EncodingIndexPath: ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: ArchAArch64, Languages: []CodegenLang{LangRust}})
	defer parser.Close(5 * time.Second)
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	source := a64CompareBranchTests + a64CompareBranchReviewTests + compareBranchPrimaryWitnesses(t, path)
	if err := os.WriteFile(filepath.Join(dir, "review.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"--edition=2021", "--test", "review.rs", "--extern", "aarch64=libaarch64.rlib", "-Copt-level=1", "-Dwarnings", "-o", "review-tests"},
		{"./review-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("compare-branch public consumer %v: %v\n%s", args, err, output)
		} else {
			t.Log(string(output))
		}
	}
}

// The four non-alias June pages contain 36 CMPBR encodings. Derive allocated
// witnesses independently from each primary diagram and encoding overlay.
func compareBranchPrimaryWitnesses(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
	}
	type class struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	selected := map[string]bool{"cbcc_regs.xml": true, "cbcc_imm.xml": true, "cbbcc_regs.xml": true, "cbhcc_regs.xml": true}
	var source strings.Builder
	source.WriteString("\n#[test]fn primary_compare_encoding_and_feature_witnesses(){use aarch64::requirements::Satisfaction as S;for(word,id)in[\n")
	tr := tar.NewReader(gz)
	pages, encodings := 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !selected[name] || h.Name != "ISA_A64_xml_A_profile-2026-06/"+name {
			continue
		}
		var p page
		if err := xml.NewDecoder(tr).Decode(&p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			for _, enc := range cl.Encodings {
				var mask, value uint32
				boxes := append(append([]box{}, cl.Diagram.Boxes...), enc.Boxes...)
				for _, b := range boxes {
					position := b.Hi
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						bits := strings.Trim(strings.TrimSpace(c.Text), "()")
						if len(bits) != span {
							bits = strings.Repeat("x", span)
						}
						for _, bit := range bits {
							if bit == '0' || bit == '1' {
								mask |= 1 << uint(position)
								if bit == '1' {
									value |= 1 << uint(position)
								} else {
									value &^= 1 << uint(position)
								}
							}
							position--
						}
					}
				}
				// Exercise nonzero sources, maximal immediate and negative branch offset.
				operands := uint32(2<<16 | 511<<5 | 1)
				if name == "cbcc_imm.xml" {
					operands = 63<<15 | 511<<5 | 1
				}
				value |= operands &^ mask
				fmt.Fprintf(&source, "(0x%08xu32,%q),\n", value, enc.Name)
				encodings++
			}
		}
	}
	if pages != 4 || encodings != 36 {
		t.Fatalf("June CMPBR: %d pages/%d encodings", pages, encodings)
	}
	t.Logf("June CMPBR: %d primary pages/%d encoding witnesses", pages, encodings)
	source.WriteString(`]{let d=aarch64::decode(word).unwrap();assert!(d.encoding_id==id||d.alias_of==id||d.ambiguous.contains(&id),"{word:08x}: {} expected{id}",d.encoding_id);assert_eq!(d.evaluate_requirements(&[],"a64").primary,S::Unsatisfied);assert_eq!(d.evaluate_requirements(&["FEAT_CMPBR"],"a64").primary,S::Satisfied);assert_eq!(d.semantic_recipe(0).support,aarch64::semantics::Support::Full);}}`)
	return source.String()
}

const a64CompareBranchTests = `
mod compare_branch {
use aarch64::*;
use aarch64::semantics::*;
struct Inputs{gpr:[u64;32],nzcv:u8}
impl Machine for Inputs {
 fn read_register(&self,r:Register)->Value {match r.bank {
  "a64.gpr"=>Value::known(64,self.gpr[usize::from(r.index)]),
  "a64.nzcv"=>Value::known(1,u64::from((self.nzcv>>(3-r.index))&1)),
  _=>panic!("unexpected input {}",r.bank)
 }}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("branch reads memory")}
}
fn run(word:u32,pc:u64,state:&Inputs)->Transition {
 let recipe=decode(word).unwrap().semantic_recipe(pc);assert_eq!(recipe.support,Support::Full,"{word:08x}");
 assert_eq!(recipe.flow.kind,FlowKind::Branch);let t=evaluate(&recipe,state).unwrap();
 assert!(t.registers.is_empty());assert!(t.memory.is_empty());assert!(t.events.is_empty());t
}
fn signed(value:u64,width:u8)->i128 {let shift=64-width;i128::from(((value<<shift)as i64)>>shift)}
fn unsigned(value:u64,width:u8)->u64 {if width==64{value}else{value&((1<<width)-1)}}
fn compare(cc:u32,a:u64,b:u64,width:u8,immediate:bool)->bool {
 let (ua,ub)=(unsigned(a,width),unsigned(b,width));let(sa,sb)=(signed(a,width),signed(b,width));
 match cc {0=>sa>sb,1 if immediate=>sa<sb,1=>sa>=sb,2=>ua>ub,3 if immediate=>ua<ub,3=>ua>=ub,6=>ua==ub,7=>ua!=ub,_=>unreachable!()}
}
#[test] fn every_cmpbr_width_comparison_alias_and_signed_branch_offset() {
 for (base,width) in [(0x74000000,32),(0xf4000000,64),(0x74008000,8),(0x7400c000,16)] {
  let cases=[0,1,2,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fff_ffff,0x8000_0000,0xffff_ffff,0x7fff_ffff_ffff_ffff,0x8000_0000_0000_0000,u64::MAX];
  for cc in [0,1,2,3,6,7] {for &a in &cases {for &b in &cases {for (rt,rm) in [(1,2),(1,1),(31,2),(1,31),(31,31)] {
   let mut state=Inputs{gpr:[0;32],nzcv:15};state.gpr[1]=a;state.gpr[2]=b;
   let va=if rt==31{0}else{state.gpr[rt as usize]};let vb=if rm==31{0}else{state.gpr[rm as usize]};
   for imm9 in [0u32,1,255,256,511] {
    let word=base|cc<<21|rm<<16|imm9<<5|rt;
    let pc:u64=if imm9&1==0{0xffff_ffff_ffff_fffc}else{0};
    let delta=if imm9>=256{i64::from(imm9)-512}else{i64::from(imm9)}*4;
    let expected=if compare(cc,va,vb,width,false){pc.wrapping_add(delta as u64)}else{pc.wrapping_add(4)};
    assert_eq!(run(word,pc,&state).next_pc.bits,expected,"{word:08x} {a:x} {b:x}");
   }
  }}}}
 }
}
#[test] fn cmpbr_immediate_uses_unsigned_six_bit_literal_and_signed_low_operand() {
 for (base,width) in [(0x75000000,32),(0xf5000000,64)] {for cc in [0,1,2,3,6,7] {for imm6 in 0..64u32 {
  for a in [0,1,31,32,63,64,u64::from(u32::MAX),u64::MAX,0x8000_0000_0000_0000,0x8000_0000] {for rt in [1,31] {
   let mut state=Inputs{gpr:[0;32],nzcv:0};state.gpr[1]=a;
   let word=base|cc<<21|imm6<<15|511<<5|rt;
   let take=compare(cc,if rt==31{0}else{a},u64::from(imm6),width,true);
   assert_eq!(run(word,0x1000,&state).next_pc.bits,if take{0xffc}else{0x1004},"{word:08x} {a:x}");
  }}
 }}}
}
#[test] fn cmpbr_rejects_reserved_condition_and_encoding_bits() {
 for base in [0x74000000,0xf4000000,0x74008000,0x7400c000,0x75000000,0xf5000000] {for cc in [4,5] {
  assert_ne!(aarch64::recipes::for_word(base|cc<<21,0).support,Support::Full);
 }}
 for word in [0x74004000,0xf4008000,0x75004000] {assert_ne!(aarch64::recipes::for_word(word,0).support,Support::Full);}
}
#[test] fn hbc_matches_all_architectural_conditions_without_changing_flags() {
 for condition in 0..16u32 {for nzcv in 0..16u8 {for imm19 in [0u32,1,0x3ffff,0x40000,0x7ffff] {
  let n=nzcv&8!=0;let z=nzcv&4!=0;let c=nzcv&2!=0;let v=nzcv&1!=0;
  let basic=match condition>>1 {0=>z,1=>c,2=>n,3=>v,4=>c&&!z,5=>n==v,6=>!z&&(n==v),7=>true,_=>unreachable!()};
  let take=if condition&1!=0&&condition!=15{!basic}else{basic};
  let word=0x54000010|imm19<<5|condition;let state=Inputs{gpr:[0;32],nzcv};
  let delta=if imm19>=0x40000{i64::from(imm19)-0x80000}else{i64::from(imm19)}*4;
  assert_eq!(run(word,u64::MAX-3,&state).next_pc.bits,if take{(u64::MAX-3).wrapping_add(delta as u64)}else{0});
 }}}
}
#[test] fn prefetch_hints_need_no_data_or_address_inputs_and_never_fault() {
 struct Missing;
 impl Machine for Missing {
  fn read_register(&self,_:Register)->Value{panic!("ignored prefetch consumes a register")}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("ignored prefetch consumes memory")}
 }
 for op in 0..32u32 {for rn in [0,1,31] {for offset in [0,1,511,4095] {
  for word in [0xf9800000|offset<<10|rn<<5|op,0xd8000000|offset<<5|op,0xf8800000|(offset&511)<<12|rn<<5|op] {
   let r=decode(word).unwrap().semantic_recipe(u64::MAX-3);assert_eq!(r.support,Support::Full,"{word:08x}");
   let t=evaluate(&r,&Missing).unwrap();assert_eq!(t.next_pc.bits,0);assert!(t.registers.is_empty()&&t.memory.is_empty()&&t.events.is_empty());
  }
  for option in [2,3,6,7] {for scale in [0,1] {for rm in [0,1,31] {
   let word=0xf8a00800|rm<<16|option<<13|scale<<12|rn<<5|op;
   let r=decode(word).unwrap().semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);
   let t=evaluate(&r,&Missing).unwrap();assert_eq!(t.next_pc.bits,0x1004);assert!(t.registers.is_empty()&&t.memory.is_empty()&&t.events.is_empty());
  }}}
 }}}
 for option in [0,1,4,5] {let word=0xf8a00800|option<<13;assert_ne!(aarch64::recipes::for_word(word,0).support,Support::Full);}
}
}
`

const a64CompareBranchReviewTests = `
mod independent_review {
use aarch64::{decode,analysis as a,effects as e,semantics as s};
#[test] fn typed_flow_and_effects_agree_for_all_physical_relations() {
 for(base,width,immediate)in[(0x74000000,32,false),(0xf4000000,64,false),(0x74008000,8,false),(0x7400c000,16,false),(0x75000000,32,true),(0xf5000000,64,true)] {
  for cc in[0,1,2,3,6,7] {for rt in[0,1,31] {for rm in[0,1,31] {for imm9 in[0,255,256,511] {
   let literal=if immediate {63<<15}else{rm<<16};let word=base|cc<<21|literal|imm9<<5|rt;
   let d=decode(word).unwrap();let f=d.analyze(0x1000).unwrap().control_flow;
   assert_eq!(f.kind,a::FlowKind::Branch);assert_eq!(f.fallthrough,Some(0x1004));
   let displacement=i128::from(if imm9>=256 {i64::from(imm9)-512}else{i64::from(imm9)})*4;
   assert_eq!(f.target,Some(a::BranchTarget::Direct(Some((0x1000i128+displacement)as u64))));
   let a::Predicate::RegisterCompare{left,right,width:bits,signed,relation}=f.predicate else {panic!("{word:08x} {f:?}")};
   assert_eq!((left.number,left.width,bits,signed),(rt as u8,Some(width as u16),width,cc<2));
   assert_eq!(left.role,if rt==31{a::RegisterRole::Zero}else{a::RegisterRole::General});
   assert_eq!(relation,match cc{0|2=>a::CompareRelation::GreaterThan,1|3 if immediate=>a::CompareRelation::LessThan,1|3=>a::CompareRelation::GreaterOrEqual,6=>a::CompareRelation::Equal,7=>a::CompareRelation::NotEqual,_=>unreachable!()});
   match right {a::CompareOperand::Immediate(v)=>{assert!(immediate);assert_eq!(v,63)},a::CompareOperand::Register(v)=>{assert!(!immediate);assert_eq!((v.number,v.width),(rm as u8,Some(width as u16)));assert_eq!(v.role,if rm==31{a::RegisterRole::Zero}else{a::RegisterRole::General});}}
   let e=d.effects();assert_eq!(e.registers_knowledge,e::EffectKnowledge::Complete);assert_eq!(e.flags_knowledge,e::EffectKnowledge::Complete);assert_eq!(e.memory_knowledge,e::EffectKnowledge::Complete);
   assert!(e.memory.is_empty());assert_eq!(e.registers.len(),usize::from(rt!=31)+usize::from(!immediate&&rm!=31));
   assert!(e.registers.iter().all(|r|r.read&&!r.write&&!r.address&&!r.conditional&&r.register.bank=="gpr"&&r.register.offset==0&&r.register.width==Some(width as u16)));
   assert_eq!(e.flags.len(),4);assert!(e.flags.iter().all(|f|!f.read&&f.action==e::FlagAction::Preserve));
  }}}}
 }
}
#[test] fn compare_ignores_nzcv_and_zero_register_storage() {
 struct ZeroOnly;
 impl s::Machine for ZeroOnly {
  fn read_register(&self,r:s::Register)->s::Value{panic!("CMPBR ZR consumed state {r:?}")}
  fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<s::Value,s::EvalError>{panic!()}
 }
 for base in[0x74000000,0xf4000000,0x74008000,0x7400c000,0x75000000,0xf5000000] {for cc in[0,1,2,3,6,7] {
  let word=base|cc<<21|if base&0x01000000!=0 {0}else{31<<16}|2<<5|31;
  let r=decode(word).unwrap().semantic_recipe(0x1000);let t=s::evaluate(&r,&ZeroOnly).unwrap();
  let take=cc==6||(base&0x01000000==0&&matches!(cc,1|3));
  assert_eq!(t.next_pc.bits,if take {0x1008}else{0x1004});
  assert!(t.registers.is_empty());
 }}
}
#[test] fn hbc_flag_dependencies_and_no_flags_for_al_nv() {
 for cond in 0..16 {let d=decode(0x54000050|cond).unwrap();let e=d.effects();let f=d.analyze(0x1000).unwrap().control_flow;
  assert_eq!(f.predicate,a::Predicate::Condition(cond as u8));assert_eq!(f.fallthrough,if cond<14{Some(0x1004)}else{None});
  let names=match cond>>1 {0=>&["Z"][..],1=>&["C"][..],2=>&["N"][..],3=>&["V"][..],4=>&["Z","C"][..],5=>&["N","V"][..],6=>&["N","Z","V"][..],_=>&[]};
  let actual=e.flags.iter().filter(|f|f.read).map(|f|f.name).collect::<Vec<_>>();assert_eq!(actual,names,"cond{cond}");assert!(e.flags.iter().all(|f|f.action==e::FlagAction::Preserve));
 }
 struct NoInputs;
 impl s::Machine for NoInputs {fn read_register(&self,r:s::Register)->s::Value{panic!("AL/NV read {r:?}")}fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<s::Value,s::EvalError>{panic!()}}
 for cond in[14,15] {assert_eq!(s::evaluate(&decode(0x54000050|cond).unwrap().semantic_recipe(0x1000),&NoInputs).unwrap().next_pc.bits,0x1008);}
}
#[test] fn feature_absence_is_undef_for_compare_hbc_but_nop_fallback_for_range_hint() {
 use aarch64::requirements::Satisfaction as S;
 for(word,feature)in[(0x74020020,"FEAT_CMPBR"),(0x54000050,"FEAT_HBC")] {
  let d=decode(word).unwrap();let missing=d.evaluate_requirements(&[],"a64");assert_eq!(missing.primary,S::Unsatisfied);assert_ne!(missing.fallback,Some(S::Satisfied));assert_eq!(d.evaluate_requirements(&[feature],"a64").primary,S::Satisfied);
 }
 for option in[2,3,6,7] {for scale in[0,1] {for op in 24..32 {
  let word=0xf8a00800|31<<16|option<<13|scale<<12|31<<5|op;let d=decode(word).unwrap();let missing=d.evaluate_requirements(&[],"a64");
  assert_eq!(missing.primary,S::Unsatisfied,"{word:08x} {}",d.encoding_id);assert_eq!(missing.fallback_behavior,"nop");assert_eq!(missing.fallback,Some(S::Satisfied));assert_eq!(d.evaluate_requirements(&["FEAT_RPRFM"],"a64").primary,S::Satisfied);
 }}}
}
}
`

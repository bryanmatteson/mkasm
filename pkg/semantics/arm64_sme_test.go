package semantics

import (
	"archive/tar"
	"compress/gzip"
	_ "embed"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed arm64_sme.rs
var a64SMEModuleSource string

func TestRustA64SMEMatrices(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_sme") {
		source += "\npub mod arm64_sme {\n" + a64SMEModuleSource + "\n}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sme.rs"), []byte(a64SMEBehavior+a64SMECorpus(t)), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "sme.rs", "-Dwarnings", "-o", "sme-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile SME recipes: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "sme-tests"), "sme_behavior::", "--test-threads=1")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute SME recipes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

// Fixed masks and named operands are taken from the installed release, not a
// duplicate of the implementation's dispatch constants. Both operand extremes
// exercise every encoding, including MOV aliases and mixed signedness.
func a64SMECorpus(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	out.WriteString("\nconst SME_CORPUS:&[(u32,&str)]=&[\n")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		return out.String() + "];\n"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
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
		Name string `xml:"name,attr"`
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
	wanted := map[string]bool{"smstart_msr_imm": true, "smstop_msr_imm": true, "zero_za_i": true, "mova_z_p_rza": true, "mova_za_p_rz": true, "fmopa_za_pp_zz": true, "fmops_za_pp_zz": true, "bfmopa_za_pp_zz": true, "bfmops_za_pp_zz": true, "bfmopa_za32_pp_zz": true, "bfmops_za32_pp_zz": true}
	for _, name := range []string{"fmopa_za32_pp_zz", "fmops_za32_pp_zz", "bmopa_za_pp_zz", "bmops_za_pp_zz", "mova_mz_za2", "mova_mz_za4", "mova_za_mz2", "mova_za_mz4", "mova_mz2_za", "mova_mz4_za", "mova_za2_z", "mova_za4_z"} {
		wanted[name] = true
	}
	for _, op := range []string{"smopa", "smops", "umopa", "umops", "sumopa", "sumops", "usmopa", "usmops"} {
		wanted[op+"_za_pp_zz"] = true
	}
	for _, op := range []string{"smopa", "smops", "umopa", "umops"} {
		wanted[op+"_za32_pp_zz"] = true
	}
	reader := tar.NewReader(gzipReader)
	pages, count := 0, 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(header.Name), ".xml")
		if !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") || !wanted[name] {
			continue
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err = xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			var mask, value uint32
			for _, box := range cl.Diagram.Boxes {
				pos := box.Hi
				for _, cell := range box.Cells {
					span := cell.Span
					if span == 0 {
						span = 1
					}
					text := strings.Trim(strings.TrimSpace(cell.Text), "()")
					if len(text) == span {
						for _, bit := range text {
							if bit == '0' || bit == '1' {
								mask |= 1 << uint(pos)
								if bit == '1' {
									value |= 1 << uint(pos)
								}
							}
							pos--
						}
					} else {
						pos -= span
					}
				}
			}
			for _, en := range cl.Encodings {
				for _, fields := range []uint32{0, ^mask} {
					word := value | fields
					if strings.HasPrefix(name, "smstart") || strings.HasPrefix(name, "smstop") {
						word |= 1 << 9
					}
					fmt.Fprintf(&out, "(0x%08x,%q),\n", word, en.Name)
					count++
				}
			}
		}
	}
	if pages != len(wanted) || count < 80 {
		t.Fatalf("SME real-corpus coverage incomplete: pages=%d want=%d words=%d", pages, len(wanted), count)
	}
	t.Logf("SME June XML: %d pages, %d physical words", pages, count)
	out.WriteString("];\n")
	return out.String()
}

const a64SMEBehavior = `
#![allow(dead_code)]
mod semantics;
#[cfg(test)] mod sme_behavior {
 use super::semantics::{*,arm64_sme::a64};
 use std::{collections::BTreeMap,cell::RefCell};
 const SVLS:[u16;5]=[128,256,512,1024,2048];
 fn reg(bank:&'static str,index:u16)->Register {Register{bank,index}}
 fn za(row:u16,chunk:u16)->Register {reg("a64.za64",row*32+chunk)}
 fn z(n:u16,chunk:u16)->Register {reg("a64.vector64",n*32+chunk)}
 fn p(n:u16,chunk:u16)->Register {reg("a64.predicate64",n*4+chunk)}
 fn mask(w:u8)->u64 {if w==64 {u64::MAX}else{(1u64<<w)-1}}
 #[derive(Clone)] struct State {
  regs:BTreeMap<(&'static str,u16),Value>,reads:RefCell<Vec<Register>>,
  floats:RefCell<Vec<(FloatOperation,u8,Vec<u64>,u64)>>, fail_float:bool,
 }
 impl State {
  fn new()->Self {
   let mut s=Self{regs:BTreeMap::new(),reads:RefCell::new(Vec::new()),floats:RefCell::new(Vec::new()),fail_float:false};
   for row in 0..256 {for chunk in 0..32 {s.set(za(row,chunk),64,(u64::from(row)+1).wrapping_mul(0x0102040810204081)^u64::from(chunk));}}
   for n in 0..32 {for chunk in 0..32 {s.set(z(n,chunk),64,(u64::from(n)+3).wrapping_mul(0x817f0102ff80fe03)^u64::from(chunk));}}
   for n in 0..17 {for chunk in 0..4 {s.set(p(n,chunk),64,0xd5a5ff003355aacc^u64::from(n*4+chunk));}}
   for n in 0..31 {s.set(reg("a64.gpr",n),64,if (12..16).contains(&n) {0xffff_ffff}else{u64::from(n)});}
   for chunk in 0..8 {s.set(reg("a64.zt064",chunk),64,u64::MAX-u64::from(chunk));}
   for (bank,width,value) in [("a64.svcr",2,3),("a64.fpcr",32,0x00c09f00),("a64.fpsr",32,0xface_1234),("a64.fpmr",64,0x1234)] {s.set(reg(bank,0),width,value);}
   s
  }
  fn set(&mut self,r:Register,width:u8,bits:u64) {self.regs.insert((r.bank,r.index),Value::known(width,bits));}
  fn value(&self,r:Register)->u64 {self.regs[&(r.bank,r.index)].bits}
  fn lane(&self,r:Register,at:u16,w:u8)->u64 {self.value(Register{index:r.index+at/64,..r})>>(at%64)&mask(w)}
  fn put_lane(&mut self,r:Register,at:u16,w:u8,bits:u64) {let r=Register{index:r.index+at/64,..r};let shift=at%64;let old=self.value(r);self.set(r,64,(old&!(mask(w)<<shift))|((bits&mask(w))<<shift));}
  fn active(&self,n:u16,byte:u16)->bool {self.value(p(n,byte/64))&(1<<(byte%64))!=0}
  fn commit(&mut self,t:Transition) {assert!(t.memory.is_empty()&&t.wide_memory.is_empty()&&t.atomics.is_empty()&&t.trap.is_none());assert_eq!(t.next_pc,Value::known(64,0x1004));for w in t.registers {self.regs.insert((w.register.bank,w.register.index),w.value);}}
 }
 impl Machine for State {
  fn read_register(&self,r:Register)->Value {self.reads.borrow_mut().push(r);*self.regs.get(&(r.bank,r.index)).unwrap_or_else(||panic!("unexpected inactive input {r:?}"))}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("matrix arithmetic touched memory")}
  fn evaluate_float(&self,f:&FloatExpression,v:&[Value],control:Value,status:Value)->Result<Value,EvalError> {
   assert_eq!(f.environment,FloatEnvironment::A64);assert_eq!(f.projection,FloatProjection::Value);assert_eq!(status,Value::known(32,0));
   assert!(v.iter().all(|v|v.is_known()));assert!(control.is_known());
   if matches!(f.operation,FloatOperation::BFloatDotAdd|FloatOperation::ZaHalfDot|FloatOperation::ZaFused{..}) {assert_eq!(control.bits,self.value(reg("a64.fpcr",0)));}else{assert_eq!(control.bits&(1<<25),1<<25);assert_eq!(control.bits&0x9f00,0);}
   if matches!(f.operation,FloatOperation::Convert {source_width:16,..}) {assert_eq!(control.bits&(1<<26),0,"FPDot ignores AHP");}
   self.floats.borrow_mut().push((f.operation,f.width,v.iter().map(|v|v.bits).collect(),control.bits));
   if self.fail_float {return Err(EvalError::UnsupportedContext)}
   let out=match f.operation {
    FloatOperation::ZaFused{bfloat:false} if f.width==32 => {
     let a=f32::from_bits(v[0].bits as u32);let n=f32::from_bits(v[1].bits as u32);let m=f32::from_bits(v[2].bits as u32);
     u64::from(n.mul_add(m,a).to_bits())
    }
    FloatOperation::ZaFused{bfloat:false} if f.width==64 => {
     let a=f64::from_bits(v[0].bits);let n=f64::from_bits(v[1].bits);let m=f64::from_bits(v[2].bits);
     n.mul_add(m,a).to_bits()
    }
    FloatOperation::ZaHalfDot => {
     let half=|x:u64| if x&0x7fff==0||x&0x7c00==0&&control.bits&(1<<19)!=0{if x&0x8000!=0{-0f32}else{0f32}}else{match x{0x3c00=>1f32,0xbc00=>-1f32,0x4000=>2f32,0xc000=>-2f32,0x4200=>3f32,0xc200=>-3f32,0x4400=>4f32,0xc400=>-4f32,_=>panic!("independent half dot fixture")}};
     let dot=half(v[1].bits)*half(v[3].bits)+half(v[2].bits)*half(v[4].bits);u64::from((f32::from_bits(v[0].bits as u32)+dot).to_bits())
    }
    FloatOperation::Convert{source_width:16,round_to_odd:false} => u64::from(match v[0].bits {0=>0f32,0x8000=>-0f32,0x3c00=>1f32,0xbc00=>-1f32,0x4000=>2f32,0xc000=>-2f32,0x4200=>3f32,0xc200=>-3f32,0x4400=>4f32,0xc400=>-4f32,_=>panic!("test fixture needs an independent half conversion")}.to_bits()),
    FloatOperation::Multiply|FloatOperation::Add if f.width==32 => {
     let a=f32::from_bits(v[0].bits as u32);let z=f32::from_bits(v[1].bits as u32);
     u64::from(if f.operation==FloatOperation::Multiply {a*z}else{a+z}.to_bits())
    }
    // A tagged typed-engine result exercises BF16/FP16 operation plumbing,
    // without pretending host half/bfloat arithmetic is an Arm FP engine.
    FloatOperation::ZaFused{..}|FloatOperation::BFloatDotAdd=>0x5a5a,
    _=>panic!("unexpected operation"),
   };Ok(Value::known(f.width,out))
  }
 }
 fn recipe(word:u32,svl:u16)->Recipe {let r=a64(word,0x1000,svl).unwrap_or_else(||panic!("unrecognized {word:08x}"));assert_eq!(r.support,Support::Full);r.validate().unwrap();r}
 fn run(s:&mut State,word:u32,svl:u16) {let r=recipe(word,svl);let t=evaluate(&r,s).unwrap();s.commit(t);}
 fn predicates(s:&mut State,bits:u64) {for n in 0..8 {for chunk in 0..4 {s.set(p(n,chunk),64,bits);}}}

 #[test] fn streaming_changes_reset_complete_maximum_storage_and_fpmr() {
  for svl in SVLS {for selection in [2,4,6] {for start in [false,true] {for old in 0..4 {
   let mut s=State::new();s.set(reg("a64.svcr",0),2,old);let before=s.clone();
   let word=0xd503407f|((selection|u32::from(start))<<8);run(&mut s,word,svl);
   let sm_change=selection&2!=0&&(old&1!=0)!=start;
   let za_enable=selection&4!=0&&start&&old&2==0;
   for n in 0..32 {for chunk in 0..32 {assert_eq!(s.value(z(n,chunk)),if sm_change {0}else{before.value(z(n,chunk))});}}
   for n in 0..17 {for chunk in 0..4 {assert_eq!(s.value(p(n,chunk)),if sm_change {0}else{before.value(p(n,chunk))});}}
   for row in 0..256 {for chunk in 0..32 {assert_eq!(s.value(za(row,chunk)),if za_enable {0}else{before.value(za(row,chunk))});}}
   for chunk in 0..8 {assert_eq!(s.value(reg("a64.zt064",chunk)),if za_enable {0}else{before.value(reg("a64.zt064",chunk))});}
   assert_eq!(s.value(reg("a64.fpsr",0)),if sm_change {0x0800009f}else{before.value(reg("a64.fpsr",0))});
   assert_eq!(s.value(reg("a64.fpmr",0)),if sm_change {0}else{0x1234});
   assert_eq!(s.value(reg("a64.fpcr",0)),before.value(reg("a64.fpcr",0)));
   let mask=u64::from(selection>>1);assert_eq!(s.value(reg("a64.svcr",0)),if start {old|mask}else{old&!mask});
  }}}}
 }
 #[test] fn zero_tiles_are_distinct_and_cover_the_last_2048_bit_row() {
  for svl in SVLS {for tiles in [0,1,0x80,0x55,0xff] {let mut s=State::new();s.set(reg("a64.svcr",0),2,2);let before=s.clone();run(&mut s,0xc0080000|tiles,svl);
   for row in 0..256 {for chunk in 0..32 {assert_eq!(s.value(za(row,chunk)),if row<svl/8&&chunk<svl/64&&tiles&(1<<(row%8))!=0 {0}else{before.value(za(row,chunk))});}}
  }}
 }

 fn mova_word(width:u16,extract:bool,vertical:bool,tile:u16,offset:u16)->u32 {
  let size=if width==128 {3}else{(width/8).trailing_zeros()};let low=(tile<<(4-(width/8).trailing_zeros()))|offset;
  0xc0000000|(size<<22)|(if width==128 {1<<16}else{0})|(u32::from(extract)<<17)|(u32::from(vertical)<<15)|(2<<13)|(3<<10)|
   if extract {(u32::from(low)<<5)|31}else{(31<<5)|u32::from(low)}
 }
 fn reference_move(s:&mut State,svl:u16,width:u16,extract:bool,vertical:bool,tile:u16,offset:u16) {
  let before=s.clone();let selected=((u64::from(u32::MAX)+u64::from(offset))%u64::from(svl/width))as u16;
  for element in 0..svl/width {if !before.active(3,element*width/8) {continue}
   let row=(if vertical {element}else{selected})*width/8+tile;let column=if vertical {selected}else{element};
   for half in 0..(width/64).max(1) {let w=width.min(64)as u8;let zb=element*width+half*64;let ab=column*width+half*64;
    if extract {s.put_lane(z(31,0),zb,w,before.lane(za(row,0),ab,w));}else{s.put_lane(za(row,0),ab,w,before.lane(z(31,0),zb,w));}
   }
  }
  if extract {for chunk in svl/64..32 {s.set(z(31,chunk),64,0);}}
 }
 #[test] fn mova_horizontal_vertical_all_widths_wrap_offsets_and_preserve_inactive() {
  for svl in SVLS {for width in [8,16,32,64,128] {for extract in [false,true] {for vertical in [false,true] {
   let tile=width/8-1;let offset=16/(width/8)-1;let word=mova_word(width,extract,vertical,tile,offset);
   let mut s=State::new();let mut expected=s.clone();reference_move(&mut expected,svl,width,extract,vertical,tile,offset);run(&mut s,word,svl);
   assert_eq!(s.regs,expected.regs,"SVL={svl} width={width} extract={extract} vertical={vertical}");
  }}}}
 }
 #[test] fn inactive_moves_and_outer_products_do_not_consume_source_data_or_fp_context() {
  for extract in [false,true] {let mut s=State::new();predicates(&mut s,0);
   if extract {s.regs.retain(|(bank,_),_|*bank!="a64.za64");}else{s.regs.retain(|(bank,_),_|*bank!="a64.vector64");}
   run(&mut s,mova_word(32,extract,false,3,3),128);
  }
  for word in [0xa0800000,0x80800000,0x81800008,0x81a00008,0x81800000,0x81a00000,0x80800008] {
   let mut s=State::new();predicates(&mut s,0);s.regs.retain(|(bank,_),_|!matches!(*bank,"a64.vector64"|"a64.fpcr"|"a64.fpsr"));
   let before=s.regs.clone();run(&mut s,word,128);assert_eq!(s.regs,before);assert!(s.floats.borrow().is_empty());
  }
 }

 #[test] fn multi_vector_and_tile_moves_combine_vertical_writes_without_losing_members() {
  for svl in SVLS {for nreg in [2u16,4] {for extract in [false,true] {for array in [false,true] {
   for width in if array {vec![8]}else{vec![8,16,32,64]} {for vertical in if array {vec![false]}else{vec![false,true]} {
    let mut s=State::new();let mut expected=s.clone();let base=if extract {0xc0060000}else{0xc0040000};
    let size=if array {0}else{(width/8u16).trailing_zeros()};
    let tile=if array {0}else{width/8-1};let offset_bits=if array {3}else{(4-(width/8).trailing_zeros()).saturating_sub(nreg.trailing_zeros())};
    let offset=(1u16<<offset_bits)-1;let low=(tile<<offset_bits)|offset;
    let number=32-nreg;let word=base|(if array {if nreg==4 {0xc00}else{0x800}}else{u32::from(nreg==4)<<10})|(size<<22)|(u32::from(vertical)<<15)|(2<<13)|
     if extract {(u32::from(low)<<5)|u32::from(number)}else{(u32::from(number)<<5)|u32::from(low)};
    if !array&&nreg==4&&width==64&&svl<256 {let t=evaluate(&recipe(word,svl),&s).unwrap();assert_eq!(t.trap,Some(TrapKind::InvalidInstruction));assert!(t.registers.is_empty());continue;}
    let incoming=if array {10}else{14};let index=expected.value(reg("a64.gpr",incoming))as u32 as u64;
    let dim=svl/width;let stride=svl/8/nreg;
    let first=if array {(index+u64::from(offset))%u64::from(stride)}else{((index-index%u64::from(nreg))+u64::from(offset*nreg))%u64::from(dim)}as u16;
    for member in 0..nreg {let selected=first+if array {member*stride}else{member};
     for e in 0..dim {let row=if vertical {e}else{selected};let col=if vertical {selected}else{e};let physical=row*width/8+tile;
      let bits=s.lane(if extract {za(physical,0)}else{z(number+member,0)},if extract {col*width}else{e*width},width as u8);
      expected.put_lane(if extract {z(number+member,0)}else{za(physical,0)},if extract {e*width}else{col*width},width as u8,bits);
     }
     if extract {for chunk in svl/64..32 {expected.set(z(number+member,chunk),64,0);}}
    }
    run(&mut s,word,svl);assert_eq!(s.regs,expected.regs,"{word:08x} svl={svl} width={width} group={nreg} array={array}");
   }}
  }}}}
 }

 // June mova_mz4_za/mova_za4_z check CurrentVL before selecting slices.
 // These recorded native words are UNDEFINED at 128, not wrapping transfers.
 #[test] fn recorded_four_doubleword_moves_trap_at_128_and_align_wrap_at_larger_lengths() {
  for word in [0xc0c6e4e0u32,0xc0c4a481] {for svl in SVLS {
   let extract=word&(1<<17)!=0;let vector=if extract {word&31}else{(word>>5)&31}as u16;
   let tile=if extract {(word>>5)&7}else{word&7}as u16;let indexreg=12+((word>>13)&3)as u16;
   let dimension=svl/64;
   for index in [0u64,1,3,4,u64::from(dimension-1),u64::from(dimension),u64::from(u32::MAX)] {
    let mut state=State::new();state.set(reg("a64.gpr",indexreg),64,index);let before=state.clone();
    if svl==128 {let t=evaluate(&recipe(word,svl),&state).unwrap();assert_eq!(t.trap,Some(TrapKind::InvalidInstruction));assert!(t.registers.is_empty());assert!(state.reads.borrow().iter().all(|r|r.bank=="a64.svcr"));continue;}
    let mut expected=before.clone();let first=((index-index%4)%u64::from(dimension))as u16;
    for member in 0..4 {for row in 0..dimension {
     let physical=row*8+tile;let column=first+member;
     if extract {let v=before.lane(za(physical,0),column*64,64);expected.put_lane(z(vector+member,0),row*64,64,v);}
     else {let v=before.lane(z(vector+member,0),row*64,64);expected.put_lane(za(physical,0),column*64,64,v);}
    }if extract {for chunk in svl/64..32 {expected.set(z(vector+member,chunk),64,0);}}}
    run(&mut state,word,svl);assert_eq!(state.regs,expected.regs,"{word:08x} SVL={svl} index={index}");
   }
  }}
 }

 #[test] fn bitwise_outer_products_count_xnor_and_wrap_the_accumulator() {
  for svl in SVLS {for subtract in [false,true] {let mut s=State::new();let mut expected=s.clone();
   for row in 0..svl/32 {for col in 0..svl/32 {if s.active(1,row*4)&&s.active(2,col*4) {
    let count=(!(s.lane(z(31,0),row*32,32)^s.lane(z(31,0),col*32,32))as u32).count_ones()as u64;
    let old=s.lane(za(row*4+3,0),col*32,32);expected.put_lane(za(row*4+3,0),col*32,32,if subtract {old.wrapping_sub(count)}else{old.wrapping_add(count)});
   }}}
   run(&mut s,0x80800008|(u32::from(subtract)<<4)|3|(31<<5)|(31<<16)|(1<<10)|(2<<13),svl);assert_eq!(s.regs,expected.regs);
  }}
 }
 #[test] fn widening_half_dot_has_separate_dot_and_accumulator_rounding_and_fz16() {
  for subtract in [false,true] {for flush in [false,true] {for alternative in [false,true] {
   let mut s=State::new();predicates(&mut s,0);s.set(p(1,0),64,5);s.set(p(2,0),64,5);
   s.put_lane(z(1,0),0,16,if flush {1}else{0x3c00});s.put_lane(z(1,0),16,16,0x4200);
   s.put_lane(z(2,0),0,16,0x4000);s.put_lane(z(2,0),16,16,0x4400);
   s.put_lane(za(0,0),0,32,u64::from(3f32.to_bits()));s.set(reg("a64.fpcr",0),32,(u64::from(flush)<<19)|(u64::from(alternative)<<26));
   let before=s.clone();run(&mut s,0x81a00000|(u32::from(subtract)<<4)|(1<<5)|(2<<16)|(1<<10)|(2<<13),128);
   let dot=if flush {12f32}else{14f32};let want=if subtract {3f32-dot}else{3f32+dot};
   assert_eq!(s.lane(za(0,0),0,32),u64::from(want.to_bits()));assert_eq!(s.floats.borrow().len(),1);assert_eq!(s.value(reg("a64.fpsr",0)),before.value(reg("a64.fpsr",0)));
  }}}
 }

 fn signed(value:u64,width:u8)->i128 {((value<<(64-width))as i64>>(64-width))as i128}
 fn reference_integer(s:&mut State,svl:u16,width:u8,parts:u16,tile:u16,left_unsigned:bool,right_unsigned:bool,subtract:bool) {
  let before=s.clone();let input=width/parts as u8;let dim=svl/u16::from(width);
  for row in 0..dim {for col in 0..dim {let physical=row*u16::from(width)/8+tile;let mut sum=before.lane(za(physical,0),col*u16::from(width),width);
   for k in 0..parts {let a=row*parts+k;let b=col*parts+k;if !before.active(1,a*u16::from(input)/8)||!before.active(2,b*u16::from(input)/8) {continue}
    let a=before.lane(z(31,0),a*u16::from(input),input);let b=before.lane(z(31,0),b*u16::from(input),input);
    let a=if left_unsigned {i128::from(a)}else{signed(a,input)};let b=if right_unsigned {i128::from(b)}else{signed(b,input)};
    sum=(if subtract {i128::from(sum)-a*b}else{i128::from(sum)+a*b})as u64&mask(width);
   }
   s.put_lane(za(physical,0),col*u16::from(width),width,sum);
  }}
 }
 #[test] fn integer_outer_products_signed_mixed_unsigned_dot_groups_and_wrapping() {
  for svl in SVLS {for width in [32u8,64] {for left_unsigned in [false,true] {for right_unsigned in [false,true] {for subtract in [false,true] {
   let tile=u16::from(width/8-1);let word=0xa0800000|(u32::from(width==64)<<22)|(u32::from(left_unsigned)<<24)|(u32::from(right_unsigned)<<21)|(u32::from(subtract)<<4)|u32::from(tile)|(31<<5)|(31<<16)|(1<<10)|(2<<13);
   let mut s=State::new();let mut expected=s.clone();reference_integer(&mut expected,svl,width,4,tile,left_unsigned,right_unsigned,subtract);run(&mut s,word,svl);
   assert_eq!(s.regs,expected.regs,"{word:08x} svl={svl}");
  }}}}}
  for unsigned in [false,true] {for subtract in [false,true] {let mut s=State::new();predicates(&mut s,u64::MAX);let mut expected=s.clone();
   reference_integer(&mut expected,256,32,2,3,unsigned,unsigned,subtract);
   run(&mut s,0xa0800008|(u32::from(unsigned)<<24)|(u32::from(subtract)<<4)|3|(31<<5)|(31<<16)|(1<<10)|(2<<13),256);assert_eq!(s.regs,expected.regs);
  }}
 }

 #[test] fn float_outer_products_use_fused_scalar_values_and_never_write_status() {
  for (width,base,one,two,three,five) in [(32u8,0x80800000,1f32.to_bits()as u64,2f32.to_bits()as u64,3f32.to_bits()as u64,5f32.to_bits()as u64),(64,0x80c00000,1f64.to_bits(),2f64.to_bits(),3f64.to_bits(),5f64.to_bits())] {
   for subtract in [false,true] {let mut s=State::new();predicates(&mut s,u64::MAX);let svl=256;let tile=u16::from(width/8-1);
    for e in 0..svl/u16::from(width) {s.put_lane(z(1,0),e*u16::from(width),width,one);s.put_lane(z(2,0),e*u16::from(width),width,two);for col in 0..svl/u16::from(width) {s.put_lane(za(e*u16::from(width)/8+tile,0),col*u16::from(width),width,three);}}
    let before=s.clone();run(&mut s,base|u32::from(tile)|(1<<5)|(2<<16)|(1<<10)|(2<<13)|(u32::from(subtract)<<4),svl);
    for row in 0..svl/u16::from(width) {for col in 0..svl/u16::from(width) {assert_eq!(s.lane(za(row*u16::from(width)/8+tile,0),col*u16::from(width),width),if subtract {one}else{five});}}
    assert_eq!(s.value(reg("a64.fpsr",0)),before.value(reg("a64.fpsr",0)));assert_eq!(s.value(reg("a64.fpcr",0)),before.value(reg("a64.fpcr",0)));
    assert_eq!(s.floats.borrow().len(),usize::from(svl/u16::from(width)).pow(2));
   }
  }
 }
 #[test] fn half_bfloat_and_dot_operations_keep_typed_width_order_and_predicate_rules() {
  for (word,operation,width) in [(0x81800008,FloatOperation::ZaFused{bfloat:false},16),(0x81a00018,FloatOperation::ZaFused{bfloat:true},16),(0x81800010,FloatOperation::BFloatDotAdd,32)] {
   let mut s=State::new();predicates(&mut s,0);s.set(p(1,0),64,1);s.set(p(2,0),64,1);let before=s.clone();
   run(&mut s,word|(1<<5)|(2<<16)|(1<<10)|(2<<13),128);
   assert_eq!(s.floats.borrow().len(),1);let record=&s.floats.borrow()[0];assert_eq!(record.0,operation);assert_eq!(record.1,width);
   assert_eq!(record.2[0],before.lane(za(0,0),0,width));
   if operation==FloatOperation::BFloatDotAdd {assert_eq!(record.2.len(),5);assert_eq!(record.2[1],before.lane(z(1,0),0,16)^0x8000);assert_eq!(record.2[2],0);assert_eq!(record.2[3],before.lane(z(2,0),0,16));assert_eq!(record.2[4],0);}
   assert_eq!(s.lane(za(0,0),0,width),0x5a5a);assert_eq!(s.value(reg("a64.fpsr",0)),before.value(reg("a64.fpsr",0)));
  }
 }
 #[test] fn unavailable_modes_lengths_and_float_engines_fail_without_publishing() {
  let mut s=State::new();s.regs.insert(("a64.svcr",0),Value::unknown(2));let before=s.regs.clone();assert_eq!(evaluate(&recipe(0xd503477f,128),&s),Err(EvalError::UnknownCondition));assert_eq!(s.regs,before);
  for svl in [0,127,384,768,1536,2176] {let s=State::new();let before=s.regs.clone();assert_eq!(evaluate(&recipe(0xc00800ff,svl),&s),Err(EvalError::UnsupportedContext));assert_eq!(s.regs,before);assert!(s.reads.borrow().is_empty());}
  for state in 0..3 {let mut s=State::new();s.set(reg("a64.svcr",0),2,state);let before=s.regs.clone();assert_eq!(evaluate(&recipe(0x80800000,128),&s),Err(EvalError::UnsupportedContext));assert_eq!(s.regs,before);assert_eq!(s.reads.borrow().as_slice(),&[reg("a64.svcr",0)]);}
  let mut s=State::new();predicates(&mut s,u64::MAX);s.fail_float=true;let before=s.regs.clone();assert_eq!(evaluate(&recipe(0x80800000,128),&s),Err(EvalError::UnsupportedContext));assert_eq!(s.regs,before);
  for control in [1<<13,1<<1] {let mut s=State::new();predicates(&mut s,u64::MAX);s.set(reg("a64.fpcr",0),32,control);let before=s.regs.clone();let transition=evaluate(&recipe(0x81800000,128),&s).unwrap();assert_eq!(transition.trap,None);assert_eq!(s.regs,before);assert!(!s.floats.borrow().is_empty());assert!(s.floats.borrow().iter().all(|record|record.3==control));}
  for word in [0xd503417f,0xc0080100,0xc0020200,0xc0000010,0xa0800004,0xa0c00008,0x80800004] {assert!(a64(word,0x1000,128).is_none(),"reserved/unrelated {word:08x}");}
 }
 #[test] fn june_corpus_dispatches_every_owned_encoding_and_highest_tile() {
  for &(word,id) in super::SME_CORPUS {let r=a64(word,0x1000,128).unwrap_or_else(||panic!("{id} {word:08x}"));assert_eq!(r.support,Support::Full,"{id}");r.validate().unwrap();}
  for svl in SVLS {let r=recipe(0xa0c00007|(31<<5)|(31<<16)|(7<<10)|(7<<13),svl);let mut largest=0;for e in r.effects {if let Effect::WriteRegister{destination,..}=e {assert_eq!(destination.register.bank,"a64.za64");largest=largest.max(destination.register.index);}}assert_eq!(largest,(svl/8-1)*32+svl/64-1);}
 }
}
`

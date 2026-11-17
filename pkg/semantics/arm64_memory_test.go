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
	"regexp"
	"strings"
	"testing"
)

//go:embed arm64_memory.rs
var a64MemoryModuleSource string

func TestRustA64StructureMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_memory") {
		source += "\npub mod arm64_memory {\n" + a64MemoryModuleSource + "\n}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.rs"), []byte(a64MemoryBehavior+a64MemoryCorpus(t)), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "memory.rs", "-Dwarnings", "-o", "memory-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 structure memory: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "memory-tests"), "structure_memory_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A64 structure memory: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

// Read both the class diagram and encoding-specific bit constraints from the
// actual release. Do not treat the deliberately broad LD1 class as one opcode.
func a64MemoryCorpus(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	result.WriteString("\nconst STRUCTURE_CORPUS:&[(u32,&str)]=&[\n")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		result.WriteString("];\n")
		return result.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zipped, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zipped.Close()
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name  string `xml:"name,attr"`
		Diff  string `xml:"bitdiffs,attr"`
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
	fixed := func(boxes []box) (uint32, uint32) {
		var mask, value uint32
		for _, b := range boxes {
			width := b.Width
			if width == 0 {
				width = 1
			}
			pos := b.Hi
			for _, c := range b.Cells {
				span := c.Span
				if span == 0 {
					span = 1
				}
				text := strings.Trim(strings.TrimSpace(c.Text), "()")
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
		return mask, value
	}
	equality := regexp.MustCompile(`([A-Za-z0-9_]+) == ([01x]+)`)
	reader := tar.NewReader(zipped)
	pages, count := 0, 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		name := filepath.Base(header.Name)
		chosen := false
		for n := 1; n <= 4; n++ {
			for _, prefix := range []string{"ld", "st"} {
				if name == fmt.Sprintf("%s%d_advsimd_mult.xml", prefix, n) || name == fmt.Sprintf("%s%d_advsimd_sngl.xml", prefix, n) {
					chosen = true
				}
			}
			if name == fmt.Sprintf("ld%dr_advsimd.xml", n) {
				chosen = true
			}
		}
		if !chosen {
			continue
		}
		pages++
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var parsed page
		if err = xml.Unmarshal(body, &parsed); err != nil {
			t.Fatal(err)
		}
		for _, cl := range parsed.Classes {
			cm, cv := fixed(cl.Diagram.Boxes)
			fields := map[string]box{}
			for _, b := range cl.Diagram.Boxes {
				fields[b.Name] = b
			}
			for _, enc := range cl.Encodings {
				em, ev := fixed(enc.Boxes)
				// Q=1, Rn=1, Rt=31 exercises V31->V0 wrapping. Register post-index Xm=1
				// aliases the base; fixed immediate/no-offset fields override that choice.
				word := uint32(1<<30 | 1<<16 | 1<<5 | 31)
				word = word&^cm | cv
				word = word&^em | ev
				for _, m := range equality.FindAllStringSubmatch(enc.Diff, -1) {
					b, ok := fields[m[1]]
					if !ok {
						t.Fatalf("missing field %s in %s", m[1], enc.Name)
					}
					for i, bit := range m[2] {
						if bit == 'x' {
							continue
						}
						mask := uint32(1) << uint(b.Hi-i)
						word &^= mask
						if bit == '1' {
							word |= mask
						}
					}
				}
				fmt.Fprintf(&result, "(0x%08x,%q),\n", word, enc.Name)
				count++
			}
		}
	}
	if pages != 20 || count < 100 {
		t.Fatalf("incomplete real structure corpus: %d pages, %d encodings", pages, count)
	}
	result.WriteString("];\n")
	t.Logf("derived %d physical structure words from %d upstream pages", count, pages)
	return result.String()
}

const a64MemoryBehavior = `
#[allow(dead_code)] mod semantics;
mod structure_memory_behavior {
 use super::semantics::*;
 use super::semantics::arm64_memory::a64;
 use std::{cell::RefCell,collections::HashMap};
 #[derive(Clone)] struct State {registers:HashMap<Register,Value>,bytes:Vec<u8>,reads:RefCell<Vec<(u64,u8,Endian)>>,fail:Option<usize>}
 fn reg(bank:&'static str,index:u16)->Register{register(bank,index,64,64).register}
 fn vector(n:u16,chunk:u16)->Register {reg("a64.vector64",n*32+chunk)}
 impl State {
  fn new()->Self {let mut s=Self{registers:HashMap::new(),bytes:(0..128).map(|i|(i as u8).wrapping_mul(17).wrapping_add(3)).collect(),reads:RefCell::new(vec![]),fail:None};
   for n in 0..32 {for chunk in 0..2 {s.registers.insert(vector(n,chunk),Value::known(64,0x123456789abcdef0u64.wrapping_mul(u64::from(n*2+chunk+1))));}}
   for n in 0..31 {s.registers.insert(reg("a64.gpr",n),Value::known(64,if n==1 {32}else{11}));}
   s.registers.insert(reg("a64.sp",0),Value::known(64,32));s
  }
  fn value(&self,r:Register)->u64 {self.registers[&r].bits}
  fn commit(&mut self,t:&Transition)->Result<(),EvalError> {
   let mut bytes=self.bytes.clone();for m in &t.memory {let b=encode(m.value.bits,m.value.width,m.endian);let dest=bytes.get_mut(m.address as usize..m.address as usize+b.len()).ok_or(EvalError::Memory)?;dest.copy_from_slice(&b);}
   self.bytes=bytes;for r in &t.registers {self.registers.insert(r.register,r.value);}Ok(())
  }
 }
 impl Machine for State {
  fn read_register(&self,r:Register)->Value {*self.registers.get(&r).unwrap_or_else(||panic!("unexpected input {r:?}"))}
  fn read_memory(&self,address:u64,width:u8,endian:Endian)->Result<Value,EvalError> {
   let mut reads=self.reads.borrow_mut();let index=reads.len();reads.push((address,width,endian));if self.fail==Some(index){return Err(EvalError::Memory);}
   let bytes=self.bytes.get(address as usize..address as usize+usize::from(width/8)).ok_or(EvalError::Memory)?;
   Ok(Value::known(width,decode(bytes,endian)))
  }
  fn read_wide_memory(&self,_:u64,_:u16,_:Endian)->Result<Vec<Value>,EvalError>{panic!("structure accesses falsely aggregated")}
 }
 fn decode(bytes:&[u8],endian:Endian)->u64 {bytes.iter().enumerate().fold(0,|a,(i,b)|a|(u64::from(*b)<<8*if endian==Endian::Little{i}else{bytes.len()-1-i}))}
 fn encode(value:u64,width:u8,endian:Endian)->Vec<u8> {(0..usize::from(width/8)).map(|i|(value>>8*if endian==Endian::Little{i}else{usize::from(width/8)-1-i})as u8).collect()}
 #[derive(Clone,Copy,Debug)] struct Spec {rpt:u8,structures:u8,width:u8,vector_bits:u16,lane:Option<u8>,replicate:bool,load:bool}
 fn reference(s:&mut State,spec:Spec,endian:Endian,rt:u16,post:Option<u16>) {
  let size=usize::from(spec.width/8);let lanes=if spec.lane.is_some()||spec.replicate{1}else{usize::from(spec.vector_bits/u16::from(spec.width))};
  let registers=usize::from(spec.rpt*spec.structures);let original=s.registers.clone();
  if spec.load && spec.lane.is_none() {for n in 0..registers {for chunk in 0..2 {s.registers.insert(vector((rt+n as u16)%32,chunk),Value::known(64,0));}}}
  let transfers=registers*lanes;
  for transfer in 0..transfers {
   let (relative,lane)=if spec.lane.is_some()||spec.replicate {(transfer,spec.lane.unwrap_or(0)as usize)}else if spec.structures==1 {(transfer/lanes,transfer%lanes)}else{(transfer%registers,transfer/registers)};
   let n=(rt+relative as u16)%32;let at=32+transfer*size;
   if spec.load {let value=decode(&s.bytes[at..at+size],endian);
    for lane in if spec.replicate {0..usize::from(spec.vector_bits/u16::from(spec.width))}else{lane..lane+1} {
     let bit=lane*usize::from(spec.width);let r=vector(n,(bit/64)as u16);let shift=bit%64;let mask=if spec.width==64{u64::MAX}else{(1u64<<spec.width)-1};
     let old=s.value(r);s.registers.insert(r,Value::known(64,(old&!(mask<<shift))|(value<<shift)));
    }
   }else{let bit=lane*usize::from(spec.width);let value=original[&vector(n,(bit/64)as u16)].bits>>(bit%64);s.bytes[at..at+size].copy_from_slice(&encode(value,spec.width,endian));}
  }
  if let Some(rm)=post {let increment=if rm==31{(transfers*size)as u64}else{original[&reg("a64.gpr",rm)].bits};s.registers.insert(reg("a64.gpr",1),Value::known(64,32u64.wrapping_add(increment)));}
 }
 fn check(word:u32,spec:Spec,endian:Endian,post:Option<u16>) {
  let mut state=State::new();let mut expected=state.clone();reference(&mut expected,spec,endian,31,post);
  let recipe=a64(word,0x1000,endian).expect("structure family");assert_eq!(recipe.support,Support::Full,"{word:08x} {spec:?}");
  assert!(recipe.wide_loads.is_empty());assert!(recipe.atomics.is_empty());
  let transition=evaluate(&recipe,&state).unwrap_or_else(|e|panic!("{word:08x}: {e:?}"));
  assert_eq!(state.registers,State::new().registers);assert_eq!(state.bytes,State::new().bytes);
  let transfers=usize::from(spec.rpt*spec.structures)*if spec.lane.is_some()||spec.replicate{1}else{usize::from(spec.vector_bits/u16::from(spec.width))};
  if spec.load {assert_eq!(*state.reads.borrow(),(0..transfers).map(|i|(32+(i*usize::from(spec.width/8))as u64,spec.width,endian)).collect::<Vec<_>>());}
  else {assert!(state.reads.borrow().is_empty());assert_eq!(transition.memory.len(),transfers);assert_eq!(transition.events,(0..transfers).map(OrderedEvent::Store).collect::<Vec<_>>());}
  assert!(transition.wide_memory.is_empty());assert_eq!(transition.next_pc,Value::known(64,0x1004));state.commit(&transition).unwrap();
  assert_eq!(state.registers,expected.registers,"{word:08x} {endian:?} {spec:?}");assert_eq!(state.bytes,expected.bytes,"{word:08x} {endian:?} {spec:?}");
 }
 fn addressing(word:u32,post:Option<u16>)->u32 {word|31|(1<<5)|post.map_or(0,|rm|(1<<23)|(u32::from(rm)<<16))}
 #[test]fn every_multiple_structure_shape_interleaves_and_wraps_registers(){
  for (opcode,rpt,structures) in [(7,1,1),(10,2,1),(6,3,1),(2,4,1),(8,1,2),(4,1,3),(0,1,4)] {
   for q in 0..=1 {for scale in 0..=3 {if q==0&&scale==3&&structures!=1 {continue}for load in [false,true]{for endian in [Endian::Little,Endian::Big]{for post in [None,Some(31),Some(3),Some(1)]{
    let word=addressing(0x0c000000|(q<<30)|(u32::from(load)<<22)|(opcode<<12)|(scale<<10),post);
    check(word,Spec{rpt,structures,width:8<<scale,vector_bits:64<<q,lane:None,replicate:false,load},endian,post);
   }}}}}
  }
 }
 fn single_word(structures:u8,width:u8,index:u8)->u32 {
  let (scale,q,s,size)=match width {8=>(0,index>>3,(index>>2)&1,index&3),16=>(1,index>>2,(index>>1)&1,(index&1)<<1),32=>(2,index>>1,index&1,0),64=>(2,index,0,1),_=>panic!()};
  let opcode=(scale<<1)|((structures-1)>>1);0x0d000000|(u32::from(q)<<30)|(u32::from((structures-1)&1)<<21)|(u32::from(opcode)<<13)|(u32::from(s)<<12)|(u32::from(size)<<10)
 }
 #[test]fn lane_transfers_preserve_every_unselected_bit_and_use_one_element_access(){
  for structures in 1..=4 {for width in [8u8,16,32,64] {for index in 0..128/width {for load in [false,true] {for endian in [Endian::Little,Endian::Big]{for post in [None,Some(31),Some(3),Some(1)]{
   let word=addressing(single_word(structures,width,index)|(u32::from(load)<<22),post);
   check(word,Spec{rpt:1,structures,width,vector_bits:128,lane:Some(index),replicate:false,load},endian,post);
  }}}}}}
 }
 #[test]fn replicate_reads_each_element_once_and_clears_upper_half_for_64_bit_destinations(){
  for structures in 1..=4 {for scale in 0..=3 {for q in 0..=1 {for endian in [Endian::Little,Endian::Big] {for post in [None,Some(31),Some(3),Some(1)]{
   let opcode=6|((structures-1)>>1);let word=addressing(0x0d400000|(q<<30)|(((structures-1)&1)<<21)|(opcode<<13)|(scale<<10),post);
   check(word,Spec{rpt:1,structures:structures as u8,width:8<<scale,vector_bits:64<<q,lane:None,replicate:true,load:true},endian,post);
  }}}}}
 }
 #[test]fn faults_publish_no_register_or_memory_updates_and_stores_commit_transactionally(){
  let word=addressing(0x4c400000,Some(31)); // LD4 .16B; 64 separate byte accesses.
  let recipe=a64(word,0,Endian::Big).unwrap();
  for failure in [0,1,31,63] {let mut state=State::new();state.fail=Some(failure);let original=state.clone();assert_eq!(evaluate(&recipe,&state),Err(EvalError::Memory));assert_eq!(state.bytes,original.bytes);assert_eq!(state.registers,original.registers);assert_eq!(state.reads.borrow().len(),failure+1);}
  let mut state=State::new();state.bytes.truncate(63);let original=state.clone();let store=a64(word&!(1<<22),0,Endian::Little).unwrap();let pending=evaluate(&store,&state).unwrap();assert_eq!(state.commit(&pending),Err(EvalError::Memory));assert_eq!(state.bytes,original.bytes);assert_eq!(state.registers,original.registers);
 }
 #[test]fn sp_alignment_and_address_wrap_are_explicit(){
  let word=0x4cdf73ffu32; // LD1 V31.16B,[SP],#16.
  let mut state=State::new();state.registers.insert(reg("a64.sp",0),Value::known(64,33));let recipe=a64(word,0,Endian::Little).unwrap();assert_eq!(evaluate(&recipe,&state),Err(EvalError::UnsupportedContext));assert!(state.reads.borrow().is_empty());
  state.registers.insert(reg("a64.sp",0),Value::known(64,32));let t=evaluate(&recipe,&state).unwrap();assert!(t.registers.iter().any(|r|r.register==reg("a64.sp",0)&&r.value.bits==48));
  // Store address arithmetic is modulo 2^64, including the element offsets.
  let mut state=State::new();state.registers.insert(reg("a64.gpr",1),Value::known(64,u64::MAX-3));let recipe=a64(addressing(0x0c000000,Some(31)),u64::MAX-1,Endian::Little).unwrap();let t=evaluate(&recipe,&state).unwrap();assert_eq!(t.memory[0].address,u64::MAX-3);assert_eq!(t.memory[4].address,0);assert_eq!(t.next_pc.bits,2);assert!(t.registers.iter().any(|r|r.register==reg("a64.gpr",1)&&r.value.bits==28));
 }
 #[test]fn partial_register_availability_is_preserved_for_lane_transfers(){
  // LD1 {V31.H}[5],[X1] changes only bits 95:80, leaving all unavailable
  // incoming bits unavailable and never reading the untouched lower chunk.
  let word=addressing(single_word(1,16,5)|(1<<22),None);
  let mut state=State::new();state.registers.remove(&vector(31,0));state.registers.insert(vector(31,1),Value::unknown(64));
  let t=evaluate(&a64(word,0,Endian::Big).unwrap(),&state).unwrap();assert_eq!(t.registers.len(),1);
  assert_eq!(t.registers[0].register,vector(31,1));assert_eq!(t.registers[0].value.defined,0xffff<<16);
  assert_eq!(t.registers[0].value.bits,decode(&state.bytes[32..34],Endian::Big)<<16);
  // ST1 of that lane consumes only its sixteen known bits, without requiring
  // any other lane or the other chunk of the vector to be available.
  state.registers.insert(vector(31,1),Value{bits:0xabcdu64<<16,defined:0xffff<<16,width:64});
  let t=evaluate(&a64(word&!(1<<22),0,Endian::Big).unwrap(),&state).unwrap();assert_eq!(t.memory[0].value,Value::known(16,0xabcd));
 }
 #[test]fn inactive_recipe_guards_suppress_all_architectural_inputs(){
  struct NoState;impl Machine for NoState {fn read_register(&self,_:Register)->Value{panic!("inactive register read")}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("inactive memory read")}}
  for word in [0x4cdf73ff,0x4c9f73ff,0x0d40c03f,0x4d40103f,0x4d00103f] {
   let mut r=a64(word,0,Endian::Big).unwrap();r.guard=Expr::constant(1,0);let t=evaluate(&r,&NoState).unwrap();assert!(t.registers.is_empty());assert!(t.memory.is_empty());assert!(t.events.is_empty());assert_eq!(t.next_pc.bits,4);
  }
 }
 #[test]fn reserved_encodings_never_claim_full_support(){
  for word in [0x0c200000,0x0c010000,0x0c403000,0x0c400c00,0x0d010000,0x0d004400,0x0d008800,0x0d009400,0x0d00c000,0x0d40d000] {let r=a64(word,0,Endian::Little).unwrap();assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");}
  for word in [0,0xf9400020,0xad400820,0x1e222820,0x8c400000] {assert!(a64(word,0,Endian::Little).is_none(),"{word:08x}");}
 }
 #[test]fn actual_corpus_encoding_constraints_reach_valid_complete_recipes(){
  for &(word,name) in super::STRUCTURE_CORPUS {let r=a64(word,0,Endian::Big).unwrap_or_else(||panic!("{name}"));assert_eq!(r.support,Support::Full,"{name} {word:08x}");evaluate(&r,&State::new()).unwrap_or_else(|e|panic!("{name} {word:08x}: {e:?}"));}
 }
}
`

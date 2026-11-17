package semantics

import (
	_ "embed"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

//go:embed arm32_memory.rs
var arm32MemorySource string

func TestRustArm32StructuredMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"runtime.rs": RustRuntime, "arm32_memory.rs": arm32MemorySource,
		"memory_tests.rs": arm32MemoryBehaviorTests + arm32MemoryCorpus(t),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "memory_tests.rs", "-Dwarnings", "-o", "memory-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A32 structured memory: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "memory-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A32 structured memory: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// Cover every primary encoding diagram, including A32/T32 spacing aliases.
// Runtime layout or dispatch code does not participate in constructing words.
func arm32MemoryCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "Documents/Developer/go-mkasm/ISA_AArch32_xml_A_profile-2026-06")
	if _, err = os.Stat(root); os.IsNotExist(err) {
		t.Log("optional Arm XML absent; portable memory matrix still runs")
		return "const MEMORY_CORPUS:&[(bool,u32,&str)]=&[];"
	}
	type cell struct {
		Text string `xml:",chardata"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type diagram struct {
		Form  string `xml:"form,attr"`
		Boxes []box  `xml:"box"`
	}
	var out strings.Builder
	out.WriteString("const MEMORY_CORPUS:&[(bool,u32,&str)]=&[\n")
	count := 0
	pages := 0
	for n := 1; n <= 4; n++ {
		for _, op := range []string{"vld", "vst"} {
			for _, suffix := range []string{"m", "1", "a"} {
				if op == "vst" && suffix == "a" {
					continue
				}
				name := fmt.Sprintf("%s%d_%s.xml", op, n, suffix)
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				pages++
				decoder := xml.NewDecoder(strings.NewReader(string(data)))
				for {
					token, err := decoder.Token()
					if err != nil {
						if err == io.EOF {
							break
						}
						t.Fatal(err)
					}
					start, ok := token.(xml.StartElement)
					if !ok || start.Name.Local != "regdiagram" {
						continue
					}
					var d diagram
					if err := decoder.DecodeElement(&d, &start); err != nil {
						t.Fatal(err)
					}
					for variant := 0; variant < 2; variant++ {
						var word uint32
						for _, b := range d.Boxes {
							width := b.Width
							if width == 0 {
								width = 1
							}
							var bits strings.Builder
							for _, c := range b.Cells {
								text := strings.Trim(strings.TrimSpace(c.Text), "()")
								if text == "x" {
									text = strconv.Itoa(variant)
								}
								if text == "0" || text == "1" {
									bits.WriteString(text)
								}
							}
							var value uint64
							if bits.Len() == width {
								value, err = strconv.ParseUint(bits.String(), 2, 32)
								if err != nil {
									t.Fatal(err)
								}
							} else {
								switch b.Name {
								case "Rn":
									value = 2
								case "Rm":
									value = uint64(15 - 2*variant)
								case "Vd":
									value = uint64(variant * 8)
								case "D", "T":
									value = uint64(variant)
								}
							}
							word |= uint32(value) << uint(b.Hi-width+1)
						}
						fmt.Fprintf(&out, "(%t,0x%08x,%q),\n", d.Form == "16x2", word, name)
						count++
					}
				}
			}
		}
	}
	out.WriteString("];\n")
	t.Logf("primary structured-memory corpus: %d words from %d pages", count, pages)
	return out.String()
}

const arm32MemoryBehaviorTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
mod arm32_memory;
use std::cell::RefCell;
#[derive(Default)]
struct State { d:[u64;32], g:[u32;16], it:u8, reads:RefCell<Vec<(u64,u8,Endian)>> }
fn byte(a:u64)->u8 { (a.wrapping_mul(37).wrapping_add(a>>8).wrapping_add(19)) as u8 }
fn memory(a:u64,w:u8,endian:Endian)->u64 {
    let bytes=w/8;
    (0..bytes).fold(0,|v,i| v | (u64::from(byte(a+u64::from(i))) << (if endian==Endian::Little {i} else {bytes-1-i} * 8)))
}
impl Machine for State {
    fn read_register(&self,r:Register)->Value {
        match r.bank {
            "a32.vector64"=>Value::known(64,self.d[usize::from(r.index)]),
            "a32.gpr"=>Value::known(32,u64::from(self.g[usize::from(r.index)])),
            "pipeline"=>Value::known(8,0x44),
            "a32.itstate"=>Value::known(8,u64::from(self.it)),
            _=>panic!("unexpected input {r:?}"),
        }
    }
    fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError> {
        self.reads.borrow_mut().push((a,w,e)); Ok(Value::known(w,memory(a,w,e)))
    }
}
fn initial()->State {
    let mut s=State::default();
    for i in 0..32 { s.d[i]=0x814223c465a607e8u64.rotate_left(i as u32); }
    s.g[2]=0x100; s.g[3]=0x37; s
}
fn base(active:bool,thumb:bool)->Recipe {
    let mut r=Recipe::new(0x1004,32); r.guard=Expr::constant(1,u64::from(active));
    if thumb { r.write_always(register("pipeline",0,8,8),WritePolicy::ZeroUpper,Expr::constant(8,0x18)); }
    r
}
fn word(single:bool,load:bool,d:u32,typ:u32,bits:u32,m:u32)->u32 {
    0xf4000000 | (u32::from(single)<<23) | (u32::from(load)<<21)
      | ((d>>4)<<22) | (2<<16) | ((d&15)<<12) | (typ<<8) | bits | m
}
fn recipe(w:u32,thumb:bool,e:Endian,active:bool)->Recipe {
    let b=base(active,thumb);
    let r=if thumb { arm32_memory::thumb((w&0xffffff)|0xf9000000,4,b.clone(),e) }
          else { arm32_memory::a32(w,b.clone(),e) }.unwrap();
    assert_eq!(r.always_writes,b.always_writes); assert_eq!(r.flow,b.flow);
    r
}
fn value(t:&Transition,s:&State,bank:&'static str,index:usize)->u64 {
    t.registers.iter().rev().find(|w|w.register==Register{bank,index:index as u16}).map(|w| {
        assert!(w.value.is_known()); w.value.bits
    }).unwrap_or_else(||if bank=="a32.vector64" {s.d[index]} else {u64::from(s.g[index])})
}
fn run(w:u32,thumb:bool,endian:Endian,s:&State)->Transition {
    let r=recipe(w,thumb,endian,true); assert_eq!(r.support,Support::Full,"{w:08x}");
    r.validate().unwrap(); let t=evaluate(&r,s).unwrap_or_else(|e|panic!("{w:08x}: {e:?}"));
    assert_eq!(t.trap,None,"{w:08x}"); assert!(t.atomics.is_empty()); assert!(t.wide_memory.is_empty());
    assert_eq!(t.next_pc,Value::known(32,0x1004)); t
}
// Independent explicit table: (physical type,number of structures,registers
// per structure,spacing). Iteration is the architectural memory order.
const MULTIPLE:&[(u32,usize,usize,usize)]=&[
 (7,1,1,1),(10,1,2,1),(6,1,3,1),(2,1,4,1),
 (8,2,1,1),(9,2,1,2),(3,2,2,2),(4,3,1,1),(5,3,1,2),(0,4,1,1),(1,4,1,2),
];
#[test]
fn all_multiple_layouts_endians_and_postindex_modes() {
    for thumb in [false,true] { for endian in [Endian::Little,Endian::Big] {
      for &(typ,streams,groups,spacing) in MULTIPLE { for bytes in [1u8,2,4,8] {
        if streams!=1 && bytes==8 {continue;}
        for load in [false,true] { for m in [15,13,3,2] {
          let s=initial(); let w=word(false,load,16,typ,u32::from(bytes.trailing_zeros() as u8)<<6,m);
          let t=run(w,thumb,endian,&s); let mut expected=s.d; let mut accesses=Vec::new(); let mut offset=0u32;
          for group in 0..groups {for lane in 0..8/bytes {for stream in 0..streams {
            let reg=16+stream*spacing+group; let a=0x100+u64::from(offset); let width=bytes*8;
            if load {
                let v=memory(a,width,endian); let mask=runtime::mask(width)<<(lane*width);
                expected[reg]=(expected[reg]&!mask)|(v<<(lane*width));
            } else {
                let v=(s.d[reg]>>(lane*width))&runtime::mask(width);
                if bytes==8 { for i in 0..2 {
                    let shift=if endian==Endian::Little {i*32} else {(1-i)*32};
                    accesses.push((a+i*4,32,(v>>shift)&0xffffffff));
                }} else {accesses.push((a,width,v));}
            }
            offset+=u32::from(bytes);
          }}}
          for (i,expected) in expected.into_iter().enumerate() { assert_eq!(value(&t,&s,"a32.vector64",i),expected,"{w:08x} D{i}"); }
          if load {
              let reads=s.reads.borrow(); assert_eq!(reads.len(),if bytes==8 {offset as usize/4} else {offset as usize/usize::from(bytes)});
              for (i,(a,width,e)) in reads.iter().enumerate() {
                  // VLD1 .64 assigns the low numerical half first, so big
                  // endian reverses the two word reads within each element.
                  let index=if bytes==8&&endian==Endian::Big {i^1}else{i};
                  assert_eq!((*a,*width,*e),(0x100+(index*usize::from(if bytes==8 {4}else{bytes})) as u64,if bytes==8{32}else{bytes*8},endian));
              }
              assert!(t.memory.is_empty());
          } else {
              assert!(s.reads.borrow().is_empty()); assert_eq!(t.memory.len(),accesses.len());
              for (actual,(a,w,v)) in t.memory.iter().zip(accesses) {assert_eq!((actual.address,actual.value,actual.endian),(a,Value::known(w,v),endian));}
          }
          let expected_g=match m {15=>0x100,13=>0x100+u64::from(offset),3=>0x137,2=>0x200,_=>unreachable!()};
          assert_eq!(value(&t,&s,"a32.gpr",2),expected_g,"{w:08x}");
        }}
      }}
    }}
}
#[test]
fn every_single_lane_keeps_unselected_bits_and_spaced_registers() {
    for thumb in [false,true] {for endian in [Endian::Little,Endian::Big] {
      for streams in 1..=4u32 {for size in 0..3u32 {for index in 0..(8>>size) {
        for spacing in 1..=2u32 {
          if (streams==1 || size==0) && spacing==2 {continue;}
          for load in [false,true] {
            let bytes=1u8<<size; let ia=(index<<(size+1))|if size==0 {0}else{(spacing-1)<<size};
            let s=initial();let w=word(true,load,20,(size<<2)|(streams-1),ia<<4,13);
            let t=run(w,thumb,endian,&s);let mut expected=s.d;
            for stream in 0..streams {
              let reg=(20+stream*spacing) as usize;let offset=stream*u32::from(bytes);let shift=index*u32::from(bytes)*8;
              if load {let mask=runtime::mask(bytes*8)<<shift;expected[reg]=(expected[reg]&!mask)|(memory(0x100+u64::from(offset),bytes*8,endian)<<shift);}
              else {let actual=&t.memory[stream as usize];assert_eq!((actual.address,actual.value,actual.endian),(0x100+u64::from(offset),Value::known(bytes*8,(s.d[reg]>>shift)&runtime::mask(bytes*8)),endian));}
            }
            for(i,expected)in expected.into_iter().enumerate(){assert_eq!(value(&t,&s,"a32.vector64",i),expected,"{w:08x} D{i}");}
            assert_eq!(value(&t,&s,"a32.gpr",2),0x100+u64::from(streams)*u64::from(bytes));
            assert_eq!(s.reads.borrow().len(),if load {streams as usize}else{0});
          }
        }
      }}}
    }}
}
#[test]
fn replicate_reads_each_structure_once_and_vld1_duplicates_one_read() {
 for thumb in [false,true] {for endian in [Endian::Little,Endian::Big] {for streams in 1..=4u32 {for size in 0..3u32 {for tbit in 0..2u32 {
    let bytes=1u8<<size;let s=initial();let w=word(true,true,16,12+streams-1,(size<<6)|(tbit<<5),13);
    let transition=run(w,thumb,endian,&s);let mut expected=s.d;
    for stream in 0..streams {
        let v=memory(0x100+u64::from(stream)*u64::from(bytes),bytes*8,endian);
        let repeated=(0..8/bytes).fold(0,|r,i|r|(v<<(i*bytes*8)));
        let reg=(16+stream*(1+tbit))as usize;expected[reg]=repeated;
        if streams==1 && tbit==1 {expected[reg+1]=repeated;}
    }
    for(i,expected)in expected.into_iter().enumerate(){assert_eq!(value(&transition,&s,"a32.vector64",i),expected,"{w:08x} D{i}");}
    assert_eq!(s.reads.borrow().len(),streams as usize);assert!(transition.memory.is_empty());
    assert_eq!(value(&transition,&s,"a32.gpr",2),0x100+u64::from(streams)*u64::from(bytes));
 }}}}}
}
#[test]
fn alignment_faults_precede_memory_and_outputs_and_predication_suppresses_them() {
 for thumb in [false,true] {for load in [false,true] {
    let mut s=initial();s.g[2]=0x101;
    for w in [word(false,load,0,7,1<<4,13),word(true,load,0,1,1<<4,13),word(true,load,0,8,3<<4,13)] {
        let r=recipe(w,thumb,Endian::Little,true);assert_eq!(r.support,Support::Full);
        let transition=evaluate(&r,&s).unwrap();assert_eq!(transition.trap,Some(TrapKind::Protection));
        assert!(s.reads.borrow().is_empty());assert!(transition.memory.is_empty());assert!(transition.registers.is_empty());
        let r=recipe(w,thumb,Endian::Big,false);let transition=evaluate(&r,&s).unwrap();
        assert_eq!(transition.trap,None);assert!(transition.memory.is_empty());assert!(s.reads.borrow().is_empty());
        assert_eq!(transition.registers.len(),usize::from(thumb));
        if thumb {assert_eq!(transition.registers[0].value,Value::known(8,0x18));}
    }
 }}
}
#[test]
fn reserved_encodings_register_overflow_and_pc_bases_are_rejected() {
 for thumb in [false,true] {for w in [
    word(false,true,0,11,0,15),word(false,true,0,8,3<<6,15),
    word(false,true,0,7,2<<4,15),word(false,true,31,10,0,15),
    word(false,true,0,7,0,15)|(15<<16),word(true,true,31,1,0,15),
    word(true,true,0,0,1<<4,15),word(true,true,0,4,2<<4,15),
    word(true,true,0,8,1<<4,15),word(true,false,0,12,0,15),
    word(true,true,0,12,1<<4,15),word(true,true,0,14,1<<4,15),
    word(true,true,0,15,3<<6,15),
 ] {let r=recipe(w,thumb,Endian::Little,true);assert!(matches!(r.support,Support::Unsupported(_)),"{w:08x}");}}
 assert!(arm32_memory::a32(0xed900a00,base(true,false),Endian::Little).is_none());
 assert!(arm32_memory::thumb(0xf920070f,2,base(true,true),Endian::Little).is_none());
}
#[test]
fn aligned64_uses_two_word_accesses_and_unrepresented_unaligned_policy_is_checked() {
 for thumb in [false,true] {for load in [false,true] {
    let mut s=initial();s.g[2]=0x104;let w=word(false,load,31,7,3<<6,13);
    let r=recipe(w,thumb,Endian::Little,true);assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));
    assert!(s.reads.borrow().is_empty());
    // Explicit alignment overrides the missing optional SCTLR policy: this
    // context is a definite architectural fault, never an unsupported guess.
    let encoded=recipe(w|(1<<4),thumb,Endian::Little,true);
    let fault=evaluate(&encoded,&s).unwrap();assert_eq!(fault.trap,Some(TrapKind::Protection));
    assert!(fault.registers.is_empty());assert!(fault.memory.is_empty());assert!(s.reads.borrow().is_empty());
    let r=recipe(w,thumb,Endian::Little,false);assert!(evaluate(&r,&s).is_ok());
 }}
}
#[test]
fn split64_loads_observe_primary_endian_read_order_before_fault() {
 struct Fault<'a> {state:&'a State,at:u64}
 impl Machine for Fault<'_> {
    fn read_register(&self,r:Register)->Value {self.state.read_register(r)}
    fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError> {
        self.state.reads.borrow_mut().push((a,w,e));
        if a==self.at {Err(EvalError::Memory)}else{Ok(Value::known(w,memory(a,w,e)))}
    }
 }
 for thumb in [false,true] {for endian in [Endian::Little,Endian::Big] {for second in [false,true] {
    let state=initial();let incoming_d=state.d;let incoming_g=state.g;
    let order=if endian==Endian::Little {[0x100,0x104]}else{[0x104,0x100]};
    let fault=Fault{state:&state,at:order[usize::from(second)]};
    let w=word(false,true,31,7,3<<6,13);let r=recipe(w,thumb,endian,true);
    assert_eq!(evaluate(&r,&fault),Err(EvalError::Memory));
    assert_eq!(*state.reads.borrow(),order[..=usize::from(second)].iter().map(|&a|(a,32,endian)).collect::<Vec<_>>());
    assert_eq!(state.d,incoming_d);assert_eq!(state.g,incoming_g);
    state.reads.borrow_mut().clear();
    assert!(evaluate(&recipe(w,thumb,endian,false),&fault).is_ok());
    assert!(state.reads.borrow().is_empty());
 }}}
}
#[test]
fn addresses_and_register_postindex_wrap_at32_bits() {
 for endian in [Endian::Little,Endian::Big] {
    let mut s=initial();s.g[2]=0xfffffffc;s.g[3]=8;
    let w=word(false,true,0,7,0,3);let transition=run(w,false,endian,&s);
    let addresses=s.reads.borrow().iter().map(|x|x.0).collect::<Vec<_>>();
    assert_eq!(addresses,vec![0xfffffffc,0xfffffffd,0xfffffffe,0xffffffff,0,1,2,3]);
    assert_eq!(value(&transition,&s,"a32.gpr",2),4);
 }
}

#[test]
fn inherited_dynamic_predicate_and_it_pipeline_updates_observe_incoming_state() {
 for active in [false,true] {for load in [false,true] {
    let mut s=initial();s.it=if active {0x18}else{0x08};
    let mut base=Recipe::new(0x1004,32);
    let it=Expr::register(register("a32.itstate",0,8,8));
    base.guard=Expr::extract(it.clone(),4,1);
    base.write_always(register("a32.itstate",0,8,8),WritePolicy::ZeroUpper,
        Expr::binary(BinaryOp::Shl,it,Expr::constant(8,1)));
    let w=(word(false,load,0,7,0,13)&0xffffff)|0xf9000000;
    let r=arm32_memory::thumb(w,4,base.clone(),Endian::Little).unwrap();
    assert_eq!(r.guard,base.guard);assert_eq!(r.always_writes,base.always_writes);
    let transition=evaluate(&r,&s).unwrap();
    assert_eq!(transition.registers.last().unwrap().register,Register{bank:"a32.itstate",index:0});
    assert_eq!(transition.registers.last().unwrap().value,Value::known(8,u64::from(s.it)<<1));
    assert_eq!(s.reads.borrow().len(),if active&&load{8}else{0});
    assert_eq!(transition.memory.len(),if active&&!load{8}else{0});
    assert_eq!(value(&transition,&s,"a32.gpr",2),if active{0x108}else{0x100});
 }}
}
#[test]
fn primary_xml_physical_encodings_execute_as_a32_and_thumb() {
 for &(thumb,w,name) in MEMORY_CORPUS {
    let s=initial();let t=run(w,thumb,Endian::Little,&s);
    let load=w&(1<<21)!=0;
    assert_eq!(t.memory.is_empty(),load,"{name} {w:08x}");
    assert_eq!(s.reads.borrow().is_empty(),!load,"{name} {w:08x}");
    assert_eq!(t.registers.last().is_some_and(|x|x.register.bank=="pipeline"),thumb,"{name} {w:08x}");
 }
}

#[test]
fn all_encoded_alignment_sizes_fault_before_memory_and_support_special_vld4_32() {
 let forms=&[
   // multiple: byte elements, one/two/three/four-D layouts and streams
   (false,7,1<<4,8),(false,10,2<<4,16),(false,6,1<<4,8),
   (false,2,3<<4,32),(false,8,2<<4,16),(false,3,3<<4,32),
   (false,4,1<<4,8),(false,0,3<<4,32),
   // single-lane: distinct permitted alignment encodings
   (true,4,1<<4,2),(true,8,3<<4,4),(true,1,1<<4,2),
   (true,5,1<<4,4),(true,9,1<<4,8),(true,3,1<<4,4),
   (true,7,1<<4,8),(true,11,1<<4,8),(true,11,2<<4,16),
   // replicate: VLD4 size=3,a=1 is .32 with 16-byte alignment
   (true,12,(1<<6)|(1<<4),2),(true,12,(2<<6)|(1<<4),4),
   (true,13,1<<4,2),(true,13,(1<<6)|(1<<4),4),(true,13,(2<<6)|(1<<4),8),
   (true,15,1<<4,4),(true,15,(1<<6)|(1<<4),8),
   (true,15,(2<<6)|(1<<4),8),(true,15,(3<<6)|(1<<4),16),
 ];
 for thumb in [false,true] {for &(single,typ,bits,alignment) in forms {
    let w=word(single,true,0,typ,bits,13);
    let mut s=initial();let r=recipe(w,thumb,Endian::Big,true);
    assert_eq!(r.support,Support::Full,"{w:08x}");
    let good=evaluate(&r,&s).unwrap();assert_eq!(good.trap,None,"{w:08x}");
    if single && typ==15 && bits>>6==3 {
        assert_eq!(*s.reads.borrow(),vec![(0x100,32,Endian::Big),(0x104,32,Endian::Big),(0x108,32,Endian::Big),(0x10c,32,Endian::Big)]);
        for reg in 0..4 {let value32=memory(0x100+reg*4,32,Endian::Big);
            assert_eq!(value(&good,&s,"a32.vector64",reg as usize),value32|(value32<<32));}
        assert_eq!(value(&good,&s,"a32.gpr",2),0x110);
    }
    s.reads.borrow_mut().clear();s.g[2]+=alignment/2;
    let bad=evaluate(&r,&s).unwrap();assert_eq!(bad.trap,Some(TrapKind::Protection),"{w:08x}");
    assert!(s.reads.borrow().is_empty());assert!(bad.registers.is_empty());assert!(bad.memory.is_empty());
 }}
}
`

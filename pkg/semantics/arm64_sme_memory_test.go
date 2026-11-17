package semantics

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRustA64SMEMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_sme") {
		source += "\npub mod arm64_sme {\n" + a64SMEModuleSource + "\n}\n"
	}
	for name, body := range map[string]string{"semantics.rs": source, "memory.rs": a64SMEMemoryBehavior + a64SMEMemoryCorpus(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "memory.rs", "-Dwarnings", "-o", "memory-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile SME memory: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "memory-tests"), "memory_behavior::", "--test-threads=1")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute SME memory: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// Construct actual words from every June memory-class diagram, independently
// of the helper's dispatch. Named register fields keep all addresses in the
// byte-backed fixture while both legal encoded register-list extremes run.
func a64SMEMemoryCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		return "const SME_MEMORY_CORPUS:&[(u32,&str)]=&[];"
	}
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
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type class struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []struct {
			Name string `xml:"name,attr"`
		} `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	wanted := map[string]bool{"ldr_za_ri": true, "str_za_ri": true, "ldr_zt_br": true, "str_zt_br": true}
	for _, op := range []string{"ld1", "st1"} {
		for _, size := range []string{"b", "h", "w", "d", "q"} {
			wanted[op+size+"_za_p_rrr"] = true
		}
	}
	for _, op := range []string{"ld1", "st1", "ldnt1", "stnt1"} {
		for _, size := range []string{"b", "h", "w", "d"} {
			for _, form := range []string{"_mz_p_bi", "_mz_p_br", "_mzx_p_bi", "_mzx_p_br"} {
				wanted[op+size+form] = true
			}
		}
	}
	var out strings.Builder
	out.WriteString("const SME_MEMORY_CORPUS:&[(u32,&str)]=&[\n")
	reader := tar.NewReader(gz)
	pages, words := 0, 0
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
			for _, en := range cl.Encodings {
				for extreme := 0; extreme < 2; extreme++ {
					var word uint32
					for _, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						pos := b.Hi
						var fixedMask, fixedValue uint32
						for _, c := range b.Cells {
							span := c.Span
							if span == 0 {
								span = 1
							}
							text := strings.Trim(strings.TrimSpace(c.Text), "()")
							if len(text) == span {
								for _, bit := range text {
									if bit == '0' || bit == '1' {
										fixedMask |= 1 << uint(pos)
										if bit == '1' {
											fixedValue |= 1 << uint(pos)
										}
									}
									pos--
								}
							} else {
								pos -= span
							}
						}
						value := uint32(0)
						if extreme != 0 {
							value = (1 << uint(width)) - 1
						}
						switch b.Name {
						case "Rn":
							value = 2
						case "Rm":
							value = 3
						case "Rv", "Rs", "Pg", "PNg":
							value = 0
						case "imm4":
							value = uint32(extreme)
						}
						region := ((uint32(1) << uint(width)) - 1) << uint(b.Hi-width+1)
						word |= (value<<uint(b.Hi-width+1))&(region&^fixedMask) | fixedValue
					}
					fmt.Fprintf(&out, "(0x%08x,%q),\n", word, en.Name)
					words++
				}
			}
		}
	}
	if pages != len(wanted) || words < 250 {
		t.Fatalf("SME memory corpus pages=%d want=%d words=%d", pages, len(wanted), words)
	}
	t.Logf("SME memory June primary XML: %d pages, %d words", pages, words)
	out.WriteString("];\n")
	return out.String()
}

const a64SMEMemoryBehavior = `
#[allow(dead_code)] mod semantics;
#[cfg(test)] mod memory_behavior {
 use super::{semantics::{*,arm64_sme::a64_with_endian},SME_MEMORY_CORPUS};
 use std::{collections::{BTreeMap,HashMap},cell::RefCell};
 const SVLS:[u16;5]=[128,256,512,1024,2048];
 fn reg(bank:&'static str,index:u16)->Register{Register{bank,index}}
 fn za(row:u16,chunk:u16)->Register{reg("a64.za64",row*32+chunk)}
 fn z(n:u16,chunk:u16)->Register{reg("a64.vector64",n*32+chunk)}
 fn p(n:u16,chunk:u16)->Register{reg("a64.predicate64",n*4+chunk)}
 fn mask(w:u8)->u64{u64::MAX>>(64-w)}
 #[derive(Clone)] struct State {
  regs:HashMap<Register,Value>,bytes:Vec<u8>,extra:BTreeMap<u64,u8>,
  reads:RefCell<Vec<(u64,u16,Endian)>>,inputs:RefCell<Vec<Register>>,fault:Option<u64>,
 }
 impl State {
  fn new()->Self {
   let mut s=Self{regs:HashMap::new(),bytes:(0..65536u64).map(|a|(a.wrapping_mul(37)^(a>>7)^0xa5)as u8).collect(),extra:BTreeMap::new(),reads:RefCell::new(vec![]),inputs:RefCell::new(vec![]),fault:None};
   for row in 0..256{for chunk in 0..32{s.set(za(row,chunk),64,0x81ff02037f80fe01^u64::from(row*32+chunk));}}
   for n in 0..32{for chunk in 0..32{s.set(z(n,chunk),64,0xfe8002037f8001ff^u64::from(n*32+chunk));}}
   for n in 0..16{for chunk in 0..4{s.set(p(n,chunk),64,0);}}
   for n in 0..31{s.set(reg("a64.gpr",n),64,if n==2 {0x4000}else if n==3 {3}else {0xffff_ffff});}
   for chunk in 0..8{s.set(reg("a64.zt064",chunk),64,0x12fe45ab99776003^u64::from(chunk));}
   s.set(reg("a64.sve2p1",0),1,0);s.set(reg("a64.sp",0),64,0x4000);s.set(reg("a64.svcr",0),2,3);s
  }
  fn set(&mut self,r:Register,width:u8,bits:u64){self.regs.insert(r,Value::known(width,bits));}
  fn bits(&self,r:Register)->u64{self.regs[&r].bits}
  fn pred(&mut self,n:u16,byte:u16,active:bool){let r=p(n,byte/64);let bit=1u64<<(byte%64);let old=self.bits(r);self.set(r,64,if active{old|bit}else{old&!bit});}
  fn numeric(&self,a:u64,w:u16,e:Endian)->Vec<Value>{
   let mut chunks=vec![0u64;usize::from(w).div_ceil(64)];
   for i in 0..w/8 {let at=a.wrapping_add(u64::from(i));let byte=self.extra.get(&at).copied().or_else(||usize::try_from(at).ok().and_then(|a|self.bytes.get(a).copied())).unwrap_or_else(||panic!("unmapped test memory {at:x}"));
    let pos=if e==Endian::Little{i}else{w/8-1-i};chunks[usize::from(pos/8)]|=u64::from(byte)<<((pos%8)*8);
   }
   chunks.into_iter().enumerate().map(|(i,v)|Value::known((usize::from(w)-i*64).min(64)as u8,v)).collect()
  }
  fn observed(&self,a:u64,w:u16,e:Endian)->Result<Vec<Value>,EvalError>{self.reads.borrow_mut().push((a,w,e));if self.fault.is_some_and(|fault|(0..w/8).any(|i|a.wrapping_add(u64::from(i))==fault)){return Err(EvalError::Memory)}Ok(self.numeric(a,w,e))}
  fn commit(&mut self,t:&Transition){assert!(t.trap.is_none());assert_eq!(t.next_pc,Value::known(64,0x1004));for w in &t.registers{assert!(w.value.is_known());self.regs.insert(w.register,w.value);}}
  fn lane(&mut self,row:u16,bit:u16,w:u8,value:u64){let r=za(row,bit/64);let shift=bit%64;self.set(r,64,(self.bits(r)&!(mask(w)<<shift))|((value&mask(w))<<shift));}
 }
 impl Machine for State {
  fn read_register(&self,r:Register)->Value{self.inputs.borrow_mut().push(r);*self.regs.get(&r).unwrap_or_else(||panic!("unavailable input {r:?}"))}
  fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{Ok(self.observed(a,u16::from(w),e)?[0])}
  fn read_wide_memory(&self,a:u64,w:u16,e:Endian)->Result<Vec<Value>,EvalError>{self.observed(a,w,e)}
 }
 fn recipe(word:u32,svl:u16,e:Endian)->Recipe{let r=a64_with_endian(word,0x1000,svl,e).unwrap_or_else(||panic!("unrecognized {word:08x}"));assert_eq!(r.support,Support::Full);r.validate().unwrap();r}
 fn stores(t:&Transition)->Vec<(u64,u16,Endian,Vec<Value>)>{t.events.iter().filter_map(|event|match *event{
  OrderedEvent::Store(i)=>{let w=&t.memory[i];Some((w.address,u16::from(w.value.width),w.endian,vec![w.value]))},
  OrderedEvent::WideStore(i)=>{let w=&t.wide_memory[i];Some((w.address,w.width,w.endian,w.chunks.clone()))},_=>None}).collect()}

 #[test]fn za_rows_and_zt0_keep_original_byte_accesses_and_no_writeback(){
  for svl in SVLS {for endian in [Endian::Little,Endian::Big]{for table in [false,true]{for load in [false,true]{
   let mut s=State::new();s.set(reg("a64.svcr",0),2,2);let before=s.clone();
   let offset=if table{0}else{15};let bytes=if table{64}else{svl/8};let selected=(0xffff_ffffu64+offset)%u64::from(svl/8);
   let word=if table{0xe11f8000}else{0xe1000000}|(u32::from(!load)<<21)|(2<<5)|offset as u32;
   let r=recipe(word,svl,endian);let t=evaluate(&r,&s).unwrap();s.commit(&t);
   let address=0x4000+offset*u64::from(bytes);
   if load{
    assert_eq!(*s.reads.borrow(),(0..bytes).map(|i|(address+u64::from(i),8,Endian::Little)).collect::<Vec<_>>());
    let mut expected=before.regs.clone();for chunk in 0..bytes/8{expected.insert(if table{reg("a64.zt064",chunk)}else{za(selected as u16,chunk)},before.numeric(address+u64::from(chunk)*8,64,Endian::Little)[0]);}
    assert_eq!(s.regs,expected);assert!(stores(&t).is_empty());
   }else{
    let expected=(0..bytes).map(|i|{let value=if table{before.bits(reg("a64.zt064",i/8))}else{before.bits(za(selected as u16,i/8))};(address+u64::from(i),8,Endian::Little,vec![Value::known(8,value>>(i%8*8)&255)])}).collect::<Vec<_>>();
    assert_eq!(stores(&t),expected);assert!(s.reads.borrow().is_empty());assert_eq!(s.regs,before.regs);
   }
  }}}}
 }
 #[test]fn slice_elements_preserve_width_endian_predication_and_other_matrix_bits(){
  for svl in SVLS{for width in [8u16,16,32,64,128]{for vertical in [false,true]{for endian in [Endian::Little,Endian::Big]{for load in [false,true]{
   let mut s=State::new();let dim=svl/width;for e in 0..dim{s.pred(0,e*width/8,e%3!=1);}
   let before=s.clone();let bits=4-(width/8).trailing_zeros();let off=(1<<bits)-1;let tile=width/8-1;
   let low=(u32::from(tile)<<bits)|off;let selected=((0xffff_ffffu64+u64::from(off))%u64::from(dim))as u16;
   let fixed=match width{8=>0xe0000000,16=>0xe0400000,32=>0xe0800000,64=>0xe0c00000,_=>0xe1c00000};
   let word=fixed|(u32::from(!load)<<21)|(3<<16)|(u32::from(vertical)<<15)|(2<<5)|low;
   let r=recipe(word,svl,endian);let t=evaluate(&r,&s).unwrap();s.commit(&t);let start=0x4000+3*u64::from(width/8);
   let mut expected=before.clone();let mut accesses=vec![];let mut expected_stores=vec![];
   for e in 0..dim{let a=start+u64::from(e*width/8);let active=e%3!=1;
    let row=if vertical{e}else{selected}*width/8+tile;let bit=if vertical{selected}else{e}*width;
    let values=before.numeric(a,width,endian);
    for half in 0..(width/64).max(1){let at=bit+half*64;let w=width.min(64)as u8;
     if load {expected.lane(row,at,w,if active{values[usize::from(half)].bits}else{0});}
    }
    if active {if load{accesses.push((a,width,endian));}else{
     let chunks=(0..(width/64).max(1)).map(|half|Value::known(width.min(64)as u8,before.bits(za(row,(bit+half*64)/64))>>((bit+half*64)%64)&mask(width.min(64)as u8))).collect();
     expected_stores.push((a,width,endian,chunks));
    }}
   }
   assert_eq!(s.regs,expected.regs,"{word:08x} SVL{svl}");assert_eq!(*s.reads.borrow(),accesses);
   assert_eq!(stores(&t),expected_stores);assert_eq!(t.wide_memory.len(),if !load&&width==128{expected_stores.len()}else{0});
   assert_eq!(s.bits(reg("a64.gpr",2)),0x4000);assert_eq!(s.bits(reg("a64.gpr",3)),3);
  }}}}}
 }
 #[test]fn counter_vector_groups_cover_strides_offsets_endian_and_zeroing(){
  for svl in SVLS{for width in [8u16,16,32,64]{for count in [2u16,4]{for strided in [false,true]{for immediate in [false,true]{for load in [false,true]{for endian in [Endian::Little,Endian::Big]{for invert in [false,true]{
   let mut s=State::new();s.set(reg("a64.svcr",0),2,1);let elements=svl/width;let prefix=elements+1;let k=(width/8).trailing_zeros();
   s.set(p(15,0),64,(u64::from(prefix)<<(k+1))|(1<<k)|(u64::from(invert)<<15));let before=s.clone();
   let low=if strided{16+if count==2{7}else{3}}else{32-count};
   let first=if strided{if count==2{23}else{19}}else{32-count};let stride=if strided{16/count}else{1};
   let word=0xa0000000|(u32::from(strided)<<24)|(u32::from(immediate)<<22)|(u32::from(!load)<<21)|((if immediate{15}else{3})<<16)|(u32::from(count==4)<<15)|((width/8).trailing_zeros()<<13)|(7<<10)|(2<<5)|u32::from(low);
   let r=recipe(word,svl,endian);let t=evaluate(&r,&s).unwrap();s.commit(&t);
   let start=if immediate{0x4000-u64::from(count*svl/8)}else{0x4000+3*u64::from(width/8)};
   let mut expected=before.clone();let mut accesses=vec![];let mut expected_stores=vec![];
   for member in 0..count{let vector=first+member*stride;
    if load{for chunk in 0..32{expected.set(z(vector,chunk),64,0);}}
    for e in 0..elements{let index=member*elements+e;let active=(index<prefix)^invert;let a=start+u64::from(index*width/8);
     if load{let value=if active{before.numeric(a,width,endian)[0].bits}else{0};let bit=e*width;let dest=z(vector,bit/64);expected.set(dest,64,expected.bits(dest)|(value<<(bit%64)));}
     if active{if load{accesses.push((a,width,endian));}else{let bit=e*width;expected_stores.push((a,width,endian,vec![Value::known(width as u8,before.bits(z(vector,bit/64))>>(bit%64)&mask(width as u8))]));}}
    }
   }
   assert_eq!(s.regs,expected.regs,"{word:08x} SVL{svl}");assert_eq!(*s.reads.borrow(),accesses);assert_eq!(stores(&t),expected_stores);
  }}}}}}}}
 }

 #[test]fn predicate_counter_tags_counts_and_inversion_match_primary_bit_expansion(){
  for svl in SVLS {for tag in [0u16,1,2,4,8]{for invert in [false,true]{for count in [0u16,1,3,7]{
   let mut s=State::new();let k=if tag==0{0}else{tag.trailing_zeros()};let encoded=(if tag==0{0}else{count<<(k+1)})|tag|(u16::from(invert)<<15);s.set(p(8,0),64,u64::from(encoded));
   let word=0xa043c040; // LD1W {z0-z3},PN8/Z,[X2,#3,MUL VL]
   let r=recipe(word,svl,Endian::Little);let t=evaluate(&r,&s).unwrap();let elements=svl/32;
   let expanded=(0..4*elements).filter(|index|{
    let bit=index*4;if tag==0||bit%tag!=0{return false}
    let maxbit=(svl/2).trailing_zeros();let count=(encoded>>(k+1))&((1<<(maxbit-k))-1);
    ((bit/tag)<count)^invert
   }).map(|index|(0x4000+u64::from(3*4*svl/8)+u64::from(index*4),32,Endian::Little)).collect::<Vec<_>>();
   assert_eq!(*s.reads.borrow(),expanded,"SVL{svl} {encoded:04x}");assert!(stores(&t).is_empty());
  }}}}
 }
 #[test]fn reserved_group_fields_do_not_alias_allocated_memory_forms(){
  for word in [0xa0500000,0xa0408002,0xa1408004,0xe1000010,0xe11f8001]{assert!(a64_with_endian(word,0x1000,128,Endian::Little).is_none(),"{word:08x}");}
 }
 #[test]fn primary_corpus_dispatches_each_memory_class_and_nt_alias(){
  for &(word,name) in SME_MEMORY_CORPUS{for endian in [Endian::Little,Endian::Big]{
   let mut s=State::new();for pn in 8..16{s.set(p(pn,0),64,0x7f);}
   for chunk in 0..4{s.set(p(0,chunk),64,u64::MAX);}
   let r=recipe(word,128,endian);let t=evaluate(&r,&s).unwrap_or_else(|err|panic!("{name} {word:08x}: {err:?}"));
   assert!(t.trap.is_none(),"{name}");assert!(t.atomics.is_empty());assert!(!s.reads.borrow().is_empty()||!stores(&t).is_empty(),"{name} {word:08x}");
  }}
 }
 #[test]fn context_checks_precede_memory_and_inactive_predicates_suppress_faults(){
  for word in [0xe1000040,0xe1200040,0xe11f8040,0xe13f8040,0xe0030040,0xe0230040,0xe1c30040,0xe1e30040,0xa0030040,0xa0230040]{
   for state in 0..4{let need=if word&0xfe000000==0xa0000000{1}else if word&0xff000000==0xe0000000||word&0xffc00000==0xe1c00000{3}else{2};
    if state&need==need{continue}let mut s=State::new();s.set(reg("a64.svcr",0),2,state);s.fault=Some(0x4000);
    assert_eq!(evaluate(&recipe(word,128,Endian::Little),&s),Err(EvalError::UnsupportedContext),"{word:08x} state{state}");
    assert!(s.reads.borrow().is_empty());assert_eq!(*s.inputs.borrow(),if need==1{vec![reg("a64.sve2p1",0),reg("a64.svcr",0)]}else{vec![reg("a64.svcr",0)]});
   }
  }
  for word in [0xe0030040,0xe0230040,0xe1c30040,0xe1e30040,0xa0030040,0xa0230040]{
   let mut s=State::new();s.fault=Some(0x4000);s.regs.remove(&reg("a64.gpr",2));s.regs.remove(&reg("a64.gpr",3));
   let t=evaluate(&recipe(word,128,Endian::Big),&s).unwrap();assert!(s.reads.borrow().is_empty());assert!(stores(&t).is_empty());
   assert!(s.inputs.borrow().iter().all(|r|r.bank!="a64.gpr"||r.index==12));
  }
  for word in [0xe1000040,0xe1200040,0xe11f8040,0xe13f8040]{let mut s=State::new();s.set(reg("a64.gpr",2),64,0x4001);
   assert_eq!(evaluate(&recipe(word,128,Endian::Little),&s),Err(EvalError::UnsupportedContext));assert!(s.reads.borrow().is_empty());
  }
  for word in [0xe00303e0,0xe02303e0,0xa00303e0,0xa02303e0]{let mut s=State::new();s.set(p(8,0),64,3);s.set(reg("a64.sp",0),64,0x4001);
   assert_eq!(evaluate(&recipe(word,128,Endian::Little),&s),Err(EvalError::UnsupportedContext));assert!(s.reads.borrow().is_empty());
  }
 }

 #[test]fn invalid_streaming_lengths_reject_before_any_machine_input(){
  for svl in [0u16,64,384,768,4096]{for word in [0xe1000040,0xe1200040,0xe11f8040,0xe13f8040,0xe0030040,0xe0230040,0xa0030040,0xa0230040]{
   let s=State::new();assert_eq!(evaluate(&recipe(word,svl,Endian::Little),&s),Err(EvalError::UnsupportedContext));
   assert!(s.reads.borrow().is_empty());assert!(s.inputs.borrow().is_empty());
  }}
 }
 #[test]fn native_width_faults_stop_read_stream_and_publish_no_transition(){
  for (word,first,width) in [(0xe1000040,0x4000,8u16),(0xe11f8040,0x4000,8),(0xe0030040,0x4003,8),(0xe1c30040,0x4030,128),(0xa0034040,0x400c,32)]{
   for second in [false,true]{let mut s=State::new();s.set(p(0,0),64,u64::MAX);s.set(p(8,0),64,0x7f);s.fault=Some(first+if second{u64::from(width/8)}else{0});
    let before=s.regs.clone();assert_eq!(evaluate(&recipe(word,256,Endian::Big),&s),Err(EvalError::Memory),"{word:08x}");
    assert_eq!(s.reads.borrow().len(),if second{2}else{1});assert!(s.reads.borrow().iter().all(|(_,w,_)|*w==width));assert_eq!(s.regs,before);
   }
  }
 }

 #[test]fn byte_spills_and_native_quad_elements_wrap_the_address_boundary(){
  for endian in [Endian::Little,Endian::Big]{
   let mut s=State::new();s.set(reg("a64.gpr",2),64,u64::MAX-15);for i in 0..16{s.extra.insert(u64::MAX-15+i,i as u8+0x80);}
   let r=recipe(0xe1000040,256,endian);let t=evaluate(&r,&s).unwrap();
   assert_eq!(*s.reads.borrow(),(0..32).map(|i|((u64::MAX-15).wrapping_add(i),8,Endian::Little)).collect::<Vec<_>>());
   assert!(t.registers.iter().all(|w|w.register.bank=="a64.za64"));s.reads.borrow_mut().clear();
   s.set(reg("a64.gpr",2),64,u64::MAX-7);s.set(p(0,0),64,1);
   let word=0xe1df0040;let r=recipe(word,128,endian);let t=evaluate(&r,&s).unwrap();
   assert_eq!(*s.reads.borrow(),vec![(u64::MAX-7,128,endian)]);
   let chunks=s.numeric(u64::MAX-7,128,endian);let mut out=s.clone();out.commit(&t);
   assert_eq!(out.bits(za(0,0)),chunks[0].bits);assert_eq!(out.bits(za(0,1)),chunks[1].bits);
   s.reads.borrow_mut().clear();s.fault=Some(u64::MAX);assert_eq!(evaluate(&r,&s),Err(EvalError::Memory));
   assert_eq!(*s.reads.borrow(),vec![(u64::MAX-7,128,endian)],"fault remains one native-width callback");
  }
 }
 #[test]fn address_arithmetic_wraps_and_base_index_aliases_use_incoming_values(){
  // Rn==Rm scales the incoming base. There is no writeback in any of these
  // SME memory forms; offsets update the memory address, never Xn/Ws.
  let mut s=State::new();s.set(reg("a64.gpr",2),64,u64::MAX-15);s.set(p(0,0),64,1);
  for i in 0..16{s.extra.insert((u64::MAX-15).wrapping_mul(3).wrapping_add(i),0x10+i as u8);}
  let r=recipe(0xe0420040,128,Endian::Little);let t=evaluate(&r,&s).unwrap();assert_eq!(s.reads.borrow()[0],((u64::MAX-15).wrapping_mul(3),16,Endian::Little));
  assert!(t.registers.iter().all(|w|w.register.bank!="a64.gpr"));
 }

}
`

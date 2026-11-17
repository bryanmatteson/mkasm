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

// Exercise the public decoder and evaluator against every VFP register-list
// encoding, with transfer oracles independent of the generated recipe.
func TestRustA32VfpRegisterLists(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32VfpListsPrimary(t, path)
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "Documents/Developer/go-mkasm")
	if err = os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "a32-vfp-lists-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "lists.rs"), []byte(a32VfpListsBehavior+primary), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "arm32", "--crate-type", "lib", "src/lib.rs", "-Dwarnings", "-o", "libarm32.rlib"},
		{"--edition=2021", "--test", "lists.rs", "--extern", "arm32=libarm32.rlib", "-Dwarnings", "-Copt-level=1", "-o", "list-tests"},
		{"./list-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated A32 VFP lists %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a32VfpListsPrimary(t *testing.T, path string) string {
	t.Helper()
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Hi    int    `xml:"hibit,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name string `xml:"name,attr"`
	}
	type class struct {
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out strings.Builder
	out.WriteString("#[test]fn primary_register_list_encoding_identities(){for(word,thumb,id)in[\n")
	pages, classes, ids := 0, 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/") {
			continue
		}
		name := strings.TrimPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/")
		if name != "vldm.xml" && name != "vstm.xml" && name != "fldmx.xml" && name != "fstmx.xml" {
			continue
		}
		var p page
		if err = xml.NewDecoder(tr).Decode(&p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			classes++
			for _, e := range cl.Encodings {
				double := strings.HasSuffix(e.Name, "A1") || strings.HasSuffix(e.Name, "T1")
				legacy := strings.HasPrefix(name, "f")
				load := name == "vldm.xml" || name == "fldmx.xml"
				word := uint32(0xec820a00 | 4)
				if cl.ISA == "A32" {
					word |= 0xe0000000
				}
				if load {
					word |= 1 << 20
				}
				if double {
					word |= 0x100
				}
				if legacy {
					word |= 1
				}
				if strings.Contains(e.Name, "DB") {
					word &^= 1 << 23
					word |= 1<<24 | 1<<21
				}
				// Verify the constructed word against every literal cell in its primary class.
				for _, b := range cl.Diagram.Boxes {
					pos := b.Hi
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						bits := strings.TrimSpace(c.Text)
						if len(bits) != span {
							bits = strings.Repeat("x", span)
						}
						for _, bit := range bits {
							if (bit == '0' || bit == '1') && ((word>>uint(pos))&1) != uint32(bit-'0') {
								t.Fatalf("%s fixture conflicts with primary bit %d", e.Name, pos)
							}
							pos--
						}
					}
				}
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", e.Name)
				ids++
			}
		}
	}
	if pages != 4 || classes != 12 || ids != 24 {
		t.Fatalf("register list primary coverage pages=%d classes=%d ids=%d", pages, classes, ids)
	}
	out.WriteString("]{let d=decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();}}\n")
	t.Logf("qualified %d primary pages, %d classes, %d encoding identities", pages, classes, ids)
	return out.String()
}

const a32VfpListsBehavior = `use arm32::{decode,Decoded,Mode,Endian as CodeEndian};
use arm32::semantics::*;
use std::cell::RefCell;
struct State{base:u32,it:u8,z:bool,available:bool,fault:Option<u32>,reads:RefCell<Vec<(u32,u8)>>}
fn parent(n:u16)->u64{0x1234567800000000u64.wrapping_add(u64::from(n)*0x0102030405060708)}
fn datum(a:u32)->u32{a.rotate_left(13)^0x96a5c33c}
impl Machine for State {
 fn read_register(&self,r:Register)->Value {match r.bank {
 "a32.gpr"=>if self.available{Value::known(32,u64::from(self.base))}else{Value::unknown(32)},
 "a32.vector64"=>if self.available{Value::known(64,parent(r.index))}else{Value::unknown(64)},
 "a32.itstate"=>Value::known(8,u64::from(self.it)),
 "a32.nzcv"=>Value::known(1,u64::from(if r.index==1{self.z}else{false})),
 _=>panic!("unexpected register {r:?}")}}
 fn read_memory(&self,a:u64,w:u8,_:Endian)->Result<Value,EvalError>{assert_eq!(w,32);assert_eq!(a&3,0);self.reads.borrow_mut().push((a as u32,w));if self.fault==Some(a as u32){return Err(EvalError::Memory)}Ok(Value::known(32,u64::from(datum(a as u32))))}
}
fn state(base:u32)->State{State{base,it:0,z:true,available:true,fault:None,reads:RefCell::new(vec![])}}
fn bytes(word:u32,thumb:bool,endian:CodeEndian)->Vec<u8>{if thumb{[(word>>16)as u16,word as u16].into_iter().flat_map(|h|match endian{CodeEndian::Little=>h.to_le_bytes(),CodeEndian::Big=>h.to_be_bytes()}).collect()}else{match endian{CodeEndian::Little=>word.to_le_bytes(),CodeEndian::Big=>word.to_be_bytes()}.to_vec()}}
fn decoded(word:u32,thumb:bool,endian:CodeEndian)->Decoded{decode(&bytes(word,thumb,endian),if thumb{Mode::Thumb}else{Mode::Arm},endian).unwrap_or_else(|e|panic!("{word:08x}/{thumb}: {e:?}"))}
fn word(first:u32,count:u32,double:bool,load:bool,puw:u32,rn:u32,spare:bool)->u32{
 let (vd,d)=if double{(first&15,first>>4)}else{(first>>1,first&1)};
 0xec000a00|((puw&4)<<22)|((puw&2)<<22)|((puw&1)<<21)|((load as u32)<<20)|(rn<<16)|(vd<<12)|(d<<22)|((double as u32)<<8)|(count*if double{2}else{1})|u32::from(spare)
}
fn transferred(t:&Transition,first:u32,count:u32,double:bool,load:bool,start:u32,endian:Endian){
 if load{
  assert!(t.memory.is_empty());
  let mut expected=std::collections::BTreeMap::new();
  for i in 0..count{if double{
   let a=datum(start.wrapping_add(i*8))as u64;let b=datum(start.wrapping_add(i*8+4))as u64;
   expected.insert((first+i)as u16,if endian==Endian::Big{a<<32|b}else{b<<32|a});
  }else{let sn=first+i;let n=(sn/2)as u16;let old=*expected.get(&n).unwrap_or(&parent(n));let offset=(sn&1)*32;expected.insert(n,(old&!(0xffffffffu64<<offset))|((datum(start.wrapping_add(i*4))as u64)<<offset));}}
  let actual:std::collections::BTreeMap<_,_>=t.registers.iter().filter(|r|r.register.bank=="a32.vector64").map(|r|(r.register.index,r.value.bits)).collect();assert_eq!(actual,expected);
 }else{
  assert!(t.registers.iter().all(|r|r.register.bank!="a32.vector64"));assert_eq!(t.memory.len(),(count*if double{2}else{1})as usize);
  for(i,m)in t.memory.iter().enumerate(){assert_eq!(m.address,start.wrapping_add(i as u32*4)as u64);assert_eq!(m.value.width,32);assert_eq!(m.endian,endian);
   let n=if double{first+i as u32/2}else{first+i as u32};let p=parent(if double{n as u16}else{(n/2)as u16});let offset=if double{if endian==Endian::Big{(1-i as u32%2)*32}else{i as u32%2*32}}else{(n&1)*32};assert_eq!(m.value.bits,(p>>offset)&0xffffffff);
  }
 }
}
#[test]fn complete_lists_all_register_ranges_modes_endians_counts_and_addressing(){
 for thumb in[false,true]{for code in[CodeEndian::Little,CodeEndian::Big]{for endian in[Endian::Little,Endian::Big]{for double in[false,true]{for first in 0..32{for count in 1..=if double{16.min(32-first)}else{32-first}{for load in[false,true]{for puw in[2,3,5]{
  let w=word(first,count,double,load,puw,2,false);let r=decoded(w,thumb,code).semantic_recipe_with_endian(0xfffffffc,endian);assert_eq!(r.support,Support::Full,"{w:08x}");r.validate().unwrap();let s=state(0x1004);let t=evaluate(&r,&s).unwrap();assert!(t.trap.is_none());assert_eq!(t.next_pc.bits,0);
  let extent=count*if double{8}else{4};let start=if puw==5{s.base.wrapping_sub(extent)}else{s.base};transferred(&t,first,count,double,load,start,endian);
  let wb:Vec<_>=t.registers.iter().filter(|r|r.register.bank=="a32.gpr").collect();assert_eq!(wb.len(),usize::from(puw!=2));if puw!=2{assert_eq!(wb[0].register.index,2);assert_eq!(wb[0].value.bits,if puw==5{start}else{s.base+extent}as u64)}
  let reads=s.reads.borrow();assert_eq!(reads.len(),if load{extent as usize/4}else{0});for(i,(a,w))in reads.iter().enumerate(){assert_eq!((*a,*w),(start.wrapping_add(i as u32*4),32));}
 }}}}}}}}
}
#[test]fn legacy_spare_words_stack_aliases_and_a32_pc_base(){
 for thumb in[false,true]{for load in[false,true]{for puw in[2,3,5]{for first in 0..16{for count in 1..=16-first{
  let w=word(first,count,true,load,puw,13,true);let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);let mut s=state(0x400);let extent=count*8+4;let start=if puw==5{s.base-extent}else{s.base};s.fault=Some(start+count*8);let t=evaluate(&r,&s).unwrap();transferred(&t,first,count,true,load,start,Endian::Little);
  if puw!=2{assert_eq!(t.registers.iter().find(|r|r.register.bank=="a32.gpr").unwrap().value.bits,if puw==5{start}else{s.base+extent}as u64)}
 }}}}}
 for double in[false,true]{for load in[false,true]{let r=decoded(word(0,2,double,load,2,15,false),false,CodeEndian::Little).semantic_recipe(0x1000);let s=state(0);let t=evaluate(&r,&s).unwrap();transferred(&t,0,2,double,load,0x1008,Endian::Little);}}
}
#[test]fn predication_alignment_faults_and_missing_memory_have_no_completed_transfer(){
 for thumb in[false,true]{for load in[false,true]{let mut w=word(1,3,false,load,3,2,false);if !thumb{w&=0x0fffffff};let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);
  let mut s=state(0x1000);s.z=false;s.available=false;if thumb{s.it=8};let t=evaluate(&r,&s).unwrap();assert!(t.memory.is_empty()&&s.reads.borrow().is_empty());assert!(t.registers.iter().all(|r|r.register.bank=="a32.itstate"));
  s.available=true;s.z=true;s.base=0x1001;let t=evaluate(&r,&s).unwrap();assert_eq!(t.trap,Some(TrapKind::Protection));assert!(t.memory.is_empty()&&t.registers.is_empty()&&s.reads.borrow().is_empty());
  if load{s.base=0x1000;s.fault=Some(0x1004);assert_eq!(evaluate(&r,&s),Err(EvalError::Memory));assert_eq!(*s.reads.borrow(),vec![(0x1000,32),(0x1004,32)]);}
 }}
}
#[test]fn rejects_empty_overflowing_and_illegal_pc_lists(){
 for thumb in[false,true]{for double in[false,true]{for(first,count,rn,puw,spare)in[(0,0,2,2,false),(31,2,2,3,false),(0,17,2,2,false),(16,1,2,2,true),(0,1,15,3,false),(0,1,15,5,false)]{
  if !double&&(count==17||spare){continue}let w=word(first,count,double,true,puw,rn,spare);if let Ok(d)=decode(&bytes(w,thumb,CodeEndian::Little),if thumb{Mode::Thumb}else{Mode::Arm},CodeEndian::Little){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"{w:08x}");}
 }}}
 let w=word(0,1,true,true,2,15,false);if let Ok(d)=decode(&bytes(w,true,CodeEndian::Little),Mode::Thumb,CodeEndian::Little){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)));}
}
`

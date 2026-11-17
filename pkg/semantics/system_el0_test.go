package semantics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"

	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

// Exercise the production emitted module and actual A64 recipe dispatch. The
// instruction words are the June 2026 MRS/MSR/SYS and hint physical encodings;
// target-dependent access permission is supplied explicitly, never invented.
func TestRustEL0SystemOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := WriteRust(dir); err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("recipes").ParseFS(assettemplates.FS, "rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := tmpl.ExecuteTemplate(&rendered, "recipes.rs.tmpl", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recipes.rs"), rendered.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "el0_tests.rs"), []byte(el0SystemTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "el0_tests.rs", "-Dwarnings", "-o", "el0-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile production EL0 recipes: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "el0-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute production EL0 recipes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

// Bind the executed constants to independent primary regdiagrams, including
// every Rt and every immediate. The June archive also contains March entries;
// select the exact June member rather than whichever basename appears first.
func TestEL0SystemPhysicalEncodings(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Documents", "Developer", "go-mkasm", "architecture-expansion", "ISA_A64_xml_A_profile-2026-06.tar.gz")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		t.Skip("June Arm corpus unavailable")
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
	diagrams := map[string]systemCorpusDiagram{}
	reader := tar.NewReader(zipped)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		prefix := "ISA_A64_xml_A_profile-2026-06/"
		if !strings.HasPrefix(header.Name, prefix) {
			continue
		}
		name := strings.TrimPrefix(header.Name, prefix)
		switch name {
		case "mrs.xml", "msr_reg.xml", "msr_imm.xml", "sys.xml", "yield.xml", "wfe.xml", "wfi.xml", "sev.xml", "sevl.xml":
		default:
			continue
		}
		decoder := xml.NewDecoder(reader)
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if start, ok := token.(xml.StartElement); ok && start.Name.Local == "regdiagram" {
				var d systemCorpusDiagram
				if err := decoder.DecodeElement(&d, &start); err != nil {
					t.Fatal(err)
				}
				diagrams[name] = d
				break
			}
		}
	}
	checked := 0
	check := func(name string, fields map[string]uint32, want uint32) {
		t.Helper()
		d, ok := diagrams[name]
		if !ok {
			t.Fatalf("missing primary diagram %s", name)
		}
		var word uint32
		for _, box := range d.Boxes {
			width := box.Width
			if width == 0 {
				width = 1
			}
			var bits strings.Builder
			for _, cell := range box.Cells {
				text := strings.TrimSpace(cell.Text)
				if text == "0" || text == "1" {
					bits.WriteString(text)
				}
			}
			var value uint64
			if bits.Len() == width {
				var err error
				value, err = strconv.ParseUint(bits.String(), 2, 32)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				field, exists := fields[box.Name]
				if !exists {
					t.Fatalf("missing field %s in %s", box.Name, name)
				}
				value = uint64(field)
			}
			if value >= 1<<width {
				t.Fatalf("field overflow %s.%s=%d", name, box.Name, value)
			}
			word |= uint32(value) << uint(box.Hi-width+1)
		}
		if word != want {
			t.Fatalf("%s %v derived %08x, executed %08x", name, fields, word, want)
		}
		checked++
	}
	for rt := uint32(0); rt < 32; rt++ {
		for _, entry := range []struct{ crn, crm, op2, read, write uint32 }{
			{4, 2, 5, 0xd53b42a0, 0xd51b42a0}, {4, 2, 7, 0xd53b42e0, 0xd51b42e0},
			{13, 0, 2, 0xd53bd040, 0xd51bd040}, {13, 0, 3, 0xd53bd060, 0},
			{0, 0, 7, 0xd53b00e0, 0},
		} {
			fields := map[string]uint32{"o0": 1, "op1": 3, "CRn": entry.crn, "CRm": entry.crm, "op2": entry.op2, "Rt": rt}
			check("mrs.xml", fields, entry.read|rt)
			if entry.write != 0 {
				check("msr_reg.xml", fields, entry.write|rt)
			}
		}
		check("sys.xml", map[string]uint32{"op1": 3, "CRn": 7, "CRm": 4, "op2": 1, "Rt": rt}, 0xd50b7420|rt)
	}
	for imm := uint32(0); imm < 16; imm++ {
		for _, entry := range []struct{ op2, word uint32 }{{2, 0xd503405f}, {4, 0xd503409f}} {
			check("msr_imm.xml", map[string]uint32{"op1": 3, "op2": entry.op2, "CRm": imm}, entry.word|(imm<<8))
		}
	}
	for name, word := range map[string]uint32{"yield.xml": 0xd503203f, "wfe.xml": 0xd503205f, "wfi.xml": 0xd503207f, "sev.xml": 0xd503209f, "sevl.xml": 0xd50320bf} {
		check(name, nil, word)
	}
	t.Logf("checked %d executed EL0 encodings against primary June regdiagrams", checked)
}

const el0SystemTests = `
#[allow(dead_code)] pub mod semantics;
#[allow(dead_code)] mod recipes;
use semantics::*;
use std::cell::RefCell;
pub struct Decoded {pub raw:u32}
#[derive(Default)] struct State {
 gpr:[u64;32],dit:u64,tco:u64,tpidr:u64,tpidrro:u64,dczid:u64,permitted:u64,
 no_gpr:bool,unknown_context:bool,wait:Option<WaitOutcome>,events:RefCell<Vec<(bool,bool)>>,
}
impl Machine for State {
 fn read_register(&self,r:Register)->Value {
  let (width,bits)=match r.bank {
   "a64.gpr"=>{assert!(!self.no_gpr,"rejected context evaluated Xt");(64,self.gpr[r.index as usize])},
   "a64.dit"=>(1,self.dit),"a64.tco"=>(1,self.tco),
   "a64.tpidr_el0"=>(64,self.tpidr),"a64.tpidrro_el0"=>(64,self.tpidrro),
   "a64.dczid_el0"=>{if self.unknown_context{return Value::unknown(64)};(64,self.dczid)},
   "a64.dc_zva_permitted"=>(1,self.permitted),
   _=>panic!("unexpected bank {r:?}"),
  };Value::known(width,bits)
 }
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("EL0 system recipe read memory")}
 fn wait(&self,allow:bool)->Result<WaitOutcome,EvalError>{self.events.borrow_mut().push((false,allow));self.wait.ok_or(EvalError::Unsupported)}
 fn send_event(&self,local:bool)->Result<(),EvalError>{self.events.borrow_mut().push((true,local));Ok(())}
}
fn output(t:&Transition,bank:&str,index:u16)->u64 {
 t.registers.iter().find(|w|w.register.bank==bank&&w.register.index==index).unwrap().value.bits
}
#[test]fn pstate_register_and_immediate_forms_use_exact_bit_positions_and_zero_register(){
 for (bank,position,read,write,immediate) in [
  ("a64.dit",24,0xd53b42a0,0xd51b42a0,0xd503405f),
  ("a64.tco",25,0xd53b42e0,0xd51b42e0,0xd503409f),
 ] {
  for bit in 0..2 {for rt in 0..32 {
   let mut s=State::default();s.dit=bit;s.tco=bit;
   let t=evaluate(&recipes::for_word(read|rt,0x1000),&s).unwrap();
   assert_eq!(t.next_pc.bits,0x1004);
   if rt==31{assert!(t.registers.is_empty())}else{assert_eq!(t.registers.len(),1);assert_eq!(output(&t,"a64.gpr",rt as u16),bit<<position)}
   s.gpr[rt as usize]=!(1<<position)|(bit<<position);
   let t=evaluate(&recipes::for_word(write|rt,0x1000),&s).unwrap();
   assert_eq!(t.registers.len(),1);assert_eq!(output(&t,bank,0),if rt==31{0}else{bit});
  }}
  for imm in 0..16 {let t=evaluate(&recipes::for_word(immediate|(imm<<8),0),&State::default()).unwrap();assert_eq!(t.registers.len(),1);assert_eq!(output(&t,bank,0),u64::from(imm&1))}
 }
}
#[test]fn thread_pointer_reads_and_writes_keep_full_values_and_readonly_identity(){
 for rt in 0..32 {
  let mut s=State::default();s.tpidr=0xfedcba9876543210;s.tpidrro=0x123456789abcdef0;s.gpr[rt as usize]=!u64::from(rt);
  for (word,expected) in [(0xd53bd040,s.tpidr),(0xd53bd060,s.tpidrro)] {
   let t=evaluate(&recipes::for_word(word|rt,0),&s).unwrap();
   if rt==31{assert!(t.registers.is_empty())}else{assert_eq!(output(&t,"a64.gpr",rt as u16),expected)}
  }
  let t=evaluate(&recipes::for_word(0xd51bd040|rt,0),&s).unwrap();
  assert_eq!(t.registers.len(),1);assert_eq!(output(&t,"a64.tpidr_el0",0),if rt==31{0}else{!u64::from(rt)});
 }
 for word in [0xd51bd060,0xd51b00e0] {
  let r=system::a64(word,0).unwrap();assert!(matches!(r.support,Support::Unsupported(_)));
  assert_eq!(evaluate(&r,&State{no_gpr:true,..Default::default()}),Err(EvalError::Unsupported));
 }
}
fn check_zero(t:&Transition,address:u64,bytes:u16){
 assert!(t.registers.is_empty());assert_eq!(t.next_pc.bits,4);
 let expected=address&!(u64::from(bytes)-1);
 if bytes<=8 {
  assert_eq!(t.memory.len(),1);assert!(t.wide_memory.is_empty());
  assert_eq!(t.memory[0].address,expected);assert_eq!(t.memory[0].value,Value::known((bytes*8)as u8,0));
 }else{
  assert!(t.memory.is_empty());assert_eq!(t.wide_memory.len(),1);
  let w=&t.wide_memory[0];assert_eq!(w.address,expected);assert_eq!(w.width,bytes*8);
  assert_eq!(w.chunks.len(),usize::from(bytes/8));assert!(w.chunks.iter().all(|v|*v==Value::known(64,0)));
 }
}
#[test]fn dczid_and_zero_share_target_size_and_publish_one_original_width_access(){
 for bs in 0..=6 {for address in [0,1,3,7,15,63,255,256,0x12345678,u64::MAX] {
  let mut s=State::default();s.dczid=bs;s.permitted=1;s.gpr[7]=address;
  let t=evaluate(&recipes::for_word(0xd53b00e3,0),&s).unwrap();assert_eq!(output(&t,"a64.gpr",3),bs);
  let context=system::A64El0Context{dczid_el0:bs,dc_zva_permitted:true};
  let r=recipes::for_word(0xd50b7427,0);assert_eq!(r.support,Support::Full);
  check_zero(&evaluate(&r,&s).unwrap(),address,4u16<<bs);
  let r=system::a64_with_el0_context(0xd50b7427,0,context).unwrap();
  check_zero(&evaluate(&r,&s).unwrap(),address,4u16<<bs);
  check_zero(&evaluate(&recipes::for_word(0xd50b743f,0),&s).unwrap(),0,4u16<<bs);
  let t=evaluate(&system::a64_with_el0_context(0xd53b00e3,0,context).unwrap(),&State{no_gpr:true,..Default::default()}).unwrap();
  assert_eq!(output(&t,"a64.gpr",3),bs);
 }}
}
#[test]fn prohibited_unknown_and_unrepresentable_zero_contexts_reject_before_xt(){
 for (dczid,permitted) in [(4,0),(0x14,1),(7,1),(8,1),(9,1),(15,1)] {
  let s=State{dczid,permitted,no_gpr:true,..Default::default()};
  assert_eq!(evaluate(&recipes::for_word(0xd50b7427,0),&s),Err(EvalError::UnsupportedContext));
  let context=system::A64El0Context{dczid_el0:dczid,dc_zva_permitted:permitted!=0};
  assert_eq!(evaluate(&system::a64_with_el0_context(0xd50b7427,0,context).unwrap(),&s),Err(EvalError::UnsupportedContext));
  // A prohibited instruction still exposes the effective DZP read image.
  assert_eq!(output(&evaluate(&recipes::for_word(0xd53b00e3,0),&s).unwrap(),"a64.gpr",3),dczid);
 }
 assert_eq!(evaluate(&recipes::for_word(0xd50b7427,0),&State{permitted:1,unknown_context:true,no_gpr:true,..Default::default()}),Err(EvalError::UnknownCondition));
}
#[test]fn waits_and_events_retain_typed_environment_boundaries_and_predication(){
 for (word,send,argument) in [(0xd503203f,false,false),(0xd503205f,false,false),(0xd503207f,false,true),(0xd503209f,true,false),(0xd50320bf,true,true)] {
  let s=State{wait:Some(WaitOutcome::FallThrough),..Default::default()};
  let mut r=recipes::for_word(word,0x1000);assert_eq!(r.support,Support::Full);
  let t=evaluate(&r,&s).unwrap();assert_eq!(t.next_pc.bits,0x1004);assert!(t.registers.is_empty());assert_eq!(t.events.len(),1);
  assert_eq!(*s.events.borrow(),[(send,argument)]);
  if send{assert_eq!(t.events,[OrderedEvent::SendEvent{local:argument}])}else{assert_eq!(t.events,[OrderedEvent::Wait{allow_protection_trap:argument,outcome:WaitOutcome::FallThrough}])}
  s.events.borrow_mut().clear();r.guard=Expr::constant(1,0);assert!(evaluate(&r,&s).unwrap().events.is_empty());assert!(s.events.borrow().is_empty());
 }
 for word in [0xd503203f,0xd503205f,0xd503207f] {
  assert_eq!(evaluate(&recipes::for_word(word,0),&State::default()),Err(EvalError::Unsupported));
 }
 let s=State{wait:Some(WaitOutcome::ProtectionTrap),..Default::default()};
 for word in [0xd503203f,0xd503205f]{assert_eq!(evaluate(&recipes::for_word(word,0),&s),Err(EvalError::InvalidEnvironmentOutcome))}
 let mut r=recipes::for_word(0xd503207f,0);r.write(register("a64.gpr",0,64,64),WritePolicy::ZeroUpper,Expr::constant(64,42));
 let t=evaluate(&r,&s).unwrap();assert_eq!(t.trap,Some(TrapKind::Protection));assert!(t.registers.is_empty());
}
#[test]fn adjacent_privileged_and_reserved_forms_never_gain_a_successful_recipe(){
 for word in [0xd503211f,0xd50b7400,0xd50b7440,0xd51b42c0,0xd53b42c0,0xd53bd000,0xd51bd000] {
  assert!(system::a64(word,0).is_none(),"{word:08x}");
 }
 assert_eq!(system::a64_with_el0_context(0xd50330bf,0,system::A64El0Context{dczid_el0:4,dc_zva_permitted:true}),system::a64(0xd50330bf,0));
}
`

package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustOriginalWidthMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime+wideMemoryTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", "wide-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile original-width memory: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "wide-tests"), "wide_memory_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute original-width memory: %v\n%s", err, out)
	}
}

const wideMemoryTests = `
#[cfg(test)] mod wide_memory_behavior {
 use super::*;
 use std::cell::RefCell;
 struct Backend {bytes:Vec<u8>,calls:RefCell<Vec<(u64,u16,Endian)>>,bad:bool,fail:bool}
 impl Backend {
  fn new()->Self{Self{bytes:(0..=255).cycle().take(512).collect(),calls:RefCell::new(vec![]),bad:false,fail:false}}
  fn commit(&mut self,t:&Transition){
   let mut bytes=self.bytes.clone();
   for event in &t.events{if let OrderedEvent::WideStore(index)=event{
    let w=&t.wide_memory[*index];let mut encoded=vec![];
    for chunk in &w.chunks{assert!(chunk.is_known());encoded.extend_from_slice(&chunk.bits.to_le_bytes()[..usize::from(chunk.width/8)]);}
    assert_eq!(encoded.len(),usize::from(w.width/8));if w.endian==Endian::Big{encoded.reverse();}
    let start=w.address as usize;bytes[start..start+encoded.len()].copy_from_slice(&encoded);
   }}self.bytes=bytes;
  }
 }
 impl Machine for Backend {
  fn read_register(&self,_:Register)->Value{panic!("unexpected architectural input")}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("wide access split into scalar reads")}
  fn read_wide_memory(&self,address:u64,width:u16,endian:Endian)->Result<Vec<Value>,EvalError>{
   self.calls.borrow_mut().push((address,width,endian));if self.fail{return Err(EvalError::Memory);}
   let start=address as usize;let mut bytes=self.bytes.get(start..start+usize::from(width/8)).ok_or(EvalError::Memory)?.to_vec();
   if endian==Endian::Big{bytes.reverse();}
   let mut result=bytes.chunks(8).map(|bytes|{let mut bits=[0;8];bits[..bytes.len()].copy_from_slice(bytes);Value::known((bytes.len()*8)as u8,u64::from_le_bytes(bits))}).collect::<Vec<_>>();
   if self.bad{result.pop();}Ok(result)
  }
 }
 fn memory(address:u64,width:u16,endian:Endian)->WideMemory{WideMemory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,address)),width,endian}}
 #[test]fn one_access_preserves_width_endian_chunks_and_pending_commit(){
  for width in [72,128,256,512,2048]{for endian in [Endian::Little,Endian::Big]{
   let mut state=Backend::new();let original=state.bytes.clone();let mut r=Recipe::new(4,64);
   let chunks=r.load_wide(memory(0,width,endian));assert_eq!(chunks.len(),usize::from(width).div_ceil(64));
   let first=r.bind(chunks[0].clone());r.write(register("test",0,64,64),WritePolicy::ZeroUpper,first);
   r.store_wide(memory(256,width,endian),chunks);
   let t=evaluate(&r,&state).unwrap();assert_eq!(*state.calls.borrow(),vec![(0,width,endian)]);
   assert_eq!(state.bytes,original);assert!(t.memory.is_empty());assert!(t.atomics.is_empty());
   assert_eq!(t.wide_memory.len(),1);assert_eq!(t.wide_memory[0].width,width);assert_eq!(t.events,vec![OrderedEvent::WideStore(0)]);
   let mut numeric=original[..usize::from(width/8)].to_vec();if endian==Endian::Big{numeric.reverse();}
   assert_eq!(t.registers[0].value.bits,u64::from_le_bytes(numeric[..8].try_into().unwrap()));
   state.commit(&t);assert_eq!(&state.bytes[256..256+usize::from(width/8)],&original[..usize::from(width/8)]);
  }}
 }
 #[test]fn predication_faults_and_malformed_capability_responses_do_not_publish(){
  let mut r=Recipe::new(4,64);let chunks=r.load_wide(memory(0,128,Endian::Little));r.store_wide(memory(32,128,Endian::Little),chunks);
  r.guard=Expr::constant(1,0);let mut state=Backend::new();let t=evaluate(&r,&state).unwrap();assert!(state.calls.borrow().is_empty());assert!(t.wide_memory.is_empty());
  r.guard=Expr::constant(1,1);state.fail=true;assert_eq!(evaluate(&r,&state),Err(EvalError::Memory));state.fail=false;state.bad=true;assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));
  struct NoWide;impl Machine for NoWide{fn read_register(&self,_:Register)->Value{panic!()}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!()}}
  assert_eq!(evaluate(&r,&NoWide),Err(EvalError::Unsupported));
 }
 #[test]fn every_wide_graph_edge_is_validated_before_state_access(){
  let state=Backend::new();
  for width in [0,65,2056]{let mut r=Recipe::new(4,64);r.load_wide(memory(0,width,Endian::Little));assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));}
  let mut r=Recipe::new(4,64);let mut chunks=r.load_wide(memory(0,128,Endian::Little));chunks.pop();r.store_wide(memory(16,128,Endian::Little),chunks);assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);let chunks=r.load_wide(memory(0,128,Endian::Little));r.guard=Expr::binary(BinaryOp::Eq,chunks[0].clone(),Expr::constant(64,0));assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));
  assert!(state.calls.borrow().is_empty());
 }
 #[test]fn conditional_store_skips_addresses_values_and_events_but_validates_the_graph(){
  let state=Backend::new();
  let memory=Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::undefined(64,"unavailable inactive address")),width:32,endian:Endian::Big};
  let faulting=Expr::load(Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,u64::MAX)),width:32,endian:Endian::Little});
  let mut r=Recipe::new(4,64);r.store_conditional(Expr::constant(1,0),memory.clone(),faulting);
  let t=evaluate(&r,&state).unwrap();assert!(t.memory.is_empty());assert!(t.events.is_empty());
  r.effects[0]=Effect::StoreConditional{condition:Expr::undefined(1,"unknown mask"),memory:memory.clone(),value:Expr::constant(32,7)};
  assert_eq!(evaluate(&r,&state),Err(EvalError::UnknownCondition));
  r.effects[0]=Effect::StoreConditional{condition:Expr::constant(1,1),memory,value:Expr::constant(32,7)};
  assert_eq!(evaluate(&r,&state),Err(EvalError::UnknownAddress));
  r.effects[0]=Effect::StoreConditional{condition:Expr::constant(1,1),memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,40)),width:32,endian:Endian::Big},value:Expr::constant(32,0x11223344)};
  let t=evaluate(&r,&state).unwrap();assert_eq!(t.events,vec![OrderedEvent::Store(0)]);assert_eq!(t.memory[0].address,40);assert_eq!(t.memory[0].value.bits,0x11223344);assert_eq!(t.memory[0].endian,Endian::Big);
  r.effects[0]=Effect::StoreConditional{condition:Expr::constant(8,0),memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,40)),width:32,endian:Endian::Big},value:Expr::constant(32,7)};
  assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));
 }
 #[test]fn conditional_original_width_load_suppresses_the_whole_access(){
  let state=Backend::new();let mut r=Recipe::new(4,64);
  let wide=WideMemory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::undefined(64,"inactive address")),width:256,endian:Endian::Little};
  let chunks=r.load_wide_conditional(Expr::constant(1,0),wide);
  r.write(register("test",0,64,64),WritePolicy::ZeroUpper,chunks[0].clone());
  let t=evaluate(&r,&state).unwrap();assert_eq!(t.registers[0].value.defined,0);assert!(state.calls.borrow().is_empty());
  r.wide_load_conditions[0]=Some(Expr::undefined(1,"unknown predicate"));assert_eq!(evaluate(&r,&state),Err(EvalError::UnknownCondition));
  r.wide_load_conditions[0]=Some(Expr::constant(1,1));assert_eq!(evaluate(&r,&state),Err(EvalError::UnknownAddress));
  r.wide_loads[0].address=Box::new(Expr::constant(64,0));let t=evaluate(&r,&state).unwrap();assert!(t.registers[0].value.is_known());assert_eq!(*state.calls.borrow(),vec![(0,256,Endian::Little)]);
  r.wide_load_conditions.clear();assert_eq!(evaluate(&r,&state),Err(EvalError::InvalidExpression));
 }
}
`

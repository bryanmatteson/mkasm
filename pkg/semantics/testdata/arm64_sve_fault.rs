#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
// Physical register diagrams and decode constants from the June 2026 corpus.
const CASES:&[(u32,u8,u8,u8,u8,u8,bool,bool)]=&[
(0xc420e000,64,8,0,0,1,false,false), // ldff1b_z_p_ai_d
(0x8420e000,32,8,0,0,1,false,false), // ldff1b_z_p_ai_s
(0xa4206000,16,8,0,0,2,false,false), // ldff1b_z_p_br_u16
(0xa4406000,32,8,0,0,2,false,false), // ldff1b_z_p_br_u32
(0xa4606000,64,8,0,0,2,false,false), // ldff1b_z_p_br_u64
(0xa4006000,8,8,0,0,2,false,false), // ldff1b_z_p_br_u8
(0xc440e000,64,8,64,0,0,false,false), // ldff1b_z_p_bz_d_64_unscaled
(0xc4006000,64,8,32,0,0,false,true), // ldff1b_z_p_bz_d_x32_unscaled
(0x84006000,32,8,32,0,0,false,true), // ldff1b_z_p_bz_s_x32_unscaled
(0xc5a0e000,64,64,0,0,1,false,false), // ldff1d_z_p_ai_d
(0xa5e06000,64,64,0,0,2,false,false), // ldff1d_z_p_br_u64
(0xc5e0e000,64,64,64,3,0,false,false), // ldff1d_z_p_bz_d_64_scaled
(0xc5c0e000,64,64,64,0,0,false,false), // ldff1d_z_p_bz_d_64_unscaled
(0xc5a06000,64,64,32,3,0,false,true), // ldff1d_z_p_bz_d_x32_scaled
(0xc5806000,64,64,32,0,0,false,true), // ldff1d_z_p_bz_d_x32_unscaled
(0xc4a0e000,64,16,0,0,1,false,false), // ldff1h_z_p_ai_d
(0x84a0e000,32,16,0,0,1,false,false), // ldff1h_z_p_ai_s
(0xa4a06000,16,16,0,0,2,false,false), // ldff1h_z_p_br_u16
(0xa4c06000,32,16,0,0,2,false,false), // ldff1h_z_p_br_u32
(0xa4e06000,64,16,0,0,2,false,false), // ldff1h_z_p_br_u64
(0xc4e0e000,64,16,64,1,0,false,false), // ldff1h_z_p_bz_d_64_scaled
(0xc4c0e000,64,16,64,0,0,false,false), // ldff1h_z_p_bz_d_64_unscaled
(0xc4a06000,64,16,32,1,0,false,true), // ldff1h_z_p_bz_d_x32_scaled
(0xc4806000,64,16,32,0,0,false,true), // ldff1h_z_p_bz_d_x32_unscaled
(0x84a06000,32,16,32,1,0,false,true), // ldff1h_z_p_bz_s_x32_scaled
(0x84806000,32,16,32,0,0,false,true), // ldff1h_z_p_bz_s_x32_unscaled
(0xc420a000,64,8,0,0,1,true,false), // ldff1sb_z_p_ai_d
(0x8420a000,32,8,0,0,1,true,false), // ldff1sb_z_p_ai_s
(0xa5c06000,16,8,0,0,2,true,false), // ldff1sb_z_p_br_s16
(0xa5a06000,32,8,0,0,2,true,false), // ldff1sb_z_p_br_s32
(0xa5806000,64,8,0,0,2,true,false), // ldff1sb_z_p_br_s64
(0xc440a000,64,8,64,0,0,true,false), // ldff1sb_z_p_bz_d_64_unscaled
(0xc4002000,64,8,32,0,0,true,true), // ldff1sb_z_p_bz_d_x32_unscaled
(0x84002000,32,8,32,0,0,true,true), // ldff1sb_z_p_bz_s_x32_unscaled
(0xc4a0a000,64,16,0,0,1,true,false), // ldff1sh_z_p_ai_d
(0x84a0a000,32,16,0,0,1,true,false), // ldff1sh_z_p_ai_s
(0xa5206000,32,16,0,0,2,true,false), // ldff1sh_z_p_br_s32
(0xa5006000,64,16,0,0,2,true,false), // ldff1sh_z_p_br_s64
(0xc4e0a000,64,16,64,1,0,true,false), // ldff1sh_z_p_bz_d_64_scaled
(0xc4c0a000,64,16,64,0,0,true,false), // ldff1sh_z_p_bz_d_64_unscaled
(0xc4a02000,64,16,32,1,0,true,true), // ldff1sh_z_p_bz_d_x32_scaled
(0xc4802000,64,16,32,0,0,true,true), // ldff1sh_z_p_bz_d_x32_unscaled
(0x84a02000,32,16,32,1,0,true,true), // ldff1sh_z_p_bz_s_x32_scaled
(0x84802000,32,16,32,0,0,true,true), // ldff1sh_z_p_bz_s_x32_unscaled
(0xc520a000,64,32,0,0,1,true,false), // ldff1sw_z_p_ai_d
(0xa4806000,64,32,0,0,2,true,false), // ldff1sw_z_p_br_s64
(0xc560a000,64,32,64,2,0,true,false), // ldff1sw_z_p_bz_d_64_scaled
(0xc540a000,64,32,64,0,0,true,false), // ldff1sw_z_p_bz_d_64_unscaled
(0xc5202000,64,32,32,2,0,true,true), // ldff1sw_z_p_bz_d_x32_scaled
(0xc5002000,64,32,32,0,0,true,true), // ldff1sw_z_p_bz_d_x32_unscaled
(0xc520e000,64,32,0,0,1,false,false), // ldff1w_z_p_ai_d
(0x8520e000,32,32,0,0,1,false,false), // ldff1w_z_p_ai_s
(0xa5406000,32,32,0,0,2,false,false), // ldff1w_z_p_br_u32
(0xa5606000,64,32,0,0,2,false,false), // ldff1w_z_p_br_u64
(0xc560e000,64,32,64,2,0,false,false), // ldff1w_z_p_bz_d_64_scaled
(0xc540e000,64,32,64,0,0,false,false), // ldff1w_z_p_bz_d_64_unscaled
(0xc5206000,64,32,32,2,0,false,true), // ldff1w_z_p_bz_d_x32_scaled
(0xc5006000,64,32,32,0,0,false,true), // ldff1w_z_p_bz_d_x32_unscaled
(0x85206000,32,32,32,2,0,false,true), // ldff1w_z_p_bz_s_x32_scaled
(0x85006000,32,32,32,0,0,false,true), // ldff1w_z_p_bz_s_x32_unscaled
(0xa430a000,16,8,0,0,3,false,false), // ldnf1b_z_p_bi_u16
(0xa450a000,32,8,0,0,3,false,false), // ldnf1b_z_p_bi_u32
(0xa470a000,64,8,0,0,3,false,false), // ldnf1b_z_p_bi_u64
(0xa410a000,8,8,0,0,3,false,false), // ldnf1b_z_p_bi_u8
(0xa5f0a000,64,64,0,0,3,false,false), // ldnf1d_z_p_bi_u64
(0xa4b0a000,16,16,0,0,3,false,false), // ldnf1h_z_p_bi_u16
(0xa4d0a000,32,16,0,0,3,false,false), // ldnf1h_z_p_bi_u32
(0xa4f0a000,64,16,0,0,3,false,false), // ldnf1h_z_p_bi_u64
(0xa5d0a000,16,8,0,0,3,true,false), // ldnf1sb_z_p_bi_s16
(0xa5b0a000,32,8,0,0,3,true,false), // ldnf1sb_z_p_bi_s32
(0xa590a000,64,8,0,0,3,true,false), // ldnf1sb_z_p_bi_s64
(0xa530a000,32,16,0,0,3,true,false), // ldnf1sh_z_p_bi_s32
(0xa510a000,64,16,0,0,3,true,false), // ldnf1sh_z_p_bi_s64
(0xa490a000,64,32,0,0,3,true,false), // ldnf1sw_z_p_bi_s64
(0xa550a000,32,32,0,0,3,false,false), // ldnf1w_z_p_bi_u32
(0xa570a000,64,32,0,0,3,false,false), // ldnf1w_z_p_bi_u64
];
#[derive(Clone)]
struct State { z:[[u64;32];32], p:[[u64;4];17], x:[u64;32], sm:bool, fa64:bool, cpta:Option<bool>, fail:Option<usize>, kind:MemoryFaultKind, calls:RefCell<Vec<(u64,u8,Endian,bool)>> }
impl State {
 fn new()->Self {Self{z:[[0;32];32],p:[[u64::MAX;4];17],x:[0;32],sm:false,fa64:false,cpta:Some(false),fail:None,kind:MemoryFaultKind::Translation,calls:RefCell::new(Vec::new())}}
 fn put(&mut self,n:usize,e:usize,width:u8,value:u64) {let bit=e*usize::from(width);let mask=if width==64{u64::MAX}else{(1<<width)-1};let slot=&mut self.z[n][bit/64];*slot=(*slot&!(mask<<(bit%64)))|((value&mask)<<(bit%64));}
 fn read(&self,address:u64,width:u8,endian:Endian,attempt:bool)->Result<Value,EvalError> {
  let nth=self.calls.borrow().len();self.calls.borrow_mut().push((address,width,endian,attempt));
  if self.fail==Some(nth){return Err(EvalError::MemoryFault(self.kind));}
  let mut bytes=[0u8;8];for (i,byte) in bytes.iter_mut().take(usize::from(width/8)).enumerate(){*byte=(address.wrapping_add(i as u64).wrapping_mul(37).wrapping_add(0x83))as u8;}
  let mut value=0;for i in 0..usize::from(width/8){let shift=if endian==Endian::Little{i}else{usize::from(width/8)-1-i};value|=u64::from(bytes[i])<<(shift*8);}
  Ok(Value::known(width,value))
 }
}
impl Machine for State {
 fn read_register(&self,r:Register)->Value {
  if r.bank=="a64.cpta" {return self.cpta.map(|value|Value::known(1,u64::from(value))).unwrap_or_else(||Value::unknown(1));}
  Value::known(match r.bank{"a64.sme_fa64"=>1,_=>64},match r.bank{
  "a64.vector64"=>self.z[usize::from(r.index/32)][usize::from(r.index%32)],
  "a64.predicate64"=>self.p[usize::from(r.index/4)][usize::from(r.index%4)],
  "a64.gpr"=>self.x[usize::from(r.index)],"a64.sp"=>self.x[31],"a64.svcr"=>u64::from(self.sm),"a64.sme_fa64"=>u64::from(self.fa64),_=>panic!("bank {}",r.bank)
 })}
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.read(a,w,e,false)}
 fn try_read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.read(a,w,e,true)}
}
fn recipe(word:u32,vl:u16,endian:Endian)->Recipe {semantics::arm64_sve_fault::a64(word,0x1000,endian,vl).unwrap()}
fn lane(chunks:&[u64],e:usize,width:u8)->u64 {let bit=e*usize::from(width);let v=chunks[bit/64]>>(bit%64);if width==64{v}else{v&((1<<width)-1)}}
fn unsigned(width:u8,value:u64)->u64 {if width==64{value}else{value&((1<<width)-1)}}
fn expected_address(state:&State,e:usize,word:u32,element:u8,memory:u8,offset:u8,scale:u8,mode:u8,xs:bool,vl:u16)->u64 {
 let n=((word>>5)&31)as usize;let m=((word>>16)&31)as usize;let mb=u64::from(memory/8);
 match mode {
  0=>{let raw=unsigned(offset,lane(&state.z[m],e,element));let off=if xs&&(word>>22)&1!=0{(raw as u32 as i32 as i64)as u64}else{raw};state.x[n].wrapping_add(off.wrapping_shl(u32::from(scale)))},
  1=>lane(&state.z[n],e,element).wrapping_add(m as u64*mb),
  2=>state.x[n].wrapping_add(if m==31{0}else{state.x[m].wrapping_mul(mb)}).wrapping_add(e as u64*mb),
  3=>{let imm=((word>>16)&15)as i64;let imm=if imm>=8{imm-16}else{imm};state.x[n].wrapping_add(((imm*i64::from(vl)/i64::from(element)+e as i64)*mb as i64)as u64)},
  _=>unreachable!()
 }
}
#[test] fn all_physical_classes_address_width_endian_ffr_and_fault_order() {
 assert_eq!(CASES.len(),76);
 for &(base,element,memory,offset,scale,mode,signed,xs) in CASES {
  for vl in [128,256,512,1024,2048] {for endian in [Endian::Little,Endian::Big] {for pattern in 0..4 {
   let n=if mode==1{2}else if pattern==3{31}else{1};let m=if mode==3{15}else if mode==2&&pattern==2{31}else{2};
   let mut word=base|n<<5|m<<16|3<<10;
   if xs&&pattern&1!=0 {word|=1<<22;}
   // Alias the destination with an incoming vector base/offset in alternating cases.
   let d=if pattern&1!=0{2}else{0};word|=d;
   let mut initial=State::new();initial.x[1]=0xffff_ffff_ffff_f000;initial.x[31]=0x2000;initial.x[2]=3;
   let count=usize::from(vl)/usize::from(element);let step=usize::from(element/8);
   initial.p[3]=[0;4];
   for e in 0..count {
    initial.put(2,e,element,if pattern&1!=0{0xffff_fffd}else{e as u64*13+7});
    if pattern!=0&&(pattern==1||e%3==1) {let bit=e*step;initial.p[3][bit/64]|=1<<(bit%64);}
   }
   let active=(0..count).filter(|e|{let bit=e*step;initial.p[3][bit/64]>>(bit%64)&1!=0}).collect::<Vec<_>>();
   for fail in [None,Some(0),Some(1),active.len().checked_sub(1)] {
    let state=initial.clone();let fail=fail.filter(|f|*f<active.len());
    let mut state=state;state.fail=fail;
    let r=recipe(word,vl,endian);r.validate().unwrap();assert_eq!(r.support,Support::Full);
    let result=evaluate(&r,&state);
    if mode!=3&&fail==Some(0) {
     assert_eq!(result,Err(EvalError::MemoryFault(MemoryFaultKind::Translation)));assert_eq!(state.calls.borrow().len(),1);continue;
    }
    let t=result.unwrap();let mut out=state.z[d as usize];let mut ffr=state.p[16];
    for write in &t.registers {match write.register.bank {
     "a64.vector64"=>out[usize::from(write.register.index%32)]=write.value.bits,
     "a64.predicate64"=>ffr[usize::from(write.register.index%4)]=write.value.bits,
     _=>panic!("unexpected write"),
    }}
    let first_bad=fail.map(|f|active[f]);let mut expected_ffr=state.p[16];
    if let Some(first)=first_bad {for bit in first*step..usize::from(vl/8){expected_ffr[bit/64]&=!(1<<(bit%64));}}
    assert_eq!(ffr,expected_ffr,"FFR {word:08x} VL{vl} failure{fail:?}");
    for e in 0..count {
     let expected=if active.contains(&e)&&first_bad.is_none_or(|first|e<first) {
      let addr=expected_address(&state,e,word,element,memory,offset,scale,mode,xs,vl);
      let clean=State{fail:None,..state.clone()};let raw=clean.read(addr,memory,endian,false).unwrap().bits;
      if signed {let shift=64-memory;unsigned(element,((raw<<shift)as i64>>shift)as u64)}else{raw}
     }else{0};
     assert_eq!(lane(&out,e,element),expected,"data {word:08x} VL{vl} e{e} failure{fail:?}");
    }
    assert_eq!(&out[usize::from(vl/64)..],&state.z[d as usize][usize::from(vl/64)..]);
    let calls=state.calls.borrow();assert_eq!(calls.len(),active.len());
    for (nth,(&e,&(address,width,order,attempt))) in active.iter().zip(calls.iter()).enumerate() {
     assert_eq!(address,expected_address(&state,e,word,element,memory,offset,scale,mode,xs,vl));assert_eq!((width,order,attempt),(memory,endian,mode==3||nth!=0));
    }
   }
  }}}
 }
}
#[test] fn existing_ffr_false_zeros_later_data_without_clearing_later_ffr() {
 for vl in [128,256,512,1024,2048] {
  let mut state=State::new();state.p[16][0]&=!(1<<3);state.x[1]=0x1000;
  let t=evaluate(&recipe(0xa4006000|1<<5|31<<16,vl,Endian::Little),&state).unwrap();
  let mut result=[0;32];for w in &t.registers {if w.register.bank=="a64.vector64"{result[usize::from(w.register.index%32)]=w.value.bits;}else{assert_eq!(w.value.bits,state.p[16][usize::from(w.register.index%4)]);}}
  for e in 3..usize::from(vl/8){assert_eq!(lane(&result,e,8),0);}
  assert_eq!(state.calls.borrow().len(),usize::from(vl/8));
 }
}
#[test] fn every_declared_fault_class_is_suppressed_after_first() {
 for kind in [MemoryFaultKind::Translation,MemoryFaultKind::Permission,MemoryFaultKind::Alignment,MemoryFaultKind::TagCheck,MemoryFaultKind::ExternalAbort] {
  let mut state=State::new();state.fail=Some(2);state.kind=kind;
  evaluate(&recipe(0xa4006000,128,Endian::Little),&state).unwrap();
  state.fail=Some(0);state.calls.borrow_mut().clear();assert_eq!(evaluate(&recipe(0xa4006000,128,Endian::Little),&state),Err(EvalError::MemoryFault(kind)));
 }
}
#[test] fn context_validation_and_predicated_sp_alignment_are_lazy() {
 let mut state=State::new();state.sm=true;
 assert_eq!(evaluate(&recipe(0xa4006000,128,Endian::Little),&state),Err(EvalError::UnsupportedContext));assert!(state.calls.borrow().is_empty());
 state.fa64=true;evaluate(&recipe(0xa4006000,128,Endian::Little),&state).unwrap();
 state.calls.borrow_mut().clear();state.x[31]=3;state.p[0]=[0;4];
 evaluate(&recipe(0xa4006000|31<<5,128,Endian::Little),&state).unwrap();assert!(state.calls.borrow().is_empty());
 state.p[0][0]=1;assert_eq!(evaluate(&recipe(0xa4006000|31<<5,128,Endian::Little),&state),Err(EvalError::UnsupportedContext));assert!(state.calls.borrow().is_empty());
 for vl in [0,64,192,384,4096]{assert!(semantics::arm64_sve_fault::a64(0xa4006000,0,Endian::Little,vl).is_none());}
 for word in [0,0xa400a000,0x84004000,0xd503201f] {assert!(semantics::arm64_sve_fault::a64(word,0,Endian::Little,128).is_none());}
}

#[test] fn checked_pointer_context_is_explicit_and_inactive_masks_remain_lazy() {
 let mut state=State::new();state.cpta=Some(true);
 assert_eq!(evaluate(&recipe(0xa4006000,128,Endian::Little),&state),Err(EvalError::UnsupportedContext));assert!(state.calls.borrow().is_empty());
 state.cpta=None;assert_eq!(evaluate(&recipe(0xa4006000,128,Endian::Little),&state),Err(EvalError::UnknownCondition));assert!(state.calls.borrow().is_empty());
 state.p[0]=[0;4];evaluate(&recipe(0xa4006000,128,Endian::Little),&state).unwrap();assert!(state.calls.borrow().is_empty());
}
#[test] fn pre_read_bindings_capture_incoming_aliases_and_feed_ordered_reads() {
 let mut state=State::new();state.x[1]=0x1000;
 let mut r=Recipe::new(4,64);
 let original=r.bind_before_reads(Expr::register(register("a64.gpr",1,64,64))).unwrap();
 let address=r.bind_before_reads(Expr::binary(BinaryOp::Add,original.clone(),Expr::constant(64,8))).unwrap();
 let loaded=r.load_ordered(Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(address),width:32,endian:Endian::Little}).unwrap();
 let loaded=r.bind(loaded);
 r.write(register("a64.gpr",1,64,64),WritePolicy::Preserve,Expr::constant(64,0));
 r.write(register("a64.gpr",2,64,64),WritePolicy::Preserve,original);
 r.write(register("a64.gpr",3,64,64),WritePolicy::Preserve,Expr::cast(loaded,64,false));
 let transition=evaluate(&r,&state).unwrap();assert_eq!(transition.registers[1].value.bits,0x1000);assert_eq!(state.calls.borrow()[0].0,0x1008);
 assert_eq!(state.x[1],0x1000);
}
#[test] fn pre_read_bindings_reject_future_memory_atomic_results_and_bad_counts() {
 let mut r=Recipe::new(4,64);
 let ty=Type{width:64,signedness:Signedness::Unsigned};
 for expression in [
  Expr{ty,kind:ExprKind::Temporary(0)},
  Expr{ty,kind:ExprKind::WideLoadChunk{step:0,chunk:0}},
  Expr{ty:Type{width:1,..ty},kind:ExprKind::WideLoadSuccess{step:0}},
  Expr{ty,kind:ExprKind::AtomicResult{step:0,projection:AtomicProjection::Value}},
  Expr::load(Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,0)),width:64,endian:Endian::Little}),
 ] {
  assert_eq!(r.bind_before_reads(expression.clone()),Err(EvalError::InvalidExpression));
  // Public mutable schema must reject the same malformed graph, including
  // forbidden reads nested in an inactive Select arm.
  let mut invalid=Recipe::new(4,64);invalid.temporaries.push(Expr::select(Expr::constant(1,0),expression.clone(),Expr::constant(expression.ty.width,0)));invalid.pre_read_bindings=1;
  assert_eq!(invalid.validate(),Err(EvalError::InvalidExpression));
 }
 r.pre_read_bindings=1;assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
 r.pre_read_bindings=0;r.bind(Expr::constant(64,0));assert_eq!(r.bind_before_reads(Expr::constant(64,1)),Err(EvalError::InvalidExpression));
 let mut r=Recipe::new(4,64);r.bind_before_reads(Expr::constant(64,1)).unwrap();r.clear_exclusive();r.validate().unwrap();
}
#[test] fn pre_read_bindings_respect_false_recipe_guards_and_lazy_selects() {
 struct Unavailable(std::cell::Cell<usize>);
 impl Machine for Unavailable {
  fn read_register(&self,_:Register)->Value {self.0.set(self.0.get()+1);Value::unknown(64)}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected read")}
 }
 let state=Unavailable(std::cell::Cell::new(0));let mut r=Recipe::new(4,64);
 r.bind_before_reads(Expr::register(register("unavailable",0,64,64))).unwrap();r.guard=Expr::constant(1,0);evaluate(&r,&state).unwrap();assert_eq!(state.0.get(),0);
 let mut r=Recipe::new(4,64);let captured=r.bind_before_reads(Expr::select(Expr::constant(1,0),Expr::register(register("unavailable",0,64,64)),Expr::constant(64,7))).unwrap();r.write(register("a64.gpr",0,64,64),WritePolicy::Preserve,captured);assert_eq!(evaluate(&r,&state).unwrap().registers[0].value.bits,7);assert_eq!(state.0.get(),0);
}
#[test] fn contiguous_first_fault_uses_one_ordinary_read_at_every_vector_length() {
 for &(base,_,_,_,_,mode,_,_) in CASES {
  for vl in [128,256,512,1024,2048] {
   let r=recipe(base|1<<5|2<<16,vl,Endian::Little);
   assert!(r.pre_read_bindings>0);r.validate().unwrap();
   let ordinary=r.wide_load_recovery.iter().filter(|set|set.is_empty()).count();
   if mode==2 {assert_eq!(ordinary,1,"{base:08x} VL{vl}");}
   if mode==3 {assert_eq!(ordinary,0,"{base:08x} VL{vl}");}
  }
 }
}
#[test] fn prefix_stage_rejects_existing_ordered_and_atomic_outputs() {
 let memory=Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,0)),width:64,endian:Endian::Little};
 let mut r=Recipe::new(4,64);let read=r.load_ordered(memory.clone()).unwrap();assert_eq!(r.bind_before_reads(read),Err(EvalError::InvalidExpression));
 let mut r=Recipe::new(4,64);let result=r.atomic(AtomicOperation{memory,ordering:MemoryOrdering::Monotonic,scope:MemoryScope::System,kind:AtomicOperationKind::Load});assert_eq!(r.bind_before_reads(result.value.unwrap()),Err(EvalError::InvalidExpression));
}
#[test] fn ffr_group_boundaries_and_unused_predicate_bits_follow_elemffr_accessor() {
 for (base,width) in [(0xa4206000,16),(0xa4406000,32),(0xa4606000,64)] {
  let mut state=State::new();state.x[1]=0x1000;state.p[16][0]&=!(1<<1);
  let good=evaluate(&recipe(base|1<<5|31<<16,2048,Endian::Little),&state).unwrap();
  assert!(good.registers.iter().filter(|w|w.register.bank=="a64.vector64").any(|w|w.value.bits!=0));
  assert!(good.registers.iter().filter(|w|w.register.bank=="a64.predicate64").all(|w|w.value.bits==state.p[16][usize::from(w.register.index%4)]));
  state.calls.borrow_mut().clear();state.p[0]=[0;4];
  let step=(width/8)as usize;let first=64/step-1;let failed=64/step;
  for e in [first,failed] {let bit=e*step;state.p[0][bit/64]|=1<<(bit%64);}
  state.fail=Some(1);let t=evaluate(&recipe(base|1<<5|31<<16,2048,Endian::Little),&state).unwrap();
  for w in t.registers.iter().filter(|w|w.register.bank=="a64.predicate64") {let chunk=usize::from(w.register.index%4);assert_eq!(w.value.bits,if chunk==0{state.p[16][0]}else{0});}
 }
}

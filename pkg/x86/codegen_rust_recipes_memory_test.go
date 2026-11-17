package x86

// Decoded full-corpus tests distinguish original-width accesses, per-element
// fault suppression, scalar broadcasts, dense stores, and F16C environments.
const x86MaskedMemoryTests = `
struct AccessState{state:State,reads:std::cell::RefCell<Vec<(u64,u16)>>,unknown_address:bool,address_reads:std::cell::Cell<usize>}
impl AccessState{fn new()->Self{Self{state:State::default(),reads:Default::default(),unknown_address:false,address_reads:Default::default()}}}
impl Machine for AccessState{
 fn read_register(&self,r:s::Register)->Value{if r.bank=="x86.gpr"&&r.index==0{self.address_reads.set(self.address_reads.get()+1);if self.unknown_address{return Value::unknown(64);}}self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.reads.borrow_mut().push((a,u16::from(w)));self.state.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.reads.borrow_mut().push((a,w));(0..w/64).map(|i|self.state.read_memory(a+u64::from(i)*8,64,e)).collect()}
}
// The text assembler does not parse broadcast decorators. Encode the ordinary
// EVEX memory form and set its physical b bit, then exercise the real decoder.
fn memory_recipe(text:&str)->s::Recipe{let broadcast=text.contains("{1to");let assembly=if broadcast{text.replace("dword ptr",if text.contains("{1to8}"){ "ymmword ptr" }else{"zmmword ptr"}).replace(" {1to8}","").replace(" {1to16}","")}else{text.to_owned()};let enc=assemble_at(&assembly,0).unwrap_or_else(|e|panic!("{text}: {e:?}"));let mut bytes=enc.first().unwrap().bytes().to_vec();if broadcast{assert_eq!(bytes[0],0x62);bytes[3]|=0x10;}let d=decode(&bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full,"{text}: {bytes:02x?} {}",d.encoding().form_id);r.validate().unwrap();r}
fn memory_eval(text:&str,st:&AccessState)->Transition{s::evaluate(&memory_recipe(text),st).unwrap_or_else(|e|panic!("{text}: {e:?}"))}
#[test]fn compress_memory_stores_dense_positions_and_skips_unknown_addresses(){
 let mut st=AccessState::new();vector(&mut st.state,1,&[0x0000000200000001,0x0000000400000003,0x0000000600000005,0x0000000800000007]);st.state.x(0,0x4000);st.state.reg("x86.mask",1,0x95);
 let t=memory_eval("vpcompressd ymmword ptr [rax] {k1}, ymm1",&st);assert_eq!(t.memory.iter().map(|x|(x.address,x.value.width,x.value.bits)).collect::<Vec<_>>(),vec![(0x4000,32,1),(0x4004,32,3),(0x4008,32,5),(0x400c,32,8)]);assert!(t.wide_memory.is_empty());assert!(st.reads.borrow().is_empty());
 st.state.reg("x86.mask",1,0);st.unknown_address=true;st.address_reads.set(0);let t=memory_eval("vpcompressd ymmword ptr [rax] {k1}, ymm1",&st);assert!(t.memory.is_empty());assert_eq!(st.address_reads.get(),0);
 st.unknown_address=false;st.state.reg("x86.segment_base",4,0x10000);let t=memory_eval("vpcompressd ymmword ptr fs:[rax] {k1}, ymm1",&st);assert!(t.memory.is_empty());st.state.reg("x86.mask",1,0x84);let t=memory_eval("vpcompressd ymmword ptr fs:[rax] {k1}, ymm1",&st);assert_eq!(t.memory.iter().map(|x|(x.address,x.value.bits)).collect::<Vec<_>>(),vec![(0x14000,3),(0x14004,8)]);
 let r=memory_recipe("vpcompressd ymmword ptr [rax], ymm1");let t=s::evaluate(&r,&st).unwrap();assert!(t.memory.is_empty());assert_eq!(t.wide_memory.len(),1);assert_eq!(t.wide_memory[0].width,256);assert_eq!(t.wide_memory[0].chunks.iter().map(|v|v.bits).collect::<Vec<_>>(),vec![0x0000000200000001,0x0000000400000003,0x0000000600000005,0x0000000800000007]);
}
#[test]fn masked_mov_stores_retain_lane_addresses_and_native_unmasked_width(){
 let mut st=AccessState::new();st.state.x(0,0x8000);vector(&mut st.state,1,&[0x0706050403020100;8]);st.state.reg("x86.mask",1,0x8000000000000005);
 let t=memory_eval("vmovdqu8 zmmword ptr [rax] {k1}, zmm1",&st);assert_eq!(t.memory.iter().map(|x|(x.address,x.value.width,x.value.bits)).collect::<Vec<_>>(),vec![(0x8000,8,0),(0x8002,8,2),(0x803f,8,7)]);
 st.state.reg("x86.mask",1,0);st.unknown_address=true;st.address_reads.set(0);assert!(memory_eval("vmovdqu32 zmmword ptr [rax] {k1}, zmm1",&st).memory.is_empty());assert_eq!(st.address_reads.get(),0);
 st.unknown_address=false;let t=memory_eval("vmovdqu32 zmmword ptr [rax], zmm1",&st);assert_eq!(t.wide_memory[0].width,512);assert_eq!(t.wide_memory[0].chunks.len(),8);
}
#[test]fn elementwise_loads_fault_only_active_lanes_and_broadcast_reads_once(){
 let mut st=AccessState::new();st.state.x(0,0x4000);st.state.reg("x86.mask",1,0x81);vector(&mut st.state,1,&[0x0000000200000001;4]);st.state.mem.insert(0x4000,10);st.state.mem.insert(0x401c,20);
 let t=memory_eval("vpaddd ymm0 {k1}{z}, ymm1, ymmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,32),(0x401c,32)]);assert_eq!(vector_result(&t,0,0),11);assert_eq!(vector_result(&t,0,3),22u64<<32);
 st.state.reg("x86.mask",1,3);st.reads.borrow_mut().clear();assert_eq!(s::evaluate(&memory_recipe("vpaddd ymm0 {k1}{z}, ymm1, ymmword ptr [rax]"),&st),Err(EvalError::Memory));assert_eq!(*st.reads.borrow(),vec![(0x4000,32),(0x4004,32)]);
 st.state.reg("x86.mask",1,0x81);st.reads.borrow_mut().clear();let t=memory_eval("vpaddd ymm0 {k1}{z}, ymm1, dword ptr [rax] {1to8}",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,32)]);assert_eq!(vector_result(&t,0,3),12u64<<32);
 st.state.reg("x86.mask",1,1<<8);st.unknown_address=true;st.reads.borrow_mut().clear();st.address_reads.set(0);let t=memory_eval("vpaddd ymm0 {k1}{z}, ymm1, dword ptr [rax] {1to8}",&st);assert!(st.reads.borrow().is_empty());assert_eq!(st.address_reads.get(),0);assert_eq!(vector_result(&t,0,0),0);
}
#[test]fn full_width_reads_and_nf_zero_masks_preserve_fault_contract(){
 let mut st=AccessState::new();st.state.x(0,0x4000);for i in 0..8{st.state.mem.insert(0x4000+i*8,i+1);}vector(&mut st.state,1,&[0;8]);
 let _=memory_eval("vpaddd zmm0, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,512)]);
 st.state.reg("x86.mask",1,0);for (text,width) in [("vpermd zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",512),("vpshufd zmm0 {k1}{z}, zmmword ptr [rax], 27",512),("vpsllw zmm0 {k1}{z}, zmm1, xmmword ptr [rax]",128),("vgf2p8affineqb zmm0 {k1}{z}, zmm1, zmmword ptr [rax], 0",512)]{st.reads.borrow_mut().clear();let t=memory_eval(text,&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,width)],"{text}");assert_eq!(vector_result(&t,0,0),0);st.state.x(0,0xdead0000);st.reads.borrow_mut().clear();assert_eq!(s::evaluate(&memory_recipe(text),&st),Err(EvalError::Memory),"{text}");st.state.x(0,0x4000);}
 st.state.mem.remove(&0x4008);assert_eq!(s::evaluate(&memory_recipe("vpsllw zmm0 {k1}{z}, zmm1, xmmword ptr [rax]"),&st),Err(EvalError::Memory));
 st.reads.borrow_mut().clear();let _=memory_eval("vpermd zmm0 {k1}{z}, zmm1, dword ptr [rax] {1to16}",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,32)]);
 st.state.x(0,0xdead0000);assert_eq!(s::evaluate(&memory_recipe("vpermd zmm0 {k1}{z}, zmm1, dword ptr [rax] {1to16}"),&st),Err(EvalError::Memory));
}
#[test]fn gfni_and_bitshuffle_suppress_individual_masked_control_bytes(){
 let mut st=AccessState::new();st.state.x(0,0x4000);st.state.mem.insert(0x4000,0x57);st.state.mem.insert(0x403f,0x83);st.state.reg("x86.mask",1,0x8000000000000001);vector(&mut st.state,1,&[0x1313131313131313;8]);
 let t=memory_eval("vgf2p8mulb zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,8),(0x403f,8)]);assert_eq!(vector_result(&t,0,0),u64::from(reference_gfmul(0x13,0x57)));assert_eq!(vector_result(&t,0,7),u64::from(reference_gfmul(0x13,0x83))<<56);
 st.reads.borrow_mut().clear();let t=memory_eval("vpshufbitqmb k2 {k1}, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,8),(0x403f,8)]);assert_eq!(reg(&t,"x86.mask",2).bits,(0x1313131313131313u64>>(0x57&63)&1)|(0x1313131313131313u64>>(0x83&63)&1)<<63);
}
#[test]fn unmasked_expand_is_one_native_read(){let mut st=AccessState::new();st.state.x(0,0x4000);for i in 0..4{st.state.mem.insert(0x4000+i*8,0x0000000200000001+i);}let _=memory_eval("vpexpandd ymm0, ymmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,256)]);}
#[test]fn float_broadcast_load_is_captured_before_three_projections(){
 let mut st=FloatState{state:State::default(),calls:Default::default(),loads:Default::default()};st.state.reg("x86.mxcsr",0,0x1f80);st.state.reg("x86.mask",1,0x81);st.state.x(0,0x4000);st.state.mem.insert(0x4000,u64::from(2.5f32.to_bits()));vector(&mut st.state,1,&[u64::from(1.5f32.to_bits())*0x100000001;4]);
 let t=s::evaluate(&memory_recipe("vaddps ymm0 {k1}{z}, ymm1, dword ptr [rax] {1to8}"),&st).unwrap();assert_eq!(st.loads.get(),1);assert_eq!(st.calls.get(),6);assert_eq!(vector_result(&t,0,0),u64::from(4f32.to_bits()));assert_eq!(vector_result(&t,0,3),u64::from(4f32.to_bits())<<32);
}
#[test]fn broadcast_displacement_uses_element_tuple_scale(){let mut st=AccessState::new();st.state.x(0,0x4000);st.state.reg("x86.mask",1,1);st.state.mem.insert(0x4008,7);vector(&mut st.state,1,&[1;4]);let d=decode(&[0x62,0xf1,0x75,0xb9,0xfe,0x40,0x02],Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x4008,32)]);assert_eq!(vector_result(&t,0,0),8);}
#[test]fn aligned_moves_trap_before_reads_and_even_with_empty_mask(){
 let mut st=AccessState::new();st.state.x(0,0x4001);st.state.reg("x86.mask",1,0);for text in ["vmovdqa32 zmm0 {k1}{z}, zmmword ptr [rax]", "vmovdqa64 zmmword ptr [rax] {k1}, zmm1", "movdqa xmm0, xmmword ptr [rax]", "vmovdqa ymm0, ymmword ptr [rax]"]{st.reads.borrow_mut().clear();let t=memory_eval(text,&st);assert_eq!(t.trap,Some(s::TrapKind::Protection),"{text}");assert!(t.memory.is_empty());assert!(t.wide_memory.is_empty());assert!(t.registers.is_empty());assert!(st.reads.borrow().is_empty());}
 st.state.x(0,0x4000);for i in 0..4{st.state.mem.insert(0x4000+i*8,i);}let _=memory_eval("vmovdqa ymm0, ymmword ptr [rax]",&st);assert_eq!(*st.reads.borrow(),vec![(0x4000,256)]);
 for text in ["vmovdqa32 zmm0, zmmword ptr fs:[rax]", "vmovdqa32 zmmword ptr fs:[rax], zmm0"]{st.state.reg("x86.segment_base",4,1);st.reads.borrow_mut().clear();let t=memory_eval(text,&st);assert_eq!(t.trap,Some(s::TrapKind::Protection));assert!(st.reads.borrow().is_empty());assert!(t.registers.is_empty());assert!(t.memory.is_empty());assert!(t.wide_memory.is_empty());}
}

`

// The half reference engine handles all half inputs exactly. Narrowing is
// bounded to finite f32 values within half's finite range, using a binary
// search over representable half values rather than the generated expression.
const x86HalfRecipeTests = `
fn half_value(h:u16)->f64{let exponent=(h>>10)&31;let fraction=h&1023;let a=if exponent==0{f64::from(fraction)*2f64.powi(-24)}else{f64::from(1024+fraction)*2f64.powi(i32::from(exponent)-25)};if h&0x8000!=0{-a}else{a}}
struct HalfState{memory:AccessState,calls:std::cell::Cell<usize>}
impl HalfState{fn new()->Self{let mut memory=AccessState::new();memory.state.reg("x86.mxcsr",0,0x1f80);Self{memory,calls:Default::default()}}}
impl Machine for HalfState{
 fn read_register(&self,r:s::Register)->Value{self.memory.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.memory.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.memory.read_wide_memory(a,w,e)}
 fn evaluate_float(&self,f:&s::FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  if f.environment!=s::FloatEnvironment::X86Mxcsr||!matches!(f.operation,s::FloatOperation::Convert{round_to_odd:false,..})||inputs.len()!=1||!inputs[0].is_known(){return Err(EvalError::Unsupported);}self.calls.set(self.calls.get()+1);
  let mut raised=0;let v=inputs[0];let bits=if v.width==16&&f.width==32{let h=v.bits as u16;if h&0x7c00==0x7c00{if h&1023==0{u64::from(h&0x8000)<<16|0x7f800000}else{if h&512==0{raised|=1;}u64::from(h&0x8000)<<16|0x7fc00000|u64::from(h&1023)<<13}}else{u64::from((half_value(h)as f32).to_bits())}}
  else if v.width==32&&f.width==16{let a=f32::from_bits(v.bits as u32)as f64;if !a.is_finite()||a.abs()>65504.0||a!=0.0&&a.abs()<2f64.powi(-126){return Err(EvalError::Unsupported);}let negative=a.is_sign_negative();let a=a.abs();let(mut low,mut high)=(0u16,0x7bffu16);while low<high{let mid=low+(high-low).div_ceil(2);if half_value(mid)<=a{low=mid}else{high=mid-1}}let exact=half_value(low)==a;let result=if exact{low}else{raised|=32;let upper=low+1;match control.bits>>13&3{0=>{let distance=a-half_value(low);let remainder=half_value(upper)-a;if distance<remainder||distance==remainder&&low&1==0{low}else{upper}},1=>if negative{upper}else{low},2=>if negative{low}else{upper},_=>low}};if !exact&&result&0x7c00==0{raised|=16;}u64::from(result|if negative{0x8000}else{0})}
  else{return Err(EvalError::Unsupported)};
  Ok(match f.projection{s::FloatProjection::Value=>Value::known(f.width,bits),s::FloatProjection::Status=>Value::known(32,status.bits|raised),s::FloatProjection::Trapped=>Value::known(1,u64::from(raised&!(control.bits>>7)&63!=0))})
 }
}
fn half_eval(text:&str,st:&HalfState)->Transition{s::evaluate(&memory_recipe(text),st).unwrap_or_else(|e|panic!("{text}: {e:?}"))}
fn packed_halves(h:[u16;4])->u64{u64::from(h[0])|u64::from(h[1])<<16|u64::from(h[2])<<32|u64::from(h[3])<<48}
#[test]fn f16c_half_input_normalizes_subnormals_and_preserves_payloads(){
 let mut st=HalfState::new();st.memory.state.reg("x86.mxcsr",0,0x9fc0);vector(&mut st.memory.state,1,&[packed_halves([0x0001,0x8000,0x3c00,0x7d01]),0]);let t=half_eval("vcvtph2ps xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),u64::from((2f32.powi(-24)).to_bits())|0x80000000u64<<32);assert_eq!(vector_result(&t,0,1),u64::from(1f32.to_bits())|0x7fe02000u64<<32);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fc1);for i in 2..8{assert_eq!(vector_result(&t,0,i),0);}assert_eq!(st.calls.get(),12);
 st.memory.state.x(0,0x4000);st.memory.state.mem.insert(0x4000,packed_halves([0x0001,0x8000,0x3c00,0x7c00]));let t=half_eval("vcvtph2ps xmm0, qword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x4000,64)]);assert_eq!(vector_result(&t,0,1),0x7f8000003f800000);
}
#[test]fn f16c_immediate_rounding_keeps_architectural_control_and_ignores_ftz(){
 let mut st=HalfState::new();st.memory.state.reg("x86.mxcsr",0,0xdf80);let halfway=1f32+2f32.powi(-11);vector(&mut st.memory.state,1,&[u64::from(halfway.to_bits())|u64::from((-halfway).to_bits())<<32,u64::from(2f32.powi(-24).to_bits())|u64::from(65504f32.to_bits())<<32]);
 for (imm,expected) in [(0,[0x3c00,0xbc00,0x0001,0x7bff]),(1,[0x3c00,0xbc01,0x0001,0x7bff]),(2,[0x3c01,0xbc00,0x0001,0x7bff]),(3,[0x3c00,0xbc00,0x0001,0x7bff]),(4,[0x3c01,0xbc00,0x0001,0x7bff]),(0xf8,[0x3c00,0xbc00,0x0001,0x7bff])]{let t=half_eval(&format!("vcvtps2ph xmm0, xmm1, {imm}"),&st);assert_eq!(vector_result(&t,0,0),packed_halves(expected),"{imm}");assert_eq!(reg(&t,"x86.mxcsr",0).bits,0xdfa0);for i in 1..8{assert_eq!(vector_result(&t,0,i),0);}}
}
#[test]fn half_masked_loads_and_stores_apply_output_lane_predicates(){
 let mut st=HalfState::new();st.memory.state.x(0,0x4000);st.memory.state.reg("x86.mask",1,0x81);st.memory.state.mem.insert(0x4000,0x3c00);st.memory.state.mem.insert(0x400e,0xc000);let t=half_eval("vcvtph2ps ymm0 {k1}{z}, xmmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x4000,16),(0x400e,16)]);assert_eq!(vector_result(&t,0,0),u64::from(1f32.to_bits()));assert_eq!(vector_result(&t,0,3),u64::from((-2f32).to_bits())<<32);
 vector(&mut st.memory.state,1,&[u64::from(1f32.to_bits())|u64::from(2f32.to_bits())<<32;4]);let t=half_eval("vcvtps2ph xmmword ptr [rax] {k1}, ymm1, 0",&st);assert_eq!(t.memory.iter().map(|v|(v.address,v.value.width,v.value.bits)).collect::<Vec<_>>(),vec![(0x4000,16,0x3c00),(0x400e,16,0x4000)]);
 st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;st.memory.address_reads.set(0);st.memory.reads.borrow_mut().clear();st.calls.set(0);let t=half_eval("vcvtph2ps ymm0 {k1}{z}, xmmword ptr [rax]",&st);assert_eq!(st.memory.address_reads.get(),0);assert_eq!(st.calls.get(),0);assert!(st.memory.reads.borrow().is_empty());assert_eq!(vector_result(&t,0,0),0);assert!(half_eval("vcvtps2ph xmmword ptr [rax] {k1}, ymm1, 0",&st).memory.is_empty());assert_eq!(st.memory.address_reads.get(),0);
}
#[test]fn f16c_inexact_tiny_results_raise_underflow_and_round_signed_zero(){
 let mut st=HalfState::new();st.memory.state.reg("x86.mxcsr",0,0x9f80);let tiny=2f32.powi(-25);vector(&mut st.memory.state,1,&[u64::from(tiny.to_bits())|u64::from((-tiny).to_bits())<<32,u64::from((tiny*2.5).to_bits())|u64::from((-0f32).to_bits())<<32]);
 let t=half_eval("vcvtps2ph xmm0, xmm1, 0",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0,0x8000,1,0x8000]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fb0);
 let t=half_eval("vcvtps2ph xmm0, xmm1, 2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([1,0x8000,2,0x8000]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fb0);
}
#[test]fn half_unmasked_native_footprints_and_traps_before_result_stores(){
 let mut st=HalfState::new();st.memory.state.x(0,0x4000);for i in 0..4{st.memory.state.mem.insert(0x4000+i*8,0x3c003c003c003c00);}let _=half_eval("vcvtph2ps zmm0, ymmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x4000,256)]);
 vector(&mut st.memory.state,1,&[u64::from(1f32.to_bits())*0x100000001;8]);let t=half_eval("vcvtps2ph ymmword ptr [rax], zmm1, 0",&st);assert_eq!(t.wide_memory.len(),1);assert_eq!(t.wide_memory[0].width,256);assert_eq!(t.wide_memory[0].chunks.iter().map(|v|v.bits).collect::<Vec<_>>(),vec![0x3c003c003c003c00;4]);
 st.memory.state.reg("x86.mxcsr",0,0x0f80);vector(&mut st.memory.state,1,&[u64::from((1f32+2f32.powi(-11)).to_bits())*0x100000001;8]);let t=half_eval("vcvtps2ph ymmword ptr [rax], zmm1, 0",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert!(t.memory.is_empty());assert!(t.wide_memory.is_empty());assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x0fa0);assert!(!t.registers.iter().any(|v|v.register.bank=="x86.vector64"));
}
`

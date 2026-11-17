package x86

// These checks run against the full imported corpus; expected values are
// computed with ordinary host integer operations, independently of the IR.
const x86ExpandedRecipeTests = `
fn vector(st:&mut State,n:u16,values:&[u64]){for (i,&v) in values.iter().enumerate(){st.reg("x86.vector64",n*8+i as u16,v);}}
fn vector_result(t:&Transition,n:u16,chunk:u16)->u64{reg(t,"x86.vector64",n*8+chunk).bits}
fn mode_run(bytes:&[u8],mode:Mode,ip:u64,st:&State)->Transition{let d=decode(bytes,mode).unwrap();let r=d.semantic_recipe(ip);assert_eq!(r.support,Support::Full,"{bytes:02x?} {}",d.encoding().form_id);r.validate().unwrap();s::evaluate(&r,st).unwrap()}
#[test]fn effective_near_branch_width_and_wrapped_fallthrough(){
 let mut st=State::default();st.reg("x86.flags",3,1);st.x(0,0x12345678);
 assert_eq!(mode_run(&[0x66,0xe9,0,0,1,0],Mode::Mode16,0x1000,&st).next_pc.bits,0x11006);
 assert_eq!(mode_run(&[0x66,0x0f,0x84,0,0,1,0],Mode::Mode16,0x1000,&st).next_pc.bits,0x11007);
 assert_eq!(mode_run(&[0x66,0xff,0xe0],Mode::Mode16,0x1000,&st).next_pc.bits,0x12345678);
 st.reg("x86.flags",3,0);assert_eq!(mode_run(&[0x66,0x0f,0x84,0,0,1,0],Mode::Mode16,0xfffc,&st).next_pc.bits,3);
 assert_eq!(mode_run(&[0x66,0xe9,0,0],Mode::Mode32,0x12340000,&st).next_pc.bits,4);
}
#[test]fn bit_scan_count_swap_and_test_outcomes(){
 let mut st=State::default();st.x(1,0x8000000000000400);
 assert_eq!(x(&run(&[0x48,0x0f,0xbc,0xc1],&st),0),10);
 assert_eq!(x(&run(&[0x48,0x0f,0xbd,0xc1],&st),0),63);
 assert_eq!(x(&run(&[0xf3,0x48,0x0f,0xbc,0xc1],&st),0),10);
 assert_eq!(x(&run(&[0xf3,0x48,0x0f,0xbd,0xc1],&st),0),0);
 assert_eq!(x(&run(&[0xf3,0x48,0x0f,0xb8,0xc1],&st),0),2);
 st.x(1,0);let t=run(&[0x48,0x0f,0xbc,0xc1],&st);assert_eq!(reg(&t,"x86.gpr",0).defined,0);assert_eq!(flag(&t,3).bits,1);
 assert_eq!(x(&run(&[0xf3,0x48,0x0f,0xbc,0xc1],&st),0),64);
 st.x(0,0x0123456789abcdef);assert_eq!(x(&run(&[0x48,0x0f,0xc8],&st),0),0xefcdab8967452301);
 st.x(1,65);let t=run(&[0x48,0x0f,0xbb,0xc8],&st);assert_eq!(x(&t,0),0x0123456789abcded);assert_eq!(flag(&t,0).bits,1);
}
#[test]fn segment_bases_and_wrapped_offsets_are_explicit(){
 let mut st=State::default();st.x(3,0xffff);st.x(6,2);st.reg("x86.segment_base",3,0x100000);st.mem.insert(0x100001,0x1234);
 assert_eq!(x(&mode_run(&[0x8b,0x00],Mode::Mode16,0,&st),0),0x1234);
 st.x(5,0xfffffff0);st.reg("x86.segment_base",2,0x200000);st.mem.insert(0x200010,0x5678);
 assert_eq!(x(&mode_run(&[0x8b,0x45,0x20],Mode::Mode32,0,&st),0),0x5678);
}
#[test]fn legacy_and_vex_integer_add_preservation_and_zeroing(){
 let mut st=State::default();vector(&mut st,0,&[0xffffffff00000001,0x7fffffff80000000,0xaaaa]);vector(&mut st,1,&[0x0000000100000002,0x0000000180000000]);
 let t=run(&[0x66,0x0f,0xfe,0xc1],&st);assert_eq!(vector_result(&t,0,0),3);assert_eq!(vector_result(&t,0,1),0x8000000000000000);assert!(!t.registers.iter().any(|v|v.register.bank=="x86.vector64"&&v.register.index==2));
 vector(&mut st,2,&[1,2,3,4]);vector(&mut st,3,&[9,8,7,6]);let t=run(&[0xc5,0xed,0xfe,0xcb],&st);
 for (i,expected) in [10,10,10,10,0,0,0,0].into_iter().enumerate(){assert_eq!(vector_result(&t,1,i as u16),expected)}
}
#[test]fn packed_saturation_compare_multiply_shuffle_and_unpack(){
 let mut st=State::default();vector(&mut st,0,&[0x7f80ff01020304ff,0x1122334455667788]);vector(&mut st,1,&[0x010101ff01010102,0x0102030405060708]);
 let t=run(&[0x66,0x0f,0xdc,0xc1],&st);let mut expected=0;for i in 0..8{let a=((0x7f80ff01020304ffu64>>(8*i))&255)as u8;let b=((0x010101ff01010102u64>>(8*i))&255)as u8;expected|=u64::from(a.saturating_add(b))<<(8*i);}assert_eq!(vector_result(&t,0,0),expected);
 let t=run(&[0x66,0x0f,0xec,0xc1],&st);let mut expected=0;for i in 0..8{let a=(0x7f80ff01020304ffu64>>(8*i))as i8;let b=(0x010101ff01010102u64>>(8*i))as i8;expected|=u64::from(a.saturating_add(b)as u8)<<(8*i);}assert_eq!(vector_result(&t,0,0),expected);
 let t=run(&[0x66,0x0f,0x64,0xc1],&st);let mut expected=0;for i in 0..8{if (0x7f80ff01020304ffu64>>(8*i))as i8>(0x010101ff01010102u64>>(8*i))as i8{expected|=255u64<<(8*i)}}assert_eq!(vector_result(&t,0,0),expected);
 vector(&mut st,0,&[0x00020003fffef800,0]);vector(&mut st,1,&[0x00030004fffeffff,0]);let t=run(&[0x66,0x0f,0xd5,0xc1],&st);assert_eq!(vector_result(&t,0,0),0x0006000c00040800);
 vector(&mut st,0,&[0x0706050403020100,0x0f0e0d0c0b0a0908]);vector(&mut st,1,&[0x8080808080800f08,0x0001020304050607]);let t=run(&[0x66,0x0f,0x38,0x00,0xc1],&st);assert_eq!(vector_result(&t,0,0),0x0f08);assert_eq!(vector_result(&t,0,1),0x0001020304050607);
 let t=run(&[0x66,0x0f,0x60,0xc1],&st);assert_eq!(vector_result(&t,0,0),0x800380020f010800);
 let t=run(&[0x66,0x0f,0x70,0xc0,0x1b],&st);assert_eq!(vector_result(&t,0,0),0x0b0a09080f0e0d0c);assert_eq!(vector_result(&t,0,1),0x0302010007060504);
}
#[test]fn evex_mask_merge_zero_and_inactive_memory_lanes(){
 let mut st=State::default();vector(&mut st,1,&[0xaaaaaaaabbbbbbbb;8]);vector(&mut st,2,&[0x0000000200000001;8]);vector(&mut st,3,&[0x0000000400000003;8]);st.reg("x86.mask",1,0x5555);
 let t=run(&[0x62,0xf1,0x6d,0x49,0xfe,0xcb],&st);for i in 0..8{assert_eq!(vector_result(&t,1,i),0xaaaaaaaa00000004);}
 let t=run(&[0x62,0xf1,0x6d,0xc9,0xfe,0xcb],&st);for i in 0..8{assert_eq!(vector_result(&t,1,i),4);}
 st.reg("x86.mask",1,1);st.x(0,0x4000);st.mem.insert(0x4000,9);
 let t=run(&[0x62,0xf1,0x6d,0xc9,0xfe,0x08],&st);assert_eq!(vector_result(&t,1,0),10);for i in 1..8{assert_eq!(vector_result(&t,1,i),0);}
 // Qualified broadcast reads one scalar and masked stores retain lane positions.
 let t=run(&[0x62,0xf1,0x6d,0x59,0xfe,0x08],&st);assert_eq!(vector_result(&t,1,0),0xaaaaaaaa0000000a);
 let t=run(&[0x62,0xf1,0x7e,0x49,0x7f,0x08],&st);assert_eq!(t.memory.len(),1);assert_eq!(t.memory[0].address,0x4000);assert_eq!(t.memory[0].value.bits,0xbbbbbbbb);
}

#[test]fn full_width_multiply_and_sign_conversions(){
 let mut st=State::default();
 for (a,b) in [(u64::MAX,u64::MAX),(0x123456789abcdef0,0xfedcba9876543210),(0x8000000000000000,2),(7,9)]{
  st.x(0,a);st.x(1,b);let t=run(&[0x48,0xf7,0xe1],&st);let expected=u128::from(a)*u128::from(b);assert_eq!(x(&t,0),expected as u64);assert_eq!(x(&t,2),(expected>>64)as u64);assert_eq!(flag(&t,0).bits,u64::from(expected>u128::from(u64::MAX)));
  let t=run(&[0x48,0xf7,0xe9],&st);let expected=(a as i64 as i128)*(b as i64 as i128);assert_eq!(x(&t,0),expected as u64);assert_eq!(x(&t,2),(expected>>64)as u64);assert_eq!(flag(&t,0).bits,u64::from(expected!=expected as i64 as i128));
  let t=run(&[0x48,0x0f,0xaf,0xc1],&st);assert_eq!(x(&t,0),expected as u64);assert_eq!(flag(&t,5).bits,u64::from(expected!=expected as i64 as i128));
 }
 st.x(0,0xffffffffffffff80);st.x(1,2);let t=run(&[0xf6,0xe9],&st);assert_eq!(x(&t,0),0xffffffffffffff00);assert_eq!(flag(&t,0).bits,1);
 st.x(0,0x80000000);assert_eq!(x(&run(&[0x48,0x98],&st),0),0xffffffff80000000);assert_eq!(x(&run(&[0x99],&st),2),0xffffffff);
 st.x(0,0x8000000000000000);assert_eq!(x(&run(&[0x48,0x99],&st),2),u64::MAX);
 assert_eq!(x(&run(&[0x48,0x6b,0xc8,0xff],&st),1),0x8000000000000000);
}
#[test]fn double_shifts_and_carry_rotates_match_wide_host_arithmetic(){
 let mut st=State::default();st.x(0,0x8123456789abcdef);st.x(2,0xfedcba9876543210);st.reg("x86.flags",0,1);
 for count in [0,1,7,31,32,63,64,65,255]{
  st.x(1,count);let n=(count&63)as u32;let a=0x8123456789abcdefu64;let b=0xfedcba9876543210u64;
  let expected=if n==0{a}else{(a<<n)|(b>>(64-n))};assert_eq!(x(&run(&[0x48,0x0f,0xa5,0xd0],&st),0),expected);
  let expected=if n==0{a}else{(a>>n)|(b<<(64-n))};assert_eq!(x(&run(&[0x48,0x0f,0xad,0xd0],&st),0),expected);
  let wide=(u128::from(a)<<1)|1;let mask=(1u128<<65)-1;
  let rol=if n==0{wide}else{((wide<<n)|(wide>>(65-n)))&mask};let t=run(&[0x48,0xd3,0xd0],&st);assert_eq!(x(&t,0),(rol>>1)as u64);assert_eq!(flag(&t,0).bits,(rol&1)as u64);
  let ror=if n==0{wide}else{((wide>>n)|(wide<<(65-n)))&mask};let t=run(&[0x48,0xd3,0xd8],&st);assert_eq!(x(&t,0),(ror>>1)as u64);assert_eq!(flag(&t,0).bits,(ror&1)as u64);
 }
 for count in 0..32{st.x(0,0x81);st.x(1,count);let n=(count%9)as u32;let wide=0x103u16;let rotated=if n==0{wide}else{((wide<<n)|(wide>>(9-n)))&511};let t=run(&[0xd2,0xd0],&st);assert_eq!(x(&t,0),(rotated>>1)as u64);assert_eq!(flag(&t,0).bits,(rotated&1)as u64);if count==0{assert!(flag(&t,5).is_known());}else if count!=1{assert_eq!(flag(&t,5).defined,0);}}
}
#[test]fn explicit_flag_accesses_and_loop_prestate(){
 let mut st=State::default();for (i,v) in [(0,1),(1,1),(2,0),(3,1),(4,1)]{st.reg("x86.flags",i,v);}
 st.x(0,0x1122334455667788);assert_eq!(x(&run(&[0x9f],&st),0),0x112233445566c788);
 st.x(0,0x5500);let t=run(&[0x9e],&st);assert_eq!(flag(&t,0).bits,1);assert_eq!(flag(&t,3).bits,1);assert_eq!(flag(&t,4).bits,0);
 assert_eq!(flag(&run(&[0xf8],&st),0).bits,0);assert_eq!(flag(&run(&[0xf9],&st),0).bits,1);assert_eq!(flag(&run(&[0xf5],&st),0).bits,0);assert_eq!(flag(&run(&[0xfc],&st),6).bits,0);assert_eq!(flag(&run(&[0xfd],&st),6).bits,1);
 st.x(1,2);let t=run(&[0xe2,0xfe],&st);assert_eq!(x(&t,1),1);assert_eq!(t.next_pc.bits,0x1000);st.x(1,1);assert_eq!(run(&[0xe2,0xfe],&st).next_pc.bits,0x1002);
}

fn asm_run(text:&str,st:&State)->Transition{let encodings=assemble_at(text,0x1000).unwrap();let bytes=encodings.first().unwrap().bytes();run(bytes,st)}
#[test]fn bmi_and_adx_results_and_flag_preservation(){
 let mut st=State::default();st.x(1,0x8123456789abcdef);st.x(2,13);for i in 0..6{st.reg("x86.flags",i,1);}
 assert_eq!(x(&asm_run("shlx rax, rcx, rdx",&st),0),0x8123456789abcdefu64<<13);
 assert_eq!(x(&asm_run("shrx rax, rcx, rdx",&st),0),0x8123456789abcdefu64>>13);
 assert_eq!(x(&asm_run("sarx rax, rcx, rdx",&st),0),(0x8123456789abcdefu64 as i64>>13)as u64);
 let t=asm_run("rorx rax, rcx, 13",&st);assert_eq!(x(&t,0),0x8123456789abcdefu64.rotate_right(13));assert!(!t.registers.iter().any(|r|r.register.bank=="x86.flags"));
 assert_eq!(x(&asm_run("andn rax, rcx, rdx",&st),0),!0x8123456789abcdefu64&13);
 st.x(2,0x1008);assert_eq!(x(&asm_run("bextr rax, rcx, rdx",&st),0),0xabcd);
 st.x(2,8);assert_eq!(x(&asm_run("bzhi rax, rcx, rdx",&st),0),0xef);
 assert_eq!(x(&asm_run("blsr rax, rcx",&st),0),0x8123456789abcdee);assert_eq!(x(&asm_run("blsi rax, rcx",&st),0),1);assert_eq!(x(&asm_run("blsmsk rax, rcx",&st),0),1);
 for (a,mask) in [(0x123456789abcdef0u64,0xf0f0f0f0f0f0f0f0u64),(u64::MAX,0),(0x1234,u64::MAX)]{st.x(1,a);st.x(2,mask);let(mut dep,mut ext,mut j)=(0,0,0);for bit in 0..64{if mask>>bit&1!=0{dep|=(a>>j&1)<<bit;ext|=(a>>bit&1)<<j;j+=1;}}assert_eq!(x(&asm_run("pdep rax, rcx, rdx",&st),0),dep);assert_eq!(x(&asm_run("pext rax, rcx, rdx",&st),0),ext);}
 st.x(0,u64::MAX);st.x(1,0);let t=asm_run("adcx rax, rcx",&st);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,0).bits,1);assert!(!t.registers.iter().any(|r|r.register.bank=="x86.flags"&&r.register.index!=0));let t=asm_run("adox rax, rcx",&st);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,5).bits,1);
}
#[test]fn packed_shift_and_pack_host_outcomes(){
 let mut st=State::default();vector(&mut st,0,&[0x8001ffff12345678,0x80007fff00010000]);vector(&mut st,1,&[4,0]);
 let t=asm_run("psllw xmm0, xmm1",&st);let mut expected=0;for i in 0..4{expected|=u64::from(((0x8001ffff12345678u64>>(16*i))as u16).wrapping_shl(4))<<(16*i);}assert_eq!(vector_result(&t,0,0),expected);
 let t=asm_run("psraw xmm0, 17",&st);assert_eq!(vector_result(&t,0,0),0xffffffff00000000);assert_eq!(vector_result(&t,0,1),0xffff000000000000);
 let t=asm_run("vpsllq ymm2, ymm0, 64",&st);for i in 0..8{assert_eq!(vector_result(&t,2,i),0);}
 vector(&mut st,1,&[0x0100ff000080ff80,0x0000ffff007f0080]);let t=asm_run("packsswb xmm0, xmm1",&st);
 let source=[0x8001ffff12345678u64,0x80007fff00010000,0x0100ff000080ff80,0x0000ffff007f0080];let mut out=[0u8;16];for i in 0..16{let value=(source[i/4]>>(16*(i%4)))as i16;out[i]=value.clamp(-128,127)as i8 as u8;}assert_eq!(vector_result(&t,0,0),u64::from_le_bytes(out[..8].try_into().unwrap()));assert_eq!(vector_result(&t,0,1),u64::from_le_bytes(out[8..].try_into().unwrap()));
}
#[test]fn every_admitted_real_form_is_structurally_valid(){
 let mut admitted=0;let mut bytes=[0;15];for i in 0..encoding_count(){for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64]{if let Ok(length)=encode_representative(i,mode,&mut bytes){if let Ok(d)=decode(&bytes[..length],mode){let r=d.semantic_recipe(0x1000);if r.support==Support::Full{r.validate().unwrap_or_else(|e|panic!("{} {mode:?} {:02x?}: {e:?}",d.encoding().form_id,&bytes[..length]));admitted+=1;}}}}}assert!(admitted>500,"admitted {admitted}");
}

#[test]fn division_success_and_explicit_exceptions(){
 let mut st=State::default();
 for (hi,lo,b) in [(0u64,100u64,7u64),(1,u64::MAX,3),(0x1234,0x567890abcdef0000,0x12345678),(0,u64::MAX,u64::MAX)]{
  st.x(2,hi);st.x(0,lo);st.x(1,b);let t=run(&[0x48,0xf7,0xf1],&st);let dividend=(u128::from(hi)<<64)|u128::from(lo);assert_eq!(t.trap,None);assert_eq!(x(&t,0),(dividend/u128::from(b))as u64);assert_eq!(x(&t,2),(dividend%u128::from(b))as u64);
 }
 for (a,b) in [(-100i128,7i64),(100,-7),(-100,-7),(i64::MIN as i128,1),((i64::MAX as i128)*5,7)]{
  st.x(2,(a>>64)as u64);st.x(0,a as u64);st.x(1,b as u64);let t=run(&[0x48,0xf7,0xf9],&st);assert_eq!(t.trap,None);assert_eq!(x(&t,0),(a/i128::from(b))as u64);assert_eq!(x(&t,2),(a%i128::from(b))as u64);
 }
 st.x(2,0);st.x(0,99);st.x(1,0);let t=run(&[0x48,0xf7,0xf1],&st);assert_eq!(t.trap,Some(s::TrapKind::IntegerDivideByZero));assert!(t.registers.is_empty());
 st.x(2,2);st.x(1,2);let t=run(&[0x48,0xf7,0xf1],&st);assert_eq!(t.trap,Some(s::TrapKind::IntegerOverflow));assert!(t.registers.is_empty());
 st.x(2,u64::MAX);st.x(0,0x8000000000000000);st.x(1,u64::MAX);assert_eq!(run(&[0x48,0xf7,0xf9],&st).trap,Some(s::TrapKind::IntegerOverflow));
 st.x(0,0x112233445566ff9c);st.x(1,7);let t=run(&[0xf6,0xf9],&st);assert_eq!(x(&t,0),0x112233445566fef2);assert_eq!(t.trap,None);
}
struct FloatState{state:State,calls:std::cell::Cell<usize>,loads:std::cell::Cell<usize>}
impl Machine for FloatState{
 fn read_register(&self,r:s::Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.loads.set(self.loads.get()+1);self.state.read_memory(a,w,e)}
 fn evaluate_float(&self,f:&s::FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.environment,s::FloatEnvironment::X86Mxcsr);assert_eq!(control.width,32);assert_eq!(status.width,32);self.calls.set(self.calls.get()+1);
  if !matches!(f.operation,s::FloatOperation::Add|s::FloatOperation::Subtract|s::FloatOperation::Multiply|s::FloatOperation::Divide|s::FloatOperation::SquareRoot){return Err(EvalError::Unsupported);}
  let zero_divide=f.operation==s::FloatOperation::Divide && inputs[1].bits==0;
  let status_bits=status.bits|if zero_divide{4}else{0};
  Ok(match f.projection{
   s::FloatProjection::Status=>Value::known(32,status_bits),
   s::FloatProjection::Trapped=>Value::known(1,u64::from(zero_divide&&control.bits&(1<<9)==0)),
   s::FloatProjection::Value=>{
    let apply=|a:f64,b:f64|if f.operation==s::FloatOperation::Add{a+b}else if f.operation==s::FloatOperation::Subtract{a-b}else if f.operation==s::FloatOperation::Multiply{a*b}else if f.operation==s::FloatOperation::Divide{a/b}else if f.operation==s::FloatOperation::SquareRoot{a.sqrt()}else{panic!("focused reference engine does not implement this FP operation")};
    if f.width==32{Value::known(32,(apply(f32::from_bits(inputs[0].bits as u32)as f64,inputs.get(1).map(|v|f32::from_bits(v.bits as u32)as f64).unwrap_or(0.0))as f32).to_bits()as u64)}else{Value::known(64,apply(f64::from_bits(inputs[0].bits),inputs.get(1).map(|v|f64::from_bits(v.bits)).unwrap_or(0.0)).to_bits())}
   }
  })
 }
}
fn float_run(bytes:&[u8],state:&FloatState)->Transition{let d=decode(bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{bytes:02x?}");s::evaluate(&r,state).unwrap()}
#[test]fn floating_recipes_preserve_scalar_bits_and_order_exceptions(){
 let mut f=FloatState{state:State::default(),calls:std::cell::Cell::new(0),loads:std::cell::Cell::new(0)};f.state.reg("x86.mxcsr",0,0x1f80);
 vector(&mut f.state,0,&[0xaabbccdd00000000|1.5f32.to_bits()as u64,0x1122334455667788,0xcccc]);vector(&mut f.state,1,&[2.5f32.to_bits()as u64,0]);
 let t=float_run(&[0xf3,0x0f,0x58,0xc1],&f);assert_eq!(vector_result(&t,0,0),0xaabbccdd00000000|4.0f32.to_bits()as u64);assert!(!t.registers.iter().any(|r|r.register.bank=="x86.vector64"&&r.register.index>0));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f80);
 vector(&mut f.state,2,&[0xdeadbeef00000000|8.0f32.to_bits()as u64,0x12345678]);vector(&mut f.state,3,&[2.0f32.to_bits()as u64,0]);
 let t=float_run(&[0xc5,0xea,0x5e,0xcb],&f);assert_eq!(vector_result(&t,1,0),0xdeadbeef00000000|4.0f32.to_bits()as u64);assert_eq!(vector_result(&t,1,1),0x12345678);for i in 2..8{assert_eq!(vector_result(&t,1,i),0);}
 f.state.reg("x86.mxcsr",0,0);vector(&mut f.state,1,&[0,0]);let t=float_run(&[0xf3,0x0f,0x5e,0xc1],&f);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,4);assert!(!t.registers.iter().any(|r|r.register.bank=="x86.vector64"));
 f.state.x(0,0x4000);f.state.mem.insert(0x4000,2.0f32.to_bits()as u64);f.loads.set(0);let _=float_run(&[0xf3,0x0f,0x58,0x00],&f);assert_eq!(f.loads.get(),1);
 f.state.reg("x86.mask",1,0);f.state.x(0,0xdead0000);f.calls.set(0);f.loads.set(0);let t=float_run(&[0x62,0xf1,0x6c,0xc9,0x58,0x08],&f);assert_eq!(f.calls.get(),0);assert_eq!(f.loads.get(),0);assert_eq!(t.trap,None);for i in 0..8{assert_eq!(vector_result(&t,1,i),0);}
}

#[test]fn packed_transfer_broadcast_align_and_multiply_add(){
 let mut st=State::default();st.x(0,0x1122334455667788);vector(&mut st,1,&[0x0706050403020100,0x0f0e0d0c0b0a0908]);vector(&mut st,2,&[0x1716151413121110,0x1f1e1d1c1b1a1918]);
 let t=asm_run("movd xmm0, eax",&st);assert_eq!(vector_result(&t,0,0),0x55667788);assert_eq!(vector_result(&t,0,1),0);
 let t=asm_run("vmovq xmm0, rax",&st);assert_eq!(vector_result(&t,0,0),0x1122334455667788);for i in 1..8{assert_eq!(vector_result(&t,0,i),0);}
 assert_eq!(x(&asm_run("pextrb eax, xmm1, 11",&st),0),11);
 let t=asm_run("vpinsrd xmm0, xmm1, eax, 2",&st);assert_eq!(vector_result(&t,0,0),0x0706050403020100);assert_eq!(vector_result(&t,0,1),0x0f0e0d0c55667788);
 let t=asm_run("vpbroadcastb ymm0, xmm1",&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0);}
 let t=asm_run("palignr xmm1, xmm2, 12",&st);assert_eq!(vector_result(&t,1,0),0x030201001f1e1d1c);assert_eq!(vector_result(&t,1,1),0x0b0a090807060504);
 vector(&mut st,0,&[0x800080007fff7fff,0]);vector(&mut st,1,&[0x800080007fff7fff,0]);let t=asm_run("pmaddwd xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),0x800000007ffe0002);
 vector(&mut st,0,&[0x0000000200000003,0]);vector(&mut st,1,&[0x0000000400000005,0]);let t=asm_run("pmuludq xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),15);
 let t=asm_run("psadbw xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),4);
 vector(&mut st,0,&[0x8080808080808080,0]);assert_eq!(x(&asm_run("pmovmskb eax, xmm0",&st),0),255);
 st.x(0,0x2000);st.mem.insert(0x2000,0x0123456789abcdef);assert_eq!(x(&asm_run("movbe rcx, qword ptr [rax]",&st),1),0xefcdab8967452301);
}

struct AtomicState{state:State,requests:std::cell::RefCell<Vec<s::AtomicRequest>>}
impl Machine for AtomicState{
 fn read_register(&self,r:s::Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.state.read_memory(a,w,e)}
 fn evaluate_atomic(&self,request:&s::AtomicRequest,previous:&[s::AtomicTransition])->Result<s::AtomicObservation,EvalError>{assert!(previous.is_empty());assert_eq!(request.ordering,s::MemoryOrdering::SequentiallyConsistent);assert_eq!(request.scope,s::MemoryScope::System);self.requests.borrow_mut().push(request.clone());Ok(s::AtomicObservation{old:Some(self.state.read_memory(request.address,request.width,request.endian)?),store_succeeded:None,reservation_token:None,witness:42})}
 fn evaluate_atomic_pair(&self,request:&s::AtomicRequest,previous:&[s::AtomicTransition])->Result<s::AtomicPairObservation,EvalError>{
  assert!(previous.is_empty());assert_eq!(request.width,128);assert_eq!(request.ordering,s::MemoryOrdering::SequentiallyConsistent);assert_eq!(request.scope,s::MemoryScope::System);self.requests.borrow_mut().push(request.clone());
  Ok(s::AtomicPairObservation{observation:s::AtomicObservation{old:Some(self.state.read_memory(request.address,64,request.endian)?),store_succeeded:None,reservation_token:None,witness:99},old_high:Some(self.state.read_memory(request.address+8,64,request.endian)?)})
 }
}
fn atomic_run(bytes:&[u8],state:&AtomicState)->Transition{let d=decode(bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{bytes:02x?} {}",d.encoding().form_id);r.validate().unwrap();s::evaluate(&r,state).unwrap()}
#[test]fn locked_rmw_exchange_and_compare_exchange_keep_atomic_identity(){
 let mut st=AtomicState{state:State::default(),requests:Default::default()};st.state.x(0,0x4000);st.state.x(1,1);st.state.mem.insert(0x4000,0x7fffffffffffffff);
 let t=atomic_run(&[0xf0,0x48,0x01,0x08],&st);assert!(t.memory.is_empty());assert_eq!(t.atomics.len(),1);assert_eq!(t.atomics[0].stored,Some(Value::known(64,0x8000000000000000)));assert_eq!(flag(&t,5).bits,1);
 st.state.x(1,7);st.state.mem.insert(0x4000,10);let t=atomic_run(&[0x48,0x87,0x08],&st);assert_eq!(x(&t,1),10);assert_eq!(t.atomics[0].stored,Some(Value::known(64,7)));assert!(t.memory.is_empty());
 let t=atomic_run(&[0xf0,0x48,0x0f,0xc1,0x08],&st);assert_eq!(x(&t,1),10);assert_eq!(t.atomics[0].stored,Some(Value::known(64,17)));
 st.state.x(3,0x4000);st.state.x(0,0xaabbccdd0000000a);let t=atomic_run(&[0xf0,0x0f,0xb1,0x0b],&st);assert_eq!(t.atomics[0].success,Some(true));assert_eq!(t.atomics[0].stored,Some(Value::known(32,7)));assert_eq!(x(&t,0),0xaabbccdd0000000a);assert_eq!(flag(&t,3).bits,1);
 st.state.mem.insert(0x4000,12);let t=atomic_run(&[0xf0,0x0f,0xb1,0x0b],&st);assert_eq!(t.atomics[0].success,Some(false));assert_eq!(t.atomics[0].stored,None);assert_eq!(x(&t,0),12);assert_eq!(flag(&t,3).bits,0);
 st.state.x(0,0xaabbccdd0000000a);st.state.x(2,0x1122334400000000);st.state.x(3,0x4000);st.state.x(1,0x12345678);st.state.x(7,0x4000);st.state.mem.insert(0x4000,10);let t=atomic_run(&[0xf0,0x0f,0xc7,0x0f],&st);assert_eq!(t.atomics[0].success,Some(true));assert_eq!(t.atomics[0].stored,Some(Value::known(64,0x1234567800004000)));assert_eq!(x(&t,0),0xaabbccdd0000000a);assert_eq!(x(&t,2),0x1122334400000000);
 st.state.mem.insert(0x4000,0x5566778899aabbcc);let t=atomic_run(&[0xf0,0x0f,0xc7,0x0f],&st);assert_eq!(t.atomics[0].success,Some(false));assert_eq!(x(&t,0),0x99aabbcc);assert_eq!(x(&t,2),0x55667788);
 let d=decode(&[0xf0,0x48,0x01,0x08],Mode::Mode64).unwrap();assert_eq!(s::evaluate(&d.semantic_recipe(0),&st.state),Err(EvalError::Unsupported));
 st.state.x(0,7);let t=run(&[0x48,0x0f,0xc1,0xc0],&st.state);assert_eq!(x(&t,0),14);assert!(t.atomics.is_empty());
}

#[test]fn string_direction_segments_and_frame_stack_order(){
 let mut st=State::default();st.x(6,0x2000);st.x(7,0x3000);st.mem.insert(0x2000,0x5a);st.mem.insert(0x3000,0x5a);
 let t=run(&[0xa4],&st);assert_eq!(t.memory[0].address,0x3000);assert_eq!(t.memory[0].value.bits,0x5a);assert_eq!(x(&t,6),0x2001);assert_eq!(x(&t,7),0x3001);
 st.reg("x86.flags",6,1);let t=run(&[0xa6],&st);assert_eq!(flag(&t,3).bits,1);assert_eq!(x(&t,6),0x1fff);assert_eq!(x(&t,7),0x2fff);
 st.x(0,0x1234);let t=run(&[0xaa],&st);assert_eq!(t.memory[0].value.bits,0x34);assert_eq!(x(&t,7),0x2fff);
 let t=run(&[0xac],&st);assert_eq!(x(&t,0),0x125a);assert_eq!(x(&t,6),0x1fff);
 st.reg("x86.segment_base",4,0x4000);st.mem.insert(0x6000,0x99);let t=run(&[0x64,0xa4],&st);assert_eq!(t.memory[0].value.bits,0x99);assert_eq!(t.memory[0].address,0x3000);
 st.x(3,0x2000);st.x(0,3);st.mem.insert(0x2003,0x7a);assert_eq!(x(&run(&[0xd7],&st),0),0x7a);
 st.x(5,0x5000);st.x(4,0x6000);st.mem.insert(0x5000,0x12345678);let t=run(&[0xc9],&st);assert_eq!(x(&t,4),0x5008);assert_eq!(x(&t,5),0x12345678);
 let t=run(&[0xc8,0x20,0,0],&st);assert_eq!(x(&t,5),0x5ff8);assert_eq!(x(&t,4),0x5fd8);assert_eq!(t.memory[0].address,0x5ff8);assert_eq!(t.memory[0].value.bits,0x5000);
 // Frame-chain reads can alias an earlier push. Forward that pushed value
 // instead of performing a stale pre-instruction memory read.
 st.x(4,0x6000);st.x(5,0x6000);let t=run(&[0xc8,0,0,2],&st);assert_eq!(t.memory.len(),3);assert_eq!(t.memory[1].value.bits,0x6000);assert_eq!(t.memory[2].value.bits,0x5ff8);assert_eq!(x(&t,4),0x5fe8);
 for bytes in [&[0xf3,0xa4][..],&[0xf2,0xa6][..]]{assert!(matches!(decode(bytes,Mode::Mode64).unwrap().semantic_recipe(0).support,Support::Unsupported(_)));}
}
// Deliberately bounded reference backend: finite exact conversions/arithmetic,
// comparisons including NaNs, and integral rounding only. Other math rejects.
struct ExtendedFloatState{state:State,loads:std::cell::Cell<usize>}
impl Machine for ExtendedFloatState{
 fn read_register(&self,r:s::Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.loads.set(self.loads.get()+1);self.state.read_memory(a,w,e)}
 fn evaluate_float(&self,f:&s::FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  use s::{FloatOperation as F,FloatRounding as R};
  if f.environment!=s::FloatEnvironment::X86Mxcsr||control.bits&0x8040!=0||inputs.iter().any(|v|!v.is_known()){return Err(EvalError::Unsupported);}
  let decode=|v:Value|if v.width==32{f32::from_bits(v.bits as u32)as f64}else{f64::from_bits(v.bits)};
  let bits=|v:f64|if f.width==32{(v as f32).to_bits()as u64}else{v.to_bits()};
  let rounded=|v:f64,rounding:R|{let r=if rounding==R::Environment{match control.bits>>13&3{0=>R::NearestEven,1=>R::NegativeInfinity,2=>R::PositiveInfinity,_=>R::Zero}}else{rounding};match r{R::NearestEven=>v.round_ties_even(),R::NegativeInfinity=>v.floor(),R::PositiveInfinity=>v.ceil(),R::Zero=>v.trunc(),_=>f64::NAN}};
  let mut raised=0u64;
  let value=match f.operation{
   F::FusedMultiplyAdd{negate_product,negate_addend}=>{let a=decode(inputs[0]);let b=decode(inputs[1]);let c=decode(inputs[2]);if ![a,b,c].iter().all(|v|v.is_finite()&&v.fract()==0.0&&v.abs()<=1024.0)||control.bits>>13&3!=0{return Err(EvalError::Unsupported);}let b=if negate_product{-b}else{b};let a=if negate_addend{-a}else{a};if f.width==32{((b as f32).mul_add(c as f32,a as f32)).to_bits()as u64}else{b.mul_add(c,a).to_bits()}},
   F::Compare{signal_all_nans,..}=>{let a=decode(inputs[0]);let b=decode(inputs[1]);let snan=inputs.iter().any(|v|if v.width==32{v.bits&0x7f800000==0x7f800000&&v.bits&0x7fffff!=0&&v.bits&0x400000==0}else{v.bits&0x7ff0000000000000==0x7ff0000000000000&&v.bits&0xfffffffffffff!=0&&v.bits&0x8000000000000==0});if snan||signal_all_nans&&(a.is_nan()||b.is_nan()){raised|=1;}if a.is_nan()||b.is_nan(){3}else if a<b{8}else if a==b{6}else{2}},
   F::Convert{round_to_odd:false,..}=>{let a=decode(inputs[0]);if !a.is_finite()||(f.width==32&&(a as f32)as f64!=a){return Err(EvalError::Unsupported);}bits(a)},
   F::FromInteger{signed,fractional_bits:0,..}=>{let a=inputs[0];let value=if signed{if a.width==32{a.bits as u32 as i32 as f64}else{a.bits as i64 as f64}}else{a.bits as f64};if value.abs()>16777216.0{return Err(EvalError::Unsupported);}bits(value)},
   F::ToInteger{signed,fractional_bits:0,rounding,..}=>{let a=decode(inputs[0]);let rounded=rounded(a,rounding);if !a.is_finite()||!rounded.is_finite()||rounded.abs()>16777216.0||(!signed&&rounded<0.0){return Err(EvalError::Unsupported);}if rounded!=a{raised|=32;}if signed{rounded as i64 as u64}else{rounded as u64}},
   F::MinMax{minimum,numeric:false}=>{if inputs.iter().any(|v|if v.width==32{v.bits&0x7f800000==0x7f800000&&v.bits&0x7fffff!=0&&v.bits&0x400000==0}else{v.bits&0x7ff0000000000000==0x7ff0000000000000&&v.bits&0xfffffffffffff!=0&&v.bits&0x8000000000000==0}){return Err(EvalError::Unsupported);}let a=decode(inputs[0]);let b=decode(inputs[1]);if a.is_nan()||b.is_nan()||a==b{inputs[1].bits}else if if minimum{a<b}else{a>b}{inputs[0].bits}else{inputs[1].bits}},
   F::RoundScale{scale,rounding,exact}=>{let a=decode(inputs[0]);if !a.is_finite(){return Err(EvalError::Unsupported);}let factor=2f64.powi(i32::from(scale));let n=a*factor;if !n.is_finite(){return Err(EvalError::Unsupported);}let v=rounded(n,rounding)/factor;if exact&&v!=a{raised|=32;}bits(if v==0.0{v.copysign(a)}else{v})},
   F::RoundToIntegral{rounding,exact}=>{let a=decode(inputs[0]);if !a.is_finite(){return Err(EvalError::Unsupported);}let v=rounded(a,rounding);if !v.is_finite(){return Err(EvalError::Unsupported);}if exact&&v!=a{raised|=32;}bits(v)},
   _=>return Err(EvalError::Unsupported)
  };
  Ok(match f.projection{s::FloatProjection::Value=>Value::known(f.width,value),s::FloatProjection::Status=>Value::known(32,status.bits|raised),s::FloatProjection::Trapped=>Value::known(1,u64::from(raised&!(control.bits>>7)&63!=0))})
 }
}
fn extended_float()->ExtendedFloatState{let mut state=State::default();state.reg("x86.mxcsr",0,0x1f80);ExtendedFloatState{state,loads:std::cell::Cell::new(0)}}
fn extended_run(text:&str,state:&ExtendedFloatState)->Transition{let enc=assemble_at(text,0x1000).unwrap_or_else(|e|panic!("{text}: {e:?}"));let bytes=enc.first().unwrap().bytes();let d=decode(bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{text}: {bytes:02x?} {}",d.encoding().form_id);r.validate().unwrap();s::evaluate(&r,state).unwrap()}
#[test]fn fma_operand_orders_signs_and_scalar_preservation(){
 let mut f=extended_float();vector(&mut f.state,0,&[0xdeadbeef00000000|2f32.to_bits()as u64,0x1234,0xabcd]);vector(&mut f.state,1,&[3f32.to_bits()as u64,0]);vector(&mut f.state,2,&[5f32.to_bits()as u64,0]);
 for (name,expected) in [("vfmadd132ss",13f32),("vfmadd213ss",11.),("vfmadd231ss",17.),("vfmsub132ss",7.),("vfnmadd132ss",-7.),("vfnmsub132ss",-13.)]{let t=extended_run(&format!("{name} xmm0, xmm1, xmm2"),&f);assert_eq!(vector_result(&t,0,0),0xdeadbeef00000000|expected.to_bits()as u64,"{name}");assert!(!t.registers.iter().any(|r|r.register.bank=="x86.vector64"&&r.register.index==1));for i in 2..8{assert_eq!(vector_result(&t,0,i),0);}}
 vector(&mut f.state,0,&[u64::from(2f32.to_bits())*0x100000001;2]);vector(&mut f.state,1,&[u64::from(3f32.to_bits())*0x100000001;2]);vector(&mut f.state,2,&[u64::from(5f32.to_bits())*0x100000001;2]);
 let t=extended_run("vfmaddsub132ps xmm0, xmm1, xmm2",&f);assert_eq!(vector_result(&t,0,0),u64::from(13f32.to_bits())<<32|u64::from(7f32.to_bits()));
}
#[test]fn float_conversions_rounding_and_narrow_destination_zeroes(){
 let mut f=extended_float();f.state.x(0,(-7i64)as u64);vector(&mut f.state,1,&[0x1122334400000000,0xabcdef]);let t=extended_run("vcvtsi2ss xmm0, xmm1, rax",&f);assert_eq!(vector_result(&t,0,0),0x1122334400000000|u64::from((-7f32).to_bits()));assert_eq!(vector_result(&t,0,1),0xabcdef);
 vector(&mut f.state,1,&[(-3.75f64).to_bits(),0]);assert_eq!(x(&extended_run("cvttsd2si rax, xmm1",&f),0),(-3i64)as u64);assert_eq!(x(&extended_run("cvtsd2si rax, xmm1",&f),0),(-4i64)as u64);
 let t=extended_run("cvtsd2ss xmm0, xmm1",&f);assert_eq!(vector_result(&t,0,0)&0xffffffff,u64::from((-3.75f32).to_bits()));
 vector(&mut f.state,1,&[2.5f64.to_bits(),(-4.5f64).to_bits()]);let t=extended_run("cvtpd2ps xmm0, xmm1",&f);assert_eq!(vector_result(&t,0,0),u64::from((-4.5f32).to_bits())<<32|u64::from(2.5f32.to_bits()));assert_eq!(vector_result(&t,0,1),0);
 vector(&mut f.state,1,&[u64::from(2.5f32.to_bits())|u64::from((-2.5f32).to_bits())<<32,0]);
 for (imm,a,b) in [(0,2f32,-2f32),(1,2.,-3.),(2,3.,-2.),(3,2.,-2.)]{let t=extended_run(&format!("roundps xmm0, xmm1, {}",imm|8),&f);assert_eq!(vector_result(&t,0,0),u64::from(a.to_bits())|u64::from(b.to_bits())<<32);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f80);}
 f.state.reg("x86.mxcsr",0,0x3f80);let t=extended_run("roundps xmm0, xmm1, 4",&f);assert_eq!(vector_result(&t,0,0),u64::from(2f32.to_bits())|u64::from((-3f32).to_bits())<<32);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x3fa0);
}
#[test]fn x86_float_comparisons_flags_predicates_and_traps(){
 let mut f=extended_float();vector(&mut f.state,0,&[1f32.to_bits()as u64,0]);vector(&mut f.state,1,&[2f32.to_bits()as u64,0]);let t=extended_run("ucomiss xmm0, xmm1",&f);for (i,v) in [(0,1),(1,0),(2,0),(3,0),(4,0),(5,0)]{assert_eq!(flag(&t,i).bits,v);}
 // Test all 32 AVX predicates against four independently classified relations.
 for (a,b,less,equal,unordered) in [(1f32,2f32,true,false,false),(2.,1.,false,false,false),(1.,1.,false,true,false),(f32::NAN,1.,false,false,true)]{
 vector(&mut f.state,1,&[a.to_bits()as u64,0]);vector(&mut f.state,2,&[b.to_bits()as u64,0]);
 for predicate in 0..32{let truth=match predicate&15{0=>equal,1=>less,2=>less||equal,3=>unordered,4=>!equal,5=>!less,6=>!(less||equal),7=>!unordered,8=>equal||unordered,9=>less||unordered,10=>less||equal||unordered,11=>false,12=>!equal&&!unordered,13=>!less&&!unordered,14=>!less&&!equal&&!unordered,_=>true};let t=extended_run(&format!("vcmpss xmm0, xmm1, xmm2, {predicate}"),&f);assert_eq!(vector_result(&t,0,0)&0xffffffff,if truth{0xffffffff}else{0},"predicate {predicate}, {a:?}, {b:?}");}
 }
 vector(&mut f.state,0,&[0x7fc00000,0]);let t=extended_run("ucomiss xmm0, xmm1",&f);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f80);for i in [0,1,3]{assert_eq!(flag(&t,i).bits,1);}
 f.state.reg("x86.mxcsr",0,0);let t=extended_run("comiss xmm0, xmm1",&f);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,1);assert!(!t.registers.iter().any(|r|r.register.bank=="x86.flags"));
}
#[test]fn minmax_second_source_and_masked_fp_memory(){
 let mut f=extended_float();vector(&mut f.state,0,&[0x7fc00001,0]);vector(&mut f.state,1,&[(-0f32).to_bits()as u64,0]);assert_eq!(vector_result(&extended_run("minss xmm0, xmm1",&f),0,0)&0xffffffff,0x80000000);vector(&mut f.state,0,&[0,0]);assert_eq!(vector_result(&extended_run("maxss xmm0, xmm1",&f),0,0)&0xffffffff,0x80000000);
 f.state.reg("x86.mask",1,0);f.state.x(0,0xdead0000);let enc=assemble_at("vfmadd132ps zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",0x1000).unwrap();let d=decode(enc.first().unwrap().bytes(),Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);let t=s::evaluate(&r,&f).unwrap();assert_eq!(f.loads.get(),0);for i in 0..8{assert_eq!(vector_result(&t,0,i),0);}
}
#[test]fn cmpxchg16b_is_one_pair_atomic_with_exact_failure_outputs(){
 let mut st=AtomicState{state:State::default(),requests:Default::default()};st.state.x(7,0x4000);st.state.x(0,10);st.state.x(2,20);st.state.x(3,30);st.state.x(1,40);st.state.mem.insert(0x4000,10);st.state.mem.insert(0x4008,20);
 let t=atomic_run(&[0xf0,0x48,0x0f,0xc7,0x0f],&st);assert_eq!(st.requests.borrow().len(),1);assert_eq!(t.atomics.len(),1);assert_eq!(t.atomics[0].observation.as_ref().unwrap().witness,99);assert_eq!(t.atomics[0].stored,Some(Value::known(64,30)));assert_eq!(t.atomics[0].stored_high,Some(Value::known(64,40)));assert_eq!(flag(&t,3).bits,1);assert_eq!(x(&t,0),10);assert_eq!(x(&t,2),20);assert!(t.memory.is_empty());
 st.state.mem.insert(0x4008,21);let t=atomic_run(&[0xf0,0x48,0x0f,0xc7,0x0f],&st);assert_eq!(t.atomics[0].stored,None);assert_eq!(t.atomics[0].stored_high,None);assert_eq!(flag(&t,3).bits,0);assert_eq!(x(&t,0),10);assert_eq!(x(&t,2),21);
}

#[test]fn evex_float_mask_conversion_and_segment_memory_contract(){
 let mut f=extended_float();vector(&mut f.state,1,&[u64::from(1f32.to_bits())|u64::from(3f32.to_bits())<<32;8]);vector(&mut f.state,2,&[u64::from(2f32.to_bits())|u64::from(2f32.to_bits())<<32;8]);f.state.reg("x86.mask",1,5);
 let t=extended_run("vcmpps k2 {k1}, zmm1, zmm2, 1",&f);assert_eq!(reg(&t,"x86.mask",2).bits,5);
 f.state.x(0,7);let t=extended_run("vcvtusi2ss xmm0, xmm1, rax",&f);assert_eq!(vector_result(&t,0,0)&0xffffffff,u64::from(7f32.to_bits()));
 vector(&mut f.state,1,&[u64::from(7.75f32.to_bits()),0]);let t=extended_run("vcvttss2usi rax, xmm1",&f);assert_eq!(x(&t,0),7);
 let t=extended_run("vrndscaleps zmm0, zmm1, 8",&f);assert_eq!(vector_result(&t,0,0)&0xffffffff,u64::from(8f32.to_bits()));
 let t=extended_run("vrndscaleps zmm0, zmm1, 24",&f);assert_eq!(vector_result(&t,0,0)&0xffffffff,u64::from(8f32.to_bits()));
 // Segment selectors stay at the memory boundary, rather than becoming
 // scalar temporary reads that consumers could mistake for stored GPRs.
 for (bytes,mode) in [(&[0x64,0x48,0x89,0x08][..],Mode::Mode64),(&[0x89,0x08][..],Mode::Mode32)]{let d=decode(bytes,mode).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);let m=r.effects.iter().find_map(|e|if let s::Effect::Store{memory,..}=e{Some(memory)}else{None}).unwrap();assert!(matches!(&m.address.kind,s::ExprKind::Binary{op:s::BinaryOp::Add,right,..} if matches!(&right.kind,s::ExprKind::Register(slice) if slice.register.bank=="x86.segment_base")));}
}

#[test]fn focused_float_reference_rejects_unimplemented_contracts(){
 let enc=assemble_at("vfmadd132ss xmm0, xmm1, xmm2",0).unwrap();let d=decode(enc.first().unwrap().bytes(),Mode::Mode64).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);
 let mut f=extended_float();vector(&mut f.state,0,&[0.25f32.to_bits()as u64,0]);assert_eq!(s::evaluate(&r,&f),Err(EvalError::Unsupported));
 let f=FloatState{state:f.state,calls:Default::default(),loads:Default::default()};assert_eq!(s::evaluate(&r,&f),Err(EvalError::Unsupported));
}
fn set128(st:&mut State,n:u16,value:u128){vector(st,n,&[value as u64,(value>>64)as u64]);}
fn result128(t:&Transition,n:u16)->u128{u128::from(vector_result(t,n,0))|u128::from(vector_result(t,n,1))<<64}
#[test]fn aes_rounds_key_schedule_and_lane_boundaries(){
 let mut st=State::default();let state=0x7b5b54657374566563746f725d53475du128;let key=0x48692853686179295b477565726f6e5du128;set128(&mut st,0,state);set128(&mut st,1,key);
 for (opcode,expected) in [(0xdc,0xa8311c2f9fdba3c58b104b58ded7e595u128),(0xdd,0xc7fb881e938c5964177ec42553fdc611),(0xde,0x138ac342faea2787b58eb95eb730392a),(0xdf,0xc5a391ef6b317f95d410637b72a593d0)]{let t=run(&[0x66,0x0f,0x38,opcode,0xc1],&st);assert_eq!(result128(&t,0),expected);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"&&x.register.index>=2));}
 set128(&mut st,1,state);assert_eq!(result128(&asm_run("aesimc xmm0, xmm1",&st),0),0x627a6f6644b109c82b18330a81c3b3e5);
 set128(&mut st,1,0x3c4fcf098815f7aba6d2ae2816157e2b);assert_eq!(result128(&asm_run("aeskeygenassist xmm0, xmm1, 1",&st),0),0x01eb848beb848a013424b5e524b5e434);
 vector(&mut st,1,&[state as u64,(state>>64)as u64,state as u64,(state>>64)as u64]);vector(&mut st,2,&[key as u64,(key>>64)as u64,key as u64,(key>>64)as u64]);let t=asm_run("vaesenc ymm0, ymm1, ymm2",&st);for base in [0,2]{assert_eq!(u128::from(vector_result(&t,0,base))|u128::from(vector_result(&t,0,base+1))<<64,0xa8311c2f9fdba3c58b104b58ded7e595);}for i in 4..8{assert_eq!(vector_result(&t,0,i),0);}
}
fn reference_gfmul(mut a:u8,mut b:u8)->u8{let mut v=0;while b!=0{if b&1!=0{v^=a;}a=(a<<1)^if a&128!=0{0x1b}else{0};b>>=1;}v}
fn reference_affine(matrix:u64,a:u8,constant:u8)->u8{let rows=matrix.to_le_bytes();let mut v=constant;for i in 0..8{v^=(((rows[7-i]&a).count_ones()&1)as u8)<<i;}v}
#[test]fn carryless_and_gfni_match_independent_polynomial_reference(){
 let mut st=State::default();let a=0x7b5b54657374566563746f725d53475du128;let b=0x48692853686179295b477565726f6e5du128;set128(&mut st,0,a);set128(&mut st,1,b);
 for imm in [0,1,16,17,0xff]{let left=(a>>(64*(imm&1)))as u64;let right=(b>>(64*(imm>>4&1)))as u64;let mut product=0u128;for i in 0..64{if right>>i&1!=0{product^=u128::from(left)<<i;}}let t=asm_run(&format!("pclmulqdq xmm0, xmm1, {imm}"),&st);assert_eq!(result128(&t,0),product);}
 let bytes_a=a.to_le_bytes();let bytes_b=b.to_le_bytes();let expected=u128::from_le_bytes(std::array::from_fn(|i|reference_gfmul(bytes_a[i],bytes_b[i])));assert_eq!(result128(&asm_run("gf2p8mulb xmm0, xmm1",&st),0),expected);
 for inverse in [false,true]{for constant in [0,0x63,0xa5]{let expected=u128::from_le_bytes(std::array::from_fn(|i|{let byte=if inverse{(1u16..256).find(|&x|reference_gfmul(bytes_a[i],x as u8)==1).unwrap_or(0)as u8}else{bytes_a[i]};reference_affine((b>>(64*(i/8)))as u64,byte,constant)}));let name=if inverse{"gf2p8affineinvqb"}else{"gf2p8affineqb"};assert_eq!(result128(&asm_run(&format!("{name} xmm0, xmm1, {constant}"),&st),0),expected);}}
 st.reg("x86.mask",1,0x5555);vector(&mut st,1,&[0x5353535353535353;8]);vector(&mut st,2,&[0xf1e3c78f1f3e7cf8;8]);let t=asm_run("vgf2p8affineinvqb zmm0 {k1}{z}, zmm1, zmm2, 99",&st);for i in 0..2{assert_eq!(vector_result(&t,0,i),0x00ed00ed00ed00ed);}for i in 2..8{assert_eq!(vector_result(&t,0,i),0);}
}
fn dwords(values:[u32;4])->u128{u128::from(values[0])|u128::from(values[1])<<32|u128::from(values[2])<<64|u128::from(values[3])<<96}
fn sigma0(x:u32)->u32{x.rotate_right(7)^x.rotate_right(18)^(x>>3)}
fn sigma1(x:u32)->u32{x.rotate_right(17)^x.rotate_right(19)^(x>>10)}
#[test]fn sha_message_schedule_and_round_state_match_reference(){
 let mut st=State::default();let a=[0x01234567u32,0x89abcdef,0xfedcba98,0x76543210];let b=[0xaabbccddu32,0x11223344,0x55667788,0x99aabbcc];set128(&mut st,1,dwords(a));set128(&mut st,2,dwords(b));
 for (name,expected) in [("sha1msg1",[a[0]^b[2],a[1]^b[3],a[2]^a[0],a[3]^a[1]]),("sha1nexte",[b[0],b[1],b[2],b[3].wrapping_add(a[3].rotate_left(30))]),("sha256msg1",[a[0].wrapping_add(sigma0(a[1])),a[1].wrapping_add(sigma0(a[2])),a[2].wrapping_add(sigma0(a[3])),a[3].wrapping_add(sigma0(b[0]))])]{let t=asm_run(&format!("{name} xmm1, xmm2"),&st);assert_eq!(result128(&t,1),dwords(expected),"{name}");}
 let mut x=[0u32;4];for i in 0..4{x[3-i]=(a[3-i]^if i<3{b[2-i]}else{x[3]}).rotate_left(1);}assert_eq!(result128(&asm_run("sha1msg2 xmm1, xmm2",&st),1),dwords(x));
 for i in 0..4{x[i]=a[i].wrapping_add(sigma1(if i<2{b[i+2]}else{x[i-2]}));}assert_eq!(result128(&asm_run("sha256msg2 xmm1, xmm2",&st),1),dwords(x));
 for selector in 0..4{let(mut av,mut bv,mut cv,mut dv,mut ev)=(a[3],a[2],a[1],a[0],0u32);for i in 0..4{let f=match selector{0=>(bv&cv)^(!bv&dv),2=>(bv&cv)^(bv&dv)^(cv&dv),_=>bv^cv^dv};let next=av.rotate_left(5).wrapping_add(f).wrapping_add(ev).wrapping_add(b[3-i]).wrapping_add([0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6][selector]);ev=dv;dv=cv;cv=bv.rotate_left(30);bv=av;av=next;}assert_eq!(result128(&asm_run(&format!("sha1rnds4 xmm1, xmm2, {selector}"),&st),1),dwords([dv,cv,bv,av]));}
 let wk=[0x31415926u32,0x27182818];set128(&mut st,0,dwords([wk[0],wk[1],0,0]));let mut state=[b[3],b[2],a[3],a[2],b[1],b[0],a[1],a[0]];for word in wk {let [av,bv,cv,dv,ev,fv,gv,hv]=state;let t1=hv.wrapping_add(ev.rotate_right(6)^ev.rotate_right(11)^ev.rotate_right(25)).wrapping_add((ev&fv)^(!ev&gv)).wrapping_add(word);let t2=(av.rotate_right(2)^av.rotate_right(13)^av.rotate_right(22)).wrapping_add((av&bv)^(av&cv)^(bv&cv));state=[t1.wrapping_add(t2),av,bv,cv,dv.wrapping_add(t1),ev,fv,gv];}assert_eq!(result128(&asm_run("sha256rnds2 xmm1, xmm2",&st),1),dwords([state[5],state[4],state[1],state[0]]));
}
#[test]fn vector_permutation_truth_tables_masks_and_dense_positions(){
 let mut st=State::default();vector(&mut st,1,&[0x0000000200000003,0x0000000000000001,0x0000000600000007,0x0000000400000005]);vector(&mut st,2,&[0x0000000b0000000a,0x0000000d0000000c,0x0000000f0000000e,0x0000001100000010]);let t=asm_run("vpermd ymm0, ymm1, ymm2",&st);assert_eq!(vector_result(&t,0,0),0x0000000c0000000d);assert_eq!(vector_result(&t,0,3),0x0000000e0000000f);
 let t=asm_run("vpermq ymm0, ymm2, 27",&st);for i in 0..4{assert_eq!(vector_result(&t,0,i),[0x0000001100000010,0x0000000f0000000e,0x0000000d0000000c,0x0000000b0000000a][i as usize]);}
 vector(&mut st,0,&[0x5555555555555555;8]);vector(&mut st,1,&[0x3333333333333333;8]);vector(&mut st,2,&[0x0f0f0f0f0f0f0f0f;8]);let t=asm_run("vpternlogq zmm0, zmm1, zmm2, 150",&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0x6969696969696969);}
 vector(&mut st,1,&[0x0000000200000001,0x0000000400000003,0x0000000600000005,0x0000000800000007]);

 st.reg("x86.mask",1,0x55);let t=asm_run("vpcompressd ymm0 {k1}{z}, ymm1",&st);assert_eq!(vector_result(&t,0,0),0x0000000300000001);assert_eq!(vector_result(&t,0,1),0x0000000700000005);assert_eq!(vector_result(&t,0,2),0);assert_eq!(vector_result(&t,0,3),0);
 let t=asm_run("vpexpandd ymm0 {k1}{z}, ymm1",&st);for(i,v)in [1u64,2,3,4].into_iter().enumerate(){assert_eq!(vector_result(&t,0,i as u16),v);}
 vector(&mut st,1,&[0x0001020304050607;8]);vector(&mut st,2,&[0x0123456789abcdef;8]);let t=asm_run("vpmultishiftqb zmm0, zmm1, zmm2",&st);let controls=0x0001020304050607u64.to_le_bytes();let expected=u64::from_le_bytes(std::array::from_fn(|i|0x0123456789abcdefu64.rotate_right(u32::from(controls[i]&63))as u8));for i in 0..8{assert_eq!(vector_result(&t,0,i),expected);}
 let t=asm_run("vpshufbitqmb k2, zmm2, zmm1",&st);let mut expected=0u64;for i in 0..64{expected|=(0x0123456789abcdefu64>>(controls[i%8]&63)&1)<<i;}assert_eq!(reg(&t,"x86.mask",2).bits,expected);
 vector(&mut st,0,&[0x1111111111111111;8]);vector(&mut st,1,&[0x2222222222222222;8]);vector(&mut st,2,&[0x3333333333333333;8]);let t=asm_run("vpermi2d zmm0, zmm1, zmm2",&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0x3333333333333333);}
 let t=asm_run("vpermt2d zmm0, zmm1, zmm2",&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0x1111111111111111);}
 let t=asm_run("vperm2i128 ymm0, ymm1, ymm2, 129",&st);assert_eq!(vector_result(&t,0,0),0x2222222222222222);assert_eq!(vector_result(&t,0,1),0x2222222222222222);assert_eq!(vector_result(&t,0,2),0);assert_eq!(vector_result(&t,0,3),0);
}
#[test]fn mask_storage_logic_shifts_unpack_and_tests(){
 let mut st=State::default();st.reg("x86.mask",1,0xa55a);st.reg("x86.mask",2,0x3c3c);for(name,expected)in [("kandw",0xa55a&0x3c3c),("kandnw",!0xa55au64&0x3c3c),("korw",0xa55a|0x3c3c),("kxorw",0xa55a^0x3c3c),("kxnorw",!(0xa55au64^0x3c3c)&65535),("kaddw",(0xa55a+0x3c3c)&65535)]{assert_eq!(reg(&asm_run(&format!("{name} k0, k1, k2"),&st),"x86.mask",0).bits,expected);}
 assert_eq!(reg(&run(&[0xc5,0xf8,0x44,0xc1],&st),"x86.mask",0).bits,!0xa55au64&65535);assert_eq!(reg(&asm_run("kshiftlw k0, k1, 16",&st),"x86.mask",0).bits,0);assert_eq!(reg(&asm_run("kshiftrw k0, k1, 3",&st),"x86.mask",0).bits,0xa55a>>3);
 assert_eq!(reg(&asm_run("kunpckbw k0, k1, k2",&st),"x86.mask",0).bits,0x5a3c);assert_eq!(x(&asm_run("kmovb eax, k1",&st),0),0x5a);
 st.x(0,0x123456789abcdef0);assert_eq!(reg(&asm_run("kmovq k0, rax",&st),"x86.mask",0).bits,0x123456789abcdef0);
 let t=asm_run("ktestw k1, k2",&st);assert_eq!(flag(&t,3).bits,0);assert_eq!(flag(&t,0).bits,0);for i in [1,2,4,5]{assert_eq!(flag(&t,i).bits,0);}
 st.reg("x86.mask",2,0x5aa5);let t=run(&[0xc5,0xf8,0x98,0xca],&st);assert_eq!(flag(&t,0).bits,1);assert_eq!(flag(&t,3).bits,0);
}
struct WideState{state:State,wide_reads:std::cell::Cell<usize>,scalar_reads:std::cell::Cell<usize>}
impl Machine for WideState{
 fn read_register(&self,r:s::Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.scalar_reads.set(self.scalar_reads.get()+1);self.state.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.wide_reads.set(self.wide_reads.get()+1);assert_eq!(w,128);(0..w/64).map(|i|self.state.read_memory(a+u64::from(i)*8,64,e)).collect()}
}
#[test]fn crypto_native_access_and_masked_expand_load_boundaries(){
 let mut st=WideState{state:State::default(),wide_reads:Default::default(),scalar_reads:Default::default()};st.state.x(0,0x4000);st.state.mem.insert(0x4000,0);st.state.mem.insert(0x4008,0);let d=decode(&[0x66,0x0f,0x38,0xdc,0x00],Mode::Mode64).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);let t=s::evaluate(&r,&st).unwrap();assert_eq!(result128(&t,0),0x63636363636363636363636363636363);assert_eq!(st.wide_reads.get(),1);assert_eq!(st.scalar_reads.get(),0);
 st.state.reg("x86.mask",1,0);st.state.x(0,0xdead0000);let enc=assemble_at("vpexpandd ymm0 {k1}{z}, ymmword ptr [rax]",0).unwrap();let d=decode(enc.first().unwrap().bytes(),Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(st.scalar_reads.get(),0);for i in 0..8{assert_eq!(vector_result(&t,0,i),0);}
 st.state.x(0,0x5000);st.state.mem.insert(0x5000,11);st.state.mem.insert(0x5004,22);st.state.reg("x86.mask",1,0x11);let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(st.scalar_reads.get(),2);assert_eq!(vector_result(&t,0,0),11);assert_eq!(vector_result(&t,0,2),22);
 for text in ["vpcompressd ymmword ptr [rax] {k1}, ymm1","vgf2p8mulb zmm0 {k1}, zmm1, zmmword ptr [rax]"]{let enc=assemble_at(text,0).unwrap();let d=decode(enc.first().unwrap().bytes(),Mode::Mode64).unwrap();assert_eq!(d.semantic_recipe(0).support,Support::Full,"{text}");}
}

#[test]fn vector_broadcast_prefix_is_physically_qualified(){let d=decode(&[0x62,0xf2,0x75,0x59,0x36,0x00],Mode::Mode64).unwrap();assert_eq!(d.encoding().mnemonic,"VPERMD");assert_eq!(d.semantic_recipe(0).support,Support::Full);}

#[test]fn mask_widths_bound_shifts_and_zero_parent_bits(){
 let mut st=State::default();st.reg("x86.mask",1,0x8123456789abcdef);st.reg("x86.mask",2,0xff00ff00ff00ff00);
 for (suffix,width) in [("b",8),("w",16),("d",32),("q",64)]{let mask=if width==64{u64::MAX}else{(1u64<<width)-1};let t=asm_run(&format!("kand{suffix} k0, k1, k2"),&st);assert_eq!(reg(&t,"x86.mask",0).bits,0x8123456789abcdef&0xff00ff00ff00ff00&mask);let t=asm_run(&format!("kshiftl{suffix} k0, k1, {width}"),&st);assert_eq!(reg(&t,"x86.mask",0).bits,0);}
 assert_eq!(reg(&asm_run("kunpckwd k0, k1, k2",&st),"x86.mask",0).bits,0xcdefff00);assert_eq!(reg(&asm_run("kunpckdq k0, k1, k2",&st),"x86.mask",0).bits,0x89abcdefff00ff00);
}

#[test]fn permil_register_controls_and_immediates_stay_within_128bit_lanes(){
 let mut st=State::default();vector(&mut st,1,&[0x0000000b0000000a,0x0000000d0000000c,0x0000000f0000000e,0x0000001100000010]);vector(&mut st,2,&[0x0000000200000003,0x0000000000000001,0x0000000200000003,0x0000000000000001]);
 for text in ["vpermilps ymm0, ymm1, ymm2","vpermilps ymm0, ymm1, 27"]{let t=asm_run(text,&st);for(i,v)in [0x0000000c0000000du64,0x0000000a0000000b,0x0000001000000011,0x0000000e0000000f].into_iter().enumerate(){assert_eq!(vector_result(&t,0,i as u16),v,"{text}");}}
 vector(&mut st,2,&[2,0,2,0]);let t=asm_run("vpermilpd ymm0, ymm1, ymm2",&st);for(i,v)in [0x0000000d0000000cu64,0x0000000b0000000a,0x0000001100000010,0x0000000f0000000e].into_iter().enumerate(){assert_eq!(vector_result(&t,0,i as u16),v);}
}
`

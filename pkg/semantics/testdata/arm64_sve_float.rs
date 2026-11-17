#[allow(dead_code)] #[path="semantics.rs"] mod semantics;
use semantics::*;
use std::{collections::HashMap,cell::RefCell};
fn recipe(word:u32,vl:u16)->Option<Recipe>{semantics::arm64_sve_float_matrix::a64(word,0x1000,vl).or_else(||semantics::arm64_sve::a64(word,0x1000,Endian::Little,vl))}
#[derive(Default)]
struct State { registers:HashMap<Register,u64>, trace:RefCell<Vec<(FloatOperation,Vec<u64>,u64)>>, forbidden:Option<u16> }
impl State {
 fn set(&mut self,bank:&'static str,index:u16,value:u64){self.registers.insert(Register{bank,index},value);}
 fn lane(&mut self,n:u16,e:u16,w:u8,value:u64){let bit=e*w as u16;let index=n*32+bit/64;let old=*self.registers.get(&Register{bank:"a64.vector64",index}).unwrap_or(&0);let mask=if w==64{u64::MAX}else{(1u64<<w)-1};self.set("a64.vector64",index,(old&!(mask<<(bit%64)))|((value&mask)<<(bit%64)));}
 fn pred(&mut self,n:u16,e:u16,w:u8){let bit=e*(w as u16/8);let index=n*4+bit/64;let old=*self.registers.get(&Register{bank:"a64.predicate64",index}).unwrap_or(&0);self.set("a64.predicate64",index,old|(1<<(bit%64)));}
 fn all(&mut self,n:u16,w:u8,vl:u16){for e in 0..vl/w as u16{self.pred(n,e,w);}}
 fn trace(&self)->Vec<(FloatOperation,Vec<u64>,u64)>{self.trace.borrow().clone()}
}
fn number(bits:u64,w:u8)->f64{match w{16=>{let sign=if bits&0x8000!=0{-1.0}else{1.0};let e=(bits>>10)&31;let f=bits&1023;if e==31 {if f==0{sign*f64::INFINITY}else{f64::NAN}}else if e==0{sign*(f as f64)*2f64.powi(-24)}else{sign*(1.0+f as f64/1024.0)*2f64.powi(e as i32-15)}},32=>f32::from_bits(bits as u32)as f64,64=>f64::from_bits(bits),_=>panic!("unsupported reference format")}}
fn encode(n:f64,w:u8)->u64{match w{32=>(n as f32).to_bits()as u64,64=>n.to_bits(),16=>{let sign=(n.is_sign_negative()as u64)<<15;if n.is_nan(){return sign|0x7e00;}if n.is_infinite(){return sign|0x7c00;}if n==0.0{return sign;}let e=n.abs().log2().floor()as i32;assert!((-14..=15).contains(&e),"reference half normal only");let f=(n.abs()/2f64.powi(e)-1.0)*1024.0;assert_eq!(f.fract(),0.0,"reference half must be exact");sign|((e+15)as u64)<<10|f as u64},_=>panic!("reference format")}}
fn signaling(bits:u64,w:u8)->bool{let(e,f,q)=match w{16=>(0x7c00,0x3ff,0x200),32=>(0x7f800000,0x7fffff,0x400000),64=>(0x7ff0000000000000,0xfffffffffffff,0x8000000000000),_=>panic!("reference format")};bits&e==e&&bits&f!=0&&bits&q==0}
fn rounding(n:f64,r:FloatRounding,c:u64)->f64{match r{FloatRounding::Environment=>rounding(n,match(c>>22)&3{0=>FloatRounding::NearestEven,1=>FloatRounding::PositiveInfinity,2=>FloatRounding::NegativeInfinity,_=>FloatRounding::Zero},0),FloatRounding::NearestEven=>n.round_ties_even(),FloatRounding::PositiveInfinity=>n.ceil(),FloatRounding::NegativeInfinity=>n.floor(),FloatRounding::Zero=>n.trunc(),FloatRounding::NearestAway=>n.round()}}
impl Machine for State {
 fn read_register(&self,r:Register)->Value{if r.bank=="a64.vector64"{assert_ne!(self.forbidden,Some(r.index/32),"inactive source was read");}Value::known(if matches!(r.bank,"a64.fpcr"|"a64.fpsr"){32}else if matches!(r.bank,"a64.sme_fa64"|"a64.ssve_fexpa"){1}else{64},*self.registers.get(&r).unwrap_or(&0))}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("FP lane recipe accessed memory")}
 // This bounded reference checks finite exact arithmetic/transport, basic NaN
 // comparison and exception sequencing. Production software FP owns general
 // rounding, denormal/NaN payload and enhanced FPCR domains.
 fn evaluate_float(&self,f:&FloatExpression,input:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.environment,FloatEnvironment::A64);assert_eq!(control.bits&((1<<26)|3),0,"reference enhanced FP controls unsupported");
  if f.projection==FloatProjection::Value{self.trace.borrow_mut().push((f.operation,input.iter().map(|x|x.bits).collect(),status.bits));}
  let sw=match f.operation{FloatOperation::Compare{source_width,..}|FloatOperation::Convert{source_width,..}|FloatOperation::ToInteger{source_width,..}|FloatOperation::FromInteger{source_width,..}=>source_width,_=>f.width};
  let a=number(input[0].bits,sw);let b=input.get(1).map_or(0.0,|v|number(v.bits,sw));let mut flags=0;
  let bits=match f.operation{
   FloatOperation::Compare{signal_all_nans,..}=>{let nan=a.is_nan()||b.is_nan();if nan&&(signal_all_nans||input.iter().any(|v|signaling(v.bits,sw))){flags|=1;}if nan{3}else if a==b{6}else if a<b{8}else{2}},
   FloatOperation::ToInteger{signed,fractional_bits,rounding:r,..}=>{assert_eq!(fractional_bits,0);let n=rounding(a,r,control.bits);assert!(n.is_finite()&&n.abs()<1048576.0,"bounded reference integer range");if n!=a{flags|=16;}if signed{n as i64 as u64}else{assert!(n>=0.0);n as u64}},
   FloatOperation::ReciprocalEstimate|FloatOperation::ReciprocalSquareRootEstimate=>{
    let fbits=match sw{16=>10,32=>23,_=>52};let ebits=sw-fbits-1;let exp=(input[0].bits>>fbits)&((1u64<<ebits)-1);let frac=input[0].bits&((1u64<<fbits)-1);assert!(a>0.0&&a.is_finite()&&exp>0,"bounded normal estimate reference");
    let(rsqrt,base)=if f.operation==FloatOperation::ReciprocalEstimate{(false,match sw{16=>29,32=>253,_=>2045})}else{(true,match sw{16=>44,32=>380,_=>3068})};
    let estimate=if !rsqrt{let scaled=256+(frac>>(fbits-8));((1u64<<19)/(scaled*2+1)+1)/2}else{let scaled=if exp&1==0{256+(frac>>(fbits-8))}else{128+(frac>>(fbits-7))};let scaled=if scaled<256{scaled*2+1}else{((scaled>>1)<<1)+1<<1};let mut v=512;while scaled*(v+1)*(v+1)<1<<28{v+=1;}(v+1)/2};
    let result_exp=if rsqrt{(base-exp)/2}else{base-exp};assert!(result_exp>0&&result_exp<(1<<ebits)-1);(result_exp<<fbits)|((estimate&255)<<(fbits-8))
   },
   FloatOperation::ReciprocalExponent=>{assert!(a.is_finite()&&a!=0.0);let fbits=match sw{16=>10,32=>23,_=>52};let expmask=((1u64<<(sw-fbits-1))-1)<<fbits;(input[0].bits&(1u64<<(sw-1)))|((!input[0].bits)&expmask)},
   FloatOperation::ToBFloat16=>{assert_eq!(input[0].bits&0xffff,0,"bounded exact BF16 conversion");input[0].bits>>16},
   FloatOperation::FromInteger{signed,fractional_bits,..}=>{assert_eq!(fractional_bits,0);let n=if signed{let sh=64-sw;((input[0].bits<<sh)as i64>>sh)as f64}else{input[0].bits as f64};encode(n,f.width)},
   _=>{let n=match f.operation{
    FloatOperation::Add=>a+b,FloatOperation::Subtract=>a-b,FloatOperation::Multiply=>a*b,
    FloatOperation::Divide=>{if b==0.0{flags|=if a==0.0{1}else{2};}a/b},
    FloatOperation::SquareRoot=>{if a<0.0{flags|=1;}a.sqrt()},
    FloatOperation::FusedMultiplyAdd{negate_product,negate_addend}=>{let add=if negate_addend{-a}else{a};let mul=if negate_product{-b}else{b};mul.mul_add(number(input[2].bits,sw),add)},
    FloatOperation::ReciprocalStep=>(-a).mul_add(b,2.0),
    FloatOperation::ReciprocalSquareRootStep=>(-a).mul_add(b,3.0)*0.5,
    FloatOperation::MultiplyExtended=>if(a.is_infinite()&&b==0.0)||(b.is_infinite()&&a==0.0){if a.is_sign_negative()^b.is_sign_negative(){-2.0}else{2.0}}else{a*b},
    FloatOperation::MinMax{minimum,numeric}=>{if signaling(input[0].bits,sw)||signaling(input[1].bits,sw){flags|=1;}if !numeric&&(a.is_nan()||b.is_nan()){f64::NAN}else if minimum{a.min(b)}else{a.max(b)}},
    FloatOperation::Convert{round_to_odd:false,..}=>a,
    FloatOperation::RoundToIntegral{rounding:r,exact}=>{let n=rounding(a,r,control.bits);if exact&&n!=a{flags|=16;}n},
    _=>return Err(EvalError::Unsupported)
   };encode(n,f.width)}
  };
  let trapped=flags&((control.bits>>8)&31)!=0;
  Ok(match f.projection{FloatProjection::Value=>Value::known(f.width,bits),FloatProjection::Status=>Value::known(32,status.bits|flags),FloatProjection::Trapped=>Value::known(1,trapped as u64)})
 }
}
fn run(word:u32,vl:u16,s:&State)->Transition{let r=recipe(word,vl).unwrap_or_else(||panic!("unhandled {word:08x} VL{vl}"));assert_eq!(r.support,Support::Full);r.validate().unwrap();let t=evaluate(&r,s).unwrap_or_else(|e|panic!("{word:08x}: {e:?}"));assert_eq!(t.next_pc.bits,0x1004);assert!(t.memory.is_empty()&&t.wide_memory.is_empty()&&t.atomics.is_empty());t}
fn reg(t:&Transition,bank:&str,index:u16)->u64{t.registers.iter().find(|w|w.register.bank==bank&&w.register.index==index).unwrap_or_else(||panic!("missing {bank}/{index}")).value.bits}
fn output(t:&Transition,n:u16,e:u16,w:u8)->u64{let bit=e*w as u16;let bits=reg(t,"a64.vector64",n*32+bit/64);(bits>>(bit%64))&if w==64{u64::MAX}else{(1u64<<w)-1}}
fn word(base:u32,w:u8,d:u32,n:u32,m:u32)->u32{base|((w.trailing_zeros()-3)<<22)|(m<<16)|(n<<5)|d}
#[test]fn predicated_arithmetic_all_vl_alias_merge_and_source_suppression(){
 for vl in [128,256,512,1024,2048]{for w in [16,32,64]{for(base,expected)in[(0x65008000,10.0),(0x65018000,6.0),(0x65038000,-6.0),(0x65028000,16.0),(0x650d8000,4.0),(0x650c8000,0.25),(0x650a8000,16.0),(0x65048000,8.0),(0x65058000,2.0),(0x65068000,8.0),(0x65078000,2.0)]{
  let mut s=State::default();s.set("a64.fpsr",0,1<<27);for e in 0..vl/w as u16{s.lane(0,e,w,encode(8.0,w));s.lane(1,e,w,encode(2.0,w));if e%2==0{s.pred(0,e,w);}}
  let t=run(word(base,w,0,1,0),vl,&s);for e in 0..vl/w as u16{assert_eq!(output(&t,0,e,w),encode(if e%2==0{expected}else{8.0},w));}assert_eq!(reg(&t,"a64.fpsr",0),1<<27);assert_eq!(s.trace().len(),(vl/w as u16/2)as usize);
 }}}
 let mut s=State::default();s.forbidden=Some(1);s.lane(0,0,32,0x7f800001);let t=run(word(0x65008000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),0x7f800001);assert!(s.trace().is_empty());
 let mut s=State::default();s.all(0,32,128);for e in 0..4{s.lane(0,e,32,encode(3.0,32));}let t=run(word(0x65008000,32,0,0,0),128,&s);for e in 0..4{assert_eq!(output(&t,0,e,32),encode(6.0,32));}
}
#[test]fn cumulative_status_late_lane_trap_and_no_later_evaluation(){
 let mut s=State::default();s.all(0,32,128);s.set("a64.fpsr",0,1<<27);s.set("a64.fpcr",0,1<<8);for(e,a,b)in[(0,1.0,0.0),(1,0.0,0.0),(2,4.0,2.0),(3,8.0,2.0)]{s.lane(0,e,32,encode(a,32));s.lane(1,e,32,encode(b,32));}
 let t=run(word(0x650d8000,32,0,1,0),128,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(reg(&t,"a64.fpsr",0),(1<<27)|3);assert!(t.registers.iter().all(|w|w.register.bank=="a64.fpsr"));let trace=s.trace();assert_eq!(trace.len(),2);assert_eq!(trace[0].2,1<<27);assert_eq!(trace[1].2,(1<<27)|2);
 s.set("a64.fpcr",0,0);s.trace.borrow_mut().clear();let t=run(word(0x650d8000,32,0,1,0),128,&s);assert_eq!(t.trap,None);assert_eq!(reg(&t,"a64.fpsr",0),(1<<27)|3);assert_eq!(output(&t,0,2,32),encode(2.0,32));assert_eq!(s.trace().len(),4);
}
#[test]fn last_vector_chunk_trap_commits_no_destination(){
 let mut s=State::default();s.all(0,32,256);s.set("a64.fpcr",0,1<<8);s.set("a64.fpsr",0,1<<27);
 for e in 0..8{s.lane(0,e,32,encode(if e==7{0.0}else{1.0},32));s.lane(1,e,32,encode(if e==0||e==7{0.0}else{1.0},32));}
 let t=run(word(0x650d8000,32,0,1,0),256,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|r|r.register.bank=="a64.fpsr"));assert_eq!(reg(&t,"a64.fpsr",0),(1<<27)|3);assert_eq!(s.trace().len(),8);assert_eq!(s.trace()[7].2,(1<<27)|2);
}
#[test]fn fused_plain_immediate_and_segment_indexing(){
 for(base,expected)in[(0x65200000,16.0),(0x65202000,4.0),(0x65204000,-16.0),(0x65206000,-4.0)]{let mut s=State::default();s.all(0,32,128);for e in 0..4{s.lane(0,e,32,encode(10.0,32));s.lane(1,e,32,encode(3.0,32));s.lane(2,e,32,encode(2.0,32));}let t=run(word(base,32,0,1,2),128,&s);for e in 0..4{assert_eq!(output(&t,0,e,32),encode(expected,32));}}
 for(base,expected)in[(0x65000000,5.0),(0x65000400,1.0),(0x65000800,6.0)]{let mut s=State::default();for e in 0..4{s.lane(1,e,32,encode(3.0,32));s.lane(2,e,32,encode(2.0,32));}let t=run(word(base,32,1,1,2),128,&s);for e in 0..4{assert_eq!(output(&t,1,e,32),encode(expected,32));}}
 for(base,expected)in[(0x65188000,4.0),(0x65198000,2.0),(0x651a8000,6.0)]{let mut s=State::default();s.all(0,32,128);for e in 0..4{s.lane(0,e,32,encode(3.0,32));}let t=run(word(base,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(expected,32));}
 for(base,w,index)in[(0x64200000,16,7),(0x64202000,16,7),(0x64a00000,32,3),(0x64a02000,32,3),(0x64e00000,64,1),(0x64e02000,64,1)]{let mut s=State::default();let vl=256;for e in 0..vl/w as u16{s.lane(0,e,w,encode(10.0,w));s.lane(1,e,w,encode(3.0,w));s.lane(2,e,w,encode(if e<(128/w as u16){2.0}else{4.0},w));}let indexbits=if w==16{((index&4)<<20)|((index&3)<<19)}else if w==32{index<<19}else{index<<20};let t=run(base|indexbits|(2<<16)|(1<<5),vl,&s);for e in 0..vl/w as u16{let product=if e<128/w as u16{6.0}else{12.0};assert_eq!(output(&t,0,e,w),encode(product+if base&0x2000==0{10.0}else{0.0},w));}}
}
#[test]fn unary_zero_merge_bit_sign_and_rounding(){
 for(base,zero)in[(0x650da000,false),(0x641ba000,true)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(4.0,32));s.lane(0,1,32,0xdeadbeef);let t=run(word(base,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(2.0,32));assert_eq!(output(&t,0,1,32),if zero{0}else{0xdeadbeef});}
 for(base,expected)in[(0x041ca000,0x3fc00000),(0x041da000,0x3fc00000),(0x040ca000,0x3fc00000),(0x040da000,0x3fc00000)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,0xbfc00000);let t=run(word(base,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),expected);assert!(s.trace().is_empty());assert!(!t.registers.iter().any(|v|v.register.bank=="a64.fpsr"));}
 let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,0xff800001);s.set("a64.fpcr",0,2);let t=run(word(0x041ca000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),0xff800001);
 for(base,expected,flags)in[(0x6500a000,2.0,0),(0x6501a000,3.0,0),(0x6502a000,2.0,0),(0x6503a000,2.0,0),(0x6504a000,3.0,0),(0x6506a000,2.0,16),(0x6507a000,2.0,0),(0x64188000,2.0,0),(0x6418a000,3.0,0),(0x6418c000,2.0,0),(0x6418e000,2.0,0),(0x64198000,3.0,0),(0x6419c000,2.0,16),(0x6419e000,2.0,0)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(2.5,32));let t=run(word(base,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(expected,32));assert_eq!(reg(&t,"a64.fpsr",0),flags);}
}
#[test]fn mixed_conversion_stride_extension_and_ahp_override(){
 for(base,src,dst)in[(0x6589a000,16,32),(0x65c9a000,16,64),(0x6588a000,32,16),(0x65cba000,32,64),(0x65c8a000,64,16),(0x65caa000,64,32),(0x649aa000,16,32),(0x64daa000,16,64),(0x649a8000,32,16),(0x64dae000,32,64),(0x64da8000,64,16),(0x64dac000,64,32)]{let stride=src.max(dst);let mut s=State::default();s.pred(0,0,stride);s.set("a64.fpcr",0,1<<26);s.lane(1,0,stride,encode(1.5,src));s.lane(0,1,stride,u64::MAX);let t=run(base|(1<<5),128,&s);assert_eq!(output(&t,0,0,stride),encode(1.5,dst));assert_eq!(output(&t,0,1,stride),if base&0xff000000==0x64000000{0}else{if stride==64{u64::MAX}else{(1u64<<stride)-1}});}
 for(base,src,dst)in[(0x6552a000,16,16),(0x6554a000,32,16),(0x6594a000,32,32),(0x65d0a000,32,64),(0x6556a000,64,16),(0x65d4a000,64,32),(0x65d6a000,64,64)]{let stride=src.max(dst);let mut s=State::default();s.pred(0,0,stride);s.lane(1,0,stride,(-3i64)as u64&if src==64{u64::MAX}else{(1u64<<src)-1});let t=run(base|(1<<5),128,&s);assert_eq!(output(&t,0,0,stride),encode(-3.0,dst));}
 let mut s=State::default();s.pred(0,0,64);s.lane(1,0,64,encode(-2.5,64));let t=run(0x65d8a020,128,&s);assert_eq!(output(&t,0,0,64),(-2i64)as u64);assert_eq!(reg(&t,"a64.fpsr",0),16);
}
#[test]fn comparisons_preserve_nzcv_zero_inactive_and_signal_rules(){
 for(base,expected)in[(0x65006000,0),(0x65006010,1),(0x65004000,0),(0x65004010,0),(0x6500c000,0)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(1.0,32));s.lane(2,0,32,encode(2.0,32));let t=run(word(base,32,1,1,2),128,&s);assert_eq!(reg(&t,"a64.predicate64",4),expected);assert!(!t.registers.iter().any(|v|v.register.bank=="a64.nzcv"));for i in 5..8{assert_eq!(reg(&t,"a64.predicate64",i),0);}}
 for(base,expected)in[(0x65122000,0),(0x65132000,1),(0x65102000,0),(0x65102010,0),(0x65112000,1),(0x65112010,1)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(-1.0,32));let t=run(word(base,32,1,1,0),128,&s);assert_eq!(reg(&t,"a64.predicate64",4),expected);}
 for(base,flags)in[(0x65006000,0),(0x65004000,1)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,0x7fc00001);s.lane(2,0,32,encode(1.0,32));let t=run(word(base,32,1,1,2),128,&s);assert_eq!(reg(&t,"a64.fpsr",0),flags);}
}
#[test]fn tree_reduction_high_first_ordered_accumulation_and_upper_clear(){
 let mut s=State::default();s.all(0,32,256);for(e,value)in[1.0,2.0,4.0,8.0,16.0,32.0,64.0,128.0].into_iter().enumerate(){s.lane(1,e as u16,32,encode(value,32));}let t=run(word(0x65002000,32,0,1,0),256,&s);assert_eq!(output(&t,0,0,32),encode(255.0,32));for chunk in 1..4{assert_eq!(reg(&t,"a64.vector64",chunk),0);}let trace=s.trace();let pairs=trace.iter().map(|v|v.1.iter().map(|x|number(*x,32)).collect::<Vec<_>>()).collect::<Vec<_>>();assert_eq!(pairs,vec![vec![64.0,128.0],vec![16.0,32.0],vec![48.0,192.0],vec![4.0,8.0],vec![1.0,2.0],vec![3.0,12.0],vec![15.0,240.0]]);
 for vl in [128,256,512,1024,2048]{let mut s=State::default();s.lane(0,0,32,encode(10.0,32));s.all(0,32,vl);for e in 0..vl/32{s.lane(1,e,32,encode(1.0,32));}let t=run(word(0x65182000,32,0,1,0),vl,&s);assert_eq!(output(&t,0,0,32),encode(10.0+f64::from(vl/32),32));for chunk in 1..vl/64{assert_eq!(reg(&t,"a64.vector64",chunk),0);}}
 let mut s=State::default();s.lane(0,0,32,0x80000000);s.forbidden=Some(1);let t=run(word(0x65182000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),0x80000000);assert!(s.trace().is_empty());
 for(base,expected)in[(0x65042000,0x7fc00000),(0x65052000,0x7fc00000),(0x65062000,0xff800000),(0x65072000,0x7f800000)]{let s=State::default();let t=run(word(base,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),expected);}
}
#[test]fn exact_dispatch_boundaries_and_context(){
 for vl in [0,64,129,384,640,768,896,1152,1536,1920,2176]{assert!(recipe(word(0x65008000,32,0,1,0),vl).is_none());}
 for word in [0x65008020,0x1e222820,0x4e22d420,0xd503201f]{assert!(semantics::arm64_sve::a64(word,0x1000,Endian::Little,128).is_none(),"overadmitted {word:08x}");}
}

#[test]fn pairwise_fused_destination_multiplicand_reciprocals_and_bfloat(){
 for(base,expected)in[(0x65208000,32.0),(0x6520a000,-8.0),(0x6520c000,-32.0),(0x6520e000,8.0)]{let mut s=State::default();s.all(0,32,128);for e in 0..4{s.lane(0,e,32,encode(10.0,32));s.lane(1,e,32,encode(12.0,32));s.lane(2,e,32,encode(2.0,32));}let t=run(word(base,32,0,1,2),128,&s);assert_eq!(output(&t,0,0,32),encode(expected,32));}
 for(base,expected)in[(0x64108000,[3.0,30.0,7.0,70.0]),(0x64148000,[2.0,20.0,4.0,40.0]),(0x64158000,[1.0,10.0,3.0,30.0]),(0x64168000,[2.0,20.0,4.0,40.0]),(0x64178000,[1.0,10.0,3.0,30.0])]{let mut s=State::default();s.all(0,32,128);for e in 0..4{s.lane(0,e,32,encode(f64::from(e+1),32));s.lane(1,e,32,encode(f64::from((e+1)*10),32));}let t=run(word(base,32,0,1,0),128,&s);for(e,x)in expected.into_iter().enumerate(){assert_eq!(output(&t,0,e as u16,32),encode(x,32));}}
 for w in [16,32,64]{for(base,expected)in[(0x650e3000,match w{16=>0x37fc,32=>0x3eff8000,_=>0x3fdff00000000000}),(0x650f3000,match w{16=>0x37fc,32=>0x3eff8000,_=>0x3fdff00000000000})]{let mut s=State::default();for e in 0..128/w as u16{s.lane(1,e,w,encode(if base==0x650e3000{2.0}else{4.0},w));}let t=run(word(base,w,0,1,0),128,&s);assert_eq!(output(&t,0,0,w),expected);}}
 for(base,expected)in[(0x65001800,1.0),(0x65001c00,1.0)]{let mut s=State::default();for e in 0..4{s.lane(1,e,32,encode(2.0,32));s.lane(2,e,32,encode(0.5,32));}let t=run(word(base,32,0,1,2),128,&s);assert_eq!(output(&t,0,0,32),encode(expected,32));}
 let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(2.0,32));let t=run(word(0x650ca000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(1.0,32));
 for base in [0x658aa000,0x649ac000]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(3.0,32));s.lane(0,1,32,0xdeadbeef);let t=run(base|(1<<5),128,&s);assert_eq!(output(&t,0,0,32),0x4040);assert_eq!(output(&t,0,1,32),if base==0x658aa000{0xdeadbeef}else{0});}
 let mut s=State::default();for e in 0..4{s.lane(0,e,32,encode(10.0,32));s.lane(1,e,32,encode(3.0,32));s.lane(2,e,32,encode(2.0,32));}let t=run(0x64a00400|(2<<16)|(1<<5),128,&s);assert_eq!(output(&t,0,0,32),encode(4.0,32));
}

#[test]fn immediate_variants_absolute_compare_and_nonstreaming_admission(){
 for(base,small,large)in[(0x65188000,3.5,4.0),(0x65198000,2.5,2.0),(0x651a8000,1.5,6.0),(0x651b8000,-2.5,-2.0),(0x651c8000,3.0,3.0),(0x651d8000,0.0,1.0),(0x651e8000,3.0,3.0),(0x651f8000,0.0,1.0)]{for(i,expected)in[(0,small),(1,large)]{let mut s=State::default();s.pred(0,0,32);s.lane(0,0,32,encode(3.0,32));let t=run(word(base,32,0,i,0),128,&s);assert_eq!(output(&t,0,0,32),encode(expected,32));}}
 for(base,expected)in[(0x6500c010,1),(0x6500e010,1)]{let mut s=State::default();s.pred(0,0,32);s.lane(1,0,32,encode(-3.0,32));s.lane(2,0,32,encode(2.0,32));let t=run(word(base,32,1,1,2),128,&s);assert_eq!(reg(&t,"a64.predicate64",4),expected);}
 let mut s=State::default();s.set("a64.svcr",0,1);s.forbidden=Some(1);let r=recipe(word(0x65182000,32,0,1,0),128).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.trace().is_empty());s.set("a64.sme_fa64",0,1);s.lane(0,0,32,encode(2.0,32));let t=run(word(0x65182000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(2.0,32));
}

const EXPECTED_EXP16: &[u64]=&[0x0,0x16,0x2d,0x45,0x5d,0x75,0x8e,0xa8,0xc2,0xdc,0xf8,0x114,0x130,0x14d,0x16b,0x189,0x1a8,0x1c8,0x1e8,0x209,0x22b,0x24e,0x271,0x295,0x2ba,0x2e0,0x306,0x32e,0x356,0x37f,0x3a9,0x3d4];

const EXPECTED_EXP32: &[u64]=&[0x0,0x164d2,0x2cd87,0x43a29,0x5aac3,0x71f62,0x8980f,0xa14d5,0xb95c2,0xd1adf,0xea43a,0x1031dc,0x11c3d3,0x135a2b,0x14f4f0,0x16942d,0x1837f0,0x19e046,0x1b8d3a,0x1d3eda,0x1ef532,0x20b051,0x227043,0x243516,0x25fed7,0x27cd94,0x29a15b,0x2b7a3a,0x2d583f,0x2f3b79,0x3123f6,0x3311c4,0x3504f3,0x36fd92,0x38fbaf,0x3aff5b,0x3d08a4,0x3f179a,0x412c4d,0x4346cd,0x45672a,0x478d75,0x49b9be,0x4bec15,0x4e248c,0x506334,0x52a81e,0x54f35b,0x5744fd,0x599d16,0x5bfbb8,0x5e60f5,0x60ccdf,0x633f89,0x65b907,0x68396a,0x6ac0c7,0x6d4f30,0x6fe4ba,0x728177,0x75257d,0x77d0df,0x7a83b3,0x7d3e0c];

const EXPECTED_EXP64: &[u64]=&[0x0,0x2c9a3e778061,0x59b0d3158574,0x874518759bc8,0xb5586cf9890f,0xe3ec32d3d1a2,0x11301d0125b51,0x1429aaea92de0,0x172b83c7d517b,0x1a35beb6fcb75,0x1d4873168b9aa,0x2063b88628cd6,0x2387a6e756238,0x26b4565e27cdd,0x29e9df51fdee1,0x2d285a6e4030b,0x306fe0a31b715,0x33c08b26416ff,0x371a7373aa9cb,0x3a7db34e59ff7,0x3dea64c123422,0x4160a21f72e2a,0x44e086061892d,0x486a2b5c13cd0,0x4bfdad5362a27,0x4f9b2769d2ca7,0x5342b569d4f82,0x56f4736b527da,0x5ab07dd485429,0x5e76f15ad2148,0x6247eb03a5585,0x6623882552225,0x6a09e667f3bcd,0x6dfb23c651a2f,0x71f75e8ec5f74,0x75feb564267c9,0x7a11473eb0187,0x7e2f336cf4e62,0x82589994cce13,0x868d99b4492ed,0x8ace5422aa0db,0x8f1ae99157736,0x93737b0cdc5e5,0x97d829fde4e50,0x9c49182a3f090,0xa0c667b5de565,0xa5503b23e255d,0xa9e6b5579fdbf,0xae89f995ad3ad,0xb33a2b84f15fb,0xb7f76f2fb5e47,0xbcc1e904bc1d2,0xc199bdd85529c,0xc67f12e57d14b,0xcb720dcef9069,0xd072d4a07897c,0xd5818dcfba487,0xda9e603db3285,0xdfc97337b9b5f,0xe502ee78b3ff6,0xea4afa2a490da,0xefa1bee615a27,0xf50765b6e4540,0xfa7c1819e90d8];

const EXPECTED_TRIG16: &[u64]=&[0x3c00,0xb155,0x2030,0x0,0x0,0x0,0x0,0x0,0x3c00,0xb800,0x293a,0x0,0x0,0x0,0x0,0x0];

const EXPECTED_TRIG32: &[u64]=&[0x3f800000,0xbe2aaaab,0x3c088886,0xb95008b9,0x36369d6d,0x0,0x0,0x0,0x3f800000,0xbf000000,0x3d2aaaa6,0xbab60705,0x37cd37cc,0x0,0x0,0x0];

const EXPECTED_TRIG64: &[u64]=&[0x3ff0000000000000,0xbfc5555555555543,0x3f8111111110f30c,0xbf2a01a019b92fc6,0x3ec71de351f3d22b,0xbe5ae5e2b60f7b91,0x3de5d8408868552f,0x0,0x3ff0000000000000,0xbfe0000000000000,0x3fa5555555555536,0xbf56c16c16c13a0b,0x3efa01a019b1e8d8,0xbe927e4f7282f468,0x3e21ee96d2641b13,0xbda8f76380fbb401];

#[test]fn fexpa_literal_coefficients_all_indices_widths_vl_alias_and_context(){
 for w in[16,32,64]{let expected=match w{16=>EXPECTED_EXP16,32=>EXPECTED_EXP32,_=>EXPECTED_EXP64};let(index_bits,exponent_bits,fraction_bits)=match w{16=>(5,5,10),32=>(6,8,23),_=>(6,11,52)};
  for vl in[128,256,512,1024,2048]{let elements=vl/w as u16;for batch in 0..(expected.len()as u16).div_ceil(elements){let mut s=State::default();s.set("a64.fpsr",0,0x0800009f);let mut values=Vec::new();for e in 0..elements{let index=(e+batch*elements)as usize%expected.len();let exponent=(e as u64*13+17)&((1<<exponent_bits)-1);let input=(!((1u64<<(index_bits+exponent_bits))-1))|(exponent<<index_bits)|index as u64;s.lane(0,e,w,input);values.push((exponent<<fraction_bits)|expected[index]);}let t=run(word(0x0420b800,w,0,0,0),vl,&s);for(e,v)in values.into_iter().enumerate(){assert_eq!(output(&t,0,e as u16,w),v);}assert!(!t.registers.iter().any(|w|w.register.bank=="a64.fpsr"));assert!(s.trace().is_empty());}}
 }
 let mut s=State::default();s.set("a64.svcr",0,1);s.forbidden=Some(0);let r=recipe(word(0x0420b800,32,0,0,0),128).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));s.forbidden=None;s.set("a64.ssve_fexpa",0,1);assert!(evaluate(&r,&s).is_ok());s.set("a64.ssve_fexpa",0,0);s.set("a64.sme_fa64",0,1);assert!(evaluate(&r,&s).is_ok());
}
#[test]fn ftmad_exact_coefficients_sign_index_fused_operands_and_context(){
 for w in[16,32,64]{let expected=match w{16=>EXPECTED_TRIG16,32=>EXPECTED_TRIG32,_=>EXPECTED_TRIG64};for index in 0..16{let mut s=State::default();for e in 0..128/w as u16{s.lane(0,e,w,encode(0.0,w));s.lane(1,e,w,encode(if index>=8{-2.0}else{2.0},w));}let instruction=word(0x65108000,w,0,1,(index&7)as u32);let t=run(instruction,128,&s);assert_eq!(output(&t,0,0,w),expected[index]);let calls=s.trace();assert_eq!(calls[0].1,[expected[index],encode(0.0,w),encode(2.0,w)]);}}
 let mut s=State::default();for e in 0..4{s.lane(0,e,32,encode(3.0,32));s.lane(1,e,32,encode(-2.0,32));}let t=run(word(0x65108000,32,0,1,0),128,&s);assert_eq!(output(&t,0,0,32),encode(7.0,32));
 let mut s=State::default();s.set("a64.svcr",0,1);s.set("a64.ssve_fexpa",0,1);let r=recipe(word(0x65108000,32,0,1,0),128).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.trace().is_empty());s.set("a64.sme_fa64",0,1);assert!(evaluate(&r,&s).is_ok());
}

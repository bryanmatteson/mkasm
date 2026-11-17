package x86

// A deliberately bounded half reference engine handles exact finite values,
// quiet comparisons and selected explicit exception cases. It rejects math
// outside its independent oracle rather than accepting the generated recipe.
const x86FP16RecipeTests = `
struct FP16State{memory:AccessState,calls:std::cell::Cell<usize>,controls:std::cell::RefCell<Vec<u64>>}
impl FP16State{fn new()->Self{let mut memory=AccessState::new();memory.state.reg("x86.mxcsr",0,0x9fc0);Self{memory,calls:Default::default(),controls:Default::default()}}}
fn half_number(bits:u16)->f64{let sign=if bits&0x8000!=0{-1.0}else{1.0};let exp=(bits>>10)&31;let frac=bits&1023;if exp==31{if frac==0{sign*f64::INFINITY}else{f64::NAN}}else if exp==0{sign*f64::from(frac)*2f64.powi(-24)}else{sign*(1.0+f64::from(frac)/1024.0)*2f64.powi(i32::from(exp)-15)}}
fn exact_half(number:f64)->Result<u64,EvalError>{if number==0.0{return Ok(if number.is_sign_negative(){0x8000}else{0});}if !number.is_finite(){return Err(EvalError::Unsupported);}let f=(number as f32).to_bits();let sign=u64::from(f>>16&0x8000);let exp=((f>>23)&255)as i32-127;if exp < -14{let sub=number.abs()*2f64.powi(24);if sub.fract()!=0.0||sub>=1024.0{return Err(EvalError::Unsupported)}return Ok(sign|sub as u64);}if !(-14..=15).contains(&exp)||f&0x1fff!=0{return Err(EvalError::Unsupported);}Ok(sign|((exp+15)as u64)<<10|u64::from((f>>13)&1023))}
// Binary search the IEEE binary16 lattice. Half operands/products/addends
// fit exactly in binary64, so this oracle rounds only at the specified boundary.
fn reference_half_round(n:f64,rc:u64)->Result<(u64,u64),EvalError>{
 if !n.is_finite(){return Err(EvalError::Unsupported)}
 let sign=if n.is_sign_negative(){0x8000}else{0};let x=n.abs();
 if x==0.0{return Ok((sign,0))}
 let mut lo=0u16;let mut hi=0x7bffu16;
 while lo<hi{let mid=lo+(hi-lo).div_ceil(2);if half_number(mid)<=x{lo=mid}else{hi=mid-1}}
 let low=half_number(lo);if low==x{return Ok((sign|u64::from(lo),0))}
 let upper=if lo==0x7bff{65536.0}else{half_number(lo+1)};
 let up=match rc&3{0=>x-low>upper-x||(x-low==upper-x&&lo&1!=0),1=>sign!=0,2=>sign==0,_=>false};
 let bits=if up{lo+1}else{lo};let overflow=x>=65536.0||bits==0x7c00;
 let flags=32|if overflow{8}else if bits<0x400{16}else{0};
 Ok((sign|u64::from(bits),flags))
}
impl Machine for FP16State{
 fn read_register(&self,r:s::Register)->Value{self.memory.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.memory.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.memory.read_wide_memory(a,w,e)}
 fn evaluate_float(&self,f:&s::FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  use s::{FloatOperation as F,FloatRounding as R};if f.environment!=s::FloatEnvironment::X86Mxcsr||inputs.iter().any(|v|!v.is_known()){return Err(EvalError::Unsupported)}self.calls.set(self.calls.get()+1);self.controls.borrow_mut().push(control.bits);
  let number=|v:Value|match v.width{16=>half_number(v.bits as u16),32=>f32::from_bits(v.bits as u32)as f64,64=>f64::from_bits(v.bits),_=>f64::NAN};
  let encode=|v:f64|match f.width{16=>exact_half(v),32=>Ok(u64::from((v as f32).to_bits())),64=>Ok(v.to_bits()),_=>Err(EvalError::Unsupported)};
  let mut raised=0u64;let value=match f.operation{
   F::Add|F::Subtract|F::Multiply|F::Divide|F::SquareRoot=>{if f.width!=16{return Err(EvalError::Unsupported)}let a=number(inputs[0]);let b=inputs.get(1).copied().map(number).unwrap_or(0.0);if !a.is_finite()||!b.is_finite(){return Err(EvalError::Unsupported)}if f.operation==F::Divide&&b==0.0&&a!=0.0{raised=4;if a.is_sign_negative(){0xfc00}else{0x7c00}}else if f.operation==F::Multiply{let(v,flags)=reference_half_round(a*b,control.bits>>13)?;raised|=flags;v}else{encode(match f.operation{F::Add=>a+b,F::Subtract=>a-b,F::Multiply=>a*b,F::Divide=>a/b,F::SquareRoot=>a.sqrt(),_=>unreachable!()})?}},
   F::FusedMultiplyAdd{negate_product,negate_addend}=>{if f.width!=16{return Err(EvalError::Unsupported)}let a=number(inputs[0]);let b=number(inputs[1]);let c=number(inputs[2]);if ![a,b,c].iter().all(|v|v.is_finite()){return Err(EvalError::Unsupported)}let (v,flags)=reference_half_round((if negate_product{-b}else{b}).mul_add(c,if negate_addend{-a}else{a}),control.bits>>13)?;raised|=flags;v},
   F::GetExponent|F::GetMantissa{..}=>{
    let raw=inputs[0].bits;let n=number(inputs[0]);let negative=raw>>(f.width-1)!=0;
    let snan=f.width==16&&raw&0x7c00==0x7c00&&raw&0x3ff!=0&&raw&0x200==0;
    if n.is_nan(){if f.width!=16{return Err(EvalError::Unsupported)}if snan{raised|=1;}if f.operation==F::GetExponent{(raw&0x7fff)|0x200}else{raw|0x200}}
    else {let sub=f.width==16&&raw&0x7c00==0&&raw&0x3ff!=0;
     match f.operation{
      F::GetExponent=>{if sub{raised|=2;}if n==0.0{if f.width!=16{return Err(EvalError::Unsupported)}0xfc00}else if n.is_infinite(){if f.width!=16{return Err(EvalError::Unsupported)}0x7c00}else{encode(n.abs().log2().floor())?}},
      F::GetMantissa{interval,sign_control}=>{if negative&&n!=0.0&&sign_control&2!=0{raised|=1;if f.width!=16{return Err(EvalError::Unsupported)}0xfe00}else{let sign=if negative&&sign_control&1==0{-1.0}else{1.0};if n==0.0||n.is_infinite(){encode(sign)?}else{if sub{raised|=2;}let exponent=n.abs().log2().floor()as i32;let mut v=n.abs()/2f64.powi(exponent);if match interval{0=>false,1=>exponent&1!=0,2=>true,3=>v>=1.5,_=>return Err(EvalError::Unsupported)}{v*=0.5;}encode(sign*v)?}}},
      _=>unreachable!(),
     }
    }
   },
   F::Convert{round_to_odd:false,..}=>encode(number(inputs[0]))?,
   F::FromInteger{source_width,signed,fractional_bits:0}=>{let raw=inputs[0].bits;let n=if signed{((raw<<(64-source_width))as i64>>(64-source_width))as f64}else{raw as f64};encode(n)?},
   F::ToInteger{signed,fractional_bits:0,rounding,..}=>{let n=number(inputs[0]);if !n.is_finite()||n.abs()>1024.0||!signed&&n<0.0{return Err(EvalError::Unsupported)}let rounding=if rounding==R::Environment{match control.bits>>13&3{0=>R::NearestEven,1=>R::NegativeInfinity,2=>R::PositiveInfinity,_=>R::Zero}}else{rounding};let out=match rounding{R::Zero=>n.trunc(),R::NearestEven=>n.round_ties_even(),R::NegativeInfinity=>n.floor(),R::PositiveInfinity=>n.ceil(),_=>return Err(EvalError::Unsupported)};if out!=n{raised|=32;}out as i64 as u64},
   F::Compare{signal_all_nans,..}=>{let a=number(inputs[0]);let b=number(inputs[1]);let snan=inputs.iter().any(|v|v.width==16&&v.bits&0x7c00==0x7c00&&v.bits&0x3ff!=0&&v.bits&0x200==0);if snan||signal_all_nans&&(a.is_nan()||b.is_nan()){raised|=1;}if a.is_nan()||b.is_nan(){3}else if a<b{8}else if a==b{6}else{2}},
   F::MinMax{minimum,numeric:false}=>{let a=number(inputs[0]);let b=number(inputs[1]);if a.is_nan()||b.is_nan(){return Err(EvalError::Unsupported)}if a==b{inputs[1].bits}else if if minimum{a<b}else{a>b}{inputs[0].bits}else{inputs[1].bits}},
   F::RoundScale{scale,rounding,exact}|F::Reduce{scale,rounding,exact}=>{
    let a=number(inputs[0]);let reduce=matches!(f.operation,F::Reduce{..});let quiet=1u64<<(if f.width==16{9}else if f.width==32{22}else{51});
    if a.is_nan(){if inputs[0].bits&quiet==0{raised|=1;}inputs[0].bits|quiet}
    else if a.is_infinite(){if reduce{0}else{inputs[0].bits}}
    else {
     let rounding=if rounding==R::Environment{match control.bits>>13&3{0=>R::NearestEven,1=>R::NegativeInfinity,2=>R::PositiveInfinity,_=>R::Zero}}else{rounding};
     let factor=2f64.powi(i32::from(scale));let n=a*factor;
     if !n.is_finite(){return Err(EvalError::Unsupported)}
     let integral=match rounding{R::NearestEven=>n.round_ties_even(),R::Zero=>n.trunc(),R::NegativeInfinity=>n.floor(),R::PositiveInfinity=>n.ceil(),_=>return Err(EvalError::Unsupported)};
     let rounded=integral/factor;let mut out=if reduce{a-rounded}else{rounded};
     if out==0.0{out=if reduce{if rounding==R::NegativeInfinity{-0.0}else{0.0}}else{out.copysign(a)}}
     if exact&&n!=integral{raised|=32;}encode(out)?
    }
   },
   F::X86ReciprocalEstimate|F::X86ReciprocalSquareRootEstimate=>{
    if f.width!=16{return Err(EvalError::Unsupported)}let raw=inputs[0].bits;let sign=raw&0x8000;let mag=raw&0x7fff;let sqrt=f.operation==F::X86ReciprocalSquareRootEstimate;
    if mag>0x7c00{raw|0x200}else if mag==0{sign|0x7c00}else if sqrt&&sign!=0{0xfe00}else if mag==0x7c00{sign}else{
     let x=half_number(raw as u16);let out=if sqrt{1.0/x.sqrt()}else{1.0/x};let candidate=reference_half_round(out,0)?.0;if candidate&0x7fff<0x7c00&&((half_number(candidate as u16)-out)/out).abs()>=9.0/16384.0{return Err(EvalError::Unsupported)}candidate
    }
   },
   F::Scale=>{let a=number(inputs[0]);let z=number(inputs[1]);if f.width!=16||!a.is_finite()||!z.is_finite()||z.abs()>64.0{return Err(EvalError::Unsupported)}if inputs[0].bits&0x7c00==0&&inputs[0].bits&0x3ff!=0{raised|=2;}let(v,flags)=reference_half_round(a*2f64.powi(z.floor()as i32),control.bits>>13)?;raised|=flags;v},
   F::RoundToIntegral{rounding,exact}=>{let a=number(inputs[0]);if !a.is_finite(){return Err(EvalError::Unsupported)}let v=match rounding{R::NearestEven=>a.round_ties_even(),R::Zero=>a.trunc(),R::NegativeInfinity=>a.floor(),R::PositiveInfinity=>a.ceil(),_=>return Err(EvalError::Unsupported)};if exact&&a!=v{raised|=32;}encode(v)?},
   _=>return Err(EvalError::Unsupported),
  };
  Ok(match f.projection{s::FloatProjection::Value=>Value::known(f.width,value),s::FloatProjection::Status=>Value::known(32,status.bits|raised),s::FloatProjection::Trapped=>Value::known(1,u64::from(raised&!(control.bits>>7)&63!=0))})
 }
}
fn fp16_eval(text:&str,st:&FP16State)->Transition{s::evaluate(&memory_recipe(text),st).unwrap_or_else(|e|panic!("{text}: {e:?}"))}
#[test]fn actual_xed_fp16_packed_scalar_arithmetic_and_upper_rules(){
 let mut st=FP16State::new();vector(&mut st.memory.state,1,&[packed_halves([0x3c00,0x4000,0xc200,1]),packed_halves([0x4400;4])]);vector(&mut st.memory.state,2,&[packed_halves([0x4000,0x4200,0x3c00,1]),packed_halves([0x4000;4])]);
 let t=fp16_eval("vaddph xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x4200,0x4500,0xc000,2]));assert_eq!(vector_result(&t,0,1),packed_halves([0x4600;4]));for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fc0);
 let t=fp16_eval("vaddsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x4200,0x4000,0xc200,1]));assert_eq!(vector_result(&t,0,1),packed_halves([0x4400;4]));for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}
 for (text,value) in [("vsubsh xmm0, xmm1, xmm2",0xbc00),("vmulsh xmm0, xmm1, xmm2",0x4000),("vdivsh xmm0, xmm1, xmm2",0x3800),("vminsh xmm0, xmm1, xmm2",0x3c00),("vmaxsh xmm0, xmm1, xmm2",0x4000)]{assert_eq!(vector_result(&fp16_eval(text,&st),0,0)&0xffff,value);}
}
#[test]fn actual_xed_fp16_fma_compare_round_and_conversion(){
 let mut st=FP16State::new();vector(&mut st.memory.state,0,&[packed_halves([0x3c00;4]);2]);vector(&mut st.memory.state,1,&[packed_halves([0x4000;4]);2]);vector(&mut st.memory.state,2,&[packed_halves([0x4200;4]);2]);
 for (order,result) in [(132,0x4500),(213,0x4500),(231,0x4700)]{let t=fp16_eval(&format!("vfmadd{order}ph xmm0, xmm1, xmm2"),&st);assert_eq!(vector_result(&t,0,0),packed_halves([result;4]));}
 let t=fp16_eval("vcmpph k2, xmm1, xmm2, 1",&st);assert_eq!(reg(&t,"x86.mask",2).bits,255);
 let t=fp16_eval("vcomish xmm1, xmm2",&st);assert_eq!(flag(&t,0).bits,1);assert_eq!(flag(&t,1).bits,0);assert_eq!(flag(&t,3).bits,0);
 vector(&mut st.memory.state,1,&[packed_halves([0x3e00;4]);2]);let t=fp16_eval("vrndscaleph xmm0, xmm1, 0",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x4000;4]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fe0);
 let t=fp16_eval("vcvtph2psx xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),u64::from(1.5f32.to_bits())*0x100000001);
 let t=fp16_eval("vcvttph2w xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),packed_halves([1;4]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fe0);
 vector(&mut st.memory.state,1,&[u64::from(2f32.to_bits())*0x100000001;2]);let t=fp16_eval("vcvtps2phx xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x4000;4]));assert_eq!(vector_result(&t,0,1),0);
 st.memory.state.x(1,7);let t=fp16_eval("vcvtsi2sh xmm0, xmm1, rcx",&st);assert_eq!(vector_result(&t,0,0)&0xffff,0x4700);
}
#[test]fn actual_xed_fp16_masks_fault_suppression_disp8_and_traps(){
 let mut st=FP16State::new();vector(&mut st.memory.state,1,&[packed_halves([0x3c00;4]);8]);st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;
 let t=fp16_eval("vaddph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);assert!(st.memory.reads.borrow().is_empty());for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}
 st.memory.unknown_address=false;st.memory.state.x(0,0x4000);st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.mem.insert(0x4000,0x4000);st.memory.state.mem.insert(0x403e,0x4200);let t=fp16_eval("vaddph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x4000,16),(0x403e,16)]);assert_eq!(vector_result(&t,0,0),0x4200);assert_eq!(vector_result(&t,0,7),0x4400u64<<48);
 st.memory.reads.borrow_mut().clear();st.memory.state.mem.insert(0x4004,0x4000);let bytes=[0x62,0xf5,0x74,0x58,0x58,0x40,2];let d=decode(&bytes,Mode::Mode64).unwrap();assert_eq!(d.operands().iter().find(|o|o.kind==OperandKind::Memory).unwrap().memory.displacement,4);assert!(d.format_intel(0).contains("word ptr [rax+0x4] {1to32}"));let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);let _=s::evaluate(&r,&st).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0x4004,16)]);
 let d=decode(&[0x62,0xf5,0x74,0x48,0x58,0x40,2],Mode::Mode64).unwrap();assert_eq!(d.operands().iter().find(|o|o.kind==OperandKind::Memory).unwrap().memory.displacement,128);
 vector(&mut st.memory.state,2,&[0;2]);st.memory.state.reg("x86.mxcsr",0,0x1d80);let t=fp16_eval("vdivsh xmm0, xmm1, xmm2",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1d84);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"));
}

#[test]fn actual_xed_fp16_embedded_rounding_sae_and_quarter_narrowing(){
 let mut st=FP16State::new();vector(&mut st.memory.state,1,&[packed_halves([0x3c00;4]);8]);vector(&mut st.memory.state,2,&[packed_halves([0x4000;4]);8]);
 let enc=assemble_at("vaddsh xmm0, xmm1, xmm2",0).unwrap();let mut bytes=enc.first().unwrap().bytes().to_vec();bytes[3]=(bytes[3]&!0x60)|0x70;
 let d=decode(&bytes,Mode::Mode64).unwrap();assert_eq!(d.physical.vector_length,128);assert_eq!(d.physical.rounding_control,3);assert!(d.format_intel(0).ends_with(", {rz-sae}"));let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);r.validate().unwrap();let t=s::evaluate(&r,&st).unwrap();assert_eq!(vector_result(&t,0,0)&0xffff,0x4200);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));assert!(st.controls.borrow().iter().all(|x|*x==0xffc0));
 let enc=assemble_at("vcomish xmm1, xmm2",0).unwrap();let mut bytes=enc.first().unwrap().bytes().to_vec();bytes[3]|=0x10;vector(&mut st.memory.state,1,&[0x7c01,0]);st.memory.state.reg("x86.mxcsr",0,0);let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(t.trap,None);for n in [0,1,3]{assert_eq!(flag(&t,n).bits,1)}assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
 vector(&mut st.memory.state,1,&[1f64.to_bits(),2f64.to_bits()]);let t=fp16_eval("vcvtpd2ph xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),0x40003c00);for i in 1..8{assert_eq!(vector_result(&t,0,i),0)}
}

#[test]fn xed_fp16_real_decode_recipe_partition(){
 let mut families=std::collections::BTreeMap::<&str,(usize,usize)>::new();let mut imported=0;
 for i in 0..encoding_count(){let e=encoding(i).unwrap();if !e.form_id.starts_with("XED/"){continue}imported+=1;let mode=if encoding_supports_mode(i,Mode::Mode64){Mode::Mode64}else{Mode::Mode32};let mut bytes=[0;15];let n=encode_representative(i,mode,&mut bytes).unwrap();let d=decode(&bytes[..n],mode).unwrap();assert_eq!(d.encoding().mnemonic,e.mnemonic);let r=d.semantic_recipe(0);let entry=families.entry(e.mnemonic).or_default();entry.1+=1;if r.support==Support::Full{r.validate().unwrap();entry.0+=1;}}
 assert_eq!(imported,590);let mut supported=0;for (name,(full,total)) in &families{println!("XED FP16 {name}: {full}/{total} Full");supported+=full;}println!("XED FP16 total: {supported}/{imported} Full");assert_eq!(supported,590);
}

#[test]fn fp16_moves_classes_and_ignored_scalar_ll(){
 let mut st=FP16State::new();st.memory.state.x(1,0x1122334455667788);vector(&mut st.memory.state,0,&[u64::MAX;8]);vector(&mut st.memory.state,1,&[0x123456789abc4000,0x55667788]);vector(&mut st.memory.state,2,&[0x3c00,0]);
 let t=fp16_eval("vmovw xmm0, ecx",&st);assert_eq!(vector_result(&t,0,0),0x7788);for i in 1..8{assert_eq!(vector_result(&t,0,i),0)}
 let t=fp16_eval("vmovw eax, xmm1",&st);assert_eq!(x(&t,0),0x4000);
 let t=fp16_eval("vmovsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),0x123456789abc3c00);assert_eq!(vector_result(&t,0,1),0x55667788);
 st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;let t=fp16_eval("vmovsh xmm0 {k1}{z}, word ptr [rax]",&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}assert!(fp16_eval("vmovsh word ptr [rax] {k1}, xmm1",&st).memory.is_empty());assert_eq!(st.memory.address_reads.get(),0);
 let vals=[0x7e01,0,0x8000,0x7c00,0xfc00,1,0x8001,0x7c01];vector(&mut st.memory.state,1,&[packed_halves(vals[..4].try_into().unwrap()),packed_halves(vals[4..].try_into().unwrap())]);
 for (imm,expected) in [(1,1),(2,2),(4,4),(8,8),(16,16),(32,96),(64,64),(128,128)]{let t=fp16_eval(&format!("vfpclassph k2, xmm1, {imm}"),&st);assert_eq!(reg(&t,"x86.mask",2).bits,expected);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));}
 vector(&mut st.memory.state,1,&[0x4000,0]);let d=decode(&[0x62,0xf5,0x76,0x68,0x58,0xc2],Mode::Mode64).unwrap();assert_eq!(d.physical.vector_length,128);let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);let t=s::evaluate(&r,&st).unwrap();assert_eq!(vector_result(&t,0,0)&0xffff,0x4200);
}

#[test]fn actual_fp16_complex_pair_order_conjugation_and_scalar_copy(){
 let mut st=FP16State::new();vector(&mut st.memory.state,0,&[packed_halves([0x3c00,0x4000,0x3c00,0x4000]);8]);
 vector(&mut st.memory.state,1,&[packed_halves([0x4200,0x4400,0x4200,0x4400]);2]);
 vector(&mut st.memory.state,2,&[packed_halves([0x4500,0x4600,0x4500,0x4600]);8]);
 // (3+4i)*(5+6i)=-9+38i; conjugating second input gives39+2i.
 for(text,expected)in[("vfmulcph xmm0, xmm1, xmm2",[0xc880,0x50c0]),("vfcmulcph xmm0, xmm1, xmm2",[0x50e0,0x4000]),("vfmaddcph xmm0, xmm1, xmm2",[0xc800,0x5100]),("vfcmaddcph xmm0, xmm1, xmm2",[0x5100,0x4400])]{let t=fp16_eval(text,&st);assert_eq!(vector_result(&t,0,0),packed_halves([expected[0],expected[1],expected[0],expected[1]]));for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}}
 vector(&mut st.memory.state,1,&[packed_halves([0x4200,0x4400,0x4200,0x4400]),0x1122334455667788]);let t=fp16_eval("vfmulcsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0xc880,0x50c0,0x4200,0x4400]));assert_eq!(vector_result(&t,0,1),0x1122334455667788);for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}
 // A single-round complex calculation would produce b01f. Intel's first
 // half multiply must round to30b1 before the subtracting fused operation.
 vector(&mut st.memory.state,1,&[packed_halves([0x3aa1,0x3ae7,0,0]),0]);vector(&mut st.memory.state,2,&[packed_halves([0x31a9,0x351b,0,0]),0]);let t=fp16_eval("vfmulcsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0)&0xffff,0xb01e);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fe0);
}
#[test]fn actual_fp16_complex_masks_memory_rounding_status_and_aliases(){
 let mut st=FP16State::new();vector(&mut st.memory.state,0,&[u64::MAX;8]);vector(&mut st.memory.state,1,&[packed_halves([0x3c00;4]);8]);vector(&mut st.memory.state,2,&[packed_halves([0x3c00;4]);8]);
 st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;let t=fp16_eval("vfmulcph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}
 st.memory.unknown_address=false;st.memory.state.x(0,0x5000);st.memory.state.mem.insert(0x5000,0x3c003c00);st.memory.state.mem.insert(0x503c,0x40003c00);st.memory.state.reg("x86.mask",1,0x8001);let t=fp16_eval("vfmulcph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x5000,32),(0x503c,32)]);assert_eq!(vector_result(&t,0,0),0x40000000);assert_eq!(vector_result(&t,0,7),0x4200bc00u64<<32);
 st.memory.reads.borrow_mut().clear();let enc=assemble_at("vfmulcph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();assert!(d.format_intel(0).contains("dword ptr [rax] {1to16}"));let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0x5000,32)]);assert_eq!(vector_result(&t,0,7),0x40000000u64<<32);
 // Inexact complex operations always mask exceptions but update sticky flags
 // without overwriting the incoming (unmasked) exception control bits.
 vector(&mut st.memory.state,1,&[packed_halves([0x3aa1,0x3ae7,0,0]),0]);vector(&mut st.memory.state,2,&[packed_halves([0x31a9,0x351b,0,0]),0]);st.memory.state.reg("x86.mxcsr",0,0);let t=fp16_eval("vfmulcsh xmm0, xmm1, xmm2",&st);assert_eq!(t.trap,None);assert_eq!(reg(&t,"x86.mxcsr",0).bits,32);assert_eq!(vector_result(&t,0,0)&0xffff,0xb01e);assert!(st.controls.borrow().iter().all(|x|x&0x1f80==0x1f80));
 let enc=assemble_at("vfmulcsh xmm0, xmm1, xmm2",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=0x70;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(t.trap,None);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
 for text in ["vfmulcph xmm0, xmm0, xmm2","vfmaddcsh xmm0, xmm1, xmm0","vfcmulcph zmm17, zmm17, zmm2","vfmaddcph zmm17, zmm1, zmm17"]{assert!(assemble_at(text,0).is_err(),"#UD alias assembled: {text}")}
 let enc=assemble_at("vfmulcph xmm0, xmm1, xmm2",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[5]&=!7;assert!(decode(&bytes,Mode::Mode64).is_err());
 let mut count=0;for i in 0..encoding_count(){let e=encoding(i).unwrap();if !matches!(e.mnemonic,"VFMADDCPH"|"VFCMADDCPH"|"VFMADDCSH"|"VFCMADDCSH"|"VFMULCPH"|"VFCMULCPH"|"VFMULCSH"|"VFCMULCSH"){continue}count+=1;let mut bytes=[0;15];let n=encode_representative(i,Mode::Mode64,&mut bytes).unwrap();let d=decode(&bytes[..n],Mode::Mode64).unwrap();assert_eq!(d.semantic_recipe(0).support,Support::Full,"{}",e.form_id);}assert_eq!(count,40);
}

#[test]fn fp16_memory_classification_masks_preserve_actual_access_widths(){
 let mut st=FP16State::new();st.memory.unknown_address=true;st.memory.state.reg("x86.mask",1,0);
 let t=fp16_eval("vfpclassph k2 {k1}, zmmword ptr [rax], 1",&st);assert_eq!(reg(&t,"x86.mask",2).bits,0);assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);assert!(st.memory.reads.borrow().is_empty());
 st.memory.unknown_address=false;st.memory.state.x(0,0x6000);st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.mem.insert(0x6000,0x7e01);st.memory.state.mem.insert(0x603e,0x7c01);
 let t=fp16_eval("vfpclassph k2 {k1}, zmmword ptr [rax], 129",&st);assert_eq!(reg(&t,"x86.mask",2).bits,0x80000001);assert_eq!(*st.memory.reads.borrow(),vec![(0x6000,16),(0x603e,16)]);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
 st.memory.reads.borrow_mut().clear();st.memory.state.reg("x86.mask",1,1);let t=fp16_eval("vfpclasssh k2 {k1}, word ptr [rax], 1",&st);assert_eq!(reg(&t,"x86.mask",2).bits,1);assert_eq!(*st.memory.reads.borrow(),vec![(0x6000,16)]);
}

#[test]fn actual_getexp_getmant_half_normal_subnormal_specials_and_controls(){
 let mut st=FP16State::new();vector(&mut st.memory.state,1,&[packed_halves([0x3e00,0xc600,1,0x7c00]),packed_halves([0,0x8000,0x7e03,0xfc01])]);
 let t=fp16_eval("vgetexpph xmm0, xmm1",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0,0x4000,0xce00,0x7c00]));assert_eq!(vector_result(&t,0,1),packed_halves([0xfc00,0xfc00,0x7e03,0x7e01]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fc3);
 for(imm,expected)in[(0,[0x3e00,0xbe00,0x3c00,0x3c00]),(1,[0x3e00,0xbe00,0x3c00,0x3c00]),(2,[0x3a00,0xba00,0x3800,0x3c00]),(3,[0x3a00,0xba00,0x3c00,0x3c00]),(4,[0x3e00,0x3e00,0x3c00,0x3c00]),(8,[0x3e00,0xfe00,0x3c00,0x3c00])]{let t=fp16_eval(&format!("vgetmantph xmm0, xmm1, {imm}"),&st);assert_eq!(vector_result(&t,0,0),packed_halves(expected));}
 vector(&mut st.memory.state,2,&[0xc600,0]);let t=fp16_eval("vgetexpsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x4000,0xc600,1,0x7c00]));assert_eq!(vector_result(&t,0,1),packed_halves([0,0x8000,0x7e03,0xfc01]));
 st.memory.state.reg("x86.mxcsr",0,0x1f00);let t=fp16_eval("vgetmantsh xmm0, xmm1, xmm2, 8",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f01);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"));
 let enc=assemble_at("vgetmantsh xmm0, xmm1, xmm2, 8",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=0x10;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(t.trap,None);assert_eq!(vector_result(&t,0,0)&0xffff,0xfe00);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
 // Typed operation also serves the existing real PS/PD physical forms.
 vector(&mut st.memory.state,1,&[u64::from(6f32.to_bits())*0x100000001;2]);assert_eq!(vector_result(&fp16_eval("vgetexpps xmm0, xmm1",&st),0,0),u64::from(2f32.to_bits())*0x100000001);
 vector(&mut st.memory.state,1,&[6f64.to_bits();2]);assert_eq!(vector_result(&fp16_eval("vgetmantpd xmm0, xmm1, 2",&st),0,0),0.75f64.to_bits());
}
#[test]fn getexp_getmant_half_mask_fault_suppression_and_single_broadcast(){
 let mut st=FP16State::new();st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;let t=fp16_eval("vgetexpph zmm0 {k1}{z}, zmmword ptr [rax]",&st);assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}
 st.memory.unknown_address=false;st.memory.state.x(0,0x7000);st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.mem.insert(0x7000,0x4600);st.memory.state.mem.insert(0x703e,0x4000);let t=fp16_eval("vgetexpph zmm0 {k1}{z}, zmmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x7000,16),(0x703e,16)]);assert_eq!(vector_result(&t,0,0),0x4000);assert_eq!(vector_result(&t,0,7),0x3c00u64<<48);
 st.memory.reads.borrow_mut().clear();let enc=assemble_at("vgetmantph zmm0 {k1}{z}, zmmword ptr [rax], 2",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0x7000,16)]);assert_eq!(vector_result(&t,0,0),0x3a00);assert_eq!(vector_result(&t,0,7),0x3a00u64<<48);
}

#[test]fn actual_rndscale_all_immediates_and_rounding_selection(){
 // Each immediate reaches real encode/decode and the recipe evaluator. The
 // independent grid oracle uses exact power-of-two scaling in binary64.
 let values=[0.34375,-0.34375,1.03125,-1.03125,65504.0,-0.0];
 for rc in 0..4u64{for imm in 0..256u64{for &input in &values{
  let mut st=FP16State::new();st.memory.state.reg("x86.mxcsr",0,0x1f80|(rc<<13));vector(&mut st.memory.state,1,&[0x1122334455667788,0x8877665544332211]);vector(&mut st.memory.state,2,&[exact_half(input).unwrap(),0]);
  let selected=if imm&4!=0{rc}else{imm&3};let scale=2f64.powi((imm>>4)as i32);let n=input*scale;
  let integral=match selected{0=>n.round_ties_even(),1=>n.floor(),2=>n.ceil(),_=>n.trunc()};let mut expected=integral/scale;if expected==0.0{expected=expected.copysign(input);}
  let t=fp16_eval(&format!("vrndscalesh xmm0, xmm1, xmm2, {imm}"),&st);assert_eq!(vector_result(&t,0,0),0x1122334455660000|exact_half(expected).unwrap(),"RC={rc} imm={imm} input={input}");assert_eq!(vector_result(&t,0,1),0x8877665544332211);for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}
  let flags=if imm&8==0&&expected!=input{32}else{0};assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f80|(rc<<13)|flags);assert_eq!(t.trap,None);
 }}}
}
#[test]fn actual_rndscale_packed_masks_broadcast_sae_and_precision_commit(){
 let mut st=FP16State::new();st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;let t=fp16_eval("vrndscaleph zmm0 {k1}{z}, zmmword ptr [rax], 240",&st);assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}
 st.memory.unknown_address=false;st.memory.state.x(0,0x8000);st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.mem.insert(0x8000,0x3580);st.memory.state.mem.insert(0x803e,0xb580);let t=fp16_eval("vrndscaleph zmm0 {k1}{z}, zmmword ptr [rax], 16",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x8000,16),(0x803e,16)]);assert_eq!(vector_result(&t,0,0),0x3800);assert_eq!(vector_result(&t,0,7),0xb800u64<<48);
 st.memory.reads.borrow_mut().clear();let enc=assemble_at("vrndscaleph zmm0 {k1}{z}, zmmword ptr [rax], 16",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0x8000,16)]);assert_eq!(vector_result(&t,0,7),0x3800u64<<48);
 vector(&mut st.memory.state,2,&[0x3580,0]);st.memory.state.reg("x86.mxcsr",0,0x0f80);let t=fp16_eval("vrndscalesh xmm0, xmm1, xmm2, 16",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x0fa0);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"));
 let t=fp16_eval("vrndscalesh xmm0, xmm1, xmm2, 24",&st);assert_eq!(t.trap,None);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x0f80);assert_eq!(vector_result(&t,0,0)&0xffff,0x3800);
 let enc=assemble_at("vrndscalesh xmm0, xmm1, xmm2, 16",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(t.trap,None);assert_eq!(vector_result(&t,0,0)&0xffff,0x3800);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
}

#[test]fn actual_reduce_all_immediates_and_scale_floor_half_boundaries(){
 for rc in 0..4u64{for imm in 0..256u64{for &a in &[0.34375,-0.34375,1.03125,-1.03125,65504.0,-0.0]{
  let mut st=FP16State::new();st.memory.state.reg("x86.mxcsr",0,0x1f80|(rc<<13));vector(&mut st.memory.state,1,&[0x1122334455667788,0x8877665544332211]);vector(&mut st.memory.state,2,&[exact_half(a).unwrap(),0]);let rc=if imm&4!=0{rc}else{imm&3};let factor=2f64.powi((imm>>4)as i32);let n=a*factor;let rounded=match rc{0=>n.round_ties_even(),1=>n.floor(),2=>n.ceil(),_=>n.trunc()};let mut expected=a-rounded/factor;if expected==0.0{expected=if rc==1{-0.0}else{0.0};}
  let t=fp16_eval(&format!("vreducesh xmm0, xmm1, xmm2, {imm}"),&st);assert_eq!(vector_result(&t,0,0),0x1122334455660000|exact_half(expected).unwrap(),"imm={imm} a={a}");assert_eq!(vector_result(&t,0,1),0x8877665544332211);assert_eq!(reg(&t,"x86.mxcsr",0).bits&63,if imm&8==0&&n!=rounded{32}else{0});assert_eq!(t.trap,None);
 }}}
 let mut st=FP16State::new();vector(&mut st.memory.state,1,&[packed_halves([0x3c00,0x3c00,1,0x7bff]);2]);vector(&mut st.memory.state,2,&[packed_halves([0xbe00,0x3e00,0x3c00,0]);2]);let t=fp16_eval("vscalefph xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x3400,0x4000,2,0x7bff]));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x9fc2);
 vector(&mut st.memory.state,2,&[0xbe00,0]);let t=fp16_eval("vscalefsh xmm0, xmm1, xmm2",&st);assert_eq!(vector_result(&t,0,0),packed_halves([0x3400,0x3c00,1,0x7bff]));
 st.memory.state.reg("x86.mxcsr",0,0x1e80);vector(&mut st.memory.state,1,&[1,0]);vector(&mut st.memory.state,2,&[0x3c00,0]);let t=fp16_eval("vscalefsh xmm0, xmm1, xmm2",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1e82);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"));
}
#[test]fn actual_scaled_transforms_masks_broadcast_and_sae(){
 let mut st=FP16State::new();st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;vector(&mut st.memory.state,1,&[packed_halves([0x3c00;4]);8]);for text in["vscalefph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]","vreduceph zmm0 {k1}{z}, zmmword ptr [rax], 16"]{let t=fp16_eval(text,&st);for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}}assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);
 st.memory.unknown_address=false;st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.x(0,0x9000);st.memory.state.mem.insert(0x9000,0x3e00);st.memory.state.mem.insert(0x903e,0xbe00);let t=fp16_eval("vscalefph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",&st);assert_eq!(*st.memory.reads.borrow(),vec![(0x9000,16),(0x903e,16)]);assert_eq!(vector_result(&t,0,0),0x4000);assert_eq!(vector_result(&t,0,7),0x3400u64<<48);
 st.memory.reads.borrow_mut().clear();let enc=assemble_at("vscalefph zmm0 {k1}{z}, zmm1, zmmword ptr [rax]",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0x9000,16)]);assert_eq!(vector_result(&t,0,7),0x4000u64<<48);
 vector(&mut st.memory.state,2,&[0x3580,0]);st.memory.state.reg("x86.mxcsr",0,0x0f80);let t=fp16_eval("vreducesh xmm0, xmm1, xmm2, 16",&st);assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert!(!t.registers.iter().any(|x|x.register.bank=="x86.vector64"));let enc=assemble_at("vreducesh xmm0, xmm1, xmm2, 16",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(t.trap,None);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
}

#[test]fn actual_rndscale_all_immediates_existing_single_double_and_sae_llig(){
 for w in [32u8,64]{for rc in 0..4u64{for imm in 0..256u64{
  let mut st=FP16State::new();st.memory.state.reg("x86.mxcsr",0,0x1f80|(rc<<13));let a=-2.34375f64;let input=if w==32{u64::from((a as f32).to_bits())}else{a.to_bits()};vector(&mut st.memory.state,1,&[0x1122334455667788,0x8877665544332211]);vector(&mut st.memory.state,2,&[input,0]);
  let selected=if imm&4!=0{rc}else{imm&3};let factor=2f64.powi((imm>>4)as i32);let n=a*factor;let v=match selected{0=>n.round_ties_even(),1=>n.floor(),2=>n.ceil(),_=>n.trunc()}/factor;let expected=if w==32{u64::from((v as f32).to_bits())}else{v.to_bits()};let suffix=if w==32{"ss"}else{"sd"};let t=fp16_eval(&format!("vrndscale{suffix} xmm0, xmm1, xmm2, {imm}"),&st);assert_eq!(vector_result(&t,0,0),if w==32{0x1122334400000000|expected}else{expected});assert_eq!(vector_result(&t,0,1),0x8877665544332211);assert_eq!(reg(&t,"x86.mxcsr",0).bits,0x1f80|(rc<<13)|if imm&8==0&&a!=v{32}else{0});
 }}}
 let mut st=FP16State::new();st.memory.state.reg("x86.mxcsr",0,0x0f80);vector(&mut st.memory.state,2,&[u64::from(2.34375f32.to_bits()),0]);let enc=assemble_at("vrndscaless xmm0, xmm1, xmm2, 16",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=0x70;let d=decode(&bytes,Mode::Mode64).unwrap();assert_eq!(d.physical.vector_length,128);let t=s::evaluate(&d.semantic_recipe(0),&st).unwrap();assert_eq!(vector_result(&t,0,0)&0xffffffff,u64::from(2.5f32.to_bits()));assert_eq!(t.trap,None);assert!(!t.registers.iter().any(|x|x.register.bank=="x86.mxcsr"));
}

struct EstimateState<'a>(&'a FP16State);
impl Machine for EstimateState<'_>{
 fn read_register(&self,r:s::Register)->Value{assert_ne!(r.bank,"x86.mxcsr","estimate read architectural MXCSR");self.0.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.0.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.0.read_wide_memory(a,w,e)}
 fn evaluate_float(&self,f:&s::FloatExpression,i:&[Value],c:Value,s:Value)->Result<Value,EvalError>{assert_eq!(f.projection,s::FloatProjection::Value);self.0.evaluate_float(f,i,c,s)}
}
#[test]fn actual_fp16_estimates_specials_relative_bound_and_no_mxcsr(){
 let cases=[(0,0x7c00,0x7c00),(0x8000,0xfc00,0xfc00),(0x7c00,0,0),(0xfc00,0x8000,0xfe00),(0x7e03,0x7e03,0x7e03),(0xfc03,0xfe03,0xfe03),(1,0x7c00,0x6c00),(0x8001,0xfc00,0xfe00),(0x3c00,0x3c00,0x3c00),(0x4000,0x3800,0x39a8),(0xbc00,0xbc00,0xfe00),(0x7bff,0x0100,0x1c00)];
 for (input,rcp,rsqrt) in cases{let mut st=FP16State::new();st.memory.state.reg("x86.mxcsr",0,0);vector(&mut st.memory.state,1,&[0x1122334455667788,0x8877665544332211]);vector(&mut st.memory.state,2,&[input,0]);for(text,expected)in[("vrcpsh xmm0, xmm1, xmm2",rcp),("vrsqrtsh xmm0, xmm1, xmm2",rsqrt)]{let r=memory_recipe(text);assert!(r.effects.iter().all(|e|!matches!(e,s::Effect::Trap{..})&&!matches!(e,s::Effect::WriteRegister{destination,..} if destination.register.bank=="x86.mxcsr")));let t=s::evaluate(&r,&EstimateState(&st)).unwrap();assert_eq!(t.trap,None);assert_eq!(vector_result(&t,0,0),0x1122334455660000|expected,"{text} source={input:x}");assert_eq!(vector_result(&t,0,1),0x8877665544332211);for i in 2..8{assert_eq!(vector_result(&t,0,i),0)}if input>0&&input<0x7c00&&expected<0x7c00{let exact=if text.starts_with("vrsqrt"){1.0/half_number(input as u16).sqrt()}else{1.0/half_number(input as u16)};assert!(((half_number(expected as u16)-exact)/exact).abs()<2f64.powi(-11)+2f64.powi(-14));}}}
}
#[test]fn actual_fp16_estimate_masks_pair_of_far_lanes_and_broadcast(){
 let mut st=FP16State::new();st.memory.state.reg("x86.mask",1,0);st.memory.unknown_address=true;for text in["vrcpph zmm0 {k1}{z}, zmmword ptr [rax]","vrsqrtph zmm0 {k1}{z}, zmmword ptr [rax]"]{let t=s::evaluate(&memory_recipe(text),&EstimateState(&st)).unwrap();for i in 0..8{assert_eq!(vector_result(&t,0,i),0)}}assert_eq!(st.calls.get(),0);assert_eq!(st.memory.address_reads.get(),0);
 st.memory.unknown_address=false;st.memory.state.reg("x86.mask",1,0x80000001);st.memory.state.x(0,0xa000);st.memory.state.mem.insert(0xa000,0x4000);st.memory.state.mem.insert(0xa03e,0x4400);let t=s::evaluate(&memory_recipe("vrsqrtph zmm0 {k1}{z}, zmmword ptr [rax]"),&EstimateState(&st)).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0xa000,16),(0xa03e,16)]);assert_eq!(vector_result(&t,0,0),0x39a8);assert_eq!(vector_result(&t,0,7),0x3800u64<<48);
 st.memory.reads.borrow_mut().clear();let enc=assemble_at("vrcpph zmm0 {k1}{z}, zmmword ptr [rax]",0).unwrap();let mut bytes=enc[0].bytes().to_vec();bytes[3]|=16;let d=decode(&bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full);let t=s::evaluate(&r,&EstimateState(&st)).unwrap();assert_eq!(*st.memory.reads.borrow(),vec![(0xa000,16)]);assert_eq!(vector_result(&t,0,0),0x3800);assert_eq!(vector_result(&t,0,7),0x3800u64<<48);
}

#[test]fn estimate_reference_rejects_unrepresentable_architectural_error_bound(){
 // 1/60000 lies between half subnormals. Neither adjacent result satisfies
 // the SDM relative bound; keep that native capability limitation explicit.
 let mut st=FP16State::new();vector(&mut st.memory.state,2,&[0x7b53,0]);let r=memory_recipe("vrcpsh xmm0, xmm1, xmm2");assert_eq!(s::evaluate(&r,&EstimateState(&st)),Err(EvalError::Unsupported));
}
`

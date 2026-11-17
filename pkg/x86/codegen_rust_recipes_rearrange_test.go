package x86

// Public decoder/evaluator checks for the complete SSE/AVX shuffle and unpack
// category. The host oracle works on element arrays, independent of recipe IR.
const x86RearrangeRecipeTests = `
fn rearrange_family(name:&str)->bool{matches!(name.strip_prefix('V').unwrap_or(name),"SHUFPS"|"SHUFPD"|"UNPCKLPS"|"UNPCKHPS"|"UNPCKLPD"|"UNPCKHPD"|"PSHUFD"|"PSHUFHW"|"PSHUFLW"|"PSHUFB"|"PUNPCKLBW"|"PUNPCKHBW"|"PUNPCKLWD"|"PUNPCKHWD"|"PUNPCKLDQ"|"PUNPCKHDQ"|"PUNPCKLQDQ"|"PUNPCKHQDQ"|"SHUFF32X4"|"SHUFF64X2"|"SHUFI32X4"|"SHUFI64X2")}
fn rearrange_expected(name:&str,w:u8,vl:usize,a:&[u64],b:&[u64],imm:usize)->Vec<u64>{
 let per=128/usize::from(w);let n=vl/usize::from(w);
 (0..n).map(|i|{let base=i/per*per;let lane=i%per;
  if name.starts_with("shuff")||name.starts_with("shufi"){let block=i/per;let count=vl/128;let src=if block<count/2{a}else{b};let selected=if count==2{imm>>block&1}else{imm>>(2*block)&3};src[selected*per+lane]}
  else if name=="shufps"{let src=if lane<2{a}else{b};src[base+(imm>>(2*lane)&3)]}
  else if name=="shufpd"{let src=if lane==0{a}else{b};src[base+(imm>>i&1)]}
  else if name=="pshufd"{a[base+(imm>>(2*lane)&3)]}
  else if name=="pshufhw"||name=="pshuflw"{let upper=name=="pshufhw";if (lane>=4)==upper{a[base+(if upper{4}else{0})+(imm>>(2*(lane%4))&3)]}else{a[i]}}
  else if name=="pshufb"{if b[i]&128!=0{0}else{a[base+(b[i]&15)as usize]}}
  else{let high=name.starts_with("unpckh")||name.starts_with("punpckh");let src=if i%2==0{a}else{b};src[base+(if high{per/2}else{0})+lane/2]}
 }).collect()
}
const REARRANGE:&[(&str,u8,bool)]=&[("shufps",32,true),("shufpd",64,true),("unpcklps",32,false),("unpckhps",32,false),("unpcklpd",64,false),("unpckhpd",64,false),("pshufd",32,true),("pshufhw",16,true),("pshuflw",16,true),("pshufb",8,false),("punpcklbw",8,false),("punpckhbw",8,false),("punpcklwd",16,false),("punpckhwd",16,false),("punpckldq",32,false),("punpckhdq",32,false),("punpcklqdq",64,false),("punpckhqdq",64,false),("shuff32x4",32,true),("shuff64x2",64,true),("shufi32x4",32,true),("shufi64x2",64,true)];
#[test]fn rearrange_all_immediates_lane_boundaries_aliases_and_mask_modes(){
 for &(name,w,immediate)in REARRANGE{let unary=matches!(name,"pshufd"|"pshufhw"|"pshuflw");let block=name.starts_with("shuff")||name.starts_with("shufi");
  for(vl,regname)in[(128,"xmm"),(256,"ymm"),(512,"zmm")]{if block&&vl==128{continue}let n=vl/usize::from(w);let mask=if w==64{u64::MAX}else{(1u64<<w)-1};
   let a:Vec<_>=(0..n).map(|i|(0xf123456789abcdefu64.wrapping_add(i as u64*0x13579))&mask).collect();let b:Vec<_>=(0..n).map(|i|if name=="pshufb"{[0,15,8,128,255,7,32,5][i%8]}else{(0x8123456789abcdefu64.wrapping_sub(i as u64*0x2468b))&mask}).collect();
   for imm in 0..if immediate{256}else{1}{let mut state=State::default();vector(&mut state,0,&pack_int_lanes(&a,w));vector(&mut state,1,&pack_int_lanes(&a,w));vector(&mut state,2,&pack_int_lanes(&b,w));
    let tail=if immediate{format!(", {imm}")}else{String::new()};let src=if unary{format!("{regname}1")}else{format!("{regname}1, {regname}2")};let modern=format!("v{name} {regname}0, {src}{tail}");let t=s::evaluate(&memory_recipe(&modern),&state).unwrap();let expected=rearrange_expected(name,w,vl,&a,&b,imm);
    for(i,&value)in expected.iter().enumerate(){assert_eq!(int_lane(&t,0,i,w),value,"{modern} lane{i}");}for chunk in vl/64..8{assert_eq!(vector_result(&t,0,chunk as u16),0)}
    if vl==128&&!block{let legacy=format!("{name} xmm0, xmm{}{tail}",if unary{1}else{2});let t=s::evaluate(&memory_recipe(&legacy),&state).unwrap();for(i,&value)in expected.iter().enumerate(){assert_eq!(int_lane(&t,0,i,w),value,"{legacy} lane{i}");}assert!(t.registers.iter().all(|w|w.register.bank!="x86.vector64"||w.register.index<2));}
    if imm%51==0{for alias in[false,true]{for zero in[false,true]{state.reg("x86.mask",1,0xaaaaaaaaaaaaaaaa);let src=if unary{format!("{regname}{}",if alias{0}else{1})}else{format!("{regname}{}, {regname}2",if alias{0}else{1})};let text=format!("v{name} {regname}0 {{k1}}{}, {src}{tail}",if zero{"{z}"}else{""});let t=s::evaluate(&memory_recipe(&text),&state).unwrap();for i in 0..n{assert_eq!(int_lane(&t,0,i,w),if i%2==1{expected[i]}else if zero{0}else{a[i]},"{text} lane{i}");}}}}
   }
  }
 }
}
struct RearrangeNoSources<'a>(&'a AccessState);
impl Machine for RearrangeNoSources<'_>{fn read_register(&self,r:s::Register)->Value{assert!(r.bank!="x86.vector64","inactive shuffle input read {r:?}");self.0.read_register(r)}fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.0.read_memory(a,w,e)}fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.0.read_wide_memory(a,w,e)}}
#[test]fn rearrange_nf_memory_broadcasts_empty_register_masks_and_legacy_alignment(){
 for &(name,w,immediate)in REARRANGE{let unary=matches!(name,"pshufd"|"pshufhw"|"pshuflw");let block=name.starts_with("shuff")||name.starts_with("shufi");
  for(vl,regname,memname)in[(128,"xmm","xmmword"),(256,"ymm","ymmword"),(512,"zmm","zmmword")]{if block&&vl==128{continue}let tail=if immediate{", 255"}else{""};let src=if unary{String::new()}else{format!("{regname}1, ")};let mut st=AccessState::new();st.state.x(0,0x8000);st.state.reg("x86.mask",1,0);for i in 0..vl/64{st.state.mem.insert(0x8000+i as u64*8,0x123456789abcdef0);}
   let text=format!("v{name} {regname}0 {{k1}}{{z}}, {src}{memname} ptr [rax]{tail}");let r=memory_recipe(&text);let t=s::evaluate(&r,&RearrangeNoSources(&st)).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x8000,vl)]);for i in 0..vl/64{assert_eq!(vector_result(&t,0,i),0)}
   st.reads.borrow_mut().clear();st.state.mem.remove(&0x8000);assert_eq!(s::evaluate(&r,&RearrangeNoSources(&st)),Err(EvalError::Memory),"{text}");
   let register=format!("v{name} {regname}0 {{k1}}{{z}}, {src}{regname}2{tail}");s::evaluate(&memory_recipe(&register),&RearrangeNoSources(&st)).unwrap();
   if w>=32&&!matches!(name,"pshufhw"|"pshuflw"|"pshufb"){let r=integer_broadcast(&text);st.state.mem.insert(0x8000,0x123456789abcdef0);st.reads.borrow_mut().clear();s::evaluate(&r,&RearrangeNoSources(&st)).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x8000,u16::from(w))]);}
   if vl==128&&!block{st.state.x(0,0x8001);st.reads.borrow_mut().clear();let legacy=format!("{name} xmm0, xmmword ptr [rax]{tail}");let t=s::evaluate(&memory_recipe(&legacy),&RearrangeNoSources(&st)).unwrap();assert_eq!(t.trap,Some(s::TrapKind::Protection));assert!(st.reads.borrow().is_empty());assert!(t.registers.is_empty());}
  }
 }
}
#[test]fn rearrange_catalog_all_forms_modes_physical_qualifications(){
 let mut count=0;for i in 0..encoding_count(){let e=encoding(i).unwrap();if !rearrange_family(e.mnemonic)||e.id.contains("_rq")||!SSE_AVX_FORMS.contains(&e.form_id){continue}let mut counted=false;for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{if !encoding_supports_mode(i,mode){continue}let mut bytes=[0;15];let n=encode_representative(i,mode,&mut bytes).unwrap_or_else(|err|panic!("{} {mode:?}: {err:?}",e.form_id));let d=decode(&bytes[..n],mode).unwrap();if !d.operands().iter().any(|o|o.register.is_some_and(|r|r.class==RegisterClass::Vector)){continue}if !counted{count+=1;counted=true;}let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{} {mode:?} {bytes:02x?}",e.form_id);r.validate().unwrap();
  if bytes[0]==0x62&&bytes[5]>>6==3{bytes[3]|=16;if let Ok(d)=decode(&bytes[..n],mode){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"reserved b bit {}",e.form_id)}}
 }}assert!(count>=150,"shuffle/unpack catalog only {count} forms");
}
`

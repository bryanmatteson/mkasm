package x86

const x86MaskCompareRecipeTests = `
const MASK_COMPARE:&[(&str,u8,u8)]=&[
 ("vpcmpb",8,0),("vpcmpw",16,0),("vpcmpd",32,0),("vpcmpq",64,0),
 ("vpcmpub",8,1),("vpcmpuw",16,1),("vpcmpud",32,1),("vpcmpuq",64,1),
 ("vpcmpeqb",8,2),("vpcmpeqw",16,2),("vpcmpeqd",32,2),("vpcmpeqq",64,2),
 ("vpcmpgtb",8,3),("vpcmpgtw",16,3),("vpcmpgtd",32,3),("vpcmpgtq",64,3),
 ("vptestmb",8,4),("vptestmw",16,4),("vptestmd",32,4),("vptestmq",64,4),
 ("vptestnmb",8,5),("vptestnmw",16,5),("vptestnmd",32,5),("vptestnmq",64,5),
];
fn mask_compare_expected(a:u64,b:u64,w:u8,form:u8,predicate:u8)->bool{
 let signed=|v:u64|((v<<(64-w))as i64)>>(64-w);
 let order=if form==0{signed(a).cmp(&signed(b))}else{a.cmp(&b)};
 match form{0|1=>match predicate{0=>order.is_eq(),1=>order.is_lt(),2=>order.is_le(),3=>false,4=>!order.is_eq(),5=>!order.is_lt(),6=>order.is_gt(),_=>true},2=>a==b,3=>signed(a)>signed(b),4=>a&b!=0,5=>a&b==0,_=>unreachable!()}
}
#[test]fn evex_integer_mask_comparisons_all_predicates_widths_mask_aliases_and_high_bits(){
 for &(name,w,form)in MASK_COMPARE{for(vl,regname)in[(128,"xmm"),(256,"ymm"),(512,"zmm")]{let lanes=vl/usize::from(w);let bits=if w==64{u64::MAX}else{(1u64<<w)-1};
  let a:Vec<_>=(0..lanes).map(|i|[0,1,bits,1u64<<(w-1),(1u64<<(w-1))-1,0x55&bits][i%6]).collect();let b:Vec<_>=(0..lanes).map(|i|[0,bits,1,(1u64<<(w-1))-1,1u64<<(w-1),0xaa&bits][i%6]).collect();
  for predicate in 0..if form<=1{8}else{1}{for alias in[false,true]{for dest in[0,1,3]{for mask in[0,1,2]{let mut st=State::default();vector(&mut st,1,&pack_int_lanes(&a,w));vector(&mut st,2,&pack_int_lanes(&b,w));for k in 0..8{st.reg("x86.mask",k,u64::MAX);}st.reg("x86.mask",1,0xaaaaaaaaaaaaaaaa);st.reg("x86.mask",2,0x5555555555555555);
   let text=format!("{name} k{dest}{}, {regname}1, {regname}{}{}",if mask==0{String::new()}else{format!(" {{k{mask}}}")},if alias{1}else{2},if form<=1{format!(", {predicate}")}else{String::new()});let t=s::evaluate(&memory_recipe(&text),&st).unwrap();let mut expected=0u64;
   for i in 0..lanes{let active=mask==0||(if mask==1{0xaaaaaaaaaaaaaaaau64}else{0x5555555555555555u64})>>i&1!=0;if active&&mask_compare_expected(a[i],if alias{a[i]}else{b[i]},w,form,predicate){expected|=1u64<<i;}}
   assert_eq!(reg(&t,"x86.mask",dest).bits,expected,"{text}");assert_eq!(t.registers.len(),1,"{text}");
  }}}}
 }}
}
#[test]fn integer_mask_comparisons_e4_accesses_broadcasts_empty_masks_and_constant_predicates(){
 for &(name,w,form)in MASK_COMPARE{for(vl,regname,memname)in[(128,"xmm","xmmword"),(256,"ymm","ymmword"),(512,"zmm","zmmword")]{let lanes=vl/usize::from(w);let bits=if w==64{u64::MAX}else{(1u64<<w)-1};
  let tail=if form<=1{", 0"}else{""};let mut st=AccessState::new();st.state.x(0,0x8000);st.state.reg("x86.mask",1,1|(1u64<<(lanes-1)));vector(&mut st.state,1,&pack_int_lanes(&vec![bits;lanes],w));st.state.mem.insert(0x8000,bits);st.state.mem.insert(0x8000+((lanes-1)*usize::from(w)/8)as u64,bits);
  let text=format!("{name} k1 {{k1}}, {regname}1, {memname} ptr [rax]{tail}");let r=memory_recipe(&text);let t=s::evaluate(&r,&st).unwrap();let expected=if mask_compare_expected(bits,bits,w,form,0){1|(1u64<<(lanes-1))}else{0};assert_eq!(reg(&t,"x86.mask",1).bits,expected,"{text}");assert_eq!(*st.reads.borrow(),vec![(0x8000,u16::from(w)),(0x8000+((lanes-1)*usize::from(w)/8)as u64,u16::from(w))]);
  st.state.mem.clear();assert_eq!(s::evaluate(&r,&st),Err(EvalError::Memory));st.state.reg("x86.mask",1,0);st.unknown_address=true;st.address_reads.set(0);st.reads.borrow_mut().clear();let t=s::evaluate(&r,&ShiftSources{state:&st,merge:false}).unwrap();assert_eq!(reg(&t,"x86.mask",1).bits,0);assert!(st.reads.borrow().is_empty());assert_eq!(st.address_reads.get(),0);
  let register=memory_recipe(&format!("{name} k1 {{k1}}, {regname}1, {regname}2{tail}"));s::evaluate(&register,&ShiftSources{state:&st,merge:false}).unwrap();
  if w>=32{let broadcast=integer_broadcast(&text);s::evaluate(&broadcast,&ShiftSources{state:&st,merge:false}).unwrap();assert_eq!(st.address_reads.get(),0);st.unknown_address=false;st.state.reg("x86.mask",1,1|(1u64<<(lanes-1)));st.state.mem.insert(0x8000,bits);st.reads.borrow_mut().clear();let t=s::evaluate(&broadcast,&st).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x8000,u16::from(w))]);assert_eq!(reg(&t,"x86.mask",1).bits,expected);}
  // A constant true/false predicate still reads active memory elements.
  if form<=1{for predicate in[3,7]{st.unknown_address=false;st.state.reg("x86.mask",1,1);st.state.mem.clear();let r=memory_recipe(&format!("{name} k0 {{k1}}, {regname}1, {memname} ptr [rax], {predicate}"));assert_eq!(s::evaluate(&r,&st),Err(EvalError::Memory));}}
 }}
}
#[test]fn integer_mask_comparison_catalog_modes_and_reserved_encodings(){
 let mut forms=0;for i in 0..encoding_count(){let e=encoding(i).unwrap();if !MASK_COMPARE.iter().any(|(name,_,_)|e.mnemonic.eq_ignore_ascii_case(name))||!SSE_AVX_FORMS.contains(&e.form_id){continue}let mut counted=false;
  for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{if !encoding_supports_mode(i,mode){continue}let mut bytes=[0;15];let n=encode_representative(i,mode,&mut bytes).unwrap();let d=decode(&bytes[..n],mode).unwrap();if d.operands().first().and_then(|o|o.register).is_none_or(|r|r.class!=RegisterClass::Mask){continue}if !counted{forms+=1;counted=true;}let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{} {mode:?}",e.form_id);r.validate().unwrap();
   let mut bad=bytes;bad[3]|=128;if let Ok(d)=decode(&bad[..n],mode){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"zeroing {}",e.form_id);}
   if bytes[5]>>6==3{let mut bad=bytes;bad[3]|=16;if let Ok(d)=decode(&bad[..n],mode){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"register b {}",e.form_id);}}
   if matches!(e.mnemonic,"VPCMPB"|"VPCMPUB"|"VPCMPW"|"VPCMPUW"|"VPCMPD"|"VPCMPUD"|"VPCMPQ"|"VPCMPUQ"){bytes[n-1]=8;if let Ok(d)=decode(&bytes[..n],mode){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"reserved predicate {}",e.form_id);}}
  }
 }assert_eq!(forms,144);
}
`

package x86

const x86MovementMigrationRecipeTests = `
const MOVEMENT_NAMES: &[&str] = &["MOVAPS", "MOVUPS", "MOVAPD", "MOVUPD", "MOVDQA", "MOVDQU", "MOVDQU64", "LDDQU", "MOVNTDQA", "MOVNTPS", "MOVNTPD", "MOVNTDQ", "MOVNTI", "MOVNTQ", "MOVD", "MOVQ", "MOVQ2DQ", "MOVDQ2Q", "MOVNTSS", "MOVNTSD", "MOVSS", "MOVSD", "MOVLPS", "MOVLPD", "MOVHPS", "MOVHPD", "MOVHLPS", "MOVLHPS", "MOVDDUP", "MOVSHDUP", "MOVSLDUP", "MASKMOVDQU", "MASKMOVQ", "PBROADCASTB", "PBROADCASTW", "PBROADCASTD", "PBROADCASTQ", "BROADCASTSS", "BROADCASTSD", "BROADCASTF128", "BROADCASTI128", "INSERTF128", "INSERTI128", "EXTRACTF128", "EXTRACTI128", "PERM2F128", "PERM2I128", "PERMD", "PERMPS", "PERMQ", "PERMPD", "PERMILPS", "PERMILPD", "SHUFPS", "SHUFPD", "UNPCKLPS", "UNPCKHPS", "UNPCKLPD", "UNPCKHPD", "BLENDPS", "BLENDPD", "BLENDVPS", "BLENDVPD", "ANDPS", "ANDPD", "ORPS", "ORPD", "XORPS", "XORPD", "ANDNPS", "ANDNPD", "INSERTPS", "EXTRACTPS", "PINSRB", "PINSRW", "PINSRD", "PINSRQ", "PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "MASKMOVPS", "MASKMOVPD", "PMASKMOVD", "PMASKMOVQ", "GATHERDPS", "GATHERDPD", "GATHERQPS", "GATHERQPD", "PGATHERDD", "PGATHERDQ", "PGATHERQD", "PGATHERQQ", "TESTPS", "TESTPD", "ZEROALL", "ZEROUPPER"];
#[test]
fn generated_movement_admits_every_supported_corpus_form() {
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64] {
  let mut covered=std::collections::HashSet::new();let mut count=0;let mut declined=Vec::new();
  for index in 0..encoding_count(){let e=encoding(index).unwrap();let name=e.mnemonic.strip_prefix('V').unwrap_or(e.mnemonic);
   if !MOVEMENT_NAMES.contains(&name)||!SSE_AVX_FORMS.contains(&e.form_id)||!encoding_supports_mode(index,mode){continue;}
   let mut bytes=[0;15];let len=encode_representative(index,mode,&mut bytes).unwrap_or_else(|error|panic!("{mode:?} {}: {error:?}",e.form_id));
   let decoded=decode(&bytes[..len],mode).unwrap();
   if name=="MOVSD"&&decoded.operands().iter().all(|o|o.implicit){continue;}
   let r=decoded.semantic_recipe(0x1000);covered.insert(name);if r.support!=Support::Full{declined.push(format!("{}: {:?}",e.form_id,r.support));continue;}if let Err(error)=r.validate(){declined.push(format!("{}: {error:?}",e.form_id));continue;}count+=1;
  }
  assert!(declined.is_empty(),"{mode:?} declined movement corpus forms: {declined:?}");
  assert_eq!(covered,MOVEMENT_NAMES.iter().copied().filter(|name|mode==Mode::Mode64||!matches!(*name,"PINSRQ"|"PEXTRQ")).collect());println!("generated movement {mode:?}: {count} public corpus witnesses");
 }
}
fn movement_reg(t:&Transition,bank:&str,n:u16)->Value{t.registers.iter().rev().find(|w|w.register.bank==bank&&w.register.index==n).unwrap().value}
struct GatherState{state:State,reads:std::cell::RefCell<Vec<(u64,u8)>>,fault:Option<u64>}
impl Machine for GatherState{
 fn read_register(&self,r:s::Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.reads.borrow_mut().push((a,w));if self.fault==Some(a){Err(EvalError::MemoryFault(s::MemoryFaultKind::Translation))}else{self.state.read_memory(a,w,e)}}
}
fn commit_gather(state:&mut State,t:&Transition){for write in &t.registers{state.reg(write.register.bank,write.register.index,write.value.bits);}}
#[test]
fn generated_gather_public_fault_transition_resumes_only_remaining_lanes(){
 // vgatherdps xmm0,[rax+xmm1*4+8],xmm2
 let bytes=[0xc4,0xe2,0x69,0x92,0x44,0x88,8];
 let d=decode(&bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();
 let mut st=GatherState{state:State::default(),reads:Default::default(),fault:Some(0x200c)};
 st.state.x(0,0x2000);vector(&mut st.state,0,&[0x2222222211111111,0x4444444433333333,99,99]);vector(&mut st.state,1,&[1u64<<32,3u64<<32|2]);vector(&mut st.state,2,&[0x8000000080000000,0x8000000080000000,99,99]);
 for lane in 0..4{st.state.mem.insert(0x2008+lane*4,100+lane);}
 let failure=s::evaluate_with_progress(&r,&st).unwrap_err();assert_eq!(failure.error,EvalError::MemoryFault(s::MemoryFaultKind::Translation));let published=failure.published.unwrap();
 assert_eq!(published.next_pc.bits,0x1000);assert_eq!(movement_reg(&published,"x86.vector64",0).bits,0x2222222200000064);assert_eq!(movement_reg(&published,"x86.vector64",16).bits,0xffffffff00000000);assert_eq!(*st.reads.borrow(),vec![(0x2008,32),(0x200c,32)]);
 commit_gather(&mut st.state,&published);st.fault=None;st.reads.borrow_mut().clear();let completed=s::evaluate_with_progress(&r,&st).unwrap();
 assert_eq!(movement_reg(&completed,"x86.vector64",0).bits,101u64<<32|100);assert_eq!(movement_reg(&completed,"x86.vector64",1).bits,103u64<<32|102);assert_eq!(movement_reg(&completed,"x86.vector64",16).bits,0);assert_eq!(completed.next_pc.bits,0x1007);assert_eq!(*st.reads.borrow(),vec![(0x200c,32),(0x2010,32),(0x2014,32)]);
}
#[test]
fn generated_evex_gather_clears_mask_progress_and_suppresses_inactive_addresses(){
 let bytes=[0x62,0xf2,0x7d,0x49,0x92,0x0c,0x90]; // vgatherdps zmm1{k1},[rax+zmm2*4]
 let d=decode(&bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x3000);assert_eq!(r.support,Support::Full);r.validate().unwrap();
 let mut st=GatherState{state:State::default(),reads:Default::default(),fault:Some(0x2004)};
 st.state.x(0,0x2000);vector(&mut st.state,1,&[0xaaaaaaaaaaaaaaaa;8]);vector(&mut st.state,2,&[1u64<<32,3u64<<32|2,0,0,0,0,0,0]);st.state.reg("x86.mask",1,0xffff000000000003);st.state.mem.insert(0x2000,42);
 let f=s::evaluate_with_progress(&r,&st).unwrap_err();let t=f.published.unwrap();assert_eq!(movement_reg(&t,"x86.mask",1).bits,2);assert_eq!(movement_reg(&t,"x86.vector64",8).bits,0xaaaaaaaa0000002a);assert_eq!(t.next_pc.bits,0x3000);
 let mut empty=AccessState::new();empty.unknown_address=true;empty.state.reg("x86.mask",1,0);let t=s::evaluate_with_progress(&r,&empty).unwrap();assert!(empty.reads.borrow().is_empty());assert_eq!(empty.address_reads.get(),0);assert_eq!(movement_reg(&t,"x86.mask",1).bits,0);
}
#[test]
fn generated_movement_masked_duplicate_reads_only_selected_source_elements_once(){
 let mut st=AccessState::new();st.state.x(0,0x4000);st.state.mem.insert(0x4000,0x12345678);st.state.reg("x86.mask",1,3);
 let t=memory_eval("vmovddup zmm0 {k1}, zmmword ptr [rax]",&st);assert_eq!(movement_reg(&t,"x86.vector64",0).bits,0x12345678);assert_eq!(movement_reg(&t,"x86.vector64",1).bits,0x12345678);assert_eq!(*st.reads.borrow(),vec![(0x4000,64)]);
 st.state.reg("x86.mask",1,0);st.unknown_address=true;st.reads.borrow_mut().clear();st.address_reads.set(0);memory_eval("vmovddup zmm0 {k1}, zmmword ptr [rax]",&st);assert!(st.reads.borrow().is_empty());assert_eq!(st.address_reads.get(),0);
}

#[test]
fn generated_vzero_clears_complete_zmm_storage_and_preserves_the_other_registers(){
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64]{for all in [false,true]{
  let bytes=[0xc5,if all{0xfc}else{0xf8},0x77];let d=decode(&bytes,mode).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();
  let mut state=State::default();for n in 0..32{vector(&mut state,n,&[u64::MAX;8]);}let t=s::evaluate(&r,&state).unwrap();
  let limit=if mode==Mode::Mode64{16}else{8};let start=if all{0}else{2};assert_eq!(t.registers.len(),limit*(8-start));
  for n in 0..32usize{for chunk in 0..8usize{let write=t.registers.iter().rev().find(|w|w.register.bank=="x86.vector64"&&usize::from(w.register.index)==n*8+chunk);
   if n<limit&&chunk>=start{assert_eq!(write.unwrap().value,Value::known(64,0));}else{assert!(write.is_none());}
  }}
 }}
}

#[test]
fn generated_movement_masked_byte_stores_follow_each_source_and_mask_byte(){
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64]{for vex in [false,true]{
  let bytes=if vex{vec![0xc5,0xf9,0xf7,0xca]}else{vec![0x66,0x0f,0xf7,0xca]};
  let d=decode(&bytes,mode).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();
  let mut st=State::default();st.x(7,0x4000);vector(&mut st,1,&[0x0807060504030201,0x100f0e0d0c0b0a09]);vector(&mut st,2,&[0x0080008000800080,0x0080008000800080]);
  let t=s::evaluate(&r,&st).unwrap();let expected:Vec<_>=(0..16).filter(|n|n%2==0).map(|n|(0x4000+n,Value::known(8,n+1))).collect();
  let actual:Vec<_>=t.memory.iter().map(|w|(w.address,w.value)).collect();assert_eq!(actual,expected,"{mode:?} vex={vex}: {:?}",d.operands());
 }}
}
`

package x86

// Array/scalar host oracles exercise actual public decoder bytes across the
// whole packed variable shift and rotate category, not synthetic recipe nodes.
const x86VariableShiftRecipeTests = `
const VARIABLE_SHIFT:&[(&str,u8,u8,bool)]=&[
 ("vpsllvw",16,0,false),("vpsllvd",32,0,false),("vpsllvq",64,0,false),
 ("vpsrlvw",16,1,false),("vpsrlvd",32,1,false),("vpsrlvq",64,1,false),
 ("vpsravw",16,2,false),("vpsravd",32,2,false),("vpsravq",64,2,false),
 ("vprolvd",32,3,false),("vprolvq",64,3,false),("vprorvd",32,4,false),("vprorvq",64,4,false),
 ("vprold",32,3,true),("vprolq",64,3,true),("vprord",32,4,true),("vprorq",64,4,true),
];
fn variable_shift_expected(a:u64,n:u64,w:u8,operation:u8)->u64{
 let mask=if w==64{u64::MAX}else{(1u64<<w)-1};let a=a&mask;
 match operation{
  0=>if n>=u64::from(w){0}else{(a<<n)&mask},
  1=>if n>=u64::from(w){0}else{a>>n},
  2=>{let signed=((a<<(64-w))as i64)>>(64-w);(signed>>(n.min(u64::from(w-1))))as u64&mask},
  3|4=>{let n=n%u64::from(w);if n==0{a}else if operation==3{((a<<n)|(a>>(u64::from(w)-n)))&mask}else{((a>>n)|(a<<(u64::from(w)-n)))&mask}},
  _=>unreachable!(),
 }
}
#[test]fn packed_variable_shift_rotate_all_counts_widths_masks_and_source_aliases(){
 for &(name,w,operation,immediate) in VARIABLE_SHIFT{for(vl,regname)in[(128,"xmm"),(256,"ymm"),(512,"zmm")]{
  let count=vl/usize::from(w);let mask=if w==64{u64::MAX}else{(1u64<<w)-1};
  let a:Vec<_>=(0..count).map(|i|[mask,1,1u64<<(w-1),0,0x123456789abcdef0&mask][i%5]).collect();
  for n in (0..256).chain([u64::MAX,1<<63,1<<32]){if immediate&&n>255{continue}let b:Vec<_>=(0..count).map(|i|n.wrapping_add(if n<256{i as u64%3}else{0})&mask).collect();
   let aliases: &[u8]=if n<256&&n%31!=0{&[0]}else{&[0,1,2]};
   for &alias in aliases{if alias==2&&immediate{continue}let prior=if alias==2{&b}else{&a};let mut st=State::default();vector(&mut st,0,&pack_int_lanes(prior,w));vector(&mut st,1,&pack_int_lanes(&a,w));vector(&mut st,2,&pack_int_lanes(&b,w));st.reg("x86.mask",1,0xaaaaaaaaaaaaaaaa);
    let src=if immediate{format!("{regname}{}, {n}",if alias==1{0}else{1})}else{format!("{regname}{}, {regname}{}",if alias==1{0}else{1},if alias==2{0}else{2})};
    let modes:&[u8]=if n<256&&n%31!=0{&[0]}else{&[0,1,2]};
    for &mode in modes{let text=format!("{name} {regname}0{}, {src}",match mode{1=>" {k1}",2=>" {k1}{z}",_=>""});let t=s::evaluate(&memory_recipe(&text),&st).unwrap();
     for lane in 0..count{let expected=if mode!=0&&lane%2==0{if mode==2{0}else{prior[lane]}}else{variable_shift_expected(a[lane],if immediate{n}else{b[lane]},w,operation)};assert_eq!(int_lane(&t,0,lane,w),expected,"{text} alias{alias} lane{lane}");}
     for chunk in vl/64..8{assert_eq!(vector_result(&t,0,chunk as u16),0,"{text} upper");}assert!(t.registers.iter().all(|r|r.register.bank=="x86.vector64"));
    }
   }
  }
 }}
}
struct ShiftSources<'a>{state:&'a AccessState,merge:bool}
impl Machine for ShiftSources<'_>{
 fn read_register(&self,r:s::Register)->Value{if r.bank=="x86.vector64"{assert!(self.merge&&r.index<8,"inactive packed shift read {r:?}");}self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:s::Endian)->Result<Value,EvalError>{self.state.read_memory(a,w,e)}
 fn read_wide_memory(&self,a:u64,w:u16,e:s::Endian)->Result<Vec<Value>,EvalError>{self.state.read_wide_memory(a,w,e)}
}
#[test]fn packed_variable_shifts_rotate_e4_memory_suppression_broadcasts_and_dependencies(){
 for &(name,w,operation,immediate)in VARIABLE_SHIFT{for(vl,regname,memname)in[(128,"xmm","xmmword"),(256,"ymm","ymmword"),(512,"zmm","zmmword")]{
  let lanes=vl/usize::from(w);let bits=if w==64{u64::MAX}else{(1u64<<w)-1};let values:Vec<_>=(0..lanes).map(|i|if immediate{bits.wrapping_sub(i as u64)}else{[0,1,u64::from(w),bits][i%4]}).collect();
  let a:Vec<_>=(0..lanes).map(|i|bits.wrapping_sub(i as u64)&bits).collect();let mut st=AccessState::new();st.state.x(0,0x8000);vector(&mut st.state,1,&pack_int_lanes(&a,w));vector(&mut st.state,0,&pack_int_lanes(&a,w));st.state.reg("x86.mask",1,1|(1u64<<(lanes-1)));
  for &i in &[0,lanes-1]{st.state.mem.insert(0x8000+(i*usize::from(w)/8)as u64,values[i]);}
  let src=if immediate{format!("{memname} ptr [rax], 255")}else{format!("{regname}1, {memname} ptr [rax]")};let text=format!("{name} {regname}0 {{k1}}{{z}}, {src}");let r=memory_recipe(&text);let t=s::evaluate(&r,&st).unwrap();
  assert_eq!(*st.reads.borrow(),vec![(0x8000,u16::from(w)),(0x8000+((lanes-1)*usize::from(w)/8)as u64,u16::from(w))],"{text}");
  for i in 0..lanes{assert_eq!(int_lane(&t,0,i,w),if i==0||i==lanes-1{variable_shift_expected(if immediate{values[i]}else{a[i]},if immediate{255}else{values[i]},w,operation)}else{0},"{text} lane{i}");}
  // One selected inaccessible element faults; the same inaccessible address
  // becomes irrelevant when its mask bit and every other bit are clear.
  st.state.mem.clear();assert_eq!(s::evaluate(&r,&st),Err(EvalError::Memory));st.state.reg("x86.mask",1,0);st.unknown_address=true;st.address_reads.set(0);st.reads.borrow_mut().clear();s::evaluate(&r,&ShiftSources{state:&st,merge:false}).unwrap();assert!(st.reads.borrow().is_empty());assert_eq!(st.address_reads.get(),0);
  for merge in [false,true]{let src=if immediate{format!("{regname}1, 255")}else{format!("{regname}1, {regname}2")};let text=format!("{name} {regname}0 {{k1}}{}, {src}",if merge{""}else{"{z}"});let t=s::evaluate(&memory_recipe(&text),&ShiftSources{state:&st,merge}).unwrap();for i in 0..lanes{assert_eq!(int_lane(&t,0,i,w),if merge{a[i]}else{0});}}
  if w>=32{let broadcast=integer_broadcast(&text);s::evaluate(&broadcast,&ShiftSources{state:&st,merge:false}).unwrap();assert_eq!(st.address_reads.get(),0);st.unknown_address=false;st.state.reg("x86.mask",1,1|(1u64<<(lanes-1)));st.state.mem.insert(0x8000,values[0]);st.reads.borrow_mut().clear();let t=s::evaluate(&broadcast,&st).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x8000,u16::from(w))]);for i in[0,lanes-1]{assert_eq!(int_lane(&t,0,i,w),variable_shift_expected(if immediate{values[0]}else{a[i]},if immediate{255}else{values[0]},w,operation));}}
  // Unmasked forms retain one access of the complete original vector width.
  st.state.reg("x86.mask",1,0);st.unknown_address=false;st.state.mem.clear();for(i,v)in pack_int_lanes(&values,w).into_iter().enumerate(){st.state.mem.insert(0x8000+i as u64*8,v);}st.reads.borrow_mut().clear();let text=format!("{name} {regname}0, {src}");s::evaluate(&memory_recipe(&text),&st).unwrap();assert_eq!(*st.reads.borrow(),vec![(0x8000,vl as u16)]);
 }}
}
#[test]fn packed_variable_shifts_rotate_catalog_all_forms_and_reserved_decorators(){
 let mut forms=0;for i in 0..encoding_count(){let e=encoding(i).unwrap();if !VARIABLE_SHIFT.iter().any(|(name,_,_,_)|e.mnemonic.eq_ignore_ascii_case(name))||!SSE_AVX_FORMS.contains(&e.form_id){continue}forms+=1;
  for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{if !encoding_supports_mode(i,mode){continue}let mut bytes=[0;15];let n=encode_representative(i,mode,&mut bytes).unwrap();let d=decode(&bytes[..n],mode).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{} {mode:?} {bytes:02x?}",e.form_id);r.validate().unwrap();
   if bytes[0]==0x62&&bytes[5]>>6==3{bytes[3]|=16;if let Ok(d)=decode(&bytes[..n],mode){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"reserved b: {}",e.form_id);}}
  }
 }assert!(forms>=120,"only {forms} packed variable shift/rotate forms");
}
`

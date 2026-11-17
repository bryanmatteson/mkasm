//! SVE first-fault and non-fault loads from the June 2026 A64 corpus.
//! Reads retain lane order and architectural width. The first active LDFF1
//! lane faults normally; subsequent active lanes and all LDNF1 lanes use the
//! explicit recoverable-read capability. Choose NONFAULT=false unless an
//! architectural fault occurs, and the permitted zero result after FFR becomes
//! false. CurrentVL backing above the active vector/predicate length is kept.
use super::*;
use BinaryOp as B;
#[derive(Clone,Copy)]
struct Shape { mask:u32,value:u32,element:u8,memory:u8,offset:u8,scale:u8,mode:u8,signed:bool,offset_signed:bool }
const SHAPES:&[Shape]=&[
 Shape{mask:0xffe0e000,value:0xc420e000,element:64,memory:8,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1b_z_p_ai_d
 Shape{mask:0xffe0e000,value:0x8420e000,element:32,memory:8,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1b_z_p_ai_s
 Shape{mask:0xffe0e000,value:0xa4206000,element:16,memory:8,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1b_z_p_br_u16
 Shape{mask:0xffe0e000,value:0xa4406000,element:32,memory:8,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1b_z_p_br_u32
 Shape{mask:0xffe0e000,value:0xa4606000,element:64,memory:8,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1b_z_p_br_u64
 Shape{mask:0xffe0e000,value:0xa4006000,element:8,memory:8,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1b_z_p_br_u8
 Shape{mask:0xffe0e000,value:0xc440e000,element:64,memory:8,offset:64,scale:0,mode:0,signed:false,offset_signed:false}, // ldff1b_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc4006000,element:64,memory:8,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1b_z_p_bz_d_x32_unscaled
 Shape{mask:0xffa0e000,value:0x84006000,element:32,memory:8,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1b_z_p_bz_s_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc5a0e000,element:64,memory:64,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1d_z_p_ai_d
 Shape{mask:0xffe0e000,value:0xa5e06000,element:64,memory:64,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1d_z_p_br_u64
 Shape{mask:0xffe0e000,value:0xc5e0e000,element:64,memory:64,offset:64,scale:3,mode:0,signed:false,offset_signed:false}, // ldff1d_z_p_bz_d_64_scaled
 Shape{mask:0xffe0e000,value:0xc5c0e000,element:64,memory:64,offset:64,scale:0,mode:0,signed:false,offset_signed:false}, // ldff1d_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc5a06000,element:64,memory:64,offset:32,scale:3,mode:0,signed:false,offset_signed:true}, // ldff1d_z_p_bz_d_x32_scaled
 Shape{mask:0xffa0e000,value:0xc5806000,element:64,memory:64,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1d_z_p_bz_d_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc4a0e000,element:64,memory:16,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1h_z_p_ai_d
 Shape{mask:0xffe0e000,value:0x84a0e000,element:32,memory:16,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1h_z_p_ai_s
 Shape{mask:0xffe0e000,value:0xa4a06000,element:16,memory:16,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1h_z_p_br_u16
 Shape{mask:0xffe0e000,value:0xa4c06000,element:32,memory:16,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1h_z_p_br_u32
 Shape{mask:0xffe0e000,value:0xa4e06000,element:64,memory:16,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1h_z_p_br_u64
 Shape{mask:0xffe0e000,value:0xc4e0e000,element:64,memory:16,offset:64,scale:1,mode:0,signed:false,offset_signed:false}, // ldff1h_z_p_bz_d_64_scaled
 Shape{mask:0xffe0e000,value:0xc4c0e000,element:64,memory:16,offset:64,scale:0,mode:0,signed:false,offset_signed:false}, // ldff1h_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc4a06000,element:64,memory:16,offset:32,scale:1,mode:0,signed:false,offset_signed:true}, // ldff1h_z_p_bz_d_x32_scaled
 Shape{mask:0xffa0e000,value:0xc4806000,element:64,memory:16,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1h_z_p_bz_d_x32_unscaled
 Shape{mask:0xffa0e000,value:0x84a06000,element:32,memory:16,offset:32,scale:1,mode:0,signed:false,offset_signed:true}, // ldff1h_z_p_bz_s_x32_scaled
 Shape{mask:0xffa0e000,value:0x84806000,element:32,memory:16,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1h_z_p_bz_s_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc420a000,element:64,memory:8,offset:0,scale:0,mode:1,signed:true,offset_signed:false}, // ldff1sb_z_p_ai_d
 Shape{mask:0xffe0e000,value:0x8420a000,element:32,memory:8,offset:0,scale:0,mode:1,signed:true,offset_signed:false}, // ldff1sb_z_p_ai_s
 Shape{mask:0xffe0e000,value:0xa5c06000,element:16,memory:8,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sb_z_p_br_s16
 Shape{mask:0xffe0e000,value:0xa5a06000,element:32,memory:8,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sb_z_p_br_s32
 Shape{mask:0xffe0e000,value:0xa5806000,element:64,memory:8,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sb_z_p_br_s64
 Shape{mask:0xffe0e000,value:0xc440a000,element:64,memory:8,offset:64,scale:0,mode:0,signed:true,offset_signed:false}, // ldff1sb_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc4002000,element:64,memory:8,offset:32,scale:0,mode:0,signed:true,offset_signed:true}, // ldff1sb_z_p_bz_d_x32_unscaled
 Shape{mask:0xffa0e000,value:0x84002000,element:32,memory:8,offset:32,scale:0,mode:0,signed:true,offset_signed:true}, // ldff1sb_z_p_bz_s_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc4a0a000,element:64,memory:16,offset:0,scale:0,mode:1,signed:true,offset_signed:false}, // ldff1sh_z_p_ai_d
 Shape{mask:0xffe0e000,value:0x84a0a000,element:32,memory:16,offset:0,scale:0,mode:1,signed:true,offset_signed:false}, // ldff1sh_z_p_ai_s
 Shape{mask:0xffe0e000,value:0xa5206000,element:32,memory:16,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sh_z_p_br_s32
 Shape{mask:0xffe0e000,value:0xa5006000,element:64,memory:16,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sh_z_p_br_s64
 Shape{mask:0xffe0e000,value:0xc4e0a000,element:64,memory:16,offset:64,scale:1,mode:0,signed:true,offset_signed:false}, // ldff1sh_z_p_bz_d_64_scaled
 Shape{mask:0xffe0e000,value:0xc4c0a000,element:64,memory:16,offset:64,scale:0,mode:0,signed:true,offset_signed:false}, // ldff1sh_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc4a02000,element:64,memory:16,offset:32,scale:1,mode:0,signed:true,offset_signed:true}, // ldff1sh_z_p_bz_d_x32_scaled
 Shape{mask:0xffa0e000,value:0xc4802000,element:64,memory:16,offset:32,scale:0,mode:0,signed:true,offset_signed:true}, // ldff1sh_z_p_bz_d_x32_unscaled
 Shape{mask:0xffa0e000,value:0x84a02000,element:32,memory:16,offset:32,scale:1,mode:0,signed:true,offset_signed:true}, // ldff1sh_z_p_bz_s_x32_scaled
 Shape{mask:0xffa0e000,value:0x84802000,element:32,memory:16,offset:32,scale:0,mode:0,signed:true,offset_signed:true}, // ldff1sh_z_p_bz_s_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc520a000,element:64,memory:32,offset:0,scale:0,mode:1,signed:true,offset_signed:false}, // ldff1sw_z_p_ai_d
 Shape{mask:0xffe0e000,value:0xa4806000,element:64,memory:32,offset:0,scale:0,mode:2,signed:true,offset_signed:false}, // ldff1sw_z_p_br_s64
 Shape{mask:0xffe0e000,value:0xc560a000,element:64,memory:32,offset:64,scale:2,mode:0,signed:true,offset_signed:false}, // ldff1sw_z_p_bz_d_64_scaled
 Shape{mask:0xffe0e000,value:0xc540a000,element:64,memory:32,offset:64,scale:0,mode:0,signed:true,offset_signed:false}, // ldff1sw_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc5202000,element:64,memory:32,offset:32,scale:2,mode:0,signed:true,offset_signed:true}, // ldff1sw_z_p_bz_d_x32_scaled
 Shape{mask:0xffa0e000,value:0xc5002000,element:64,memory:32,offset:32,scale:0,mode:0,signed:true,offset_signed:true}, // ldff1sw_z_p_bz_d_x32_unscaled
 Shape{mask:0xffe0e000,value:0xc520e000,element:64,memory:32,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1w_z_p_ai_d
 Shape{mask:0xffe0e000,value:0x8520e000,element:32,memory:32,offset:0,scale:0,mode:1,signed:false,offset_signed:false}, // ldff1w_z_p_ai_s
 Shape{mask:0xffe0e000,value:0xa5406000,element:32,memory:32,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1w_z_p_br_u32
 Shape{mask:0xffe0e000,value:0xa5606000,element:64,memory:32,offset:0,scale:0,mode:2,signed:false,offset_signed:false}, // ldff1w_z_p_br_u64
 Shape{mask:0xffe0e000,value:0xc560e000,element:64,memory:32,offset:64,scale:2,mode:0,signed:false,offset_signed:false}, // ldff1w_z_p_bz_d_64_scaled
 Shape{mask:0xffe0e000,value:0xc540e000,element:64,memory:32,offset:64,scale:0,mode:0,signed:false,offset_signed:false}, // ldff1w_z_p_bz_d_64_unscaled
 Shape{mask:0xffa0e000,value:0xc5206000,element:64,memory:32,offset:32,scale:2,mode:0,signed:false,offset_signed:true}, // ldff1w_z_p_bz_d_x32_scaled
 Shape{mask:0xffa0e000,value:0xc5006000,element:64,memory:32,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1w_z_p_bz_d_x32_unscaled
 Shape{mask:0xffa0e000,value:0x85206000,element:32,memory:32,offset:32,scale:2,mode:0,signed:false,offset_signed:true}, // ldff1w_z_p_bz_s_x32_scaled
 Shape{mask:0xffa0e000,value:0x85006000,element:32,memory:32,offset:32,scale:0,mode:0,signed:false,offset_signed:true}, // ldff1w_z_p_bz_s_x32_unscaled
 Shape{mask:0xfff0e000,value:0xa430a000,element:16,memory:8,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1b_z_p_bi_u16
 Shape{mask:0xfff0e000,value:0xa450a000,element:32,memory:8,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1b_z_p_bi_u32
 Shape{mask:0xfff0e000,value:0xa470a000,element:64,memory:8,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1b_z_p_bi_u64
 Shape{mask:0xfff0e000,value:0xa410a000,element:8,memory:8,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1b_z_p_bi_u8
 Shape{mask:0xfff0e000,value:0xa5f0a000,element:64,memory:64,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1d_z_p_bi_u64
 Shape{mask:0xfff0e000,value:0xa4b0a000,element:16,memory:16,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1h_z_p_bi_u16
 Shape{mask:0xfff0e000,value:0xa4d0a000,element:32,memory:16,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1h_z_p_bi_u32
 Shape{mask:0xfff0e000,value:0xa4f0a000,element:64,memory:16,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1h_z_p_bi_u64
 Shape{mask:0xfff0e000,value:0xa5d0a000,element:16,memory:8,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sb_z_p_bi_s16
 Shape{mask:0xfff0e000,value:0xa5b0a000,element:32,memory:8,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sb_z_p_bi_s32
 Shape{mask:0xfff0e000,value:0xa590a000,element:64,memory:8,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sb_z_p_bi_s64
 Shape{mask:0xfff0e000,value:0xa530a000,element:32,memory:16,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sh_z_p_bi_s32
 Shape{mask:0xfff0e000,value:0xa510a000,element:64,memory:16,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sh_z_p_bi_s64
 Shape{mask:0xfff0e000,value:0xa490a000,element:64,memory:32,offset:0,scale:0,mode:3,signed:true,offset_signed:false}, // ldnf1sw_z_p_bi_s64
 Shape{mask:0xfff0e000,value:0xa550a000,element:32,memory:32,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1w_z_p_bi_u32
 Shape{mask:0xfff0e000,value:0xa570a000,element:64,memory:32,offset:0,scale:0,mode:3,signed:false,offset_signed:false}, // ldnf1w_z_p_bi_u64
];
fn c(width:u8,value:u64)->Expr {Expr::constant(width,value)}
fn b(op:B,left:Expr,right:Expr)->Expr {Expr::binary(op,left,right)}
fn inv(value:Expr)->Expr {Expr::unary(UnaryOp::Not,value)}
fn pred(chunk:u16,n:u32)->Expr {Expr::register(register("a64.predicate64",n as u16*4+chunk,64,64))}
fn zlane(n:u32,e:u16,width:u8)->Expr {
 let bit=e*u16::from(width);
 Expr::extract(Expr::register(register("a64.vector64",n as u16*32+bit/64,64,64)),(bit%64)as u8,width)
}
fn low_mask(bits:u16)->u64 {if bits>=64 {u64::MAX}else{(1u64<<bits)-1}}
fn or_all(mut values:Vec<Expr>)->Expr {
 if values.is_empty(){return c(64,0);}
 while values.len()>1 {values=values.chunks(2).map(|v|if v.len()==2{b(B::Or,v[0].clone(),v[1].clone())}else{v[0].clone()}).collect();}
 values.pop().unwrap()
}
fn prefix(r:&mut Recipe,bitmaps:&[Expr])->Vec<Expr> {
 let mut previous=c(1,0);let mut result=Vec::new();
 for bitmap in bitmaps {
  // -(x & -x) sets every bit at or above the first failure, with zero
  // remaining zero. This avoids expanding a six-stage shift prefix when the
  // native graph is reconstructed for validation.
  let spread=r.bind(Expr::unary(UnaryOp::Neg,b(B::And,bitmap.clone(),Expr::unary(UnaryOp::Neg,bitmap.clone()))));
  let full=r.bind(Expr::select(previous.clone(),c(64,u64::MAX),spread));
  previous=r.bind(inv(b(B::Eq,full.clone(),c(64,0))));result.push(full);
 }
 result
}
/// All 60 LDFF1 and 16 LDNF1 physical classes. Memory capabilities must honor
/// the instruction's non-fault access policy before performing Device reads;
/// the generated Machine interface rejects that capability by default.
pub fn a64(word:u32,address:u64,endian:Endian,vl:u16)->Option<Recipe> {
 if !(128..=2048).contains(&vl)||!vl.is_power_of_two(){return None;}
 let s=*SHAPES.iter().find(|s|word&s.mask==s.value)?;
 let d=word&31;let n=(word>>5)&31;let pg=(word>>10)&7;let m=(word>>16)&31;
 let elements=vl/u16::from(s.element);let pbits=vl/8;let chunks=pbits.div_ceil(64);
 let bytes=u16::from(s.element)/8;let mut element_mask=0u64;
 for bit in (0..64).step_by(usize::from(bytes)){element_mask|=1<<bit;}
 let mut r=Recipe::new(address.wrapping_add(4),64);
 let sm=Expr::extract(Expr::register(register("a64.svcr",0,64,64)),0,1);
 r.guard=Expr::require_context(Expr::select(sm,Expr::register(register("a64.sme_fa64",0,1,1)),c(1,1)),"first-fault/non-fault SVE loads require non-streaming mode or effective FA64");
 let selected=(0..chunks).map(|chunk| {
  let width=(pbits-chunk*64).min(64) as u8;
  let incoming=Expr::cast(Expr::register(RegisterSlice {width,..register("a64.predicate64",pg as u16*4+chunk,64,64)}),64,false);
  b(B::And,incoming,c(64,element_mask&low_mask(pbits-chunk*64)))
 }).collect::<Vec<_>>();
 if s.mode!=1 && n==31 {
  let any=inv(b(B::Eq,or_all(selected.clone()),c(64,0)));
  let aligned=b(B::Eq,b(B::And,Expr::register(register("a64.sp",0,64,64)),c(64,15)),c(64,0));
  r.guard=b(B::And,r.guard,Expr::require_context(Expr::select(any,aligned,c(1,1)),"active SVE SP access requires alignment or an explicit SP-alignment policy"));
 }
 // AddressAdd invokes checked pointer arithmetic. Until that address policy
 // is represented here, reject active checked-pointer contexts explicitly.
 // Inactive predicates need neither an address nor an available CPTA input.
 let any=inv(b(B::Eq,or_all(selected.clone()),c(64,0)));
 let unchecked=b(B::Eq,Expr::register(register("a64.cpta",0,1,1)),c(1,0));
 r.guard=b(B::And,r.guard,Expr::require_context(Expr::select(any,unchecked,c(1,1)),"SVE fault loads require unchecked address arithmetic"));
 let base=Expr::register(register(if n==31{"a64.sp"}else{"a64.gpr"},if n==31{0}else{n as u16},64,64));
 // Predicate captures precede the ordered read stream and all architectural
 // writes. They are the instruction's incoming mask, shared by read guards,
 // failure bitmap construction and final values without expanding per use.
 let selected=selected.into_iter().map(|value|r.bind_before_reads(value).ok()).collect::<Option<Vec<_>>>()?;
 let mut predicates=Vec::new();
 for e in 0..elements {
  let bit=e*bytes;let chunk=bit/64;let position=(bit%64)as u8;
  let active=Expr::extract(selected[usize::from(chunk)].clone(),position,1);
  let seen=if s.mode==3{c(1,0)}else{
   let earlier=(0..=chunk).map(|part|b(B::And,selected[usize::from(part)].clone(),c(64,if part==chunk{low_mask(bit%64)}else{u64::MAX}))).collect();
   r.bind_before_reads(inv(b(B::Eq,or_all(earlier),c(64,0)))).ok()?
  };
  predicates.push((active,seen));
 }
 // Contiguous first-fault loads need exactly one ordinary access, at the
 // first selected element. Select its lane index from the incoming predicate
 // before reading memory. This replaces one mutually exclusive ordinary load
 // per lane with one actual first access and retains its original fault point.
 // Gather forms retain lane-local addresses so later vector offsets are never
 // evaluated before an earlier ordinary fault.
 let first_contiguous=if s.mode==2 {
  let first=or_all(predicates.iter().enumerate().map(|(e,(active,seen))|
   Expr::select(b(B::And,active.clone(),inv(seen.clone())),c(64,e as u64),c(64,0))).collect());
  let first=r.bind_before_reads(first).ok()?;
  let offset=if m==31{c(64,0)}else{Expr::register(register("a64.gpr",m as u16,64,64))};
  let target=b(B::Add,base.clone(),b(B::Mul,b(B::Add,offset,first),c(64,u64::from(s.memory/8))));
  let any=inv(b(B::Eq,or_all(selected.clone()),c(64,0)));
  Some(r.load_ordered_conditional(any,Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(target),width:s.memory,endian}).ok()?)
 }else{None};
 let mut values=Vec::new();let mut failures=vec![Vec::new();usize::from(chunks)];
 for e in 0..elements {
  let bit=e*bytes;let chunk=bit/64;let position=(bit%64)as u8;
  let(active,seen)=predicates[usize::from(e)].clone();
  let target=match s.mode {
   1=>b(B::Add,Expr::cast(zlane(n,e,s.element),64,false),c(64,u64::from(m)*u64::from(s.memory/8))),
   0=>{
    let raw=Expr::cast(zlane(m,e,s.element),s.offset,false);
    let offset=Expr::cast(raw,64,s.offset_signed&&((word>>22)&1)!=0);
    b(B::Add,base.clone(),b(B::Shl,offset,c(64,u64::from(s.scale))))
   },
   2=>{
    let offset=if m==31{c(64,0)}else{Expr::register(register("a64.gpr",m as u16,64,64))};
    b(B::Add,base.clone(),b(B::Add,b(B::Mul,offset,c(64,u64::from(s.memory/8))),c(64,u64::from(e)*u64::from(s.memory/8))))
   },
   3=>{
    let immediate=((word>>16)&15)as i64;let immediate=if immediate&8!=0{immediate-16}else{immediate};
    let delta=(immediate*i64::from(elements)+i64::from(e))*i64::from(s.memory/8);
    b(B::Add,base.clone(),c(64,delta as u64))
   },
   _=>return None,
  };
  let memory=Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(target),width:s.memory,endian};
  let attempt=if s.mode==3{active.clone()}else{b(B::And,active.clone(),seen.clone())};
  let first=if s.mode==2 {first_contiguous.clone()}else if s.mode!=3 {
   Some(r.load_ordered_conditional(b(B::And,active.clone(),inv(seen.clone())),memory.clone()).ok()?)
  }else{None};
  let(value,success)=r.try_load_ordered(attempt.clone(),memory,vec![MemoryFaultKind::Translation,MemoryFaultKind::Permission,MemoryFaultKind::Alignment,MemoryFaultKind::TagCheck,MemoryFaultKind::ExternalAbort]).ok()?;
  let failed=Expr::select(attempt,inv(success),c(1,0));
  failures[usize::from(chunk)].push(b(B::Shl,Expr::cast(failed,64,false),c(64,u64::from(position))));
  let value=if let Some(first)=first {Expr::select(seen,value,first)}else{value};
  values.push(Expr::select(active,Expr::cast(value,s.element,s.signed),c(s.element,0)));
 }
 let failure_bits=failures.into_iter().map(|bits|r.bind(or_all(bits))).collect::<Vec<_>>();
 let fault_prefix=prefix(&mut r,&failure_bits);
 let bad_bits=(0..chunks).map(|chunk|{
  let incoming=pred(chunk,16);
  let was_bad=b(B::And,inv(incoming),c(64,element_mask&low_mask(pbits-chunk*64)));
  r.bind(b(B::Or,failure_bits[usize::from(chunk)].clone(),was_bad))
 }).collect::<Vec<_>>();
 let bad_prefix=prefix(&mut r,&bad_bits);
 for chunk in 0..vl/64 {
  let per=64/u16::from(s.element);let mut parts=Vec::new();
  for slot in 0..per {
   let e=chunk*per+slot;let bit=e*bytes;
   let bad=Expr::extract(bad_prefix[usize::from(bit/64)].clone(),(bit%64)as u8,1);
   let value=Expr::select(bad,c(s.element,0),values[usize::from(e)].clone());
   parts.push(b(B::Shl,Expr::cast(value,64,false),c(64,u64::from(slot)*u64::from(s.element))));
  }
  r.write(register("a64.vector64",d as u16*32+chunk,64,64),WritePolicy::Preserve,or_all(parts));
 }
 for chunk in 0..chunks {
  let clear=b(B::And,fault_prefix[usize::from(chunk)].clone(),c(64,low_mask(pbits-chunk*64)));
  r.write(register("a64.predicate64",16*4+chunk,64,64),WritePolicy::Preserve,b(B::And,pred(chunk,16),inv(clear)));
 }
 Some(r)
}

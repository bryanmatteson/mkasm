package arm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/pkg/semantics"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

// Every recipe is reached through the same raw/mode/length boundary as the
// production wrapper, after a generated decoder recognizes an assembler-derived
// instruction word. Thumb32 words have architectural high-halfword-first order.
func TestRustA32ThumbContextRecipes(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0755); err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("arm32").ParseFS(assettemplates.FS, "rust/decoders.rs.tmpl", "arm32_rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	words := map[string][]uint32{
		"a32": {0xe3a00007, 0xe3e00007, 0xe0910182, 0xe1b00061, 0xe1b00211, 0xe1b00231, 0xe1b00251, 0xe1b00271, 0xe1b00021, 0xe1b00041, 0xe0b00001, 0xe0d00001, 0xe1f100d2, 0xe0d100b2, 0xe7210102, 0xe7cf0411, 0xe7e70451, 0xe7a70451, 0xe0000291, 0xe0810392, 0xe4910004, 0xe5c10002, 0xe591f000, 0xe1e200d8, 0xe0c200f8, 0xe92d4003, 0xe8bd8003, 0xe12fff1e, 0xe12fff31, 0xe1a0f001, 0xe4911004, 0xe328f001, 0xe321f001, 0xe1600070, 0xe16f0f11, 0xe6bf0f31, 0xe6bf0fb1, 0xe6ff0fb1, 0xe6ff0f31, 0xe6af0071, 0xe6bf0471, 0xe6ef0071, 0xe6ff0071, 0xe6a20071, 0xe6f20071, 0xe710f211, 0xe730f211, 0xee300a81, 0xee721a62, 0xee233a84, 0xeec54a25, 0xeeb16ae6, 0xee310b02, 0xee710be2, 0xee6debac, 0xee8a9b0b, 0xeeb1cbcd, 0xeeb00a60, 0xeeb00ae0, 0xeeb10a60, 0xed910a01, 0xed810b02, 0xee100a90, 0xee000a90, 0xec510b12, 0xec410b12, 0xf2010802, 0xf2120844, 0xf26208e4, 0xf2320844, 0xf3020844, 0xf2120954, 0xf2020154, 0xf2120154, 0xf2220154, 0xf2320154, 0xf3020154, 0xf3120154, 0xf3220154, 0xf3320154, 0xf3b005c2, 0xf3220854, 0xf2220344, 0xf3020354, 0xeafffffe, 0xfb000000},
		"t16": {0xbf00, 0xbf08, 0xbf0c, 0x2001, 0x1888, 0x00c8, 0x4088, 0x40c8, 0x4108, 0x41c8, 0x4148, 0x4188, 0x4248, 0x4348, 0x2802, 0x4478, 0x4687, 0x4770, 0x4788, 0x4801, 0x5088, 0x5688, 0x8048, 0x9801, 0xa001, 0xa801, 0xb082, 0xb208, 0xba08, 0xbac8, 0xb110, 0xb910, 0xb503, 0xbd03, 0xc905, 0xd002, 0xe002, 0xde00, 0xdf00, 0xe7fe},
		"t32": {0xeb0100c2, 0xeb1100c2, 0xeb410002, 0xea610002, 0xf2412034, 0xf2c12034, 0xf2011023, 0xf2a11023, 0xf361200f, 0xf3c12007, 0xf3412007, 0xf8d10123, 0xf8510f04, 0xf9110022, 0xe8b10005, 0xe92d4101, 0xfb01f002, 0xfb013002, 0xfba20103, 0xfa01f002, 0xf000b808, 0xf0008008, 0xf000f808, 0xf000e808, 0xf05f4000, 0xf01100ff, 0xeb700001, 0xea4f00c1, 0xf8d1f000, 0xf8410b04, 0xf9110f02, 0xf8df0004, 0xf85f0004, 0xf04f0001, 0xe9f20102, 0xe8e20102, 0xf3bf8f5f, 0xe8510f00, 0xe8d10fbf, 0xfab1f081, 0xfa91f081, 0xfa91f091, 0xfa91f0b1, 0xfa91f0a1, 0xfa4ff081, 0xfa0ff091, 0xfa5ff081, 0xfa1ff081, 0xfa42f081, 0xfa12f081, 0xfb91f0f2, 0xfbb1f0f2, 0xee300a81, 0xee710be2, 0xeeb16ae6, 0xed910a01, 0xef010802, 0xef120844, 0xef6208e4, 0xef320844, 0xff020844, 0xef120954, 0xef020154, 0xff020154, 0xf7ffbffe, 0xf43faffe},
	}
	words["a32"] = append(words["a32"], 0xe1910f9f, 0xe1d10f9f, 0xe1f10f9f, 0xe1b20f9f, 0xe1820f91, 0xe1c20f91, 0xe1e20f91, 0xe1a10f92, 0xe1910c9f, 0xe1d10c9f, 0xe1f10c9f, 0xe181fc90, 0xe1c1fc90, 0xe1e1fc90, 0xe1910e9f, 0xe1d10e9f, 0xe1f10e9f, 0xe1b20e9f, 0xe1820e91, 0xe1c20e91, 0xe1e20e91, 0xe1a10e92, 0xe1020091, 0xe1420091, 0x01020091, 0x01910f9f, 0x01820f91, 0xe1021091, 0xe1911f9f)
	words["t32"] = append(words["t32"], 0xe8510f03, 0xe8d10f4f, 0xe8d10f5f, 0xe8d2017f, 0xe8421003, 0xe8c21f40, 0xe8c21f50, 0xe8c12370, 0xe8d10faf, 0xe8d10f8f, 0xe8d10f9f, 0xe8c10faf, 0xe8c10f8f, 0xe8c10f9f, 0xe8d10fef, 0xe8d10fcf, 0xe8d10fdf, 0xe8d201ff, 0xe8c21fe0, 0xe8c21fc0, 0xe8c21fd0, 0xe8c123f0, 0xe8d2037f, 0xe8c12270)

	vfpExtended := []uint32{0xeeb70ae0, 0xeeb70bc1, 0xeeb80ae0, 0xeeb80a60, 0xeeb80be0, 0xeeb80b60, 0xeebd0ae0, 0xeebc0ae0, 0xeebd0a60, 0xeebc0a60, 0xeebd0bc1, 0xeebc0b41, 0xeea00a81, 0xeee10ba2, 0xee000a81, 0xeea00ac1, 0xeeb40a60}
	words["a32"] = append(words["a32"], vfpExtended...)
	words["t32"] = append(words["t32"], vfpExtended...)
	words["a32"] = append(words["a32"], 0xf3bb0642, 0xf3bb06c2, 0xf3bb0742, 0xf3bb07c2, 0xf2020c54, 0xf2020d44, 0xf2220d44, 0xf3020d54, 0xf3bb2642, 0xf2000c50)
	words["t32"] = append(words["t32"], 0xffbb0642, 0xffbb06c2, 0xffbb0742, 0xffbb07c2, 0xef020c54, 0xef020d44, 0xef220d44, 0xff020d54, 0xffbb2642, 0xef000c50)

	nonfused := []uint32{0xee000a81, 0xee000ac1, 0xee100ac1, 0xee100a81, 0xee200ac1, 0xee410ba2, 0xee000a01}
	transport := []uint32{0xee100990, 0xee000990, 0xeeb009e0, 0xeeb10960, 0xeeb70900, 0xeeb70a00, 0xeeb70b00, 0xed910901, 0xed810901, 0xec510a30, 0xec410a30}
	words["a32"] = append(words["a32"], nonfused...)
	words["t32"] = append(words["t32"], nonfused...)
	words["a32"] = append(words["a32"], transport...)
	words["t32"] = append(words["t32"], transport...)
	words["a32"] = append(words["a32"], 0xf2020d54, 0xf2220d54, 0xf2000d50, 0xf3b90742, 0xf3b907c2, 0xf3b50742, 0xf3b507c2)
	words["t32"] = append(words["t32"], 0xef020d54, 0xef220d54, 0xef000d50, 0xffb90742, 0xffb907c2, 0xffb50742, 0xffb507c2)

	compareAndSigned := []uint32{0xeea00ac1, 0xee900ac1, 0xee900a81, 0xeeb40a60, 0xeeb40ae0, 0xeeb50a40, 0xeef40be1, 0xeef50b40, 0xeef50bc0, 0xeef1fa10, 0xeef10a10, 0xeeb30a60}
	words["a32"] = append(words["a32"], compareAndSigned...)
	words["t32"] = append(words["t32"], compareAndSigned...)
	words["a32"] = append(words["a32"], 0xf2220c54)
	words["t32"] = append(words["t32"], 0xef220c54)

	halfConversions := []uint32{0xeeb30a60, 0xeeb30ae0, 0xeeb20a60, 0xeeb20ae0, 0xeeb30b41, 0xeeb30bc1, 0xeeb20b60, 0xeeb20be0, 0xeef30a60, 0xeef20ae0, 0xeef3fb6f, 0xeef2fbef, 0x0eb30a60}
	words["a32"] = append(words["a32"], halfConversions...)
	words["t32"] = append(words["t32"], halfConversions[:12]...)

	for name, list := range words {
		var instructions []*ir.InstructionIR
		for _, word := range list {
			v := uint64(word)
			instructions = append(instructions, &ir.InstructionIR{EncodingID: fmt.Sprintf("word_%08x", word), Mnemonic: "fixture", BitPattern: fmt.Sprintf("%032b", word), Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "word", Start: 0, End: 31, Fixed: &v}}}})
		}
		data, err := buildRustDecoderData(BuildCatalog(instructions))
		if err != nil {
			t.Fatal(err)
		}
		if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(src, name+".rs"), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := execTmplWrite(tmpl, "recipes.rs.tmpl", filepath.Join(src, "recipes.rs"), nil); err != nil {
		t.Fatal(err)
	}
	if err := semantics.WriteRust(src); err != nil {
		t.Fatal(err)
	}
	wrapper := `#![allow(dead_code)]
 pub mod semantics;pub mod recipes;mod a32;mod t16;mod t32;
 #[derive(PartialEq,Eq)]pub enum Mode{Arm,Thumb}
 pub struct Decoded{raw:u32,pub mode:Mode,pub length:usize}
 impl Decoded{pub fn raw(&self)->u32{self.raw}}
 fn decode(word:u32,thumb:bool)->Decoded{let length=if thumb&&word<65536{2}else{4};let raw=if !thumb{a32::decode(word).unwrap().raw}else if length==2{t16::decode(word).unwrap().raw}else{t32::decode(word).unwrap().raw};Decoded{raw,mode:if thumb{Mode::Thumb}else{Mode::Arm},length}}
 `
	for path, body := range map[string]string{"Cargo.toml": "[package]\nname=\"recipe_a32_context_test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n", "src/lib.rs": wrapper + a32ThumbContextTests} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("cargo", "test", "--lib", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("A32/Thumb recipes: %v\n%s", err, out)
	}
}

const a32ThumbContextTests = `
#[cfg(test)]mod tests{
 use super::*;use semantics::*;use std::collections::HashMap;use std::cell::{Cell,RefCell};
 #[test]fn moves_do_not_read_the_unused_rn_or_nonwriting_shifter_carry(){
  struct Incoming;impl Machine for Incoming{
   fn read_register(&self,r:Register)->Value{assert_ne!(r.bank,"a32.gpr","MOV/MVN consumed unused incoming Rn");Value::unknown(32)}
   fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("move accessed memory")}
  }
  for(word,expected)in[(0xe3a00007,7),(0xe3e00007,0xfffffff8)]{
   let recipe=decode(word,false).semantic_recipe(0x1000);recipe.validate().unwrap();
   let transition=evaluate(&recipe,&Incoming).unwrap();
   assert_eq!(transition.registers.len(),1);assert_eq!(transition.registers[0].value,Value::known(32,expected));
  }
 }
 #[derive(Default)]struct State{regs:HashMap<Register,u64>,mem:HashMap<u64,u8>,monitor:Option<ExclusiveReservation>,interference:bool,atomic_calls:Cell<usize>,monitor_reads:Cell<usize>,plain_reads:Cell<usize>,float_calls:Cell<usize>,float_statuses:RefCell<Vec<(FloatEnvironment,u64,u64)>>}
 impl State{
 fn set(&mut self,bank:&'static str,index:u16,v:u64){self.regs.insert(Register{bank,index},v);}
 fn g(&mut self,n:u16,v:u64){self.set("a32.gpr",n,v)}
 fn f(&mut self,n:u16,v:u64){self.set("a32.nzcv",n,v)}
 fn it(&mut self,v:u64){self.set("a32.itstate",0,v)}
 fn put(&mut self,address:u64,v:u32){for i in 0..4{self.mem.insert(address+i,((v>>(i*8))&255) as u8);}}
 fn bytes(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{let mut v=0;for i in 0..w/8{let offset=if e==Endian::Little{i}else{w/8-1-i};v|=(*self.mem.get(&(a+offset as u64)).ok_or(EvalError::Memory)? as u64)<<(i*8);}Ok(Value::known(w,v))}
 fn apply(&mut self,t:&Transition){for event in &t.events{if let OrderedEvent::Atomic(index)=event{let atomic=&t.atomics[*index];assert_eq!(atomic.observation.as_ref().unwrap().witness,0x1234);if let(Some(request),Some(value))=(&atomic.request,atomic.stored){for i in 0..value.width/8{let offset=if request.endian==Endian::Little{i}else{value.width/8-1-i};self.mem.insert(request.address+offset as u64,(value.bits>>(i*8)) as u8);}}match atomic.monitor{ExclusiveMonitorEffect::Set(r)=>self.monitor=Some(r),ExclusiveMonitorEffect::Cleared=>self.monitor=None,ExclusiveMonitorEffect::Preserved=>{}}}}for r in &t.registers{self.regs.insert(r.register,r.value.bits);}for m in &t.memory{for i in 0..m.value.width/8{let offset=if m.endian==Endian::Little{i}else{m.value.width/8-1-i};self.mem.insert(m.address+offset as u64,(m.value.bits>>(i*8)) as u8);}}}
 }
 // Closed IEEE-half primitive observations exercise recipe wiring at exact
 // boundaries. Full conversion execution is verified by the consumer's native
 // software FP suite; unlisted half inputs deliberately return Unsupported.
 const HALF_CONTROL_MASK:u64=(3<<22)|(1<<24)|(1<<25)|(1<<19);
 const HALF_CASES:&[(u8,u8,u64,u64,u64,u64)]=&[
  (16,32,0x3c00,0,0x3f800000,0),(16,64,0x3c00,0,0x3ff0000000000000,0),
  (16,32,0x0000,0,0x00000000,0),(16,32,0x8000,0,0x80000000,0),
  (16,32,0x0001,0,0x33800000,0),(16,32,0x03ff,0,0x387fc000,0),(16,32,0x0400,0,0x38800000,0),
  (16,32,0x0001,(1<<24)|(1<<19),0x33800000,0),
  (16,32,0x7c00,0,0x7f800000,0),(16,32,0xfc00,0,0xff800000,0),
  (16,32,0x7e55,0,0x7fcaa000,0),(16,32,0xfe55,0,0xffcaa000,0),(16,32,0x7c01,0,0x7fc02000,1),
  (16,32,0xfe55,1<<25,0x7fc00000,0),(16,32,0x7c01,1<<25,0x7fc00000,1),
  (16,64,0x0001,0,0x3e70000000000000,0),(16,64,0x03ff,0,0x3f0ff80000000000,0),(16,64,0x0400,0,0x3f10000000000000,0),
  (16,64,0x0001,(1<<24)|(1<<19),0x3e70000000000000,0),
  (16,64,0x7e55,0,0x7ff9540000000000,0),(16,64,0x7c01,0,0x7ff8040000000000,1),
  (32,16,0x00000000,0,0x0000,0),(32,16,0x80000000,0,0x8000,0),
  (32,16,0x33000000,0,0x0000,24),(32,16,0x33000001,0,0x0001,24),
  (32,16,0x33800000,0,0x0001,0),(32,16,0x387fc000,0,0x03ff,0),(32,16,0x387fe000,0,0x0400,24),(32,16,0x38800000,0,0x0400,0),
  (32,16,0x33800000,(1<<24)|(1<<19),0x0001,0),
  (32,16,0x3f801000,0,0x3c00,16),(32,16,0x3f803000,0,0x3c02,16),
  (32,16,0x3f801000,1<<22,0x3c01,16),(32,16,0x3f803000,3<<22,0x3c01,16),
  (32,16,0x477fe000,0,0x7bff,0),(32,16,0x47800000,0,0x7c00,20),
  (32,16,0xffc12345,0,0xfe09,0),(32,16,0x7f812345,0,0x7e09,1),
  (32,16,0xffc12345,1<<25,0x7e00,0),(32,16,0x7f812345,1<<25,0x7e00,1),
  (64,16,0x3e70000000000000,0,0x0001,0),(64,16,0x3f0ff80000000000,0,0x03ff,0),(64,16,0x3f10000000000000,0,0x0400,0),
  (64,16,0x3ff0000000000000,0,0x3c00,0),(64,16,0x3ff0020000000000,0,0x3c00,16),
  (64,16,0x3ff0020000000001,0,0x3c01,16), // direct F64->half must avoid F32 double rounding
  (64,16,0x7ff8123456789abc,0,0x7e04,0),(64,16,0x7ff0123456789abc,0,0x7e04,1),
 ];
 impl Machine for State{
 fn read_register(&self,r:Register)->Value{Value::known(if r.bank=="a32.vector64"{64}else{32},*self.regs.get(&r).unwrap_or(&0))}
 // This bounded oracle tests recipe wiring and exact selected examples.
 // The production consumer's software FP engine owns full NaN/rounding behavior.
 fn evaluate_float(&self,e:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  self.float_calls.set(self.float_calls.get()+1);assert!(matches!(e.environment,FloatEnvironment::A32Vfp|FloatEnvironment::A32Neon));assert!(inputs.iter().all(|v|v.is_known()));
  if e.projection==FloatProjection::Status{self.float_statuses.borrow_mut().push((e.environment,control.bits,status.bits));}
  let a=inputs[0].bits;let b=inputs.last().unwrap().bits;let mut raised=0u64;
  let fp=|bits:u64,w:u8|if w==32{f32::from_bits(bits as u32) as f64}else{f64::from_bits(bits)};
  let float_bits=|value:f64,w:u8|if w==32{(value as f32).to_bits() as u64}else{value.to_bits()};
  let bits=match e.operation{
   FloatOperation::Convert{source_width,round_to_odd:false}=>{if source_width==16||e.width==16{let case=HALF_CASES.iter().find(|&&(from,to,input,ctrl,_,_)|from==source_width&&to==e.width&&input==a&&ctrl==control.bits&HALF_CONTROL_MASK).ok_or(EvalError::Unsupported)?;raised=case.5;case.4}else{let value=fp(a,source_width);if !value.is_finite(){return Err(EvalError::Unsupported)}let out=float_bits(value,e.width);if fp(out,e.width)!=value{raised|=16}out}},
   FloatOperation::FromInteger{source_width:32,signed,fractional_bits:0}=>{let value=if signed{a as u32 as i32 as f64}else{a as u32 as f64};let out=float_bits(value,e.width);if fp(out,e.width)!=value{raised|=16}out},
   FloatOperation::ToInteger{source_width,signed,fractional_bits:0,rounding}=>{let value=fp(a,source_width);if !value.is_finite(){return Err(EvalError::Unsupported)}let mode=if rounding==FloatRounding::Environment{match (control.bits>>22)&3{0=>FloatRounding::NearestEven,1=>FloatRounding::PositiveInfinity,2=>FloatRounding::NegativeInfinity,_=>FloatRounding::Zero}}else{rounding};let out=match mode{FloatRounding::Zero=>value.trunc(),FloatRounding::NearestEven=>value.round_ties_even(),FloatRounding::PositiveInfinity=>value.ceil(),FloatRounding::NegativeInfinity=>value.floor(),_=>return Err(EvalError::Unsupported)};if out!=value{raised|=16}if signed{if out<i32::MIN as f64||out>i32::MAX as f64{return Err(EvalError::Unsupported)}(out as i32) as u32 as u64}else{if out<0.||out>u32::MAX as f64{return Err(EvalError::Unsupported)}out as u32 as u64}},
   FloatOperation::Compare{source_width,signal_all_nans}=>{let nan=|v:u64|{let fraction=if source_width==32{23}else{52};let exponent=if source_width==32{8}else{11};v>>fraction&mask(exponent)==mask(exponent)&&v&mask(fraction)!=0};let snan=|v:u64|nan(v)&&v&(1<<(if source_width==32{22}else{51}))==0;if snan(a)||snan(b)||signal_all_nans&&(nan(a)||nan(b)){raised|=1}if nan(a)||nan(b){3}else if fp(a,source_width)==fp(b,source_width){6}else if fp(a,source_width)<fp(b,source_width){8}else{2}},
   FloatOperation::FusedMultiplyAdd{negate_product,negate_addend}=>{let sign=1u64<<(e.width-1);let addend=if negate_addend{a^sign}else{a};let x=if negate_product{inputs[1].bits^sign}else{inputs[1].bits};let y=inputs[2].bits;if !fp(addend,e.width).is_finite()||!fp(x,e.width).is_finite()||!fp(y,e.width).is_finite(){return Err(EvalError::Unsupported)}if e.width==32{f32::from_bits(x as u32).mul_add(f32::from_bits(y as u32),f32::from_bits(addend as u32)).to_bits() as u64}else{f64::from_bits(x).mul_add(f64::from_bits(y),f64::from_bits(addend)).to_bits()}},
   FloatOperation::Add|FloatOperation::Subtract|FloatOperation::Multiply|FloatOperation::Divide|FloatOperation::SquareRoot=>{
    if e.operation==FloatOperation::Divide&&(b&mask(e.width-1))==0{raised|=2}
    if e.width==32{let a=f32::from_bits(a as u32);let b=f32::from_bits(b as u32);let out=match e.operation{FloatOperation::Add=>a+b,FloatOperation::Subtract=>a-b,FloatOperation::Multiply=>a*b,FloatOperation::Divide=>a/b,FloatOperation::SquareRoot=>a.sqrt(),_=>unreachable!()};let exact=match e.operation{FloatOperation::Add=>Some(a as f64+b as f64),FloatOperation::Subtract=>Some(a as f64-b as f64),FloatOperation::Multiply=>Some(a as f64*b as f64),_=>None};if exact.is_some_and(|v|v.is_finite()&&v!=out as f64){raised|=16}out.to_bits() as u64}
    else{let a=f64::from_bits(a);let b=f64::from_bits(b);match e.operation{FloatOperation::Add=>(a+b).to_bits(),FloatOperation::Subtract=>(a-b).to_bits(),FloatOperation::Multiply=>(a*b).to_bits(),FloatOperation::Divide=>(a/b).to_bits(),FloatOperation::SquareRoot=>a.sqrt().to_bits(),_=>unreachable!()}}
   },_=>return Err(EvalError::Unsupported),
  };
  let trapped=e.environment==FloatEnvironment::A32Vfp&&raised&((control.bits>>8)&31)!=0;
  Ok(match e.projection{FloatProjection::Value=>Value::known(e.width,bits),FloatProjection::Status=>Value::known(32,status.bits|raised),FloatProjection::Trapped=>Value::known(1,trapped as u64)})
 }
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.plain_reads.set(self.plain_reads.get()+1);self.bytes(a,w,e)}
 fn read_exclusive_monitor(&self)->Result<Option<ExclusiveReservation>,EvalError>{self.monitor_reads.set(self.monitor_reads.get()+1);Ok(self.monitor)}
 fn evaluate_atomic(&self,request:&AtomicRequest,previous:&[AtomicTransition])->Result<AtomicObservation,EvalError>{
  self.atomic_calls.set(self.atomic_calls.get()+1);assert!(previous.is_empty(),"one instruction acquired multiple native atomic steps");assert_eq!(request.scope,MemoryScope::System);
  let read=matches!(request.kind,AtomicRequestKind::Load|AtomicRequestKind::LoadLinked|AtomicRequestKind::ReadModifyWrite{..});
  let success=matches!(request.kind,AtomicRequestKind::StoreConditional{..}).then(||!self.interference&&request.reservation.is_some_and(|r|r.address==request.address&&r.width==request.width&&r.scope==request.scope&&r.token==0x55));
  Ok(AtomicObservation{old:if read{Some(self.bytes(request.address,request.width,request.endian)?)}else{None},store_succeeded:success,reservation_token:matches!(request.kind,AtomicRequestKind::LoadLinked).then_some(0x55),witness:0x1234})
 }
 }
 fn run(word:u32,thumb:bool,s:&State)->Transition{run_at(word,thumb,s,0x1000,Endian::Little)}
 fn run_at(word:u32,thumb:bool,s:&State,pc:u64,e:Endian)->Transition{let r=decode(word,thumb).semantic_recipe_with_endian(pc,e);assert_eq!(r.support,Support::Full,"{word:08x}");r.validate().unwrap();evaluate(&r,s).unwrap_or_else(|e|panic!("{word:08x}: {e:?}"))}
 fn v(t:&Transition,bank:&str,n:u16)->u64{t.registers.iter().rev().find(|r|r.register.bank==bank&&r.register.index==n).unwrap_or_else(||panic!("missing {bank}:{n} in {t:?}")).value.bits}
 fn g(t:&Transition,n:u16)->u64{v(t,"a32.gpr",n)}fn f(t:&Transition,n:u16)->u64{v(t,"a32.nzcv",n)}
 fn no_scalar(t:&Transition)->bool{t.registers.iter().all(|r|r.register.bank=="a32.itstate")&&t.memory.is_empty()}
 #[test]fn a32_shift_carry_boundaries(){
  let mut s=State::default();s.g(1,0x80000001);s.f(2,1);
  for n in [0,1,31,32,33,255,256]{s.g(2,n);let k=(n&255) as u32;
   for (word,kind) in [(0xe1b00211,0),(0xe1b00231,1),(0xe1b00251,2),(0xe1b00271,3)]{
    let x=0x80000001u32;let (value,carry)=if k==0{(x,1)}else{match kind{
     0=>(if k<32{x<<k}else{0},if k<=32{(x>>(32-k))&1}else{0}),
     1=>(if k<32{x>>k}else{0},if k<=32{(x>>(k-1))&1}else{0}),
     2=>(((x as i32)>>(k.min(31))) as u32,(x>>(k-1).min(31))&1),
     _=>{let y=x.rotate_right(k);(y,y>>31)},}};
    let t=run(word,false,&s);assert_eq!((g(&t,0),f(&t,2)),(value as u64,carry as u64),"{word:08x} shift {n}");
   }
  }
  let t=run(0xe1b00061,false,&s);assert_eq!((g(&t,0),f(&t,2)),(0xc0000000,1));
  assert_eq!(g(&run(0xe1b00021,false,&s),0),0);assert_eq!(g(&run(0xe1b00041,false,&s),0),0xffffffff);
  s.g(1,2);s.g(2,3);assert_eq!(g(&run(0xe0910182,false,&s),0),26);
 }
 #[test]fn a32_arithmetic_snapshots_incoming_carry(){let mut s=State::default();s.g(0,0xffffffff);s.g(1,0);s.f(2,1);let t=run(0xe0b00001,false,&s);assert_eq!((g(&t,0),f(&t,2)),(0,1));s.g(0,0);s.f(2,0);let t=run(0xe0d00001,false,&s);assert_eq!((g(&t,0),f(&t,2)),(0xffffffff,0));}
 #[test]fn bitfields_and_multiply_both_modes(){let mut s=State::default();s.g(0,0x12345678);s.g(1,0x80ff);for (word,thumb) in[(0xe7cf0411,false),(0xf361200f,true)]{assert_eq!(g(&run(word,thumb,&s),0),0x1234ff78)}for(word,thumb)in[(0xe7e70451,false),(0xf3c12007,true)]{assert_eq!(g(&run(word,thumb,&s),0),0x80)}for(word,thumb)in[(0xe7a70451,false),(0xf3412007,true)]{assert_eq!(g(&run(word,thumb,&s),0),0xffffff80)}s.g(1,7);s.g(2,9);for(word,thumb)in[(0xe0000291,false),(0xfb01f002,true)]{assert_eq!(g(&run(word,thumb,&s),0),63)}s.g(2,0xffffffff);s.g(3,2);for(word,thumb)in[(0xe0810392,false),(0xfba20103,true)]{let t=run(word,thumb,&s);assert_eq!((g(&t,0),g(&t,1)),(0xfffffffe,1))}s.g(1,3);s.g(2,4);s.g(3,5);assert_eq!(g(&run(0xfb013002,true,&s),0),17);}
 #[test]fn a32_scalar_memory_addressing_writeback_and_endian(){
  let mut s=State::default();s.g(1,0x2000);s.g(2,2);s.g(0,0x11223344);s.put(0x2000,0x80ff5678);
  let t=run(0xe4910004,false,&s);assert_eq!((g(&t,0),g(&t,1)),(0x80ff5678,0x2004));
  let t=run_at(0xe4910004,false,&s,0x1000,Endian::Big);assert_eq!(g(&t,0),0x7856ff80);
  let t=run(0xe1f100d2,false,&s);assert_eq!((g(&t,0),g(&t,1)),(0xffffffff,0x2002));
  let t=run(0xe0d100b2,false,&s);assert_eq!((g(&t,0),g(&t,1)),(0x5678,0x2002));
  let t=run(0xe7210102,false,&s);assert_eq!((t.memory[0].address,t.memory[0].value.bits,g(&t,1)),(0x1ff8,0x11223344,0x1ff8));
  let t=run_at(0xe7210102,false,&s,0x1000,Endian::Big);assert_eq!(t.memory[0].endian,Endian::Big);s.apply(&t);assert_eq!(s.mem[&0x1ff8],0x11);assert_eq!(s.mem[&0x1ffb],0x44);
  assert!(matches!(decode(0xe4911004,false).semantic_recipe(0).support,Support::Unsupported(_)));
 }
 #[test]fn it_true_false_else_advance_and_flag_suppression(){
  let mut s=State::default();s.f(1,1);s.f(0,1);s.f(2,1);s.f(3,1);
  let t=run(0xbf0c,true,&s);assert_eq!(v(&t,"a32.itstate",0),0x0c);s.apply(&t);
  let t=run(0x2001,true,&s);assert_eq!(g(&t,0),1);assert_eq!([f(&t,0),f(&t,1),f(&t,2)],[1,1,1]);assert!(t.registers.iter().all(|r|r.register.bank!="a32.nzcv"||r.register.index!=3));assert_eq!(v(&t,"a32.itstate",0),0x18);s.apply(&t);
  let t=run(0x2001,true,&s);assert!(no_scalar(&t));assert_eq!(v(&t,"a32.itstate",0),0);s.apply(&t);
  let t=run(0x2001,true,&s);assert_eq!([f(&t,0),f(&t,1)],[0,0]);
  s.f(1,0);s.it(0x0c);let t=run(0x2001,true,&s);assert!(no_scalar(&t));assert_eq!(v(&t,"a32.itstate",0),0x18);s.apply(&t);
  let t=run(0x2001,true,&s);assert_eq!(g(&t,0),1);assert_eq!(f(&t,1),0);assert_eq!(v(&t,"a32.itstate",0),0);
 }
 #[test]fn all_it_conditions_use_incoming_nzcv(){let mut s=State::default();for bits in 0u32..16{let n=bits>>3&1;let z=bits>>2&1;let c=bits>>1&1;let v=bits&1;s.f(0,n as u64);s.f(1,z as u64);s.f(2,c as u64);s.f(3,v as u64);for cond in 0..14{let base=match cond>>1{0=>z!=0,1=>c!=0,2=>n!=0,3=>v!=0,4=>c!=0&&z==0,5=>n==v,_=>n==v&&z==0};let want=if cond&1!=0{!base}else{base};s.it((cond*16+8) as u64);let t=run(0x2001,true,&s);assert_eq!(!no_scalar(&t),want,"cond {cond} NZCV {bits:04b}");assert_eq!(v_it(&t),0);}}}
 fn v_it(t:&Transition)->u64{v(t,"a32.itstate",0)}
 #[test]fn it_guard_captures_input_nzcv_and_explicit_flags(){let mut s=State::default();s.it(8);s.f(1,1);s.g(0,1);let t=run(0x2802,true,&s);assert_eq!(f(&t,1),0);assert_eq!(v(&t,"a32.itstate",0),0);s.g(1,0xffffffff);s.g(2,0);s.f(2,1);let t=run(0xeb1100c2,true,&s);assert_eq!(g(&t,0),0xffffffff);assert_eq!(f(&t,0),1);s.f(1,0);assert!(no_scalar(&run(0xeb1100c2,true,&s)));s.it(0);let t=run(0xf05f4000,true,&s);assert_eq!((g(&t,0),f(&t,2)),(0x80000000,1));}
 #[test]fn thumb16_alu_and_address_families(){let mut s=State::default();s.g(0,3);s.g(1,2);s.g(2,4);s.g(13,0x2000);
  for(word,want)in[(0x1888,6),(0x00c8,16),(0x4088,12),(0x40c8,0),(0x4108,0),(0x41c8,0xc0000000),(0x4248,0xfffffffe),(0x4348,6),(0x4478,0x1007),(0xa001,0x1008),(0xa801,0x2004),(0xb082,0x1ff8),(0xb208,2),(0xba08,0x02000000),(0xbac8,0x200)]{let t=run(word,true,&s);assert_eq!(g(&t,if word==0xb082{13}else{0}),want,"{word:04x}");}
  s.g(0,0xffffffff);s.g(1,0);s.f(2,1);assert_eq!(g(&run(0x4148,true,&s),0),0);s.g(0,0);s.f(2,0);assert_eq!(g(&run(0x4188,true,&s),0),0xffffffff);
 }
 #[test]fn thumb32_alu_plain_modified_and_register_forms(){let mut s=State::default();s.g(0,0xffff5678);s.g(1,2);s.g(2,3);
  for(word,want)in[(0xeb0100c2,26),(0xea610002,0xfffffffe),(0xf2412034,0x1234),(0xf2c12034,0x12345678),(0xf2011023,0x125),(0xf2a11023,0xfffffedf),(0xea4f00c1,16),(0xfa01f002,16),(0xf04f0001,1)]{assert_eq!(g(&run(word,true,&s),0),want,"{word:08x}")}
  s.f(2,1);assert_eq!(g(&run(0xeb410002,true,&s),0),6);s.g(0,0);s.g(1,0);s.f(2,0);let t=run(0xeb700001,true,&s);assert_eq!((g(&t,0),f(&t,2)),(0xffffffff,0));s.g(1,0x1234);s.f(2,1);let t=run(0xf01100ff,true,&s);assert_eq!((g(&t,0),f(&t,2)),(0x34,1));
 }
 #[test]fn thumb_scalar_memory_literal_signed_endian_and_writeback(){let mut s=State::default();s.g(0,0x11223344);s.g(1,0x2000);s.g(2,1);s.g(13,0x2000);s.put(0x2000,0x80ff5678);s.put(0x2004,0x87654321);s.put(0x2123,0xabcdef12);s.put(0x1008,0x12345678);s.put(0x1000,0x87654321);
  for(word,want)in[(0x4801,0x12345678),(0x5688,0x56),(0x9801,0x87654321),(0xf8d10123,0xabcdef12),(0xf8510f04,0x87654321),(0xf9110f02,0xffffffff),(0xf8df0004,0x12345678),(0xf85f0004,0x87654321)]{assert_eq!(g(&run(word,true,&s),0),want,"{word:08x}");}
  let t=run(0xf8510f04,true,&s);assert_eq!(g(&t,1),0x2004);s.g(2,0);assert_eq!(g(&run(0xf9110022,true,&s),0),0x78);
  let t=run_at(0xf8d10123,true,&s,0x1000,Endian::Big);assert_eq!(g(&t,0),0x12efcdab);
  let t=run_at(0xf8410b04,true,&s,0x1000,Endian::Big);assert_eq!((t.memory[0].address,g(&t,1)),(0x2000,0x2004));s.apply(&t);assert_eq!(s.mem[&0x2000],0x11);assert_eq!(s.mem[&0x2003],0x44);
  s.it(8);s.f(1,0);s.mem.clear();let t=run(0xf8d10123,true,&s);assert!(no_scalar(&t));
 }
 #[test]fn stacks_pairs_and_multiple_preserve_original_registers(){let mut s=State::default();s.g(0,11);s.g(1,22);s.g(8,88);s.g(14,0x3001);s.g(13,0x2000);
  for(word,thumb)in[(0xe92d4003,false),(0xb503,true)]{let t=run(word,thumb,&s);assert_eq!(g(&t,13),0x1ff4);assert_eq!(t.memory.iter().map(|m|(m.address,m.value.bits)).collect::<Vec<_>>(),vec![(0x1ff4,11),(0x1ff8,22),(0x1ffc,0x3001)]);}
  let t=run(0xe92d4101,true,&s);assert_eq!(t.memory[1].value.bits,88);s.put(0x2000,31);s.put(0x2004,32);s.put(0x2008,0x3001);
  for(word,thumb)in[(0xe8bd8003,false),(0xbd03,true)]{let t=run(word,thumb,&s);assert_eq!((g(&t,0),g(&t,1),g(&t,13),t.next_pc.bits,v(&t,"a32.thumb_state",0)),(31,32,0x200c,0x3000,1));}
  s.g(1,0x2000);for word in[0xc905,0xe8b10005]{let t=run(word,true,&s);assert_eq!((g(&t,0),g(&t,2),g(&t,1)),(31,32,0x2008));}
  s.g(2,0x2000);s.put(0x2008,41);s.put(0x200c,42);let t=run(0xe1e200d8,false,&s);assert_eq!((g(&t,0),g(&t,1),g(&t,2)),(41,42,0x2008));
 }
 #[test]fn branches_links_alignment_and_interworking(){let mut s=State::default();s.g(0,0x3003);s.g(1,0x3001);s.g(14,0x3001);
  for(word,thumb)in[(0xe12fff1e,false),(0xe1a0f001,false),(0x4770,true)]{let t=run(word,thumb,&s);assert_eq!((t.next_pc.bits,v(&t,"a32.thumb_state",0)),(0x3000,1));}
  for(word,thumb,lr)in[(0xe12fff31,false,0x1004),(0x4788,true,0x1003)]{let t=run(word,thumb,&s);assert_eq!((t.next_pc.bits,g(&t,14)),(0x3000,lr));}
  assert_eq!(run(0x4687,true,&s).next_pc.bits,0x3002);
  for(word,target)in[(0xe7fe,0x1000),(0xf7ffbffe,0x1000),(0xe002,0x1008),(0xf000b808,0x1014),(0xf000f808,0x1014),(0xf000e808,0x1014)]{let t=run(word,true,&s);assert_eq!(t.next_pc.bits,target,"{word:08x}");}
  assert_eq!(g(&run(0xf000f808,true,&s),14),0x1005);assert_eq!(v(&run(0xf000e808,true,&s),"a32.thumb_state",0),0);
  assert_eq!(run(0xeafffffe,false,&s).next_pc.bits,0x1000);assert_eq!(run(0xfb000000,false,&s).next_pc.bits,0x100a);let t=run_at(0xf000e808,true,&s,0x1002,Endian::Little);assert_eq!((t.next_pc.bits,g(&t,14)),(0x1014,0x1007));
  s.f(1,1);assert_eq!(run(0xf43faffe,true,&s).next_pc.bits,0x1000);assert_eq!(run(0xd002,true,&s).next_pc.bits,0x1008);assert_eq!(run(0xf0008008,true,&s).next_pc.bits,0x1014);s.f(1,0);assert_eq!(run(0xd002,true,&s).next_pc.bits,0x1002);
  s.g(0,0);assert_eq!(run(0xb110,true,&s).next_pc.bits,0x1008);assert_eq!(run(0xb910,true,&s).next_pc.bits,0x1002);
  s.g(1,0x2000);s.put(0x2000,0x3000);for(word,thumb)in[(0xe591f000,false),(0xf8d1f000,true)]{let t=run(word,thumb,&s);assert_eq!((t.next_pc.bits,v(&t,"a32.thumb_state",0)),(0x3000,0));}
 }
 #[test]fn scalar_utilities_and_total_division(){let mut s=State::default();s.g(1,0x800080ff);s.g(2,7);
  for(a,t,want)in[(0xe16f0f11,0xfab1f081,0),(0xe6bf0f31,0xfa91f081,0xff800080),(0xe6bf0fb1,0xfa91f091,0x0080ff80),(0xe6ff0fb1,0xfa91f0b1,0xffffff80),(0xe6ff0f31,0xfa91f0a1,0xff010001),(0xe6af0071,0xfa4ff081,0xffffffff),(0xe6bf0471,0xfa0ff091,128),(0xe6ef0071,0xfa5ff081,255),(0xe6ff0071,0xfa1ff081,0x80ff),(0xe6a20071,0xfa42f081,6),(0xe6f20071,0xfa12f081,0x8106)]{for(word,thumb)in[(a,false),(t,true)]{assert_eq!(g(&run(word,thumb,&s),0),want,"{word:08x}");}}
  for value in[0,1,0x80000000]{s.g(1,value);assert_eq!(g(&run(0xe16f0f11,false,&s),0),(value as u32).leading_zeros() as u64);}
  s.g(1,(-21i32) as u32 as u64);s.g(2,4);for(word,thumb)in[(0xe710f211,false),(0xfb91f0f2,true)]{assert_eq!(g(&run(word,thumb,&s),0),(-5i32) as u32 as u64);}s.g(1,21);for(word,thumb)in[(0xe730f211,false),(0xfbb1f0f2,true)]{assert_eq!(g(&run(word,thumb,&s),0),5);s.g(2,0);assert_eq!(g(&run(word,thumb,&s),0),0);s.g(2,4);}
 }
 #[test]fn vfp_arithmetic_alias_slices_predication_and_traps(){let mut s=State::default();
  // S1 occupies the high half of D0; destination S0 must preserve S1.
  s.set("a32.vector64",0,((1.5f32.to_bits() as u64)<<32)|0xdeadbeef);s.set("a32.vector64",1,2.5f32.to_bits() as u64);
  for thumb in[false,true]{let t=run(0xee300a81,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),((1.5f32.to_bits() as u64)<<32)|4f32.to_bits() as u64);assert_eq!(v(&t,"a32.fpscr",0),0);}
  s.set("a32.vector64",2,((2f32.to_bits() as u64)<<32)|7f32.to_bits() as u64);let t=run(0xee721a62,false,&s);assert_eq!(v(&t,"a32.vector64",1)>>32,5f32.to_bits() as u64);
  s.set("a32.vector64",3,(3f32.to_bits() as u64)<<32);s.set("a32.vector64",4,4f32.to_bits() as u64);assert_eq!(v(&run(0xee233a84,false,&s),"a32.vector64",3)&0xffffffff,12f32.to_bits() as u64);
  s.set("a32.vector64",5,((2f32.to_bits() as u64)<<32)|8f32.to_bits() as u64);assert_eq!(v(&run(0xeec54a25,false,&s),"a32.vector64",4)>>32,4f32.to_bits() as u64);
  s.set("a32.vector64",6,(9f32.to_bits() as u64)<<32);for thumb in[false,true]{assert_eq!(v(&run(0xeeb16ae6,thumb,&s),"a32.vector64",6)&0xffffffff,3f32.to_bits() as u64);}
  s.set("a32.vector64",1,1.5f64.to_bits());s.set("a32.vector64",2,2.5f64.to_bits());assert_eq!(v(&run(0xee310b02,false,&s),"a32.vector64",0),4f64.to_bits());
  s.set("a32.vector64",17,7f64.to_bits());s.set("a32.vector64",18,2f64.to_bits());for thumb in[false,true]{assert_eq!(v(&run(0xee710be2,thumb,&s),"a32.vector64",16),5f64.to_bits());}
  s.set("a32.vector64",29,3f64.to_bits());s.set("a32.vector64",28,4f64.to_bits());assert_eq!(v(&run(0xee6debac,false,&s),"a32.vector64",30),12f64.to_bits());s.set("a32.vector64",10,8f64.to_bits());s.set("a32.vector64",11,2f64.to_bits());assert_eq!(v(&run(0xee8a9b0b,false,&s),"a32.vector64",9),4f64.to_bits());s.set("a32.vector64",13,9f64.to_bits());assert_eq!(v(&run(0xeeb1cbcd,false,&s),"a32.vector64",12),3f64.to_bits());
  s.set("a32.vector64",5,8f32.to_bits() as u64);s.set("a32.fpscr",0,0x200);let t=run(0xeec54a25,false,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(v(&t,"a32.fpscr",0),0x202);assert!(t.registers.iter().all(|r|r.register.bank!="a32.vector64"));
  s.it(8);s.f(1,0);s.set("a32.fpscr",0,0x10000);assert!(no_scalar(&run(0xee300a81,true,&s)));s.f(1,1);assert_eq!(evaluate(&decode(0xee300a81,true).semantic_recipe(0x1000),&s),Err(EvalError::UnsupportedContext));
 }
 #[test]fn missing_native_fp_engine_rejects_and_false_it_skips(){struct NoFloat(State);impl Machine for NoFloat{fn read_register(&self,r:Register)->Value{self.0.read_register(r)}fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.0.read_memory(a,w,e)}}let mut s=NoFloat(State::default());let r=decode(0xee300a81,false).semantic_recipe(0x1000);assert_eq!(evaluate(&r,&s),Err(EvalError::Unsupported));s.0.it(8);s.0.f(1,0);let r=decode(0xee300a81,true).semantic_recipe(0x1000);assert!(no_scalar(&evaluate(&r,&s).unwrap()));}
 #[test]fn vfp_bit_moves_and_memory_share_d_register_storage(){let mut s=State::default();s.set("a32.vector64",0,0xbf80000012345678);
  for(word,want)in[(0xeeb00a60,0xbf800000),(0xeeb00ae0,0x3f800000),(0xeeb10a60,0x3f800000)]{assert_eq!(v(&run(word,false,&s),"a32.vector64",0),0xbf80000000000000|want);}
  assert_eq!(g(&run(0xee100a90,false,&s),0),0xbf800000);s.g(0,0xabcdef12);assert_eq!(v(&run(0xee000a90,false,&s),"a32.vector64",0),0xabcdef1212345678);
  s.set("a32.vector64",2,0x1122334455667788);let t=run(0xec510b12,false,&s);assert_eq!((g(&t,0),g(&t,1)),(0x55667788,0x11223344));s.g(0,0x12345678);s.g(1,0xabcdef00);assert_eq!(v(&run(0xec410b12,false,&s),"a32.vector64",2),0xabcdef0012345678);
  s.g(1,0x2000);s.put(0x2004,0x87654321);for thumb in[false,true]{let t=run(0xed910a01,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),0xbf80000087654321);let t=run_at(0xed910a01,thumb,&s,0x1000,Endian::Big);assert_eq!(v(&t,"a32.vector64",0),0xbf80000021436587);}
  let t=run_at(0xed810b02,false,&s,0x1000,Endian::Big);assert_eq!(t.memory[0].address,0x2008);assert_eq!(t.memory[0].value.width,64);assert_eq!(t.memory[0].value.bits,0xbf80000012345678);assert_eq!(t.memory[0].endian,Endian::Big);
  s.g(2,0x2000);s.put(0x2008,41);s.put(0x200c,42);let t=run(0xe9f20102,true,&s);assert_eq!((g(&t,0),g(&t,1),g(&t,2)),(41,42,0x2008));let t=run(0xe8e20102,true,&s);assert_eq!((t.memory[0].address,t.memory[1].address,g(&t,2)),(0x2000,0x2004,0x2008));
 }
 #[test]fn neon_d_q_aliases_integer_lanes_and_logical_masks(){let mut s=State::default();
  s.set("a32.vector64",1,0xff00ff00ff00ff00);s.set("a32.vector64",2,0x0101010101010101);for(word,thumb)in[(0xf2010802,false),(0xef010802,true)]{assert_eq!(v(&run(word,thumb,&s),"a32.vector64",0),0x0001000100010001);}
  s.set("a32.vector64",2,0x0002ffff00020003);s.set("a32.vector64",3,0x0004000500060007);s.set("a32.vector64",4,0x0003000200010002);s.set("a32.vector64",5,0x0008000700060005);
  for(word,thumb)in[(0xf2120844,false),(0xef120844,true)]{let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),0x0005000100030005);assert_eq!(v(&t,"a32.vector64",1),0x000c000c000c000c);}
  for(word,thumb)in[(0xf2120954,false),(0xef120954,true)]{let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),0x0006fffe00020006);assert_eq!(v(&t,"a32.vector64",1),0x0020002300240023);}
  let a=0x0002ffff00020003;let b=0x0003000200010002;
  for(word,want)in[(0xf2020154,a&b),(0xf2120154,a&!b),(0xf2220154,a|b),(0xf2320154,a|!b),(0xf3020154,a^b)]{assert_eq!(v(&run(word,false,&s),"a32.vector64",0),want);}
  for(word,thumb,want)in[(0xef020154,true,a&b),(0xff020154,true,a^b)]{assert_eq!(v(&run(word,thumb,&s),"a32.vector64",0),want);}
  s.set("a32.vector64",0,0x00ff00ff00ff00ff);let old=0x00ff00ff00ff00ff;
  for(word,want)in[(0xf3120154,(old&a)|(!old&b)),(0xf3220154,(old&!b)|(a&b)),(0xf3320154,(old&b)|(a&!b)),(0xf3b005c2,!a)]{assert_eq!(v(&run(word,false,&s),"a32.vector64",0),want);}
  s.set("a32.vector64",18,0xffffffff00000001);s.set("a32.vector64",19,0x0000000200000003);s.set("a32.vector64",20,0x0000000100000004);s.set("a32.vector64",21,0x0000000500000006);for(word,thumb)in[(0xf26208e4,false),(0xef6208e4,true)]{let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",16),5);assert_eq!(v(&t,"a32.vector64",17),0x0000000700000009);}
 }
 #[test]fn closed_system_helpers_preserve_thumb_context(){let mut s=State::default();assert_eq!(run(0xde00,true,&s).trap,Some(TrapKind::InvalidInstruction));let t=run(0xf3bf8f5f,true,&s);assert!(!t.events.is_empty());s.it(8);s.f(1,0);let t=run(0xf3bf8f5f,true,&s);assert!(t.events.is_empty());assert_eq!(v(&t,"a32.itstate",0),0);}
 // The byte backend is a read-only planning oracle. It commits atomic stores
 // and reservation changes only when the caller explicitly applies a transition.
 fn request(t:&Transition)->&AtomicRequest{assert!(t.memory.is_empty());assert_eq!(t.atomics.len(),1);assert_eq!(t.events,vec![OrderedEvent::Atomic(0)]);t.atomics[0].request.as_ref().unwrap()}
 fn atomic_state()->State{let mut s=State::default();s.g(1,0x2000);s.g(2,0x2000);s.put(0x2000,0x44332211);s.put(0x2004,0x88776655);s.put(0x200c,0xccbbaa99);s}
 fn lanes(values:[u32;2])->u64{values[0] as u64|((values[1] as u64)<<32)}
 #[test]fn vfp_format_and_integer_conversions_use_mixed_register_widths(){for thumb in[false,true]{let mut s=State::default();
  s.set("a32.vector64",0,(1.5f32.to_bits() as u64)<<32|0xdeadbeef);let t=run(0xeeb70ae0,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),1.5f64.to_bits());
  s.set("a32.vector64",0,0xaabbccdd00000000);s.set("a32.vector64",1,1.5f64.to_bits());let t=run(0xeeb70bc1,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),0xaabbccdd00000000|1.5f32.to_bits() as u64);
  for(word,signed,double)in[(0xeeb80ae0,true,false),(0xeeb80a60,false,false),(0xeeb80be0,true,true),(0xeeb80b60,false,true)]{let integer=if signed{-3i32 as u32}else{7};s.set("a32.vector64",0,lanes([0x12345678,integer]));let t=run(word,thumb,&s);let want:f64=if signed{-3.0}else{7.0};if double{assert_eq!(v(&t,"a32.vector64",0),want.to_bits())}else{assert_eq!(v(&t,"a32.vector64",0),lanes([(want as f32).to_bits(),integer]));}}
  s.set("a32.vector64",0,lanes([0,0xfffffff0]));s.set("a32.fpscr",0,0x00110000);let t=run(0xeeb80b60,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),4294967280f64.to_bits());assert_eq!(v(&t,"a32.fpscr",0),0x00110000); // scalar conversion ignores legacy vector LEN/STRIDE
  s.set("a32.vector64",1,3000000000.75f64.to_bits());s.set("a32.fpscr",0,0x00400000);let t=run(0xeebc0b41,thumb,&s);assert_eq!(v(&t,"a32.vector64",0)&0xffffffff,3000000001);
  for(word,signed,source64,environment)in[(0xeebd0ae0,true,false,false),(0xeebc0ae0,false,false,false),(0xeebd0a60,true,false,true),(0xeebc0a60,false,false,true),(0xeebd0bc1,true,true,false),(0xeebc0b41,false,true,true)]{let value=if signed{-3.75f64}else{3.75};if source64{s.set("a32.vector64",1,value.to_bits())}else{s.set("a32.vector64",0,lanes([0x12345678,(value as f32).to_bits()]))}s.set("a32.fpscr",0,0x00400002);let t=run(word,thumb,&s);let want=if environment{if signed{-3i32 as u32}else{4}}else{if signed{-3i32 as u32}else{3}};assert_eq!(v(&t,"a32.vector64",0)&0xffffffff,want as u64,"{word:08x}");assert_eq!(v(&t,"a32.fpscr",0),0x00400012);}
 }}
 #[test]fn vfp_fma_is_one_rounding_with_original_addend_and_high_d_registers(){for thumb in[false,true]{let mut s=State::default();s.set("a32.vector64",0,lanes([0xbf800000,0x3f800001]));s.set("a32.vector64",1,0x3f7ffffe);let t=run(0xeea00a81,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([0xa8800000,0x3f800001]));s.set("a32.vector64",16,3f64.to_bits());s.set("a32.vector64",17,1.5f64.to_bits());s.set("a32.vector64",18,2f64.to_bits());assert_eq!(v(&run(0xeee10ba2,thumb,&s),"a32.vector64",16),6f64.to_bits());s.set("a32.fpscr",0,1<<20);assert_eq!(evaluate(&decode(0xeea00a81,thumb).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));}}
 #[test]fn conversion_flags_trap_before_destination_and_false_it_skips(){let mut s=State::default();s.set("a32.vector64",0,lanes([0x12345678,1.75f32.to_bits()]));s.set("a32.fpscr",0,0x1002);s.it(8);s.f(1,1);let before=s.regs.clone();let t=run(0xeebd0ae0,true,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(v(&t,"a32.fpscr",0),0x1012);assert!(t.registers.iter().all(|w|w.register.bank=="a32.fpscr"));assert_eq!(s.regs,before);s.f(1,0);s.float_calls.set(0);let t=run(0xeebd0ae0,true,&s);assert!(no_scalar(&t));assert_eq!(s.float_calls.get(),0);assert_eq!(v_it(&t),0);}
 #[test]fn neon_conversions_chain_status_and_use_standard_nontrapping_environment(){for thumb in[false,true]{let mut s=State::default();let base=if thumb{0xff000000}else{0xf3000000};s.set("a32.vector64",2,lanes([-1i32 as u32,2]));s.set("a32.vector64",3,lanes([-3i32 as u32,4]));let t=run(base|0xbb0642,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([(-1f32).to_bits(),2f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([(-3f32).to_bits(),4f32.to_bits()]));let t=run(base|0xbb2642,thumb,&s);assert_eq!(v(&t,"a32.vector64",2),lanes([(-1f32).to_bits(),2f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",3),lanes([(-3f32).to_bits(),4f32.to_bits()]));
  s.set("a32.vector64",2,lanes([7,8]));s.set("a32.vector64",3,lanes([9,10]));let t=run(base|0xbb06c2,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([7f32.to_bits(),8f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([9f32.to_bits(),10f32.to_bits()]));
  s.set("a32.vector64",2,lanes([(-1.75f32).to_bits(),2.25f32.to_bits()]));s.set("a32.vector64",3,lanes([(-3.5f32).to_bits(),4f32.to_bits()]));s.set("a32.fpscr",0,0x00401002);s.float_statuses.borrow_mut().clear();s.float_calls.set(0);let t=run(base|0xbb0742,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([-1i32 as u32,2]));assert_eq!(v(&t,"a32.vector64",1),lanes([-3i32 as u32,4]));assert_eq!(v(&t,"a32.fpscr",0),0x00401012);assert_eq!(t.trap,None);assert_eq!(s.float_calls.get(),12);let seen=s.float_statuses.borrow();assert_eq!(seen.len(),4);assert_eq!(seen[0],(FloatEnvironment::A32Neon,0x00401002,0x00401002));assert_eq!(seen[3],(FloatEnvironment::A32Neon,0x00401002,0x00401012));drop(seen);
  s.set("a32.vector64",2,lanes([0x80000000,0xffffffff]));s.set("a32.vector64",3,lanes([7,0]));let t=run(base|0xbb06c2,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([2147483648f32.to_bits(),4294967296f32.to_bits()]));
  s.set("a32.vector64",2,lanes([1.75f32.to_bits(),2.25f32.to_bits()]));s.set("a32.vector64",3,lanes([3.5f32.to_bits(),4f32.to_bits()]));let t=run(base|0xbb07c2,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([1,2]));assert_eq!(v(&t,"a32.vector64",1),lanes([3,4]));s.set("a32.vector64",2,lanes([3000000000f32.to_bits(),4000000000f32.to_bits()]));let t=run(base|0xbb07c2,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([3000000000,4000000000]));
 }}
 #[test]fn neon_fma_and_arithmetic_preserve_chunk_aliases_and_predication(){for thumb in[false,true]{let mut s=State::default();let prefix=if thumb{0xef000000}else{0xf2000000};s.set("a32.vector64",0,lanes([0xbf800000,3f32.to_bits()]));s.set("a32.vector64",1,lanes([5f32.to_bits(),7f32.to_bits()]));s.set("a32.vector64",2,lanes([0x3f800001,2f32.to_bits()]));s.set("a32.vector64",3,lanes([3f32.to_bits(),4f32.to_bits()]));s.set("a32.vector64",4,lanes([0x3f7ffffe,4f32.to_bits()]));s.set("a32.vector64",5,lanes([5f32.to_bits(),6f32.to_bits()]));let t=run(prefix|0x020c54,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([0xa8800000,11f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([20f32.to_bits(),31f32.to_bits()]));
  s.set("a32.vector64",0,lanes([1f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",1,lanes([3f32.to_bits(),4f32.to_bits()]));let t=run(prefix|0x000c50,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([2f32.to_bits(),6f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([12f32.to_bits(),20f32.to_bits()]));
  s.set("a32.vector64",2,lanes([1f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",3,lanes([3f32.to_bits(),4f32.to_bits()]));s.set("a32.vector64",4,lanes([1f32.to_bits(),4f32.to_bits()]));for(word,w0,w1)in[(prefix|0x020d44,[2f32,6f32],[8f32,10f32]),(prefix|0x220d44,[0f32,-2f32],[-2f32,-2f32]),((if thumb{0xff000000}else{0xf3000000})|0x020d54,[1f32,8f32],[15f32,24f32])]{let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes(w0.map(f32::to_bits)));assert_eq!(v(&t,"a32.vector64",1),lanes(w1.map(f32::to_bits)));}
  if thumb{s.it(8);s.f(1,0);s.float_calls.set(0);let t=run(prefix|0x020c54,true,&s);assert!(no_scalar(&t));assert_eq!(s.float_calls.get(),0);assert_eq!(v_it(&t),0);}
 }}
 #[test]fn native_exclusive_loads_all_sizes_orders_and_endian(){
  for (word,thumb,width,ordered,rt2,offset) in[
   (0xe1910f9f,false,32,false,None,0),(0xe1d10f9f,false,8,false,None,0),(0xe1f10f9f,false,16,false,None,0),(0xe1b20f9f,false,64,false,Some(1),0),
   (0xe1910e9f,false,32,true,None,0),(0xe1d10e9f,false,8,true,None,0),(0xe1f10e9f,false,16,true,None,0),(0xe1b20e9f,false,64,true,Some(1),0),
   (0xe8510f03,true,32,false,None,12),(0xe8d10f4f,true,8,false,None,0),(0xe8d10f5f,true,16,false,None,0),(0xe8d2017f,true,64,false,Some(1),0),
   (0xe8d10fef,true,32,true,None,0),(0xe8d10fcf,true,8,true,None,0),(0xe8d10fdf,true,16,true,None,0),(0xe8d201ff,true,64,true,Some(1),0),(0xe8d2037f,true,64,false,Some(3),0)
  ]{for endian in[Endian::Little,Endian::Big]{let mut s=atomic_state();let address=0x2000+offset;let old=s.bytes(address,width,endian).unwrap().bits;let t=run_at(word,thumb,&s,0x1000,endian);let q=request(&t);assert_eq!((q.address,q.width,q.endian),(address,width,endian));assert!(matches!(q.kind,AtomicRequestKind::LoadLinked));assert_eq!(q.ordering,if ordered{MemoryOrdering::Acquire}else{MemoryOrdering::Monotonic});assert_eq!(s.atomic_calls.get(),1);assert_eq!(s.plain_reads.get(),0);assert_eq!(s.monitor_reads.get(),0);assert!(s.monitor.is_none());assert_eq!(t.atomics[0].monitor,ExclusiveMonitorEffect::Set(ExclusiveReservation{address,width,scope:MemoryScope::System,token:0x55}));if let Some(rt2)=rt2{let low=s.bytes(address,32,endian).unwrap().bits;let high=s.bytes(address+4,32,endian).unwrap().bits;assert_eq!((g(&t,0),g(&t,rt2)),(low,high));}else{assert_eq!(g(&t,0),old)}s.apply(&t);assert!(s.monitor.is_some());}}
  let s=atomic_state();assert_eq!(g(&run(0xe1911f9f,false,&s),1),0x44332211);
 }
 #[test]fn native_store_conditionals_success_failure_monitor_clear_and_endian(){
  for(word,thumb,width,ordered,offset,double)in[
   (0xe1820f91,false,32,false,0,false),(0xe1c20f91,false,8,false,0,false),(0xe1e20f91,false,16,false,0,false),(0xe1a10f92,false,64,false,0,true),
   (0xe1820e91,false,32,true,0,false),(0xe1c20e91,false,8,true,0,false),(0xe1e20e91,false,16,true,0,false),(0xe1a10e92,false,64,true,0,true),
   (0xe8421003,true,32,false,12,false),(0xe8c21f40,true,8,false,0,false),(0xe8c21f50,true,16,false,0,false),(0xe8c12370,true,64,false,0,true),
   (0xe8c21fe0,true,32,true,0,false),(0xe8c21fc0,true,8,true,0,false),(0xe8c21fd0,true,16,true,0,false),(0xe8c123f0,true,64,true,0,true),
  ]{for endian in[Endian::Little,Endian::Big]{for failure in 0..4{let mut s=atomic_state();if double{s.g(2,0xaabbccdd);s.g(3,0x11223344)}else{s.g(1,0xaabbccdd)}let address=0x2000+offset;s.monitor=if failure==1{None}else{Some(ExclusiveReservation{address:address+if failure==2{4}else{0},width,scope:MemoryScope::System,token:0x55})};s.interference=failure==3;
   let before=s.mem.clone();let t=run_at(word,thumb,&s,0x1000,endian);let q=request(&t);assert_eq!((q.address,q.width,q.endian),(address,width,endian));assert_eq!(q.ordering,if ordered{MemoryOrdering::Release}else{MemoryOrdering::Monotonic});let expected=if double{if endian==Endian::Little{0x11223344aabbccdd}else{0xaabbccdd11223344}}else{0xaabbccdd&mask(width)};assert!(matches!(q.kind,AtomicRequestKind::StoreConditional{value}if value.bits==expected));assert_eq!(g(&t,0),(failure!=0) as u64);assert_eq!(t.atomics[0].success,Some(failure==0));assert_eq!(t.atomics[0].stored,if failure==0{Some(Value::known(width,expected))}else{None});assert_eq!(t.atomics[0].monitor,ExclusiveMonitorEffect::Cleared);assert_eq!(s.atomic_calls.get(),1);assert_eq!(s.monitor_reads.get(),1);assert_eq!(s.plain_reads.get(),0);assert_eq!(s.mem,before);s.apply(&t);assert!(s.monitor.is_none());if failure==0{assert_eq!(s.bytes(address,width,endian).unwrap().bits,expected)}else{assert_eq!(s.mem,before)}
  }}}
  // T32 allows an explicit second source and may name the same source twice.
  let mut s=atomic_state();s.g(2,0xabcdef12);s.monitor=Some(ExclusiveReservation{address:0x2000,width:64,scope:MemoryScope::System,token:0x55});let t=run(0xe8c12270,true,&s);assert_eq!(t.atomics[0].stored.unwrap().bits,0xabcdef12abcdef12);
 }
 #[test]fn native_acquire_release_without_exclusives_preserve_monitor(){
  for(loads,stores,thumb)in[([0xe1910c9f,0xe1d10c9f,0xe1f10c9f],[0xe181fc90,0xe1c1fc90,0xe1e1fc90],false),([0xe8d10faf,0xe8d10f8f,0xe8d10f9f],[0xe8c10faf,0xe8c10f8f,0xe8c10f9f],true)]{for index in 0..3{let width=[32,8,16][index];for endian in[Endian::Little,Endian::Big]{let mut s=atomic_state();s.g(0,0xaabbccdd);let reservation=ExclusiveReservation{address:0x3000,width:32,scope:MemoryScope::System,token:0x55};s.monitor=Some(reservation);
   let t=run_at(loads[index],thumb,&s,0x1000,endian);let q=request(&t);assert!(matches!(q.kind,AtomicRequestKind::Load));assert_eq!((q.width,q.ordering),(width,MemoryOrdering::Acquire));assert_eq!(g(&t,0),s.bytes(0x2000,width,endian).unwrap().bits);assert_eq!(t.atomics[0].monitor,ExclusiveMonitorEffect::Preserved);assert_eq!(s.monitor_reads.get(),0);assert_eq!(s.plain_reads.get(),0);
   let t=run_at(stores[index],thumb,&s,0x1000,endian);let q=request(&t);assert!(matches!(q.kind,AtomicRequestKind::Store{value}if value.bits==0xaabbccdd&mask(width)));assert_eq!((q.width,q.ordering),(width,MemoryOrdering::Release));assert_eq!(t.atomics[0].monitor,ExclusiveMonitorEffect::Preserved);s.apply(&t);assert_eq!(s.monitor,Some(reservation));assert_eq!(s.bytes(0x2000,width,endian).unwrap().bits,0xaabbccdd&mask(width));
  }}}
 }
 #[test]fn native_swap_is_one_exchange_with_captured_source(){for(word,width,alias)in[(0xe1020091,32,false),(0xe1420091,8,false),(0xe1021091,32,true)]{for endian in[Endian::Little,Endian::Big]{let mut s=atomic_state();s.g(1,0xaabbccdd);let old=s.bytes(0x2000,width,endian).unwrap().bits;let t=run_at(word,false,&s,0x1000,endian);let q=request(&t);assert!(matches!(q.kind,AtomicRequestKind::ReadModifyWrite{operation:AtomicRmwOp::Exchange,value}if value.bits==0xaabbccdd&mask(width)));assert_eq!((q.width,q.ordering),(width,MemoryOrdering::Monotonic));assert_eq!(g(&t,if alias{1}else{0}),old);assert_eq!(t.atomics[0].stored.unwrap().bits,0xaabbccdd&mask(width));assert_eq!(s.atomic_calls.get(),1);assert_eq!(s.plain_reads.get(),0);s.apply(&t);assert_eq!(s.bytes(0x2000,width,endian).unwrap().bits,0xaabbccdd&mask(width));}}}
 #[test]fn exclusive_sequences_commit_once_and_clear_on_failed_repetition(){for thumb in[false,true]{let mut s=atomic_state();let load=if thumb{0xe8d10fef}else{0xe1910e9f};let t=run(load,thumb,&s);s.apply(&t);s.g(1,0x9999);s.g(2,0x2000);let store=if thumb{0xe8c21fe0}else{0xe1820e91};let t=run(store,thumb,&s);assert_eq!(g(&t,0),0);s.apply(&t);assert_eq!(s.bytes(0x2000,32,Endian::Little).unwrap().bits,0x9999);let t=run(store,thumb,&s);assert_eq!(g(&t,0),1);assert!(t.atomics[0].stored.is_none());}}
 #[test]fn atomic_false_predication_skips_backend_monitor_and_context_checks(){for(word,thumb)in[(0x01910f9f,false),(0x01820f91,false),(0x01020091,false),(0xe8510f03,true),(0xe8d10faf,true),(0xe8c21fe0,true)]{let mut s=atomic_state();s.it(8);s.f(1,0);s.g(1,0x2001);s.g(2,0x2001);let reservation=ExclusiveReservation{address:0x4000,width:32,scope:MemoryScope::System,token:0x55};s.monitor=Some(reservation);s.mem.clear();let t=run(word,thumb,&s);assert!(t.atomics.is_empty());assert!(t.events.is_empty());assert!(t.memory.is_empty());assert!(no_scalar(&t));assert_eq!(s.atomic_calls.get(),0);assert_eq!(s.monitor_reads.get(),0);assert_eq!(s.plain_reads.get(),0);if thumb{assert_eq!(v_it(&t),0);}s.apply(&t);assert_eq!(s.monitor,Some(reservation));}}
 #[test]fn atomic_true_predication_and_context_rejection_are_deterministic(){
  let mut s=atomic_state();s.f(1,1);let t=run(0x01910f9f,false,&s);assert_eq!(g(&t,0),0x44332211);assert_eq!(s.atomic_calls.get(),1);
  let mut s=atomic_state();s.it(8);s.f(1,1);let t=run(0xe8d10fef,true,&s);assert_eq!(g(&t,0),0x44332211);assert_eq!(v_it(&t),0);assert_eq!(s.atomic_calls.get(),1);
  s.it(0xf8);let r=decode(0xe8d10fef,true).semantic_recipe(0);assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert_eq!(s.atomic_calls.get(),1);
  struct UnknownIt;impl Machine for UnknownIt{fn read_register(&self,r:Register)->Value{if r.bank=="a32.itstate"{Value::unknown(8)}else{Value::known(32,0)}}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unknown IT accessed memory")}}
  assert_eq!(evaluate(&decode(0x2001,true).semantic_recipe(0),&UnknownIt),Err(EvalError::UnknownCondition));
  // Rejected ARM-state target alignment is an explicit context error, never an
  // undefined PC or a nondeterministic choice to execute the branch.
  let mut s=State::default();s.g(1,0x3002);assert_eq!(evaluate(&decode(0xe1a0f001,false).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));s.g(1,0x2000);s.put(0x2000,0x3002);assert_eq!(evaluate(&decode(0xf8d1f000,true).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));
 }
 #[test]fn atomic_constraints_and_backend_unavailability_are_explicit(){
  for word in[0xe19f0f9f,0xe191ff9f,0xe1b21f9f,0xe1b2ef9f,0xe1822f91,0xe1821f91,0xe1a12f92,0xe1810c90,0xe1022091,0xe1020092,0xe1910b9f]{let r=recipes::for_word(word,0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");assert!(r.atomics.is_empty());}
  for word in[0xe85f0f00,0xe851ff00,0xe8d2017e,0xe8d2007f,0xe8c22372,0xe8d10e4f,0xe8c10fa0,0xe8d20fbf]{let r=recipes::for_thumb(word,4,0,Endian::Little);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");assert!(r.atomics.is_empty());}
  for(word,thumb)in[(0xe1910f9f,false),(0xe1020091,false),(0xe8510f03,true)]{let mut s=atomic_state();s.g(1,0x2001);s.g(2,0x2001);let r=decode(word,thumb).semantic_recipe(0x1000);assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert_eq!(s.atomic_calls.get(),0);}
  struct Missing;impl Machine for Missing{fn read_register(&self,r:Register)->Value{Value::known(32,if r.bank=="a32.gpr"{0x2000}else{0})}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("native atomic used ordinary load")}}
  for(word,thumb)in[(0xe1910f9f,false),(0xe1020091,false),(0xe8510f03,true)]{assert_eq!(evaluate(&decode(word,thumb).semantic_recipe(0x1000),&Missing),Err(EvalError::Unsupported));}
 }
 #[test]fn constrained_bitfields_fail_without_panicking(){for word in[0xe7c30411,0xe7cf0f91,0xe4811004]{assert!(matches!(recipes::for_word(word,0).support,Support::Unsupported(_)));}for word in[0xf3612003,0xf36f2003,0xf8411b04]{assert!(matches!(recipes::for_thumb(word,4,0,Endian::Little).support,Support::Unsupported(_)));}}
 #[test]fn invalid_contexts_and_non_scalar_classes_are_explicit(){let mut s=State::default();s.it(0x0c);s.f(1,1);for word in[0xe002,0xbf08,0xb110]{assert_eq!(evaluate(&decode(word,true).semantic_recipe(0x1000),&s),Err(EvalError::UnsupportedContext));}s.it(0xf8);assert_eq!(evaluate(&decode(0x2001,true).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));s.it(8);s.f(1,0);let t=run(0xe002,true,&s);assert_eq!(t.next_pc.bits,0x1002);assert_eq!(v(&t,"a32.itstate",0),0);for(word,thumb)in[(0xe321f001,false),(0xe1600070,false),(0xdf00,true),(0xe8d10fbf,true)]{assert!(matches!(decode(word,thumb).semantic_recipe(0).support,Support::Unsupported(_)),"{word:08x}");}}
 #[test]fn vfp_nonfused_stages_signs_aliases_and_rounding(){for thumb in[false,true]{let mut s=State::default();s.set("a32.vector64",0,lanes([3f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",1,4f32.to_bits() as u64);for(word,want)in[(0xee000a81,11f32),(0xee000ac1,-5f32),(0xee100ac1,-11f32),(0xee100a81,5f32),(0xee200ac1,-8f32)]{s.float_calls.set(0);let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([want.to_bits(),2f32.to_bits()]));assert_eq!(s.float_calls.get(),if word==0xee200ac1{3}else{6});}
  s.set("a32.vector64",0,lanes([3f32.to_bits(),2f32.to_bits()]));assert_eq!(v(&run(0xee000a01,thumb,&s),"a32.vector64",0),lanes([15f32.to_bits(),2f32.to_bits()]));
  s.set("a32.vector64",16,3f64.to_bits());s.set("a32.vector64",17,2f64.to_bits());s.set("a32.vector64",18,4f64.to_bits());assert_eq!(v(&run(0xee410ba2,thumb,&s),"a32.vector64",16),11f64.to_bits());
  s.set("a32.vector64",0,lanes([(-1f32).to_bits(),0x3f800001]));s.set("a32.vector64",1,0x3f7ffffe);s.set("a32.fpscr",0,2);s.float_statuses.borrow_mut().clear();let t=run(0xee000a81,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([0,0x3f800001]));assert_eq!(v(&t,"a32.fpscr",0),18);let seen=s.float_statuses.borrow();assert_eq!(seen.iter().map(|v|v.2).collect::<Vec<_>>(),vec![2,18]);drop(seen);
  s.set("a32.fpscr",0,0x1002);s.float_calls.set(0);s.float_statuses.borrow_mut().clear();let t=run(0xee000a81,thumb,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(v(&t,"a32.fpscr",0),0x1012);assert!(t.registers.iter().all(|w|w.register.bank!="a32.vector64"));assert_eq!(s.float_calls.get(),3);assert_eq!(s.float_statuses.borrow().len(),1);
  s.set("a32.vector64",0,lanes([(2f32.powi(-24)).to_bits(),1f32.to_bits()]));s.set("a32.vector64",1,1f32.to_bits() as u64);s.float_calls.set(0);let t=run(0xee000a81,thumb,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(s.float_calls.get(),6);assert_eq!(v(&t,"a32.fpscr",0),0x1012);
  s.set("a32.fpscr",0,1<<20);assert_eq!(evaluate(&decode(0xee000a81,thumb).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));
  if thumb{s.it(8);s.f(1,0);s.float_calls.set(0);assert!(no_scalar(&run(0xee000a81,true,&s)));assert_eq!(s.float_calls.get(),0);}
 }}
 #[test]fn neon_nonfused_rounding_status_and_input_aliases(){for thumb in[false,true]{let mut s=State::default();let prefix=if thumb{0xef000000}else{0xf2000000};s.set("a32.vector64",0,lanes([(-1f32).to_bits(),3f32.to_bits()]));s.set("a32.vector64",1,lanes([5f32.to_bits(),7f32.to_bits()]));s.set("a32.vector64",2,lanes([0x3f800001,2f32.to_bits()]));s.set("a32.vector64",3,lanes([3f32.to_bits(),4f32.to_bits()]));s.set("a32.vector64",4,lanes([0x3f7ffffe,4f32.to_bits()]));s.set("a32.vector64",5,lanes([5f32.to_bits(),6f32.to_bits()]));s.set("a32.fpscr",0,0x1002);let t=run(prefix|0x020d54,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([0,11f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([20f32.to_bits(),31f32.to_bits()]));assert_eq!(v(&t,"a32.fpscr",0),0x1012);assert_eq!(t.trap,None);assert_eq!(s.float_calls.get(),24);let seen=s.float_statuses.borrow();assert_eq!(seen[0].2,0x1002);assert_eq!(seen[1].2,0x1012);assert!(seen.iter().all(|v|v.0==FloatEnvironment::A32Neon));drop(seen);
  s.set("a32.vector64",2,lanes([1f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",3,lanes([3f32.to_bits(),4f32.to_bits()]));s.set("a32.vector64",4,lanes([1f32.to_bits(),4f32.to_bits()]));let t=run(prefix|0x220d54,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([(-2f32).to_bits(),(-5f32).to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([(-10f32).to_bits(),(-17f32).to_bits()]));
  s.set("a32.vector64",0,lanes([1f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",1,lanes([3f32.to_bits(),4f32.to_bits()]));let t=run(prefix|0x000d50,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([2f32.to_bits(),6f32.to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([12f32.to_bits(),20f32.to_bits()]));
  if thumb{s.it(8);s.f(1,0);s.float_calls.set(0);assert!(no_scalar(&run(prefix|0x020d54,true,&s)));assert_eq!(s.float_calls.get(),0);}
 }}
 #[test]fn half_transports_preserve_nan_bits_and_correct_s_register_slices(){for thumb in[false,true]{let mut s=State::default();s.set("a32.vector64",0,0xfffffc0112345678);assert_eq!(g(&run(0xee100990,thumb,&s),0),0xfc01);s.g(0,0xaabbccdd);assert_eq!(v(&run(0xee000990,thumb,&s),"a32.vector64",0),0x0000ccdd12345678);
  assert_eq!(v(&run(0xeeb009e0,thumb,&s),"a32.vector64",0),0xfffffc0100007c01);assert_eq!(v(&run(0xeeb10960,thumb,&s),"a32.vector64",0),0xfffffc0100007c01);
  for(word,want)in[(0xeeb70900,0xfffffc0100003c00),(0xeeb70a00,0xfffffc013f800000),(0xeeb70b00,1f64.to_bits())]{assert_eq!(v(&run(word,thumb,&s),"a32.vector64",0),want);}
  s.g(1,0x2000);s.put(0x2000,0x78563412);for(endian,want)in[(Endian::Little,0x7856),(Endian::Big,0x5678)]{let t=run_at(0xed910901,thumb,&s,0x1000,endian);assert_eq!(v(&t,"a32.vector64",0),0xfffffc0100000000|want);let t=run_at(0xed810901,thumb,&s,0x1000,endian);assert_eq!((t.memory[0].address,t.memory[0].value.width,t.memory[0].value.bits,t.memory[0].endian),(0x2002,16,0x5678,endian));}
  assert_eq!(s.float_calls.get(),0);assert!(s.float_statuses.borrow().is_empty());
  s.set("a32.vector64",1,0xaaaaaaaa87654321);let t=run(0xec510a30,thumb,&s);assert_eq!((g(&t,0),g(&t,1)),(0xfffffc01,0x87654321));s.g(0,0x11223344);s.g(1,0x55667788);let t=run(0xec410a30,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),0x1122334412345678);assert_eq!(v(&t,"a32.vector64",1),0xaaaaaaaa55667788);
  if thumb{s.it(8);s.f(1,1);for word in[0xee100990,0xeeb009e0,0xeeb70900,0xed910901]{assert_eq!(evaluate(&decode(word,true).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));}}
 }}
 #[test]fn vector_abs_negation_are_pure_bit_transports(){for thumb in[false,true]{let mut s=State::default();let prefix=if thumb{0xff000000}else{0xf3000000};s.set("a32.vector64",2,0xffc12345ffc54321);s.set("a32.vector64",3,0x8000000000000000);for(word,mask,negate)in[(0xb90742,0x8000000080000000,false),(0xb907c2,0x8000000080000000,true),(0xb50742,0x8000800080008000,false),(0xb507c2,0x8000800080008000,true)]{let t=run(prefix|word,thumb,&s);for(d,input)in[(0,0xffc12345ffc54321),(1,0x8000000000000000)]{assert_eq!(v(&t,"a32.vector64",d),if negate{input^mask}else{input&!mask});}assert!(t.registers.iter().all(|w|w.register.bank=="a32.vector64"||w.register.bank=="a32.itstate"));}assert_eq!(s.float_calls.get(),0);}}

 #[test]fn vfp_compare_updates_fpscr_only_and_vmrs_transfers_nzcv(){for thumb in[false,true]{let mut s=State::default();for(left,right,nzcv)in[(1f32,2f32,8),(2f32,1f32,2),(1f32,1f32,6),(-0f32,0f32,6)]{s.set("a32.vector64",0,lanes([left.to_bits(),right.to_bits()]));s.set("a32.fpscr",0,0xa0000002);let t=run(0xeeb40a60,thumb,&s);assert_eq!(v(&t,"a32.fpscr",0),(nzcv<<28)|2);assert!(t.registers.iter().all(|w|w.register.bank!="a32.nzcv"));}
  for(word,source,invalid)in[(0xeeb40a60,0x7fc12345,false),(0xeeb40ae0,0x7fc12345,true),(0xeeb40a60,0x7f812345,true)]{s.set("a32.vector64",0,lanes([source,1f32.to_bits()]));s.set("a32.fpscr",0,0xa0000002);let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.fpscr",0),0x30000002|invalid as u64);assert_eq!(t.trap,None);}
  s.set("a32.vector64",0,lanes([0x7fc12345,1f32.to_bits()]));s.set("a32.fpscr",0,0xa0000102);let t=run(0xeeb40ae0,thumb,&s);assert_eq!(v(&t,"a32.fpscr",0),0xa0000103);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|w|w.register.bank!="a32.nzcv"));
  s.set("a32.vector64",0,(-1f32).to_bits() as u64);s.set("a32.fpscr",0,2);assert_eq!(v(&run(0xeeb50a40,thumb,&s),"a32.fpscr",0),0x80000002);s.set("a32.vector64",16,(-1f64).to_bits());assert_eq!(v(&run(0xeef50b40,thumb,&s),"a32.fpscr",0),0x80000002);s.set("a32.vector64",17,f64::NAN.to_bits());assert_eq!(v(&run(0xeef40be1,thumb,&s),"a32.fpscr",0),0x30000003);s.set("a32.vector64",16,f64::NAN.to_bits());assert_eq!(v(&run(0xeef50bc0,thumb,&s),"a32.fpscr",0),0x30000003);
  for nzcv in 0..16{s.set("a32.fpscr",0,(nzcv<<28)|0x1234);let t=run(0xeef1fa10,thumb,&s);assert_eq!((f(&t,0),f(&t,1),f(&t,2),f(&t,3)),((nzcv>>3)&1,(nzcv>>2)&1,(nzcv>>1)&1,nzcv&1));assert_eq!(g(&run(0xeef10a10,thumb,&s),0),(nzcv<<28)|0x1234);}
  if thumb{s.it(8);s.f(1,0);s.float_calls.set(0);assert!(no_scalar(&run(0xeeb40ae0,true,&s)));assert_eq!(s.float_calls.get(),0);}
 }}
 #[test]fn signed_fused_operations_use_typed_input_sign_changes(){for thumb in[false,true]{let mut s=State::default();s.set("a32.vector64",0,lanes([3f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",1,4f32.to_bits() as u64);for(word,want)in[(0xeea00a81,11f32),(0xeea00ac1,-5f32),(0xee900ac1,-11f32),(0xee900a81,5f32)]{s.float_calls.set(0);let t=run(word,thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([want.to_bits(),2f32.to_bits()]));assert_eq!(s.float_calls.get(),3);}
  s.set("a32.vector64",0,lanes([(-1f32).to_bits(),0x3f800001]));s.set("a32.vector64",1,0x3f7ffffe);assert_eq!(v(&run(0xee900ac1,thumb,&s),"a32.vector64",0),lanes([0x28800000,0x3f800001]));
  s.set("a32.vector64",0,lanes([3f32.to_bits(),3f32.to_bits()]));s.set("a32.vector64",1,lanes([3f32.to_bits(),3f32.to_bits()]));s.set("a32.vector64",2,lanes([2f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",3,lanes([2f32.to_bits(),2f32.to_bits()]));s.set("a32.vector64",4,lanes([4f32.to_bits(),4f32.to_bits()]));s.set("a32.vector64",5,lanes([4f32.to_bits(),4f32.to_bits()]));let t=run(if thumb{0xef220c54}else{0xf2220c54},thumb,&s);assert_eq!(v(&t,"a32.vector64",0),lanes([(-5f32).to_bits(),(-5f32).to_bits()]));assert_eq!(v(&t,"a32.vector64",1),lanes([(-5f32).to_bits(),(-5f32).to_bits()]));
 }}

 #[test]fn legacy_half_conversion_selects_s_half_and_preserves_unselected_storage(){for thumb in[false,true]{for &(from,to,input,control,output,raised)in HALF_CASES{for top in[false,true]{let mut s=State::default();let sentinel=0xa5a55a5a11223344u64;let shift=if top{16}else{0};s.set("a32.fpscr",0,control|2);let word=if from==16{let incoming=(0x55667788u32 as u64&!(0xffff<<shift))|(input<<shift);s.set("a32.vector64",0,(incoming<<32)|0x11223344);if to==32{0xeeb20a60}else{0xeeb20b60}}else{s.set("a32.vector64",0,sentinel);if from==32{s.set("a32.vector64",0,(input<<32)|(sentinel&0xffffffff));0xeeb30a60}else{s.set("a32.vector64",1,input);0xeeb30b41}}|if top{0x80}else{0};let before=s.regs.clone();let t=run(word,thumb,&s);let expected=if to==16{let old=*s.regs.get(&Register{bank:"a32.vector64",index:0}).unwrap();(old&!(0xffff<<shift))|(output<<shift)}else if to==32{let old=*s.regs.get(&Register{bank:"a32.vector64",index:0}).unwrap();(old&0xffffffff00000000)|output}else{output};assert_eq!(v(&t,"a32.vector64",0),expected,"{word:08x} {from}->{to} {input:016x} ctrl={control:08x}");assert_eq!(v(&t,"a32.fpscr",0),control|2|raised);assert_eq!(t.trap,None);assert_eq!(s.float_calls.get(),3);assert_eq!(s.float_statuses.borrow().as_slice(),&[(FloatEnvironment::A32Vfp,control|2,control|2)]);assert_eq!(s.regs,before);assert!(t.registers.iter().all(|w|w.register.bank!="a32.nzcv"));}}}}
 #[test]fn legacy_half_aliases_high_registers_predication_and_checked_ahp(){for thumb in[false,true]{let mut s=State::default();s.set("a32.vector64",0,0x3f80100011223344);assert_eq!(v(&run(0xeef30a60,thumb,&s),"a32.vector64",0),0x3f803c0011223344);s.set("a32.vector64",0,0x3c00000111223344);assert_eq!(v(&run(0xeef20ae0,thumb,&s),"a32.vector64",0),0x3f80000011223344);
  s.set("a32.vector64",15,0xaabbccdd11223344);s.set("a32.vector64",31,0x3ff0000000000000);let t=run(0xeef3fb6f,thumb,&s);assert_eq!(v(&t,"a32.vector64",15),0xaabb3c0011223344);s.set("a32.vector64",15,0x3c00123411223344);assert_eq!(v(&run(0xeef2fbef,thumb,&s),"a32.vector64",31),0x3ff0000000000000);
  s.set("a32.vector64",0,0x3f80100011223344);s.set("a32.fpscr",0,0x00110000);assert_eq!(v(&run(0xeeb30a60,thumb,&s),"a32.vector64",0),0x3f80100011223c00); // source permits legacy LEN/STRIDE
  s.set("a32.fpscr",0,1<<26);s.float_calls.set(0);assert_eq!(evaluate(&decode(0xeeb30a60,thumb).semantic_recipe(0),&s),Err(EvalError::UnsupportedContext));assert_eq!(s.float_calls.get(),0);
  if thumb{s.it(8);s.f(1,0);assert!(no_scalar(&run(0xeeb30a60,true,&s)));assert_eq!(s.float_calls.get(),0);s.set("a32.fpscr",0,0);s.f(1,1);let t=run(0xeeb30a60,true,&s);assert_eq!(v(&t,"a32.vector64",0),0x3f80100011223c00);assert_eq!(v_it(&t),0);}else{s.f(1,0);assert!(no_scalar(&run(0x0eb30a60,false,&s)));s.set("a32.fpscr",0,0);s.f(1,1);assert_eq!(v(&run(0x0eb30a60,false,&s),"a32.vector64",0),0x3f80100011223c00);}
 }}
 #[test]fn legacy_half_traps_before_partial_destination_update(){for thumb in[false,true]{for(input,enable,raised)in[(0x7f812345,0x100,1),(0x33000000,0x800,24),(0x3f801000,0x1000,16)]{let mut s=State::default();s.set("a32.vector64",0,((input as u64)<<32)|0x11223344);s.set("a32.fpscr",0,enable|2);let t=run(0xeeb30ae0,thumb,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(v(&t,"a32.fpscr",0),enable|2|raised);assert!(t.registers.iter().all(|w|w.register.bank!="a32.vector64"));assert_eq!(s.float_calls.get(),3);}}}

}
`

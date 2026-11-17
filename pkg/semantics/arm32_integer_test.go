package semantics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

//go:embed arm32_integer.rs
var arm32IntegerSource string

func TestRustArm32IntegerDSPAndSIMD(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"runtime.rs": RustRuntime, "arm32_integer.rs": arm32IntegerSource,
		"integer_tests.rs": arm32IntegerBehaviorTests + arm32IntegerExtendedTests + arm32IntegerShiftTests + arm32IntegerCorpus(t),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "integer_tests.rs", "-Dwarnings", "-o", "integer-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile generated DSP/SIMD recipes: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "integer-tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute DSP/SIMD recipes: %v\n%s", err, out)
	}
}

// Derive words from actual public encoding diagrams; tests also exercise an
// independent numeric oracle rather than relying on decode/recipe labels.
func arm32IntegerCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Documents", "Developer", "go-mkasm", "ISA_AArch32_xml_A_profile-2026-06.tar.gz")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		t.Log("optional Arm corpus absent; running portable behavioral cases")
		return "const DSP_CORPUS: &[(bool,u32)] = &[];\n"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	names := strings.Fields(`qadd qsub qdadd qdsub qadd16 qasx qsax qsub16 qadd8 qsub8 uqadd16 uqasx uqsax uqsub16 uqadd8 uqsub8 shadd16 shasx shsax shsub16 shadd8 shsub8 uhadd16 uhasx uhsax uhsub16 uhadd8 uhsub8 ssat usat ssat16 usat16 smlabb smulbb smlawb smulwb smlad smuad smlsd smusd smlalbb smlald smlsld smmla smmls smmul vqadd vqsub vmla_i vmls_i vqdmulh vqrdmulh vaddl vaddw vsubl vsubw vmull_i vmlal_i vmlsl_i vmovn vqmovn vmovl vshll vrev16 vrev32 vrev64 vtrn vzip vuzp vshl_i vshr vrshr vsli vsri vshl_r vrshl vqshl_i vqshl_r vqrshl vshrn vrshrn vqshrn vqrshrn`)
	wanted := make(map[string]bool)
	for _, name := range names {
		wanted[name+".xml"] = true
	}
	var out strings.Builder
	out.WriteString("\nconst DSP_CORPUS: &[(bool,u32)] = &[\n")
	reader := tar.NewReader(compressed)
	count := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(header.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !wanted[filepath.Base(header.Name)] {
			continue
		}
		name := filepath.Base(header.Name)
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		decoder := xml.NewDecoder(bytes.NewReader(body))
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "regdiagram" {
				continue
			}
			var diagram systemCorpusDiagram
			if err := decoder.DecodeElement(&diagram, &start); err != nil {
				t.Fatal(err)
			}
			if name == "vqdmulh.xml" || name == "vqrdmulh.xml" {
				vector := false
				for _, box := range diagram.Boxes {
					vector = vector || box.Name == "Q" && box.Hi == 6
				}
				if !vector {
					continue // Scalar-element multiply is a distinct encoding family.
				}
			}
			for variant := 0; variant < 4; variant++ {
				var word uint32
				for _, box := range diagram.Boxes {
					width := box.Width
					if width == 0 {
						width = 1
					}
					var fixed strings.Builder
					for _, cell := range box.Cells {
						text := strings.Trim(strings.TrimSpace(cell.Text), "()")
						if text == "0" || text == "1" {
							fixed.WriteString(text)
						}
					}
					var value uint64
					if fixed.Len() == width {
						value, err = strconv.ParseUint(fixed.String(), 2, 32)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						switch box.Name {
						case "cond":
							value = 14
						case "Rn":
							value = 1
						case "Rm":
							value = 2
						case "Ra":
							value = 3
						case "RdHi":
							value = 1
						case "Vn":
							value = 2
						case "Vm":
							value = 4
						case "D", "N", "M", "U":
							value = uint64(variant & 1)
						case "Q", "sh":
							value = uint64((variant >> 1) & 1)
						case "size":
							value = uint64(variant % 3)
							if name == "vrev16.xml" {
								value = 0
							}
							if name == "vrev32.xml" {
								value = uint64(variant % 2)
							}
							if name == "vqdmulh.xml" || name == "vqrdmulh.xml" {
								value = uint64(1 + variant%2)
							}
						case "imm3H":
							value = uint64(1 << (variant % 3))
						case "imm6":
							value = uint64((8 << (variant % 3)) + variant)
						case "sat_imm":
							value = 7
						case "imm5", "imm2":
							value = 1
						case "op":
							if name == "vqmovn.xml" {
								value = uint64(1 + variant%3)
							} else if name == "vqshrn.xml" || name == "vqrshrn.xml" || name == "vqshl_i.xml" {
								value = 1
							}
						}
					}
					word |= uint32(value) << uint(box.Hi-width+1)
				}
				fmt.Fprintf(&out, "(%t,0x%08x), // %s\n", diagram.Form == "16x2", word, name)
				count++
			}
		}
	}
	out.WriteString("];\n")
	t.Logf("derived %d DSP/SIMD encodings from %d corpus families", count, len(names))
	return out.String()
}

const arm32IntegerBehaviorTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
mod arm32_integer;
use std::cell::Cell;
#[derive(Clone,Default)]struct State {g:[u32;15],d:[u64;32],q:u64,fpscr:u32,reads:Cell<usize>}
impl Machine for State {
 fn read_register(&self,r:Register)->Value {
  self.reads.set(self.reads.get()+1);
  match r.bank {
   "a32.gpr"=>Value::known(32,u64::from(self.g[r.index as usize])),
   "a32.vector64"=>Value::known(64,self.d[r.index as usize]),
   "a32.q"=>{assert_eq!(r.index,0);Value::known(1,self.q)},
   "a32.fpscr"=>{assert_eq!(r.index,0);Value::known(32,u64::from(self.fpscr))},
   _=>panic!("unexpected state dependency {r:?}"),
  }
 }
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("integer instruction read memory")}
}
fn base(active:bool,thumb:bool)->Recipe {
 let mut r=Recipe::new(0x1004,32);r.guard=Expr::constant(1,u64::from(active));
 if thumb {r.write_always(register("it",0,8,8),WritePolicy::ZeroUpper,Expr::constant(8,0x18));}r
}
fn recipe(word:u32,thumb:bool,active:bool)->Recipe {
 let original=base(active,thumb);let r=if thumb {arm32_integer::thumb(word,4,original.clone())}else{arm32_integer::a32(word,original.clone())}.unwrap_or_else(||panic!("unhandled {word:08x} thumb={thumb}"));
 assert_eq!(r.guard,original.guard);assert_eq!(r.always_writes,original.always_writes);r
}
fn run(word:u32,thumb:bool,s:&State)->Transition {let r=recipe(word,thumb,true);assert_eq!(r.support,Support::Full,"{word:08x}");evaluate(&r,s).unwrap()}
fn out(t:&Transition,bank:&str,index:u16)->Value {t.registers.iter().find(|w|w.register.bank==bank && w.register.index==index).unwrap_or_else(||panic!("missing {bank}/{index}: {:?}",t.registers)).value}
fn sat(x:i128,w:u8,signed:bool)->(u64,bool) {
 let lo=if signed {-(1i128<<(w-1))}else{0};let hi=if signed {(1i128<<(w-1))-1}else{(1i128<<w)-1};
 ((x.clamp(lo,hi) as u64)&mask(w),x<lo || x>hi)
}
fn signed(x:u64,w:u8)->i128 {let x=i128::from(x&mask(w));if x&(1i128<<(w-1))!=0 {x-(1i128<<w)}else{x}}
fn elem(x:u64,i:u8,w:u8)->u64 {(x>>(i*w))&mask(w)}
fn repeat(x:u64,w:u8)->u64 {(0..64/w).fold(0,|a,i|a|((x&mask(w))<<(i*w)))}
fn vecword(base:u32,d:u32,n:u32,m:u32,q:bool,size:u32,unsigned:bool)->u32 {
 base|((d&15)<<12)|((d&16)<<18)|((n&15)<<16)|((n&16)<<3)|(m&15)|((m&16)<<1)|(u32::from(q)<<6)|(size<<20)|(u32::from(unsigned)<<24)
}
fn thumbword(w:u32)->u32 {0xef000000|(w&0x00ffffff)|((w&0x01000000)<<4)}
fn unchanged_flags(t:&Transition) {assert!(t.registers.iter().all(|w|w.register.bank!="a32.nzcv"));}
#[test]fn scalar_q_arithmetic_saturates_both_stages_and_keeps_sticky_q() {
 let samples=[i32::MIN,i32::MIN+1,-1073741824,-1,0,1,1073741824,i32::MAX-1,i32::MAX];
 for a in samples {for z in samples {for op in 0..4u32 {for oldq in 0..2 {
  let mut s=State::default();s.g[0]=a as u32;s.g[1]=z as u32;s.q=oldq;
  let (right,sat1)=if op&2!=0 {let(v,q)=sat(i128::from(z)*2,32,true);(signed(v,32),q)}else{(i128::from(z),false)};
  let (expected,sat2)=sat(if op&1!=0 {i128::from(a)-right}else{i128::from(a)+right},32,true);
  for (thumb,w) in [(false,0xe1000050|(op<<21)|(1<<16)|(2<<12)),(true,0xfa81f280|((op&1)<<5)|((op>>1)<<4))] {
   let t=run(w,thumb,&s);assert_eq!(out(&t,"a32.gpr",2).bits,expected,"op={op} a={a} b={z}");
   assert_eq!(out(&t,"a32.q",0).bits,oldq|u64::from(sat1||sat2));unchanged_flags(&t);
  }
 }}}}
}
#[test]fn parallel_saturation_and_halving_never_set_q_or_carry() {
 let patterns=[0,0x01017f7f,0x80008000,0x7fff7fff,0x8080ffff,0xffffffff,0x7f0080ff];
 let tops=[0xfa90f000,0xfaa0f000,0xfae0f000,0xfad0f000,0xfa80f000,0xfac0f000];
 for (j,op) in [0,1,2,3,4,7].into_iter().enumerate() {for kind in [2,3,6,7] {for a in patterns {for z in patterns {
  let width=if op>=4 {8}else{16};let is_signed=kind&4==0;let half=kind&1!=0;
  let mut expected=0u32;
  for i in 0..32/width {
   let other=if op==1||op==2 {i^1}else{i};let sub=match op {1=>i==0,2=>i==1,3|7=>true,_=>false};
   let x=elem(u64::from(a),i,width);let y=elem(u64::from(z),other,width);
   let x=if is_signed {signed(x,width)}else{i128::from(x)};let y=if is_signed {signed(y,width)}else{i128::from(y)};
   let v=if sub {x-y}else{x+y};let v=if half {(v>>1) as u64&mask(width)}else{sat(v,width,is_signed).0};
   expected|=(v as u32)<<(i*width);
  }
  let mut s=State::default();s.g[1]=a;s.g[2]=z;s.q=1;
  let selector=match kind {2=>1,3=>2,6=>5,_=>6};
  for (thumb,w) in [(false,0xe6000f10|(kind<<20)|(op<<5)|(1<<16)|2),(true,tops[j]|(1<<16)|(selector<<4)|2)] {
   let t=run(w,thumb,&s);assert_eq!(out(&t,"a32.gpr",0).bits,u64::from(expected));
   assert!(t.registers.iter().all(|w|matches!(w.register.bank,"a32.gpr"|"it")));unchanged_flags(&t);
  }
 }}}}
}
#[test]fn ssat_usat_and_halfword_forms_handle_width_zero_shift_wrap_and_q() {
 for signed_out in [false,true] {for imm in 0..32u32 {for value in [0,1,0x7fffffff,0x80000000,0xffffffff,0x12345678] {for asr in [false,true] {for shift in [0,1,15,31] {
  let mut s=State::default();s.g[1]=value;
  let shifted=if asr {(value as i32).checked_shr(if shift==0 {32}else{shift}).unwrap_or(if value&0x80000000!=0 {-1}else{0}) as u32}else{value.wrapping_shl(shift)};
  let bits=(imm+u32::from(signed_out)) as u8;let(expected,q)=sat(i128::from(shifted as i32),bits,signed_out);
  let expected=if signed_out {signed(expected,bits) as u32}else{expected as u32};
  let w=(if signed_out {0xe6a00010}else{0xe6e00010})|(imm<<16)|(shift<<7)|(u32::from(asr)<<6)|1;
  let t=run(w,false,&s);assert_eq!(out(&t,"a32.gpr",0).bits,u64::from(expected));assert_eq!(out(&t,"a32.q",0).bits,u64::from(q));
  // T32 ASR #0 aliases the two-lane saturation instruction.
  if !asr || shift!=0 {
   let w=(if signed_out {0xf3010000}else{0xf3810000})|((shift>>2)<<12)|((shift&3)<<6)|(u32::from(asr)<<21)|imm;
   let t=run(w,true,&s);assert_eq!(out(&t,"a32.gpr",0).bits,u64::from(expected));assert_eq!(out(&t,"a32.q",0).bits,u64::from(q));
  }
 }}}}}
 for signed_out in [false,true] {for imm in 0..16u32 {for value in [0x7fff8000,0xffffffff,0x12345678] {
  let mut s=State::default();s.g[1]=value;let bits=(imm+u32::from(signed_out)) as u8;let mut expected=0;let mut q=false;
  for i in 0..2 {let(v,saturated)=sat(signed(u64::from(value>>(i*16)),16),bits,signed_out);q|=saturated;
   expected|=if signed_out {(signed(v,bits) as u32&0xffff)<<(i*16)}else{(v as u32)<<(i*16)};
  }
  for (thumb,w) in [(false,(if signed_out {0xe6a00f30}else{0xe6e00f30})|(imm<<16)|1),(true,(if signed_out {0xf3210000}else{0xf3a10000})|imm)] {
   let t=run(w,thumb,&s);assert_eq!(out(&t,"a32.gpr",0).bits,u64::from(expected));assert_eq!(out(&t,"a32.q",0).bits,u64::from(q));
  }
 }}}
}
#[test]fn neon_saturating_add_sub_covers_64bit_carry_and_dq_overlap() {
 for size in 0..4 {let bits=8u8<<size;for unsigned in [false,true] {for sub in [false,true] {for q in [false,true] {for a in [0,1,mask(bits-1),1u64<<(bits-1),mask(bits)] {for z in [0,1,mask(bits-1),1u64<<(bits-1),mask(bits)] {
  let mut s=State::default();s.d[0]=repeat(a,bits);s.d[1]=repeat(z,bits);s.d[2]=repeat(z,bits);s.d[3]=repeat(a,bits);s.fpscr=0xa000009f;
  let x=if unsigned {i128::from(a)}else{signed(a,bits)};let y=if unsigned {i128::from(z)}else{signed(z,bits)};
  let(v,saturated)=sat(if sub {x-y}else{x+y},bits,!unsigned);
  let word=vecword(if sub {0xf2000210}else{0xf2000010},0,0,2,q,size,unsigned);
  // Destination aliases the first source. Q1 is D2:D3, with different high input.
  for thumb in [false,true] {
   let t=run(if thumb {thumbword(word)}else{word},thumb,&s);
   assert_eq!(out(&t,"a32.vector64",0).bits,repeat(v,bits),"{word:08x} {a:x} {z:x}");
   let mut any=saturated;
   if q {let(v,more)=sat(if sub {y-x}else{y+x},bits,!unsigned);assert_eq!(out(&t,"a32.vector64",1).bits,repeat(v,bits));any|=more;}
   assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(any)<<27));unchanged_flags(&t);
  }
 }}}}}}
}
#[test]fn simd_narrowing_shares_q_storage_and_accumulates_qc() {
 for size in 0..3 {let width=8u8<<size;for op in 0..4u32 {for input in [0,1,mask(width-1),mask(width),mask(width)+1,1u64<<(width*2-1),mask(width*2)] {
  let mut s=State::default();s.d[0]=repeat(input,width*2);s.d[1]=s.d[0];s.fpscr=0x100009f;
  let value=if op==3 {i128::from(input)}else{signed(input,width*2)};
  let(v,q)=if op==0 {(input&mask(width),false)}else{sat(value,width,op&1==0)};
  let word=0xf3b20200|(size<<18)|(op<<6);
  for thumb in [false,true] {let t=run(if thumb {thumbword(word)}else{word},thumb,&s);
   assert_eq!(out(&t,"a32.vector64",0).bits,repeat(v,width));
   if op!=0 {assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(q)<<27));}
  }
 }}}
}
#[test]fn corpus_words_have_executable_recipes_and_false_predication_reads_nothing() {
 for &(thumb,word) in DSP_CORPUS {
  let s=State::default();let r=recipe(word,thumb,true);assert_eq!(r.support,Support::Full,"{word:08x} thumb={thumb}");
  evaluate(&r,&s).unwrap_or_else(|e|panic!("{word:08x} {e:?}"));
  s.reads.set(0);let r=recipe(word,thumb,false);let t=evaluate(&r,&s).unwrap();
  assert_eq!(s.reads.get(),0,"inactive {word:08x}");
  assert_eq!(t.registers.len(),usize::from(thumb));assert!(t.registers.iter().all(|w|w.register.bank=="it"));
 }
}
#[test]fn malformed_operands_reject_without_writes_and_unknown_permutation_stays_unknown() {
 for (thumb,word) in [(false,0xe100f051),(true,0xfa81ff80),(true,0xf3210010),(true,0xf3a10010),(false,0xe7411012),(false,0xf2010052),(false,0xf3b20201),(false,0xf3b21140)] {
  let r=recipe(word,thumb,true);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");assert_eq!(evaluate(&r,&State::default()),Err(EvalError::Unsupported));
 }
 assert!(arm32_integer::a32(0xe1a00000,base(true,false)).is_none());
 assert!(arm32_integer::a32(0xf1000050,base(true,false)).is_none());
 assert!(arm32_integer::thumb(0x1234,2,base(true,true)).is_none());
 let t=run(0xf3b20080,false,&State::default());assert_eq!(out(&t,"a32.vector64",0).defined,0);
}
`

const arm32IntegerExtendedTests = `
struct UnknownStatus(State);
impl Machine for UnknownStatus {
 fn read_register(&self,r:Register)->Value {match r.bank {"a32.q"=>Value::unknown(1),"a32.fpscr"=>Value::unknown(32),_=>self.0.read_register(r)}}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
}
#[test]fn known_saturation_defines_q_and_qc_even_with_unknown_incoming_status() {
 let mut s=State::default();s.g[0]=0x7fffffff;s.g[1]=1;s.d[0]=0x7f7f7f7f7f7f7f7f;s.d[2]=0x0101010101010101;
 let state=UnknownStatus(s);
 let t=evaluate(&recipe(0xe1012050,false,true),&state).unwrap();assert_eq!(out(&t,"a32.q",0),Value::known(1,1));
 let t=evaluate(&recipe(0xf2000012,false,true),&state).unwrap();let fpscr=out(&t,"a32.fpscr",0);
 assert_eq!(fpscr.defined,1<<27);assert_eq!(fpscr.bits&(1<<27),1<<27);
}
#[test]fn dsp_multiply_and_accumulate_match_wide_integer_oracle_with_aliases() {
 let arm=[0x01000080,0x01600080,0x01200080,0x012000a0,0x07000010,0x0700f010,0x07000050,0x0700f050,0x01400080,0x07400010,0x07400050,0x07500010,0x0750f010,0x075000d0];
 let thumb=[0xfb100000,0xfb10f000,0xfb300000,0xfb30f000,0xfb200000,0xfb20f000,0xfb400000,0xfb40f000,0xfbc00080,0xfbc000c0,0xfbd000c0,0xfb500000,0xfb50f000,0xfb600000];
 for kind in 0..arm.len() {for selector in 0..4u32 {for rd in [0,1,4] {for (a,z,acc) in [
  (0x80008000,0x80008000,0x7fffffff),(0x7fff8000,0xffff7fff,0x80000000),
  (0xffffffff,0x80000001,1),(0x12345678,0x76543210,0xffffffff),(0x7fffffff,0x7fffffff,0x7fffffff),
 ] {
  let long=(8..=10).contains(&kind);let noacc=[1,3,5,7,12].contains(&kind);
  let mut s=State::default();s.g[0]=a;s.g[1]=z;s.g[3]=acc;s.g[4]=0xdeadbeef;s.q=u64::from(selector&1!=0);
  let n=i128::from(s.g[0] as i32);let m=i128::from(s.g[1] as i32);
  let highn=(selector>>1)&1;let highm=selector&1;
  let mut expected=if [0,1,8].contains(&kind) {
   signed(u64::from(s.g[0]>>(highn*16)),16)*signed(u64::from(s.g[1]>>(highm*16)),16)
  }else if [2,3].contains(&kind) { (n*signed(u64::from(s.g[1]>>(highm*16)),16))>>16 }
  else if (4..=10).contains(&kind) {
   let lo=signed(u64::from(s.g[0]),16)*signed(u64::from(s.g[1]>>(highm*16)),16);
   let hi=signed(u64::from(s.g[0]>>16),16)*signed(u64::from(s.g[1]>>((highm^1)*16)),16);
   if [6,7,10].contains(&kind) {lo-hi}else{lo+hi}
  }else {n*m};
  if !noacc {
   let acc=if long {signed((u64::from(s.g[rd as usize])<<32)|u64::from(s.g[3]),64)}
    else if kind>=11 {i128::from(s.g[3] as i32)<<32}else{i128::from(s.g[3] as i32)};
   expected=if kind==13 {acc-expected}else{expected+acc};
  }
  if kind>=11 {if highm!=0 {expected+=0x80000000;}expected>>=32;}
  let flag=[0,2,4,5,6].contains(&kind);
  let overflow=expected!=i128::from(expected as i32);
  let mut aw=0xe0000000|arm[kind]|(rd<<16)|(1<<8);
  let mut tw=thumb[kind]|(rd<<8)|1;
  if !noacc {aw|=3<<12;tw|=3<<12;}
  if [0,1,8].contains(&kind) {aw|=(highn<<5)|(highm<<6);tw|=(highn<<5)|(highm<<4);}
  else if [2,3].contains(&kind) {aw|=highm<<6;tw|=highm<<4;}
  else {aw|=highm<<5;tw|=highm<<4;}
  for (is_thumb,w) in [(false,aw),(true,tw)] {
   let t=run(w,is_thumb,&s);
   if long {assert_eq!(out(&t,"a32.gpr",3).bits,expected as u64&0xffffffff,"{w:08x}");assert_eq!(out(&t,"a32.gpr",rd as u16).bits,(expected as u64)>>32,"{w:08x}");}
   else {assert_eq!(out(&t,"a32.gpr",rd as u16).bits,u64::from(expected as u32),"{w:08x} kind={kind}");}
   if flag {assert_eq!(out(&t,"a32.q",0).bits,s.q|u64::from(overflow),"{w:08x}");}
   else {assert!(t.registers.iter().all(|w|w.register.bank!="a32.q"));}
   unchanged_flags(&t);
  }
 }}}}
}
fn vector_elem(s:&State,n:usize,index:u8,width:u8)->u64 {let bit=usize::from(index)*usize::from(width);(s.d[n+bit/64]>>(bit%64))&mask(width)}
fn unaryword(base:u32,d:u32,m:u32,q:bool,size:u32)->u32 {
 base|((d&15)<<12)|((d&16)<<18)|(m&15)|((m&16)<<1)|(u32::from(q)<<6)|(size<<18)
}
#[test]fn widening_add_sub_and_multiply_accumulate_share_overlapping_dq_sources() {
 let bases=[0xf2800000,0xf2800100,0xf2800200,0xf2800300,0xf2800800,0xf2800a00,0xf2800c00];
 for size in 0..3 {let bits=8u8<<size;for unsigned in [false,true] {for (kind,base) in bases.into_iter().enumerate() {for alias in [false,true] {
  let mut s=State::default();s.d[16]=0x800000007fff8000;s.d[17]=0xffff800000000001;s.d[18]=0x7fff0001ffff8000;
  let dest=if alias {16}else{20};s.d[20]=u64::MAX;s.d[21]=0x123456789abcdef0;
  let word=vecword(base,dest,16,18,false,size,unsigned);
  let width=bits*2;let mut expected=[0u64;2];
  for i in 0..64/bits {
   let wide=kind==1||kind==3;
   let a=vector_elem(&s,16,i,if wide {width}else{bits});let z=vector_elem(&s,18,i,bits);
   let a=if unsigned {i128::from(a)}else{signed(a,if wide {width}else{bits})};
   let z=if unsigned {i128::from(z)}else{signed(z,bits)};
   let mut v=match kind {2|3=>a-z,4..=6=>a*z,_=>a+z};
   if kind==4||kind==5 {let old=i128::from(vector_elem(&s,dest as usize,i,width));v=if kind==5 {old-v}else{old+v};}
   let bit=u16::from(i)*u16::from(width);expected[usize::from(bit/64)]|=(v as u64&mask(width))<<(bit%64);
  }
  for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
   for chunk in 0..2 {assert_eq!(out(&t,"a32.vector64",dest as u16+chunk).bits,expected[chunk as usize],"{word:08x} chunk={chunk}");}
   assert!(t.registers.iter().all(|w|!matches!(w.register.bank,"a32.q"|"a32.fpscr"|"a32.nzcv")));
  }
 }}}}
}
#[test]fn vector_multiply_accumulate_and_doubling_high_round_and_saturate() {
 for size in 0..3 {let bits=8u8<<size;for q in [false,true] {for op in 0..4 {if op>=2 && bits==8 {continue;}for a in [0,1,mask(bits),1u64<<(bits-1),mask(bits-1)] {for z in [0,1,mask(bits),1u64<<(bits-1),mask(bits-1)] {
  let base=if op>=2 {0xf2000b00}else{0xf2000900};let word=vecword(base,0,0,2,q,size,op&1!=0);
  let mut s=State::default();s.d[0]=repeat(a,bits);s.d[1]=s.d[0];s.d[2]=repeat(z,bits);s.d[3]=s.d[2];s.fpscr=0x8000009f;
  let(v,saturated)=if op>=2 {
   let product=2*signed(a,bits)*signed(z,bits);let rounded=if op&1!=0 {product+(1i128<<(bits-1))}else{product};sat(rounded>>bits,bits,true)
  }else {(((if op==0 {i128::from(a)+i128::from(a)*i128::from(z)}else{i128::from(a)-i128::from(a)*i128::from(z)}) as u64)&mask(bits),false)};
  for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
   for chunk in 0..if q {2}else{1} {assert_eq!(out(&t,"a32.vector64",chunk).bits,repeat(v,bits),"{word:08x} {a:x} {z:x}");}
   if op>=2 {assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(saturated)<<27));}
  }
 }}}}}
}
#[test]fn permutations_cover_both_q_chunks_and_reverse_element_containers() {
 for size in 0..3 {let bits=8u8<<size;for q in [false,true] {for base in [0xf3b00000,0xf3b00080,0xf3b00100,0xf3b20080,0xf3b20100,0xf3b20180] {
  let reverse=base<0xf3b20000;let container=match base {0xf3b00080=>32,0xf3b00100=>16,_=>64};
  if reverse && bits>=container || !reverse && base!=0xf3b20080 && !q && bits==32 {continue;}
  let mut s=State::default();s.d[16]=0x0706050403020100;s.d[17]=0x0f0e0d0c0b0a0908;s.d[18]=0x1716151413121110;s.d[19]=0x1f1e1d1c1b1a1918;
  let elements=(64/bits)*if q {2}else{1};
  let first:Vec<_>=(0..elements).map(|i|vector_elem(&s,16,i,bits)).collect();
  let second:Vec<_>=(0..elements).map(|i|vector_elem(&s,18,i,bits)).collect();
  let mut expected=vec![vec![0;elements as usize];if reverse {1}else{2}];
  if reverse {let group=container/bits;for i in 0..elements {expected[0][i as usize]=second[((i/group)*group+group-1-i%group) as usize];}}
  else if base==0xf3b20080 {for i in 0..elements {expected[0][i as usize]=if i&1==0 {first[i as usize]}else{second[(i-1) as usize]};expected[1][i as usize]=if i&1==0 {first[(i+1) as usize]}else{second[i as usize]};}}
  else if base==0xf3b20180 {let mut zip=Vec::new();for i in 0..elements as usize {zip.push(first[i]);zip.push(second[i]);}expected[0].copy_from_slice(&zip[..elements as usize]);expected[1].copy_from_slice(&zip[elements as usize..]);}
  else {let all=[first,second].concat();for i in 0..elements as usize {expected[0][i]=all[i*2];expected[1][i]=all[i*2+1];}}
  let word=unaryword(base,16,18,q,size);
  for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
   for (operand,lanes) in expected.iter().enumerate() {for chunk in 0..if q {2}else{1} {
    let mut value=0;for i in 0..64/bits {value|=lanes[(chunk*(64/bits)+i) as usize]<<(i*bits);}
    assert_eq!(out(&t,"a32.vector64",16+(operand as u16)*2+u16::from(chunk)).bits,value,"{word:08x}");
   }}
  }
 }}}
}
`

const arm32IntegerShiftTests = `
#[test]fn insert_shifts_preserve_destination_bits_and_distinguish_vsli_from_vshl() {
 for size in 0..4 {let bits=8u8<<size;for left in [false,true] {for q in [false,true] {
  for amount in [if left {0}else{1},1,if left {bits-1}else{bits}] {
   let mut s=State::default();s.d[0]=repeat(0xa5a55a5aa5a55a5a,bits);s.d[1]=!s.d[0];s.d[2]=repeat(0x123456789abcdef0,bits);s.d[3]=!s.d[2];
   let encoded=if left {u32::from(bits+amount)}else{2*u32::from(bits)-u32::from(amount)};
   let word=immword(if left {0xf2800510}else{0xf2800410},0,2,q,encoded,true);
   for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
    for chunk in 0..if q {2}else{1} {
     let mut expected=0;
     for i in 0..64/bits {let a=elem(s.d[chunk as usize],i,bits);let z=elem(s.d[2+chunk as usize],i,bits);
      let copied=if left {mask(bits).checked_shl(u32::from(amount)).unwrap_or(0)&mask(bits)}else{mask(bits).checked_shr(u32::from(amount)).unwrap_or(0)};
      let shifted=if left {z.checked_shl(u32::from(amount)).unwrap_or(0)}else{z.checked_shr(u32::from(amount)).unwrap_or(0)};
      expected|=(((a&!copied)|shifted)&mask(bits))<<(i*bits);
     }
     assert_eq!(out(&t,"a32.vector64",chunk).bits,expected,"{word:08x}");
    }
   }
  }
 }}}
}
fn shift_oracle(input:u64,bits:u8,shift:i16,signed_in:bool,unsigned_out:bool,rounding:bool,saturating:bool)->(u64,bool) {
 let input=if signed_in {signed(input,bits)}else{i128::from(input&mask(bits))};
 if shift<0 {
  let n=(-shift) as u8;
  let value=if rounding && n>bits {0}else if !rounding && n>=bits {if input<0 {-1}else{0}}
   else if rounding {(input+(1i128<<(n-1)))>>n}else{input>>n};
  if saturating {sat(value,bits,!unsigned_out)}else{(value as u64&mask(bits),false)}
 }else{
  let n=shift as u8;
  if saturating {
   if n>=bits && input!=0 {sat(if input<0 {-(1i128<<bits)}else{1i128<<bits},bits,!unsigned_out)}else{sat(input<<n,bits,!unsigned_out)}
  }else{(if n>=bits {0}else{(input<<n) as u64&mask(bits)},false)}
 }
}
#[test]fn register_shifts_use_signed_low_byte_counts_and_total_64bit_rounding() {
 for size in 0..4 {let bits=8u8<<size;for unsigned in [false,true] {for q in [false,true] {for op in [0xf2000400,0xf2000500,0xf2000410,0xf2000510] {for input in [0,1,mask(bits),1u64<<(bits-1),mask(bits-1)] {for shift in [-128,-65,-64,-33,-(i16::from(bits)),-1,0,1,i16::from(bits)-1,i16::from(bits),i16::from(bits)+1,63,64,127] {
  let saturating=op&0x10!=0;let rounding=op&0x100!=0;
  let(expected,saturated)=shift_oracle(input,bits,shift,!unsigned,unsigned,rounding,saturating);
  let mut s=State::default();s.d[0]=repeat(input,bits);s.d[1]=s.d[0];
  let encoded=if bits==8 {u64::from(shift as u8)}else{mask(bits)&!255|u64::from(shift as u8)};
  s.d[2]=repeat(encoded,bits);s.d[3]=s.d[2];s.fpscr=0x9000009f;
  let word=vecword(op,0,2,0,q,size,unsigned);
  for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
   for chunk in 0..if q {2}else{1} {assert_eq!(out(&t,"a32.vector64",chunk).bits,repeat(expected,bits),"{word:08x} input={input:x} shift={shift}");}
   if saturating {assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(saturated)<<27),"{word:08x} input={input:x} shift={shift}");}
  }
 }}}}}}
}
fn immword(base:u32,d:u32,m:u32,q:bool,encoded:u32,unsigned:bool)->u32 {
 base|((d&15)<<12)|((d&16)<<18)|(m&15)|((m&16)<<1)|(u32::from(q)<<6)|((encoded&63)<<16)|((encoded&64)<<1)|(u32::from(unsigned)<<24)
}
#[test]fn immediate_shifts_saturate_signed_to_unsigned_and_round_at_lane_width() {
 for size in 0..4 {let bits=8u8<<size;for kind in 0..6 {for unsigned in [false,true] {
  if kind==0&&unsigned || kind==5&&!unsigned {continue;}
  let right=kind==1||kind==2;let round=kind==2;let saturating=kind>=3;
  let base=match kind {0=>0xf2800510,1=>0xf2800010,2=>0xf2800210,3|4=>0xf2800710,_=>0xf2800610};
  for n in [if right {1}else{0},1,bits-1,if right {bits}else{bits-1}] {for input in [0,1,mask(bits),1u64<<(bits-1),mask(bits-1)] {
   let encoded=if right {2*u32::from(bits)-u32::from(n)}else{u32::from(bits+n)};
   let word=immword(base,0,0,true,encoded,unsigned);
   let(expected,saturated)=shift_oracle(input,bits,if right {-i16::from(n)}else{i16::from(n)},kind==5||!unsigned,unsigned,round,saturating);
   let mut s=State::default();s.d[0]=repeat(input,bits);s.d[1]=s.d[0];s.fpscr=0x100009f;
   for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
    assert_eq!(out(&t,"a32.vector64",0).bits,repeat(expected,bits),"{word:08x} {input:x} {n}");
    assert_eq!(out(&t,"a32.vector64",1).bits,repeat(expected,bits));
    if saturating {assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(saturated)<<27),"{word:08x} {input:x} {n}");}
   }
  }}
 }}}
}
#[test]fn narrowing_shifts_round_before_saturation_and_widening_shifts_keep_all_lanes() {
 for size in 0..3 {let bits=8u8<<size;for unsigned in [false,true] {for op in [false,true] {for round in [false,true] {for n in [1,bits] {
  let saturating=unsigned||op;let signed_in=!(unsigned&&op);
  for input in [0,1,mask(bits),mask(bits*2),1u64<<(bits*2-1),mask(bits*2-1)] {
   let value=if saturating&&signed_in {signed(input,bits*2)}else{i128::from(input)};
   let shifted=(value+if round {1i128<<(n-1)}else{0})>>n;
   let(expected,saturated)=if saturating {sat(shifted,bits,!unsigned)}else{(shifted as u64&mask(bits),false)};
   let word=immword(0xf2800810,0,0,round,u32::from(bits*2-n),unsigned)|(u32::from(op)<<8);
   let mut s=State::default();s.d[0]=repeat(input,bits*2);s.d[1]=s.d[0];s.fpscr=0x100009f;
   for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
    assert_eq!(out(&t,"a32.vector64",0).bits,repeat(expected,bits),"{word:08x} {input:x}");
    if saturating {assert_eq!(out(&t,"a32.fpscr",0).bits,u64::from(s.fpscr)|(u64::from(saturated)<<27));}
   }
  }
 }}}}}
 for size in 0..3 {let bits=8u8<<size;for unsigned in [false,true] {for n in [0,1,bits-1,bits] {
  let mut s=State::default();s.d[0]=0x80007fffff00a501;
  let word=if n==bits {unaryword(0xf3b20300,0,0,false,size)}else{immword(0xf2800a10,0,0,false,u32::from(bits+n),unsigned)};
  let mut expected=[0u64;2];
  for i in 0..64/bits {let input=elem(s.d[0],i,bits);let value=if unsigned {i128::from(input)}else{signed(input,bits)};
   let bit=u16::from(i)*u16::from(bits*2);expected[usize::from(bit/64)]|=((value<<n) as u64&mask(bits*2))<<(bit%64);
  }
  for is_thumb in [false,true] {let t=run(if is_thumb {thumbword(word)}else{word},is_thumb,&s);
   assert_eq!(out(&t,"a32.vector64",0).bits,expected[0],"{word:08x}");assert_eq!(out(&t,"a32.vector64",1).bits,expected[1]);
  }
 }}}
}
`

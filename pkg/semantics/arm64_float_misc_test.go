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
	"strings"
	"testing"
)

//go:embed arm64_float_misc.rs
var arm64FloatMiscSource string

func TestRustArm64FloatMisc(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "arm64_float_misc.rs": arm64FloatMiscSource, "float_misc_tests.rs": arm64FloatMiscBehaviorTests + arm64FloatMiscCorpus(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "float_misc_tests.rs", "-Dwarnings", "-o", "float-misc-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 FP misc: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "float-misc-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A64 FP misc: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func arm64FloatMiscCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional Arm XML absent; portable FP misc matrix still runs")
		return "const FP_MISC_CORPUS:&[(u32,&str)]=&[];"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	reader := tar.NewReader(z)
	wanted := map[string]bool{"fjcvtzs.xml": true, "famin_advsimd.xml": true, "famax_advsimd.xml": true}
	for _, n := range []int{32, 64} {
		for _, mode := range []string{"z", "x"} {
			for _, form := range []string{"float", "advsimd"} {
				wanted[fmt.Sprintf("frint%d%s_%s.xml", n, mode, form)] = true
			}
		}
	}
	seen := map[string]bool{}
	type cell struct {
		Text string `xml:",chardata"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type diagram struct {
		Boxes []box `xml:"box"`
	}
	var out strings.Builder
	out.WriteString("const FP_MISC_CORPUS:&[(u32,&str)]=&[\n")
	count := 0
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !strings.HasPrefix(h.Name, "ISA_A64_xml_A_profile-2026-06/") || !wanted[name] {
			continue
		}
		seen[name] = true
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		decoder := xml.NewDecoder(bytes.NewReader(data))
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
			var d diagram
			if err := decoder.DecodeElement(&d, &start); err != nil {
				t.Fatal(err)
			}
			for variant := 0; variant < 8; variant++ {
				var word uint32
				for _, b := range d.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					var value uint32
					bits := ""
					for _, c := range b.Cells {
						bits += strings.Trim(strings.TrimSpace(c.Text), "()")
					}
					if len(bits) == width {
						for _, bit := range bits {
							value <<= 1
							if bit == '1' || (bit == 'x' && variant&1 != 0) {
								value |= 1
							}
						}
					} else {
						switch b.Name {
						case "Q":
							value = uint32(variant & 1)
						case "sz":
							value = uint32(variant & 1)
						case "Rd":
							value = uint32([]int{0, 1, 2, 31, 0, 1, 2, 31}[variant])
						case "Rn":
							value = uint32([]int{1, 1, 2, 31, 1, 1, 2, 31}[variant])
						case "Rm":
							value = uint32([]int{2, 2, 2, 31, 2, 2, 2, 31}[variant])
						}
					}
					word |= value << uint(b.Hi-width+1)
				}
				fmt.Fprintf(&out, "(0x%08x,%q),\n", word, strings.TrimSuffix(name, ".xml"))
				count++
			}
		}
	}
	for n := range wanted {
		if !seen[n] {
			t.Errorf("missing primary FP misc page %s", n)
		}
	}
	out.WriteString("];\n")
	t.Logf("primary A64 FP misc corpus: %d words from %d pages", count, len(seen))
	return out.String()
}

const arm64FloatMiscBehaviorTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
mod arm64_float_misc;
#[derive(Clone,Default)]struct State{v:[[u64;2];32],x:[u64;31],fpcr:u32,fpsr:u32,nzcv:u8}
impl Machine for State {
 fn read_register(&self,r:Register)->Value{match r.bank{
  "a64.vector64"=>Value::known(64,self.v[usize::from(r.index/32)][usize::from(r.index%32)]),
  "a64.gpr"=>Value::known(64,self.x[usize::from(r.index)]),
  "a64.fpcr"=>Value::known(32,u64::from(self.fpcr)),"a64.fpsr"=>Value::known(32,u64::from(self.fpsr)),
  "a64.nzcv"=>Value::known(1,u64::from((self.nzcv>>(3-r.index))&1)),_=>panic!("unexpected state {r:?}"),
 }}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("FP misc memory")}
}
fn initial()->State{let mut s=State::default();for i in 0..32{s.v[i]=[0x0123456789abcdefu64.rotate_left(i as u32),0xfedcba9876543210u64.rotate_right(i as u32)];}s.x.fill(u64::MAX);s.nzcv=11;s.fpsr=0x08000002;s}
fn execute(w:u32,s:&State)->(State,Transition){
 let r=arm64_float_misc::a64(w,0xfffffffffffffffc).unwrap_or_else(||panic!("unhandled {w:08x}"));assert_eq!(r.support,Support::Full,"{w:08x}");r.validate().unwrap();
 let t=evaluate(&r,s).unwrap();assert_eq!(t.next_pc,Value::known(64,0));assert!(t.memory.is_empty());assert!(t.wide_memory.is_empty());assert!(t.atomics.is_empty());
 let mut out=s.clone();for wr in&t.registers{assert!(wr.value.is_known());match wr.register.bank{
  "a64.vector64"=>out.v[usize::from(wr.register.index/32)][usize::from(wr.register.index%32)]=wr.value.bits,
  "a64.gpr"=>out.x[usize::from(wr.register.index)]=wr.value.bits,
  "a64.fpsr"=>out.fpsr=wr.value.bits as u32,
  "a64.nzcv"=>{let bit=3-wr.register.index;out.nzcv=(out.nzcv&!(1<<bit))|((wr.value.bits as u8)<<bit);},
  _=>panic!("unexpected write {wr:?}"),
 }}assert_eq!(out.fpcr,s.fpcr);(out,t)
}
fn famword(w:u8,q:bool,min:bool,d:u32,n:u32,m:u32)->u32{
 (if w==16{0x0ec01c00}else{0x0ea0dc00|(u32::from(w==64)<<22)})|(u32::from(q)<<30)|(u32::from(min)<<29)|(m<<16)|(n<<5)|d
}
fn lane(v:[u64;2],index:u8,w:u8)->u64{(v[usize::from(index/(64/w))]>>((index%(64/w))*w))&mask(w)}
fn insert(v:&mut[u64;2],index:u8,w:u8,bits:u64){let chunk=usize::from(index/(64/w));let shift=(index%(64/w))*w;v[chunk]=(v[chunk]&!(mask(w)<<shift))|((bits&mask(w))<<shift);}
// Golden bit reference: no host floating operations. Independent priority
// cases below assert the architectural sign/payload and exception decisions.
fn famref(a:u64,b:u64,w:u8,min:bool,dn:bool)->(u64,bool){
 let f=match w{16=>10,32=>23,_=>52};let exponent=mask(w-1)&!mask(f);let quiet=1<<(f-1);
 let nan=|v:u64|v&exponent==exponent&&v&mask(f)!=0;let snan=|v:u64|nan(v)&&v&quiet==0;
 let signaling=snan(a)||snan(b);
 if nan(a)||nan(b){let selected=if snan(a){a}else if snan(b){b}else if nan(a){a}else{b};return(if dn{exponent|quiet}else{selected|quiet},signaling);}
 let a=a&mask(w-1);let b=b&mask(w-1);(if min{a.min(b)}else{a.max(b)},false)
}
#[test]fn faminmax_all_formats_aliases_controls_nan_and_subnormal_boundaries(){
 for w in[16u8,32,64]{let f=match w{16=>10,32=>23,_=>52};let exp=mask(w-1)&!mask(f);let sign=1<<(w-1);let quiet=1<<(f-1);
  let operands=[0,sign,1,sign|1,mask(f),1<<f,exp-1,exp,sign|exp,exp|1,sign|exp|1,exp|quiet,sign|exp|quiet|17,exp|quiet|31];
  for q in[false,true]{if w==64&&!q{continue;}for min in[false,true]{for controls in 0..32u32{
   let fpcr=((controls&1)<<25)|(((controls>>1)&1)<<24)|(((controls>>2)&1)<<19)|(((controls>>3)&1)<<1)|((controls>>4)&1);
   for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(31,31,31)]{for start in 0..operands.len(){
    let mut s=initial();s.fpcr=fpcr;let count=if q{128/w}else{64/w};
    for index in 0..count{insert(&mut s.v[n as usize],index,w,operands[(start+usize::from(index))%operands.len()]);insert(&mut s.v[m as usize],index,w,operands[(start*3+usize::from(index)+1)%operands.len()]);}
    let mut expected=[0;2];let mut invalid=false;
    for index in 0..count{let(v,raised)=famref(lane(s.v[n as usize],index,w),lane(s.v[m as usize],index,w),w,min,fpcr&(1<<25)!=0);insert(&mut expected,index,w,v);invalid|=raised;}
    let word=famword(w,q,min,d,n,m);let(out,t)=execute(word,&s);assert_eq!(t.trap,None);
    for reg in 0..32{assert_eq!(out.v[reg],if reg==d as usize{expected}else{s.v[reg]},"{word:08x} V{reg}");}
    assert_eq!(out.x,s.x);assert_eq!(out.nzcv,s.nzcv);assert_eq!(out.fpsr,s.fpsr|u32::from(invalid));
   }}
  }}}
 }
}
#[test]fn faminmax_explicit_nan_priority_default_nan_and_signed_zero_goldens(){
 for(min,word)in[(false,0x4ea2dc20u32),(true,0x6ea2dc20)]{
  for(a,b,expected,invalid)in[(0x80000000,0,0,false),(0x80000001,0x80000000,if min{0}else{1},false),
   (0xffc01234,0x7f800005,0x7fc00005,true),(0xff800009,0x7f800005,0xffc00009,true),
   (0xffc01234,0x7fc05678,0xffc01234,false),(0x80000001,0x7fc05678,0x7fc05678,false)]{
   let mut s=initial();for index in 0..4{insert(&mut s.v[1],index,32,a);insert(&mut s.v[2],index,32,b);}
   s.fpcr=(1<<24)|(1<<19)|3;let(out,t)=execute(word,&s);assert_eq!(t.trap,None);
   for index in 0..4{assert_eq!(lane(out.v[0],index,32),expected);}
   assert_eq!(out.fpsr,s.fpsr|u32::from(invalid));
   if a&0x7f800000==0x7f800000{ s.fpcr|=1<<25;let(out,_)=execute(word,&s);for index in 0..4{assert_eq!(lane(out.v[0],index,32),0x7fc00000);}}
  }
 }
}
#[test]fn faminmax_unmasked_signaling_nan_stops_before_any_vector_write(){
 let mut s=initial();s.fpcr=(1<<8)|(1<<24)|3;s.v[1]=[0x3f8000003f800000;2];s.v[2]=[0x7f80000140000000;2];
 let(out,t)=execute(famword(32,true,false,1,1,2),&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(out.v,s.v);assert_eq!(out.nzcv,s.nzcv);assert_eq!(out.x,s.x);assert_eq!(out.fpsr,s.fpsr|1);assert_eq!(t.registers.len(),1);
}
// Decode a binary rational into u128 integer magnitude and fractional residue.
// This reference does not use the recipe's exponent thresholds/shift network.
fn jsref(raw:u64,control:u32)->(u32,u8,u32){
 let sign=raw>>63!=0;let exp=((raw>>52)&2047)as i32;let fraction=raw&mask(52);
 if exp==2047{return(0,0,1);}
 if exp==0&&fraction==0{return(0,if sign{0}else{4},0);}
 let subnormal=exp==0;let fz=control&(1<<24)!=0&&control&2==0;let flushed=subnormal&&(fz||control&1!=0);
 if flushed{return(0,0,if fz{128}else{0});}
 let significand=if subnormal{u128::from(fraction)}else{u128::from(fraction)|(1<<52)};
 let power=if subnormal{-1074}else{exp-1023-52};
 let(magnitude,fractional,huge)=if power>=0{if power>=76{(0,false,true)}else{(significand<<power,false,false)}}else{
  let shift=(-power)as u32;if shift>=128{(0,true,false)}else{(significand>>shift,significand&((1u128<<shift)-1)!=0,false)}
 };
 let invalid=huge||magnitude>if sign{1u128<<31}else{(1u128<<31)-1};
 let result=if sign{(magnitude as u32).wrapping_neg()}else{magnitude as u32};
 let raised=if invalid{1}else if fractional{16}else{0};(result,if raised==0{4}else{0},raised)
}
#[test]fn javascript_wrapping_flags_and_exceptions_cover_ieee_exponents_and_aliases(){
 let fractions=[0,1,(1<<20)-1,1<<20,(1<<21)-1,1<<21,(1<<51)-1,1<<51,mask(52)];
 let exponents=[0,1,1022,1023,1053,1054,1055,1074,1075,1085,1086,2046,2047];
 for sign in[0u64,1]{for exponent in exponents{for fraction in fractions{for controls in 0..16u32{
  let mut s=initial();s.fpcr=(controls&3)|(((controls>>2)&1)<<24)|(((controls>>3)&1)<<25);s.v[31][0]=(sign<<63)|(exponent<<52)|fraction;
  let(expected,flags,raised)=jsref(s.v[31][0],s.fpcr);for d in[0,30,31]{let word=0x1e7e0000|(31<<5)|d;let(out,t)=execute(word,&s);assert_eq!(t.trap,None);
   assert_eq!(out.v,s.v);assert_eq!(out.nzcv,flags,"{word:08x} {:016x} {:08x}",s.v[31][0],s.fpcr);assert_eq!(out.fpsr,s.fpsr|raised);
   for reg in 0..31{assert_eq!(out.x[reg],if reg==d as usize{u64::from(expected)}else{s.x[reg]},"{word:08x} {:016x}",s.v[31][0]);}
  }
 }}}}
}
#[test]fn javascript_independent_literal_check_vectors(){
 for(raw,result,nzcv,raised)in[
  (0x0000000000000000,0,4,0),(0x8000000000000000,0,0,0),
  (0x3ff0000000000000,1,4,0),(0xbff0000000000000,0xffffffff,4,0),
  (0x3ff8000000000000,1,0,16),(0xbff8000000000000,0xffffffff,0,16),
  (0x41e0000000000000,0x80000000,0,1),(0xc1e0000000000000,0x80000000,4,0),
  (0x41f0000000100000,1,0,1),(0xc1f0000000100000,0xffffffff,0,1),
  (0x7ff0000000000000,0,0,1),(0xfff0000000000000,0,0,1),
  (0x7ff8000000000001,0,0,1),(0xfff0000000000001,0,0,1),
  (1,0,0,16),(0x8000000000000001,0,0,16),
 ]{let mut s=initial();s.v[1][0]=raw;let(out,t)=execute(0x1e7e0020,&s);assert_eq!(t.trap,None);assert_eq!(out.x[0],result,"{raw:016x}");assert_eq!(out.nzcv,nzcv,"{raw:016x}");assert_eq!(out.fpsr,s.fpsr|raised,"{raw:016x}");}
}
#[test]fn javascript_exception_enables_gate_commit_even_with_preexisting_sticky_flags(){
 for(raw,control,raised)in[(0x7ff8000000000001,1<<8,1),(0x3ff8000000000000,1<<12,16),(1,(1<<24)|(1<<15),128)]{
  let mut s=initial();s.v[1][0]=raw;s.fpcr=control;s.fpsr|=raised;let(out,t)=execute(0x1e7e0020,&s);
  assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(out.x,s.x);assert_eq!(out.nzcv,s.nzcv);assert_eq!(out.v,s.v);assert_eq!(out.fpsr,s.fpsr);assert_eq!(t.registers.len(),1);
 }
 // AH disables FZ, and FIZ flushes without Input Denormal. Neither mode is
 // constrained to a fabricated random execute-or-skip context.
 for control in[(1<<24)|2,(1<<24)|3,(1<<15)|1]{let mut s=initial();s.fpcr=control;s.v[1][0]=1;let(out,t)=execute(0x1e7e0020,&s);assert_eq!(t.trap,None);assert_eq!(out.fpsr,s.fpsr|if control&1!=0{0}else{16});}
}
#[test]fn primary_june_physical_words_use_exact_reference_results(){
 for &(word,name)in FP_MISC_CORPUS{let s=initial();let(out,t)=execute(word,&s);assert_eq!(t.trap,None);
  if name=="fjcvtzs"{let n=((word>>5)&31)as usize;let(v,z,raised)=jsref(s.v[n][0],s.fpcr);let d=(word&31)as usize;if d!=31{assert_eq!(out.x[d],u64::from(v));}assert_eq!(out.nzcv,z);assert_eq!(out.fpsr,s.fpsr|raised);}
  else if name.starts_with("frint"){check_round_reference(word,&s,&out,&t);}
  else{let half=word&0x9fe0fc00==0x0ec01c00;let w=if half{16}else{32<<((word>>22)&1)};let count=if word&(1<<30)!=0{128/w}else{64/w};let n=((word>>5)&31)as usize;let m=((word>>16)&31)as usize;let d=(word&31)as usize;
   let mut expected=[0;2];let mut invalid=false;for i in 0..count{let(v,raised)=famref(lane(s.v[n],i,w),lane(s.v[m],i,w),w,name=="famin_advsimd",false);insert(&mut expected,i,w,v);invalid|=raised;}
   assert_eq!(out.v[d],expected,"{name} {word:08x}");assert_eq!(out.nzcv,s.nzcv);assert_eq!(out.fpsr,s.fpsr|u32::from(invalid));
  }
 }
}
#[test]fn reserved_and_other_scalar_sve_sme_and_fp_forms_do_not_gain_full_support(){
 for word in[0x1e7e8000,0x1e3e0000,0x9e7e0000,0x1e780000,0x1e204800,0x5ea0dc20,0x5ec01c20,0x65ce8000,0xc1a85880]{assert!(arm64_float_misc::a64(word,0).is_none(),"{word:08x}");}
 let r=arm64_float_misc::a64(famword(64,false,false,0,1,2),0).unwrap();assert!(matches!(r.support,Support::Unsupported(_)));assert_eq!(evaluate(&r,&initial()),Err(EvalError::Unsupported));
}

fn roundword(w:u8,intsize:u8,environment:bool,scalar:bool,q:bool,d:u32,n:u32)->u32{
 (if scalar{0x1e284000|(u32::from(intsize==64)<<16)|(u32::from(environment)<<15)}else{0x0e21e800|(u32::from(intsize==64)<<12)|(u32::from(environment)<<29)|(u32::from(q)<<30)})|(u32::from(w==64)<<22)|(n<<5)|d
}
fn roundref(raw:u64,w:u8,intsize:u8,mode:u32,control:u32)->(u64,u32){
 let f=if w==32{23u32}else{52};let bias=if w==32{127i32}else{1023};let sign=raw>>(w-1)!=0;
 let exponent=((raw>>f)&if w==32{255}else{2047})as i32;let fraction=raw&mask(f as u8);
 let indefinite=(1<<(w-1))|((bias as u64+u64::from(intsize)-1)<<f);
 if exponent==if w==32{255}else{2047}{return(indefinite,1);}
 let subnormal=exponent==0&&fraction!=0;let fz=control&(1<<24)!=0&&control&2==0;
 if subnormal&&(fz||control&1!=0){return(u64::from(sign)<<(w-1),if fz{128}else{0});}
 let significand=u128::from(fraction)|if exponent==0{0}else{1u128<<f};
 let power=if exponent==0{1-bias-f as i32}else{exponent-bias-f as i32};
 let(mut magnitude,remainder,denominator)=if power>=0{
  if power>=76{return(indefinite,1);} (significand<<power,0,1)
 }else{let shift=(-power)as u32;if shift>=128{(0,significand,u128::MAX)}else{(significand>>shift,significand&((1u128<<shift)-1),1u128<<shift)}};
 let fractional=remainder!=0;
 let up=match mode{0=>remainder>denominator/2||(remainder==denominator/2&&denominator!=1&&magnitude&1!=0),1=>!sign&&fractional,2=>sign&&fractional,_=>false};
 magnitude+=u128::from(up);
 let limit=1u128<<(intsize-1);if magnitude>if sign{limit}else{limit-1}{return(indefinite,1);}
 let bits=if magnitude==0{0}else{
  let highest=127-magnitude.leading_zeros();let fraction=magnitude-(1u128<<highest);
  let encoded=if highest<=f{fraction<<(f-highest)}else{fraction>>(highest-f)};
  (((highest as i32+bias)as u64)<<f)|(encoded as u64)
 };
 (bits|(u64::from(sign)<<(w-1)),if fractional{16}else{0})
}
fn check_round_reference(word:u32,s:&State,out:&State,t:&Transition){
 let scalar=word&0x1f000000==0x1e000000;let w=32u8<<((word>>22)&1);
 let intsize=if word&(if scalar{1<<16}else{1<<12})!=0{64}else{32};
 let environment=word&(if scalar{1<<15}else{1<<29})!=0;let mode=if environment{(s.fpcr>>22)&3}else{3};
 let q=word&(1<<30)!=0;let count=if scalar{1}else{if q{128/w}else{64/w}};
 let d=(word&31)as usize;let n=((word>>5)&31)as usize;let mut expected=if scalar&&s.fpcr&4!=0{s.v[d]}else{[0;2]};let mut raised=0;
 for i in 0..count{let(v,r)=roundref(lane(s.v[n],i,w),w,intsize,mode,s.fpcr);insert(&mut expected,i,w,v);raised|=r;}
 assert_eq!(t.trap,if(raised&(s.fpcr>>8))!=0{Some(TrapKind::FloatingPoint)}else{None});
 assert_eq!(out.fpsr,s.fpsr|raised,"{word:08x}");assert_eq!(out.x,s.x);assert_eq!(out.nzcv,s.nzcv);
 for reg in 0..32{assert_eq!(out.v[reg],if reg==d&&t.trap.is_none(){expected}else{s.v[reg]},"{word:08x} V{reg} {:x?} fpcr={:08x}",s.v[n],s.fpcr);}
}
#[test]fn frintts_scalar_vector_ranges_modes_flags_and_aliases(){
 for w in[32u8,64]{let f=if w==32{23}else{52};let bias=if w==32{127}else{1023};
  let fractions=[0,1,mask(f)/2,(1<<(f-1))+1,mask(f)-1,mask(f)];
  for intsize in[32u8,64]{for environment in[false,true]{for scalar in[false,true]{for q in[false,true]{if !scalar&&w==64&&!q{continue;}
   for mode in 0..4u32{for sign in[0u64,1]{for exponent in[0,1,bias-1,bias,bias+1,bias+30,bias+31,bias+62,bias+63,if w==32{254}else{2046},if w==32{255}else{2047}]{for fraction in fractions{
    let mut s=initial();s.fpcr=(mode<<22)|if q{4}else{0};let raw=(sign<<(w-1))|(exponent<<f)|fraction;
    for i in 0..128/w{insert(&mut s.v[1],i,w,raw);}
    let word=roundword(w,intsize,environment,scalar,q,1,1);let(out,t)=execute(word,&s);check_round_reference(word,&s,&out,&t);
   }}}}
  }}}}
 }
}
#[test]fn frintts_denormal_flush_exception_enable_and_integer_indefinite_goldens(){
 for w in[32u8,64]{for intsize in[32u8,64]{for scalar in[false,true]{
  for control in[0,1,2,3,1<<24,(1<<24)|2,(1<<24)|3,1<<12,(1<<24)|(1<<15),1<<8]{
   let mut s=initial();s.fpcr=control;let f=if w==32{23}else{52};let allones=mask(w-1)&!mask(f);
   for raw in[1,1u64<<(w-1),allones,allones|1,allones|(1<<(f-1))]{
    for i in 0..128/w{insert(&mut s.v[1],i,w,raw);}
    let word=roundword(w,intsize,true,scalar,true,0,1);let(out,t)=execute(word,&s);check_round_reference(word,&s,&out,&t);
   }
  }
 }}}
 let mut s=initial();s.v[1][0]=0x3ff8000000000000;
 let(out,_)=execute(roundword(64,32,false,true,false,0,1),&s);assert_eq!(out.v[0],[0x3ff0000000000000,0]);assert_eq!(out.fpsr,s.fpsr|16);
 s.v[1][0]=0x41e0000000000000;let(out,_)=execute(roundword(64,32,false,true,false,0,1),&s);assert_eq!(out.v[0],[0xc1e0000000000000,0]);assert_eq!(out.fpsr,s.fpsr|1);
}
`

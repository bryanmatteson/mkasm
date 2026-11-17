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

//go:embed arm64_float_extra.rs
var arm64FloatExtraSource string

func TestRustArm64ScaleLogB(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "arm64_float_extra.rs": arm64FloatExtraSource, "extra_tests.rs": arm64FloatExtraBehaviorTests + arm64FloatExtraCorpus(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "extra_tests.rs", "-Dwarnings", "-o", "extra-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile FPScale/FPLogB: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "extra-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute FPScale/FPLogB: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// Derive words and each diagram's actual size-field location directly from
// the primary corpus. These stateless helpers deliberately do not dispatch
// words: instruction/predicate ownership remains in their SVE/SME caller.
func arm64FloatExtraCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional XML absent; portable Scale/LogB references still run")
		return "const EXTRA_CORPUS:&[(u32,u8,&str)]=&[];"
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
	wanted := map[string]bool{}
	for _, n := range strings.Fields("fscale_advsimd fscale_z_p_zz fscale_mz_zzv fscale_mz_zzw flogb_z_p_z") {
		wanted[n+".xml"] = true
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
	out.WriteString("const EXTRA_CORPUS:&[(u32,u8,&str)]=&[\n")
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
			for variant := 0; variant < 3; variant++ {
				var word uint32
				esize := 16
				for _, b := range d.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					bits := ""
					for _, c := range b.Cells {
						bits += strings.Trim(strings.TrimSpace(c.Text), "()")
					}
					var value uint64
					fixed := len(bits) == width
					for _, bit := range bits {
						if bit != '0' && bit != '1' && bit != 'x' {
							fixed = false
						}
					}
					if fixed {
						for _, bit := range bits {
							value <<= 1
							if bit == '1' || (bit == 'x' && variant%2 == 1) {
								value |= 1
							}
						}
					} else {
						switch b.Name {
						case "size":
							value = uint64(variant + 1)
						case "Q":
							value = 1
						case "Rn", "Zn":
							value = 1
						case "Rm", "Zm":
							value = 2
						case "Rd", "Zd", "Zdn":
							value = uint64(variant)
						case "Pg":
							value = uint64(variant + 1)
						}
					}
					if b.Name == "size" {
						esize = 8 << value
					}
					word |= uint32(value) << uint(b.Hi-width+1)
				}
				fmt.Fprintf(&out, "(0x%08x,%d,%q),\n", word, esize, strings.TrimSuffix(name, ".xml"))
				count++
			}
		}
	}
	for n := range wanted {
		if !seen[n] {
			t.Errorf("missing Scale/LogB XML page %s", n)
		}
	}
	out.WriteString("];\n")
	t.Logf("primary Scale/LogB corpus: %s words from %d pages", strconv.Itoa(count), len(seen))
	return out.String()
}

const arm64FloatExtraBehaviorTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
mod arm64_float_extra;
use arm64_float_extra::Outcome;
#[test]fn fixed_bfloat_dispatch_is_distinct_from_scale_and_logb(){
 for word in [0,0x1e244020,0x65c98020]{assert!(arm64_float_extra::fixed_bfloat(word,0).is_none());}
 for word in [0x2e42fc20,0x4f42f020,0x6e42ec20]{arm64_float_extra::fixed_bfloat(word,0).unwrap().validate().unwrap();}
}
struct State{w:u8,value:u64,exponent:u64,control:u32,status:u32}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{match r.bank{
  "value"=>Value::known(self.w,self.value),"exponent"=>Value::known(self.w,self.exponent),
  "control"=>Value::known(32,u64::from(self.control)),"status"=>Value::known(32,u64::from(self.status)),_=>panic!("{r:?}"),
 }}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("scale/logb memory")}
}
fn input(bank:&'static str,w:u8)->Expr{Expr::register(register(bank,0,w,w))}
fn scale(w:u8)->Outcome{arm64_float_extra::scale(w,input("value",w),input("exponent",w),input("control",32),input("status",32)).unwrap()}
fn logb(w:u8)->Outcome{arm64_float_extra::logb(w,input("value",w),input("control",32),input("status",32)).unwrap()}
fn eval(o:&Outcome,s:&State)->(u64,u32,bool){
 let val=evaluate_expression(&o.value,s,&[]).unwrap();let status=evaluate_expression(&o.status,s,&[]).unwrap();let trapped=evaluate_expression(&o.trapped,s,&[]).unwrap();
 assert!(val.is_known()&&status.is_known()&&trapped.is_known());assert_eq!(val.width,s.w);assert_eq!(status.width,32);assert_eq!(trapped.width,1);(val.bits,status.bits as u32,trapped.bits!=0)
}
fn params(w:u8)->(u32,u32,i64){match w{16=>(10,31,15),32=>(23,255,127),_=>(52,2047,1023)}}
// Independent dyadic arithmetic: retain the original (possibly subnormal)
// significand, then round directly to the destination's minimum unit. This
// reference does not normalize and rebias in the helper's expression network.
fn accrued(s:&State,raised:u32,nontrapping:u32)->(u32,bool){
 let mut status=s.status;let order=if s.control&2!=0{[0,1,3,2,4,7]}else{[7,0,1,3,2,4]};
 for bit in order {if raised&(1<<bit)!=0 {if nontrapping&(1<<bit)==0 && s.control&(1<<(bit+8))!=0{return(status,true)}status|=1<<bit;}}
 (status,false)
}
fn scale_ref(s:&State)->(u64,u32,bool){
 let(f,emax,bias)=params(s.w);let sign=s.value&(1<<(s.w-1));let negative=sign!=0;let exp=((s.value>>f)&u64::from(emax))as i64;let frac=s.value&mask(f as u8);
 let nan=exp==i64::from(emax)&&frac!=0;let snan=nan&&frac&(1<<(f-1))==0;
 let sub=exp==0&&frac!=0;let ah=s.control&2!=0;let fz=s.control&(1<<if s.w==16{19}else{24})!=0;
 let input_fz=fz&&(s.w==16||!ah);
 let flushed=sub&&(input_fz||(s.w!=16&&s.control&1!=0));let id=s.w!=16&&sub&&(input_fz||ah&&!flushed);
 let mut raised=if id{128}else{0};let mut nontrapping=0u32;
 let value=if nan{raised|=u32::from(snan);if s.control&(1<<25)!=0{(u64::from(emax)<<f)|(1<<(f-1))|if ah{1<<(s.w-1)}else{0}}else{s.value|(1<<(f-1))}}
 else if exp==i64::from(emax){s.value}else if exp==0&&frac==0||flushed{sign}else{
  let exponent=if s.w==64{s.exponent as i64}else{((s.exponent<<(64-s.w))as i64)>>(64-s.w)};
  let power=(if exp==0{1-bias}else{exp-bias})-i64::from(f)+exponent.clamp(-10000,10000);
  let significand=u128::from(frac)|if exp==0{0}else{1u128<<f};let highest=127-significand.leading_zeros();let result_exp=i64::from(highest)+power;
  let mode=(s.control>>22)&3;let out_inf=mode==0||(mode==1&&!negative)||(mode==2&&negative);
  if result_exp>bias{raised|=20;sign|if out_inf{u64::from(emax)<<f}else{(u64::from(emax)<<f)-1}}
  else if result_exp<1-bias&&fz{raised|=if ah{24}else{8};nontrapping=8;sign}
  else if result_exp>=1-bias{
   let normalized=significand<<(f-highest);sign|(((result_exp+bias)as u64)<<f)|((normalized as u64)&mask(f as u8))
  }else{
   let distance=(1-bias-i64::from(f))-power;
   let(integer,remainder,denom)=if distance>=128{(0,significand,u128::MAX)}else if distance>0{let shift=distance as u32;(significand>>shift,significand&((1u128<<shift)-1),1u128<<shift)}else{(significand<<(-distance)as u32,0,1)};
   let error=remainder!=0;let up=match mode{0=>remainder>denom/2||(remainder==denom/2&&denom!=1&&integer&1!=0),1=>error&&!negative,2=>error&&negative,_=>false};
   if error||s.control&(1<<11)!=0{raised|=8;}if error{raised|=16;}
   sign|((integer+u128::from(up))as u64)
  }
 };
 if ah && (raised&!128&!nontrapping&(s.control>>8))!=0 {raised&=!128;}
 {let(status,trapped)=accrued(s,raised,nontrapping);(value,status,trapped)}
}
fn log_ref(s:&State)->(u64,u32,bool){
 let(f,max,bias)=params(s.w);let exp=(s.value>>f)&u64::from(max);let frac=s.value&mask(f as u8);let sub=exp==0&&frac!=0;
 let ah=s.control&2!=0;let fz=s.control&(1<<if s.w==16{19}else{24})!=0&&(s.w==16||!ah);
 let flushed=sub&&(fz||(s.w!=16&&s.control&1!=0));let zero=exp==0&&frac==0||flushed;let nan=exp==u64::from(max)&&frac!=0;
 let id=s.w!=16&&sub&&(fz||ah&&!flushed);let mut raised=if id{128}else{0};
 let value=if zero||nan{raised|=1;1<<(s.w-1)}else if exp==u64::from(max){mask(s.w-1)}else{
  let log=if exp==0{let highest=63-frac.leading_zeros();1-bias-i64::from(f)+i64::from(highest)}else{exp as i64-bias};log as u64&mask(s.w)
 };
 {let(status,trapped)=accrued(s,raised,0);(value,status,trapped)}
}
#[test]fn exact_scale_ieee_boundaries_rounding_flush_dn_and_exception_enables(){
 for w in[16u8,32,64]{let o=scale(w);let(f,max,_)=params(w);
  for sign in[0,1u64<<(w-1)]{for exp in[0,1,2,u64::from(max/2),u64::from(max-2),u64::from(max-1),u64::from(max)]{for frac in[0,1,mask(f as u8)/2,(1<<(f-1)),mask(f as u8)]{
   for exponent in[0,1,2,10,100,10000,u64::MAX,u64::MAX-1,u64::MAX-9,u64::MAX-99,1u64<<(w-1),mask(w-1)]{
    for mode in 0..4u32{for control in[mode<<22,(mode<<22)|(1<<25),(mode<<22)|(1<<if w==16{19}else{24}),(mode<<22)|(1<<11),(mode<<22)|(1<<8)|(1<<10)|(1<<12)|(1<<15),(mode<<22)|1,(mode<<22)|2,(mode<<22)|3,(mode<<22)|2|(1<<25),(mode<<22)|2|(1<<if w==16{19}else{24}),(mode<<22)|2|(1<<11),(mode<<22)|2|(1<<8)|(1<<10)|(1<<11)|(1<<12)|(1<<15),(mode<<22)|3|(1<<24)]{
     let s=State{w,value:sign|(exp<<f)|frac,exponent:exponent&mask(w),control,status:0x08000002};assert_eq!(eval(&o,&s),scale_ref(&s),"w={w} {:016x} exp={:016x} control={control:08x}",s.value,s.exponent);
    }}
   }
  }}}
 }
}
#[test]fn scale_single_rounding_and_nontrapping_flush_goldens(){
 for(w,v,e,ctrl,expected,raised,trap)in[
  (16,0x0400,u64::MAX,0,0x0200,0,false),
  (16,0x0400,u64::MAX,1<<11,0x0200,8,true),
  (16,0x0400,u64::MAX,(1<<19)|(1<<11),0,8,false),
  (16,1,u64::MAX,0,0,24,false),(16,1,u64::MAX,1<<22,1,24,false),
  (16,0x8001,u64::MAX,2<<22,0x8001,24,false),
  (16,0x07ff,u64::MAX,0,0x0400,24,false),
  (32,0x00800000,u64::MAX,0,0x00400000,0,false),
  (32,0x7f7fffff,1,0,0x7f800000,20,false),
  (32,0x7f7fffff,1,3<<22,0x7f7fffff,20,false),
  (64,0x0010000000000000,u64::MAX,0,0x0008000000000000,0,false),
  (64,0x7fefffffffffffff,1,0,0x7ff0000000000000,20,false),
  (64,0xffefffffffffffff,1,1<<22,0xffefffffffffffff,20,false),
 ]{let s=State{w,value:v,exponent:e&mask(w),control:ctrl,status:0};assert_eq!(eval(&scale(w),&s),(expected,if trap {0}else{raised},trap),"w={w} {v:x}");}
}
#[test]fn logb_formats_nan_zeros_infinity_subnormal_ah_fiz_and_enables(){
 for w in[16u8,32,64]{let o=logb(w);let(f,max,_)=params(w);
  for sign in[0,1u64<<(w-1)]{for exp in[0,1,2,u64::from(max/2),u64::from(max-1),u64::from(max)]{for frac in[0,1,mask(f as u8)/2,1<<(f-1),mask(f as u8)]{
   for control in[0,1,2,3,1<<24,(1<<24)|1,(1<<24)|2,(1<<24)|3,1<<19,(1<<19)|(1<<8),(1<<24)|(1<<15)|(1<<8),1<<25]{
    let s=State{w,value:sign|(exp<<f)|frac,exponent:0,control,status:0x08000002};assert_eq!(eval(&o,&s),log_ref(&s),"w={w} {:016x} control={control:08x}",s.value);
   }
  }}}
 }
 for(w,v,expected)in[(16,1,0xffe8),(16,0x0400,0xfff2),(32,1,0xffffff6b),(64,1,0xfffffffffffffbce)]{let s=State{w,value:v,exponent:0,control:0,status:0};assert_eq!(eval(&logb(w),&s),(expected,0,false));}
}
#[test]fn half_logb_exhausts_every_payload_without_host_floating_point(){
 let o=logb(16);for v in 0..=u16::MAX{let s=State{w:16,value:u64::from(v),exponent:0,control:0,status:0};assert_eq!(eval(&o,&s),log_ref(&s),"{v:04x}");}
}
#[test]fn dimensions_and_inactive_expression_suppression(){
 assert!(arm64_float_extra::scale(8,input("value",8),input("exponent",8),input("control",32),input("status",32)).is_none());
 assert!(arm64_float_extra::scale(32,input("value",32),input("exponent",64),input("control",32),input("status",32)).is_none());
 assert!(arm64_float_extra::logb(64,input("value",64),input("control",64),input("status",32)).is_none());
 struct NoReads;impl Machine for NoReads{
  fn read_register(&self,r:Register)->Value{panic!("inactive outcome read {r:?}")}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("inactive memory")}
 }
 for w in[16u8,32,64]{for o in[scale(w),logb(w)]{
  for expression in[o.value,o.status,o.trapped]{let width=expression.ty.width;let inactive=Expr::select(Expr::constant(1,0),expression,Expr::constant(width,0));assert_eq!(evaluate_expression(&inactive,&NoReads,&[]).unwrap(),Value::known(width,0));}
 }}
}
#[test]fn ah_scale_exhausts_every_half_payload_with_signed_scale_and_rounding(){
 let o=scale(16);for value in 0..=u16::MAX{for mode in 0..4u32{for exponent in[1,u64::from(u16::MAX)]{
  let control=2|(mode<<22);let s=State{w:16,value:u64::from(value),exponent,control,status:0x08000081};assert_eq!(eval(&o,&s),scale_ref(&s),"half={value:04x} exp={exponent:04x} mode={mode}");
 }}}
}
#[test]fn ah_flush_nan_and_denormal_exception_goldens(){
 for(w,value,exponent,control,expected,raised,trap)in[
  // AH=1 output flushing raises IXC as well as direct, nontrapping UFC.
  (16,0x0400,u64::MAX,2|(1<<19),0,24,false),
  (16,0x0400,u64::MAX,2|(1<<19)|(1<<11),0,24,false),
  (16,0x0400,u64::MAX,2|(1<<19)|(1<<12),0,24,true),
  (32,0x00800000,u64::MAX,2|(1<<24),0,24,false),
  (64,0x0010000000000000,u64::MAX,2|(1<<24)|(1<<12),0,24,true),
  // Input FZ is disabled by AH for single/double. A denormal is processed
  // after scaling, even if its now-normal result itself raises no exception.
  (32,1,23,2|(1<<24),0x00800000,128,false),
  (64,1,52,2|(1<<24)|(1<<15),0x0010000000000000,128,true),
  (32,1,0,2|(1<<24),0,152,false),
  (32,1,0,2|(1<<24)|(1<<11),0,152,false),
  (32,1,0,2|(1<<24)|(1<<15),0,152,true),
  // FIZ flushes the input without IDC, bypassing FPRound and result flushing.
  (32,1,0,3|(1<<24)|(1<<15)|(1<<12),0,0,false),
  (64,1,0,3|(1<<15),0,0,false),
  // Half input FZ16 still applies in AH; FIZ and AHP never reinterpret half.
  (16,1,0,2|(1<<19)|(1<<15)|(1<<12),0,0,false),
  (16,1,0,3|(1<<26),1,0,false),
  // AFP DefaultNaN has a negative sign in every format.
  (16,0x7e01,0,2|(1<<25),0xfe00,0,false),
  (32,0x7f800001,0,2|(1<<25),0xffc00000,1,false),
  (64,0x7ff8000000001234,0,2|(1<<25),0xfff8000000000000,0,false),
  // Unconstrained rounding is exact for Scale, so tininess remains true
  // even when rounding the subnormal to the minimum normal encoding.
  (16,0x07ff,u64::MAX,2,0x0400,24,false),
  (32,0x00ffffff,u64::MAX,2,0x00800000,24,false),
  (64,0x001fffffffffffff,u64::MAX,2,0x0010000000000000,24,false),
 ]{
  for status in[0,0x0800009f]{let s=State{w,value,exponent:exponent&mask(w),control,status};let nontrapping=if control&(if w==16{1<<19}else{1<<24})!=0{8}else{0};let(expected_status,_)=accrued(&s,raised,nontrapping);assert_eq!(eval(&scale(w),&s),(expected,expected_status,trap),"w={w} value={value:016x} ctrl={control:08x}");}
 }
}

fn nodes(e:&Expr)->usize{1+match &e.kind{
 ExprKind::Constant(_)|ExprKind::Register(_)=>0,
 ExprKind::Unary{value,..}|ExprKind::Cast{value,..}|ExprKind::Extract{value,..}=>nodes(value),
 ExprKind::Binary{left,right,..}=>nodes(left)+nodes(right),
 ExprKind::Select{condition,yes,no}=>nodes(condition)+nodes(yes)+nodes(no),
 ExprKind::RequireContext{condition,..}=>nodes(condition),
 _=>panic!("Scale/LogB must use exact bit algebra: {e:?}"),
}}
#[test]fn helpers_are_bounded_bit_expressions_without_opaque_float_calls_or_effects(){
 for w in[16u8,32,64]{for out in[scale(w),logb(w)]{
  let size=[nodes(&out.value),nodes(&out.status),nodes(&out.trapped)];assert!(size.into_iter().all(|n|n<10000),"w={w}: {size:?}");
  for expression in[&out.value,&out.status,&out.trapped]{validate_expression(expression,&[]).unwrap();}
 }}
}
#[test]fn all_primary_physical_size_fields_exercise_exact_stateless_algebra(){
 for &(word,w,name)in EXTRA_CORPUS{let(f,emax,bias)=params(w);let(f,emax)=(u64::from(f),u64::from(emax));
  let values=[0,1,1<<f,(bias as u64)<<f,(emax-1)<<f,emax<<f,(emax<<f)|1,(emax<<f)|(1<<(f-1))];
  for value in values{let s=State{w,value,exponent:mask(w),control:0,status:0x08000002};
   if name.starts_with("fscale"){assert_eq!(eval(&scale(w),&s),scale_ref(&s),"{name} {word:08x}");}
   else{assert_eq!(eval(&logb(w),&s),log_ref(&s),"{name} {word:08x}");}
  }
 }
}
#[test]fn bfloat_scale_uses_bfloat_significand_and_fp32_flush_controls(){
 let out=arm64_float_extra::bfloat_scale(input("value",16),input("exponent",16),input("control",32),input("status",32)).unwrap();
 for(value,exponent,control,expected,flags)in[(0x0081,0xffff,0,0x0040,24),(1,1,1<<19,2,0),(1,1,3,0,0),(0x7f7f,1,3<<22,0x7f7f,20)]{
  let s=State{w:16,value,exponent,control,status:1<<27};assert_eq!(eval(&out,&s),(expected,(1<<27)|flags,false));
 }
}

#[test]fn captured_scale_ssa_matches_stateless_algebra_and_suppresses_inactive_context(){
 struct Unavailable;
 impl Machine for Unavailable{fn read_register(&self,r:Register)->Value{panic!("inactive scale read {r:?}")}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!()}}
 for (w,bf) in [(16,false),(32,false),(64,false),(16,true)] {
  for active in [false,true] {
   let mut recipe=Recipe::new(0x1004,64);let guard=Expr::constant(1,u64::from(active));
   let out=arm64_float_extra::scale_bound(&mut recipe,guard,w,input("value",w),input("exponent",w),input("control",32),input("status",32),bf).unwrap();
   for (bank,value) in [("out_value",out.value),("out_status",out.status),("out_trapped",out.trapped)]{let width=value.ty.width;recipe.write(register(bank,0,width,width),WritePolicy::ZeroUpper,Expr::select(Expr::constant(1,u64::from(active)),value,Expr::constant(width,0)));}
   recipe.validate().unwrap();
   if !active{let t=evaluate(&recipe,&Unavailable).unwrap();assert!(t.registers.iter().all(|w|w.value.bits==0));continue;}
   let raw=if bf{arm64_float_extra::bfloat_scale(input("value",w),input("exponent",w),input("control",32),input("status",32)).unwrap()}else{scale(w)};
   let(f,max,bias)=if bf{(7,255,127)}else{params(w)};
   for value in [0,1,mask(w),1<<(w-1),(bias as u64)<<f,((max-1)as u64)<<f,(max as u64)<<f,((max as u64)<<f)|1] {
    for exponent in [0,1,mask(w),1<<(w-1),(1<<(w-1))-1] {for control in [0,1,2,3,0x9f00,0x1000000,0x2080000,0xc00000]{let state=State{w,value,exponent,control,status:0x08000002};let t=evaluate(&recipe,&state).unwrap();let got=(t.registers[0].value.bits,t.registers[1].value.bits as u32,t.registers[2].value.bits!=0);assert_eq!(got,eval(&raw,&state),"w{w} BF{bf} value{value:x} exponent{exponent:x} control{control:x}");}}
   }
  }
 }
}
`

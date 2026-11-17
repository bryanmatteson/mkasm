package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustArm64PointerArithmetic(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "tests.rs": arm64PointerTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const arm64PointerTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
use runtime::arm64_pointer;
#[derive(Default)]struct State{x:[u64;31],sp:u64,flags:u8,cpta:bool,cptm:bool,mte:bool,exclude:u16,rrnd:bool,eirg:bool,seed:u16,tag:u8,entropy:u64,draws:std::cell::Cell<usize>}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{match r.bank{
 "a64.gpr"=>Value::known(64,self.x[r.index as usize]),"a64.sp"=>Value::known(64,self.sp),
 "a64.nzcv"=>Value::known(1,u64::from((self.flags>>(3-r.index))&1)),
 "a64.cpta"=>Value::known(1,u64::from(self.cpta)),"a64.cptm"=>Value::known(1,u64::from(self.cptm)),
 "a64.mte_enabled"=>Value::known(1,u64::from(self.mte)),
 "a64.tag_rrnd"=>Value::known(1,u64::from(self.rrnd)),"a64.tag_eirg"=>Value::known(1,u64::from(self.eirg)),
 "a64.tag_seed"=>Value::known(16,u64::from(self.seed)),"a64.tag_state"=>Value::known(4,u64::from(self.tag)),
 "a64.tag_exclude"=>{assert!(self.mte,"disabled MTE must not read exclusion state");Value::known(16,u64::from(self.exclude))},
 _=>panic!("{r:?}"),}}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("pointer memory")}
 fn choose(&self,step:usize,width:u8)->Result<Value,EvalError>{assert_eq!((step,width),(0,64));self.draws.set(self.draws.get()+1);Ok(Value::known(64,self.entropy))}
}
fn input(s:&State,n:u32,sp:bool)->u64{if n==31 {if sp{s.sp}else{0}}else{s.x[n as usize]}}
fn run(word:u32,s:&State)->Transition{let r=arm64_pointer::a64(word,u64::MAX-3).unwrap();assert_eq!(r.support,Support::Full);r.validate().unwrap();let t=evaluate(&r,s).unwrap();assert_eq!(t.trap,None);assert_eq!(t.next_pc,Value::known(64,0));assert!(t.memory.is_empty());t}
fn output(t:&Transition,d:u32,sp:bool)->Option<u64>{t.registers.iter().find(|w|if d==31{sp&&w.register.bank=="a64.sp"}else{w.register.bank=="a64.gpr"&&w.register.index==d as u16}).map(|w|{assert!(w.value.is_known());w.value.bits})}
fn checked(result:u64,base:u64,over:bool,s:&State)->u64{if(s.cpta&&((result>>56)!=(base>>56)||((base>>55)^(base>>54))&1!=0))||(s.cptm&&over){(result&((1u64<<54)-1))|(base&0xff80000000000000)|(((!base>>55)&1)<<54)}else{result}}
#[test]fn pointer_add_sub_all_shifts_alias_sp_and_controls(){
 for a in [0,1,0x003fffffffffffff,0x0080000000000000,0x00fffffffffffff0,0xff00000000000000,u64::MAX]{for z in [0,1,0x100000000000000,0x7fffffffffffffff,u64::MAX]{for enabled in [false,true]{for shift in 0..8{for sub in [false,true]{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(31,31,2),(0,31,31)]{
 let mut s=State::default();s.x[1]=a;s.x[2]=z;s.sp=a;s.cpta=enabled;s.cptm=true;
 let base=input(&s,n,true);let offset=input(&s,m,false).wrapping_shl(shift);
 let result=if sub{base.wrapping_sub(offset)}else{base.wrapping_add(offset)};
 let t=run((if sub{0xda002000}else{0x9a002000})|(m<<16)|(shift<<10)|(n<<5)|d,&s);
 assert_eq!(output(&t,d,true),Some(checked(result,base,false,&s)));assert_eq!(t.registers.len(),1);
 }}}}}}
}
#[test]fn pointer_multiply_uses_signed_product_overflow_and_separate_cptm(){
 for a in [0i64,1,-1,i64::MIN,i64::MAX,1<<40]{for z in [0i64,1,-1,3,i64::MIN,i64::MAX]{for cpta in [false,true]{for cptm in [false,true]{for sub in [false,true]{for(d,n,m,acc)in[(0,1,2,3),(1,1,2,1),(2,1,2,2),(31,1,2,3),(0,31,2,31)]{
 let mut s=State::default();s.x[1]=a as u64;s.x[2]=z as u64;s.x[3]=0x123456789abc;s.cpta=cpta;s.cptm=cptm;
 let p=i128::from(input(&s,n,false)as i64)*i128::from(input(&s,m,false)as i64);let over=p!=(p as i64)as i128;let base=input(&s,acc,false);
 let result=if sub{base.wrapping_sub(p as u64)}else{base.wrapping_add(p as u64)};
 let t=run(0x9b600000|(u32::from(sub)<<15)|(m<<16)|(acc<<10)|(n<<5)|d,&s);
 assert_eq!(output(&t,d,false),if d==31{None}else{Some(checked(result,base,over,&s))});assert_eq!(t.registers.len(),usize::from(d!=31));
 }}}}}}
}
fn choose(mut tag:u8,offset:u8,exclude:u16)->u8{if exclude==u16::MAX{return 0;}if offset==0{while exclude&(1<<tag)!=0{tag=(tag+1)&15;}}for _ in 0..offset{tag=(tag+1)&15;while exclude&(1<<tag)!=0{tag=(tag+1)&15;}}tag}
#[test]fn addg_subg_all_tags_offsets_and_exclusion_masks(){
 for excluded in [0,1,0x8000,0x5555,0xaaaa,0xfffe,0x7fff,0xffff]{for tag in 0..16u64{for offset in 0..16u32{for mte in [false,true]{for sub in [false,true]{for(d,n)in[(0,1),(1,1),(31,31)]{
 let mut s=State::default();s.mte=mte;s.exclude=excluded;s.sp=0xa000fffffffffff0|(tag<<56);s.x[1]=s.sp;
 let imm=(offset*5)&63;let base=input(&s,n,true);let addr=if sub{base.wrapping_sub(u64::from(imm)*16)}else{base.wrapping_add(u64::from(imm)*16)};
 let t=run((if sub{0xd1800000}else{0x91800000})|(imm<<16)|(offset<<10)|(n<<5)|d,&s);
 let tag=if mte{u64::from(choose(tag as u8,offset as u8,excluded))}else{0};let expected=(addr&!(15u64<<56))|(tag<<56);
 assert_eq!(output(&t,d,true),Some(expected));assert_eq!(t.registers.len(),1);
 }}}}}}
}
#[test]fn subp_signextends_56bit_addresses_and_subps_sets_nzcv(){
 for a in [0,1,0x7fffffffffffff,0x80000000000000,0xffffffffffffff,u64::MAX]{for z in [0,1,0x7fffffffffffff,0x80000000000000,u64::MAX]{for set in [false,true]{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(31,31,2),(0,1,31)]{
 let mut s=State::default();s.x[1]=a;s.x[2]=z;s.sp=z;
 let a=((input(&s,n,true)<<8)as i64)>>8;let z=((input(&s,m,true)<<8)as i64)>>8;let result=a.wrapping_sub(z);
 let t=run((if set{0xbac00000}else{0x9ac00000})|(m<<16)|(n<<5)|d,&s);
 assert_eq!(output(&t,d,false),if d==31{None}else{Some(result as u64)});
 let mut f=0;for w in &t.registers{if w.register.bank=="a64.nzcv"{assert!(w.value.is_known());f|=(w.value.bits as u8)<<(3-w.register.index);}}
 if set{let over=(i128::from(a)-i128::from(z))!=i128::from(result);assert_eq!(f,(u8::from(result<0)<<3)|(u8::from(result==0)<<2)|(u8::from(a as u64>=z as u64)<<1)|u8::from(over));}else{assert_eq!(t.registers.len(),usize::from(d!=31));}
 }}}}
}
#[test]fn gmi_sets_only_logical_tag_bit_in_full_mask_and_honors_sp_zr(){
 for tag in 0..16u64{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(31,1,2),(0,31,31)]{let mut s=State::default();s.x[1]=tag<<56;s.x[2]=0xaaaaaaaaaaaa0000;s.sp=tag<<56;
 let t=run(0x9ac01400|(m<<16)|(n<<5)|d,&s);assert_eq!(output(&t,d,false),if d==31{None}else{Some(input(&s,m,false)|(1<<tag))});}}
}
fn lfsr(seed:u16)->(u16,u8){let top=((seed>>5)^(seed>>3)^(seed>>2)^seed)&1;((seed>>1)|(top<<15),top as u8)}
#[test]fn irg_deterministic_modes_follow_lfsr_bins_and_state_updates(){
 for eirg in [false,true]{for seed in [0,1,2,0x5678,0x8000,0xffff]{for tag in 0..16u8{for exclude in [0,1,0x5555,0xaaaa,0xfffe,0x7fff,0xffff]{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(31,31,31)]{
 let mut s=State::default();s.mte=true;s.eirg=eirg;s.seed=seed;s.tag=tag;s.exclude=exclude;s.x[1]=0xfabcde0012345678;s.x[2]=0x8002;s.sp=s.x[1];
 let excluded=exclude|input(&s,m,false)as u16;let bins=(0..16).filter(|t|excluded&(1<<t)==0).collect::<Vec<_>>();
 let(mut next_seed,mut next_tag)=(seed,tag);let result;
 if eirg {if bins.is_empty(){result=0;}else{let state=if usize::from(tag)+1>=bins.len(){0}else{tag+1};let rank=(usize::from(state)+((bins.len()*usize::from(seed))>>16))%bins.len();result=bins[rank];next_tag=state;next_seed=lfsr(seed).0;}}
 else{let mut offset=0;for i in 0..4{let(ns,bit)=lfsr(next_seed);next_seed=ns;offset|=bit<<i;}result=choose(tag,offset,excluded);next_tag=result;}
 let t=run(0x9ac01000|(m<<16)|(n<<5)|d,&s);assert_eq!(output(&t,d,true),Some((input(&s,n,true)&!(15u64<<56))|(u64::from(result)<<56)));
 let controls=t.registers.iter().filter(|w|w.register.bank.starts_with("a64.tag_")).collect::<Vec<_>>();
 if eirg&&bins.is_empty(){assert!(controls.is_empty());}else{assert_eq!(controls.len(),2);assert_eq!(controls[0].value,Value::known(16,u64::from(next_seed)));assert_eq!(controls[1].value,Value::known(4,u64::from(next_tag)));}assert_eq!(s.draws.get(),0);
 }}}}}
}
#[test]fn irg_random_bins_and_disabled_paths_are_lazy(){
 for enabled in [false,true]{for excluded in [0,0x5555,0xfffe,0xffff]{for entropy in [0,1,u64::MAX/2,u64::MAX]{let mut s=State::default();s.mte=enabled;s.rrnd=true;s.exclude=excluded;s.entropy=entropy;s.x[1]=0xfabcde0012345678;
 let t=run(0x9adf1020,&s);let bins=(0..16u8).filter(|v|excluded&(1<<v)==0).collect::<Vec<_>>();let wanted=if !enabled||bins.is_empty(){0}else{bins[((u128::from(entropy)*bins.len()as u128)>>64)as usize]};assert_eq!(output(&t,0,true),Some((s.x[1]&!(15u64<<56))|(u64::from(wanted)<<56)));assert_eq!(s.draws.get(),usize::from(enabled&&!bins.is_empty()));assert_eq!(t.registers.len(),1);
 }}}
 struct Disabled;impl Machine for Disabled{fn read_register(&self,r:Register)->Value{match r.bank{"a64.mte_enabled"=>Value::known(1,0),"a64.gpr"=>Value::known(64,0xabcdef),_=>Value::unknown(16)}}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!()}}
 let r=arm64_pointer::a64(0x9adf1020,0).unwrap();assert_eq!(evaluate(&r,&Disabled).unwrap().registers[0].value,Value::known(64,0xabcdef));
}
#[test]fn unrelated_reserved_and_wrong_width_encodings_are_not_claimed(){for w in [0x1a002000,0x9a004000,0x9b200000,0x91804000,0x91808000,0x11c00000,0x1ac01400,0xd503201f]{assert!(arm64_pointer::a64(w,0).is_none(),"{w:08x}");}}
`

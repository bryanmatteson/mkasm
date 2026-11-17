package x86

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Uses the standalone generated crate directly: no Cargo or remote build.
func TestRustX86XEDIntegerRecipes(t *testing.T) {
	input := os.Getenv("MKASM_X86_OPCODESDB")
	if input == "" {
		t.Skip("set MKASM_X86_OPCODESDB to the actual pinned opcodesDB corpus")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseOpcodesDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SupplementXEDFP16(c); err != nil {
		t.Fatal(err)
	}
	report, err := SupplementXEDInteger(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("source forms %d; integer imported %d, unrelated source classes %d", len(c.Encodings), report.Imported, report.OtherClasses)
	dir := t.TempDir()
	if err := GenerateRust(c, dir); err != nil {
		t.Fatal(err)
	}
	tests := x86RecipeTests + x86CorpusBoundaryTests + x86ExpandedRecipeTests + x86MaskedMemoryTests + x86HalfRecipeTests + x86BfloatRecipeTests + x86FP16RecipeTests + x86Avx512IntegerRecipeTests + x86XEDIntegerRecipeTests
	if err := os.WriteFile(filepath.Join(dir, "recipes_test.rs"), []byte(tests), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "x86_64", "--crate-type", "rlib", "src/lib.rs", "-Dwarnings", "-o", "libx86_64.rlib"}, {"--edition=2021", "--test", "recipes_test.rs", "--extern", "x86_64=libx86_64.rlib", "-Dwarnings", "-o", "recipes_test"}} {
		cmd := exec.Command("rustc", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated Rust %v: %v\n%s", args, err, out)
		}
	}
	cmd := exec.Command(filepath.Join(dir, "recipes_test"), "--nocapture")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated integer recipes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

const x86XEDIntegerRecipeTests = `
fn xed_integer_width(e:&Encoding)->u16{if e.form_id.contains("ZMM"){512}else if e.form_id.contains("YMM"){256}else{128}}
fn xed_integer_bytes(i:usize,mode:Mode,alias:u8,mask:u8,zeroing:bool,broadcast:bool)->Vec<u8>{let e=encoding(i).unwrap();let mem=e.form_id.contains("MEM");let fields=EncodeFields{mode,mod_bits:if mem{0}else{3},reg:0,vvvv:if alias==1{0}else{1},rm:if mem||alias==2{0}else{2},mask,zeroing,broadcast,..Default::default()};let mut out=[0;15];let n=encode(i,fields,&mut out).unwrap();out[..n].to_vec()}
fn xed_integer_eval(bytes:&[u8],mode:Mode,state:&impl Machine)->Transition{let d=decode(bytes,mode).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full,"{} {bytes:02x?}",d.encoding().form_id);r.validate().unwrap();s::evaluate(&r,state).unwrap()}
fn xed_dot_expected(name:&str,acc:u32,a:u32,b:u32)->u32{
 let (w,sa,sb,uu)=match name{"VPDPBUSD"|"VPDPBUSDS"=>(8,false,true,false),"VPDPWSSD"|"VPDPWSSDS"=>(16,true,true,false),"VPDPBSSD"|"VPDPBSSDS"=>(8,true,true,false),"VPDPBSUD"|"VPDPBSUDS"=>(8,true,false,false),"VPDPBUUD"|"VPDPBUUDS"=>(8,false,false,true),"VPDPWSUD"|"VPDPWSUDS"=>(16,true,false,false),"VPDPWUSD"|"VPDPWUSDS"=>(16,false,true,false),"VPDPWUUD"|"VPDPWUUDS"=>(16,false,false,true),_=>panic!("{name}")};
 let mut sum=if uu{i64::from(acc)}else{i64::from(acc as i32)};for j in 0..32/w {let(x,y)=if w==8{let(x,y)=((a>>(j*w))as u8,(b>>(j*w))as u8);(if sa{i64::from(x as i8)}else{i64::from(x)},if sb{i64::from(y as i8)}else{i64::from(y)})}else{let(x,y)=((a>>(j*w))as u16,(b>>(j*w))as u16);(if sa{i64::from(x as i16)}else{i64::from(x)},if sb{i64::from(y as i16)}else{i64::from(y)})};sum+=x*y;}
 if name.ends_with("DS"){if uu{sum.clamp(0,i64::from(u32::MAX))as u32}else{sum.clamp(i64::from(i32::MIN),i64::from(i32::MAX))as u32}}else{sum as u32}
}
#[test]fn xed_integer_primary_forms_full_all_modes_arithmetic_aliases_and_upper_zeroing(){
 let mut forms=0;let aa=[0xffffffffu64,0x80008000,0x7fff7fff,0x00ff80ff,0xffff0000,0x01020304,0,0x00010001];let bb=[0x80008000u64,0xffffffff,0x7fff7fff,0xff008080,0x0000ffff,0xff017f80,0xffffffff,0x00020002];let dd=[0x7fffffffu64,0x80000000,0xffffffff,0,0x7fffffff,0x80000000,9,0xfffffff0];
 for i in 0..encoding_count(){let e=encoding(i).unwrap();if !e.id.starts_with("XED-INTEGER/"){continue}forms+=1;let vl=xed_integer_width(e);for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{let bytes=xed_integer_bytes(i,mode,0,0,false,false);let d=decode(&bytes,mode).unwrap();assert_eq!(d.semantic_recipe(0).support,Support::Full,"{} {mode:?}",e.form_id);d.semantic_recipe(0).validate().unwrap();if e.form_id.contains("MEM"){continue}for alias in[0,1,2]{let mut st=State::default();let bytes=xed_integer_bytes(i,mode,alias,0,false,false);if e.mnemonic.starts_with("VPMADD52") {let a=[u64::MAX,0x8000000000000,0x10000000000001,0x123456789abcdef0];let b=[0xfffffffffffff,0x8000000000000,u64::MAX,0xfedcba9876543210];let acc=[u64::MAX,9,0xfffffffffffffff0,7];vector(&mut st,0,&acc);vector(&mut st,1,&a);vector(&mut st,2,&b);let t=xed_integer_eval(&bytes,mode,&st);for lane in 0..usize::from(vl/64){let x=if alias==1{acc[lane]}else{a[lane]};let y=if alias==2{acc[lane]}else{b[lane]};let product=u128::from(x&0xfffffffffffff)*u128::from(y&0xfffffffffffff);let value=(if e.mnemonic.ends_with("HUQ"){product>>52}else{product})as u64&0xfffffffffffff;assert_eq!(vector_result(&t,0,lane as u16),acc[lane].wrapping_add(value));}for chunk in vl/64..8{assert_eq!(vector_result(&t,0,chunk),0)}}else{let a:Vec<_>=(0..vl/32).map(|j|aa[usize::from(j)%8]).collect();let b:Vec<_>=(0..vl/32).map(|j|bb[usize::from(j)%8]).collect();let acc:Vec<_>=(0..vl/32).map(|j|dd[usize::from(j)%8]).collect();vector(&mut st,0,&pack_int_lanes(&acc,32));vector(&mut st,1,&pack_int_lanes(&a,32));vector(&mut st,2,&pack_int_lanes(&b,32));let t=xed_integer_eval(&bytes,mode,&st);for lane in 0..usize::from(vl/32){assert_eq!(int_lane(&t,0,lane,32),u64::from(xed_dot_expected(e.mnemonic,acc[lane]as u32,if alias==1{acc[lane]}else{a[lane]}as u32,if alias==2{acc[lane]}else{b[lane]}as u32)),"{} {mode:?} alias{alias} lane{lane}",e.form_id);}for chunk in vl/64..8{assert_eq!(vector_result(&t,0,chunk),0)}}}}}
 assert_eq!(forms,144);
}
#[test]fn xed_integer_vex_memory_full_access_and_faults_evex_lane_suppression_and_broadcast(){
 for i in 0..encoding_count(){let e=encoding(i).unwrap();if !e.id.starts_with("XED-INTEGER/")||!e.form_id.contains("MEM"){continue}let vl=xed_integer_width(e);let unmasked=xed_integer_bytes(i,Mode::Mode64,0,0,false,false);let mut st=AccessState::new();st.state.x(0,0x9000);vector(&mut st.state,0,&[0xffffffff7fffffff;8]);vector(&mut st.state,1,&[0x8000ffff7fff8000;8]);for chunk in 0..vl/64{st.state.mem.insert(0x9000+u64::from(chunk*8),0xffff00018000ffff);}let t=xed_integer_eval(&unmasked,Mode::Mode64,&st);assert_eq!(*st.reads.borrow(),vec![(0x9000,vl)]);if !e.mnemonic.starts_with("VPMADD52"){for lane in 0..usize::from(vl/32){assert_eq!(int_lane(&t,0,lane,32),u64::from(xed_dot_expected(e.mnemonic,if lane%2==0{0x7fffffff}else{0xffffffff},if lane%2==0{0x7fff8000}else{0x8000ffff},if lane%2==0{0x8000ffff}else{0xffff0001})),"{} lane{lane}",e.form_id);}}else{let product=u128::from(0x8000ffff7fff8000u64&0xfffffffffffff)*u128::from(0xffff00018000ffffu64&0xfffffffffffff);let part=(if e.mnemonic.ends_with("HUQ"){product>>52}else{product})as u64&0xfffffffffffff;for chunk in 0..vl/64{assert_eq!(vector_result(&t,0,chunk),0xffffffff7fffffffu64.wrapping_add(part),"{} chunk{chunk}",e.form_id);}}
  let missing=0x9000+u64::from(vl/8)-8;st.state.mem.remove(&missing);assert_eq!(s::evaluate(&decode(&unmasked,Mode::Mode64).unwrap().semantic_recipe(0),&st),Err(EvalError::Memory));
  if unmasked[0]!=0x62{continue}let n=vl/32;let masked=xed_integer_bytes(i,Mode::Mode64,0,1,true,false);st.state.mem.clear();st.state.mem.insert(0x9000,0xffffffff);let last=0x9000+u64::from((n-1)*4);st.state.mem.insert(last,0x80008000);st.state.reg("x86.mask",1,1|(1u64<<(n-1)));st.reads.borrow_mut().clear();let t=xed_integer_eval(&masked,Mode::Mode64,&st);assert_eq!(*st.reads.borrow(),vec![(0x9000,32),(last,32)]);for lane in 0..n{let expected=if lane==0{xed_dot_expected(e.mnemonic,0x7fffffff,0x7fff8000,0xffffffff)}else if lane==n-1{xed_dot_expected(e.mnemonic,0xffffffff,0x8000ffff,0x80008000)}else{0};assert_eq!(int_lane(&t,0,usize::from(lane),32),u64::from(expected));}
  let broadcast=xed_integer_bytes(i,Mode::Mode64,0,1,true,true);st.reads.borrow_mut().clear();let t=xed_integer_eval(&broadcast,Mode::Mode64,&st);assert_eq!(*st.reads.borrow(),vec![(0x9000,32)]);assert_eq!(int_lane(&t,0,usize::from(n-1),32),u64::from(xed_dot_expected(e.mnemonic,0xffffffff,0x8000ffff,0xffffffff)));
  st.state.reg("x86.mask",1,0);st.unknown_address=true;st.address_reads.set(0);st.reads.borrow_mut().clear();let _=xed_integer_eval(&masked,Mode::Mode64,&NoIntegerVectorReads(&st));let _=xed_integer_eval(&broadcast,Mode::Mode64,&NoIntegerVectorReads(&st));assert_eq!(st.address_reads.get(),0);assert!(st.reads.borrow().is_empty());
 }
}
#[test]fn xed_integer_new_signedness_merge_masks_and_tuple_displacements(){
 for i in 0..encoding_count(){let e=encoding(i).unwrap();if !e.id.starts_with("XED-INTEGER/"){continue}let mut bytes=xed_integer_bytes(i,Mode::Mode64,0,0,false,false);if bytes[0]!=0x62{continue}let vl=xed_integer_width(e);let mut st=AccessState::new();st.state.x(0,0xa000);st.state.reg("x86.mask",1,1);vector(&mut st.state,0,&[0x7fffffff7fffffff;8]);vector(&mut st.state,1,&[0xffffffff;8]);vector(&mut st.state,2,&[0x80008000;8]);if e.form_id.contains("MEM"){let fields=EncodeFields{mode:Mode::Mode64,mod_bits:1,reg:0,vvvv:1,rm:0,mask:1,displacement:i64::from(512/vl),..Default::default()};let mut out=[0;15];let n=encode(i,fields,&mut out).unwrap();bytes=out[..n].to_vec();st.state.mem.insert(0xa040,0x80008000);}else{bytes=xed_integer_bytes(i,Mode::Mode64,0,1,false,false)}let t=xed_integer_eval(&bytes,Mode::Mode64,&st);assert_eq!(int_lane(&t,0,0,32),u64::from(xed_dot_expected(e.mnemonic,0x7fffffff,0xffffffff,0x80008000)));for lane in 1..vl/32{assert_eq!(int_lane(&t,0,usize::from(lane),32),0x7fffffff)}for chunk in vl/64..8{assert_eq!(vector_result(&t,0,chunk),0)}if e.form_id.contains("MEM"){assert_eq!(*st.reads.borrow(),vec![(0xa040,32)]);}
 }
}
`

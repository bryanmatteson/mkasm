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

//go:embed arm64_misc.rs
var arm64MiscSource string

func TestRustArm64ScalarMisc(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "arm64_misc.rs": arm64MiscSource, "misc_tests.rs": arm64MiscBehaviorTests + arm64MiscCorpus(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "misc_tests.rs", "-Dwarnings", "-o", "misc-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 misc: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "misc-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A64 misc: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func arm64MiscCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional Arm corpus absent; portable scalar matrix still runs")
		return "const MISC_CORPUS:&[(u32,&str)]=&[];"
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
	for _, n := range strings.Fields("crc32 crc32c rmif setf abs cnt ctz smax_imm smax_reg smin_imm smin_reg umax_imm umax_reg umin_imm umin_reg") {
		wanted[n+".xml"] = true
	}
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
	out.WriteString("const MISC_CORPUS:&[(u32,&str)]=&[\n")
	count := 0
	seen := map[string]bool{}
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
					var bits strings.Builder
					for _, c := range b.Cells {
						text := strings.Trim(strings.TrimSpace(c.Text), "()")
						if text == "0" || text == "1" {
							bits.WriteString(text)
						}
					}
					var value uint64
					if bits.Len() == width {
						value, err = strconv.ParseUint(bits.String(), 2, 32)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						switch b.Name {
						case "sf":
							if strings.HasPrefix(name, "crc32") {
								if variant&3 == 3 {
									value = 1
								}
							} else {
								value = uint64(variant & 1)
							}
						case "sz":
							if strings.HasPrefix(name, "crc32") {
								value = uint64(variant & 3)
							} else {
								value = uint64(variant & 1)
							}
						case "Rd":
							value = uint64([]int{0, 1, 2, 31, 0, 1, 2, 31}[variant])
						case "Rn":
							value = uint64([]int{1, 1, 2, 31, 1, 1, 2, 31}[variant])
						case "Rm":
							value = uint64([]int{2, 2, 2, 31, 2, 2, 2, 31}[variant])
						case "imm8":
							value = uint64(variant * 36)
						case "imm6":
							value = uint64(variant * 9)
						case "mask":
							value = uint64(variant*2 + 1)
						}
					}
					word |= uint32(value) << uint(b.Hi-width+1)
				}
				fmt.Fprintf(&out, "(0x%08x,%q),\n", word, strings.TrimSuffix(name, ".xml"))
				count++
			}
		}
	}
	for n := range wanted {
		if !seen[n] {
			t.Errorf("missing primary scalar corpus page %s", n)
		}
	}
	out.WriteString("];\n")
	t.Logf("primary A64 misc corpus: %d words from %d pages", count, len(seen))
	return out.String()
}

const arm64MiscBehaviorTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
mod arm64_misc;
#[derive(Default)]struct State{x:[u64;31],nzcv:u8}
impl Machine for State {
 fn read_register(&self,r:Register)->Value{match r.bank{
  "a64.gpr"=>{assert!(r.index<31);Value::known(64,self.x[usize::from(r.index)])},
  "a64.nzcv"=>Value::known(1,u64::from((self.nzcv>>(3-r.index))&1)),
  _=>panic!("unexpected scalar state {r:?}"),
 }}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("scalar misc memory")}
}
fn initial()->State{let mut s=State::default();for n in 0..31{s.x[n]=0x814223c465a607e8u64.rotate_left(n as u32);}s.nzcv=11;s}
fn get(s:&State,n:u32,width:u8)->u64{if n==31{0}else{s.x[n as usize]&mask(width)}}
fn run(word:u32,s:&State)->(State,Transition){
 let r=arm64_misc::a64(word,0xfffffffffffffffc).unwrap_or_else(||panic!("unhandled {word:08x}"));
 assert_eq!(r.support,Support::Full);r.validate().unwrap();let t=evaluate(&r,s).unwrap();
 assert_eq!(t.trap,None);assert_eq!(t.next_pc,Value::known(64,0));assert!(t.memory.is_empty());assert!(t.wide_memory.is_empty());assert!(t.atomics.is_empty());
 let mut out=State{x:s.x,nzcv:s.nzcv};for write in &t.registers{assert!(write.value.is_known());match write.register.bank{
  "a64.gpr"=>out.x[usize::from(write.register.index)]=write.value.bits,
  "a64.nzcv"=>{let bit=3-write.register.index;out.nzcv=(out.nzcv&!(1<<bit))|((write.value.bits as u8)<<bit);},
  _=>panic!("unexpected scalar write {write:?}"),
 }}(out,t)
}
// Independent nonreflected polynomial long division, matching the primary
// pseudocode's reverse-accumulator/operand, append zeros, divide and reverse.
fn crc(acc:u32,data:u64,size:u8,castagnoli:bool)->u32{
 let reverse=if size==64{data.reverse_bits()}else{(data&mask(size)).reverse_bits()>>(64-size)};
 let mut remainder=(u128::from(acc.reverse_bits())<<size)^(u128::from(reverse)<<32);
 let polynomial=(1u128<<32)|if castagnoli{0x1edc6f41}else{0x04c11db7};
 for bit in (32..32+u32::from(size)).rev(){if remainder&(1u128<<bit)!=0{remainder^=polynomial<<(bit-32);}}
 (remainder as u32).reverse_bits()
}
fn crcword(size:u8,castagnoli:bool,d:u32,n:u32,m:u32)->u32{
 0x1ac04000|(u32::from(size==64)<<31)|(u32::from(size.trailing_zeros()-3)<<10)|(u32::from(castagnoli)<<12)|(m<<16)|(n<<5)|d
}
#[test]fn crc_every_width_polynomial_alias_and_zr(){
 let mut random=0xfedcba9876543210u64;
 for size in [8u8,16,32,64]{for castagnoli in [false,true]{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(1,1,1),(0,31,2),(0,1,31),(31,1,2)]{
  let word=crcword(size,castagnoli,d,n,m);for _ in 0..16{
   random^=random<<13;random^=random>>7;random^=random<<17;let mut s=initial();s.x[1]=random;s.x[2]=random.rotate_right(23);
   let expected=crc(get(&s,n,32)as u32,get(&s,m,size),size,castagnoli);let(out,t)=run(word,&s);assert_eq!(out.nzcv,s.nzcv);
   for reg in 0..31{assert_eq!(out.x[reg],if reg==d as usize{u64::from(expected)}else{s.x[reg]},"{word:08x} X{reg}");}
   assert_eq!(t.registers.len(),usize::from(d!=31));
  }
 }}}
}
#[test]fn standard_crc_check_vectors_and_multi_byte_order(){
 for(castagnoli,check)in[(false,0xcbf43926u32),(true,0xe3069283)]{
  let mut s=State::default();s.x[0]=u64::from(u32::MAX);
  for byte in b"123456789"{s.x[1]=u64::from(*byte);s=run(crcword(8,castagnoli,0,0,1),&s).0;}
  assert_eq!(!(s.x[0]as u32),check);
  let mut serial=initial();serial.x[0]=0x12345678;
  for byte in b"abcdefgh"{serial.x[1]=u64::from(*byte);serial=run(crcword(8,castagnoli,0,0,1),&serial).0;}
  let mut wide=initial();wide.x[0]=0x12345678;wide.x[1]=u64::from_le_bytes(*b"abcdefgh");
  assert_eq!(run(crcword(64,castagnoli,0,0,1),&wide).0.x[0],serial.x[0]);
 }
 for sf in 0..2u32{for size in 0..4u32{if(sf==1)==(size==3){continue;}let word=0x1ac04000|(sf<<31)|(size<<10);
  let r=arm64_misc::a64(word,0).unwrap();assert!(matches!(r.support,Support::Unsupported(_)));assert_eq!(evaluate(&r,&initial()),Err(EvalError::Unsupported));
 }}
}
#[test]fn rmif_all_rotations_masks_and_incoming_flags(){
 for incoming in 0..16u8{for rotate in 0..64u32{for selected in 0..16u32{for n in [1,31]{
  let mut s=initial();s.nzcv=incoming;let word=0xba000400|(rotate<<15)|(n<<5)|selected;
  let rotated=get(&s,n,64).rotate_right(rotate)as u8;
  let(out,t)=run(word,&s);assert_eq!(out.x,s.x);
  assert_eq!(out.nzcv,(incoming&!(selected as u8))|(rotated&(selected as u8)),"{word:08x}");
  assert_eq!(t.registers.len(),selected.count_ones()as usize);
 }}}}
}
#[test]fn setf_captures_sign_zero_and_extension_overflow_but_preserves_carry(){
 for size in [8u8,16]{for incoming in 0..16u8{for raw in (0..=511u32).chain([0x7fff,0x8000,0xffff,0x10000,0x17fff,0x18000,0x1ffff,u32::MAX]){
  let mut s=initial();s.nzcv=incoming;s.x[1]=0xff11223300000000|u64::from(raw);
  let word=0x3a00080d|(u32::from(size==16)<<14)|(1<<5);let(out,t)=run(word,&s);
  let sign=((raw>>(size-1))&1)as u8;let zero=u8::from(u64::from(raw)&mask(size)==0);let overflow=(((raw>>size)&1)as u8)^sign;
  assert_eq!(out.nzcv,(sign<<3)|(zero<<2)|(incoming&2)|overflow,"{word:08x} {raw:x}");assert_eq!(out.x,s.x);assert_eq!(t.registers.len(),3);
 }}}
 let s=initial();assert_eq!(run(0x3a00080d|(31<<5),&s).0.nzcv,(s.nzcv&2)|4);
}
#[test]fn cssc_counts_abs_width_zero_extension_and_signed_minimum_wrap(){
 let boundary=[0,1,2,3,0x80000000,0xffffffff,0x100000000,0x8000000000000000,u64::MAX];
 for sf in 0..2u32{let w=32u8<<sf;for base in [0x5ac01800,0x5ac01c00,0x5ac02000]{for n in [1,31]{for d in [0,1,31]{for raw in boundary{
  let mut s=initial();s.x[1]=raw;let a=get(&s,n,w);
  let expected=match base{0x5ac01800=>if a==0{u64::from(w)}else{u64::from(a.trailing_zeros())},0x5ac01c00=>u64::from(a.count_ones()),_=>if a&(1<<(w-1))!=0{a.wrapping_neg()&mask(w)}else{a}};
  let word=base|(sf<<31)|(n<<5)|d;let(out,t)=run(word,&s);assert_eq!(out.nzcv,s.nzcv);
  for reg in 0..31{assert_eq!(out.x[reg],if reg==d as usize{expected}else{s.x[reg]},"{word:08x} {raw:x}");}
  assert_eq!(t.registers.len(),usize::from(d!=31));
 }}}}}
}
fn signed(a:u64,w:u8)->i64{((a<<(64-w))as i64)>>(64-w)}
#[test]fn cssc_minmax_signed_unsigned_register_and_immediate_boundaries(){
 let boundary=[0,1,127,128,255,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,0x8000000000000000,u64::MAX];
 for sf in 0..2u32{let w=32u8<<sf;for operation in 0..4u32{let unsigned=operation&1!=0;let minimum=operation&2!=0;
  for immediate in [false,true]{for a in boundary{for raw in boundary{for(d,n,m)in[(0,1,2),(1,1,2),(2,1,2),(0,31,2),(0,1,31),(31,1,2)]{
   let mut s=initial();s.x[1]=a;s.x[2]=raw;
   let word=if immediate{0x11c00000|(operation<<18)|(((raw as u32)&255)<<10)}else{0x1ac06000|(operation<<10)|(m<<16)}|(sf<<31)|(n<<5)|d;
   let a=get(&s,n,w);let z=if immediate{if unsigned{raw&255}else{((raw as u8 as i8)as i64)as u64&mask(w)}}else{get(&s,m,w)};
   let less=if unsigned{a<z}else{signed(a,w)<signed(z,w)};let expected=if less==minimum{a}else{z};
   let(out,t)=run(word,&s);assert_eq!(out.nzcv,s.nzcv);assert_eq!(t.registers.len(),usize::from(d!=31));
   for reg in 0..31{assert_eq!(out.x[reg],if reg==d as usize{expected}else{s.x[reg]},"{word:08x} {a:x} {z:x}");}
  }}}}
 }}
}
#[test]fn unrelated_scalar_system_vector_and_reserved_adjacent_encodings_are_not_claimed(){
 for word in [0xd500401f,0xd500403f,0xd500405f,0xd503201f,0x3a400000,0x7a400800,0x5ac00000,0x5ac01000,0x4e20b820,0x1ac00000,0x1ac00800,0x11d00000,0x5ac02400,0xba000410,0x3a00080c,0x7ac04000]{assert!(arm64_misc::a64(word,0).is_none(),"{word:08x}");}
}
#[test]fn primary_june_xml_encodings_execute_and_keep_unwritten_state(){
 for &(word,name)in MISC_CORPUS{let s=initial();let(out,t)=run(word,&s);
  match name{"rmif"=>{let flags=get(&s,(word>>5)&31,64).rotate_right((word>>15)&63)as u8;let selected=(word&15)as u8;assert_eq!(out.nzcv,(s.nzcv&!selected)|(flags&selected));assert_eq!(out.x,s.x);},
   "setf"=>{assert_eq!(out.x,s.x);assert_eq!(out.nzcv&2,s.nzcv&2);},
   _=>{assert_eq!(out.nzcv,s.nzcv);assert!(t.registers.iter().all(|r|r.register.bank=="a64.gpr"));let d=word&31;
    for reg in 0..31{if reg!=d as usize{assert_eq!(out.x[reg],s.x[reg]);}}
   },
  }
 }
}
`

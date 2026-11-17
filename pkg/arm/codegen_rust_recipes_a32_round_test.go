package arm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the public decoder and evaluator against every VFP register-list
// encoding, with transfer oracles independent of the generated recipe.
func TestRustA32ScalarRoundingAndFixed(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32ScalarRoundingPrimary(t, path)
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "Documents/Developer/go-mkasm")
	if err = os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "a32-scalar-round-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "scalar.rs"), []byte(a32ScalarRoundingBehavior+primary), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "arm32", "--crate-type", "lib", "src/lib.rs", "-Dwarnings", "-o", "libarm32.rlib"},
		{"--edition=2021", "--test", "scalar.rs", "--extern", "arm32=libarm32.rlib", "-Dwarnings", "-Copt-level=1", "-o", "scalar-tests"},
		{"./scalar-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated A32 IEEE scalar %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a32ScalarRoundingPrimary(t *testing.T, path string) string {
	t.Helper()
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
	}
	type class struct {
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	apply := func(word uint32, boxes []box) uint32 {
		for _, b := range boxes {
			pos := b.Hi
			for _, c := range b.Cells {
				span := c.Span
				if span == 0 {
					span = 1
				}
				bits := strings.NewReplacer("(", "", ")", "").Replace(strings.TrimSpace(c.Text))
				if len(bits) != span {
					bits = strings.Repeat("x", span)
				}
				for _, bit := range bits {
					if bit == '0' || bit == '1' {
						word &^= 1 << uint(pos)
						word |= uint32(bit-'0') << uint(pos)
					}
					pos--
				}
			}
		}
		return word
	}
	wanted := map[string]bool{}
	for _, n := range strings.Fields("vrinta_vfp vrintn_vfp vrintm_vfp vrintp_vfp vrintr_vfp vrintx_vfp vrintz_vfp vcvta_vfp vcvtn_vfp vcvtm_vfp vcvtp_vfp vmaxnm vminnm vsel vcvt_xv") {
		wanted[n+".xml"] = true
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out strings.Builder
	out.WriteString("#[test]fn primary_scalar_encoding_identities(){for(word,thumb,id)in[\n")
	classes, ids := 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/")
		if !wanted[name] {
			continue
		}
		delete(wanted, name)
		var p page
		if err = xml.NewDecoder(tr).Decode(&p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			scalar := false
			for _, b := range cl.Diagram.Boxes {
				if (b.Name == "size" || b.Name == "sf") && b.Hi == 9 {
					scalar = true
				}
			}
			if !scalar {
				continue
			}
			classes++
			for _, e := range cl.Encodings {
				word := apply(0, cl.Diagram.Boxes)
				if cl.ISA == "A32" {
					word |= 14 << 28
				}
				word = apply(word, e.Boxes)
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", e.Name)
				ids++
			}
		}
	}
	if len(wanted) != 0 || classes != 30 || ids != 114 {
		t.Fatalf("scalar primary coverage missing=%v classes=%d ids=%d", wanted, classes, ids)
	}
	out.WriteString("]{let d=decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,\"{id} {word:08x}\");r.validate().unwrap();}}\n")
	t.Logf("qualified 15 primary pages, %d scalar classes, %d encoding identities", classes, ids)
	return out.String()
}

const a32ScalarRoundingBehavior = `use arm32::{decode,Decoded,Mode,Endian as CodeEndian};
use arm32::semantics::*;
use std::cell::RefCell;
fn bytes(w:u32,t:bool,e:CodeEndian)->Vec<u8>{if t{[(w>>16)as u16,w as u16].into_iter().flat_map(|h|match e{CodeEndian::Little=>h.to_le_bytes(),CodeEndian::Big=>h.to_be_bytes()}).collect()}else{match e{CodeEndian::Little=>w.to_le_bytes(),CodeEndian::Big=>w.to_be_bytes()}.to_vec()}}
fn decoded(w:u32,t:bool,e:CodeEndian)->Decoded{decode(&bytes(w,t,e),if t{Mode::Thumb}else{Mode::Arm},e).unwrap_or_else(|x|panic!("{w:08x}/{t}: {x:?}"))}
struct State{fpscr:u32,it:u8,flags:u8,unavailable:Option<u16>,calls:RefCell<Vec<(FloatOperation,u8,Vec<Value>,u64)>>,reads:RefCell<Vec<u16>>}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{match r.bank{
 "a32.vector64"=>{self.reads.borrow_mut().push(r.index);if self.unavailable==Some(r.index){Value::unknown(64)}else{Value::known(64,0xdeadbeef12345600|u64::from(r.index))}},
 "a32.fpscr"=>Value::known(32,u64::from(self.fpscr)),"a32.itstate"=>Value::known(8,u64::from(self.it)),"a32.nzcv"=>Value::known(1,u64::from((self.flags>>r.index)&1)),_=>panic!("{r:?}")}}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("scalar FP touches memory")}
 fn evaluate_float(&self,f:&FloatExpression,values:&[Value],control:Value,status:Value)->Result<Value,EvalError>{assert_eq!(f.environment,FloatEnvironment::A32Vfp);assert_eq!(status.bits,u64::from(self.fpscr));self.calls.borrow_mut().push((f.operation,f.width,values.to_vec(),control.bits));Ok(match f.projection{FloatProjection::Value=>Value::known(f.width,0x3555),FloatProjection::Status=>Value::known(32,status.bits),FloatProjection::Trapped=>Value::known(1,0)})}
}
fn state()->State{State{fpscr:3<<22,it:0,flags:0,unavailable:None,calls:RefCell::new(vec![]),reads:RefCell::new(vec![])}}
fn reg(t:&Transition,n:u16)->u64{t.registers.iter().rev().find(|r|r.register.bank=="a32.vector64"&&r.register.index==n).unwrap().value.bits}
#[test]fn all_rounding_modes_precisions_and_integer_signedness_reach_exact_operations(){
 for thumb in[false,true]{for code in[CodeEndian::Little,CodeEndian::Big]{for size in 1..4 {let width=8<<size;for rm in 0..4 {let rounding=match rm{0=>FloatRounding::NearestAway,1=>FloatRounding::NearestEven,2=>FloatRounding::PositiveInfinity,_=>FloatRounding::NegativeInfinity};
  for integer in[false,true]{for signed in[false,true]{let w=if integer{0xfebc0840|((signed as u32)<<7)}else{0xfeb80840}|(rm<<16)|(size<<8)|2;let r=decoded(w,thumb,code).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();let s=state();let t=evaluate(&r,&s).unwrap();let op=if integer{FloatOperation::ToInteger{source_width:width,signed,fractional_bits:0,rounding}}else{FloatOperation::RoundToIntegral{rounding,exact:false}};assert!(s.calls.borrow().iter().all(|(o,w,_,c)|*o==op&&*w==(if integer{32}else{width})&&*c==u64::from(s.fpscr)),"{w:08x} expected {op:?}/{width}, got {:?}",s.calls.borrow());assert_eq!(t.trap,None);}}
 }
 for(base,rounding,exact)in[(0xeeb60840,FloatRounding::Environment,false),(0xeeb608c0,FloatRounding::Zero,false),(0xeeb70840,FloatRounding::Environment,true)]{let w=base|(size<<8)|2;let r=decoded(w,thumb,code).semantic_recipe(0x1000);let s=state();evaluate(&r,&s).unwrap();assert!(s.calls.borrow().iter().all(|(o,_,_,_)|*o==FloatOperation::RoundToIntegral{rounding,exact}));}
 }}}
}
#[test]fn fixed_point_all_scales_integer_sizes_d_and_s_registers_and_control_override(){
 for thumb in[false,true]{for size in 1..4{let width=8<<size;for int32 in[false,true]{let iw=if int32{32}else{16};for encoded in 0..=31 {if encoded>iw{continue}for unsigned in[false,true]{for to in[false,true]{for d in[0,1,15,31]{
  let (vd,dbit)=if width==64{(d&15,d>>4)}else{(d>>1,d&1)};let w=0xeeba0840|(size<<8)|((int32 as u32)<<7)|((to as u32)<<18)|((unsigned as u32)<<16)|(vd<<12)|(dbit<<22)|(encoded>>1)|((encoded&1)<<5);
  let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{w:08x}");r.validate().unwrap();let s=state();let t=evaluate(&r,&s).unwrap();assert_eq!(t.trap,None);let op=if to{FloatOperation::ToInteger{source_width:width,signed:!unsigned,fractional_bits:(iw-encoded)as u8,rounding:FloatRounding::Zero}}else{FloatOperation::FromInteger{source_width:iw as u8,signed:!unsigned,fractional_bits:(iw-encoded)as u8}};
  for(o,result,values,control)in s.calls.borrow().iter(){assert_eq!(*o,op);assert_eq!(*result,if to{iw as u8}else{width});assert_eq!(values[0].width,if to{width}else{iw as u8});assert_eq!(*control,if to{u64::from(s.fpscr)}else{0});}
 }}}}}}}
}
#[test]fn selection_uses_integer_flags_all_conditions_preserves_nan_bits_and_reads_only_selected_input(){
 for thumb in[false,true]{for size in 1..4{let width=8<<size;for cc in 0..4{for flags in 0..16{let n=(flags&1)!=0;let z=(flags&2)!=0;let v=(flags&8)!=0;let selected=match cc{0=>z,1=>v,2=>n==v,_=>!z&&n==v};let w=0xfe000800|(cc<<20)|(size<<8)|0x13002;
  let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();let mut s=state();s.flags=flags;s.fpscr=0xffffffff;s.unavailable=Some(if selected{2}else{1});let t=evaluate(&r,&s).unwrap();assert!(s.calls.borrow().is_empty());assert!(t.registers.iter().all(|r|r.register.bank!="a32.fpscr"));let source=if selected{1u16}else{2u16};let bits=0xdeadbeef12345600|u64::from(source);assert_eq!(reg(&t,3),match width{16=>0xdeadbeef00000000|(bits&0xffff),32=>0xdeadbeef00000000|(bits&0xffffffff),_=>bits});
 }}}}
}
#[test]fn unconditional_forms_reject_it_even_when_predicate_false_and_current_forms_skip_inputs(){
 for w in[0xfeb80942,0xfebc09c2,0xfe810902,0xfe010902]{let r=decoded(w,true,CodeEndian::Little).semantic_recipe(0x1000);let mut s=state();s.it=8;s.flags=0;assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.calls.borrow().is_empty()&&s.reads.borrow().is_empty());}
 let r=decoded(0x0eb60a42,false,CodeEndian::Little).semantic_recipe(0x1000);let s=state();let t=evaluate(&r,&s).unwrap();assert!(t.registers.is_empty()&&s.calls.borrow().is_empty()&&s.reads.borrow().is_empty());
}
`

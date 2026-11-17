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
func TestRustA32IeeeScalarArithmetic(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32IeeeScalarPrimary(t, path)
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
	dir, err := os.MkdirTemp(base, "a32-ieee-scalar-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "scalar.rs"), []byte(a32IeeeScalarBehavior+primary), 0644); err != nil {
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

func a32IeeeScalarPrimary(t *testing.T, path string) string {
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
	for _, n := range strings.Fields("vadd_f vsub_f vmul_f vdiv vsqrt vmla_f vmls_f vnmla vnmls vnmul vfma vfms vfnma vfnms vcmp vcmpe vcvt_vi vcvt_iv vcvtr_iv vabs vneg") {
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
				if b.Name == "size" && b.Hi == 9 {
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
	if len(wanted) != 0 || classes != 46 || ids != 150 {
		t.Fatalf("scalar primary coverage missing=%v classes=%d ids=%d", wanted, classes, ids)
	}
	out.WriteString("]{let d=decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,\"{id} {word:08x}\");r.validate().unwrap();}}\n")
	t.Logf("qualified 21 primary pages, %d scalar classes, %d encoding identities", classes, ids)
	return out.String()
}

const a32IeeeScalarBehavior = `use arm32::{decode,Decoded,Mode,Endian as CodeEndian};
use arm32::semantics::*;
use std::cell::RefCell;
fn bytes(w:u32,t:bool,e:CodeEndian)->Vec<u8>{if t{[(w>>16)as u16,w as u16].into_iter().flat_map(|h|match e{CodeEndian::Little=>h.to_le_bytes(),CodeEndian::Big=>h.to_be_bytes()}).collect()}else{match e{CodeEndian::Little=>w.to_le_bytes(),CodeEndian::Big=>w.to_be_bytes()}.to_vec()}}
fn decoded(w:u32,t:bool,e:CodeEndian)->Decoded{decode(&bytes(w,t,e),if t{Mode::Thumb}else{Mode::Arm},e).unwrap_or_else(|x|panic!("{w:08x}/{t}: {x:?}"))}
struct State{fpscr:u32,it:u8,trap:bool,calls:RefCell<Vec<(FloatOperation,u8,Vec<u64>)>>}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{match r.bank{"a32.gpr"=>Value::known(32,0x2000),"a32.vector64"=>Value::known(64,0xdeadbeefa5a50000|u64::from(r.index+1)),"a32.fpscr"=>Value::known(32,u64::from(self.fpscr)),"a32.itstate"=>Value::known(8,u64::from(self.it)),"a32.nzcv"=>Value::known(1,1),_=>panic!("{r:?}")}}
 fn read_memory(&self,_:u64,w:u8,_:Endian)->Result<Value,EvalError>{assert_eq!(w,16);Ok(Value::known(16,0x7c01))}
 fn evaluate_float(&self,f:&FloatExpression,values:&[Value],control:Value,status:Value)->Result<Value,EvalError>{assert_eq!(f.environment,FloatEnvironment::A32Vfp);assert_eq!(control.bits,u64::from(self.fpscr));assert_eq!(status.width,32);self.calls.borrow_mut().push((f.operation,f.width,values.iter().map(|v|v.bits).collect()));Ok(match f.projection{FloatProjection::Value=>Value::known(f.width,if f.width==4{6}else{0x3555}),FloatProjection::Status=>Value::known(32,u64::from(self.fpscr)|1),FloatProjection::Trapped=>Value::known(1,u64::from(self.trap))})}
}
fn state()->State{State{fpscr:0xa4000000,it:0,trap:false,calls:RefCell::new(vec![])}}
fn bits(t:&Transition,bank:&str,n:u16)->u64{t.registers.iter().rev().find(|r|r.register.bank==bank&&r.register.index==n).unwrap().value.bits}
#[test]fn half_arithmetic_all_operations_register_aliases_and_projections(){
 for thumb in[false,true]{for code in[CodeEndian::Little,CodeEndian::Big]{for(base,operation)in[(0xee300900,FloatOperation::Add),(0xee300940,FloatOperation::Subtract),(0xee200900,FloatOperation::Multiply),(0xee800900,FloatOperation::Divide),(0xeea00900,FloatOperation::FusedMultiplyAdd{negate_product:false,negate_addend:false}),(0xeea00940,FloatOperation::FusedMultiplyAdd{negate_product:true,negate_addend:false}),(0xee900900,FloatOperation::FusedMultiplyAdd{negate_product:false,negate_addend:true}),(0xee900940,FloatOperation::FusedMultiplyAdd{negate_product:true,negate_addend:true})]{for d in[0,1,15,30,31]{for n in[0,1,15,30,31]{for m in[0,1,15,30,31]{
  let w=base|((d>>1)<<12)|((d&1)<<22)|((n>>1)<<16)|((n&1)<<7)|(m>>1)|((m&1)<<5);let r=decoded(w,thumb,code).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();let s=state();let t=evaluate(&r,&s).unwrap();assert_eq!(bits(&t,"a32.vector64",(d/2)as u16),if d&1==0{0xdeadbeef00003555}else{0x00003555a5a50000|u64::from(d/2+1)});assert!(s.calls.borrow().iter().all(|(o,w,_)|*o==operation&&*w==16));assert_eq!(bits(&t,"a32.fpscr",0),u64::from(s.fpscr)|1);
 }}}}}}
}
#[test]fn half_traps_preserve_destination_and_comparison_flags_but_commit_status(){
 for thumb in[false,true]{for w in[0xee310902,0xee010902,0xee010942,0xee110902,0xee110942,0xee210942,0xeea10902,0xeeb109c2,0xeeb40942,0xeeb409c2,0xeeb50940,0xeeb509c0,0xeeb809c2,0xeebd09c2]{let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{w:08x}");r.validate().unwrap();let mut s=state();s.trap=true;let t=evaluate(&r,&s).unwrap();assert_eq!(t.trap,Some(TrapKind::FloatingPoint),"{w:08x}");assert!(t.registers.iter().all(|v|v.register.bank=="a32.fpscr"));assert_eq!(bits(&t,"a32.fpscr",0),u64::from(s.fpscr)|1);}}
}
#[test]fn h_setter_clears_s_upper_half_preserves_neighbor_and_transports_do_not_touch_fpscr(){
 for thumb in[false,true]{for(w,want)in[(0xeeb009e0,0xdeadbeef00003eef),(0xeeb10960,0xdeadbeef00003eef),(0xed910901,0xdeadbeef00007c01)]{let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);let s=state();let t=evaluate(&r,&s).unwrap();assert_eq!(bits(&t,"a32.vector64",0),want);assert!(s.calls.borrow().is_empty());assert!(t.registers.iter().all(|r|r.register.bank!="a32.fpscr"));}}
}
#[test]fn half_context_and_nonzero_legacy_vector_mode_reject_before_fp(){
 for w in[0xee310902,0xee010902,0xeea10902,0xeeb109c2]{for thumb in[false,true]{let r=decoded(w,thumb,CodeEndian::Little).semantic_recipe(0x1000);for bits in[1<<16,1<<20]{let mut s=state();s.fpscr|=bits;assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.calls.borrow().is_empty());}if thumb{let mut s=state();s.it=8;assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.calls.borrow().is_empty());}}}
 // Comparison remains scalar even with LEN/STRIDE set.
 let r=decoded(0xeeb40942,false,CodeEndian::Little).semantic_recipe(0x1000);let mut s=state();s.fpscr|=1<<16|1<<20;let t=evaluate(&r,&s).unwrap();assert_eq!(bits(&t,"a32.fpscr",0)>>28,6);
}
`

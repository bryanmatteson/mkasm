package arm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/semantics"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

func runA64RecipeExpansionTests(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "expansion.rs"), []byte(a64RecipeExpansionTests+a64ScalarRegisterConversionTests+a64CompareBranchTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "expansion", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated A64 recipe expansion: %v\n%s", err, output)
	}
}

// Portable generation uses real assembled words plus exact ordinary encoding
// classes for the exhaustive bitfield and conditional-compare property checks.
// The companion corpus test decodes the same words through the entire Arm XML.
func TestRustA64RecipeExpansion(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	words := []uint32{
		0x25034440, 0x25434440, 0x25834440, 0x25034450, 0x25034640, 0x25834450, 0x25834650, 0x25834640, 0x25034650, 0x2550c440, 0x25a08440, 0xa5a0a020, 0xa500a020, 0xa480a020, 0xe4c24020, 0xe5624020,
		0x2518e3e0, 0x2598e061, 0x25d9e3e2, 0x2518e403, 0x0420e3e0, 0x04a2e3e1, 0x25a21420, 0x25220c20, 0x25621020, 0x04a343c0, 0x04e24c20, 0x04220020, 0x04e20420, 0x04800020, 0x04430020, 0x04d00020, 0x041b0020, 0x04223020, 0x05a2c020, 0x2482a420, 0x24c28430, 0x04609420, 0x04038260, 0x04d08020, 0xa440a020, 0xa4cfa020, 0xa5424020, 0xa5e0a3e0, 0xe440e020, 0xe561e020, 0xe5e24020, 0xa41f6020, 0x85224020,
		0x6cc10820, 0x2c010820, 0xf9400020,
		0x5ea1d820, 0x6ea1d820, 0x5ee1f820, 0x4e22fc20, 0x4ee2fc20,
		0x4e421c20, 0x6fb29820, 0x5ef9d820, 0x7ee1d820, 0x5e22dc20,
		0x1e634020, 0x0ea16820, 0x4ea16820, 0x6e42fc20, 0x0f72f820,
		0x4e22e420, 0x6e62e420, 0x6ec22420, 0x6e22ec20, 0x6ea2ec20, 0x4ea0d820,
		0x6ea0c820, 0x4ea0c820, 0x6ea0d820, 0x4ea0e820, 0x7e22e420, 0x5ea0d820,
		0x4e21d820, 0x6e61d820, 0x4ea1b820, 0x6ef9b820, 0x4e21a820, 0x4e21c820,
		0x4ea1a820, 0x4e21b820, 0x4f38e420, 0x6f38fc20, 0x5e21d820, 0x5ea1b820,
		0x4e218820, 0x4ea18820, 0x4e219820, 0x4ea19820, 0x6e218820, 0x6e219820,
		0x6ea19820, 0x0e217820, 0x4e617820, 0x0e216820, 0x4e616820, 0x2e616820,
		0x6e616820, 0x7e616820, 0x4fb29820, 0x4fd21820, 0x4f325820, 0x5f829820,
		0x5f121820, 0x7e30d820, 0x7e70f820, 0x5eb0c820, 0x6e22d420, 0x6e62f420,
		0x6ec20420, 0x6e30f820, 0x4eb0c820, 0xbd400c20, 0xfc010c20, 0x3cc10420,
		0x7c5fe020, 0x3c224820, 0x3ce27820, 0x5c0000e0, 0xacc10820, 0x6dbf0820,
		0x2c410820, 0xac010820, 0xad400020, 0x3cc10421, 0xd503201f,
		0xdac00020, 0x5ac00020, 0xdac00420, 0xdac00820, 0xdac00c20, 0x5ac00820,
		0xdac01020, 0x5ac01020, 0xdac01420, 0x5ac01420,
		0x9b020020, 0x9b028020, 0x1b020020, 0x1b028020, 0x9b220020, 0x9b228020,
		0x9ba20020, 0x9ba28020, 0x9b427c20, 0x9bc27c20, 0x9ac20820, 0x9ac20c20,
		0x1ac20820, 0x1ac20c20, 0x93c21020, 0x13821020,
		0xa9bf0820, 0xa8c10820, 0x697f0820, 0x28010820, 0x28410820,
		0xb81fc820, 0x389fc820, 0xa9bf0400, 0xa9ff0400, 0xa9400020,
		0x4e221c20, 0x0e621c20, 0x4ea21c20, 0x4ee21c20, 0x6e221c20,
		0x6e621c20, 0x6ea21c20, 0x6ee21c20, 0x2e205820,
		0x6e20b820, 0x6e60b820, 0x6ea0b820, 0x6ee0b820, 0x7ee0b820,
		0x6e228c20, 0x4e223420, 0x4e223c20, 0x6ee23420, 0x6ee23c20,
		0x14000001, 0xd63f03c0, 0xd65f03c0, 0x54000040,
		0x1e222820, 0x1e623820, 0x1ee20820, 0x1e221820, 0x1e61c020,
		0x4e22d420, 0x4ee2d420, 0x6e421c20, 0x2e22fc20, 0x6ea1f820, 0x2ef9f820,
		0x6e22fc20, 0x1e204020, 0x1ee04020, 0x1e6e1000, 0x1e301000,
		0x1e260020, 0x1e270020, 0x9e660020, 0x9e670020, 0x9eae0020, 0x9eaf0020,
		0x1ee60020, 0x1ee70020, 0x1e20c020, 0x1e614020, 0x1e220c20,
		0x1f020c20, 0x1f028c20, 0x1f220c20, 0x1f228c20, 0x1e222020, 0x1e602038,
		0x1e220425, 0x1e220435, 0x1e22c020, 0x1e63c020, 0x1e220020, 0x9e630020,
		0x1e02e020, 0x9e780020, 0x1e19e020, 0x1e200020, 0x1e240020, 0x1e280020,
		0x1e300020, 0x1e244020, 0x1e24c020, 0x1e254020, 0x1e25c020, 0x1e264020,
		0x1e274020, 0x1e27c020, 0x1e224820, 0x1e627820, 0x4e22cc20, 0x4ee2cc20,
		0x4e22f420, 0x4ec20420, 0x1ea22820,
		0x91910b1a, 0xd1910b1a, 0xdac10020, 0xc85f7c20, 0xc8dffc20,
		0xf8200020, 0xf8200420, 0xd4000001, 0x1e222820, 0x4e208400,
	}
	for _, ftype := range []uint32{0, 1, 3} {
		words = append(words, 0x1e228820|ftype<<22)
		for _, sf := range []uint32{0, 1} {
			if (sf == 0 && ftype == 0) || (sf == 1 && ftype == 1) {
				continue
			}
			for _, operation := range []uint32{0x1e2a0000, 0x1e2b0000, 0x1e320000, 0x1e330000, 0x1e340000, 0x1e350000, 0x1e360000, 0x1e370000, 0x1e3a0000, 0x1e3b0000, 0x1e3c0000, 0x1e3d0000} {
				words = append(words, operation|sf<<31|ftype<<22|1<<5)
			}
		}
	}
	c := &Catalog{}
	for _, shape := range []struct{ mask, value uint32 }{{0x7f00c000, 0x74000000}, {0xff008000, 0x74008000}, {0x7f004000, 0x75000000}, {0xff000010, 0x54000010}, {0xffc00000, 0xf9800000}, {0xff000000, 0xd8000000}, {0xffe04c00, 0xf8a04800}, {0xffe00c00, 0xf8800000}} {
		c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("compare_branch_%08x", shape.value), Mnemonic: "fixture", Mask: shape.mask, Value: shape.value})
	}
	seen := map[uint32]bool{}
	for _, word := range words {
		for _, word := range []uint32{word, word | 1} {
			if seen[word] {
				continue
			}
			seen[word] = true
			c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("word_%08x", word), Mnemonic: "fixture", Mask: 0xffffffff, Value: word})
		}
	}
	for sf := uint32(0); sf < 2; sf++ {
		for opc := uint32(0); opc < 3; opc++ {
			c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("bitfield_%d_%d", sf, opc), Mnemonic: "fixture", Mask: 0xffc00000, Value: 0x13000000 | sf<<31 | sf<<22 | opc<<29})
		}
		for sub := uint32(0); sub < 2; sub++ {
			for imm := uint32(0); imm < 2; imm++ {
				c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("condcmp_%d_%d_%d", sf, sub, imm), Mnemonic: "fixture", Mask: 0xffe00c10, Value: 0x3a400000 | sf<<31 | sub<<30 | imm<<11})
			}
		}
	}
	for _, ftype := range []uint32{0, 1, 3} {
		c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("fmov_imm_%d", ftype), Mnemonic: "fixture", Mask: 0xff201fe0 | 3<<22, Value: 0x1e201000 | ftype<<22})
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0755); err != nil {
		t.Fatal(err)
	}
	data, err := buildRustDecoderData(c)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("rust").ParseFS(assettemplates.FS, "rust/decoders.rs.tmpl", "rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"decoders", "recipes"} {
		var value any
		if name == "decoders" {
			value = data
		}
		if err := execTmplWrite(tmpl, name+".rs.tmpl", filepath.Join(src, name+".rs"), value); err != nil {
			t.Fatal(err)
		}
	}
	if err := semantics.WriteRust(src); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"Cargo.toml": "[package]\nname=\"aarch64\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
		"src/lib.rs": "#![allow(dead_code)]\npub mod decoders;pub mod semantics;pub mod recipes;pub use decoders::{decode,Decoded};\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runA64RecipeExpansionTests(t, dir)
}

func TestRustA64RecipeExpansionCorpus(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		t.Skip("set MKASM_A64_RECIPES_CORPUS to the real Arm A64 XML archive")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := NewARMParser(ARMParserConfig{EncodingIndexPath: ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: ArchAArch64, Languages: []CodegenLang{LangRust}})
	defer func() {
		if err := parser.Close(5 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	runA64RecipeExpansionTests(t, dir)
}

const a64RecipeExpansionTests = `use aarch64::*;
use aarch64::semantics::*;
use std::collections::HashMap;
#[derive(Default)]struct State{regs:HashMap<Register,u64>,mem:HashMap<u64,u64>,wide_reads:std::cell::RefCell<Vec<(u64,u16,Endian)>>}
impl State {
 fn reg(&mut self,bank:&'static str,index:u16,v:u64){self.regs.insert(Register{bank,index},v);}
 fn x(&mut self,index:u16,v:u64){self.reg("a64.gpr",index,v)}
 fn v(&mut self,index:u16,lo:u64,hi:u64){self.reg("a64.vector64",index*32,lo);self.reg("a64.vector64",index*32+1,hi)}
 fn flags(&mut self,bits:u8){for i in 0..4{self.reg("a64.nzcv",i,(bits>>(3-i)&1)as u64)}}
}
impl Machine for State {
 fn read_register(&self,r:Register)->Value{Value::known(64,*self.regs.get(&r).unwrap_or(&0))}
 fn read_memory(&self,a:u64,w:u8,_:Endian)->Result<Value,EvalError>{self.mem.get(&a).map(|v|Value::known(w,*v)).ok_or(EvalError::Memory)}
 fn read_wide_memory(&self,a:u64,w:u16,endian:Endian)->Result<Vec<Value>,EvalError>{self.wide_reads.borrow_mut().push((a,w,endian));assert!(w%64==0);(0..w/64).map(|chunk|{let offset=if endian==Endian::Little{chunk}else{w/64-1-chunk};self.mem.get(&a.wrapping_add(u64::from(offset)*8)).map(|v|Value::known(64,*v)).ok_or(EvalError::Memory)}).collect()}
}
fn run(word:u32,state:&State)->Transition{let d=decode(word).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{word:08x} {}",d.encoding_id);r.validate().unwrap();evaluate(&r,state).unwrap()}
fn reg(t:&Transition,bank:&str,index:u16)->u64{t.registers.iter().rev().find(|v|v.register.bank==bank&&v.register.index==index).unwrap().value.bits}
fn x(t:&Transition,index:u16)->u64{reg(t,"a64.gpr",index)}
fn v(t:&Transition,index:u16,chunk:u16)->u64{reg(t,"a64.vector64",index*32+chunk)}
fn noflags(t:&Transition){assert!(t.registers.iter().all(|r|r.register.bank!="a64.nzcv"))}
fn sext(v:u64,w:u8)->i128{((v<<(64-w))as i64>>(64-w))as i128}
fn rotate(v:u64,n:u32,w:u8)->u64{let v=v&mask(w);if n==0{v}else{((v>>n)|(v<<(w as u32-n)))&mask(w)}}
#[test]fn bitfields_all_encodings_and_aliases(){
 let mut s=State::default();let source=0x89abcdef76543210u64;let old=0xa55aa55af00ff00fu64;s.x(1,source);s.x(0,old);
 for w in [32u8,64] {for opc in 0..3u32 {for r in 0..w as u32 {for top in 0..w as u32 {
  let word=0x13000000|((w==64)as u32)<<31|((w==64)as u32)<<22|opc<<29|r<<16|top<<10|1<<5;
  let wm=rotate(mask((top+1)as u8),r,w);let tm=mask((((top+w as u32-r)&(w as u32-1))+1)as u8);
  let rotated=rotate(source,r,w);let bot=rotated&wm;
  let expected=match opc {0=>((if source&(1<<top)!=0{mask(w)}else{0})&!tm)|(bot&tm),1=>{let b=(old&!wm)|bot;(old&!tm)|(b&tm)},_=>bot&tm}&mask(w);
  let t=run(word,&s);assert_eq!(x(&t,0),expected,"{word:08x}");noflags(&t);
 }}}}
 // BFI reads the incoming destination even when it is also its source.
 s.x(0,0x0123456789abcdef);let word=0xb3400000|60<<16|7<<10;
 assert_eq!(x(&run(word,&s),0),0x0123456789abceff);
}
#[test]fn unary_bits_extract_and_zero_upper(){
 let mut s=State::default();for value in [0,1,u64::MAX,0x8000000000000000,0x0123456789abcdef] {
  s.x(1,value);
  for (word,expected) in [(0xdac00020,value.reverse_bits()),(0x5ac00020,(value as u32).reverse_bits()as u64),(0xdac00c20,value.swap_bytes()),(0x5ac00820,(value as u32).swap_bytes()as u64),(0xdac01020,value.leading_zeros()as u64),(0x5ac01020,(value as u32).leading_zeros()as u64),(0xdac01420,(if value>>63==0{value}else{!value}).leading_zeros()as u64-1),(0x5ac01420,(if value as u32>>31==0{value as u32}else{!(value as u32)}).leading_zeros()as u64-1)] {
   let t=run(word,&s);assert_eq!(x(&t,0),expected,"{word:08x} {value:x}");noflags(&t);
  }
 }
 s.x(1,0x0123456789abcdef);assert_eq!(x(&run(0xdac00420,&s),0),0x23016745ab89efcd);assert_eq!(x(&run(0xdac00820,&s),0),0x67452301efcdab89);
 s.x(2,0xfedcba9876543210);assert_eq!(x(&run(0x93c21020,&s),0),0xffedcba987654321);assert_eq!(x(&run(0x13821020,&s),0),0xf7654321);
}
#[test]fn multiplication_division_extremes_and_aliasing(){
 let mut s=State::default();let mut seed=0x123456789abcdef0u64;
 let mut inputs=vec![(0,0),(u64::MAX,0),(u64::MAX,1),(u64::MAX,u64::MAX),(0x8000000000000000,u64::MAX),(0x80000000,0xffffffff)];
 for _ in 0..40{seed=seed.wrapping_mul(6364136223846793005).wrapping_add(1);let a=seed;seed=seed.wrapping_mul(6364136223846793005).wrapping_add(1);inputs.push((a,seed));}
 for (a,b) in inputs {s.x(0,17);s.x(1,a);s.x(2,b);
  for (word,expected) in [
   (0x9b020020,17u64.wrapping_add(a.wrapping_mul(b))),(0x9b028020,17u64.wrapping_sub(a.wrapping_mul(b))),
   (0x1b020020,17u32.wrapping_add((a as u32).wrapping_mul(b as u32))as u64),(0x1b028020,17u32.wrapping_sub((a as u32).wrapping_mul(b as u32))as u64),
   (0x9b220020,17u64.wrapping_add((sext(a,32)*sext(b,32))as u64)),(0x9b228020,17u64.wrapping_sub((sext(a,32)*sext(b,32))as u64)),
   (0x9ba20020,17u64.wrapping_add((a as u32 as u64)*(b as u32 as u64))),(0x9ba28020,17u64.wrapping_sub((a as u32 as u64)*(b as u32 as u64))),
   (0x9b427c20,((sext(a,64)*sext(b,64))>>64)as u64),(0x9bc27c20,(((a as u128)*(b as u128))>>64)as u64),
   (0x9ac20820,if b==0{0}else{a/b}),(0x9ac20c20,if b==0{0}else{(sext(a,64)/sext(b,64))as u64}),
   (0x1ac20820,if b as u32==0{0}else{(a as u32/b as u32)as u64}),(0x1ac20c20,if b as u32==0{0}else{(sext(a,32)/sext(b,32))as u32 as u64}),
  ] {let t=run(word,&s);assert_eq!(x(&t,0),expected,"{word:08x} {a:x} {b:x}");noflags(&t);}
 }
}
fn condition_holds(c:u32,f:u8)->bool{let n=f&8!=0;let z=f&4!=0;let carry=f&2!=0;let v=f&1!=0;match c{0=>z,1=>!z,2=>carry,3=>!carry,4=>n,5=>!n,6=>v,7=>!v,8=>carry&&!z,9=>!carry||z,10=>n==v,11=>n!=v,12=>!z&&n==v,13=>z||n!=v,_=>true}}
#[test]fn conditional_compare_uses_old_flags_and_fallback(){
 let mut s=State::default();for w in [32u8,64] {for sub in [false,true] {for immediate in [false,true] {for condition in 0..16 {for old in 0..16 {
  let a=mask(w)>>1;let b=if immediate{2}else{1};s.x(1,a);s.x(2,b);s.flags(old);
  let word=0x3a400000|((w==64)as u32)<<31|(sub as u32)<<30|(immediate as u32)<<11|2<<16|condition<<12|1<<5|5;
  let expected=if condition_holds(condition,old){let result=if sub{a.wrapping_sub(b)}else{a.wrapping_add(b)}&mask(w);let n=result>>(w-1);let z=(result==0)as u64;let carry=if sub{(a>=b)as u64}else{((a as u128+b as u128)>mask(w)as u128)as u64};let signed=if sub{sext(a,w)-sext(b,w)}else{sext(a,w)+sext(b,w)};let overflow=(signed< -(1i128<<(w-1))||signed>((1i128<<(w-1))-1))as u64;[n,z,carry,overflow]}else{[0,1,0,1]};
  let t=run(word,&s);for i in 0..4{assert_eq!(reg(&t,"a64.nzcv",i),expected[i as usize],"{word:08x} flags{old:x}")};assert!(t.registers.iter().all(|r|r.register.bank=="a64.nzcv"));
 }}}}}
}
#[test]fn scalar_pairs_unprivileged_and_address_snapshots(){
 let mut s=State::default();s.x(0,0x1122334455667788);s.x(1,0x2000);s.x(2,0x8877665544332211);
 let t=run(0xa9bf0820,&s);assert_eq!(x(&t,1),0x1ff0);assert_eq!(t.memory.iter().map(|m|(m.address,m.value.bits)).collect::<Vec<_>>(),vec![(0x1ff0,0x1122334455667788),(0x1ff8,0x8877665544332211)]);
 s.mem.insert(0x2000,7);s.mem.insert(0x2008,9);let t=run(0xa8c10820,&s);assert_eq!((x(&t,0),x(&t,2),x(&t,1)),(7,9,0x2010));
 s.mem.insert(0x1ff8,0x80000000);s.mem.insert(0x1ffc,0xffffffff);let t=run(0x697f0820,&s);assert_eq!((x(&t,0),x(&t,2)),(0xffffffff80000000,u64::MAX));
 let t=run(0x28010820,&s);assert_eq!(t.memory.iter().map(|m|(m.address,m.value.bits,m.value.width)).collect::<Vec<_>>(),vec![(0x2008,0x55667788,32),(0x200c,0x44332211,32)]);
 s.mem.insert(0x2008,0x80000000);s.mem.insert(0x200c,0xffffffff);let t=run(0x28410820,&s);assert_eq!((x(&t,0),x(&t,2)),(0x80000000,0xffffffff));
 let t=run(0xb81fc820,&s);assert_eq!((t.memory[0].address,t.memory[0].value.bits),(0x1ffc,0x55667788));assert!(!t.registers.iter().any(|r|r.register.bank=="a64.gpr"&&r.register.index==1));s.mem.insert(0x1ffc,0x80);let t=run(0x389fc820,&s);assert_eq!(x(&t,0),0xffffffffffffff80);assert!(!t.registers.iter().any(|r|r.register.bank=="a64.gpr"&&r.register.index==1));
 for word in [0xa9bf0400,0xa9ff0400,0xa9400020]{let r=decode(word).unwrap().semantic_recipe(0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x} {:?}",r.support);assert!(r.effects.is_empty());}
}
#[test]fn integer_simd_chunk_aliases_and_upper_clear(){
 let mut s=State::default();let a=[0x0123456789abcdef,0xfedcba9876543210];let b=[0xa55aa55aa55aa55a,0x55aa55aa55aa55aa];let d=[0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f];s.v(1,a[0],a[1]);s.v(2,b[0],b[1]);s.v(0,d[0],d[1]);
 for (word,op) in [(0x4e221c20,0),(0x0e621c20,1),(0x4ea21c20,2),(0x4ee21c20,3),(0x6e221c20,4),(0x6e621c20,5),(0x6ea21c20,6),(0x6ee21c20,7)] {
  for alias in [false,true] {let dst=if alias{1}else{0};let t=run(word|dst,&s);for chunk in 0..2 {let old=if alias{a[chunk]}else{d[chunk]};let expected=if chunk==1&&word&(1<<30)==0{0}else{match op{0=>a[chunk]&b[chunk],1=>a[chunk]&!b[chunk],2=>a[chunk]|b[chunk],3=>a[chunk]|!b[chunk],4=>a[chunk]^b[chunk],5=>(old&a[chunk])|(!old&b[chunk]),6=>(old&!b[chunk])|(a[chunk]&b[chunk]),_=>(old&b[chunk])|(a[chunk]&!b[chunk])}};assert_eq!(v(&t,dst as u16,chunk as u16),expected,"{word:08x}");}noflags(&t);assert!(t.registers.iter().all(|r|r.register.bank=="a64.vector64"&&r.register.index%32<2));}
 }
 let t=run(0x2e205820,&s);assert_eq!(v(&t,0,0),!a[0]);assert_eq!(v(&t,0,1),0);
 for (word,bits) in [(0x6e20b820,8),(0x6e60b820,16),(0x6ea0b820,32),(0x6ee0b820,64),(0x7ee0b820,64)] {let t=run(word,&s);for chunk in 0..2{let mut expected=0;for lane in 0..64/bits{let raw=(a[chunk]>>(lane*bits))&mask(bits);expected|=(raw.wrapping_neg()&mask(bits))<<(lane*bits);}if word==0x7ee0b820&&chunk==1{expected=0;}assert_eq!(v(&t,0,chunk as u16),expected,"{word:08x}");}}
 for (word,op,bits) in [(0x6e228c20,0,8),(0x4e223420,1,8),(0x4e223c20,2,8),(0x6ee23420,3,64),(0x6ee23c20,4,64)] {let t=run(word,&s);for chunk in 0..2{let mut expected=0;for lane in 0..64/bits{let a=(a[chunk]>>(lane*bits))&mask(bits);let b=(b[chunk]>>(lane*bits))&mask(bits);let yes=match op{0=>a==b,1=>sext(a,bits)>sext(b,bits),2=>sext(a,bits)>=sext(b,bits),3=>a>b,_=>a>=b};if yes{expected|=mask(bits)<<(lane*bits);}}assert_eq!(v(&t,0,chunk as u16),expected);}}
}
#[test]fn control_snapshots_wrap_and_explicit_boundaries(){
 let mut s=State::default();s.x(30,0x3456);let t=run(0xd63f03c0,&s);assert_eq!(t.next_pc.bits,0x3456);assert_eq!(x(&t,30),0x1004);assert_eq!(run(0xd65f03c0,&s).next_pc.bits,0x3456);
 let r=decode(0x14000001).unwrap().semantic_recipe(u64::MAX-3);assert_eq!(evaluate(&r,&s).unwrap().next_pc.bits,0);
 for word in [0x91910b1a,0xd1910b1a,0xdac10020,0xf8200420]{let d=decode(word).unwrap();let r=d.semantic_recipe(0);assert_eq!(r.support,Support::Full,"{word:08x} {}",d.encoding_id);r.validate().unwrap();}
 s.x(24,0x2000);s.reg("a64.mte_enabled",0,0);assert_eq!(x(&run(0x91910b1a,&s),26),0x2110);assert_eq!(x(&run(0xd1910b1a,&s),26),0x1ef0);
 for word in [0xd4000001]{let r=decode(word).unwrap().semantic_recipe(0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x} {:?}",r.support);assert!(r.effects.is_empty());}
 s.v(0,0x00ff807fff01027f,0x0101010101010101);let t=run(0x4e208400,&s);assert_eq!(v(&t,0,0),0x00fe00fefe0204fe);assert_eq!(v(&t,0,1),0x0202020202020202);
 // Unallocated selectors cannot enter adjacent ordinary scalar families.
 for word in [0x13c21020,0x1ac00020,0x5ac00c20,0xf3400020,0x9b420020,0xba400410]{assert!(matches!(recipes::for_word(word,0).support,Support::Unsupported(_)),"{word:08x}");}
}

// This bounded test engine evaluates the numeric cases below under explicit
// controls. Production consumers supply their architectural software FP engine.
struct FloatState{state:State,calls:std::cell::Cell<usize>,trace:std::cell::RefCell<Vec<(FloatOperation,Vec<u64>)>>}
impl FloatState{fn new()->Self{Self{state:State::default(),calls:std::cell::Cell::new(0),trace:std::cell::RefCell::new(vec![])}}}
fn fp_number(bits:u64,w:u8)->f64{match w{64=>f64::from_bits(bits),32=>f32::from_bits(bits as u32)as f64,_=>{let sign=if bits&0x8000!=0{-1.0}else{1.0};let e=(bits>>10)&31;let f=bits&1023;if e==31{if f==0{sign*f64::INFINITY}else{f64::NAN}}else if e==0{sign*(f as f64)*2f64.powi(-24)}else{sign*(1.0+f as f64/1024.0)*2f64.powi(e as i32-15)}}}}
fn adjacent32(bits:u32,up:bool)->u32{if bits&0x7fffffff==0{if up{1}else{0x80000001}}else if (bits>>31==0)==up{bits+1}else{bits-1}}
fn fp_rounded(value:f64,rounding:FloatRounding,control:u64)->f64{
 let rounding=if rounding==FloatRounding::Environment{match (control>>22)&3{0=>FloatRounding::NearestEven,1=>FloatRounding::PositiveInfinity,2=>FloatRounding::NegativeInfinity,_=>FloatRounding::Zero}}else{rounding};
 match rounding{FloatRounding::NearestEven=>value.round_ties_even(),FloatRounding::NearestAway=>value.round(),FloatRounding::PositiveInfinity=>value.ceil(),FloatRounding::NegativeInfinity=>value.floor(),FloatRounding::Zero=>value.trunc(),FloatRounding::Environment=>unreachable!()}
}
fn fp_signaling(bits:u64,width:u8)->bool{let e=if width==16{5}else if width==32{8}else{11};let f=width-e-1;bits>>f&mask(e)==mask(e)&&bits&mask(f)!=0&&bits&(1<<(f-1))==0}
fn fp_project(f:&FloatExpression,bits:u64,flags:u64,control:Value,status:Value)->Value{
 let enabled=(control.bits>>8)&flags;match f.projection{FloatProjection::Value=>Value::known(f.width,bits),FloatProjection::Status=>Value::known(32,status.bits|(flags&!enabled)),FloatProjection::Trapped=>Value::known(1,(enabled!=0)as u64)}
}
fn estimate_normal(bits:u64,width:u8,sqrt:bool)->u64{
 let e=if width==16{5}else if width==32{8}else{11};let frac=width-e-1;let bias=(1u64<<(e-1))-1;let exp=(bits>>frac)&mask(e);let fraction=bits&mask(frac);assert!(exp>0&&exp<mask(e));let sign=bits&(1<<(width-1));if sqrt{assert_eq!(sign,0);}
 let estimate=if sqrt{let mut a=if exp&1==0{256+(fraction>>(frac-8))}else{128+(fraction>>(frac-7))};a=if a<256{a*2+1}else{((a>>1)*2+1)*2};let mut b=512;while a*(b+1)*(b+1)<1<<28{b+=1;}(b+1)/2}else{let a=256+(fraction>>(frac-8));(((1u64<<19)/(a*2+1))+1)/2};
 let result_exp=if sqrt{(3*bias-1-exp)/2}else{2*bias-1-exp};assert!(result_exp>0&&result_exp<mask(e));sign|(result_exp<<frac)|((estimate&255)<<(frac-8))
}
fn fp_numeric(f:&FloatExpression,input:&[Value],control:Value,status:Value)->Value{
 assert_eq!(f.environment,FloatEnvironment::A64);assert!(input.iter().all(|v|v.is_known()));assert!(control.is_known()&&status.is_known());
 if f.operation==FloatOperation::BFloatDotAdd{
  assert_eq!(status.bits,0,"BFDotAdd suppresses architectural FP status");let bf=|i:usize|f32::from_bits((input[i].bits as u32)<<16)as f64;let p0=bf(1)*bf(3);let p1=bf(2)*bf(4);let prod=p0+p1;let value=f32::from_bits(input[0].bits as u32)as f64+prod;for x in [p0,p1,prod,value]{assert!(x.is_finite()&&x as f32 as f64==x,"bounded exact BF16 reference");}return fp_project(f,(value as f32).to_bits()as u64,0,control,status);
 }
 let source_width=match f.operation{FloatOperation::Compare{source_width,..}|FloatOperation::Convert{source_width,..}|FloatOperation::ToInteger{source_width,..}|FloatOperation::FromInteger{source_width,..}=>source_width,FloatOperation::ToBFloat16=>32,_=>f.width};
 let a=fp_number(input[0].bits,source_width);let b=input.get(1).map(|v|fp_number(v.bits,source_width)).unwrap_or(0.0);
 if matches!(f.operation,FloatOperation::ReciprocalEstimate|FloatOperation::ReciprocalSquareRootEstimate|FloatOperation::ReciprocalExponent){assert_eq!(control.bits&0x04000003,0);let bits=if f.operation==FloatOperation::ReciprocalExponent{let e=if f.width==16{5}else if f.width==32{8}else{11};let frac=f.width-e-1;let exp=(input[0].bits>>frac)&mask(e);(input[0].bits&(1<<(f.width-1)))|((if exp==0{mask(e)-1}else{!exp&mask(e)})<<frac)}else{estimate_normal(input[0].bits,f.width,f.operation==FloatOperation::ReciprocalSquareRootEstimate)};return fp_project(f,bits,0,control,status);}
 if f.operation==FloatOperation::ToBFloat16{assert_eq!(control.bits&0x04000003,0);assert!(a.is_finite());let bits=input[0].bits as u32;let discarded=bits&0xffff;let mut top=bits>>16;let round=(control.bits>>22)&3;let increment=match round{0=>discarded>0x8000||(discarded==0x8000&&top&1!=0),1=>discarded!=0&&bits>>31==0,2=>discarded!=0&&bits>>31!=0,_=>false};if increment{top+=1;}return fp_project(f,top as u64,if discarded!=0{16}else{0},control,status);}
 if let FloatOperation::Compare{signal_all_nans,..}=f.operation{
  let nan=a.is_nan()||b.is_nan();let invalid=nan&&(signal_all_nans||input.iter().any(|v|fp_signaling(v.bits,source_width)));let flags=if nan{3}else if a==b{6}else if a<b{8}else{2};return fp_project(f,flags,invalid as u64,control,status);
 }
 if let FloatOperation::ToInteger{signed,fractional_bits,rounding,..}=f.operation{
  let scaled=a*2f64.powi(fractional_bits as i32);let rounded=fp_rounded(scaled,rounding,control.bits);assert!(rounded.is_finite());let limit=2f64.powi(if signed{f.width-1}else{f.width}as i32);assert!(rounded>=if signed{-limit}else{0.0}&&rounded<limit,"bounded reference integer range");let bits=if signed{rounded as i64 as u64}else{rounded as u64};return fp_project(f,bits,if rounded!=scaled{16}else{0},control,status);
 }
 let mut extra=0;
 let exact=match f.operation{
  FloatOperation::Add=>a+b,FloatOperation::Subtract=>a-b,FloatOperation::Multiply=>a*b,FloatOperation::Divide=>a/b,FloatOperation::SquareRoot=>a.sqrt(),
  FloatOperation::MultiplyExtended=>if (a.is_infinite()&&b==0.0)||(b.is_infinite()&&a==0.0){if a.is_sign_negative()^b.is_sign_negative(){-2.0}else{2.0}}else{a*b},
  FloatOperation::ReciprocalStep=>if (a.is_infinite()&&b==0.0)||(b.is_infinite()&&a==0.0){2.0}else{(-a).mul_add(b,2.0)},
  FloatOperation::ReciprocalSquareRootStep=>if (a.is_infinite()&&b==0.0)||(b.is_infinite()&&a==0.0){1.5}else{(-a).mul_add(b,3.0)*0.5},
  FloatOperation::FusedMultiplyAdd{negate_product,negate_addend}=>{let c=fp_number(input[2].bits,source_width);let addend=if negate_addend{-a}else{a};let multiplicand=if negate_product{-b}else{b};multiplicand.mul_add(c,addend)},
  FloatOperation::Convert{..}=>a,
  FloatOperation::FromInteger{source_width,signed,fractional_bits}=>{let n=if signed{sext(input[0].bits,source_width)as f64}else{input[0].bits as f64};n*2f64.powi(-(fractional_bits as i32))},
  FloatOperation::MinMax{minimum,numeric}=>{assert!(a.is_finite()&&b.is_finite(),"bounded reference min/max");let _=numeric;if minimum{a.min(b)}else{a.max(b)}},
  FloatOperation::RoundToIntegral{rounding,exact}=>{let rounded=fp_rounded(a,rounding,control.bits);if exact&&rounded!=a{extra=16;}rounded},
  _=>panic!("reference engine does not implement this typed FP operation")
 };
 let mut flags=extra|if input.iter().any(|v|fp_signaling(v.bits,source_width))||exact.is_nan()&&!a.is_nan()&&!b.is_nan(){1}else if f.operation==FloatOperation::Divide&&b==0.0&&a.is_finite()&&a!=0.0{2}else{0};
 let bits=if f.width==64{exact.to_bits()}else if f.width==32{
  let mut bits=(exact as f32).to_bits();let nearest=f32::from_bits(bits)as f64;let rounding=(control.bits>>22)&3;
  if matches!(f.operation,FloatOperation::Convert{round_to_odd:true,..}){if exact.is_finite()&&nearest!=exact{flags|=16;if nearest.abs()>exact.abs(){bits-=1;}bits|=1;}return fp_project(f,bits as u64,flags,control,status);}
  if exact.is_finite()&&nearest!=exact{flags|=16;let up=rounding==1||(rounding==3&&exact<0.0);let down=rounding==2||(rounding==3&&exact>0.0);if up&&nearest<exact{bits=adjacent32(bits,true)}else if down&&nearest>exact{bits=adjacent32(bits,false)}}bits as u64
 }else{
  // Half cases use exact finite normals; no host half arithmetic is involved.
  assert!(exact.is_finite());if exact==0.0{return fp_project(f,(exact.is_sign_negative()as u64)<<15,flags,control,status);}let sign=(exact<0.0)as u64;let e=exact.abs().log2().floor()as i32;let frac=((exact.abs()/2f64.powi(e)-1.0)*1024.0)as u64;assert_eq!(exact.abs(),(1.0+frac as f64/1024.0)*2f64.powi(e));sign<<15|((e+15)as u64)<<10|frac
 };
 fp_project(f,bits,flags,control,status)
}
impl Machine for FloatState{
 fn read_register(&self,r:Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.state.read_memory(a,w,e)}
 fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{self.calls.set(self.calls.get()+1);if f.projection==FloatProjection::Value{self.trace.borrow_mut().push((f.operation,inputs.iter().map(|v|v.bits).collect()));}Ok(fp_numeric(f,inputs,control,status))}
}
fn run_fp(word:u32,s:&FloatState)->Transition{let d=decode(word).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{word:08x} {}",d.encoding_id);r.validate().unwrap();evaluate(&r,s).unwrap()}
#[test]fn scalar_fp_numeric_controls_merge_and_traps(){
 let mut s=FloatState::new();let oldlow=0x1234567887654321;let oldhi=0xabcdef9876543210;s.state.v(0,oldlow,oldhi);s.state.v(1,0xdeadbeef3fc00000,0x13579bdf2468ace0);s.state.v(2,0x40100000,0);s.state.reg("a64.fpsr",0,0x08000000);
 let t=run_fp(0x1e222820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(3.75f32.to_bits()as u64,0));assert_eq!(reg(&t,"a64.fpsr",0),0x08000000);assert_eq!(t.trap,None);
 s.state.reg("a64.fpcr",0,4);let t=run_fp(0x1e222820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0xdeadbeef40700000,0x13579bdf2468ace0));
 s.state.v(1,9f64.to_bits(),0x1111222233334444);let t=run_fp(0x1e61c020,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(3f64.to_bits(),oldhi));
 s.state.v(1,7.5f64.to_bits(),0);s.state.v(2,2.5f64.to_bits(),0);assert_eq!(v(&run_fp(0x1e623820,&s),0,0),5f64.to_bits());
 s.state.v(1,0x3e00,0);s.state.v(2,0x4000,0);assert_eq!(v(&run_fp(0x1ee20820,&s),0,0)&0xffff,0x4200);
 // 1 + 2^-24 lies exactly halfway between two binary32 numbers.
 s.state.v(1,1f32.to_bits()as u64,0);s.state.v(2,2f32.powi(-24).to_bits()as u64,0);
 for (rounding,expected) in [(0,0x3f800000),(1,0x3f800001),(2,0x3f800000),(3,0x3f800000)]{s.state.reg("a64.fpcr",0,rounding<<22);let t=run_fp(0x1e222820,&s);assert_eq!(v(&t,0,0),expected);assert_eq!(reg(&t,"a64.fpsr",0),0x08000010);}
 s.state.v(2,0,0);s.state.reg("a64.fpcr",0,0);let t=run_fp(0x1e221820,&s);assert_eq!(v(&t,0,0),f32::INFINITY.to_bits()as u64);assert_eq!(reg(&t,"a64.fpsr",0),0x08000002);
 s.state.reg("a64.fpcr",0,1<<9);let t=run_fp(0x1e221820,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(reg(&t,"a64.fpsr",0),0x08000000);assert!(t.registers.iter().all(|r|r.register.bank!="a64.vector64"));
 let r=decode(0x1e222820).unwrap().semantic_recipe(0);assert!(matches!(&r.effects[0],Effect::WriteRegister{destination,..}if destination.register.bank=="a64.fpsr"));assert!(matches!(r.effects[1],Effect::Trap{kind:TrapKind::FloatingPoint,..}));
 for expression in &r.temporaries{if let ExprKind::Float(f)=&expression.kind{assert!(f.inputs.iter().all(|i|matches!(i.kind,ExprKind::Temporary(_))));assert!(matches!(f.control.kind,ExprKind::Temporary(_)));assert!(matches!(f.status.kind,ExprKind::Temporary(_)));}}
}
#[test]fn vector_fp_numeric_cumulative_status_and_late_lane_trap(){
 let mut s=FloatState::new();s.state.v(1,(2f32.to_bits()as u64)<<32|1f32.to_bits()as u64,(4f32.to_bits()as u64)<<32|3f32.to_bits()as u64);s.state.v(2,(6f32.to_bits()as u64)<<32|5f32.to_bits()as u64,(8f32.to_bits()as u64)<<32|7f32.to_bits()as u64);
 let t=run_fp(0x4e22d420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),((8f32.to_bits()as u64)<<32|6f32.to_bits()as u64,(12f32.to_bits()as u64)<<32|10f32.to_bits()as u64));
 s.state.v(1,9f64.to_bits(),16f64.to_bits());s.state.v(2,4f64.to_bits(),7f64.to_bits());let t=run_fp(0x4ee2d420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(5f64.to_bits(),9f64.to_bits()));
 s.state.v(1,0x40003e003c004400,0x3c0040003e004400);s.state.v(2,0x4000400040004000,0x4000400040004000);let t=run_fp(0x6e421c20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x4400420040004800,0x4000440042004800));
 s.state.v(1,(4f32.to_bits()as u64)<<32|1f32.to_bits()as u64,(16f32.to_bits()as u64)<<32|9f32.to_bits()as u64);let t=run_fp(0x6ea1f820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),((2f32.to_bits()as u64)<<32|1f32.to_bits()as u64,(4f32.to_bits()as u64)<<32|3f32.to_bits()as u64));
 s.state.v(1,0x44003c0044003c00,0);let t=run_fp(0x2ef9f820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x40003c0040003c00,0));
 // FDIV lane0 inexact, lane1 divide-by-zero, lane2 invalid. All are sticky.
 s.state.v(1,(1f32.to_bits()as u64)<<32|1f32.to_bits()as u64,0);s.state.v(2,3f32.to_bits()as u64,0);s.state.reg("a64.fpsr",0,0x08000000);
 let t=run_fp(0x6e22fc20,&s);assert_eq!(reg(&t,"a64.fpsr",0),0x08000013);assert_eq!(t.trap,None);
 // Enabled lane1 trap preserves preceding IXC, suppresses later IOC and every chunk.
 s.state.reg("a64.fpcr",0,1<<9);let t=run_fp(0x6e22fc20,&s);assert_eq!(reg(&t,"a64.fpsr",0),0x08000010);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|r|r.register.bank!="a64.vector64"));
 // Q=0 upper clear, including destination equal to its source.
 s.state.reg("a64.fpcr",0,0);s.state.v(1,(4f32.to_bits()as u64)<<32|2f32.to_bits()as u64,u64::MAX);s.state.v(2,(2f32.to_bits()as u64)<<32|2f32.to_bits()as u64,0);let t=run_fp(0x2e22fc21,&s);assert_eq!((v(&t,1,0),v(&t,1,1)),((2f32.to_bits()as u64)<<32|1f32.to_bits()as u64,0));
}
#[test]fn fp_bit_transport_never_rounds_or_changes_status(){
 let mut s=State::default();s.v(0,0x1122334455667788,0x8877665544332211);s.v(1,0xabcdef017fa12345,0xfedcba9876543210);s.x(1,0x123456789abcdef0);s.reg("a64.fpcr",0,4);
 for (word,lo,hi) in [(0x1e204020,0x7fa12345,0),(0x1ee04020,0x2345,0),(0x1e6e1000,1f64.to_bits(),0),(0x1e301000,(-2f32).to_bits()as u64,0),(0x1e270020,0x9abcdef0,0),(0x9e670020,0x123456789abcdef0,0),(0x1ee70020,0xdef0,0)]{let t=run(word,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(lo,hi),"{word:08x}");assert!(t.registers.iter().all(|r|r.register.bank=="a64.vector64"));}
 for (word,expected) in [(0x1e260020,0x7fa12345),(0x9e660020,0xabcdef017fa12345),(0x9eae0020,0xfedcba9876543210),(0x1ee60020,0x2345)]{assert_eq!(x(&run(word,&s),0),expected);}
 let t=run(0x9eaf0020,&s);assert_eq!(v(&t,0,1),0x123456789abcdef0);assert!(t.registers.iter().all(|r|r.register.index!=0));
 s.v(2,0x40100000,0);for (flags,expected) in [(4,0x7fa12345),(0,0x40100000)]{s.flags(flags);let t=run(0x1e220c20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(expected,0));noflags(&t);}
 // With AH, FABS/FNEG leave NaN signs unchanged. NEP merges from Vd.
 s.v(1,0xffa12345,0);for (control,expected) in [(4,0x7fa12345),(6,0xffa12345)]{s.reg("a64.fpcr",0,control);let t=run(0x1e20c020,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x1122334400000000|expected,0x8877665544332211));}
 s.v(1,(-3f64).to_bits(),0);let t=run(0x1e614020,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(3f64.to_bits(),0x8877665544332211));
 // Exhaust all encodable scalar floating-point constants at each precision.
 for (ftype,width) in [(0,32),(1,64),(3,16)]{for imm in 0..256u32{
  let word=0x1e201000|ftype<<22|imm<<13;let t=run(word,&s);let expected=(if imm&128!=0{-1.0}else{1.0})*(1.0+(imm&15)as f64/16.0)*2f64.powi(if imm&64==0{1+((imm>>4)&3)as i32}else{-3+((imm>>4)&3)as i32});assert_eq!(fp_number(v(&t,0,0),width),expected,"{word:08x}");assert_eq!(v(&t,0,1),0);
 }}
 // Unallocated precision cannot enter adjacent ordinary FP recipes.
 for word in [0x1ea22820,0x1ea04020,0x1ea1c020,0x1f820c20]{let r=recipes::for_word(word,0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");}
}

#[test]fn fused_scalar_and_simd_single_rounding_and_merge(){
 let mut s=FloatState::new();s.state.v(1,2f32.to_bits()as u64,0);s.state.v(2,3f32.to_bits()as u64,0);s.state.v(3,0x1234567800000000|4f32.to_bits()as u64,0xabcdef9876543210);s.state.reg("a64.fpcr",0,4);
 for (word,expected) in [(0x1f020c20,10f32),(0x1f028c20,-2f32),(0x1f220c20,-10f32),(0x1f228c20,2f32)]{let t=run_fp(word,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x1234567800000000|expected.to_bits()as u64,0xabcdef9876543210));}
 s.state.v(1,(1.0f32+2f32.powi(-23)).to_bits()as u64,0);s.state.v(2,(1.0f32-2f32.powi(-23)).to_bits()as u64,0);s.state.v(3,(-1f32).to_bits()as u64,0);let t=run_fp(0x1f020c20,&s);assert_eq!(v(&t,0,0),(-2f32.powi(-46)).to_bits()as u64);
 s.state.reg("a64.fpcr",0,0);s.state.v(0,(4f32.to_bits()as u64)<<32|4f32.to_bits()as u64,(4f32.to_bits()as u64)<<32|4f32.to_bits()as u64);s.state.v(1,(2f32.to_bits()as u64)<<32|2f32.to_bits()as u64,(2f32.to_bits()as u64)<<32|2f32.to_bits()as u64);s.state.v(2,(3f32.to_bits()as u64)<<32|3f32.to_bits()as u64,(3f32.to_bits()as u64)<<32|3f32.to_bits()as u64);let t=run_fp(0x4e22cc20,&s);let expected=(10f32.to_bits()as u64)<<32|10f32.to_bits()as u64;assert_eq!((v(&t,0,0),v(&t,0,1)),(expected,expected));
 s.state.v(0,4f64.to_bits(),4f64.to_bits());s.state.v(1,2f64.to_bits(),2f64.to_bits());s.state.v(2,3f64.to_bits(),3f64.to_bits());let t=run_fp(0x4ee2cc20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),((-2f64).to_bits(),(-2f64).to_bits()));
}
fn nzcv(t:&Transition)->u64{(0..4).map(|i|reg(t,"a64.nzcv",i)<<(3-i)).sum()}
#[test]fn fp_compare_nan_flags_condition_and_trap(){
 let mut s=FloatState::new();s.state.v(1,1f32.to_bits()as u64,0);
 for (b,expected) in [(2f32.to_bits(),8),(1f32.to_bits(),6),(0f32.to_bits(),2),(0x7fc12345,3)]{s.state.v(2,b as u64,0);let t=run_fp(0x1e222020,&s);assert_eq!(nzcv(&t),expected);assert_eq!(reg(&t,"a64.fpsr",0),0);}
 s.state.v(1,(-1f64).to_bits(),0);let t=run_fp(0x1e602038,&s);assert_eq!(nzcv(&t),8);
 // Conditional false with a signaling NaN must neither raise nor trap.
 s.state.v(1,0x7fa12345,0);s.state.v(2,0,0);s.state.flags(0);s.state.reg("a64.fpcr",0,1<<8);let t=run_fp(0x1e220435,&s);assert_eq!(nzcv(&t),5);assert_eq!(reg(&t,"a64.fpsr",0),0);assert_eq!(t.trap,None);
 s.state.flags(4);let t=run_fp(0x1e220435,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|r|r.register.bank!="a64.nzcv"));
 s.state.reg("a64.fpcr",0,0);let t=run_fp(0x1e220425,&s);assert_eq!(nzcv(&t),3);assert_eq!(reg(&t,"a64.fpsr",0),1);
}
#[test]fn fp_conversions_minmax_rounding_and_zero_upper(){
 let mut s=FloatState::new();s.state.v(0,0x1234567887654321,0xabcdef9876543210);s.state.reg("a64.fpcr",0,4);s.state.v(1,1.5f32.to_bits()as u64,0);let t=run_fp(0x1e22c020,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(1.5f64.to_bits(),0xabcdef9876543210));
 s.state.v(1,1.5f64.to_bits(),0);let t=run_fp(0x1e63c020,&s);assert_eq!(v(&t,0,0),0x1234567887653e00);
 s.state.x(1,(-384i32)as u32 as u64);let t=run_fp(0x1e220020,&s);assert_eq!(v(&t,0,0),0x1234567800000000|(-384f32).to_bits()as u64);let t=run_fp(0x1e02e020,&s);assert_eq!(v(&t,0,0),0x1234567800000000|(-1.5f32).to_bits()as u64);
 s.state.x(1,42);assert_eq!(v(&run_fp(0x9e630020,&s),0,0),42f64.to_bits());
 s.state.v(1,(-3.75f64).to_bits(),0);assert_eq!(x(&run_fp(0x9e780020,&s),0),(-3i64)as u64);
 s.state.v(1,1.5f32.to_bits()as u64,0);assert_eq!(x(&run_fp(0x1e19e020,&s),0),384);
 s.state.v(1,(-2.5f32).to_bits()as u64,0);for (word,expected) in [(0x1e200020,-2i32),(0x1e240020,-3),(0x1e280020,-2),(0x1e300020,-3)]{let t=run_fp(word,&s);assert_eq!(x(&t,0),expected as u32 as u64);assert_eq!(reg(&t,"a64.fpsr",0),16);}
 for (word,expected,status) in [(0x1e244020,-2f32,0),(0x1e24c020,-2f32,0),(0x1e254020,-3f32,0),(0x1e25c020,-2f32,0),(0x1e264020,-3f32,0),(0x1e274020,-2f32,16),(0x1e27c020,-2f32,0)]{let t=run_fp(word,&s);assert_eq!(v(&t,0,0),0x1234567800000000|expected.to_bits()as u64);assert_eq!(reg(&t,"a64.fpsr",0),status);}
 s.state.reg("a64.fpcr",0,0);s.state.v(1,2f32.to_bits()as u64,0);s.state.v(2,3f32.to_bits()as u64,0);assert_eq!(v(&run_fp(0x1e224820,&s),0,0),3f32.to_bits()as u64);
 s.state.v(1,2f64.to_bits(),0);s.state.v(2,3f64.to_bits(),0);assert_eq!(v(&run_fp(0x1e627820,&s),0,0),2f64.to_bits());
 s.state.v(1,(2f32.to_bits()as u64)<<32|2f32.to_bits()as u64,(2f32.to_bits()as u64)<<32|2f32.to_bits()as u64);s.state.v(2,(3f32.to_bits()as u64)<<32|3f32.to_bits()as u64,(3f32.to_bits()as u64)<<32|3f32.to_bits()as u64);let t=run_fp(0x4e22f420,&s);let expected=(3f32.to_bits()as u64)<<32|3f32.to_bits()as u64;assert_eq!((v(&t,0,0),v(&t,0,1)),(expected,expected));
 s.state.v(1,0x4000400040004000,0x4000400040004000);s.state.v(2,0x4200420042004200,0x4200420042004200);let t=run_fp(0x4ec20420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x4000400040004000,0x4000400040004000));
 for word in [0x1e022020,0x1ea20020,0x1e234020,0x1e224020]{let r=recipes::for_word(word,0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");}
}

fn set32(s:&mut State,n:u16,lanes:[f32;4]){s.v(n,(lanes[0].to_bits()as u64)|(lanes[1].to_bits()as u64)<<32,(lanes[2].to_bits()as u64)|(lanes[3].to_bits()as u64)<<32)}
fn lanes32(t:&Transition,n:u16)->[u32;4]{let lo=v(t,n,0);let hi=v(t,n,1);[lo as u32,(lo>>32)as u32,hi as u32,(hi>>32)as u32]}
fn hpack(values:[u16;4])->u64{values.into_iter().enumerate().map(|(i,v)|(v as u64)<<(i*16)).sum()}
#[test]fn fp_transport_preserves_original_width_addresses_and_banks(){
 let mut s=State::default();s.x(1,0x2000);s.x(2,3);s.v(0,0x1122334455667788,0x8877665544332211);s.v(2,0xabcdef0123456789,0x9876543210fedcba);
 s.mem.insert(0x200c,0xf1234567);let t=run(0xbd400c20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0xf1234567,0));
 let t=run(0xfc010c20,&s);assert_eq!((t.memory[0].address,t.memory[0].value.width,t.memory[0].value.bits,x(&t,1)),(0x2010,64,0x1122334455667788,0x2010));
 s.mem.insert(0x2000,0x123456789abcdef0);s.mem.insert(0x2008,0xfedcba9876543210);let t=run(0x3cc10420,&s);assert_eq!((v(&t,0,0),v(&t,0,1),x(&t,1)),(0x123456789abcdef0,0xfedcba9876543210,0x2010));assert_eq!(&*s.wide_reads.borrow(),&[(0x2000,128,Endian::Little)]);
 // X1 writeback and V1 destination have different identities despite number1.
 let t=run(0x3cc10421,&s);assert_eq!((v(&t,1,0),v(&t,1,1),x(&t,1)),(0x123456789abcdef0,0xfedcba9876543210,0x2010));
 s.mem.insert(0x1ffe,0x81ff);assert_eq!(v(&run(0x7c5fe020,&s),0,0),0x81ff);let t=run(0x3c224820,&s);assert_eq!((t.memory[0].address,t.memory[0].value.width,t.memory[0].value.bits),(0x2003,8,0x88));
 s.mem.insert(0x2030,7);s.mem.insert(0x2038,9);let t=run(0x3ce27820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(7,9));s.mem.insert(0x101c,0xfeedface);assert_eq!(v(&run(0x5c0000e0,&s),0,0),0xfeedface);
 s.mem.insert(0x2010,11);s.mem.insert(0x2018,13);s.wide_reads.borrow_mut().clear();let t=run(0xacc10820,&s);assert_eq!((v(&t,0,0),v(&t,0,1),v(&t,2,0),v(&t,2,1),x(&t,1)),(0x123456789abcdef0,0xfedcba9876543210,11,13,0x2020));assert_eq!(&*s.wide_reads.borrow(),&[(0x2000,256,Endian::Little)]);
 let t=run(0x6dbf0820,&s);assert!(t.memory.is_empty());assert_eq!((t.wide_memory[0].address,t.wide_memory[0].width,t.wide_memory[0].endian,x(&t,1)),(0x1ff0,128,Endian::Little,0x1ff0));assert_eq!(t.wide_memory[0].chunks.iter().map(|v|v.bits).collect::<Vec<_>>(),vec![0x1122334455667788,0xabcdef0123456789]);
 s.mem.insert(0x2008,0x8765432112345678);let t=run(0x2c410820,&s);assert_eq!((v(&t,0,0),v(&t,0,1),v(&t,2,0),v(&t,2,1)),(0x12345678,0,0x87654321,0));
 let t=run(0xac010820,&s);assert_eq!((t.wide_memory[0].address,t.wide_memory[0].width),(0x2020,256));assert_eq!(t.wide_memory[0].chunks.iter().map(|v|v.bits).collect::<Vec<_>>(),vec![0x1122334455667788,0x8877665544332211,0xabcdef0123456789,0x9876543210fedcba]);
 // Original-width access has one explicit capability call; no64-bit fallback.
 struct NoWide(State);impl Machine for NoWide{fn read_register(&self,r:Register)->Value{self.0.read_register(r)}fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.0.read_memory(a,w,e)}}
 let r=decode(0x3cc10420).unwrap().semantic_recipe(0);assert_eq!(r.wide_loads.len(),1);assert_eq!(r.wide_loads[0].width,128);assert_eq!(evaluate(&r,&NoWide(State::default())),Err(EvalError::Unsupported));
 // FEAT_LSUI allocates the former reserved Q-pair space. A repeated load
 // destination chooses the permitted NOP; distinct destinations retain one
 // unprivileged original-width access.
 let repeated=recipes::for_word(0xec400020,0);assert_eq!(repeated.support,Support::Full);assert!(repeated.effects.is_empty()&&repeated.wide_loads.is_empty());
 let pair=recipes::for_word(0xec400820,0);assert_eq!(pair.support,Support::Full);assert_eq!(pair.wide_loads.len(),1);assert_eq!(pair.wide_loads[0].width,256);assert_eq!(pair.wide_loads[0].privilege,MemoryPrivilege::AArch64Unprivileged);
 for word in [0xad400020,0x3c400820,0x7d800020]{let r=recipes::for_word(word,0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");assert!(r.effects.is_empty()&&r.wide_loads.is_empty());}
}
#[test]fn vector_fp_comparisons_masks_nan_traps_and_scalar_merge(){
 let mut s=FloatState::new();set32(&mut s.state,1,[-1.0,0.0,2.0,f32::from_bits(0x7fc12345)]);set32(&mut s.state,2,[-2.0,0.0,3.0,1.0]);let t=run_fp(0x4e22e420,&s);assert_eq!(lanes32(&t,0),[0,u32::MAX,0,0]);assert_eq!(reg(&t,"a64.fpsr",0),0);noflags(&t);
 for (word,expected,status) in [(0x4ea0d820,[0,u32::MAX,0,0],0),(0x6ea0c820,[0,u32::MAX,u32::MAX,0],1),(0x4ea0c820,[0,0,u32::MAX,0],1),(0x6ea0d820,[u32::MAX,u32::MAX,0,0],1),(0x4ea0e820,[u32::MAX,0,0,0],1)]{let t=run_fp(word,&s);assert_eq!(lanes32(&t,0),expected,"{word:08x}");assert_eq!(reg(&t,"a64.fpsr",0),status);}
 s.state.reg("a64.fpcr",0,1<<8);let t=run_fp(0x6ea0c820,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|r|r.register.bank!="a64.vector64"));
 s.state.reg("a64.fpcr",0,0);set32(&mut s.state,1,[-3.0,-0.0,4.0,5.0]);set32(&mut s.state,2,[2.0,0.0,-4.0,6.0]);assert_eq!(lanes32(&run_fp(0x6e22ec20,&s),0),[u32::MAX,u32::MAX,u32::MAX,0]);assert_eq!(lanes32(&run_fp(0x6ea2ec20,&s),0),[u32::MAX,0,0,0]);
 s.state.v(1,2f64.to_bits(),1f64.to_bits());s.state.v(2,1f64.to_bits(),2f64.to_bits());let t=run_fp(0x6e62e420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(u64::MAX,0));s.state.v(1,hpack([0x4000,0x3c00,0x4000,0x3c00]),hpack([0x4000,0x3c00,0x4000,0x3c00]));s.state.v(2,hpack([0x3c00,0x4000,0x3c00,0x4000]),hpack([0x3c00,0x4000,0x3c00,0x4000]));let t=run_fp(0x6ec22420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([0xffff,0,0xffff,0]),hpack([0xffff,0,0xffff,0])));
 s.state.reg("a64.fpcr",0,4);s.state.v(1,2f32.to_bits()as u64,0);s.state.v(2,0xabcdef0100000000|1f32.to_bits()as u64,0x123456789abcdef0);let t=run_fp(0x7e22e420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0xabcdef01ffffffff,0x123456789abcdef0));s.state.v(1,0,0);let t=run_fp(0x5ea0d820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0xffffffff,0));
}
#[test]fn vector_fp_integer_conversions_rounding_and_aliases(){
 let mut s=FloatState::new();set32(&mut s.state,1,[-2.5,-1.5,1.5,2.5]);
 for (word,expected) in [(0x4e21a820,[-2i32,-2,2,2]),(0x4e21c820,[-3,-2,2,3]),(0x4ea1a820,[-2,-1,2,3]),(0x4e21b820,[-3,-2,1,2]),(0x4ea1b820,[-2,-1,1,2])]{let t=run_fp(word,&s);assert_eq!(lanes32(&t,0),expected.map(|x|x as u32));assert_eq!(reg(&t,"a64.fpsr",0),16);}
 let t=run_fp(0x4ea1b821,&s);assert_eq!(lanes32(&t,1),[(-2i32)as u32,(-1i32)as u32,1,2]);
 for (word,expected,status) in [(0x4e218820,[-2f32,-2.0,2.0,2.0],0),(0x4ea18820,[-2.0,-1.0,2.0,3.0],0),(0x4e219820,[-3.0,-2.0,1.0,2.0],0),(0x4ea19820,[-2.0,-1.0,1.0,2.0],0),(0x6e218820,[-3.0,-2.0,2.0,3.0],0),(0x6e219820,[-2.0,-2.0,2.0,2.0],16),(0x6ea19820,[-2.0,-2.0,2.0,2.0],0)]{let t=run_fp(word,&s);assert_eq!(lanes32(&t,0),expected.map(f32::to_bits));assert_eq!(reg(&t,"a64.fpsr",0),status);}
 s.state.v(1,((-384i32)as u32 as u64)|(256u64<<32),512);assert_eq!(lanes32(&run_fp(0x4e21d820,&s),0),[-384f32,256.0,512.0,0.0].map(f32::to_bits));assert_eq!(lanes32(&run_fp(0x4f38e420,&s),0),[-1.5f32,1.0,2.0,0.0].map(f32::to_bits));
 s.state.v(1,1u64<<63,42);let t=run_fp(0x6e61d820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),((2f64.powi(63)).to_bits(),42f64.to_bits()));
 set32(&mut s.state,1,[1.5,2.5,3.0,0.0]);assert_eq!(lanes32(&run_fp(0x6f38fc20,&s),0),[384,640,768,0]);s.state.v(1,hpack([0x3e00,0x4100,0x4300,0x4480]),hpack([0x3e00,0x4100,0x4300,0x4480]));let t=run_fp(0x6ef9b820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([1,2,3,4]),hpack([1,2,3,4])));
 s.state.reg("a64.fpcr",0,4);s.state.v(0,0x1234567887654321,0xabcdef9876543210);s.state.v(1,(-384i32)as u32 as u64,0);let t=run_fp(0x5e21d820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x1234567800000000|(-384f32).to_bits()as u64,0xabcdef9876543210));s.state.v(1,(-2.5f32).to_bits()as u64,0);assert_eq!(v(&run_fp(0x5ea1b820,&s),0,0),0x12345678fffffffe);
 for word in [0x0e61d820,0x0f08e420,0x5e218820,0x0f40fc20]{assert!(matches!(recipes::for_word(word,0).support,Support::Unsupported(_)),"{word:08x}");}
}
#[test]fn vector_fp_precision_conversion_halves_odd_and_aliasing(){
 let mut s=FloatState::new();s.state.v(0,0x1122334455667788,0x8877665544332211);s.state.v(1,hpack([0x3c00,0x3e00,0x4000,0x4200]),u64::MAX);let t=run_fp(0x0e217820,&s);assert_eq!(lanes32(&t,0),[1f32,1.5,2.0,3.0].map(f32::to_bits));
 set32(&mut s.state,1,[f32::NAN,f32::NAN,3.0,4.0]);let t=run_fp(0x4e617820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(3f64.to_bits(),4f64.to_bits()));
 set32(&mut s.state,1,[1.0,1.5,2.0,3.0]);let t=run_fp(0x0e216820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([0x3c00,0x3e00,0x4000,0x4200]),0));
 s.state.v(1,3f64.to_bits(),4f64.to_bits());let t=run_fp(0x4e616820,&s);assert_eq!(v(&t,0,1),(3f32.to_bits()as u64)|(4f32.to_bits()as u64)<<32);assert!(t.registers.iter().all(|w|w.register.bank!="a64.vector64"||w.register.index!=0));
 s.state.v(1,(1.0f64+2f64.powi(-25)).to_bits(),(-1.0f64-2f64.powi(-25)).to_bits());let t=run_fp(0x2e616820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0xbf8000013f800001,0));assert_eq!(reg(&t,"a64.fpsr",0),16);let t=run_fp(0x6e616820,&s);assert_eq!(v(&t,0,1),0xbf8000013f800001);assert!(t.registers.iter().all(|w|w.register.bank!="a64.vector64"||w.register.index!=0));
 s.state.reg("a64.fpcr",0,4);let t=run_fp(0x7e616820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x112233443f800001,0x8877665544332211));
}
#[test]fn indexed_pairwise_and_reduction_fp_operation_order(){
 let mut s=FloatState::new();set32(&mut s.state,1,[1.0,2.0,3.0,4.0]);set32(&mut s.state,18,[5.0,6.0,7.0,8.0]);assert_eq!(lanes32(&run_fp(0x4fb29820,&s),0),[8f32,16.0,24.0,32.0].map(f32::to_bits));
 s.state.reg("a64.fpcr",0,4);set32(&mut s.state,2,[5.0,6.0,7.0,8.0]);let t=run_fp(0x5f829820,&s);assert_eq!(lanes32(&t,0),[7f32,2.0,3.0,4.0].map(f32::to_bits));
 s.state.reg("a64.fpcr",0,0);s.state.v(0,1f64.to_bits(),2f64.to_bits());s.state.v(1,2f64.to_bits(),4f64.to_bits());s.state.v(18,99f64.to_bits(),3f64.to_bits());let t=run_fp(0x4fd21820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(7f64.to_bits(),14f64.to_bits()));
 s.state.v(0,hpack([0x4800;4]),hpack([0x4800;4]));s.state.v(1,hpack([0x4200;4]),hpack([0x4200;4]));s.state.v(2,hpack([0x3c00;4]),hpack([0x4000;4]));let t=run_fp(0x4f325820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([0x4000;4]),hpack([0x4000;4])));let t=run_fp(0x5f121820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x4b00,0));
 set32(&mut s.state,1,[1.0,2.0,3.0,4.0]);set32(&mut s.state,2,[5.0,6.0,7.0,8.0]);assert_eq!(v(&run_fp(0x7e30d820,&s),0,0),3f32.to_bits()as u64);assert_eq!(lanes32(&run_fp(0x6e22d420,&s),0),[3f32,7.0,11.0,15.0].map(f32::to_bits));
 s.trace.borrow_mut().clear();let t=run_fp(0x6e30f820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(4f32.to_bits()as u64,0));let trace=s.trace.borrow();let actual=trace.iter().map(|(_,v)|v.clone()).collect::<Vec<_>>();assert_eq!(actual,vec![vec![3f32.to_bits()as u64,4f32.to_bits()as u64],vec![1f32.to_bits()as u64,2f32.to_bits()as u64],vec![2f32.to_bits()as u64,4f32.to_bits()as u64]]);drop(trace);
 s.state.v(1,1f64.to_bits(),2f64.to_bits());s.state.v(2,3f64.to_bits(),4f64.to_bits());let t=run_fp(0x6e62f420,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(2f64.to_bits(),4f64.to_bits()));assert_eq!(v(&run_fp(0x7e70f820,&s),0,0),2f64.to_bits());s.state.v(1,hpack([0x3c00,0x4000,0x4200,0x4400]),hpack([0x4500,0x4600,0x4700,0x4800]));assert_eq!(v(&run_fp(0x4eb0c820,&s),0,0),0x3c00);assert_eq!(v(&run_fp(0x5eb0c820,&s),0,0),0x3c00);
 set32(&mut s.state,1,[1.0,2.0,3.0,4.0]);set32(&mut s.state,2,[5.0,6.0,f32::from_bits(0x7fa12345),8.0]);s.state.reg("a64.fpcr",0,1<<8);let t=run_fp(0x6e22d420,&s);assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert!(t.registers.iter().all(|r|r.register.bank!="a64.vector64"));
 for word in [0x0fd29820,0x4ff29820,0x2e30f820,0x6e70f820]{assert!(matches!(recipes::for_word(word,0).support,Support::Unsupported(_)),"{word:08x}");}
}

#[test]fn classic_reciprocal_extended_multiply_and_context_rejection(){
 let mut s=FloatState::new();s.state.v(0,0x1122334455667788,0x8877665544332211);s.state.v(1,1f32.to_bits()as u64,0);assert_eq!(v(&run_fp(0x5ea1d820,&s),0,0),0x3f7f8000);s.state.v(1,4f32.to_bits()as u64,0);assert_eq!(v(&run_fp(0x5ea1d820,&s),0,0),0x3e7f8000);
 set32(&mut s.state,1,[1.0,4.0,1.0,4.0]);assert_eq!(lanes32(&run_fp(0x6ea1d820,&s),0),[0x3f7f8000,0x3eff8000,0x3f7f8000,0x3eff8000]);s.state.v(1,4f64.to_bits(),0);assert_eq!(v(&run_fp(0x7ee1d820,&s),0,0),0x3fdff00000000000);assert_eq!(v(&run_fp(0x5ee1f820,&s),0,0),0x3fe0000000000000);s.state.v(1,0x3c00,0);assert_eq!(v(&run_fp(0x5ef9d820,&s),0,0),0x3bfc);
 set32(&mut s.state,1,[1.5,f32::INFINITY,1.5,f32::NEG_INFINITY]);set32(&mut s.state,2,[0.5,0.0,0.5,0.0]);assert_eq!(lanes32(&run_fp(0x4e22fc20,&s),0),[1.25f32,2.0,1.25,2.0].map(f32::to_bits));s.state.v(1,1.5f64.to_bits(),f64::INFINITY.to_bits());s.state.v(2,0.5f64.to_bits(),0);let t=run_fp(0x4ee2fc20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(1.125f64.to_bits(),1.5f64.to_bits()));
 s.state.v(1,f32::INFINITY.to_bits()as u64,0);s.state.v(2,(-0.0f32).to_bits()as u64,0);let t=run_fp(0x5e22dc20,&s);assert_eq!(v(&t,0,0),(-2f32).to_bits()as u64);assert_eq!(reg(&t,"a64.fpsr",0),0);
 s.state.v(1,hpack([0x7c00;4]),hpack([0xfc00;4]));s.state.v(2,0,0);let t=run_fp(0x4e421c20,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([0x4000;4]),hpack([0xc000;4])));
 set32(&mut s.state,1,[1.0,2.0,3.0,4.0]);set32(&mut s.state,18,[5.0,6.0,7.0,8.0]);assert_eq!(lanes32(&run_fp(0x6fb29820,&s),0),[8f32,16.0,24.0,32.0].map(f32::to_bits));
 for bits in [1,2,1<<26]{s.state.reg("a64.fpcr",0,bits);let r=decode(0x5ea1d820).unwrap().semantic_recipe(0);let before=s.calls.get();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert_eq!(s.calls.get(),before);}
}
#[test]fn bf16_conversion_dot_products_and_status_preservation(){
 let mut s=FloatState::new();s.state.v(0,0x1122334455667788,0x8877665544332211);s.state.v(1,1.5f32.to_bits()as u64,0);s.state.reg("a64.fpcr",0,4);let t=run_fp(0x1e634020,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0x1122334455663fc0,0x8877665544332211));
 s.state.v(1,0x3f808000,0);for(rounding,expected)in[(0,0x3f80),(1,0x3f81),(2,0x3f80),(3,0x3f80)]{s.state.reg("a64.fpcr",0,rounding<<22);let t=run_fp(0x1e634020,&s);assert_eq!(v(&t,0,0),expected);assert_eq!(reg(&t,"a64.fpsr",0),16);}
 s.state.reg("a64.fpcr",0,0);set32(&mut s.state,1,[1.0,1.5,2.0,3.0]);let t=run_fp(0x0ea16820,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(hpack([0x3f80,0x3fc0,0x4000,0x4040]),0));let t=run_fp(0x4ea16820,&s);assert_eq!(v(&t,0,1),hpack([0x3f80,0x3fc0,0x4000,0x4040]));assert!(t.registers.iter().all(|r|r.register.bank!="a64.vector64"||r.register.index!=0));
 s.state.reg("a64.fpsr",0,0x0800001f);
 set32(&mut s.state,0,[1.0,2.0,3.0,4.0]);s.state.v(1,hpack([0x3f80,0x4000,0x4040,0x4080]),hpack([0x40a0,0x40c0,0x40e0,0x4100]));s.state.v(2,hpack([0x4000;4]),hpack([0x4000;4]));let t=run_fp(0x6e42fc20,&s);assert_eq!(lanes32(&t,0),[7f32,16.0,25.0,34.0].map(f32::to_bits));assert!(t.registers.iter().all(|r|!matches!(r.register.bank,"a64.fpsr"|"a64.nzcv")));assert_eq!(t.trap,None);
 s.state.v(18,hpack([0x3f80;4]),hpack([0x3f80,0x3f80,0x4000,0x4040]));let t=run_fp(0x0f72f820,&s);assert_eq!(lanes32(&t,0),[9f32.to_bits(),20f32.to_bits(),0,0]);
 // These normal, exactly representable products agree in standard and
 // enhanced BF16 modes, including AH/FIZ and DN; the bounded reference need
 // not model their different inexact, denormal or NaN rules here.
 for bits in [1,2,1<<13,1<<26]{s.state.reg("a64.fpcr",0,bits);let t=run_fp(0x6e42fc20,&s);assert_eq!(lanes32(&t,0),[7f32,16.0,25.0,34.0].map(f32::to_bits));assert!(t.registers.iter().all(|r|!matches!(r.register.bank,"a64.fpsr"|"a64.nzcv")));assert_eq!(t.trap,None);}
}

#[test]fn explicit_data_endian_preserves_scalar_and_pair_register_order(){
 struct Bytes{state:State,bytes:HashMap<u64,u8>,reads:std::cell::RefCell<Vec<(u64,u16,Endian)>>}
 impl Machine for Bytes{
  fn read_register(&self,r:Register)->Value{self.state.read_register(r)}
  fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.reads.borrow_mut().push((a,w as u16,e));let mut bits=0;for offset in 0..w/8{let byte=*self.bytes.get(&a.wrapping_add(offset as u64)).ok_or(EvalError::Memory)?;let shift=if e==Endian::Little{offset*8}else{w-8-offset*8};bits|=(byte as u64)<<shift;}Ok(Value::known(w,bits))}
  fn read_wide_memory(&self,a:u64,w:u16,e:Endian)->Result<Vec<Value>,EvalError>{self.reads.borrow_mut().push((a,w,e));assert!(w%64==0);let mut chunks=vec![];for chunk in 0..w/64{let mut bits=0;for byte in 0..8{let offset=if e==Endian::Little{chunk*8+byte}else{w/8-8-chunk*8+byte};let value=*self.bytes.get(&a.wrapping_add(offset as u64)).ok_or(EvalError::Memory)?;let shift=if e==Endian::Little{byte*8}else{56-byte*8};bits|=(value as u64)<<shift;}chunks.push(Value::known(64,bits));}Ok(chunks)}
 }
 let mut b=Bytes{state:State::default(),bytes:(0..32).map(|i|(0x2000+i,(i+1)as u8)).collect(),reads:std::cell::RefCell::new(vec![])};b.state.x(1,0x2000);
 let execute=|word,endian,state:&Bytes|{let r=decode(word).unwrap().semantic_recipe_with_endian(0x1000,endian);assert_eq!(r.support,Support::Full);r.validate().unwrap();evaluate(&r,state).unwrap()};
 for endian in [Endian::Little,Endian::Big]{
  b.reads.borrow_mut().clear();let t=execute(0xacc10820,endian,&b);let expected=if endian==Endian::Little{[0x0807060504030201,0x100f0e0d0c0b0a09,0x1817161514131211,0x201f1e1d1c1b1a19]}else{[0x090a0b0c0d0e0f10,0x0102030405060708,0x191a1b1c1d1e1f20,0x1112131415161718]};assert_eq!([v(&t,0,0),v(&t,0,1),v(&t,2,0),v(&t,2,1)],expected);assert_eq!(x(&t,1),0x2020);assert_eq!(&*b.reads.borrow(),&[(0x2000,256,endian)]);
  let t=execute(0x6cc10820,endian,&b);let expected=if endian==Endian::Little{[0x0807060504030201,0x100f0e0d0c0b0a09]}else{[0x0102030405060708,0x090a0b0c0d0e0f10]};assert_eq!([v(&t,0,0),v(&t,2,0)],expected);assert_eq!((v(&t,0,1),v(&t,2,1)),(0,0));
  let t=execute(0x2c410820,endian,&b);let expected=if endian==Endian::Little{[0x0c0b0a09,0x100f0e0d]}else{[0x090a0b0c,0x0d0e0f10]};assert_eq!([v(&t,0,0),v(&t,2,0)],expected);
  let t=execute(0x3cc10420,endian,&b);let expected=if endian==Endian::Little{[0x0807060504030201,0x100f0e0d0c0b0a09]}else{[0x090a0b0c0d0e0f10,0x0102030405060708]};assert_eq!([v(&t,0,0),v(&t,0,1)],expected);
  let t=execute(0xbd400c20,endian,&b);assert_eq!(v(&t,0,0),if endian==Endian::Little{0x100f0e0d}else{0x0d0e0f10});let t=execute(0xf9400020,endian,&b);assert_eq!(x(&t,0),if endian==Endian::Little{0x0807060504030201}else{0x0102030405060708});
 }
 // Stores serialize a complete numeric span; pair element order changes
 // with endian, while each Q's low/high numeric chunk identities stay intact.
 b.state.v(0,0x090a0b0c0d0e0f10,0x0102030405060708);b.state.v(2,0x191a1b1c1d1e1f20,0x1112131415161718);
 let t=execute(0xac010820,Endian::Big,&b);let store=&t.wide_memory[0];assert_eq!((store.width,store.endian),(256,Endian::Big));let bytes=store.chunks.iter().rev().flat_map(|v|v.bits.to_be_bytes()).collect::<Vec<_>>();assert_eq!(bytes,(1u8..=32).collect::<Vec<_>>());
 b.state.v(0,0x0102030405060708,0);b.state.v(2,0x1112131415161718,0);let t=execute(0x6dbf0820,Endian::Big,&b);let bytes=t.wide_memory[0].chunks.iter().rev().flat_map(|v|v.bits.to_be_bytes()).collect::<Vec<_>>();assert_eq!(bytes,vec![1,2,3,4,5,6,7,8,17,18,19,20,21,22,23,24]);
 b.state.v(0,0x01020304,0);b.state.v(2,0x11121314,0);let t=execute(0x2c010820,Endian::Big,&b);assert_eq!((t.memory[0].endian,t.memory[0].value.bits),(Endian::Big,0x0102030411121314));
 let instruction=decode(0xacc10820).unwrap();assert_eq!(instruction.semantic_recipe(0),instruction.semantic_recipe_with_endian(0,Endian::Little));
 let r=recipes::for_word_with_endian(0xc85f7c20,0,Endian::Big);assert_eq!(r.support,Support::Full);assert!(matches!(&r.atomics[0],AtomicStep::Memory(operation)if operation.memory.endian==Endian::Big));
}

fn sve(word:u32,vl:u16,s:&impl Machine)->Transition{let d=decode(word).unwrap();let r=d.semantic_recipe_with_vector_length(0x1000,vl);assert_eq!(r.support,Support::Full,"{word:08x}");r.validate().unwrap();evaluate(&r,s).unwrap()}
#[test]fn sve_context_predicate_count_and_v_clear(){
 let s=State::default();for vl in [128,256,512,2048]{let t=sve(0x2518e3e0,vl,&s);for ch in 0..4{let bits=(vl/8).saturating_sub(ch*64).min(64)as u8;assert_eq!(reg(&t,"a64.predicate64",ch),mask(bits));}let t=sve(0x04a2e3e1,vl,&s);assert_eq!(x(&t,1),(vl/32*3)as u64);let t=sve(0x2598e061,vl,&s);assert_eq!(reg(&t,"a64.predicate64",4),0x111);let t=sve(0x25d9e3e2,vl,&s);assert_eq!(reg(&t,"a64.nzcv",0),1);assert_eq!(reg(&t,"a64.nzcv",1),0);assert_eq!(reg(&t,"a64.nzcv",2),0);}
 for vl in [0,64,129,2176]{let r=recipes::for_word_with_vector_length(0x2518e3e0,0,vl);assert!(matches!(r.support,Support::Unsupported(_)),"{vl} {:?}",r.support);assert!(r.effects.is_empty());}
 let mut s=State::default();s.v(1,0x123456789abcdef0,0xfedcba9876543210);let t=sve(0x1e204020,512,&s);assert_eq!(v(&t,0,0),0x9abcdef0);for ch in 1..8{assert_eq!(v(&t,0,ch),0);}
 assert_eq!(decode(0x2518e3e0).unwrap().semantic_recipe(0),decode(0x2518e3e0).unwrap().semantic_recipe_with_vector_length(0,128));
}
#[test]fn sve_while_index_and_predicated_integer_snapshot(){
 let mut s=State::default();s.x(1,5);s.x(2,8);let t=sve(0x25a21420,256,&s);assert_eq!(reg(&t,"a64.predicate64",0),0x111);assert_eq!(reg(&t,"a64.nzcv",0),1);assert_eq!(reg(&t,"a64.nzcv",2),1);
 s.x(1,0xffff_fffe);s.x(2,0xffff_ffff);let t=sve(0x25220c20,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),1); // no reactivation after wrap
 s.x(1,5);s.x(2,3);let t=sve(0x25621020,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),0x5400);
 let t=sve(0x04a343c0,256,&s);assert_eq!(v(&t,0,0),0x00000001fffffffe);assert_eq!(v(&t,0,3),0x0000001300000010);
 s.x(1,u64::MAX);s.x(2,2);let t=sve(0x04e24c20,128,&s);assert_eq!(v(&t,0,0),u64::MAX);assert_eq!(v(&t,0,1),1);
 s.v(0,0x100000002,0x300000004);s.v(1,0x100000001,0x100000001);s.reg("a64.predicate64",0,0x101);let t=sve(0x04800020,128,&s);assert_eq!(v(&t,0,0),0x100000003);assert_eq!(v(&t,0,1),0x300000005);
 s.v(1,u64::MAX,0x8000000000000000);s.v(0,0x8000000000000000,0x8000000000000000);s.reg("a64.predicate64",0,0x101);let t=sve(0x04d08020,128,&s);assert_eq!(v(&t,0,0),u64::MAX);assert_eq!(v(&t,0,1),u64::MAX);
 let t=sve(0x04609420,128,&s);assert_eq!((v(&t,0,0),v(&t,0,1)),(0,0));
 s.v(1,0x400000003,0x800000007);s.v(2,0x400000000,0x000000007);s.reg("a64.predicate64",4,0x1010);let t=sve(0x2482a420,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),0x10);assert_eq!(reg(&t,"a64.nzcv",0),1);assert_eq!(reg(&t,"a64.nzcv",2),1);
}
#[test]fn sve_contiguous_memory_suppresses_inactive_faults_and_store_events(){
 let mut s=State::default();s.x(1,u64::MAX);let t=sve(0xa440a020,256,&s);for ch in 0..4{assert_eq!(v(&t,0,ch),0);}assert!(sve(0xe440e020,256,&s).memory.is_empty());
 s.x(1,0x1000);s.reg("a64.predicate64",0,0x101);s.mem.insert(0x1000,0xff);s.mem.insert(0x1002,0x80);let t=sve(0xa440a020,128,&s);assert_eq!(v(&t,0,0),0xff);assert_eq!(v(&t,0,1),0x80);
 s.reg("a64.predicate64",0,0x1011);let r=decode(0xa440a020).unwrap().semantic_recipe_with_vector_length(0,128);assert_eq!(evaluate(&r,&s),Err(EvalError::Memory));
 s.reg("a64.predicate64",0,0x101);s.v(0,0x12345678,0xabcdef01);let t=sve(0xe440e020,128,&s);assert_eq!(t.memory.len(),2);assert_eq!((t.memory[0].address,t.memory[0].value.bits),(0x1000,0x78));assert_eq!((t.memory[1].address,t.memory[1].value.bits),(0x1002,1));
 s.x(1,0x1008);s.mem.insert(0x1000,0xffff);s.mem.insert(0x1004,0x8000);let t=sve(0xa4cfa020,128,&s);assert_eq!(v(&t,0,0),0xffff);assert_eq!(v(&t,0,1),0x8000);
 s.x(1,0x1000);s.x(2,1);s.reg("a64.predicate64",0,1);s.mem.insert(0x1004,0x12345678);let t=sve(0xa5424020,128,&s);assert_eq!(v(&t,0,0),0x12345678);
 s.reg("a64.sp",0,0x2000);s.mem.insert(0x2000,0x1234);let t=sve(0xa5e0a3e0,128,&s);assert_eq!(v(&t,0,0),0x1234);
 let r=decode(0xe440e020).unwrap().semantic_recipe_with_context(0,recipes::RecipeContext{vector_length:128,endian:Endian::Big,streaming_vector_length:None});let t=evaluate(&r,&s).unwrap();assert_eq!(t.memory[0].endian,Endian::Big);
 let first_fault=decode(0xa41f6020).unwrap().semantic_recipe_with_vector_length(0,256);assert_eq!(first_fault.support,Support::Full);first_fault.validate().unwrap();
 s.reg("a64.predicate64",0,0);let r=decode(0x85224020).unwrap().semantic_recipe_with_vector_length(0,256);assert_eq!(r.support,Support::Full);r.validate().unwrap();let t=evaluate(&r,&s).unwrap();assert!(t.memory.is_empty());for chunk in 0..4{assert_eq!(v(&t,0,chunk),0);}
}


#[test]fn sve_audited_real_words_and_numeric_endian_accesses(){
 let s=State::default();for word in [0x2518e3e0,0x2598e061,0x25d9e3e2,0x2518e403,0x0420e3e0,0x04a2e3e1,0x25a21420,0x25220c20,0x25621020,0x04a343c0,0x04e24c20,0x04220020,0x04e20420,0x04800020,0x04430020,0x04d00020,0x041b0020,0x04223020,0x05a2c020,0x2482a420,0x24c28430,0x04609420,0x04038260,0x04d08020,0xa440a020,0xa4cfa020,0xa5424020,0xa5e0a3e0,0xe440e020,0xe561e020,0xe5e24020]{for vl in [128,2048]{sve(word,vl,&s);}}
 struct Bytes{state:State,reads:std::cell::RefCell<Vec<(u64,u8,Endian)>>}
 impl Machine for Bytes{fn read_register(&self,r:Register)->Value{self.state.read_register(r)}fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.reads.borrow_mut().push((a,w,e));if !(0x1000..0x1004).contains(&a){return Err(EvalError::Memory)}let bytes=[0x12u8,0x34,0x56,0x78];let mut value=0;for i in 0..w/8{let shift=if e==Endian::Little{i}else{w/8-1-i};value|=(bytes[(a-0x1000)as usize+i as usize]as u64)<<(shift*8);}Ok(Value::known(w,value))}}
 let mut s=State::default();s.x(1,0x1008);s.reg("a64.predicate64",0,0x11);let state=Bytes{state:s,reads:Default::default()};for endian in [Endian::Little,Endian::Big]{state.reads.borrow_mut().clear();let r=decode(0xa4cfa020).unwrap().semantic_recipe_with_context(0,recipes::RecipeContext{vector_length:128,endian,streaming_vector_length:None});let t=evaluate(&r,&state).unwrap();assert_eq!(v(&t,0,0),if endian==Endian::Little{0x785600003412}else{0x567800001234});assert_eq!(*state.reads.borrow(),vec![(0x1000,16,endian),(0x1002,16,endian)]);assert_eq!(v(&t,0,1),0);}
}


#[test]fn sve_predicate_truth_tables_count_flags_and_signed_loads(){
 let mut s=State::default();s.reg("a64.predicate64",4,0b101011);s.reg("a64.predicate64",8,0b110101);s.reg("a64.predicate64",12,0b011110);
 for(word,expected)in[(0x25034440,0b010100),(0x25834440,0b111111),(0x25034450,0b100001),(0x25034640,0b101011),(0x25834450,0b110101),(0x25834650,!0b010100u64),(0x25834640,!0b111111u64)]{let t=sve(word,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),expected&0b101011);noflags(&t);}
 let t=sve(0x25034650,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),(0b110101&0b101011)|(0b011110&!0b101011));
 let t=sve(0x25434440,128,&s);assert_eq!(reg(&t,"a64.predicate64",0),0);assert_eq!(reg(&t,"a64.nzcv",0),0);assert_eq!(reg(&t,"a64.nzcv",1),1);assert_eq!(reg(&t,"a64.nzcv",2),1);
 let t=sve(0x2550c440,128,&s);assert_eq!(reg(&t,"a64.nzcv",0),1);assert_eq!(reg(&t,"a64.nzcv",1),0);assert_eq!(reg(&t,"a64.nzcv",2),0);assert!(t.registers.iter().all(|v|v.register.bank=="a64.nzcv"));
 s.reg("a64.predicate64",4,0x1111);s.reg("a64.predicate64",8,0x1011);let t=sve(0x25a08440,128,&s);assert_eq!(x(&t,0),3);
 s.reg("a64.predicate64",0,1);s.x(1,0x1000);s.x(2,2);s.mem.insert(0x1000,0x80);assert_eq!(v(&sve(0xa5a0a020,128,&s),0,0),0xffffff80);
 s.mem.insert(0x1000,0x8000);assert_eq!(v(&sve(0xa500a020,128,&s),0,0),0xffffffffffff8000);
 s.mem.insert(0x1000,0x80000000);assert_eq!(v(&sve(0xa480a020,128,&s),0,0),0xffffffff80000000);
 s.v(0,0x123456789abcdef0,0);let t=sve(0xe4c24020,128,&s);assert_eq!((t.memory[0].address,t.memory[0].value.width,t.memory[0].value.bits),(0x1004,16,0xdef0));let t=sve(0xe5624020,128,&s);assert_eq!((t.memory[0].address,t.memory[0].value.width,t.memory[0].value.bits),(0x1008,32,0x9abcdef0));
}

`

const a64ScalarRegisterConversionTests = `
#[test]fn scalar_register_conversions_all_widths_rounding_merges_and_aliases(){
 for (sf,ftype) in [(0,1),(0,3),(1,0),(1,3)] {
  let iw=32u8<<sf;let fw=match ftype{0=>32,1=>64,_=>16};
  for op in [0x1e2a0000u32,0x1e2b0000,0x1e320000,0x1e330000,0x1e340000,0x1e350000,0x1e360000,0x1e370000,0x1e3a0000,0x1e3b0000,0x1e3c0000,0x1e3d0000] {
   let from=op&!0x10000==0x1e3c0000;
   for merge in [false,true]{for alias in [false,true]{
    let dst=if alias{1}else{0};let word=op|sf<<31|ftype<<22|1<<5|dst;
    let mut s=FloatState::new();let source=if from{7}else{match fw{16=>0x3e00,32=>0x3fc00000,_=>0x3ff8000000000000}};
    s.state.v(0,0xabcddcba12344321,0x1122334455667788);s.state.v(1,source,0xaabbccddeeff0011);
    s.state.reg("a64.fpcr",0,if merge{4}else{0});s.state.reg("a64.fpsr",0,0x08000000);
    let t=run_fp(word,&s);let output_width=if from{fw}else{iw};
    let expected=if from{match fw{16=>0x4700,32=>0x40e00000,_=>0x401c000000000000}}else{match op&!0x10000{0x1e340000|0x1e360000=>1,_=>2}};
    let oldlow=if alias{source}else{0xabcddcba12344321};let oldhi=if alias{0xaabbccddeeff0011}else{0x1122334455667788};
    assert_eq!(v(&t,dst as u16,0),expected|if merge{oldlow&!mask(output_width)}else{0},"{word:08x}");
    assert_eq!(v(&t,dst as u16,1),if merge{oldhi}else{0});assert_eq!(reg(&t,"a64.fpsr",0),0x08000000|if from{0}else{16});
    let trace=s.trace.borrow();assert_eq!(trace.len(),1);assert_eq!(trace[0].1,vec![source]);
    match trace[0].0{FloatOperation::FromInteger{source_width,signed,fractional_bits}=>{assert!(from);assert_eq!(source_width,iw);assert_eq!(signed,op&0x10000==0);assert_eq!(fractional_bits,0)},FloatOperation::ToInteger{source_width,signed,fractional_bits,..}=>{assert!(!from);assert_eq!(source_width,fw);assert_eq!(signed,op&0x10000==0);assert_eq!(fractional_bits,0)},_=>panic!("conversion operation")}
    assert!(t.registers.iter().all(|w|w.register.bank!="a64.gpr"));noflags(&t);
   }}
  }
 }
 for word in [0x1e2a0020,0x9e6a0020,0x1eaa0020,0x9eac0020]{assert!(matches!(recipes::for_word(word,0).support,Support::Unsupported(_)),"reserved conversion {word:08x}");}
}
#[test]fn negated_multiply_rounds_product_then_negates_and_merges_from_source(){
 for (ftype,onehalf,two,negative_three,w) in [(0,0x3fc00000u64,0x40000000,0xc0400000,32),(1,0x3ff8000000000000,0x4000000000000000,0xc008000000000000,64),(3,0x3e00,0x4000,0xc200,16)] {
  for merge in [false,true]{for alias in [false,true]{let dst=if alias{1}else{0};let word=0x1e228820|ftype<<22|dst;
   let mut s=FloatState::new();s.state.v(1,onehalf|0xaabbccdd00000000u64&!mask(w),0x123456789abcdef0);s.state.v(2,two,0);s.state.reg("a64.fpcr",0,if merge{4}else{0});s.state.reg("a64.fpsr",0,0x08000000);
   let t=run_fp(word,&s);assert_eq!(v(&t,dst as u16,0),negative_three|if merge{0xaabbccdd00000000u64&!mask(w)}else{0});assert_eq!(v(&t,dst as u16,1),if merge{0x123456789abcdef0}else{0});assert_eq!(reg(&t,"a64.fpsr",0),0x08000000);assert_eq!(t.trap,None);
  }}
 }
}
#[test]fn scalar_register_conversion_merge_ignores_overwritten_unavailable_low_chunk(){
 struct UnavailableLow(FloatState);
 impl Machine for UnavailableLow {
  fn read_register(&self,r:Register)->Value{if r.bank=="a64.vector64"&&r.index==0{Value::unknown(64)}else{self.0.read_register(r)}}
  fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.0.read_memory(a,w,e)}
  fn evaluate_float(&self,f:&FloatExpression,i:&[Value],c:Value,s:Value)->Result<Value,EvalError>{self.0.evaluate_float(f,i,c,s)}
 }
 for (word,input,expected) in [(0x9e2a0020u32,0x3fc00000u64,2u64),(0x9eea0020,0x3e00,2),(0x1e7c0020,7,0x401c000000000000)] {
  let mut s=FloatState::new();s.state.v(0,0,0x1122334455667788);s.state.v(1,input,0);s.state.reg("a64.fpcr",0,4);
  let r=decode(word).unwrap().semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);
  let t=evaluate(&r,&UnavailableLow(s)).unwrap();
  let low=t.registers.iter().find(|w|w.register.bank=="a64.vector64"&&w.register.index==0).unwrap();
  assert_eq!(low.value,Value::known(64,expected),"{word:08x}");assert_eq!(v(&t,0,1),0x1122334455667788);
 }
}
`

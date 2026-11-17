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

// Compile a fresh public decoder and recipe surface, with no hand-written
// Decoded stand-in. The independent physical fixtures below are checked against
// all thirteen classes in the five June primary pages before Rust is compiled.
func TestRustA32PreloadHints(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32PreloadPrimary(t, path)
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
	dir, err := os.MkdirTemp(base, "a32-hints-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "hints.rs"), []byte(a32PreloadBehavior+primary), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "arm32", "--crate-type", "lib", "src/lib.rs", "-Dwarnings", "-o", "libarm32.rlib"},
		{"--edition=2021", "--test", "hints.rs", "--extern", "arm32=libarm32.rlib", "-Dwarnings", "-o", "hint-tests"},
		{"./hint-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated A32 hints %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a32PreloadPrimary(t *testing.T, path string) string {
	t.Helper()
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Hi    int    `xml:"hibit,attr"`
		Cells []cell `xml:"c"`
	}
	type encoding struct {
		Name string `xml:"name,attr"`
	}
	type class struct {
		Name    string `xml:"name,attr"`
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	type physical struct {
		mask, value uint32
		ids         string
	}
	expected := map[string]physical{
		"pld_i/A1": {0xff30f000, 0xf510f000, "PLD_i_A1 PLDW_i_A1"},
		"pld_i/T1": {0xffd0f000, 0xf890f000, "PLD_i_T1 PLDW_i_T1"},
		"pld_i/T2": {0xffd0ff00, 0xf810fc00, "PLD_i_T2 PLDW_i_T2"},
		"pld_l/A1": {0xff7ff000, 0xf55ff000, "PLD_l_A1"},
		"pld_l/T1": {0xff7ff000, 0xf81ff000, "PLD_l_T1"},
		"pld_r/A1": {0xff30f010, 0xf710f000, "PLD_r_A1 PLD_r_A1_RRX PLDW_r_A1 PLDW_r_A1_RRX"},
		"pld_r/T1": {0xffd0ffc0, 0xf810f000, "PLD_r_T1 PLDW_r_T1"},
		"pli_i/A1": {0xff70f000, 0xf450f000, "PLI_i_A1"},
		"pli_i/T1": {0xfff0f000, 0xf990f000, "PLI_i_T1"},
		"pli_i/T2": {0xfff0ff00, 0xf910fc00, "PLI_i_T2"},
		"pli_i/T3": {0xff7ff000, 0xf91ff000, "PLI_i_T3"},
		"pli_r/A1": {0xff70f010, 0xf650f000, "PLI_r_A1_RRX PLI_r_A1"},
		"pli_r/T1": {0xfff0ffc0, 0xf910f000, "PLI_r_T1"},
	}
	selected := map[string]bool{}
	for _, n := range strings.Fields("pld_i pld_l pld_r pli_i pli_r") {
		selected[n+".xml"] = true
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
	seen := map[string]bool{}
	ids := map[string]bool{}
	var fixtures strings.Builder
	fixtures.WriteString("\n#[test] fn all_primary_classes_and_encoding_identities(){\nfor(word,thumb,id)in[\n")
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(h.Name)
		if !strings.HasPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !selected[name] || seen[name] {
			continue
		}
		seen[name] = true
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err = xml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			key := strings.TrimSuffix(name, ".xml") + "/" + cl.Name
			want, ok := expected[key]
			if !ok {
				t.Fatalf("unhandled primary class %s", key)
			}
			var mask, value uint32
			for _, b := range cl.Diagram.Boxes {
				pos := b.Hi
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					text := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(text) == 1 && span > 1 && (text == "0" || text == "1") {
						text = strings.Repeat(text, span)
					}
					if len(text) != span {
						text = strings.Repeat("x", span)
					}
					for _, bit := range text {
						if bit == '0' || bit == '1' {
							mask |= 1 << uint(pos)
							if bit == '1' {
								value |= 1 << uint(pos)
							}
						}
						pos--
					}
				}
			}
			if mask != want.mask || value != want.value {
				t.Fatalf("%s primary diagram %08x/%08x, expected %08x/%08x", key, mask, value, want.mask, want.value)
			}
			var names []string
			for _, e := range cl.Encodings {
				names = append(names, e.Name)
				ids[e.Name] = true
				word := value
				if mask&0x000f0000 == 0 {
					word |= 2 << 16
				}
				if strings.HasPrefix(e.Name, "PLD_i_A1") || strings.HasPrefix(e.Name, "PLD_r_A1") {
					word |= 1 << 22
				}
				if strings.HasPrefix(e.Name, "PLDW_") && cl.ISA == "T32" {
					word |= 1 << 21
				}
				if strings.Contains(e.Name, "_r_") {
					word |= 3
					if strings.HasSuffix(e.Name, "_RRX") {
						word |= 3 << 5
					}
				}
				fmt.Fprintf(&fixtures, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", e.Name)
			}
			if strings.Join(names, " ") != want.ids {
				t.Fatalf("%s primary encoding identities changed: %v", key, names)
			}
			delete(expected, key)
		}
	}
	if len(seen) != 5 || len(expected) != 0 || len(ids) != 21 {
		t.Fatalf("primary coverage: pages=%d, remaining=%v, ids=%d", len(seen), expected, len(ids))
	}
	fixtures.WriteString("]{let d=decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");assert_hint(word,thumb);}}\n")
	t.Log("primary qualification: 5 pages, 13 physical classes, 21 encoding identities")
	return fixtures.String()
}

const a32PreloadBehavior = `use arm32::{decode,Decoded,Mode,Endian as CodeEndian};
use arm32::semantics::*;
use std::cell::RefCell;
struct State{it:Option<u8>,z:Option<bool>,reads:RefCell<Vec<&'static str>>}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{self.reads.borrow_mut().push(r.bank);match(r.bank,r.index){
 ("a32.itstate",0)=>self.it.map(|v|Value::known(8,u64::from(v))).unwrap_or(Value::unknown(8)),
 ("a32.nzcv",1)=>self.z.map(|v|Value::known(1,u64::from(v))).unwrap_or(Value::unknown(1)),
 _=>panic!("ignored hint unexpectedly reads {r:?}")}}
 fn read_memory(&self,a:u64,w:u8,_:Endian)->Result<Value,EvalError>{panic!("ignored hint touches memory {a:x}/{w}")}
}
fn decoded(word:u32,thumb:bool,endian:CodeEndian)->Decoded{
 let bytes=bytes(word,thumb,endian);let mode=if thumb{Mode::Thumb}else{Mode::Arm};
 let d=decode(&bytes,mode,endian).unwrap_or_else(|e|panic!("decode {word:08x}/{thumb}: {e:?}"));assert_eq!(d.raw(),word);assert_eq!(d.length,4);d
}
fn bytes(word:u32,thumb:bool,endian:CodeEndian)->Vec<u8>{
 if thumb{let halves=[(word>>16)as u16,word as u16];halves.into_iter().flat_map(|h|match endian{CodeEndian::Little=>h.to_le_bytes(),CodeEndian::Big=>h.to_be_bytes()}).collect()}
 else{match endian{CodeEndian::Little=>word.to_le_bytes(),CodeEndian::Big=>word.to_be_bytes()}.to_vec()}
}
fn no_inputs(it:Option<u8>,z:Option<bool>)->State{State{it,z,reads:RefCell::new(vec![])}}
fn assert_hint(word:u32,thumb:bool){
 for code in[CodeEndian::Little,CodeEndian::Big]{for data in[Endian::Little,Endian::Big]{
  let d=decoded(word,thumb,code);let r=d.semantic_recipe_with_endian(0xffff_fffd,data);
  assert_eq!(r.support,Support::Full,"{word:08x} {}",d.encoding_id());r.validate().unwrap();
  assert!(r.effects.is_empty()&&r.temporaries.is_empty()&&r.wide_loads.is_empty()&&r.atomics.is_empty()&&r.choices.is_empty());
  assert_eq!(r.always_writes.len(),usize::from(thumb));
  let s=no_inputs(if thumb{Some(0)}else{None},None);let t=evaluate(&r,&s).unwrap();
  assert_eq!(t.next_pc,Value::known(32,1));assert!(t.memory.is_empty()&&t.wide_memory.is_empty()&&t.events.is_empty()&&t.atomics.is_empty()&&t.trap.is_none());
  assert_eq!(t.registers.len(),usize::from(thumb));
  if thumb{assert_eq!(t.registers[0].register.bank,"a32.itstate");assert_eq!(t.registers[0].value,Value::known(8,0));assert!(s.reads.borrow().iter().all(|b|*b=="a32.itstate"));}
  else{assert!(s.reads.borrow().is_empty())}
 }}
}
#[test]fn all_immediate_signs_limits_bases_and_literal_redirects(){
 // (base,Thumb,immediate width,variable U). Literal encodings preserve PC bits.
 for(base,thumb,width,u)in[(0xf510f000,false,12,true),(0xf550f000,false,12,true),(0xf450f000,false,12,true),
 (0xf890f000,true,12,false),(0xf8b0f000,true,12,false),(0xf990f000,true,12,false),
 (0xf810fc00,true,8,false),(0xf830fc00,true,8,false),(0xf910fc00,true,8,false)]{
  for n in[0,13,14]{for imm in[0,1,(1<<width)-1]{for add in[false,true]{if !u&&add{continue}let word=base|(n<<16)|imm|if u&&add{1<<23}else{0};assert_hint(word,thumb);}}}
 }
 for(base,thumb,id)in[(0xf55ff000,false,"PLD_l_A1"),(0xf81ff000,true,"PLD_l_T1"),(0xf91ff000,true,"PLI_i_T3")]{
  for add in[false,true]{for imm in[0,15,63,255,4095]{let word=base|imm|if add{1<<23}else{0};assert_eq!(decoded(word,thumb,CodeEndian::Little).encoding_id(),id);assert_hint(word,thumb);}}
 }
 // PLI A1 permits PC base, whereas PLDW has no literal encoding.
 for add in[0,1]{assert_hint(0xf45ff000|(add<<23)|4095,false);}
}
#[test]fn every_register_shift_r13_and_pc_rules(){
 for(base,prefix,write_hint)in[(0xf750f000,"PLD",false),(0xf710f000,"PLDW",true),(0xf650f000,"PLI",false)]{
  for n in[0,13,14,15]{if n==15&&write_hint{continue}for m in[0,13,14]{for add in[0,1]{for kind in 0..4{for shift in 0..32{
   let word=base|(n<<16)|(add<<23)|(shift<<7)|(kind<<5)|m;
   let id=format!("{prefix}_r_A1{}",if kind==3&&shift==0{"_RRX"}else{""});assert_eq!(decoded(word,false,CodeEndian::Little).encoding_id(),id);assert_hint(word,false);
  }}}}}
 }
 for(base,id)in[(0xf810f000,"PLD_r_T1"),(0xf830f000,"PLDW_r_T1"),(0xf910f000,"PLI_r_T1")]{
  for n in[0,13,14]{for m in[0,13,14]{for shift in 0..4{let word=base|(n<<16)|(shift<<4)|m;assert_eq!(decoded(word,true,CodeEndian::Little).encoding_id(),id);assert_hint(word,true);}}}
 }
 // Rn==PC is a literal redirect in Thumb, not a register source, so an
 // immediate ending in 0xf is legal even though Rm==PC is not.
 for base in[0xf81ff000,0xf91ff000]{for imm in[15,31,63]{assert_hint(base|imm,true);}}
}
#[test]fn thumb_it_true_false_unknown_and_pipeline(){
 for word in[0xf892f000,0xf8b2f000,0xf812fcff,0xf832fc00,0xf992f000,0xf912fc00,0xf81fffff,0xf91fffff,0xf812f03d,0xf832f03d,0xf912f03d]{
  let d=decoded(word,true,CodeEndian::Little);let r=d.semantic_recipe(0x1000);
  for it in[0x08,0x0c,0x18,0x1c]{for z in[false,true]{let s=no_inputs(Some(it),Some(z));let t=evaluate(&r,&s).unwrap();
   let expected=if it&7==0{0}else{(it&0xe0)|((it<<1)&31)};assert_eq!(t.next_pc,Value::known(32,0x1004));assert_eq!(t.registers.len(),1);assert_eq!(t.registers[0].value,Value::known(8,u64::from(expected)));}}
  assert_eq!(evaluate(&r,&no_inputs(Some(8),None)),Err(EvalError::UnknownCondition));
  assert_eq!(evaluate(&r,&no_inputs(None,None)),Err(EvalError::UnknownCondition));
  assert_eq!(evaluate(&r,&no_inputs(Some(0xf8),None)),Err(EvalError::UnsupportedContext));
  assert_eq!(evaluate(&r,&no_inputs(Some(0x10),None)),Err(EvalError::UnsupportedContext));
 }
}
#[test]fn every_thumb_condition_uses_only_it_and_flags_and_advances_when_false(){
 struct Flags{it:u8,nzcv:u8}
 impl Machine for Flags{
  fn read_register(&self,r:Register)->Value{match r.bank{
   "a32.itstate"=>{assert_eq!(r.index,0);Value::known(8,u64::from(self.it))},
   "a32.nzcv"=>{assert!(r.index<4);Value::known(1,u64::from((self.nzcv>>r.index)&1))},
   _=>panic!("conditional ignored hint read {r:?}")}}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("conditional ignored hint accessed memory")}
 }
 for word in[0xf892f000,0xf8b2ffff,0xf812fcff,0xf832fc00,0xf992ffff,0xf912fc00,0xf81fffff,0xf91fffff,0xf812f03d,0xf832f03d,0xf912f03d]{
  let r=decoded(word,true,CodeEndian::Little).semantic_recipe(0xffff_fffc);
  for condition in 0u8..14{for mask in[8,12,14,15]{for nzcv in 0u8..16{
   let state=Flags{it:(condition<<4)|mask,nzcv};
   let n=nzcv&1!=0;let z=nzcv&2!=0;let c=nzcv&4!=0;let v=nzcv&8!=0;
   let passed=match condition{0=>z,1=>!z,2=>c,3=>!c,4=>n,5=>!n,6=>v,7=>!v,8=>c&&!z,9=>!c||z,10=>n==v,11=>n!=v,12=>!z&&n==v,13=>z||n!=v,_=>unreachable!()};
   assert_eq!(evaluate_expression(&r.guard,&state,&[]).unwrap(),Value::known(1,u64::from(passed)),"{word:08x} condition{condition} NZCV{nzcv:x}");
   let t=evaluate(&r,&state).unwrap();assert_eq!(t.next_pc,Value::known(32,0));assert_eq!(t.registers.len(),1);
   let advanced=if mask&7==0{0}else{(state.it&0xe0)|((state.it<<1)&31)};
   assert_eq!(t.registers[0].value,Value::known(8,u64::from(advanced)));assert_eq!(t.registers[0].register.bank,"a32.itstate");
   assert!(t.memory.is_empty()&&t.wide_memory.is_empty()&&t.events.is_empty()&&t.trap.is_none());
  }}}
 }
}
#[test]fn excluded_operands_and_neighboring_loads_are_not_ignored(){
 for(word,thumb)in[(0xf51ff000,false),(0xf71ff000,false),(0xf752f00f,false),(0xf652f06f,false),
 (0xf8bff000,true),(0xf83ffc00,true),(0xf83ff00f,true),(0xf832f00f,true),(0xf812f00f,true),(0xf912f00f,true)]{
  // Raw builders must reject these even if a decoder retains an unpredictable
  // form for analysis. The public path may instead reject at decode time.
  let r=if thumb{arm32::recipes::for_thumb(word,4,0,Endian::Little)}else{arm32::recipes::for_word(word,0)};
  assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x} {:?}",r.support);
  if let Ok(d)=decode(&bytes(word,thumb,CodeEndian::Little),if thumb{Mode::Thumb}else{Mode::Arm},CodeEndian::Little){assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"{word:08x} {}",d.encoding_id());}
 }
 // All non-PC Rt values belong outside these hint allocations. Decode may
 // reject the neighbor (e.g. an unavailable signed-byte load destination).
 for(base,thumb)in[(0xf552f000,false),(0xf452f000,false),(0xf752f003,false),(0xf652f003,false),
 (0xf892f000,true),(0xf8b2f000,true),(0xf812fc00,true),(0xf832fc00,true),(0xf992f000,true),(0xf912fc00,true),(0xf812f003,true),(0xf832f003,true),(0xf912f003,true)]{
  for rt in 0..15{let word=(base&!0xf000)|(rt<<12);let mode=if thumb{Mode::Thumb}else{Mode::Arm};
   let raw=if thumb{arm32::recipes::for_thumb(word,4,0,Endian::Little)}else{arm32::recipes::for_word(word,0)};
   assert!(raw.support!=Support::Full||!raw.effects.is_empty()||!raw.wide_loads.is_empty(),"raw neighbor became an empty Full recipe: {word:08x}");
   if let Ok(d)=decode(&bytes(word,thumb,CodeEndian::Little),mode,CodeEndian::Little){assert!(!d.encoding_id().starts_with("PL"),"{word:08x}: {}",d.encoding_id());
    let public=d.semantic_recipe(0);assert!(public.support!=Support::Full||!public.effects.is_empty()||!public.wide_loads.is_empty(),"decoded neighbor became an empty Full recipe: {word:08x}");
   }
  }
 }
 // Rt neighbors are actual byte/signed-byte loads, not ignored prefetches.
 for word in[0xf8920000,0xf9920000,0xf8120c00,0xf9120c00,0xf8120003,0xf9120003]{
  let d=decoded(word,true,CodeEndian::Little);assert!(!d.encoding_id().starts_with("PL"));let r=d.semantic_recipe(0);assert!(!r.effects.is_empty()||!r.wide_loads.is_empty()||r.support!=Support::Full,"{word:08x}: {}",d.encoding_id());
 }
 // Should-be bits are pinned by the generated catalog. Flipping D changes
 // PLD into PLI (and conversely), while clearing L leaves these hint classes.
 for(word,thumb)in[(0xf550f000,false),(0xf450f000,false),(0xf750f003,false),(0xf650f003,false)]{
  let changed=decoded(word^(1<<24),thumb,CodeEndian::Little);assert_ne!(changed.encoding_id(),decoded(word,thumb,CodeEndian::Little).encoding_id());assert_hint(word^(1<<24),thumb);
  let neighbor=word^(1<<20);if let Ok(d)=decode(&bytes(neighbor,thumb,CodeEndian::Little),Mode::Arm,CodeEndian::Little){assert!(!d.encoding_id().starts_with("PL"),"{neighbor:08x}: {}",d.encoding_id());}
 }
 for word in[0xf812f043,0xf912f043,0xf812fd00,0xf912fd00,0xf802f000,0xf902f000]{
  if let Ok(d)=decode(&bytes(word,true,CodeEndian::Little),Mode::Thumb,CodeEndian::Little){assert!(!d.encoding_id().starts_with("PL"),"{word:08x}: {}",d.encoding_id());}
 }
}
`

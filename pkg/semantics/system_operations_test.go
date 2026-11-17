package semantics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"

	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

// Compile the module emitted by the production generator, rather than a copy of
// its helpers. The machine tests exercise expressions, predication, transitions
// and explicit failure behavior. When the published Arm archives are installed,
// also derive instruction words directly from their physical register diagrams.
func TestRustSystemOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := WriteRust(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "arm32"), 0755); err != nil {
		t.Fatal(err)
	}
	for output, source := range map[string]string{
		"a64_recipes.rs":   "rust/recipes.rs.tmpl",
		"arm32/recipes.rs": "arm32_rust/recipes.rs.tmpl",
	} {
		tmpl, err := template.New("recipes").ParseFS(assettemplates.FS, source)
		if err != nil {
			t.Fatal(err)
		}
		var rendered bytes.Buffer
		if err := tmpl.ExecuteTemplate(&rendered, filepath.Base(source), nil); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, output), rendered.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	source := systemOperationTests + systemGeneratedDispatchTests + systemCorpusCases(t)
	if err := os.WriteFile(filepath.Join(dir, "system_tests.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "system_tests.rs", "-Dwarnings", "-o", "system-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile generated system operations: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "system-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute generated system operations: %v\n%s", err, out)
	}
}

type systemCorpusDiagram struct {
	Form  string `xml:"form,attr"`
	Boxes []struct {
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Name  string `xml:"name,attr"`
		Cells []struct {
			Text string `xml:",chardata"`
		} `xml:"c"`
	} `xml:"box"`
}

func systemCorpusCases(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "Documents", "Developer", "go-mkasm")
	archives := []struct {
		Path, Prefix string
		Arch         int
	}{
		{filepath.Join(root, "architecture-expansion", "ISA_A64_xml_A_profile-2026-06.tar.gz"), "ISA_A64_xml_A_profile-2026-06/", 64},
		{filepath.Join(root, "ISA_AArch32_xml_A_profile-2026-06.tar.gz"), "ISA_AArch32_xml_A_profile-2026-06/", 32},
	}
	var result strings.Builder
	result.WriteString("\nconst CORPUS_WORDS: &[(u32,u32,usize)] = &[\n")
	count := 0
	for _, archive := range archives {
		file, err := os.Open(archive.Path)
		if os.IsNotExist(err) {
			t.Logf("optional Arm corpus absent: %s", archive.Path)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		compressed, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		reader := tar.NewReader(compressed)
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(header.Name, archive.Prefix) {
				continue
			}
			name := strings.TrimPrefix(header.Name, archive.Prefix)
			switch name {
			case "dmb.xml", "dsb.xml", "isb.xml", "clrex.xml", "bkpt.xml", "udf.xml", "brk.xml", "cfinv.xml", "axflag.xml", "xaflag.xml", "sb.xml", "vmrs.xml", "vmsr.xml":
			default:
				continue
			}
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
				arch, length := archive.Arch, 4
				if diagram.Form == "16x2" || diagram.Form == "16" {
					arch = 16
				}
				if diagram.Form == "16" {
					length = 2
				}
				// The nXS DSB form has a separate environment contract. Keep it
				// out of the supported corpus subset, and assert rejection below.
				nxs := false
				for _, box := range diagram.Boxes {
					nxs = nxs || box.Name == "imm2"
				}
				if nxs {
					continue
				}
				options := 1
				if name == "dmb.xml" || name == "dsb.xml" || name == "isb.xml" || (name == "clrex.xml" && arch == 64) {
					options = 16
				}
				for option := 0; option < options; option++ {
					var word uint32
					for _, box := range diagram.Boxes {
						width := box.Width
						if width == 0 {
							width = 1
						}
						var bits strings.Builder
						for _, cell := range box.Cells {
							text := strings.Trim(strings.TrimSpace(cell.Text), "()")
							if text == "0" || text == "1" {
								bits.WriteString(text)
							}
						}
						value := uint64(0)
						if bits.Len() == width {
							value, err = strconv.ParseUint(bits.String(), 2, 32)
							if err != nil {
								t.Fatal(err)
							}
						} else if box.Name == "cond" {
							value = 14
						} else if box.Name == "reg" && (name == "vmrs.xml" || name == "vmsr.xml") {
							value = 1 // FPSCR, without privileged FPSID/MVFR/FPEXC aliases.
						} else if box.Name == "CRm" || box.Name == "option" {
							value = uint64(option)
						}
						word |= uint32(value) << uint(box.Hi-width+1)
					}
					fmt.Fprintf(&result, "(%d,0x%08x,%d), // %s\n", arch, word, length, name)
					count++
				}
			}
		}
		compressed.Close()
		file.Close()
	}
	result.WriteString("];\n")
	t.Logf("derived %d physical system encodings from Arm corpus", count)
	return result.String()
}

const systemOperationTests = `
#[allow(dead_code)] pub mod semantics;
use semantics::*;
#[derive(Default)]
struct State { gpr:[u64;32], flags:[u64;4], q:u64, fpcr:u64, fpsr:u64, fpscr:u64, fp_mask:u64, it:u64 }
impl Machine for State {
    fn read_register(&self, r:Register)->Value {
        let (width,bits) = match r.bank {
            "a64.dsb_nxs" => (1,0),
            "a64.system_hint_features" => (8,255),
            "a64.gpr" => (64,self.gpr[r.index as usize]),
            "a32.gpr" => (32,self.gpr[r.index as usize]),
            "a64.nzcv" | "a32.nzcv" => (1,self.flags[r.index as usize]),
            "a32.q" => {assert_eq!(r.index,0);(1,self.q)},
            "a64.fpcr" => {assert_eq!(r.index,0);(32,self.fpcr)},
            "a64.fpsr" => {assert_eq!(r.index,0);(32,self.fpsr)},
            "a32.fpscr" => {assert_eq!(r.index,0);(32,self.fpscr)},
            "a64.fpcr_write_mask" | "a32.fpscr_write_mask" => (32,self.fp_mask),
            "a32.itstate" => {assert_eq!(r.index,0);(8,self.it)},
            _ => panic!("uncontracted register {r:?}"),
        };
        Value::known(width,bits)
    }
    fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("system instruction read memory")}
}
fn output(t:&Transition,bank:&str,index:u16)->u64 {
    t.registers.iter().find(|w|w.register.bank==bank && w.register.index==index).unwrap().value.bits
}
fn base(active:bool)->Recipe {let mut r=Recipe::new(0x1004,32);r.guard=Expr::constant(1,u64::from(active));r}
fn thumb_base(active:bool)->Recipe {
    let mut r=base(active);
    r.write_always(register("a32.itstate",0,8,8),WritePolicy::ZeroUpper,Expr::constant(8,0x18));r
}
struct UnavailableState;
impl Machine for UnavailableState {
    fn read_register(&self,_:Register)->Value {panic!("unsupported recipe consulted architectural state")}
    fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("unsupported recipe consulted memory")}
}
fn assert_unsupported(r:Recipe) {
    assert!(matches!(r.support,Support::Unsupported(_)),"{:?}",r.support);
    assert_eq!(evaluate(&r,&UnavailableState),Err(EvalError::Unsupported));
    assert!(r.effects.is_empty());
}
#[test] fn nzcv_transfers_use_the_same_flags_as_integer_recipes() {
    for bits in 0..16u64 {
        let mut s=State::default();
        for i in 0..4 {s.flags[i]=(bits>>(3-i))&1;}
        for rt in 0..32u32 {
            let r=system::a64(0xd53b4200|rt,0x1000).unwrap();assert_eq!(r.support,Support::Full);
            let t=evaluate(&r,&s).unwrap();assert_eq!(t.next_pc.bits,0x1004);
            if rt==31 {assert!(t.registers.is_empty());} else {
                assert_eq!(t.registers.len(),1);assert_eq!(output(&t,"a64.gpr",rt as u16),bits<<28);
            }
            s.gpr[rt as usize]=0xffff_ffff_0fff_ffff|(bits<<28);
            let r=system::a64(0xd51b4200|rt,0x1000).unwrap();
            let t=evaluate(&r,&s).unwrap();assert_eq!(t.registers.len(),4);
            for i in 0..4 {assert_eq!(output(&t,"a64.nzcv",i),if rt==31 {0}else{(bits>>(3-i))&1});}
        }
    }
    // Sequential evaluation keeps a real producer/consumer flag identity.
    let mut s=State::default();s.gpr[5]=0xa0000000;
    let t=evaluate(&system::a64(0xd51b4205,0x1000).unwrap(),&s).unwrap();
    for w in t.registers {s.flags[w.register.index as usize]=w.value.bits;}
    let t=evaluate(&system::a64(0xd53b4207,0x1004).unwrap(),&s).unwrap();
    assert_eq!(output(&t,"a64.gpr",7),0xa0000000);
}
#[test] fn fp_status_transfers_have_width_and_reserved_bit_semantics() {
    let mut s=State::default();s.fpcr=0x07c80007;s.fpsr=u32::MAX as u64;s.gpr[9]=u64::MAX;
    for (encoding,expected) in [(0xd53b4409,0x07c80007),(0xd53b4429,0x0800009f)] {
        let t=evaluate(&system::a64(encoding,0).unwrap(),&s).unwrap();
        assert_eq!(output(&t,"a64.gpr",9),expected);assert_eq!(t.registers[0].value.width,64);
    }
    for (rt,expected) in [(9,0x0800009f),(31,0)] {
        let t=evaluate(&system::a64(0xd51b4420|rt,0).unwrap(),&s).unwrap();
        assert_eq!(output(&t,"a64.fpsr",0),expected);assert_eq!(t.registers[0].value.width,32);
    }
    for mask in [0,0x00c00000,0x07c80007] {
        s.fp_mask=mask;
        let t=evaluate(&system::a64(0xd51b4409,0).unwrap(),&s).unwrap();
        assert_eq!(output(&t,"a64.fpcr",0),(s.fpcr&!mask)|(s.gpr[9]&mask));
    }
    for mask in [0,0x00c00000,0x07c80007] {
        for rt in [9,31] {
            let r=system::a64_with_fpcr_write_mask(0xd51b4400|rt,0x1000,mask).unwrap();
            assert_eq!(r.support,Support::Full);
            let t=evaluate(&r,&s).unwrap();
            let incoming=if rt==31 {0}else{s.gpr[9] as u32};
            assert_eq!(output(&t,"a64.fpcr",0),u64::from((s.fpcr as u32 & !mask)|(incoming&mask)));
        }
    }
    assert_eq!(system::a64_with_fpcr_write_mask(0xd53b4209,0,0),system::a64(0xd53b4209,0));
}
#[test] fn pstate_flag_conversions_observe_a_single_incoming_snapshot() {
    for bits in 0..16u64 {
        let mut s=State::default();for i in 0..4 {s.flags[i]=(bits>>(3-i))&1;}
        let [_,z,c,v]=s.flags;
        for (word,expected) in [
            (0xd500403f,[(1-c)&(1-z),z&c,c|z,(1-c)&z]),
            (0xd500405f,[0,z|v,c&(1-v),0]),
        ] {
            let t=evaluate(&system::a64(word,0).unwrap(),&s).unwrap();
            for i in 0..4 {assert_eq!(output(&t,"a64.nzcv",i),expected[i as usize]);}
        }
        let t=evaluate(&system::a64(0xd500401f,0).unwrap(),&s).unwrap();
        assert_eq!(t.registers.len(),1);assert_eq!(output(&t,"a64.nzcv",2),1-c);
    }
}
#[test] fn a32_vfp_status_transfers_preserve_distinct_integer_and_fp_flags() {
    for bits in 0..16u64 {for rt in 0..16u32 {for active in [false,true] {
        let mut s=State::default();s.fpscr=(bits<<28)|0x0800009f;s.q=1;
        for r in [system::a32(0x0ef10a10|(rt<<12),base(active)).unwrap(),
                  system::thumb(0xeef10a10|(rt<<12),4,thumb_base(active)).unwrap()] {
            let t=evaluate(&r,&s).unwrap();
            if active && rt==15 {
                for i in 0..4 {assert_eq!(output(&t,"a32.nzcv",i),(bits>>(3-i))&1);}
            } else if active {assert_eq!(output(&t,"a32.gpr",rt as u16),s.fpscr);}
            else {assert!(t.registers.iter().all(|w|w.register.bank=="a32.itstate"));}
            assert!(t.registers.iter().all(|w|w.register.bank!="a32.q" && w.register.bank!="a32.fpscr"));
            if !r.always_writes.is_empty() {assert_eq!(output(&t,"a32.itstate",0),0x18);}
        }
    }}}
    let mut s=State::default();s.fpscr=0xa800009f;s.gpr[7]=0x55ffffff;
    for mask in [0,0xf800009f,0x07c00000] {for active in [false,true] {
        let a32=system::a32_with_fpscr_write_mask(0x0ee17a10,base(active),mask).unwrap();
        let thumb=system::thumb_with_fpscr_write_mask(0xeee17a10,4,thumb_base(active),mask).unwrap();
        for r in [a32,thumb] {
            let t=evaluate(&r,&s).unwrap();
            if active {assert_eq!(output(&t,"a32.fpscr",0),u64::from((s.fpscr as u32&!mask)|(s.gpr[7] as u32&mask)));}
            else {assert!(t.registers.iter().all(|w|w.register.bank=="a32.itstate"));}
            assert!(t.registers.iter().all(|w|w.register.bank!="a32.nzcv" && w.register.bank!="a32.q"));
        }
    }}
    for mask in [0,0xf0000000,0xfff79f9f] {
        let mut state=State::default(); state.fp_mask=mask;state.fpscr=0x55aa55aa;state.gpr[7]=0xa5a5a5a5;
        for recipe in [system::a32(0xeee17a10,base(true)).unwrap(),system::thumb(0xeee17a10,4,base(true)).unwrap()] {
            let t=evaluate(&recipe,&state).unwrap();
            assert_eq!(output(&t,"a32.fpscr",0),(state.fpscr&!mask)|(state.gpr[7]&mask));
        }
    }
    assert_unsupported(system::a32_with_fpscr_write_mask(0xeee1fa10,base(true),u32::MAX).unwrap());
    assert_unsupported(system::thumb_with_fpscr_write_mask(0xeee1fa10,4,base(true),u32::MAX).unwrap());
    assert_eq!(system::a32_with_fpscr_write_mask(0xeef17a10,base(true),0),system::a32(0xeef17a10,base(true)));
    assert_eq!(system::thumb_with_fpscr_write_mask(0xeef17a10,4,base(true),0),system::thumb(0xeef17a10,4,base(true)));
}
#[test] fn apsr_nzcvq_writes_include_q_and_honor_a32_and_thumb_predication() {
    for bits in 0..32u64 {for active in [false,true] {
        let mut s=State::default();s.gpr[6]=0x07ffffff|(bits<<27);s.q=1;
        for r in [system::a32(0x0128f006,base(active)).unwrap(),system::thumb(0xf3868800,4,thumb_base(active)).unwrap()] {
            let t=evaluate(&r,&s).unwrap();
            if active {
                for i in 0..4 {assert_eq!(output(&t,"a32.nzcv",i),(bits>>(4-i))&1);}
                assert_eq!(output(&t,"a32.q",0),bits&1);
            } else {assert!(t.registers.iter().all(|w|w.register.bank=="a32.itstate"));}
            if !r.always_writes.is_empty() {assert_eq!(output(&t,"a32.itstate",0),0x18);}
        }
    }}
    // All A32 modified immediates exercise rotate expansion, including rotate 0.
    for imm in 0..4096u32 {
        let r=system::a32(0xe328f000|imm,base(true)).unwrap();
        let t=evaluate(&r,&State::default()).unwrap();
        let value=(imm&255).rotate_right(((imm>>8)&15)*2);
        for i in 0..4 {assert_eq!(output(&t,"a32.nzcv",i),u64::from((value>>(31-i))&1));}
        assert_eq!(output(&t,"a32.q",0),u64::from((value>>27)&1));
    }
}
fn expected_barrier(kind:BarrierKind,option:u32)->Barrier {
    let access=if matches!(kind,BarrierKind::InstructionSynchronization|BarrierKind::Speculation) {BarrierAccess::All}
        else {match option&3 {1=>BarrierAccess::Reads,2=>BarrierAccess::Writes,_=>BarrierAccess::All}};
    let scope=if kind==BarrierKind::DataSynchronization {match option {7=>BarrierScope::NonShareable,11=>BarrierScope::InnerShareable,_=>BarrierScope::System}}
        else {BarrierScope::System};
    Barrier{kind,scope,access}
}
#[test] fn barrier_options_match_2026_corpus_and_do_not_merge_store_bypass_barriers() {
    for option in 0..16u32 {
        for (a64,a32,thumb,kind) in [
            (0xd50330bf,0xf57ff050,0xf3bf8f50,BarrierKind::DataMemory),
            (0xd503309f,0xf57ff040,0xf3bf8f40,BarrierKind::DataSynchronization),
            (0xd50330df,0xf57ff060,0xf3bf8f60,BarrierKind::InstructionSynchronization),
        ] {
            let r=system::a64(a64|(option<<8),0).unwrap();
            if kind==BarrierKind::DataSynchronization && [0,4].contains(&option) {let kind=if option==0 {BarrierKind::StoreBypass}else{BarrierKind::PhysicalStoreBypass};assert_eq!(evaluate(&r,&State::default()).unwrap().events,[OrderedEvent::Barrier(Barrier{kind,scope:BarrierScope::System,access:BarrierAccess::All})]);}
            else {assert_eq!(evaluate(&r,&State::default()).unwrap().events,[OrderedEvent::Barrier(expected_barrier(kind,option))]);}
            // A32 cond=1111 cannot inherit an ordinary false condition.
            let r=system::a32(a32|option,base(false)).unwrap();
            assert_eq!(evaluate(&r,&State::default()).unwrap().events,[OrderedEvent::Barrier(expected_barrier(kind,option))]);
            for active in [false,true] {
                let r=system::thumb(thumb|option,4,thumb_base(active)).unwrap();
                let t=evaluate(&r,&State::default()).unwrap();
                if active {assert_eq!(t.events,[OrderedEvent::Barrier(expected_barrier(kind,option))]);}
                else {assert!(t.events.is_empty());}
                assert_eq!(output(&t,"a32.itstate",0),0x18);
            }
        }
    }
    let r=system::a64(0xd50330ff,0).unwrap();
    assert_eq!(evaluate(&r,&State::default()).unwrap().events,[OrderedEvent::Barrier(expected_barrier(BarrierKind::Speculation,15))]);
    let r=system::a32(0xf57ff070,base(false)).unwrap();
    assert_eq!(evaluate(&r,&State::default()).unwrap().events,[OrderedEvent::Barrier(expected_barrier(BarrierKind::Speculation,15))]);
    for active in [false,true] {
        let r=system::thumb(0xf3bf8f70,4,thumb_base(active)).unwrap();
        let t=evaluate(&r,&State::default()).unwrap();
        assert_eq!(t.events,[OrderedEvent::Barrier(expected_barrier(BarrierKind::Speculation,15))]);
        assert_eq!(output(&t,"a32.itstate",0),0x18);
        let mut s=State::default();s.it=0x18;
        assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));
    }
}
#[test] fn exclusive_clear_predication_and_debug_traps_keep_pipeline_contracts() {
    for option in 0..16 {
        let t=evaluate(&system::a64(0xd503305f|(option<<8),0).unwrap(),&State::default()).unwrap();
        assert_eq!(t.events,[OrderedEvent::ExclusiveMonitorClear]);
    }
    let t=evaluate(&system::a32(0xf57ff01f,base(false)).unwrap(),&State::default()).unwrap();
    assert_eq!(t.events,[OrderedEvent::ExclusiveMonitorClear]);
    for active in [false,true] {
        let r=system::thumb(0xf3bf8f2f,4,thumb_base(active)).unwrap();let t=evaluate(&r,&State::default()).unwrap();
        assert_eq!(t.events.len(),usize::from(active));assert_eq!(output(&t,"a32.itstate",0),0x18);
        for (word,length) in [(0xde45,2),(0xf7f1a456,4)] {
            let t=evaluate(&system::thumb(word,length,thumb_base(active)).unwrap(),&State::default()).unwrap();
            assert_eq!(t.trap,if active {Some(TrapKind::InvalidInstruction)}else{None});
            if active {assert!(t.registers.is_empty());}else{assert_eq!(output(&t,"a32.itstate",0),0x18);}
        }
        let t=evaluate(&system::thumb(0xbe45,2,thumb_base(active)).unwrap(),&State::default()).unwrap();
        assert_eq!(t.trap,Some(TrapKind::Breakpoint));assert!(t.registers.is_empty());
    }
    let t=evaluate(&system::a32(0xe1200374,base(false)).unwrap(),&State::default()).unwrap();
    assert_eq!(t.trap,Some(TrapKind::Breakpoint));
    for active in [false,true] {
        let t=evaluate(&system::a32(0x07f123f4,base(active)).unwrap(),&State::default()).unwrap();
        assert_eq!(t.trap,if active {Some(TrapKind::InvalidInstruction)}else{None});
    }
    for (word,kind) in [(0xd4202460,TrapKind::Breakpoint),(0x1234,TrapKind::InvalidInstruction)] {
        assert_eq!(evaluate(&system::a64(word,0).unwrap(),&State::default()).unwrap().trap,Some(kind));
    }
    assert_eq!(evaluate(&system::a64(0xd50330bf,u64::MAX-1).unwrap(),&State::default()).unwrap().next_pc.bits,2);
}
#[test] fn unavailable_privilege_and_pstate_contracts_are_explicit_failures() {
    for word in [0xd53b4220,0xd51b4220,0xd5034fdf,0xd5034fff] {assert_unsupported(system::a64(word,0).unwrap());}
    for mask in 1..16 {if mask!=8 {
        assert_unsupported(system::a32(0xe120f006|(mask<<16),base(true)).unwrap());
        assert_unsupported(system::a32(0xe320f006|(mask<<16),base(true)).unwrap());
        assert_unsupported(system::thumb(0xf3868000|(mask<<8),4,base(true)).unwrap());
    }}
    for word in [0xe168f006,0xe368f006,0xe128f00f,0xe10f0000,0xe14f0000] {
        assert_unsupported(system::a32(word,base(true)).unwrap());
    }
    for word in [0xf3968800,0xf38f8800,0xf3ef8000,0xf3ff8000] {
        assert_unsupported(system::thumb(word,4,base(true)).unwrap());
    }
}
#[test] fn physical_masks_do_not_admit_adjacent_instruction_classes() {
    for word in [0xd503211f,0xd51b4600,0xd53b4600,0xd503329e,0xd4200001,0x10000,0xd4000001] {
        assert!(system::a64(word,0).is_none(),"A64 {word:08x}");
    }
    for word in [0x11200070,0xf7f000f0,0xf57ef01f,0xe120e006,0xf128f006,0xeef00a10,0xfef10a10] {
        assert!(system::a32(word,base(true)).is_none(),"A32 {word:08x}");
    }
    for (word,length) in [(0x1234be00,2),(0x1234de00,2),(0xbe00,1),(0xf3bf8f2f,2),(0xf3af8f2f,4),(0xf3868801,4),(0x0ef10a10,4)] {
        assert!(system::thumb(word,length,base(true)).is_none(),"Thumb {word:08x}/{length}");
    }
    for word in [0xd503323f,0xd503363f,0xd5033a3f,0xd5033e3f] {assert_eq!(system::a64(word,0).unwrap().support,Support::Full);}
}
#[test] fn physical_words_from_published_corpus_reach_typed_helpers() {
    for &(arch,word,length) in CORPUS_WORDS {
        let r=match arch {64=>system::a64(word,0),32=>system::a32(word,base(true)),16=>system::thumb(word,length,base(true)),_=>unreachable!()};
        let r=r.unwrap_or_else(||panic!("corpus instruction missed: arch={arch} word={word:08x} length={length}"));
        if word&0x0fff0fff==0x0ee10a10 && (word>>12)&15==15 {assert_unsupported(r);}
        else {assert_eq!(r.support,Support::Full,"corpus arch={arch} word={word:08x}");evaluate(&r,&State::default()).unwrap();}
    }
}
`

// Rendered production recipe builders must reach the shared helpers before
// broad legacy masks. Minimal decoded wrappers only satisfy their impl blocks;
// these tests pass physical instruction words through the actual builders.
const systemGeneratedDispatchTests = `
pub struct Decoded {pub raw:u32}
#[allow(dead_code)] mod a64_recipes;
#[allow(dead_code)] mod arm32 {
    pub use crate::semantics;
    #[derive(PartialEq,Eq)] pub enum Mode {Arm,Thumb}
    pub struct Decoded {raw:u32,pub mode:Mode,pub length:usize}
    impl Decoded {pub fn raw(&self)->u32 {self.raw}}
    pub mod recipes;
}
#[test] fn generated_a64_builder_dispatch_preserves_system_state_identities() {
    let mut s=State::default();s.flags=[1,0,1,0];s.gpr[3]=u64::MAX;
    let r=a64_recipes::for_word(0xd53b4203,0x1000);
    assert_eq!(r.support,Support::Full);
    assert_eq!(output(&evaluate(&r,&s).unwrap(),"a64.gpr",3),0xa0000000);
    let r=a64_recipes::for_word(0xd51b4423,0x1000);
    assert_eq!(output(&evaluate(&r,&s).unwrap(),"a64.fpsr",0),0x0800009f);
    assert_eq!(a64_recipes::for_word(0xd51b4403,0x1000).support,Support::Full);
    assert_eq!(evaluate(&a64_recipes::for_word(0xd503309f,0x1000),&s).unwrap().events,[OrderedEvent::Barrier(Barrier{kind:BarrierKind::StoreBypass,scope:BarrierScope::System,access:BarrierAccess::All})]);
    let t=evaluate(&a64_recipes::for_word(0xd5033bbf,0x1000),&s).unwrap();
    assert_eq!(t.events,[OrderedEvent::Barrier(expected_barrier(BarrierKind::DataMemory,11))]);
}
#[test] fn generated_a32_and_thumb_builders_supply_real_predicates_and_it_advance() {
    let mut s=State::default();s.gpr[6]=0xf8000000;
    let r=arm32::recipes::for_word(0x0128f006,0x1000); // MSREQ APSR_nzcvq,R6.
    assert_eq!(r.support,Support::Full);
    assert!(evaluate(&r,&s).unwrap().registers.is_empty());
    s.flags[1]=1;
    let t=evaluate(&r,&s).unwrap();assert_eq!(output(&t,"a32.q",0),1);
    assert_eq!(output(&t,"a32.nzcv",0),1);
    s.fpscr=0xa800009f;s.it=0x0c;s.flags[1]=0;
    let r=arm32::recipes::for_thumb(0xeef1fa10,4,0x1000,Endian::Little);
    assert_eq!(r.support,Support::Full);
    let t=evaluate(&r,&s).unwrap();assert_eq!(t.registers.len(),1);
    assert_eq!(output(&t,"a32.itstate",0),0x18);
    s.flags[1]=1;
    let t=evaluate(&r,&s).unwrap();assert_eq!(output(&t,"a32.nzcv",0),1);
    assert_eq!(output(&t,"a32.nzcv",1),0);assert_eq!(output(&t,"a32.nzcv",2),1);
    assert_eq!(output(&t,"a32.itstate",0),0x18);
    for z in [0,1] {
        s.flags[1]=z;
        let r=arm32::recipes::for_thumb(0xf3bf8f70,4,0x1000,Endian::Little);
        assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));
    }
    s.it=0;
    let t=evaluate(&arm32::recipes::for_thumb(0xf3bf8f70,4,0x1000,Endian::Little),&s).unwrap();
    assert_eq!(t.events,[OrderedEvent::Barrier(expected_barrier(BarrierKind::Speculation,15))]);
    assert_eq!(output(&t,"a32.itstate",0),0);
}
`

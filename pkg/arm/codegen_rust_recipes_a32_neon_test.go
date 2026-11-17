package arm

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/semantics"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

func TestRustA32NeonIntegerExpansion(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	tmpl, err := template.New("neon-integer").ParseFS(assettemplates.FS, "arm32_rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err = execTmplWrite(tmpl, "recipes.rs.tmpl", filepath.Join(dir, "recipes.rs"), nil); err != nil {
		t.Fatal(err)
	}
	if err = semantics.WriteRust(dir); err != nil {
		t.Fatal(err)
	}
	wrapper := `#![allow(dead_code)]
 pub mod semantics;pub mod recipes;
 #[derive(PartialEq,Eq)]pub enum Mode{Arm,Thumb}
 pub struct Decoded{raw:u32,pub mode:Mode,pub length:usize}
 impl Decoded{pub fn raw(&self)->u32{self.raw}}
 `
	if err = os.WriteFile(filepath.Join(dir, "neon.rs"), []byte(wrapper+a32NeonIntegerTests+a32NeonIntegerCorpus(t)), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "neon.rs", "-Dwarnings", "-o", "neon-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile generated NEON: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "neon-tests"), "neon_integer::", "--test-threads=1")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute generated NEON: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// Fixtures come from June's actual diagrams in both execution states. They
// supplement arithmetic oracles below; labels never drive production dispatch.
func a32NeonIntegerCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/ISA_AArch32_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional June corpus unavailable")
		return "const NEON_CORPUS:&[(u32,bool,&str)]=&[];"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
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
	type class struct {
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	names := strings.Fields(`
vceq_r vcge_r vcgt_r vrecpe vrsqrte vhadd vhsub vrhadd vpadd_i vpaddl vpadal vpmax_i
vpmin_i vmax_i vmin_i vabd_i vaba vabal vabdl_i vaddhn vraddhn vsubhn vrsubhn vtst
vceq_i vcge_i vcgt_i vcle_i vclt_i vabs vneg vqabs vqneg vclz vcls vcnt
vext vtbl vswp vdup_r vdup_s vsra vrsra vmla_s vmls_s vmul_s vmull_s vmlal_s
vmlsl_s vqdmull vqdmlal vqdmlsl vqdmulh vqrdmulh vqrdmlah vqrdmlsh vmov_i vmvn_i vorr_i vbic_i
vmov_sr vmov_rs vsdot vsdot_s vudot vudot_s vusdot vusdot_s vsudot_s vsmmla vummla vusmmla
vadd_i vsub_i vand_r vbic_r veor vmvn_r vorn_r vorr_r vbsl vbit vbif vmla_i
vmls_i vmovl vmovn vqmovn vaddl vaddw vsubl vsubw vmull_i vmlal_i vmlsl_i vqadd
vqsub vqrshl vqshl_i vqshl_r vrshl vshl_r vshl_i vshr vrshr vsli vsri vshll
vshrn vrshrn vqshrn vqrshrn vrev16 vrev32 vrev64 vtrn vzip vuzp vld1_1 vld1_a
vld1_m vld2_1 vld2_a vld2_m vld3_1 vld3_a vld3_m vld4_1 vld4_a vld4_m vst1_1 vst1_m
vst2_1 vst2_m vst3_1 vst3_m vst4_1 vst4_m
`)
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var out strings.Builder
	out.WriteString("const NEON_CORPUS:&[(u32,bool,&str)]=&[\n")
	reader := tar.NewReader(gz)
	pages, words := 0, 0
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(h.Name), ".xml")
		if !strings.HasPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !wanted[name] {
			continue
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var p page
		if err = xml.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		pages++
		for _, cl := range p.Classes {
			// Mixed scalar/FP pages also contain VFP encodings. These fixtures own the
			// SIMD integer diagrams and leave that independently-tested section alone.
			scalarFP := false
			floatOnly := false
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "size" && b.Hi == 9 {
					scalarFP = true
				}
				if b.Name == "sz" && (name == "vceq_r" || name == "vcge_r" || name == "vcgt_r") {
					floatOnly = true
				}
				if b.Name == "F" {
					for _, c := range b.Cells {
						floatOnly = floatOnly || c.Text == "1"
					}
				}
			}
			if scalarFP || floatOnly {
				continue
			}
			for variant := 0; variant < 4; variant++ {
				var word uint32
				for _, b := range cl.Diagram.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					pos := b.Hi
					var fm, fv uint32
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						text := strings.Trim(strings.TrimSpace(c.Text), "()")
						if len(text) == span {
							for _, bit := range text {
								if bit == '0' || bit == '1' {
									fm |= 1 << uint(pos)
									if bit == '1' {
										fv |= 1 << uint(pos)
									}
								}
								pos--
							}
						} else {
							pos -= span
						}
					}
					value := uint32(0)
					switch b.Name {
					case "cond":
						value = 14
					case "Vd":
						value = 0
					case "Vn":
						value = 2
					case "Vm":
						value = 4
					case "Rt":
						value = 1
					case "U", "op":
						value = uint32(variant & 1)
						if b.Name == "op" && name == "vqshl_i" {
							value = 1
						}
					case "Q":
						value = uint32(variant >> 1)
					case "size":
						value = uint32(variant % 3)
						if strings.HasSuffix(name, "_s") || strings.HasPrefix(name, "vqd") || strings.HasPrefix(name, "vqrdm") {
							value = uint32(1 + variant%2)
						}
						if name == "vrecpe" || name == "vrsqrte" {
							value = 2
						}
						if name == "vcnt" || name == "vmvn_r" {
							value = 0
						}
						if name == "vrev16" {
							value = 0
						}
						if name == "vrev32" || name == "vzip" || name == "vuzp" {
							value = uint32(variant % 2)
						}
					case "imm4":
						value = 1
					case "imm3H":
						value = uint32(1 << uint(variant%3))
					case "imm6":
						value = uint32(8 << uint(variant%3))
					case "imm3":
						value = uint32(variant)
					case "cmode":
						value = uint32(variant * 2)
					case "opc1", "opc2":
						value = 1
					case "len":
						value = uint32(variant)
					case "B":
						value = uint32(variant / 2)
					case "E":
						value = uint32(variant % 2)
						if variant == 3 {
							value = 0
						}
					}
					region := ((uint32(1) << uint(width)) - 1) << uint(b.Hi-width+1)
					word |= ((value << uint(b.Hi-width+1)) & (region &^ fm)) | fv
				}
				// VMULL's polynomial diagram shares a page with integer MUL.
				// U=1 is reserved and only P8/P64 element encodings are legal.
				canonical := word
				if cl.ISA == "T32" {
					canonical = 0xf2000000 | (word & 0x00ffffff) | ((word >> 4) & 0x01000000)
				}
				if name == "vmull_i" && canonical&0xfe800f50 == 0xf2800e00 {
					word &^= 0x00300000
					if cl.ISA == "T32" {
						word &^= 0x10000000
					} else {
						word &^= 0x01000000
					}
					word |= uint32(variant%2*2) << 20
				}
				// Pairwise ADD has a variable Q field which is architecturally reserved.
				if name == "vpadd_i" {
					word &^= 0x40
				}
				// Signed-only saturating scalar long products have fixed bit24. The
				// diagrams themselves retain that constraint through their fixed masks.
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", name)
				words++
			}
		}
	}
	if pages != len(names) {
		t.Fatalf("missing primary pages: got%d want%d", pages, len(names))
	}
	t.Logf("June NEON expansion fixtures: %d pages, %d words", pages, words)
	out.WriteString("];\n")
	return out.String()
}

const a32NeonIntegerTests = `
#[cfg(test)]
mod neon_integer {
    use super::{recipes, semantics::*, NEON_CORPUS};
    use std::cell::RefCell;
    #[derive(Clone)]
    struct State {
        d: [u64; 32],
        r: [u32; 16],
        fpscr: u32,
        it: u8,
        z: bool,
        reads: RefCell<Vec<Register>>,
        mem: [u8; 256],
        fault: Option<u64>,
        accesses: RefCell<Vec<(u64, u8, Endian)>>,
    }
    impl State {
        fn new() -> Self {
            let mut s = Self {
                d: [0; 32],
                r: [0; 16],
                fpscr: 0,
                it: 0,
                z: false,
                reads: RefCell::new(vec![]),
                mem: [0; 256],
                fault: None,
                accesses: RefCell::new(vec![]),
            };
            for n in 0..32 {
                s.d[n] = (0x8f017e00ff81027fu64.rotate_left(n as u32 * 3))
                    ^ (n as u64 * 0x0101010101010101)
            }
            for n in 0..16 {
                s.r[n] = 32 + n as u32 * 4
            }
            for i in 0..256 {
                s.mem[i] = i as u8;
            }
            s
        }
        fn lane(&self, d: u32, i: usize, w: u8) -> u64 {
            self.d[d as usize + i * usize::from(w) / 64] >> ((i * usize::from(w)) % 64) & mask(w)
        }
        fn set(&mut self, d: u32, i: usize, w: u8, v: u64) {
            let n = d as usize + i * usize::from(w) / 64;
            let sh = (i * usize::from(w)) % 64;
            self.d[n] = (self.d[n] & !(mask(w) << sh)) | ((v & mask(w)) << sh)
        }
        fn commit(&mut self, t: &Transition) {
            for w in &t.registers {
                assert!(w.value.is_known(), "{w:?}");
                match w.register.bank {
                    "a32.vector64" => self.d[usize::from(w.register.index)] = w.value.bits,
                    "a32.gpr" => self.r[usize::from(w.register.index)] = w.value.bits as u32,
                    "a32.fpscr" => self.fpscr = w.value.bits as u32,
                    "a32.itstate" => self.it = w.value.bits as u8,
                    _ => panic!("write{w:?}"),
                }
            }
            for x in &t.memory {
                assert!(x.value.is_known());
                for i in 0..x.value.width / 8 {
                    let shift = if x.endian == Endian::Little {
                        i
                    } else {
                        x.value.width / 8 - 1 - i
                    };
                    self.mem[x.address as usize + usize::from(i)] =
                        (x.value.bits >> (shift * 8)) as u8;
                }
            }
        }
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            self.reads.borrow_mut().push(r);
            match r.bank {
                "a32.vector64" => Value::known(64, self.d[usize::from(r.index)]),
                "a32.gpr" => Value::known(32, u64::from(self.r[usize::from(r.index)])),
                "a32.fpscr" => Value::known(32, u64::from(self.fpscr)),
                "a32.itstate" => Value::known(8, u64::from(self.it)),
                "a32.nzcv" => Value::known(1, u64::from(r.index == 1 && self.z)),
                _ => panic!("input{r:?}"),
            }
        }
        fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
            self.accesses.borrow_mut().push((a, w, e));
            if self
                .fault
                .is_some_and(|f| a <= f && f < a + u64::from(w / 8))
            {
                return Err(EvalError::Memory);
            }
            let mut v = 0;
            for i in 0..w / 8 {
                let shift = if e == Endian::Little {
                    i
                } else {
                    w / 8 - 1 - i
                };
                v |= u64::from(
                    *self
                        .mem
                        .get(a as usize + usize::from(i))
                        .ok_or(EvalError::Memory)?,
                ) << (shift * 8)
            }
            Ok(Value::known(w, v))
        }
    }
    fn canonical(base: u32, thumb: bool) -> u32 {
        if thumb && base & 0xfe000000 == 0xf2000000 {
            0xef000000 | (base & 0x00ffffff) | ((base & 0x01000000) << 4)
        } else {
            base
        }
    }
    fn run(word: u32, thumb: bool, s: &State) -> Transition {
        let r = if thumb {
            recipes::for_thumb(word, 4, 0x1000, Endian::Little)
        } else {
            recipes::for_word(word, 0x1000)
        };
        assert_eq!(r.support, Support::Full, "{word:08x} thumb{thumb}");
        r.validate().unwrap();
        evaluate(&r, s).unwrap()
    }
    fn regs(base: u32, d: u32, n: u32, m: u32, q: bool, size: u32) -> u32 {
        (base & !0x007ff0ef)
            | (d & 15) << 12
            | (d >> 4) << 22
            | (n & 15) << 16
            | (n >> 4) << 7
            | (m & 15)
            | (m >> 4) << 5
            | u32::from(q) << 6
            | size << 20
    }
    fn signed(v: u64, w: u8) -> i128 {
        ((v << (64 - w)) as i64 >> (64 - w)) as i128
    }
    fn clamp(v: i128, w: u8) -> (u64, bool) {
        let lo = -(1i128 << (w - 1));
        let hi = (1i128 << (w - 1)) - 1;
        ((v.clamp(lo, hi) as u64) & mask(w), v < lo || v > hi)
    }
    #[test]
    fn primary_integer_words_reach_generated_full_recipes() {
        let mut failures = vec![];
        for &(word, thumb, name) in NEON_CORPUS {
            let s = State::new();
            let r = if thumb {
                recipes::for_thumb(word, 4, 0x1000, Endian::Little)
            } else {
                recipes::for_word(word, 0x1000)
            };
            if r.support != Support::Full {
                failures.push(format!("{name}: {word:08x} thumb{thumb} {:?}", r.support));
                continue;
            }
            r.validate().unwrap();
            let t = evaluate(&r, &s).unwrap();
            assert!(t.trap.is_none(), "{name}");
            assert!(!t.registers.is_empty(), "{name}");
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
    fn misc(base: u32, d: u32, m: u32, q: bool, size: u32) -> u32 {
        (base & !0x004cf06f)
            | (d & 15) << 12
            | (d >> 4) << 22
            | (m & 15)
            | (m >> 4) << 5
            | u32::from(q) << 6
            | size << 18
    }
    fn scalar_word(base: u32, d: u32, n: u32, m: u32, index: u32, q: bool, size: u32) -> u32 {
        let mut w = (base & !0x017ff0af)
            | (d & 15) << 12
            | (d >> 4) << 22
            | (n & 15) << 16
            | (n >> 4) << 7
            | u32::from(q) << 24
            | size << 20;
        w |= if size == 1 {
            m & 7 | (index & 1) << 3 | (index >> 1) << 5
        } else {
            m & 15 | index << 5
        };
        w
    }
    #[test]
    fn halving_absolute_difference_extrema_test_and_pairwise_match_integer_oracles() {
        for thumb in [false, true] {
            for q in [false, true] {
                for size in 0..3 {
                    let w = 8u8 << size;
                    let count = if q { 128 } else { 64 } / usize::from(w);
                    for u in [false, true] {
                        for base in [
                            0xf2000000, 0xf2000100, 0xf2000200, 0xf2000600, 0xf2000610, 0xf2000700,
                            0xf2000710, 0xf2000810, 0xf2000300, 0xf2000310, 0xf3000810,
                        ] {
                            if matches!(base, 0xf2000810 | 0xf3000810) && u {
                                continue;
                            }
                            for d in [0, 2, 4] {
                                let s = State::new();
                                let mut expected = s.clone();
                                for i in 0..count {
                                    let a = s.lane(2, i, w);
                                    let b = s.lane(4, i, w);
                                    let (x, y) = if u {
                                        (a as i128, b as i128)
                                    } else {
                                        (signed(a, w), signed(b, w))
                                    };
                                    let value = match base {
                                        0xf2000000 => (x + y) >> 1,
                                        0xf2000100 => (x + y + 1) >> 1,
                                        0xf2000200 => (x - y) >> 1,
                                        0xf2000600 => x.max(y),
                                        0xf2000610 => x.min(y),
                                        0xf2000700 => (x - y).abs(),
                                        0xf2000710 => i128::from(s.lane(d, i, w)) + (x - y).abs(),
                                        0xf2000300 => {
                                            if x > y {
                                                mask(w) as i128
                                            } else {
                                                0
                                            }
                                        }
                                        0xf2000310 => {
                                            if x >= y {
                                                mask(w) as i128
                                            } else {
                                                0
                                            }
                                        }
                                        0xf3000810 => {
                                            if a == b {
                                                mask(w) as i128
                                            } else {
                                                0
                                            }
                                        }
                                        _ => {
                                            if a & b != 0 {
                                                mask(w) as i128
                                            } else {
                                                0
                                            }
                                        }
                                    };
                                    expected.set(d, i, w, value as u64);
                                }
                                let word = canonical(
                                    regs(base | if u { 0x01000000 } else { 0 }, d, 2, 4, q, size),
                                    thumb,
                                );
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "{word:08x}");
                                assert_eq!(got.fpscr, s.fpscr);
                            }
                        }
                        if !q {
                            for base in [0xf2000a00, 0xf2000a10, 0xf2000b10] {
                                if base == 0xf2000b10 && u {
                                    continue;
                                }
                                let s = State::new();
                                let mut expected = s.clone();
                                for i in 0..count {
                                    let half = count / 2;
                                    let n = if i < half { 2 } else { 4 };
                                    let j = (i % half) * 2;
                                    let a = s.lane(n, j, w);
                                    let b = s.lane(n, j + 1, w);
                                    let (x, y) = if u {
                                        (a as i128, b as i128)
                                    } else {
                                        (signed(a, w), signed(b, w))
                                    };
                                    let value = if base == 0xf2000b10 {
                                        x + y
                                    } else if base & 0x10 == 0 {
                                        x.max(y)
                                    } else {
                                        x.min(y)
                                    };
                                    expected.set(2, i, w, value as u64);
                                }
                                let word = canonical(
                                    regs(
                                        base | if u { 0x01000000 } else { 0 },
                                        2,
                                        2,
                                        4,
                                        false,
                                        size,
                                    ),
                                    thumb,
                                );
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "pair{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn widening_pairwise_absolute_accumulate_and_high_narrow_preserve_snapshot_aliases() {
        for thumb in [false, true] {
            for size in 0..3 {
                let w = 8u8 << size;
                for u in [false, true] {
                    for q in [false, true] {
                        for accumulate in [false, true] {
                            let s = State::new();
                            let mut expected = s.clone();
                            let count = if q { 128 } else { 64 } / usize::from(w * 2);
                            for i in 0..count {
                                let a = s.lane(2, i * 2, w);
                                let b = s.lane(2, i * 2 + 1, w);
                                let sum = if u {
                                    a as i128 + b as i128
                                } else {
                                    signed(a, w) + signed(b, w)
                                };
                                let value = sum
                                    + if accumulate {
                                        s.lane(2, i, w * 2) as i128
                                    } else {
                                        0
                                    };
                                expected.set(2, i, w * 2, value as u64);
                            }
                            let word = canonical(
                                misc(
                                    if accumulate { 0xf3b00600 } else { 0xf3b00200 }
                                        | if u { 0x80 } else { 0 },
                                    2,
                                    2,
                                    q,
                                    size,
                                ),
                                thumb,
                            );
                            let t = run(word, thumb, &s);
                            let mut got = s.clone();
                            got.commit(&t);
                            assert_eq!(got.d, expected.d);
                        }
                    }
                    for accumulate in [false, true] {
                        let s = State::new();
                        let mut expected = s.clone();
                        for i in 0..64 / usize::from(w) {
                            let a = s.lane(2, i, w);
                            let b = s.lane(3, i, w);
                            let value = if u {
                                (a as i128 - b as i128).abs()
                            } else {
                                (signed(a, w) - signed(b, w)).abs()
                            } + if accumulate {
                                s.lane(2, i, w * 2) as i128
                            } else {
                                0
                            };
                            expected.set(2, i, w * 2, value as u64);
                        }
                        let word = canonical(
                            regs(
                                if accumulate { 0xf2800500 } else { 0xf2800700 }
                                    | if u { 0x01000000 } else { 0 },
                                2,
                                2,
                                3,
                                false,
                                size,
                            ),
                            thumb,
                        );
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "long{word:08x}");
                    }
                    for sub in [false, true] {
                        let s = State::new();
                        let mut expected = s.clone();
                        for i in 0..64 / usize::from(w) {
                            let a = s.lane(2, i, w * 2);
                            let b = s.lane(4, i, w * 2);
                            let value = (if sub {
                                a.wrapping_sub(b)
                            } else {
                                a.wrapping_add(b)
                            })
                            .wrapping_add(if u {
                                1 << (w - 1)
                            } else {
                                0
                            }) & mask(w * 2);
                            expected.set(3, i, w, value >> w);
                        }
                        let word = canonical(
                            regs(
                                if sub { 0xf2800600 } else { 0xf2800400 }
                                    | if u { 0x01000000 } else { 0 },
                                3,
                                2,
                                4,
                                false,
                                size,
                            ),
                            thumb,
                        );
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "narrow{word:08x}");
                    }
                }
            }
        }
    }
    #[test]
    fn integer_unary_counts_comparisons_and_sticky_saturation_use_lane_width() {
        for thumb in [false, true] {
            for q in [false, true] {
                for size in 0..3 {
                    let w = 8u8 << size;
                    let count = if q { 128 } else { 64 } / usize::from(w);
                    for base in [
                        0xf3b00400, 0xf3b00480, 0xf3b00500, 0xf3b00700, 0xf3b00780, 0xf3b10000,
                        0xf3b10080, 0xf3b10100, 0xf3b10180, 0xf3b10200, 0xf3b10300, 0xf3b10380,
                    ] {
                        if base == 0xf3b00500 && w != 8 {
                            continue;
                        }
                        for initial_qc in [0, 1u32 << 27] {
                            let mut s = State::new();
                            s.fpscr = initial_qc | 0x1000000;
                            s.set(2, 0, w, 1 << (w - 1));
                            s.set(2, 1, w, 0);
                            let mut expected = s.clone();
                            let mut saturated = false;
                            for i in 0..count {
                                let a = s.lane(2, i, w);
                                let x = signed(a, w);
                                let value = match base {
                                    0xf3b00400 => {
                                        let v = if x < 0 { !a & mask(w) } else { a };
                                        ((v << (64 - w)).leading_zeros().min(u32::from(w)) - 1)
                                            as u64
                                    }
                                    0xf3b00480 => {
                                        (a << (64 - w)).leading_zeros().min(u32::from(w)) as u64
                                    }
                                    0xf3b00500 => u64::from(a.count_ones()),
                                    0xf3b00700 | 0xf3b00780 => {
                                        let (v, sat) =
                                            clamp(if base & 0x80 != 0 { -x } else { x.abs() }, w);
                                        saturated |= sat;
                                        v
                                    }
                                    0xf3b10300 => x.abs() as u64,
                                    0xf3b10380 => (-x) as u64,
                                    _ => {
                                        if match base {
                                            0xf3b10000 => x > 0,
                                            0xf3b10080 => x >= 0,
                                            0xf3b10100 => x == 0,
                                            0xf3b10180 => x <= 0,
                                            _ => x < 0,
                                        } {
                                            mask(w)
                                        } else {
                                            0
                                        }
                                    }
                                };
                                expected.set(2, i, w, value);
                            }
                            if saturated {
                                expected.fpscr |= 1 << 27;
                            }
                            let word = canonical(misc(base, 2, 2, q, size), thumb);
                            let t = run(word, thumb, &s);
                            let mut got = s.clone();
                            got.commit(&t);
                            assert_eq!(got.d, expected.d, "unary{word:08x}");
                            assert_eq!(got.fpscr, expected.fpscr);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn table_extract_swap_and_duplicate_cover_cross_chunk_aliases_and_out_of_range_bytes() {
        for thumb in [false, true] {
            for q in [false, true] {
                let bytes = if q { 16 } else { 8 };
                for offset in 0..bytes {
                    let s = State::new();
                    let mut expected = s.clone();
                    for i in 0..bytes {
                        let at = offset + i;
                        let value =
                            s.lane(if at < bytes { 2 } else { 4 }, (at % bytes) as usize, 8);
                        expected.set(2, i as usize, 8, value);
                    }
                    let word = canonical(
                        regs(0xf2b00000 | (offset as u32) << 8, 2, 2, 4, q, 3),
                        thumb,
                    );
                    let t = run(word, thumb, &s);
                    let mut got = s.clone();
                    got.commit(&t);
                    assert_eq!(got.d, expected.d, "ext{word:08x}");
                }
                let s = State::new();
                let mut expected = s.clone();
                for i in 0..if q { 2 } else { 1 } {
                    expected.d[2 + i] = s.d[4 + i];
                    expected.d[4 + i] = s.d[2 + i];
                }
                let word = canonical(misc(0xf3b20000, 2, 4, q, 0), thumb);
                let t = run(word, thumb, &s);
                let mut got = s.clone();
                got.commit(&t);
                assert_eq!(got.d, expected.d);
                for w in [8u8, 16, 32] {
                    for index in 0..64 / w {
                        let log = (w / 8).trailing_zeros();
                        let imm = (u32::from(index) << (log + 1)) | (1 << log);
                        let s = State::new();
                        let mut expected = s.clone();
                        let value = s.lane(3, index as usize, w);
                        for i in 0..if q { 128 } else { 64 } / usize::from(w) {
                            expected.set(2, i, w, value);
                        }
                        let word = canonical(regs(0xf3b00c00, 2, imm, 3, q, 3), thumb);
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "dup{word:08x}");
                    }
                }
            }
            for len in 1..=4 {
                for extend in [false, true] {
                    for (d, n, m) in [(0, 2, 4), (2, 2, 4), (4, 2, 4), (31, 28, 31)] {
                        let mut s = State::new();
                        s.d[m as usize] = 0xff201f1817100800;
                        let mut expected = s.clone();
                        for i in 0..8 {
                            let index = s.lane(m, i, 8) as usize;
                            let value = if index < (len * 8) as usize {
                                s.lane(n, index, 8)
                            } else if extend {
                                s.lane(d, i, 8)
                            } else {
                                0
                            };
                            expected.set(d, i, 8, value);
                        }
                        let word = canonical(
                            regs(0xf3b00800 | ((len - 1) << 8), d, n, m, extend, 3),
                            thumb,
                        );
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "table{word:08x}");
                    }
                }
            }
        }
    }
    #[test]
    fn immediate_right_accumulate_rounds_without_losing_the_64_bit_carry() {
        for thumb in [false, true] {
            for q in [false, true] {
                for size in 0..4 {
                    let w = 8u8 << size;
                    for u in [false, true] {
                        for round in [false, true] {
                            for shift in [1, u32::from(w) - 1, u32::from(w)] {
                                let mut s = State::new();
                                s.d[2] = u64::MAX;
                                s.d[3] = 0x8000000000000000;
                                let mut expected = s.clone();
                                for i in 0..if q { 128 } else { 64 } / usize::from(w) {
                                    let a = s.lane(2, i, w);
                                    let x = if u { a as i128 } else { signed(a, w) };
                                    let result =
                                        ((x + if round { 1i128 << (shift - 1) } else { 0 })
                                            >> shift)
                                            + s.lane(2, i, w) as i128;
                                    expected.set(2, i, w, result as u64);
                                }
                                let imm = u32::from(w) * 2 - shift;
                                let mut word = regs(
                                    0xf2800110
                                        | if round { 0x200 } else { 0 }
                                        | if u { 0x01000000 } else { 0 },
                                    2,
                                    0,
                                    2,
                                    q,
                                    0,
                                );
                                word |= (imm & 63) << 16 | (imm & 64) << 1;
                                let word = canonical(word, thumb);
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "sra{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn modified_immediates_cover_all_cmode_and_op_combinations_without_fp_or_status() {
        for thumb in [false, true] {
            for q in [false, true] {
                for cmode in 0..16u32 {
                    for op in [false, true] {
                        if cmode == 15 && op {
                            continue;
                        }
                        for imm in [0u32, 0x80, 0xff, 0x6a] {
                            let mut bytes = [0u8; 8];
                            match cmode {
                                0..=7 => {
                                    bytes[(cmode / 2) as usize] = imm as u8;
                                    bytes[4 + (cmode / 2) as usize] = imm as u8;
                                }
                                8..=11 => {
                                    for i in 0..4 {
                                        bytes[2 * i + ((cmode / 2) & 1) as usize] = imm as u8
                                    }
                                }
                                12 => bytes = [0xff, imm as u8, 0, 0, 0xff, imm as u8, 0, 0],
                                13 => bytes = [0xff, 0xff, imm as u8, 0, 0xff, 0xff, imm as u8, 0],
                                14 => {
                                    for i in 0..8 {
                                        bytes[i] = if op {
                                            if imm & (1 << i) != 0 {
                                                255
                                            } else {
                                                0
                                            }
                                        } else {
                                            imm as u8
                                        }
                                    }
                                }
                                _ => {
                                    let sign = imm >> 7;
                                    let exp =
                                        if imm & 0x40 == 0 { 0x80 } else { 0x7c } | (imm >> 4 & 3);
                                    let f = (sign << 31) | (exp << 23) | ((imm & 15) << 19);
                                    bytes[..4].copy_from_slice(&f.to_le_bytes());
                                    bytes[4..].copy_from_slice(&f.to_le_bytes());
                                }
                            }
                            let immediate = u64::from_le_bytes(bytes);
                            let s = State::new();
                            let mut expected = s.clone();
                            for i in 0..if q { 2 } else { 1 } {
                                expected.d[2 + i] = if cmode < 12 && cmode & 1 != 0 {
                                    if op {
                                        s.d[2 + i] & !immediate
                                    } else {
                                        s.d[2 + i] | immediate
                                    }
                                } else if op && cmode != 14 {
                                    !immediate
                                } else {
                                    immediate
                                };
                            }
                            let word = canonical(
                                0xf2802010
                                    | u32::from(q) << 6
                                    | cmode << 8
                                    | u32::from(op) << 5
                                    | (imm & 0x80) << 17
                                    | (imm & 0x70) << 12
                                    | imm & 15,
                                thumb,
                            );
                            let t = run(word, thumb, &s);
                            let mut got = s.clone();
                            got.commit(&t);
                            assert_eq!(got.d, expected.d, "imm{word:08x}");
                            assert_eq!(got.fpscr, s.fpscr);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn scalar_element_multiplies_and_two_stage_saturation_match_i128_reference() {
        for thumb in [false, true] {
            for size in [1u32, 2] {
                let w = 8u8 << size;
                for q in [false, true] {
                    for index in 0..64 / u32::from(w) {
                        for base in [
                            0xf2800040, 0xf2800440, 0xf2800840, 0xf2800c40, 0xf2800d40, 0xf2800e40,
                            0xf2800f40,
                        ] {
                            let mut s = State::new();
                            s.set(2, 0, w, 1 << (w - 1));
                            s.set(3, index as usize, w, 1 << (w - 1));
                            let mut expected = s.clone();
                            let mut saturated = false;
                            for i in 0..if q { 128 } else { 64 } / usize::from(w) {
                                let a = signed(s.lane(2, i, w), w);
                                let b = signed(s.lane(3, index as usize, w), w);
                                let old = signed(s.lane(2, i, w), w);
                                let product = a * b;
                                let value = match base {
                                    0xf2800040 => old + product,
                                    0xf2800440 => old - product,
                                    0xf2800840 => product,
                                    _ => {
                                        let rdm = base >= 0xf2800e40;
                                        let sub = base == 0xf2800f40;
                                        let round = base == 0xf2800d40 || rdm;
                                        let shifted = ((if sub { -product } else { product })
                                            + if round { 1i128 << (w - 2) } else { 0 })
                                            >> (w - 1);
                                        let (value, sat) =
                                            clamp(shifted + if rdm { old } else { 0 }, w);
                                        saturated |= sat;
                                        value as i128
                                    }
                                };
                                expected.set(2, i, w, value as u64);
                            }
                            if saturated {
                                expected.fpscr |= 1 << 27;
                            }
                            let word = canonical(scalar_word(base, 2, 2, 3, index, q, size), thumb);
                            let t = run(word, thumb, &s);
                            let mut got = s.clone();
                            got.commit(&t);
                            assert_eq!(got.d, expected.d, "scalar{word:08x}");
                            assert_eq!(got.fpscr, expected.fpscr, "scalarqc{word:08x}");
                        }
                    }
                }
                for scalar in [false, true] {
                    for u in [false, true] {
                        for op in [0u32, 1, 2] {
                            for doubling in [false, true] {
                                if doubling && u {
                                    continue;
                                }
                                let base = if scalar {
                                    if doubling {
                                        [0xf2800b40, 0xf2800340, 0xf2800740][op as usize]
                                    } else {
                                        [0xf2800a40, 0xf2800240, 0xf2800640][op as usize]
                                    }
                                } else if doubling {
                                    [0xf2800d00, 0xf2800900, 0xf2800b00][op as usize]
                                } else {
                                    continue;
                                };
                                let mut s = State::new();
                                s.set(2, 0, w, 1 << (w - 1));
                                s.set(3, 0, w, 1 << (w - 1));
                                let mut expected = s.clone();
                                let mut saturated = false;
                                for i in 0..64 / usize::from(w) {
                                    let a = s.lane(2, i, w);
                                    let b = s.lane(3, if scalar { 0 } else { i }, w);
                                    let (a, b) = if u {
                                        (a as i128, b as i128)
                                    } else {
                                        (signed(a, w), signed(b, w))
                                    };
                                    let mut product = a * b;
                                    if doubling {
                                        let (v, sat) = clamp(product * 2, w * 2);
                                        product = signed(v, w * 2);
                                        saturated |= sat;
                                    }
                                    let old = signed(s.lane(2, i, w * 2), w * 2);
                                    let mut value = match op {
                                        0 => product,
                                        1 => old + product,
                                        _ => old - product,
                                    };
                                    if doubling && op != 0 {
                                        let (v, sat) = clamp(value, w * 2);
                                        value = v as i128;
                                        saturated |= sat;
                                    }
                                    expected.set(2, i, w * 2, value as u64);
                                }
                                if saturated {
                                    expected.fpscr |= 1 << 27;
                                }
                                let word = canonical(
                                    if scalar {
                                        scalar_word(
                                            base | if u { 0x01000000 } else { 0 },
                                            2,
                                            2,
                                            3,
                                            0,
                                            u,
                                            size,
                                        )
                                    } else {
                                        regs(base, 2, 2, 3, false, size)
                                    },
                                    thumb,
                                );
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "longmul{word:08x}");
                                assert_eq!(got.fpscr, expected.fpscr, "longmulqc{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn rdm_has_one_final_saturation_and_dot_matrix_lane_layouts_are_exact() {
        for thumb in [false, true] {
            for size in [1u32, 2] {
                let w = 8u8 << size;
                for q in [false, true] {
                    for sub in [false, true] {
                        let mut s = State::new();
                        s.set(2, 0, w, 1 << (w - 1));
                        s.set(4, 0, w, 1 << (w - 1));
                        let mut expected = s.clone();
                        let mut sat = false;
                        for i in 0..if q { 128 } else { 64 } / usize::from(w) {
                            let old = signed(s.lane(2, i, w), w);
                            let p = signed(s.lane(2, i, w), w) * signed(s.lane(4, i, w), w);
                            let result =
                                old + ((if sub { -p } else { p }) + (1i128 << (w - 2)) >> (w - 1));
                            let (v, flag) = clamp(result, w);
                            sat |= flag;
                            expected.set(2, i, w, v);
                        }
                        if sat {
                            expected.fpscr |= 1 << 27;
                        }
                        let word = canonical(
                            regs(if sub { 0xf3000c10 } else { 0xf3000b10 }, 2, 2, 4, q, size),
                            thumb,
                        );
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "rdm{word:08x}");
                        assert_eq!(got.fpscr, expected.fpscr);
                    }
                }
            }
            for q in [false, true] {
                for scalar in [false, true] {
                    for mixed in [false, true] {
                        for u in [false, true] {
                            if mixed && !scalar && u {
                                continue;
                            }
                            for index in 0..if scalar { 2 } else { 1 } {
                                let s = State::new();
                                let mut expected = s.clone();
                                let signed1 = if mixed { u } else { !u };
                                let signed2 = if mixed { !u } else { !u };
                                for i in 0..if q { 4 } else { 2 } {
                                    let mut value = s.lane(2, i, 32) as i128;
                                    for j in 0..4 {
                                        let a = s.lane(2, i * 4 + j, 8);
                                        let b = s.lane(
                                            4,
                                            if scalar { index * 4 + j } else { i * 4 + j },
                                            8,
                                        );
                                        value += if signed1 { signed(a, 8) } else { a as i128 }
                                            * if signed2 { signed(b, 8) } else { b as i128 };
                                    }
                                    expected.set(2, i, 32, value as u64);
                                }
                                let base = if scalar {
                                    if mixed {
                                        0xfe800d00
                                    } else {
                                        0xfe200d00
                                    }
                                } else if mixed {
                                    0xfca00d00
                                } else {
                                    0xfc200d00
                                };
                                let mut word = regs(
                                    base | if u { 0x10 } else { 0 },
                                    2,
                                    2,
                                    4,
                                    q,
                                    if mixed && scalar { 0 } else { 2 },
                                );
                                if scalar {
                                    word |= (index as u32) << 5;
                                }
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "dot{word:08x}");
                            }
                        }
                    }
                }
            }
            for mode in 0..3 {
                let s = State::new();
                let mut expected = s.clone();
                for row in 0..2 {
                    for col in 0..2 {
                        let at = row * 2 + col;
                        let mut sum = s.lane(2, at, 32) as i128;
                        for k in 0..8 {
                            let a = s.lane(2, row * 8 + k, 8);
                            let b = s.lane(4, col * 8 + k, 8);
                            sum += if mode != 0 { a as i128 } else { signed(a, 8) }
                                * if mode == 1 { b as i128 } else { signed(b, 8) };
                        }
                        expected.set(2, at, 32, sum as u64);
                    }
                }
                let word = regs(
                    0xfc200c40
                        | if mode == 1 {
                            0x10
                        } else if mode == 2 {
                            0x00800000
                        } else {
                            0
                        },
                    2,
                    2,
                    4,
                    true,
                    2,
                );
                let t = run(word, thumb, &s);
                let mut got = s.clone();
                got.commit(&t);
                assert_eq!(got.d, expected.d, "matrix{word:08x}");
            }
        }
    }
    #[test]
    fn bitselect_aliases_preserve_exact_masks_and_fpscr() {
        for thumb in [false, true] {
            for q in [false, true] {
                for base in [0xf3100110, 0xf3200110, 0xf3300110] {
                    for d in [0, 2, 4] {
                        let s = State::new();
                        let mut expected = s.clone();
                        for i in 0..if q { 2 } else { 1 } {
                            let (old, a, b) = (s.d[d as usize + i], s.d[2 + i], s.d[4 + i]);
                            expected.d[d as usize + i] = match base {
                                0xf3100110 => (old & a) | (!old & b),
                                0xf3200110 => (old & !b) | (a & b),
                                _ => (old & b) | (a & !b),
                            }
                        }
                        let word = canonical(regs(base, d, 2, 4, q, (base >> 20) & 3), thumb);
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d);
                        assert_eq!(got.fpscr, s.fpscr);
                    }
                }
            }
        }
    }
    #[test]
    fn core_element_moves_and_duplicate_preserve_all_other_lanes_and_allow_armv8_sp() {
        for thumb in [false, true] {
            for rt in [1u32, 13] {
                for w in [8u8, 16, 32] {
                    for index in 0..64 / u32::from(w) {
                        let opc = match w {
                            8 => 8 | index,
                            16 => 1 | (index << 1),
                            _ => index << 2,
                        };
                        let encoding = ((opc >> 2) << 21) | ((opc & 3) << 5);
                        let d = 31;
                        for to_arm in [false, true] {
                            for unsigned in [false, true] {
                                if unsigned && (!to_arm || w == 32) {
                                    continue;
                                }
                                let mut s = State::new();
                                s.r[rt as usize] = 0x87654321;
                                let mut expected = s.clone();
                                if to_arm {
                                    let v = s.lane(d, index as usize, w);
                                    expected.r[rt as usize] = if unsigned {
                                        v as u32
                                    } else {
                                        signed(v, w) as u32
                                    };
                                } else {
                                    expected.set(d, index as usize, w, u64::from(s.r[rt as usize]));
                                }
                                let word = 0xee000b10
                                    | encoding
                                    | (d & 15) << 16
                                    | (d >> 4) << 7
                                    | rt << 12
                                    | u32::from(to_arm) << 20
                                    | u32::from(unsigned) << 23;
                                let t = run(word, thumb, &s);
                                let mut got = s.clone();
                                got.commit(&t);
                                assert_eq!(got.d, expected.d, "core{word:08x}");
                                assert_eq!(got.r, expected.r, "core{word:08x}");
                            }
                        }
                    }
                    for q in [false, true] {
                        let be = match w {
                            8 => 2,
                            16 => 1,
                            _ => 0,
                        };
                        let s = State::new();
                        let mut expected = s.clone();
                        for i in 0..if q { 128 } else { 64 } / usize::from(w) {
                            expected.set(2, i, w, u64::from(s.r[rt as usize]));
                        }
                        let word = 0xee800b10
                            | (be >> 1) << 22
                            | (be & 1) << 5
                            | u32::from(q) << 21
                            | 2 << 16
                            | rt << 12;
                        let t = run(word, thumb, &s);
                        let mut got = s.clone();
                        got.commit(&t);
                        assert_eq!(got.d, expected.d, "coredup{word:08x}");
                    }
                }
            }
        }
    }
    #[test]
    fn thumb_predicates_suppress_inputs_qc_and_memory_and_advance_it_once() {
        let words = [
            canonical(regs(0xf2000700, 2, 2, 4, true, 0), true),
            canonical(misc(0xf3b00700, 2, 4, true, 0), true),
            canonical(regs(0xf3b00800 | 0x300, 2, 2, 4, true, 3), true),
            0xeea21b10,
            0xf920084f,
        ];
        for word in words {
            let mut s = State::new();
            s.it = 0x18;
            s.z = true;
            let r = recipes::for_thumb(word, 4, 0x1000, Endian::Big);
            assert_eq!(r.support, Support::Full, "{word:08x}");
            let t = evaluate(&r, &s).unwrap();
            assert!(t.trap.is_none());
            assert!(t.memory.is_empty());
            assert!(s.accesses.borrow().is_empty());
            assert!(
                s.reads
                    .borrow()
                    .iter()
                    .all(|r| r.bank == "a32.itstate" || r.bank == "a32.nzcv"),
                "{word:08x} {:?}",
                s.reads.borrow()
            );
            let original = s.clone();
            s.commit(&t);
            assert_eq!(s.it, 0);
            assert_eq!(s.d, original.d);
            assert_eq!(s.r, original.r);
            assert_eq!(s.fpscr, original.fpscr);
        }
        // ARM core-to-lane forms retain their encoded condition as well.
        let mut s = State::new();
        s.z = true;
        let t = run(0x1e401b10, false, &s);
        assert!(t.registers.is_empty());
        assert!(s.reads.borrow().iter().all(|r| r.bank == "a32.nzcv"));
    }
    #[test]
    fn rdm_dot_and_i8mm_forbid_it_before_any_operand_even_if_condition_fails() {
        for word in [
            canonical(regs(0xf3000b10, 2, 2, 4, true, 1), true),
            canonical(scalar_word(0xf2800e40, 2, 2, 3, 0, true, 1), true),
            regs(0xfc200d00, 2, 2, 4, true, 2),
            regs(0xfe200d00, 2, 2, 4, true, 2),
            regs(0xfc200c40, 2, 2, 4, true, 2),
        ] {
            for z in [false, true] {
                let mut s = State::new();
                s.it = 0x18;
                s.z = z;
                let r = recipes::for_thumb(word, 4, 0x1000, Endian::Little);
                assert_eq!(r.support, Support::Full);
                assert_eq!(
                    evaluate(&r, &s),
                    Err(EvalError::UnsupportedContext),
                    "{word:08x}"
                );
                assert!(s.reads.borrow().iter().all(|r| r.bank == "a32.itstate"));
                assert!(s.accesses.borrow().is_empty());
            }
        }
    }
    #[test]
    fn invalid_simd_encodings_reject_explicitly_instead_of_becoming_other_operations() {
        for thumb in [false, true] {
            for word in [
                regs(0xf2000a00, 0, 2, 4, true, 0),
                regs(0xf2000700, 1, 2, 4, true, 0),
                regs(0xf2800400, 0, 3, 4, false, 0),
                misc(0xf3b00500, 0, 2, false, 1),
                regs(0xf2b00800, 0, 2, 4, false, 3),
                regs(0xf3b00b00, 0, 30, 4, false, 3),
                regs(0xf3b00c00, 1, 0, 4, true, 3),
                scalar_word(0xf2800a40, 1, 2, 3, 0, false, 1),
                0xee82fb10,
                0xeec21b30,
                0xee401b1f,
            ] {
                let word = canonical(word, thumb);
                let r = if thumb {
                    recipes::for_thumb(word, 4, 0x1000, Endian::Little)
                } else {
                    recipes::for_word(word, 0x1000)
                };
                assert!(
                    matches!(r.support, Support::Unsupported(_)),
                    "{word:08x} {:?}",
                    r.support
                );
            }
        }
    }
    #[test]
    fn emitted_structure_memory_retains_original_accesses_endian_writeback_and_fault_atomicity() {
        for thumb in [false, true] {
            for endian in [Endian::Little, Endian::Big] {
                let s = State::new();
                let mut expected = s.clone();
                for i in 0..4 {
                    for stream in 0..2 {
                        let at = 32 + (i * 2 + stream) * 2;
                        let bytes = [s.mem[at], s.mem[at + 1]];
                        let v = if endian == Endian::Little {
                            u16::from_le_bytes(bytes)
                        } else {
                            u16::from_be_bytes(bytes)
                        };
                        expected.set(stream as u32, i, 16, u64::from(v));
                    }
                }
                let word = if thumb { 0xf920084d } else { 0xf420084d };
                let r = if thumb {
                    recipes::for_thumb(word, 4, 0x1000, endian)
                } else {
                    recipes::for_word_with_endian(word, 0x1000, endian)
                };
                assert_eq!(r.support, Support::Full);
                let t = evaluate(&r, &s).unwrap();
                let mut got = s.clone();
                got.commit(&t);
                assert_eq!(got.d, expected.d);
                assert_eq!(got.r[0], 48);
                assert_eq!(
                    *s.accesses.borrow(),
                    (0..8).map(|i| (32 + i * 2, 16, endian)).collect::<Vec<_>>()
                );
                let mut stored = State::new();
                let mut expected_mem = stored.mem;
                for i in 0..4 {
                    for stream in 0..2 {
                        let v = stored.lane(stream, i, 16) as u16;
                        let bytes = if endian == Endian::Little {
                            v.to_le_bytes()
                        } else {
                            v.to_be_bytes()
                        };
                        let at = 32 + (i * 2 + stream as usize) * 2;
                        expected_mem[at..at + 2].copy_from_slice(&bytes);
                    }
                }
                let store_word = if thumb { 0xf900084d } else { 0xf400084d };
                let store = if thumb {
                    recipes::for_thumb(store_word, 4, 0x1000, endian)
                } else {
                    recipes::for_word_with_endian(store_word, 0x1000, endian)
                };
                let transition = evaluate(&store, &stored).unwrap();
                assert_eq!(transition.memory.len(), 8);
                assert!(transition
                    .memory
                    .iter()
                    .all(|m| m.value.width == 16 && m.endian == endian));
                stored.commit(&transition);
                assert_eq!(stored.mem, expected_mem);
                assert_eq!(stored.r[0], 48);
                let mut fault = s.clone();
                fault.accesses.borrow_mut().clear();
                fault.fault = Some(39);
                assert_eq!(evaluate(&r, &fault), Err(EvalError::Memory));
                assert_eq!(fault.d, s.d);
                assert_eq!(fault.r, s.r);
                assert_eq!(fault.accesses.borrow().len(), 4);
                let s = State::new();
                let word = if thumb { 0xf92007cf } else { 0xf42007cf };
                let r = if thumb {
                    recipes::for_thumb(word, 4, 0x1000, endian)
                } else {
                    recipes::for_word_with_endian(word, 0x1000, endian)
                };
                let t = evaluate(&r, &s).unwrap();
                let mut got = s.clone();
                got.commit(&t);
                let bytes = s.mem[32..40].try_into().unwrap();
                let expected = if endian == Endian::Little {
                    u64::from_le_bytes(bytes)
                } else {
                    u64::from_be_bytes(bytes)
                };
                assert_eq!(got.d[0], expected);
                assert_eq!(
                    *s.accesses.borrow(),
                    if endian == Endian::Little {
                        vec![(32, 32, endian), (36, 32, endian)]
                    } else {
                        vec![(36, 32, endian), (32, 32, endian)]
                    }
                );
            }
        }
    }
    #[test]
    fn unsigned_estimates_match_primary_integer_algorithms_at_every_interval_boundary() {
        for thumb in [false, true] {
            for q in [false, true] {
                for rsqrt in [false, true] {
                    for a in 0..512u32 {
                        for tail in [0, 0x7fffff] {
                            let operand = (a << 23) | tail;
                            let expected = if (!rsqrt && operand < 0x80000000)
                                || (rsqrt && operand < 0x40000000)
                            {
                                u32::MAX
                            } else {
                                let estimate = if rsqrt {
                                    let scaled = if a < 256 {
                                        a * 2 + 1
                                    } else {
                                        ((a >> 1) * 2 + 1) * 2
                                    };
                                    let mut b = 512;
                                    while scaled * (b + 1) * (b + 1) < 1 << 28 {
                                        b += 1
                                    }
                                    (b + 1) / 2
                                } else {
                                    ((1 << 19) / (a * 2 + 1) + 1) / 2
                                };
                                estimate << 23
                            };
                            let mut s = State::new();
                            for i in 0..if q { 4 } else { 2 } {
                                s.set(2, i, 32, u64::from(operand));
                            }
                            let word = canonical(
                                misc(if rsqrt { 0xf3b30480 } else { 0xf3b30400 }, 2, 2, q, 2),
                                thumb,
                            );
                            let t = run(word, thumb, &s);
                            let mut got = s.clone();
                            got.commit(&t);
                            for i in 0..if q { 4 } else { 2 } {
                                assert_eq!(
                                    got.lane(2, i, 32),
                                    u64::from(expected),
                                    "estimate{word:08x} {operand:08x}"
                                );
                            }
                            assert_eq!(got.fpscr, s.fpscr);
                            assert!(s
                                .reads
                                .borrow()
                                .iter()
                                .all(|r| r.bank == "a32.vector64" || r.bank == "a32.itstate"));
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn upper_d_bank_and_q15_aliases_use_full_register_identities() {
        for thumb in [false, true] {
            let s = State::new();
            let mut expected = s.clone();
            for i in 0..16 {
                expected.set(30, i, 8, s.lane(30, i, 8).max(s.lane(28, i, 8)));
            }
            let word = canonical(regs(0xf3000600, 30, 30, 28, true, 0), thumb);
            let t = run(word, thumb, &s);
            let mut got = s.clone();
            got.commit(&t);
            assert_eq!(got.d, expected.d);
            let s = State::new();
            let mut expected = s.clone();
            for i in 0..8 {
                let value = (s.lane(28, i, 16).wrapping_add(s.lane(30, i, 16)) & 0xffff) >> 8;
                expected.set(31, i, 8, value);
            }
            let word = canonical(regs(0xf2800400, 31, 28, 30, false, 0), thumb);
            let t = run(word, thumb, &s);
            let mut got = s.clone();
            got.commit(&t);
            assert_eq!(got.d, expected.d);
            let s = State::new();
            let mut expected = s.clone();
            let scalar = s.lane(31, 7, 8);
            for i in 0..16 {
                expected.set(30, i, 8, scalar);
            }
            let word = canonical(regs(0xf3b00c00, 30, 15, 31, true, 3), thumb);
            let t = run(word, thumb, &s);
            let mut got = s.clone();
            got.commit(&t);
            assert_eq!(got.d, expected.d);
        }
    }
}
`

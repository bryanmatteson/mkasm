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

func TestRustA32LegacyVfpVectors(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	tmpl, err := template.New("legacy-vfp").ParseFS(assettemplates.FS, "arm32_rust/recipes.rs.tmpl")
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
	if err = os.WriteFile(filepath.Join(dir, "vectors.rs"), []byte(wrapper+a32LegacyVfpTests+a32LegacyVfpCorpus(t)), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "vectors.rs", "-Dwarnings", "-o", "vector-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile legacy VFP: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "vector-tests"), "legacy_vectors::", "--test-threads=1")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute legacy VFP: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// June supplies the physical allocation and scalar operation. Armv7 DDI0406C.d
// Appendix D11 separately supplies this explicitly legacy profile's iteration
// rules; June's nonzero LEN/STRIDE UNDEFINED condition is not reinterpreted.
func a32LegacyVfpCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/ISA_AArch32_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		return "const LEGACY_CORPUS:&[(u32,bool,&str)]=&[];"
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
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
		Encodings []struct {
			Name string `xml:"name,attr"`
		} `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	wanted := map[string]bool{}
	for _, name := range []string{"vabs", "vadd_f", "vdiv", "vmla_f", "vmls_f", "vmov_i", "vmov_r", "vmul_f", "vneg", "vnmla", "vnmls", "vnmul", "vsqrt", "vsub_f"} {
		wanted[name] = true
	}
	var out strings.Builder
	out.WriteString("const LEGACY_CORPUS:&[(u32,bool,&str)]=&[\n")
	pages, words := 0, 0
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(header.Name), ".xml")
		if !strings.HasPrefix(header.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !wanted[name] {
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
			scalar := false
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "size" && b.Hi == 9 {
					scalar = true
				}
			}
			if !scalar {
				continue
			}
			for _, en := range cl.Encodings {
				if !strings.HasSuffix(en.Name, "_S") && !strings.HasSuffix(en.Name, "_D") {
					continue
				}
				double := strings.HasSuffix(en.Name, "_D")
				var word uint32
				for _, b := range cl.Diagram.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					pos := b.Hi
					var fixedMask, fixedValue uint32
					for _, c := range b.Cells {
						span := c.Span
						if span == 0 {
							span = 1
						}
						text := strings.Trim(strings.TrimSpace(c.Text), "()")
						if len(text) == span {
							for _, bit := range text {
								if bit == '0' || bit == '1' {
									fixedMask |= 1 << uint(pos)
									if bit == '1' {
										fixedValue |= 1 << uint(pos)
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
					case "size":
						value = 2
						if double {
							value = 3
						}
					case "Vd":
						value = 7
					case "Vn":
						value = 8
					case "Vm":
						value = 12
					}
					region := ((uint32(1) << uint(width)) - 1) << uint(b.Hi-width+1)
					word |= (value<<uint(b.Hi-width+1))&(region&^fixedMask) | fixedValue
				}
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", en.Name)
				words++
			}
		}
	}
	if pages != 14 || words != 56 {
		t.Fatalf("legacy VFP primary fixture pages=%d words=%d", pages, words)
	}
	t.Logf("June physical corpus: %d pages, %d words; legacy behavior ARM DDI0406C.d D11", pages, words)
	out.WriteString("];\n")
	return out.String()
}

const a32LegacyVfpTests = `
#[cfg(test)]
mod legacy_vectors {
    use super::{
        recipes::{self, LegacyVfpContext, LegacyVfpExceptions},
        semantics::*,
        Decoded, Mode, LEGACY_CORPUS,
    };
    use std::{cell::RefCell, collections::HashMap};
    #[derive(Clone)]
    struct State {
        d: [u64; 32],
        fpscr: u32,
        fpexc: u32,
        it: u8,
        z: u64,
        reads: RefCell<Vec<Register>>,
        fp: RefCell<Vec<(FloatOperation, FloatProjection, Vec<u64>, u64)>>,
    }
    impl State {
        fn new(width: u8, len: u32, stride: u32) -> Self {
            let mut s = Self {
                d: [0; 32],
                fpscr: (len << 16) | (stride << 20),
                fpexc: 0x40000000,
                it: 0,
                z: 0,
                reads: RefCell::new(vec![]),
                fp: RefCell::new(vec![]),
            };
            for n in 0..32 {
                if width == 64 {
                    s.d[n] = (n as f64 + 1.).to_bits()
                } else {
                    s.d[n] = u64::from(((2 * n as u32 + 1) as f32).to_bits())
                        | (u64::from(((2 * n as u32 + 2) as f32).to_bits()) << 32)
                }
            }
            s
        }
        fn read(&self, n: u32, w: u8) -> u64 {
            if w == 64 {
                self.d[n as usize]
            } else {
                self.d[n as usize / 2] >> ((n % 2) * 32) & 0xffffffff
            }
        }
        fn set(&mut self, n: u32, w: u8, b: u64) {
            if w == 64 {
                self.d[n as usize] = b
            } else {
                let shift = (n % 2) * 32;
                self.d[n as usize / 2] =
                    (self.d[n as usize / 2] & !(0xffffffff << shift)) | ((b & 0xffffffff) << shift)
            }
        }
        fn commit(&mut self, t: &Transition) {
            for w in &t.registers {
                assert!(w.value.is_known());
                match w.register.bank {
                    "a32.vector64" => self.d[usize::from(w.register.index)] = w.value.bits,
                    "a32.fpscr" => self.fpscr = w.value.bits as u32,
                    "a32.fpexc" => self.fpexc = w.value.bits as u32,
                    "a32.itstate" => self.it = w.value.bits as u8,
                    _ => panic!("unexpected write {w:?}"),
                }
            }
        }
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            self.reads.borrow_mut().push(r);
            match r.bank {
                "a32.vector64" => Value::known(64, self.d[usize::from(r.index)]),
                "a32.fpscr" => Value::known(32, u64::from(self.fpscr)),
                "a32.fpexc" => Value::known(32, u64::from(self.fpexc)),
                "a32.itstate" => Value::known(8, u64::from(self.it)),
                "a32.nzcv" => Value::known(1, if r.index == 1 { self.z } else { 0 }),
                _ => panic!("unexpected input {r:?}"),
            }
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("VFP arithmetic touched memory")
        }
        fn evaluate_float(
            &self,
            f: &FloatExpression,
            inputs: &[Value],
            control: Value,
            status: Value,
        ) -> Result<Value, EvalError> {
            assert_eq!(f.environment, FloatEnvironment::A32Vfp);
            assert_eq!(control.bits, u64::from(self.fpscr));
            assert!(control.is_known() && status.is_known() && inputs.iter().all(|x| x.is_known()));
            let bits = inputs.iter().map(|v| v.bits).collect::<Vec<_>>();
            self.fp
                .borrow_mut()
                .push((f.operation, f.projection, bits.clone(), status.bits));
            let number = |b: u64| {
                if f.width == 32 {
                    f64::from(f32::from_bits(b as u32))
                } else {
                    f64::from_bits(b)
                }
            };
            let a = number(bits[0]);
            let b = bits.get(1).copied().map(number).unwrap_or(0.);
            let raised = if inputs.iter().any(|v| {
                if f.width == 32 {
                    v.bits == 0x7f800001
                } else {
                    v.bits == 0x7ff0000000000001
                }
            }) {
                1
            } else {
                0
            };
            let value = match f.operation {
                FloatOperation::Add => a + b,
                FloatOperation::Subtract => a - b,
                FloatOperation::Multiply => a * b,
                FloatOperation::Divide => a / b,
                FloatOperation::SquareRoot => a.sqrt(),
                _ => panic!("unexpected operation"),
            };
            Ok(match f.projection {
                FloatProjection::Value => Value::known(
                    f.width,
                    if f.width == 32 {
                        u64::from((value as f32).to_bits())
                    } else {
                        value.to_bits()
                    },
                ),
                FloatProjection::Status => Value::known(32, status.bits | raised),
                FloatProjection::Trapped => {
                    Value::known(1, u64::from(raised != 0 && control.bits & 0x100 != 0))
                }
            })
        }
    }
    // Architectural source availability is independent of destination
    // preservation. Only selected source slices can be required by the FP
    // engine; untouched output bits remain unknown in the transition.
    struct Sparse {
        inner: State,
        available: [u64;32],
    }
    impl Machine for Sparse {
        fn read_register(&self, register: Register) -> Value {
            let mut value = self.inner.read_register(register);
            if register.bank == "a32.vector64" {
                value.defined &= self.available[usize::from(register.index)];
            }
            value
        }
        fn read_memory(&self, _:u64, _:u8, _:Endian)->Result<Value,EvalError> {
            panic!("VFP touched memory")
        }
        fn evaluate_float(&self, f:&FloatExpression, inputs:&[Value], control:Value, status:Value)->Result<Value,EvalError> {
            self.inner.evaluate_float(f,inputs,control,status)
        }
    }
    #[test]
    fn sparse_destinations_are_outputs_and_unselected_lanes_stay_unavailable() {
        for thumb in [false,true] {
            for exceptions in [LegacyVfpExceptions::Untrapped,LegacyVfpExceptions::SynchronousV3] {
                for width in [32,64] {
                    let bank=if width==32 {8} else {4};
                    for len in 0..if width==32 {8} else {4} {
                        let mut sparse=Sparse{inner:State::new(width,len,0),available:[0;32]};
                        let allow=|available:&mut [u64;32],n:u32| {
                            if width==64 {available[n as usize]=u64::MAX;}
                            else {available[n as usize/2]|=0xffffffff << ((n%2)*32);}
                        };
                        allow(&mut sparse.available,0);
                        for lane in 0..=len {allow(&mut sparse.available,bank*2+lane);}
                        let decoded=word(0xee300a00,width,bank,bank*2,0);
                        let transition=evaluate(&recipe(decoded,thumb,exceptions),&sparse).unwrap();
                        assert!(transition.trap.is_none());
                        let writes=transition.registers.iter().filter(|w|w.register.bank=="a32.vector64").collect::<Vec<_>>();
                        assert_eq!(writes.len(),len as usize+1);
                        for lane in 0..bank {
                            let n=bank+lane;
                            let register=if width==64 {n} else {n/2} as u16;
                            let shift=if width==64 {0} else {(n%2)*32};
                            let selected=writes.iter().rev().find(|w|w.register.index==register);
                            let defined=selected.map_or(0,|w|w.value.defined >> shift)&mask(width);
                            assert_eq!(defined,if lane<=len {mask(width)} else {0},"w{width} LEN{len} lane{lane}");
                            if lane<=len {
                                let actual=(selected.unwrap().value.bits >> shift)&mask(width);
                                let expected=host(0,sparse.inner.read(bank*2+lane,width),sparse.inner.read(0,width),0,width);
                                assert_eq!(actual,expected);
                            }
                        }
                    }
                }
            }
        }
    }

    fn context(exceptions: LegacyVfpExceptions) -> LegacyVfpContext {
        LegacyVfpContext {
            d_registers: 32,
            exceptions,
        }
    }
    fn recipe(word: u32, thumb: bool, exceptions: LegacyVfpExceptions) -> Recipe {
        let decoded = Decoded {
            raw: word,
            mode: if thumb { Mode::Thumb } else { Mode::Arm },
            length: 4,
        };
        let r = decoded
            .legacy_vfp_recipe(0x1000, context(exceptions))
            .unwrap_or_else(|| panic!("unrecognized {word:08x}"));
        assert_eq!(r.support, Support::Full);
        r.validate().unwrap();
        r
    }
    fn word(base: u32, w: u8, d: u32, n: u32, m: u32) -> u32 {
        let unary = matches!(
            base & 0x0fbf0ed0,
            0x0eb00a40 | 0x0eb00ac0 | 0x0eb10a40 | 0x0eb10ac0
        );
        let immediate = base & 0x0fb00ef0 == 0x0eb00a00;
        let mut v = (base & !0x004ff1af) | if w == 64 { 0x100 } else { 0 };
        if w == 32 {
            v |= (d / 2) << 12 | (d % 2) << 22 | (m / 2) | (m % 2) << 5
        } else {
            v |= (d & 15) << 12 | (d >> 4) << 22 | (m & 15) | (m >> 4) << 5
        }
        if unary {
            v |= base & 0x000f0080
        } else if immediate {
            v |= n << 16
        } else if w == 32 {
            v |= (n / 2) << 16 | (n % 2) << 7
        } else {
            v |= (n & 15) << 16 | (n >> 4) << 7
        }
        v
    }
    fn idx(first: u32, bank: u32, i: u32, stride: u32) -> u32 {
        first / bank * bank + (first % bank + i * stride) % bank
    }
    fn scalar(n: u32, w: u8) -> bool {
        if w == 32 {
            n < 8
        } else {
            n % 16 < 4
        }
    }
    fn host(op: u32, a: u64, b: u64, d: u64, w: u8) -> u64 {
        if w == 32 {
            let (a, b, d) = (
                f32::from_bits(a as u32),
                f32::from_bits(b as u32),
                f32::from_bits(d as u32),
            );
            u64::from(
                match op {
                    0 => a + b,
                    1 => a - b,
                    2 => a * b,
                    3 => a / b,
                    4 => b.sqrt(),
                    5 => d + a * b,
                    6 => d - a * b,
                    7 => -d + a * b,
                    8 => -d - a * b,
                    9 => -(a * b),
                    _ => unreachable!(),
                }
                .to_bits(),
            )
        } else {
            let (a, b, d) = (f64::from_bits(a), f64::from_bits(b), f64::from_bits(d));
            match op {
                0 => a + b,
                1 => a - b,
                2 => a * b,
                3 => a / b,
                4 => b.sqrt(),
                5 => d + a * b,
                6 => d - a * b,
                7 => -d + a * b,
                8 => -d - a * b,
                9 => -(a * b),
                _ => unreachable!(),
            }
            .to_bits()
        }
    }
    const OPS: [u32; 10] = [
        0xee300a00, 0xee300a40, 0xee200a00, 0xee800a00, 0xeeb10ac0, 0xee000a00, 0xee000a40,
        0xee100a00, 0xee100a40, 0xee200a40,
    ];
    #[test]
    fn arithmetic_wrap_broadcast_and_scalar_banks_match_sequential_reference() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                let bank = if w == 32 { 8 } else { 4 };
                for (len, stride_bits) in [(0, 0), (1, 0), (1, 3), (2, 0), (3, 0), (7, 0), (3, 3)] {
                    for (d, n, m) in [
                        (bank * 2 - 1, bank * 2, bank * 3),
                        (bank * 2 - 1, 0, 1),
                        (bank * 2 - 1, bank, bank * 2 - 2),
                        (0, bank * 2, bank * 3),
                        (if w == 64 { 16 } else { 2 }, bank, bank * 3),
                    ] {
                        let vector = len != 0 && !scalar(d, w);
                        let stride = if stride_bits == 3 { 2 } else { 1 };
                        if w == 64 && vector && (len + 1) * stride > 4 {
                            continue;
                        }
                        for (op, base) in OPS.into_iter().enumerate() {
                            let n = if op == 4 {
                                if w == 32 {
                                    2
                                } else {
                                    1
                                }
                            } else {
                                n
                            };
                            let mut expected = State::new(w, len, stride_bits);
                            let before = expected.clone();
                            let iterations = if vector { len + 1 } else { 1 };
                            for i in 0..iterations {
                                let di = idx(d, bank, i, if vector { stride } else { 0 });
                                let ni = idx(n, bank, i, if vector { stride } else { 0 });
                                let mi = idx(
                                    m,
                                    bank,
                                    i,
                                    if vector && !scalar(m, w) { stride } else { 0 },
                                );
                                let value = host(
                                    op as u32,
                                    expected.read(ni, w),
                                    expected.read(mi, w),
                                    expected.read(di, w),
                                    w,
                                );
                                expected.set(di, w, value);
                            }
                            let r = recipe(
                                word(base, w, d, n, m),
                                thumb,
                                LegacyVfpExceptions::Untrapped,
                            );
                            let t = evaluate(&r, &before).unwrap();
                            assert!(t.trap.is_none());
                            let mut got = before.clone();
                            got.commit(&t);
                            assert_eq!(
                                got.d, expected.d,
                                "{base:08x} width{w} d{d} n{n} m{m} len{len} stride{stride_bits}"
                            );
                            assert_eq!(got.fpscr, before.fpscr);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn bitwise_unary_and_immediate_vectors_preserve_nan_payloads_and_scalar_sources() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                let bank = if w == 32 { 8 } else { 4 };
                for source in [1, bank * 2 - 1] {
                    for op in 0..3 {
                        let mut s = State::new(w, 1, 3);
                        s.fpscr |= 0x9f00;
                        let nan = if w == 32 {
                            0xff812345
                        } else {
                            0xfff0123456789abc
                        };
                        s.set(source, w, nan);
                        let before = s.clone();
                        let base = match op {
                            0 => 0xeeb00a40,
                            1 => 0xeeb00ac0,
                            _ => 0xeeb10a40,
                        };
                        let word = word(
                            base,
                            w,
                            bank + 1,
                            if op == 2 {
                                if w == 32 {
                                    2
                                } else {
                                    1
                                }
                            } else {
                                0
                            },
                            source,
                        );
                        let t = evaluate(&recipe(word, thumb, LegacyVfpExceptions::Untrapped), &s)
                            .unwrap();
                        s.commit(&t);
                        let mut expected = before.clone();
                        for i in 0..2 {
                            let d = idx(bank + 1, bank, i, 2);
                            let m = if scalar(source, w) {
                                source
                            } else {
                                idx(source, bank, i, 2)
                            };
                            let old = expected.read(m, w);
                            expected.set(
                                d,
                                w,
                                match op {
                                    0 => old,
                                    1 => old & !(1 << (w - 1)),
                                    _ => old ^ (1 << (w - 1)),
                                },
                            );
                        }
                        assert_eq!(
                            s.d, expected.d,
                            "bits op{op} width{w} source{source} word{word:08x}"
                        );
                        assert_eq!(s.fpscr, before.fpscr);
                        assert!(s.fp.borrow().is_empty());
                    }
                }
                let mut s = State::new(w, 1, 0);
                let before = s.clone();
                let d = bank * 2 - 1;
                let immediate = word(0xeeb70a00, w, d, 7, 0);
                let t = evaluate(
                    &recipe(immediate, thumb, LegacyVfpExceptions::Untrapped),
                    &s,
                )
                .unwrap();
                s.commit(&t);
                let mut expected = before.clone();
                for i in 0..2 {
                    expected.set(
                        idx(d, bank, i, 1),
                        w,
                        if w == 32 {
                            1f32.to_bits() as u64
                        } else {
                            1f64.to_bits()
                        },
                    );
                }
                assert_eq!(s.d, expected.d);
                assert!(s.fp.borrow().is_empty());
            }
        }
    }
    #[test]
    fn invalid_modes_and_unimplemented_banks_reject_before_operands() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                let bank = if w == 32 { 8 } else { 4 };
                for len in 0..8 {
                    for stride in 0..4 {
                        for d in [0, bank, if w == 64 { 16 } else { 24 }] {
                            let s = State::new(w, len, stride);
                            let permitted = stride == 0 || (stride == 3 && (1..=3).contains(&len));
                            let vector = len != 0 && !scalar(d, w);
                            let valid = permitted
                                && !(w == 64
                                    && vector
                                    && (len + 1) * if stride == 3 { 2 } else { 1 } > 4);
                            let r = recipe(
                                word(0xee300a00, w, d, bank, bank * 2),
                                thumb,
                                LegacyVfpExceptions::Untrapped,
                            );
                            let t = evaluate(&r, &s);
                            if valid {
                                assert!(t.is_ok())
                            } else {
                                assert_eq!(t, Err(EvalError::UnsupportedContext));
                                assert!(s.fp.borrow().is_empty());
                                assert!(s.reads.borrow().iter().all(|r| r.bank == "a32.fpscr"
                                    || r.bank == "a32.itstate"
                                    || r.bank == "a32.nzcv"));
                            }
                        }
                    }
                }
            }
        }
        let word = word(0xee300a00, 64, 20, 4, 8);
        let mut c = context(LegacyVfpExceptions::Untrapped);
        c.d_registers = 16;
        let r = recipes::for_legacy_vfp(word, 4, 0x1000, false, c).unwrap();
        assert!(matches!(r.support, Support::Unsupported(_)));
        for c in [0, 8, 24, 64] {
            let r = recipes::for_legacy_vfp(
                0xee300a00,
                4,
                0x1000,
                false,
                LegacyVfpContext {
                    d_registers: c,
                    exceptions: LegacyVfpExceptions::Untrapped,
                },
            )
            .unwrap();
            assert!(matches!(r.support, Support::Unsupported(_)));
        }
    }
    #[test]
    fn conditions_and_it_skip_unavailable_context_and_advance_only_successful_instructions() {
        for thumb in [false, true] {
            let mut s = State::new(32, 7, 3);
            s.fpscr |= 0x100;
            s.fpexc = 0xc0000000;
            s.z = 1;
            s.it = if thumb { 0x18 } else { 0 };
            let word = word(if thumb { 0xee300a00 } else { 0x1e300a00 }, 32, 8, 16, 24);
            let r = recipe(word, thumb, LegacyVfpExceptions::SynchronousV3);
            let t = evaluate(&r, &s).unwrap();
            assert!(s.fp.borrow().is_empty());
            assert!(s
                .reads
                .borrow()
                .iter()
                .all(|r| r.bank == "a32.itstate" || r.bank == "a32.nzcv"));
            s.commit(&t);
            assert_eq!(s.it, 0);
        }
    }
    #[test]
    fn malformed_thumb_itstate_rejects_before_context_or_operands_without_transition() {
        let r = recipe(0xeeb04a40, true, LegacyVfpExceptions::Untrapped);
        for it in (0x10..=0xf0u8).step_by(16) {
            let mut s = State::new(32, 1, 0);
            s.it = it;
            let before = (s.d, s.fpscr, s.fpexc, s.it);
            assert_eq!(
                evaluate(&r, &s),
                Err(EvalError::UnsupportedContext),
                "IT={it:#x}"
            );
            assert_eq!((s.d, s.fpscr, s.fpexc, s.it), before);
            assert!(s.fp.borrow().is_empty());
            assert!(s.reads.borrow().iter().all(|r| r.bank == "a32.itstate"));
        }
        for (it, z, executes) in [(0, 0, true), (0x18, 0, true), (0x18, 1, false)] {
            let mut s = State::new(32, 1, 0);
            s.it = it;
            s.z = z;
            let before = s.d;
            let source = (s.read(0, 32), s.read(0, 32));
            let t = evaluate(&r, &s).unwrap();
            s.commit(&t);
            assert_eq!(s.it, 0);
            if executes {
                assert_eq!((s.read(8, 32), s.read(9, 32)), source);
            } else {
                assert_eq!(s.d, before);
                assert!(s
                    .reads
                    .borrow()
                    .iter()
                    .all(|r| r.bank == "a32.itstate" || r.bank == "a32.nzcv"));
            }
        }
    }
    #[test]
    fn synchronous_bounce_commits_earlier_lanes_and_stops_before_exceptional_destination() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                for exceptional in 0..4u32 {
                    let bank = if w == 32 { 8 } else { 4 };
                    let mut s = State::new(w, 3, 0);
                    s.fpscr |= 0x100;
                    s.it = if thumb { 0x18 } else { 0 };
                    s.z = 0;
                    s.set(
                        idx(bank * 2, bank, exceptional, 1),
                        w,
                        if w == 32 {
                            0x7f800001
                        } else {
                            0x7ff0000000000001
                        },
                    );
                    let before = s.clone();
                    let word = word(0xee300a00, w, bank, bank * 2, 1);
                    let r = recipe(word, thumb, LegacyVfpExceptions::SynchronousV3);
                    let t = evaluate(&r, &s).unwrap();
                    assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
                    s.commit(&t);
                    let mut expected = before.clone();
                    for i in 0..exceptional {
                        let d = idx(bank, bank, i, 1);
                        expected.set(
                            d,
                            w,
                            host(
                                0,
                                expected.read(idx(bank * 2, bank, i, 1), w),
                                expected.read(1, w),
                                expected.read(d, w),
                                w,
                            ),
                        );
                    }
                    assert_eq!(s.d, expected.d);
                    assert_eq!(s.fpscr, before.fpscr | 1);
                    assert_eq!(
                        s.fpexc,
                        0x68000000 | (((3 - exceptional).wrapping_sub(1) & 7) << 8)
                    );
                    assert_eq!(
                        s.it, before.it,
                        "faulting Thumb instruction must not advance ITSTATE"
                    );
                    let calls = s.fp.borrow();
                    assert_eq!(
                        calls
                            .iter()
                            .filter(|(_, p, _, _)| *p == FloatProjection::Value)
                            .count(),
                        exceptional as usize + 1
                    );
                    assert_eq!(calls.last().unwrap().3, u64::from(before.fpscr));
                }
            }
        }
    }
    #[test]
    fn nonfused_multiply_trap_suppresses_add_and_all_later_iterations() {
        for thumb in [false, true] {
            let mut s = State::new(32, 3, 0);
            s.fpscr |= 0x100;
            s.set(16, 32, 0x7f800001);
            let before = s.clone();
            let t = evaluate(
                &recipe(
                    word(0xee000a00, 32, 8, 16, 24),
                    thumb,
                    LegacyVfpExceptions::SynchronousV3,
                ),
                &s,
            )
            .unwrap();
            assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
            s.commit(&t);
            assert_eq!(s.d, before.d);
            assert!(s
                .fp
                .borrow()
                .iter()
                .all(|(op, _, _, _)| *op == FloatOperation::Multiply));
            assert_eq!(s.fp.borrow().len(), 3);
        }
    }
    #[test]
    fn nonfused_add_and_scalar_bounces_preserve_the_exceptional_output() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                let bank = if w == 32 { 8 } else { 4 };
                for scalar_destination in [false, true] {
                    let d = if scalar_destination { 0 } else { bank };
                    let mut s = State::new(w, 3, 0);
                    s.fpscr |= 0x100;
                    s.set(
                        d,
                        w,
                        if w == 32 {
                            0x7f800001
                        } else {
                            0x7ff0000000000001
                        },
                    );
                    let before = s.clone();
                    let t = evaluate(
                        &recipe(
                            word(0xee000a00, w, d, bank * 2, bank * 3),
                            thumb,
                            LegacyVfpExceptions::SynchronousV3,
                        ),
                        &s,
                    )
                    .unwrap();
                    assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
                    s.commit(&t);
                    assert_eq!(s.d, before.d);
                    assert_eq!(s.fpscr, before.fpscr | 1);
                    assert_eq!(
                        s.fpexc,
                        0x68000000 | if scalar_destination { 0x700 } else { 0x200 }
                    );
                    let ops =
                        s.fp.borrow()
                            .iter()
                            .filter(|(_, p, _, _)| *p == FloatProjection::Value)
                            .map(|(op, _, _, _)| *op)
                            .collect::<Vec<_>>();
                    assert_eq!(ops, vec![FloatOperation::Multiply, FloatOperation::Add]);
                }
            }
        }
    }
    #[test]
    fn disabled_synchronous_context_rejects_bitwise_moves_before_operands() {
        let mut s = State::new(32, 1, 0);
        s.fpexc = 0;
        let r = recipe(
            word(0xeeb00a40, 32, 8, 0, 16),
            false,
            LegacyVfpExceptions::SynchronousV3,
        );
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
        assert!(s
            .reads
            .borrow()
            .iter()
            .all(|r| r.bank == "a32.fpscr" || r.bank == "a32.fpexc"));
    }
    #[test]
    fn sticky_status_and_scalar_controls_flow_between_vector_iterations() {
        for thumb in [false, true] {
            for w in [32u8, 64] {
                let bank = if w == 32 { 8 } else { 4 };
                let mut s = State::new(w, 1, 0);
                s.fpscr |= 0x02c00010;
                s.set(
                    bank * 2,
                    w,
                    if w == 32 {
                        0x7f800001
                    } else {
                        0x7ff0000000000001
                    },
                );
                let t = evaluate(
                    &recipe(
                        word(0xee300a00, w, bank, bank * 2, 1),
                        thumb,
                        LegacyVfpExceptions::Untrapped,
                    ),
                    &s,
                )
                .unwrap();
                assert!(t.trap.is_none());
                let calls = s.fp.borrow();
                let statuses = calls
                    .iter()
                    .filter(|(_, p, _, _)| *p == FloatProjection::Value)
                    .map(|(_, _, _, status)| *status)
                    .collect::<Vec<_>>();
                assert_eq!(statuses, vec![u64::from(s.fpscr), u64::from(s.fpscr | 1)]);
                drop(calls);
                let original = s.fpscr;
                s.commit(&t);
                assert_eq!(s.fpscr, original | 1);
            }
        }
    }
    #[test]
    fn exception_protocols_are_explicit_and_default_scalar_entry_is_unchanged() {
        let word = word(0xee300a00, 32, 8, 16, 24);
        let mut s = State::new(32, 1, 0);
        s.fpscr |= 0x100;
        assert_eq!(
            evaluate(&recipe(word, false, LegacyVfpExceptions::Untrapped), &s),
            Err(EvalError::UnsupportedContext)
        );
        assert!(s.fp.borrow().is_empty());
        for fpexc in [0, 0xc0000000, 0x60000000, 0x50000000, 0x44000000] {
            s.fpexc = fpexc;
            assert_eq!(
                evaluate(&recipe(word, false, LegacyVfpExceptions::SynchronousV3), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
        s.fpexc = 0x40000000;
        s.fpscr &= !0x100;
        let t = evaluate(&recipe(word, false, LegacyVfpExceptions::Untrapped), &s).unwrap();
        assert!(t.trap.is_none());
        assert_eq!(
            evaluate(&recipes::for_word(word, 0x1000), &s),
            Err(EvalError::UnsupportedContext)
        );
        for word in [
            0xeea00a81, 0xeeb70ae0, 0xeeb80ae0, 0xeebd0ae0, 0xeeb40a60, 0xeeb30a60,
        ] {
            assert!(recipes::for_legacy_vfp(
                word,
                4,
                0x1000,
                false,
                context(LegacyVfpExceptions::Untrapped)
            )
            .is_none());
        }
        assert!(recipes::for_legacy_vfp(
            word,
            2,
            0x1000,
            false,
            context(LegacyVfpExceptions::Untrapped)
        )
        .is_none());
    }
    #[test]
    fn primary_words_cover_every_legacy_instruction_in_both_execution_states() {
        let mut seen = HashMap::new();
        for &(word, thumb, name) in LEGACY_CORPUS {
            let w = if word & 0x100 == 0 { 32 } else { 64 };
            let bank = if w == 32 { 8 } else { 4 };
            let s = State::new(w, 1, 0);
            let mut expected = s.clone();
            let reg = |field: u32, bit: u32| {
                if w == 32 {
                    ((word >> field) & 15) * 2 + ((word >> bit) & 1)
                } else {
                    ((word >> field) & 15) + ((word >> bit) & 1) * 16
                }
            };
            let (d, n, m) = (reg(12, 22), reg(16, 7), reg(0, 5));
            for i in 0..if scalar(d, w) { 1 } else { 2 } {
                let di = idx(d, bank, i, 1);
                let ni = idx(n, bank, i, 1);
                let mi = idx(m, bank, i, if scalar(m, w) { 0 } else { 1 });
                let a = expected.read(ni, w);
                let b = expected.read(mi, w);
                let old = expected.read(di, w);
                let value = if name.starts_with("VMOV_i") {
                    assert_eq!((word >> 16) & 15 | word & 15, 0);
                    if w == 32 {
                        u64::from(2f32.to_bits())
                    } else {
                        2f64.to_bits()
                    }
                } else if name.starts_with("VMOV_r") {
                    b
                } else if name.starts_with("VABS") {
                    b & !(1 << (w - 1))
                } else if name.starts_with("VNEG") {
                    b ^ (1 << (w - 1))
                } else {
                    let op = if name.starts_with("VADD") {
                        0
                    } else if name.starts_with("VSUB") {
                        1
                    } else if name.starts_with("VMUL") {
                        2
                    } else if name.starts_with("VDIV") {
                        3
                    } else if name.starts_with("VSQRT") {
                        4
                    } else if name.starts_with("VMLA") {
                        5
                    } else if name.starts_with("VMLS") {
                        6
                    } else if name.starts_with("VNMLS") {
                        7
                    } else if name.starts_with("VNMLA") {
                        8
                    } else if name.starts_with("VNMUL") {
                        9
                    } else {
                        panic!("unknown primary instruction {name}")
                    };
                    host(op, a, b, old, w)
                };
                expected.set(di, w, value);
            }
            let r = recipe(word, thumb, LegacyVfpExceptions::Untrapped);
            let t = evaluate(&r, &s).unwrap();
            assert!(t.trap.is_none(), "{name}");
            let mut got = s.clone();
            got.commit(&t);
            assert_eq!(got.d, expected.d, "primary {name} {word:08x}");
            seen.insert((name, thumb), ());
        }
        assert_eq!(seen.len(), LEGACY_CORPUS.len());
    }
}
`

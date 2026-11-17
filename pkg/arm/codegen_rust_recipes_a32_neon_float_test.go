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

// Qualify physical vector encoding identities and ordered lane plumbing through
// a freshly generated decoder and the public portable evaluator.
func TestRustA32NeonFloatingArithmeticComparisonsAndPairwise(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32NeonFloatingPrimary(t, path)
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
	dir, err := os.MkdirTemp(base, "a32-neon-float-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "scalar.rs"), []byte(a32NeonFloatingBehavior+primary), 0644); err != nil {
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
			t.Fatalf("generated A32 NEON floating %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a32NeonFloatingPrimary(t *testing.T, path string) string {
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
	for _, n := range strings.Fields("vadd_f vsub_f vmul_f vmla_f vmls_f vfma vfms vabd_f vabs vneg vacge vacgt vceq_r vcge_r vcgt_r vceq_i vcge_i vcgt_i vcle_i vclt_i vmaxnm vminnm vmax_f vmin_f vpadd_f vpmax_f vpmin_f") {
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
	out.WriteString("#[test]fn primary_neon_floating_encoding_identities(){for(word,thumb,id)in[\n")
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
			vector := false
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "sz" || b.Name == "F" {
					vector = true
				}
			}
			if !vector {
				continue
			}
			classes++
			for _, e := range cl.Encodings {
				word := apply(0, cl.Diagram.Boxes)
				for _, b := range cl.Diagram.Boxes {
					if b.Name == "F" {
						word |= 1 << uint(b.Hi)
						word = (word &^ (3 << 18)) | (2 << 18)
					}
				}

				word = apply(word, e.Boxes)
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", e.Name)
				ids++
			}
		}
	}
	if len(wanted) != 0 || classes != 54 || ids != 102 {
		t.Fatalf("NEON floating primary coverage missing=%v classes=%d ids=%d", wanted, classes, ids)
	}
	out.WriteString("]{let d=physical_decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,\"{id} {word:08x}\");r.validate().unwrap();}}\n")
	t.Logf("qualified 27 primary pages, %d vector classes, %d encoding identities", classes, ids)
	return out.String()
}

const a32NeonFloatingPrelude = `use arm32::semantics::*;
use arm32::{decode, Decoded, Endian as CodeEndian, Mode};
use std::cell::RefCell;
fn decoded(w: u32, t: bool, e: CodeEndian) -> Decoded {
    let w = if t {
        (w & 0x00ffffff) | 0xef000000 | ((w & 0x01000000) << 4)
    } else {
        w
    };
    let bytes = if t {
        [(w >> 16) as u16, w as u16]
            .into_iter()
            .flat_map(|h| match e {
                CodeEndian::Little => h.to_le_bytes(),
                CodeEndian::Big => h.to_be_bytes(),
            })
            .collect::<Vec<_>>()
    } else {
        match e {
            CodeEndian::Little => w.to_le_bytes(),
            CodeEndian::Big => w.to_be_bytes(),
        }
        .to_vec()
    };
    decode(&bytes, if t { Mode::Thumb } else { Mode::Arm }, e)
        .unwrap_or_else(|x| panic!("{w:08x}/{t}: {x:?}"))
}
fn physical_decoded(w: u32, t: bool, e: CodeEndian) -> Decoded {
    decoded(
        if t {
            (w & 0x00ffffff) | 0xf2000000 | ((w & 0x10000000) >> 4)
        } else {
            w
        },
        t,
        e,
    )
}
struct State {
    vectors: [u64; 32],
    it: u8,
    z: u64,
    nzcv: u64,
    calls: RefCell<Vec<(FloatOperation, u8, Vec<u64>)>>,
}
fn state(width: u8) -> State {
    let mut s = State {
        vectors: [0; 32],
        it: 0,
        z: 1,
        nzcv: 6,
        calls: RefCell::new(vec![]),
    };
    for n in 0..32 {
        for lane in 0..64 / width {
            s.vectors[n] |= (1 + n as u64 * 8 + u64::from(lane)) << u32::from(lane * width);
        }
    }
    s
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a32.vector64" => Value::known(64, self.vectors[usize::from(r.index)]),
            "a32.fpscr" => Value::known(32, 0xa4c01f80),
            "a32.itstate" => Value::known(8, u64::from(self.it)),
            "a32.nzcv" => Value::known(1, if r.index == 1 { self.z } else { 0 }),
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("no memory in vector floating arithmetic")
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        assert_eq!(f.environment, FloatEnvironment::A32Neon);
        assert_eq!(control.bits, 0xa4c01f80);
        self.calls
            .borrow_mut()
            .push((f.operation, f.width, v.iter().map(|x| x.bits).collect()));
        Ok(match f.projection {
            FloatProjection::Value => Value::known(
                f.width,
                if f.width == 4 {
                    self.nzcv
                } else {
                    v.iter().fold(0, |sum, x| sum + x.bits)
                },
            ),
            FloatProjection::Status => Value::known(32, status.bits | 1),
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
fn out(t: &Transition, n: u16) -> u64 {
    t.registers
        .iter()
        .rev()
        .find(|v| v.register.bank == "a32.vector64" && v.register.index == n)
        .unwrap()
        .value
        .bits
}
fn word(base: u32, d: u32, n: u32, m: u32, q: bool, width: u8) -> u32 {
    base | ((d & 15) << 12)
        | ((d & 16) << 18)
        | ((n & 15) << 16)
        | ((n & 16) << 3)
        | (m & 15)
        | ((m & 16) << 1)
        | if q { 64 } else { 0 }
        | if width == 16 { 1 << 20 } else { 0 }
}
`

const a32NeonFloatingBehavior = a32NeonFloatingPrelude + `#[test]
fn binary_pairwise_and_accumulating_sources_preserve_all_aliases_and_lane_order() {
    for thumb in [false, true] {
        for endian in [CodeEndian::Little, CodeEndian::Big] {
            for width in [16u8, 32] {
                for base in [
                    0xf2000d00, 0xf2200d00, 0xf3000d10, 0xf3200d00, 0xf2000f00, 0xf2200f00,
                    0xf3000f10, 0xf3200f10, 0xf3000d00, 0xf3000f00, 0xf3200f00, 0xf2000c10,
                    0xf2200c10, 0xf2000d10, 0xf2200d10,
                ] {
                    for q in [false, true] {
                        let pair = matches!(base, 0xf3000d00 | 0xf3000f00 | 0xf3200f00);
                        if pair && q {
                            continue;
                        }
                        for d in [0, 1, 15, 16, 30, 31] {
                            for n in [0, 1, 15, 16, 30, 31] {
                                for m in [0, 1, 15, 16, 30, 31] {
                                    if q && (d | n | m) & 1 != 0 {
                                        continue;
                                    }
                                    let w = word(base, d, n, m, q, width);
                                    let r = decoded(w, thumb, endian).semantic_recipe(0x1000);
                                    assert_eq!(r.support, Support::Full, "{w:08x}");
                                    r.validate().unwrap();
                                    let s = state(width);
                                    let t = evaluate(&r, &s).unwrap();
                                    let calls = s.calls.borrow();
                                    let values: Vec<_> = calls.iter().step_by(3).collect();
                                    let accumulating = matches!(
                                        base,
                                        0xf2000c10 | 0xf2200c10 | 0xf2000d10 | 0xf2200d10
                                    );
                                    if !accumulating {
                                        assert_eq!(
                                            values.len(),
                                            usize::from(64 / width) * if q { 2 } else { 1 }
                                        );
                                        for chunk in 0..if q { 2 } else { 1 } {
                                            for lane in 0..64 / width {
                                                let mask = (1u64 << width) - 1;
                                                let get = |reg: u32, index: u8| {
                                                    s.vectors[reg as usize]
                                                        >> u32::from(index * width)
                                                        & mask
                                                };
                                                let (a, b) = if pair {
                                                    let src = if lane < 32 / width { n } else { m };
                                                    let i = lane % (32 / width) * 2;
                                                    (get(src, i), get(src, i + 1))
                                                } else {
                                                    (get(n + chunk, lane), get(m + chunk, lane))
                                                };
                                                let call = values[(chunk as usize)
                                                    * usize::from(64 / width)
                                                    + usize::from(lane)];
                                                assert_eq!(call.1, width);
                                                assert_eq!(
                                                    call.2,
                                                    vec![a, b],
                                                    "{w:08x} lane{lane}"
                                                );
                                                assert_eq!(
                                                    out(&t, (d + chunk) as u16)
                                                        >> u32::from(lane * width)
                                                        & mask,
                                                    a + b
                                                );
                                            }
                                        }
                                    } else {
                                        assert!(calls.iter().all(|(_, w, _)| *w == width));
                                    }
                                    assert!(t
                                        .registers
                                        .iter()
                                        .filter(|v| v.register.bank == "a32.fpscr")
                                        .all(|v| v.value.bits == 0xa4c01f81));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn comparisons_project_every_nzcv_result_to_full_lane_masks() {
    for thumb in [false, true] {
        for width in [16u8, 32] {
            for (base, kind, zero, absolute) in [
                (0xf2000e00, 0, false, false),
                (0xf3000e00, 1, false, false),
                (0xf3200e00, 2, false, false),
                (0xf3000e10, 1, false, true),
                (0xf3200e10, 2, false, true),
                (0xf3b90500, 0, true, false),
                (0xf3b90480, 1, true, false),
                (0xf3b90400, 2, true, false),
                (0xf3b90580, 3, true, false),
                (0xf3b90600, 4, true, false),
            ] {
                for q in [false, true] {
                    let w = if zero {
                        (base & !0x000c0000)
                            | if width == 16 { 1 << 18 } else { 2 << 18 }
                            | 0x22
                            | if q { 64 } else { 0 }
                    } else {
                        word(base, 0, 2, 4, q, width)
                    };
                    let r = decoded(w, thumb, CodeEndian::Little).semantic_recipe(0x1000);
                    assert_eq!(r.support, Support::Full, "{w:08x}");
                    r.validate().unwrap();
                    for nzcv in 0..16 {
                        let mut s = state(width);
                        s.nzcv = nzcv;
                        let t = evaluate(&r, &s).unwrap();
                        let passed = match kind {
                            0 => nzcv & 4 != 0,
                            1 => nzcv & 3 == 2,
                            2 => nzcv & 7 == 2,
                            3 => nzcv & 12 != 0,
                            _ => nzcv & 8 != 0,
                        };
                        assert_eq!(
                            out(&t, 0),
                            if passed { u64::MAX } else { 0 },
                            "{w:08x} NZCV{nzcv:x}"
                        );
                        if q {
                            assert_eq!(out(&t, 1), if passed { u64::MAX } else { 0 });
                        }
                        for (o, w, v) in s.calls.borrow().iter() {
                            assert_eq!(*w, 4);
                            assert_eq!(
                                *o,
                                FloatOperation::Compare {
                                    source_width: width,
                                    signal_all_nans: kind != 0
                                }
                            );
                            if zero {
                                assert_eq!(v[1], 0);
                            }
                            if absolute {
                                assert!(v.iter().all(|x| x & (1 << (width - 1)) == 0));
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn physical_fp16_requirements_and_it_rejection_precede_vector_inputs() {
    for base in [
        0xf2100d00, 0xf3100d00, 0xf3100e00, 0xf3b50400, 0xf3b50700, 0xf3b50780,
    ] {
        for thumb in [false, true] {
            let d = decoded(base, thumb, CodeEndian::Little);
            assert_eq!(
                d.requirements().expression.evaluate_with(
                    &|n| if n == "FEAT_FP16" { Some(false) } else { None },
                    if thumb { "thumb" } else { "a32" },
                    &|name| d.field(name).map(u64::from)
                ),
                arm32::requirements::Satisfaction::Unsatisfied,
                "{base:08x}"
            );
            if thumb {
                for z in [0, 1] {
                    let mut s = state(16);
                    s.it = 8;
                    s.z = z;
                    assert_eq!(
                        evaluate(&d.semantic_recipe(0x1000), &s),
                        Err(EvalError::UnsupportedContext)
                    );
                    assert!(s.calls.borrow().is_empty());
                }
            }
        }
    }
}
`

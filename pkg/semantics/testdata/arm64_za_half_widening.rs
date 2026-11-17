#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
const FORMS: &[(u32, u8, u16, bool)] = &[
    (0xc1801000, 0, 1, false),
    (0xc1901000, 0, 2, false),
    (0xc1909000, 0, 4, false),
    (0xc1200c00, 1, 1, false),
    (0xc1200800, 1, 2, false),
    (0xc1300800, 1, 4, false),
    (0xc1a00800, 2, 2, false),
    (0xc1a10800, 2, 4, false),
    (0xc1801008, 0, 1, true),
    (0xc1901008, 0, 2, true),
    (0xc1909008, 0, 4, true),
    (0xc1200c08, 1, 1, true),
    (0xc1200808, 1, 2, true),
    (0xc1300808, 1, 4, true),
    (0xc1a00808, 2, 2, true),
    (0xc1a10808, 2, 4, true),
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_half_widening::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    ctrl: u32,
    w: u32,
    calls: Vec<(u8, bool, u64, u64, u64)>,
    at: Cell<usize>,
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1 << w) - 1
    }
}
fn marker(i: usize, w: u8) -> u64 {
    0xe71ab35d6219acf0u64.wrapping_mul(i as u64 + 1) & mask(w)
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.svcr" => self.sm,
                "a64.fpcr" => u64::from(self.ctrl),
                "a64.gpr" => u64::from(self.w),
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.za64" => self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                _ => panic!("unexpected read {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        ctrl: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = self.at.get();
        let (w, bf, acc, a, b) = self.calls[i];
        assert_eq!(f.operation, FloatOperation::ZaFused { bfloat: bf });
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(f.width, w);
        assert_eq!(
            v,
            [Value::known(w, acc), Value::known(w, a), Value::known(w, b)]
        );
        assert_eq!(ctrl, Value::known(32, u64::from(self.ctrl)));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(w, marker(i, w)))
    }
}
#[test]
fn all_half_widening_entries_lengths_indices_source_groups_row_wrap_and_backing() {
    for &(base, kind, nreg, sub) in FORMS {
        let width = 32u8;
        let bf = false;
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if kind == 0 { 8 } else { 1 } {
                    let n = if kind == 1 { 31 } else { 32 - u32::from(nreg) };
                    let m = if kind == 2 {
                        32 - u32::from(nreg)
                    } else if pattern == 0 {
                        0
                    } else {
                        15
                    };
                    let off = if nreg == 1 { pattern * 3 } else { pattern };
                    let ix = if kind != 0 {
                        0
                    } else if nreg == 1 {
                        ((index >> 2) << 15) | ((index & 3) << 10)
                    } else {
                        ((index >> 1) << 10) | ((index & 1) << 2)
                    };
                    let word = base | (n << 5) | (m << 16) | (pattern << 13) | off | ix;
                    let mut s = State {
                        z: std::array::from_fn(|n| {
                            std::array::from_fn(|c| {
                                0x9127356bdcfa8231u64.wrapping_mul((n * 32 + c + 1) as u64)
                            })
                        }),
                        za: (0..256)
                            .map(|r| {
                                std::array::from_fn(|c| {
                                    0x8f2e731a6954bcd1u64.wrapping_mul((r * 32 + c + 1) as u64)
                                })
                            })
                            .collect(),
                        sm: 3,
                        ctrl: if pattern == 0 {
                            0x07c09f03
                        } else {
                            0x07c09f03 & !(1 << 19)
                        },
                        w: if pattern == 0 {
                            0
                        } else if pattern == 1 {
                            u32::MAX
                        } else {
                            u32::from(vl / 8 / nreg) - 1
                        },
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    let stride = vl / 8 / nreg;
                    let row0 = ((u64::from(s.w) + u64::from(off * 2)) % u64::from(stride)) & !1;
                    let mut expected = s.za.clone();
                    let lane = |reg: u32, e: u16| {
                        let bit = e * 16;
                        (s.z[reg as usize][usize::from(bit / 64)] >> (bit % 64)) & 0xffff
                    };
                    let widen = |h: u64| {
                        let sign = (h & 0x8000) << 16;
                        let ex = (h >> 10) & 31;
                        let frac = h & 1023;
                        if ex == 31 {
                            return sign | 0x7f800000 | (frac << 13);
                        }
                        if ex == 0 && s.ctrl & (1 << 19) != 0 {
                            return sign;
                        }
                        let value = if ex == 0 {
                            (frac as f64) * 2f64.powi(-24)
                        } else {
                            (1f64 + (frac as f64) / 1024f64) * 2f64.powi(ex as i32 - 15)
                        };
                        sign | u64::from((value as f32).to_bits())
                    };
                    for member in 0..nreg {
                        for pair in 0..2u16 {
                            let row = row0 as usize + usize::from(member * stride + pair);
                            for chunk in 0..vl / 64 {
                                let old = s.za[row][usize::from(chunk)];
                                let mut out = 0;
                                for part in 0..2 {
                                    let e = chunk * 2 + part;
                                    let shift = part * 32;
                                    let src = if kind == 0 {
                                        2 * (e / 4 * 4) + index as u16
                                    } else {
                                        2 * e + pair
                                    };
                                    let i = s.calls.len();
                                    let a = lane((n + u32::from(member)) % 32, 2 * e + pair)
                                        ^ if sub { 0x8000 } else { 0 };
                                    let y = lane(
                                        m + if kind == 2 { u32::from(member) } else { 0 },
                                        src,
                                    );
                                    s.calls.push((
                                        width,
                                        bf,
                                        (old >> shift) & 0xffff_ffff,
                                        widen(a),
                                        widen(y),
                                    ));
                                    out |= marker(i, width) << shift;
                                }
                                expected[row][usize::from(chunk)] = out;
                            }
                        }
                    }
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    let mut actual = s.za.clone();
                    for wr in t.registers {
                        assert_eq!(wr.register.bank, "a64.za64");
                        assert!(wr.value.is_known());
                        actual[usize::from(wr.register.index / 32)]
                            [usize::from(wr.register.index % 32)] = wr.value.bits;
                    }
                    assert_eq!(actual, expected, "{word:08x} VL{vl}");
                    assert_eq!(s.at.get(), s.calls.len());
                    assert_eq!(t.next_pc, Value::known(64, 0x1004));
                    assert_eq!(t.trap, None);
                    assert!(t.memory.is_empty());
                }
            }
        }
    }
}
#[test]
fn streaming_guard_precedes_missing_data() {
    for &(word, _, _, _) in FORMS {
        for sm in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                sm,
                ctrl: 0,
                w: 0,
                calls: vec![],
                at: Cell::new(0),
            };
            assert_eq!(
                evaluate(&recipe(word, 128).unwrap(), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
    }
}

// Exercise the recipe's exact source expansion on every binary16 encoding,
// including payload bits, signed zeros, subnormals and both FZ16 settings.
#[test]
fn every_half_encoding_reaches_fused_engine_without_intermediate_rounding() {
    for flush in [false, true] {
        let mut s = State {
            z: [[0; 32]; 32],
            za: vec![[0; 32]; 256],
            sm: 3,
            ctrl: if flush { 1 << 19 } else { 0 },
            w: 0,
            calls: vec![],
            at: Cell::new(0),
        };
        let word = 0xc1200c00 | (1 << 16);
        let r = recipe(word, 2048).unwrap();
        r.validate().unwrap();
        for chunk in &mut s.z[1] {
            *chunk = 0x3c003c003c003c00;
        }
        let widen = |h: u32| {
            let sign = (h & 0x8000) << 16;
            let ex = (h >> 10) & 31;
            let fraction = h & 1023;
            if ex == 31 {
                return sign | 0x7f800000 | (fraction << 13);
            }
            if ex == 0 && flush {
                return sign;
            }
            let numeric = if ex == 0 {
                f64::from(fraction) * 2f64.powi(-24)
            } else {
                (1.0 + f64::from(fraction) / 1024.0) * 2f64.powi(ex as i32 - 15)
            };
            sign | (numeric as f32).to_bits()
        };
        for base in (0..65536u32).step_by(128) {
            for c in 0..32 {
                s.z[0][c] = (0..4).fold(0, |v, i| {
                    v | (u64::from(base + c as u32 * 4 + i) << (i * 16))
                });
            }
            s.calls.clear();
            s.at.set(0);
            for pair in 0..2 {
                for e in 0..64 {
                    s.calls.push((
                        32,
                        false,
                        0,
                        u64::from(widen(base + e * 2 + pair)),
                        0x3f800000,
                    ));
                }
            }
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(s.at.get(), 128);
            assert_eq!(t.trap, None);
        }
    }
}

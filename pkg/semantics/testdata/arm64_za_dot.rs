#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
const FORMS: &[(u32, u8, u16, bool)] = &[
    (0xc1500018, 3, 2, true),
    (0xc1501008, 0, 2, false),
    (0xc1509008, 0, 4, false),
    (0xc1201000, 1, 2, false),
    (0xc1301000, 1, 4, false),
    (0xc1a01000, 2, 2, false),
    (0xc1a11000, 2, 4, false),
    (0xc1500008, 3, 2, false),
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_dot::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    w: u32,
    calls: Vec<(bool, u64, u64, u64, u64, u64)>,
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
                "a64.fpcr" => 0x07c09f03,
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
        let (bf, acc, a, b, y, z) = self.calls[i];
        let w = 32;
        assert_eq!(
            f.operation,
            if bf {
                FloatOperation::BFloatDotAdd
            } else {
                FloatOperation::ZaHalfDot
            }
        );
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(f.width, 32);
        assert_eq!(
            v,
            [
                Value::known(32, acc),
                Value::known(16, a),
                Value::known(16, b),
                Value::known(16, y),
                Value::known(16, z)
            ]
        );
        assert_eq!(ctrl, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(w, marker(i, w)))
    }
}
#[test]
fn all_za_dot_entries_lengths_indices_vertical_groups_aliases_and_backing() {
    for &(base, kind, nreg, bf) in FORMS {
        let width = 32u8;
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if kind == 0 || kind == 3 { 4 } else { 1 } {
                    let n = if kind == 1 { 31 } else { 32 - u32::from(nreg) };
                    let m = if kind == 2 {
                        32 - u32::from(nreg)
                    } else if pattern == 0 {
                        0
                    } else {
                        15
                    };
                    let off = pattern * 3;
                    let ix = if kind == 0 || kind == 3 {
                        index << 10
                    } else {
                        0
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
                    let row0 = (u64::from(s.w) + u64::from(off)) % u64::from(stride);
                    let mut expected = s.za.clone();
                    let lane = |reg: u32, e: u16| {
                        let bit = e * 16;
                        (s.z[reg as usize][usize::from(bit / 64)] >> (bit % 64)) & 0xffff
                    };
                    for member in 0..nreg {
                        let row = row0 as usize + usize::from(member * stride);
                        for chunk in 0..vl / 64 {
                            let old = s.za[row][usize::from(chunk)];
                            let mut out = 0;
                            for part in 0..2 {
                                let e = chunk * 2 + part;
                                let shift = part * 32;
                                let src = if kind == 0 || kind == 3 {
                                    2 * (e / 4 * 4 + index as u16)
                                } else {
                                    2 * e
                                };
                                let i = s.calls.len();
                                let (a, b) = if kind == 3 {
                                    (lane(n, 2 * e + member), lane(n + 1, 2 * e + member))
                                } else {
                                    let reg = (n + u32::from(member)) % 32;
                                    (lane(reg, 2 * e), lane(reg, 2 * e + 1))
                                };
                                let reg = m + if kind == 2 { u32::from(member) } else { 0 };
                                s.calls.push((
                                    bf,
                                    (old >> shift) & 0xffff_ffff,
                                    a,
                                    b,
                                    lane(reg, src),
                                    lane(reg, src + 1),
                                ));
                                out |= marker(i, width) << shift;
                            }
                            expected[row][usize::from(chunk)] = out;
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

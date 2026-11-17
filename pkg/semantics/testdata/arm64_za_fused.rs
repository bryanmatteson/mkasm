#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
const FORMS: &[(u32, u8, u16, u8, bool, bool)] = &[
    (0xc1101020, 16, 2, 0, true, false),
    (0xc1109020, 16, 4, 0, true, false),
    (0xc1601c00, 16, 2, 1, true, false),
    (0xc1701c00, 16, 4, 1, true, false),
    (0xc1e01008, 16, 2, 2, true, false),
    (0xc1e11008, 16, 4, 2, true, false),
    (0xc1101030, 16, 2, 0, true, true),
    (0xc1109030, 16, 4, 0, true, true),
    (0xc1601c08, 16, 2, 1, true, true),
    (0xc1701c08, 16, 4, 1, true, true),
    (0xc1e01018, 16, 2, 2, true, true),
    (0xc1e11018, 16, 4, 2, true, true),
    (0xc1101000, 16, 2, 0, false, false),
    (0xc1500000, 32, 2, 0, false, false),
    (0xc1d00000, 64, 2, 0, false, false),
    (0xc1109000, 16, 4, 0, false, false),
    (0xc1508000, 32, 4, 0, false, false),
    (0xc1d08000, 64, 4, 0, false, false),
    (0xc1201800, 32, 2, 1, false, false),
    (0xc1601800, 64, 2, 1, false, false),
    (0xc1201c00, 16, 2, 1, false, false),
    (0xc1301800, 32, 4, 1, false, false),
    (0xc1701800, 64, 4, 1, false, false),
    (0xc1301c00, 16, 4, 1, false, false),
    (0xc1a01800, 32, 2, 2, false, false),
    (0xc1e01800, 64, 2, 2, false, false),
    (0xc1a01008, 16, 2, 2, false, false),
    (0xc1a11800, 32, 4, 2, false, false),
    (0xc1e11800, 64, 4, 2, false, false),
    (0xc1a11008, 16, 4, 2, false, false),
    (0xc1101010, 16, 2, 0, false, true),
    (0xc1500010, 32, 2, 0, false, true),
    (0xc1d00010, 64, 2, 0, false, true),
    (0xc1109010, 16, 4, 0, false, true),
    (0xc1508010, 32, 4, 0, false, true),
    (0xc1d08010, 64, 4, 0, false, true),
    (0xc1201808, 32, 2, 1, false, true),
    (0xc1601808, 64, 2, 1, false, true),
    (0xc1201c08, 16, 2, 1, false, true),
    (0xc1301808, 32, 4, 1, false, true),
    (0xc1701808, 64, 4, 1, false, true),
    (0xc1301c08, 16, 4, 1, false, true),
    (0xc1a01808, 32, 2, 2, false, true),
    (0xc1e01808, 64, 2, 2, false, true),
    (0xc1a01018, 16, 2, 2, false, true),
    (0xc1a11808, 32, 4, 2, false, true),
    (0xc1e11808, 64, 4, 2, false, true),
    (0xc1a11018, 16, 4, 2, false, true),
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_fused::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    w: u32,
    calls: Vec<(u8, bool, u64, u64, u64)>,
    at: Cell<usize>,
}
fn mask(w: u8) -> u64 {
    if w == 64 { u64::MAX } else { (1 << w) - 1 }
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
        let (w, bf, acc, a, b) = self.calls[i];
        assert_eq!(f.operation, FloatOperation::ZaFused { bfloat: bf });
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(f.width, w);
        assert_eq!(
            v,
            [Value::known(w, acc), Value::known(w, a), Value::known(w, b)]
        );
        assert_eq!(ctrl, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(w, marker(i, w)))
    }
}
#[test]
fn all_fused_entries_lengths_source_groups_indices_row_wrap_and_backing() {
    for &(base, width, nreg, kind, bf, sub) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if kind == 0 { 128 / u32::from(width) } else { 1 } {
                    let n = if kind == 1 { 31 } else { 32 - u32::from(nreg) };
                    let m = if kind == 2 {
                        32 - u32::from(nreg)
                    } else if pattern == 0 {
                        0
                    } else {
                        15
                    };
                    let off = pattern * 3;
                    let ix = if kind != 0 {
                        0
                    } else if width == 16 {
                        ((index >> 1) << 10) | ((index & 1) << 3)
                    } else {
                        index << 10
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
                    let lane = |r: u32, e: u16| {
                        let bit = e * u16::from(width);
                        (s.z[r as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(width)
                    };
                    for member in 0..nreg {
                        let row = row0 as usize + usize::from(member * stride);
                        for chunk in 0..vl / 64 {
                            let old = s.za[row][usize::from(chunk)];
                            let mut out = 0;
                            for part in 0..64 / u16::from(width) {
                                let shift = part * u16::from(width);
                                let e = chunk * (64 / u16::from(width)) + part;
                                let i = s.calls.len();
                                let a = lane((n + u32::from(member)) % 32, e)
                                    ^ if sub { 1u64 << (width - 1) } else { 0 };
                                let src = if kind == 0 {
                                    e / (128 / u16::from(width)) * (128 / u16::from(width))
                                        + index as u16
                                } else {
                                    e
                                };
                                let b =
                                    lane(m + if kind == 2 { u32::from(member) } else { 0 }, src);
                                s.calls
                                    .push((width, bf, (old >> shift) & mask(width), a, b));
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
    for &(word, _, _, _, _, _) in FORMS {
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

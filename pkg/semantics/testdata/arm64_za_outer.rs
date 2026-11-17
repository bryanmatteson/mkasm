#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
const FORMS: &[(u32, u8, bool, bool, bool)] = &[
    (0x81a00000, 32, false, true, false),
    (0x81a00010, 32, false, true, true),
    (0x81800000, 32, true, true, false),
    (0x81a00008, 16, true, false, false),
    (0x81800010, 32, true, true, true),
    (0x81a00018, 16, true, false, true),
    (0x81800008, 16, false, false, false),
    (0x80800000, 32, false, false, false),
    (0x80c00000, 64, false, false, false),
    (0x81800018, 16, false, false, true),
    (0x80800010, 32, false, false, true),
    (0x80c00010, 64, false, false, true),
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_outer::a64(word, 0x1000, vl)
}
fn mask(w: u8) -> u64 {
    if w == 64 { u64::MAX } else { (1 << w) - 1 }
}
fn marker(i: usize, w: u8) -> u64 {
    0xe71ab35d6219acf0u64.wrapping_mul(i as u64 + 1) & mask(w)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    p: [[u64; 4]; 16],
    sm: u64,
    calls: Vec<(u8, bool, bool, Vec<Value>)>,
    at: Cell<usize>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.svcr" => self.sm,
                "a64.fpcr" => 0x07c09f03,
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.za64" => self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.predicate64" => self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
                _ => panic!("unexpected {r:?}"),
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
        let (w, bf, dot, expected) = &self.calls[i];
        assert_eq!(
            f.operation,
            if *dot {
                if *bf {
                    FloatOperation::BFloatDotAdd
                } else {
                    FloatOperation::ZaHalfDot
                }
            } else {
                FloatOperation::ZaFused { bfloat: *bf }
            }
        );
        assert_eq!(f.width, *w);
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(v, expected);
        assert_eq!(ctrl, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(*w, marker(i, *w)))
    }
}
#[test]
fn all_outer_products_predicates_tiles_lengths_and_backing() {
    for &(base, width, bf, dot, sub) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3 {
                for tile in [0, width / 8 - 1] {
                    let n = 31u32;
                    let m = if pattern == 2 { 31 } else { 0 };
                    let pn = 7;
                    let pm = if pattern == 1 { 7 } else { 6 };
                    let word =
                        base | (n << 5) | (m << 16) | (pn << 10) | (pm << 13) | u32::from(tile);
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
                        p: std::array::from_fn(|r| {
                            std::array::from_fn(|c| {
                                if pattern == 0 {
                                    0
                                } else if pattern == 1 {
                                    u64::MAX
                                } else {
                                    0x91a7fc53825d6eb0u64.rotate_left((r * 7 + c) as u32)
                                }
                            })
                        }),
                        sm: 3,
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    let mut expected = s.za.clone();
                    let lane = |n: u32, e: u16, w: u8| {
                        let bit = e * u16::from(w);
                        (s.z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
                    };
                    let pred = |n: u32, e: u16, w: u8| {
                        let bit = e * u16::from(w) / 8;
                        s.p[n as usize][usize::from(bit / 64)] & (1 << (bit % 64)) != 0
                    };
                    for row in 0..vl / u16::from(width) {
                        let physical = row * u16::from(width) / 8 + u16::from(tile);
                        for chunk in 0..vl / 64 {
                            let old = s.za[usize::from(physical)][usize::from(chunk)];
                            let mut out = 0;
                            for part in 0..64 / u16::from(width) {
                                let col = chunk * (64 / u16::from(width)) + part;
                                let shift = part * u16::from(width);
                                let acc = (old >> shift) & mask(width);
                                let mut inputs = vec![Value::known(width, acc)];
                                let mut active = false;
                                if dot {
                                    let mut a = vec![];
                                    let mut b = vec![];
                                    for i in 0..2 {
                                        let pa = pred(pn, row * 2 + i, 16);
                                        let pb = pred(pm, col * 2 + i, 16);
                                        active |= pa && pb;
                                        a.push(Value::known(
                                            16,
                                            if pa {
                                                lane(n, row * 2 + i, 16)
                                                    ^ if sub { 0x8000 } else { 0 }
                                            } else {
                                                0
                                            },
                                        ));
                                        b.push(Value::known(
                                            16,
                                            if pb { lane(m, col * 2 + i, 16) } else { 0 },
                                        ));
                                    }
                                    inputs.extend(a);
                                    inputs.extend(b);
                                } else {
                                    active = pred(pn, row, width) && pred(pm, col, width);
                                    inputs.push(Value::known(
                                        width,
                                        lane(n, row, width)
                                            ^ if sub { 1u64 << (width - 1) } else { 0 },
                                    ));
                                    inputs.push(Value::known(width, lane(m, col, width)));
                                }
                                let value = if active {
                                    let i = s.calls.len();
                                    s.calls.push((width, bf, dot, inputs));
                                    marker(i, width)
                                } else {
                                    acc
                                };
                                out |= value << shift;
                            }
                            expected[usize::from(physical)][usize::from(chunk)] = out;
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
                    assert_eq!(t.trap, None);
                    assert_eq!(t.next_pc, Value::known(64, 0x1004));
                    assert!(t.memory.is_empty());
                }
            }
        }
    }
}
#[test]
fn unavailable_streaming_context_rejects_before_data() {
    for &(word, _, _, _, _) in FORMS {
        for sm in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                p: [[0; 4]; 16],
                sm,
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

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [u64; 4],
    control: u64,
    status: u64,
    missing: Vec<Register>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|c| 0xfedcba9876543210u64.wrapping_mul((n * 32 + c + 1) as u64))
            }),
            p: [0; 4],
            control: 0,
            status: 0x8000002,
            missing: vec![],
            reads: RefCell::new(vec![]),
        }
    }
    fn get(&self, n: u32, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        (self.z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
    }
    fn put(&mut self, n: u32, e: u16, w: u8, v: u64) {
        let bit = e * u16::from(w);
        let x = &mut self.z[n as usize][usize::from(bit / 64)];
        *x = (*x & !(mask(w) << (bit % 64))) | ((v & mask(w)) << (bit % 64));
    }
    fn active(&self, e: u16, w: u8) -> bool {
        let b = e * u16::from(w / 8);
        self.p[usize::from(b / 64)] & (1 << (b % 64)) != 0
    }
    fn pred(&mut self, vl: u16, w: u8, kind: u16) {
        for e in 0..vl / u16::from(w) {
            if kind == 1
                || (kind == 2 && e % 3 == 1)
                || (kind == 3 && (e == 0 || e + 1 == vl / u16::from(w)))
            {
                let b = e * u16::from(w / 8);
                self.p[usize::from(b / 64)] |= 1 << (b % 64);
            }
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        if self.missing.contains(&r) {
            return Value::unknown(if r.bank == "a64.vector64" { 64 } else { 32 });
        }
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.predicate64" => {
                assert_eq!(r.index / 4, 0);
                Value::known(64, self.p[usize::from(r.index % 4)])
            }
            "a64.fpcr" => Value::known(32, self.control),
            "a64.fpsr" => Value::known(32, self.status),
            _ => panic!("unexpected input {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory")
    }
}
fn recipe(word: u32, vl: u16) -> Recipe {
    semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl).unwrap()
}
fn word(w: u8, intsize: u8, env: bool, merge: bool, d: u32, n: u32) -> u32 {
    (if merge {
        0x6510a000
            | (u32::from(w == 64) << 17)
            | (u32::from(intsize == 64) << 18)
            | (u32::from(env) << 16)
    } else {
        0x641c8000
            | (u32::from(w == 64) << 14)
            | (u32::from(intsize == 64) << 16)
            | (u32::from(env) << 13)
    }) | (n << 5)
        | d
}
fn apply(s: &State, t: &Transition) -> State {
    let mut out = s.clone();
    for wr in &t.registers {
        assert!(wr.value.is_known(), "{wr:?}");
        match wr.register.bank {
            "a64.vector64" => {
                out.z[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                    wr.value.bits
            }
            "a64.fpsr" => out.status = wr.value.bits,
            _ => panic!("write {wr:?}"),
        }
    }
    out
}
fn roundref(raw: u64, w: u8, intsize: u8, mode: u32, control: u32) -> (u64, u32) {
    let f = if w == 32 { 23u32 } else { 52 };
    let bias = if w == 32 { 127i32 } else { 1023 };
    let sign = raw >> (w - 1) != 0;
    let exponent = ((raw >> f) & if w == 32 { 255 } else { 2047 }) as i32;
    let fraction = raw & mask(f as u8);
    let indefinite = (1 << (w - 1)) | ((bias as u64 + u64::from(intsize) - 1) << f);
    if exponent == if w == 32 { 255 } else { 2047 } {
        return (indefinite, 1);
    }
    let subnormal = exponent == 0 && fraction != 0;
    let fz = control & (1 << 24) != 0 && control & 2 == 0;
    if subnormal && (fz || control & 1 != 0) {
        return (u64::from(sign) << (w - 1), if fz { 128 } else { 0 });
    }
    let significand = u128::from(fraction) | if exponent == 0 { 0 } else { 1u128 << f };
    let power = if exponent == 0 {
        1 - bias - f as i32
    } else {
        exponent - bias - f as i32
    };
    let (mut magnitude, remainder, denominator) = if power >= 0 {
        if power >= 76 {
            return (indefinite, 1);
        }
        (significand << power, 0, 1)
    } else {
        let shift = (-power) as u32;
        if shift >= 128 {
            (0, significand, u128::MAX)
        } else {
            (
                significand >> shift,
                significand & ((1u128 << shift) - 1),
                1u128 << shift,
            )
        }
    };
    let fractional = remainder != 0;
    let up = match mode {
        0 => {
            remainder > denominator / 2
                || (remainder == denominator / 2 && denominator != 1 && magnitude & 1 != 0)
        }
        1 => !sign && fractional,
        2 => sign && fractional,
        _ => false,
    };
    magnitude += u128::from(up);
    let limit = 1u128 << (intsize - 1);
    if magnitude > if sign { limit } else { limit - 1 } {
        return (indefinite, 1);
    }
    let bits = if magnitude == 0 {
        0
    } else {
        let highest = 127 - magnitude.leading_zeros();
        let fraction = magnitude - (1u128 << highest);
        let encoded = if highest <= f {
            fraction << (f - highest)
        } else {
            fraction >> (highest - f)
        };
        (((highest as i32 + bias) as u64) << f) | (encoded as u64)
    };
    (
        bits | (u64::from(sign) << (w - 1)),
        if fractional { 16 } else { 0 },
    )
}

#[test]
fn all_forms_lengths_predicates_aliases_rounding_and_exception_boundaries() {
    let mut cases = 0;
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32u8, 64] {
            let f = if w == 32 { 23 } else { 52 };
            let bias = if w == 32 { 127 } else { 1023 };
            let sign = 1u64 << (w - 1);
            let exp = mask(w - 1) & !mask(f);
            for intsize in [32u8, 64] {
                let bound = (bias + u64::from(intsize) - 1) << f;
                let inputs = [
                    0,
                    sign,
                    1,
                    sign | 1,
                    mask(f),
                    1 << f,
                    (bias << f) | 1,
                    ((bias - 1) << f),
                    ((bias - 1) << f) | 1,
                    ((bias + 1) << f) | (1 << (f - 1)),
                    bound - 1,
                    bound,
                    bound + 1,
                    sign | bound,
                    sign | (bound + 1),
                    exp,
                    sign | exp,
                    exp | 1,
                    exp | (1 << (f - 1)),
                ];
                for merge in [false, true] {
                    for env in [false, true] {
                        for mode in 0..4 {
                            for kind in 0..4 {
                                for d in [0, 1] {
                                    for start in 0..inputs.len() {
                                        let mut s = State::new();
                                        s.control = (mode << 22)
                                            | if start % 3 == 0 {
                                                1 << 24
                                            } else if start % 3 == 1 {
                                                2
                                            } else {
                                                1
                                            };
                                        s.pred(vl, w, kind);
                                        for e in 0..vl / u16::from(w) {
                                            s.put(
                                                1,
                                                e,
                                                w,
                                                inputs[(start + usize::from(e)) % inputs.len()],
                                            );
                                        }
                                        let mut expected = s.clone();
                                        let mut flags = s.status;
                                        for e in 0..vl / u16::from(w) {
                                            let value = if s.active(e, w) {
                                                let (v, raised) = roundref(
                                                    s.get(1, e, w),
                                                    w,
                                                    intsize,
                                                    if env { mode as u32 } else { 3 },
                                                    s.control as u32,
                                                );
                                                flags |= u64::from(raised);
                                                v
                                            } else if merge {
                                                s.get(d, e, w)
                                            } else {
                                                0
                                            };
                                            expected.put(d, e, w, value);
                                        }
                                        let r = recipe(word(w, intsize, env, merge, d, 1), vl);
                                        assert_eq!(r.support, Support::Full);
                                        r.validate().unwrap();
                                        let t = evaluate(&r, &s).unwrap();
                                        assert_eq!(t.trap, None);
                                        let out = apply(&s, &t);
                                        assert_eq!(out.z,expected.z,"VL{vl} w{w} int{intsize} env{env} mode{mode} merge{merge} start{start}");
                                        assert_eq!(out.status, flags);
                                        assert_eq!(t.next_pc, Value::known(64, 0x1004));
                                        cases += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("{cases} numerical checks");
}
#[test]
fn empty_zeroing_never_reads_fp_context_or_vectors() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32, 64] {
            for intsize in [32, 64] {
                for env in [false, true] {
                    let mut s = State::new();
                    s.missing.push(Register {
                        bank: "a64.fpcr",
                        index: 0,
                    });
                    s.missing.push(Register {
                        bank: "a64.fpsr",
                        index: 0,
                    });
                    for n in [0, 1] {
                        for i in 0..32 {
                            s.missing.push(Register {
                                bank: "a64.vector64",
                                index: n * 32 + i,
                            });
                        }
                    }
                    let t = evaluate(&recipe(word(w, intsize, env, false, 0, 1), vl), &s).unwrap();
                    assert_eq!(t.trap, None);
                    assert!(!s
                        .reads
                        .borrow()
                        .iter()
                        .any(|r| r.bank == "a64.fpcr" || r.bank == "a64.vector64"));
                    assert!(t
                        .registers
                        .iter()
                        .filter(|x| x.register.bank == "a64.vector64")
                        .all(|x| x.value == Value::known(64, 0)));
                }
            }
        }
    }
}
#[test]
fn first_enabled_exception_suppresses_later_inputs_and_all_destinations() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32, 64] {
            for merge in [false, true] {
                for intsize in [32, 64] {
                    for env in [false, true] {
                        let mut s = State::new();
                        s.control = 1 << 8;
                        s.pred(vl, w, 1);
                        s.put(
                            1,
                            0,
                            w,
                            if w == 32 {
                                0x7f800001
                            } else {
                                0x7ff0000000000001
                            },
                        );
                        for i in 1..32 {
                            s.missing.push(Register {
                                bank: "a64.vector64",
                                index: 32 + i,
                            });
                        }
                        let t =
                            evaluate(&recipe(word(w, intsize, env, merge, 0, 1), vl), &s).unwrap();
                        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
                        assert!(t
                            .registers
                            .iter()
                            .all(|x| x.register.bank != "a64.vector64"));
                        let out = apply(&s, &t);
                        assert_eq!(out.z, s.z);
                        assert_eq!(out.status, s.status | 1);
                        assert!(!s
                            .reads
                            .borrow()
                            .iter()
                            .any(|r| r.bank == "a64.vector64" && r.index > 32));
                    }
                }
            }
        }
    }
}

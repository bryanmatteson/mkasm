#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_float_classic::a64(word, 0x1000, vl)
}
#[derive(Clone, Debug)]
struct Call {
    op: FloatOperation,
    width: u8,
    inputs: Vec<Value>,
}
struct State {
    z: [[u64; 32]; 32],
    fpcr: u64,
    calls: Vec<Call>,
    results: Vec<u64>,
    at: RefCell<usize>,
    trap: Option<usize>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|k| {
                    [
                        0x7c017e0100008000,
                        0x3f8000007fc00001,
                        0xfff0000000000000,
                        0x0123456789abcdef,
                    ][(n + k) % 4]
                })
            }),
            fpcr: 0,
            calls: vec![],
            results: vec![],
            at: RefCell::new(0),
            trap: None,
            reads: RefCell::new(vec![]),
        }
    }
    fn bits(&self, n: u32, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        (self.z[n as usize][usize::from(bit / 64)] >> (bit % 64))
            & if w == 64 { u64::MAX } else { (1u64 << w) - 1 }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.fpcr" => Value::known(32, self.fpcr),
            "a64.fpsr" => Value::known(32, 0x8000010),
            _ => panic!("unexpected read {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory read")
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        inputs: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = *self.at.borrow();
        let expected = &self.calls[i];
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.operation, expected.op);
        assert_eq!(f.width, expected.width);
        assert_eq!(inputs, expected.inputs);
        assert_eq!(control, Value::known(32, self.fpcr));
        assert_eq!(status, Value::known(32, 0x8000010));
        Ok(match f.projection {
            FloatProjection::Value => Value::known(
                f.width,
                self.results
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| tag(i, f.width)),
            ),
            FloatProjection::Status => {
                Value::known(32, 0x8000010 | u64::from(self.trap == Some(i)))
            }
            FloatProjection::Trapped => {
                *self.at.borrow_mut() += 1;
                Value::known(1, u64::from(self.trap == Some(i)))
            }
        })
    }
}
fn tag(i: usize, w: u8) -> u64 {
    (match w {
        16 => 0x3c00,
        32 => 0x3f800000,
        _ => 0x3ff0000000000000,
    }) | i as u64
}
fn neg(v: u64, w: u8, ah: bool) -> u64 {
    let (e, f) = match w {
        16 => (0x7c00, 0x3ff),
        32 => (0x7f800000, 0x7fffff),
        _ => (0x7ff0000000000000, 0xfffffffffffff),
    };
    if ah && v & e == e && v & f != 0 {
        v
    } else {
        v ^ (1u64 << (w - 1))
    }
}
fn verify(word: u32, vl: u16, s: &State, d: u32, w: u8) {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.events.is_empty());
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    let mut z = s.z;
    let mut status = None;
    for write in &t.registers {
        assert!(write.value.is_known());
        match write.register.bank {
            "a64.vector64" => {
                z[usize::from(write.register.index / 32)][usize::from(write.register.index % 32)] =
                    write.value.bits
            }
            "a64.fpsr" => status = Some(write.value),
            _ => panic!("unexpected output"),
        }
    }
    if let Some(at) = s.trap {
        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
        assert_eq!(z, s.z);
        assert_eq!(*s.at.borrow(), at + 1);
        assert_eq!(status, Some(Value::known(32, 0x8000011)));
    } else {
        assert_eq!(t.trap, None);
        assert_eq!(*s.at.borrow(), s.calls.len());
        assert_eq!(status, Some(Value::known(32, 0x8000010)));
        let mut expected = s.z;
        for k in 0..vl / 64 {
            expected[d as usize][usize::from(k)] = 0;
        }
        for i in 0..s.calls.len() {
            let bit = i * usize::from(w);
            expected[d as usize][bit / 64] |= tag(i, w) << (bit % 64);
        }
        assert_eq!(z, expected, "{word:08x} VL{vl}");
    }
}
#[test]
fn widening_half_all_forms_parts_indices_aliases_and_lengths() {
    for vl in [128, 256, 512, 1024, 2048] {
        for q in [false, true] {
            for upper in [false, true] {
                for sub in [false, true] {
                    for indexed in [false, true] {
                        for index in 0..if indexed { 8 } else { 1 } {
                            for d in [0u32, 1, 2] {
                                for ah in [false, true] {
                                    let mut s = State::new();
                                    s.fpcr = u64::from(ah) << 1;
                                    let elements = if q { 4 } else { 2 };
                                    let offset = if upper { elements } else { 0 };
                                    for e in 0..elements {
                                        let a = s.bits(1, offset + e, 16);
                                        s.calls.push(Call {
                                            op: FloatOperation::WideningFusedMultiplyAdd {
                                                source_width: 16,
                                            },
                                            width: 32,
                                            inputs: vec![
                                                Value::known(32, s.bits(d, e, 32)),
                                                Value::known(
                                                    16,
                                                    if sub { neg(a, 16, ah) } else { a },
                                                ),
                                                Value::known(
                                                    16,
                                                    s.bits(
                                                        2,
                                                        if indexed { index } else { offset + e },
                                                        16,
                                                    ),
                                                ),
                                            ],
                                        });
                                    }
                                    let base = if indexed {
                                        if upper {
                                            0x2f808000
                                        } else {
                                            0x0f800000
                                        }
                                    } else if upper {
                                        0x2e20cc00
                                    } else {
                                        0x0e20ec00
                                    };
                                    let selected = if indexed {
                                        (u32::from(index & 4) << 9)
                                            | (u32::from(index & 2) << 20)
                                            | (u32::from(index & 1) << 20)
                                    } else {
                                        0
                                    };
                                    let word = base
                                        | (u32::from(q) << 30)
                                        | (u32::from(sub) << if indexed { 14 } else { 23 })
                                        | selected
                                        | (2 << 16)
                                        | (1 << 5)
                                        | d;
                                    verify(word, vl, &s, d, 32);
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
fn complex_all_rotations_widths_indices_aliases_lengths_and_nan_signs() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16u8, 32, 64] {
            for q in [false, true] {
                if w == 64 && !q {
                    continue;
                }
                for indexed in [false, true] {
                    if indexed && (w == 64 || w == 32 && !q) {
                        continue;
                    }
                    for add in [false, true] {
                        if indexed && add {
                            continue;
                        }
                        for rotation in 0..4u32 {
                            if add && rotation & 1 == 0 {
                                continue;
                            }
                            let elements = (if q { 128 } else { 64 }) / u16::from(w);
                            for index in 0..if indexed { elements / 2 } else { 1 } {
                                for d in [0u32, 1, 2] {
                                    for ah in [false, true] {
                                        let mut s = State::new();
                                        s.fpcr = u64::from(ah) << 1;
                                        for e in 0..elements / 2 {
                                            let k = if indexed { index } else { e };
                                            let a = s.bits(2, k * 2, w);
                                            let b = s.bits(2, k * 2 + 1, w);
                                            let pair = match rotation {
                                                0 => [a, b],
                                                1 => [neg(b, w, ah), a],
                                                2 => [neg(a, w, ah), neg(b, w, ah)],
                                                _ => [b, neg(a, w, ah)],
                                            };
                                            for component in 0..2u16 {
                                                s.calls.push(Call {
                                                    op: if add {
                                                        FloatOperation::Add
                                                    } else {
                                                        FloatOperation::FusedMultiplyAdd {
                                                            negate_product: false,
                                                            negate_addend: false,
                                                        }
                                                    },
                                                    width: w,
                                                    inputs: if add {
                                                        vec![
                                                            Value::known(
                                                                w,
                                                                s.bits(1, e * 2 + component, w),
                                                            ),
                                                            Value::known(
                                                                w,
                                                                pair[usize::from(component)],
                                                            ),
                                                        ]
                                                    } else {
                                                        vec![
                                                            Value::known(
                                                                w,
                                                                s.bits(d, e * 2 + component, w),
                                                            ),
                                                            Value::known(
                                                                w,
                                                                s.bits(
                                                                    1,
                                                                    e * 2 + (rotation & 1) as u16,
                                                                    w,
                                                                ),
                                                            ),
                                                            Value::known(
                                                                w,
                                                                pair[usize::from(component)],
                                                            ),
                                                        ]
                                                    },
                                                });
                                            }
                                        }
                                        let size = u32::from(w.trailing_zeros() - 3);
                                        let word = if indexed {
                                            0x2f001000
                                                | (rotation << 13)
                                                | (u32::from(if w == 16 { index & 1 } else { 0 })
                                                    << 21)
                                                | (u32::from(if w == 16 {
                                                    index >> 1
                                                } else {
                                                    index
                                                }) << 11)
                                        } else if add {
                                            0x2e00e400 | ((rotation >> 1) << 12)
                                        } else {
                                            0x2e00c400 | (rotation << 11)
                                        };
                                        verify(
                                            word | (size << 22)
                                                | (u32::from(q) << 30)
                                                | (2 << 16)
                                                | (1 << 5)
                                                | d,
                                            vl,
                                            &s,
                                            d,
                                            w,
                                        );
                                    }
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
fn first_enabled_exception_suppresses_later_sources_and_destination_writes() {
    let mut s = State::new();
    s.fpcr = 1 << 8;
    s.trap = Some(0);
    s.calls.push(Call {
        op: FloatOperation::WideningFusedMultiplyAdd { source_width: 16 },
        width: 32,
        inputs: vec![
            Value::known(32, s.bits(0, 0, 32)),
            Value::known(16, s.bits(1, 0, 16)),
            Value::known(16, s.bits(2, 0, 16)),
        ],
    });
    verify(0x4e22ec20, 2048, &s, 0, 32);
    assert!(s
        .reads
        .borrow()
        .iter()
        .filter(|r| r.bank == "a64.vector64")
        .all(|r| r.index % 32 == 0));
}
#[test]
fn every_fp_immediate_has_no_control_source_or_status_dependencies() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16u8, 32, 64] {
            for q in [false, true] {
                if w == 64 && !q {
                    continue;
                }
                for literal in 0..256u32 {
                    let word = (if w == 16 {
                        0x0f00fc00
                    } else if w == 32 {
                        0x0f00f400
                    } else {
                        0x2f00f400
                    }) | (u32::from(q) << 30)
                        | ((literal >> 5) << 16)
                        | ((literal & 31) << 5);
                    let s = State::new();
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    let t = evaluate(&r, &s).unwrap();
                    assert!(s.reads.borrow().is_empty());
                    assert!(t.trap.is_none());
                    assert_eq!(t.registers.len(), usize::from(vl / 64));
                    let (fraction, exponent) = match w {
                        16 => (10, 5),
                        32 => (23, 8),
                        _ => (52, 11),
                    };
                    let sign = u64::from(literal >> 7) << (w - 1);
                    let f = u64::from(literal & 15) << (fraction - 4);
                    let exp = (if literal & 64 != 0 {
                        (1u64 << (exponent - 1)) - 4
                    } else {
                        1u64 << (exponent - 1)
                    }) | u64::from((literal >> 4) & 3);
                    let value = sign | (exp << fraction) | f;
                    let mut chunk = 0;
                    for e in 0..64 / w {
                        chunk |= value << (e * w);
                    }
                    for (i, write) in t.registers.iter().enumerate() {
                        assert_eq!(write.register.bank, "a64.vector64");
                        assert_eq!(
                            write.value,
                            Value::known(64, if i < if q { 2 } else { 1 } { chunk } else { 0 })
                        );
                    }
                }
            }
        }
    }
}

fn absolute(v: u64, w: u8, ah: bool) -> u64 {
    let f = match w {
        16 => 10,
        32 => 23,
        _ => 52,
    };
    let exponent = ((1u64 << (w - f - 1)) - 1) << f;
    if ah && v & exponent == exponent && v & ((1u64 << f) - 1) != 0 {
        v
    } else {
        v & !(1u64 << (w - 1))
    }
}
fn check_simple(
    word: u32,
    vl: u16,
    s: &State,
    d: u32,
    w: u8,
    values: &[u64],
    merge: Option<u32>,
    status: bool,
) {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    let mut actual = s.z;
    let mut fpsr = None;
    for wr in &t.registers {
        match wr.register.bank {
            "a64.vector64" => {
                assert!(wr.value.is_known());
                actual[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                    wr.value.bits;
            }
            "a64.fpsr" => fpsr = Some(wr.value),
            _ => panic!("unexpected output"),
        }
    }
    assert_eq!(
        fpsr,
        if status {
            Some(Value::known(32, 0x8000010 | u64::from(s.trap.is_some())))
        } else {
            None
        }
    );
    if let Some(at) = s.trap {
        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
        assert_eq!(actual, s.z);
        assert_eq!(*s.at.borrow(), at + 1);
    } else {
        assert_eq!(t.trap, None);
        assert_eq!(*s.at.borrow(), s.calls.len());
        let mut expected = s.z;
        for chunk in 0..vl / 64 {
            expected[d as usize][usize::from(chunk)] = 0;
        }
        if let Some(n) = merge {
            if s.fpcr & 4 != 0 {
                expected[d as usize][0] =
                    s.z[n as usize][0] & !if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                expected[d as usize][1] = s.z[n as usize][1];
            }
        }
        for (i, value) in values.iter().enumerate() {
            let bit = i * usize::from(w);
            expected[d as usize][bit / 64] |= value << (bit % 64);
        }
        assert_eq!(actual, expected, "{word:08x} VL{vl} FPCR{:x}", s.fpcr);
    }
    if !status {
        assert!(s.reads.borrow().iter().all(|r| r.bank != "a64.fpsr"));
        assert_eq!(*s.at.borrow(), 0);
    }
}
#[test]
fn half_vector_sign_transforms_cover_every_input_bit_pattern_and_ah_policy() {
    for q in [false, true] {
        for ah in [false, true] {
            for negate in [false, true] {
                let elements = if q { 8 } else { 4 };
                let base = if negate { 0x2ef8f800 } else { 0x0ef8f800 };
                let word = base | (u32::from(q) << 30) | (1 << 5) | 1;
                for start in (0..65536u32).step_by(elements) {
                    let mut s = State::new();
                    s.fpcr = (u64::from(ah) << 1) | 4;
                    let mut expected = vec![];
                    s.z[1][0] = 0;
                    s.z[1][1] = 0;
                    for e in 0..elements {
                        let v = u64::from(start) + e as u64;
                        s.z[1][e / 4] |= v << ((e % 4) * 16);
                        expected.push(if negate {
                            neg(v, 16, ah)
                        } else {
                            absolute(v, 16, ah)
                        });
                    }
                    check_simple(word, 128, &s, 1, 16, &expected, None, false);
                }
            }
        }
    }
}
#[test]
fn scalar_and_vector_sign_transforms_preserve_aliases_merge_sources_and_all_backing() {
    for vl in [128u16, 256, 512, 1024, 2048] {
        for w in [16u8, 32, 64] {
            for scalar in [false, true] {
                for q in [false, true] {
                    if scalar && !q || !scalar && w == 64 && !q {
                        continue;
                    }
                    for d in [0u32, 1, 31] {
                        for ah in [false, true] {
                            for nep in [false, true] {
                                for negate in [false, true] {
                                    let mut s = State::new();
                                    s.fpcr = (u64::from(ah) << 1) | (u64::from(nep) << 2);
                                    let base = if scalar {
                                        (if negate { 0x1e214000 } else { 0x1e20c000 })
                                            | ((match w {
                                                16 => 3,
                                                32 => 0,
                                                _ => 1,
                                            }) << 22)
                                    } else {
                                        (if w == 16 {
                                            0x0ef8f800
                                        } else {
                                            0x0ea0f800 | ((u32::from(w == 64)) << 22)
                                        }) | (u32::from(negate) << 29)
                                            | (u32::from(q) << 30)
                                    };
                                    let word = base | (1 << 5) | d;
                                    let elements = if scalar {
                                        1
                                    } else {
                                        (if q { 128 } else { 64 }) / u16::from(w)
                                    };
                                    let values = (0..elements)
                                        .map(|e| {
                                            let v = s.bits(1, e, w);
                                            if negate {
                                                neg(v, w, ah)
                                            } else {
                                                absolute(v, w, ah)
                                            }
                                        })
                                        .collect::<Vec<_>>();
                                    check_simple(
                                        word,
                                        vl,
                                        &s,
                                        d,
                                        w,
                                        &values,
                                        if scalar { Some(d) } else { None },
                                        false,
                                    );
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
fn absolute_difference_rounds_subtraction_before_absolute_and_uses_source_merging() {
    for vl in [128u16, 256, 512, 1024, 2048] {
        for w in [16u8, 32, 64] {
            for scalar in [false, true] {
                for q in [false, true] {
                    if scalar && !q || !scalar && w == 64 && !q {
                        continue;
                    }
                    let base = if w == 16 {
                        0x2ec01400
                    } else {
                        0x2ea0d400 | (u32::from(w == 64) << 22)
                    };
                    for d in [0u32, 1, 2, 31] {
                        for ah in [false, true] {
                            for nep in [false, true] {
                                for trap in [false, true] {
                                    let mut s = State::new();
                                    s.fpcr = (u64::from(ah) << 1)
                                        | (u64::from(nep) << 2)
                                        | (u64::from(trap) << 8);
                                    let word = base
                                        | (u32::from(scalar) << 28)
                                        | (u32::from(q) << 30)
                                        | (2 << 16)
                                        | (1 << 5)
                                        | d;
                                    let elements = if scalar {
                                        1
                                    } else {
                                        (if q { 128 } else { 64 }) / u16::from(w)
                                    };
                                    let f = match w {
                                        16 => 10,
                                        32 => 23,
                                        _ => 52,
                                    };
                                    let sign = 1u64 << (w - 1);
                                    let inf = ((1u64 << (w - f - 1)) - 1) << f;
                                    for e in 0..elements {
                                        s.calls.push(Call {
                                            op: FloatOperation::Subtract,
                                            width: w,
                                            inputs: vec![
                                                Value::known(w, s.bits(1, e, w)),
                                                Value::known(w, s.bits(2, e, w)),
                                            ],
                                        });
                                        s.results.push(
                                            [
                                                sign,
                                                sign | inf | 1,
                                                sign | inf | (1 << (f - 1)),
                                                sign | 1,
                                            ][usize::from(e) % 4],
                                        );
                                    }
                                    if trap {
                                        s.trap = Some(if elements > 1 { 1 } else { 0 });
                                    }
                                    let expected = s
                                        .results
                                        .iter()
                                        .map(|&v| absolute(v, w, ah))
                                        .collect::<Vec<_>>();
                                    check_simple(
                                        word,
                                        vl,
                                        &s,
                                        d,
                                        w,
                                        &expected,
                                        if scalar { Some(1) } else { None },
                                        true,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

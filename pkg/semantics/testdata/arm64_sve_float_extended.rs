// The shared bounded reference exercises existing FP contracts too. New
// references below accept only exact finite test values or explicit invalid
// operations; they are not substitutes for the production software FP engine.
include!("sve_float_base.rs");
#[derive(Default)]
struct ExtendedState(State);
impl Machine for ExtendedState {
    fn read_register(&self, r: Register) -> Value {
        self.0.read_register(r)
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        self.0.read_memory(a, w, e)
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        use FloatOperation as F;
        let bf = |value: u64| f32::from_bits((value as u32) << 16) as f64;
        let exact_bf = |value: f64| {
            let bits = (value as f32).to_bits();
            assert_eq!(
                bits & 0xffff,
                0,
                "bounded BF16 reference requires exact result"
            );
            u64::from(bits >> 16)
        };
        let record = || {
            if f.projection == FloatProjection::Value {
                self.0.trace.borrow_mut().push((
                    f.operation,
                    v.iter().map(|v| v.bits).collect(),
                    status.bits,
                ));
            }
        };
        let bits = match f.operation {
            F::Convert {
                source_width: 64,
                round_to_odd: true,
            } => {
                record();
                let input = v[0].bits;
                assert_eq!(
                    (input >> 52) & 2047,
                    1023,
                    "bounded round-to-odd reference requires |input| in [1,2)"
                );
                let fraction = input & ((1u64 << 52) - 1);
                let inexact = fraction & ((1 << 29) - 1) != 0;
                let bits = ((input >> 32) & 0x80000000)
                    | 0x3f800000
                    | (fraction >> 29)
                    | u64::from(inexact);
                return Ok(match f.projection {
                    FloatProjection::Value => Value::known(32, bits),
                    FloatProjection::Status => {
                        Value::known(32, status.bits | if inexact { 16 } else { 0 })
                    }
                    FloatProjection::Trapped => {
                        Value::known(1, u64::from(inexact && control.bits & (1 << 12) != 0))
                    }
                });
            }
            F::BFloatWideningFused { .. } => {
                record();
                let sum =
                    bf(v[1].bits).mul_add(bf(v[2].bits), f32::from_bits(v[0].bits as u32) as f64);
                assert_eq!(
                    f64::from(sum as f32),
                    sum,
                    "bounded BF16 widening FMA must be exact"
                );
                u64::from((sum as f32).to_bits())
            }
            F::BFloatDotAdd => {
                assert_eq!(control.bits & 3, 0); // This bounded exact fixture admits both EBF modes.
                record();
                let a = bf(v[1].bits) * bf(v[3].bits);
                let b = bf(v[2].bits) * bf(v[4].bits);
                let product = (a + b) as f32;
                assert_eq!(f64::from(product), a + b);
                let sum = f32::from_bits(v[0].bits as u32) + product;
                assert_eq!(
                    f64::from(sum),
                    f64::from(f32::from_bits(v[0].bits as u32)) + f64::from(product)
                );
                u64::from(sum.to_bits())
            }
            F::BFloatBinary { operation } => {
                record();
                let a = bf(v[0].bits);
                let b = bf(v[1].bits);
                exact_bf(match operation {
                    BFloatOperation::Add => a + b,
                    BFloatOperation::Multiply => a * b,
                    _ => return Err(EvalError::Unsupported),
                })
            }
            F::WideningFusedMultiplyAdd { source_width: 16 } => {
                assert_eq!(control.bits & ((1 << 26) | 3), 0);
                record();
                let a = f32::from_bits(v[0].bits as u32) as f64;
                let b = number(v[1].bits, 16);
                let c = number(v[2].bits, 16);
                let sum = b.mul_add(c, a);
                assert_eq!(
                    f64::from(sum as f32),
                    sum,
                    "bounded widening FMA must be exact"
                );
                u64::from((sum as f32).to_bits())
            }
            F::Add | F::FusedMultiplyAdd { .. } if v.iter().any(|v| signaling(v.bits, f.width)) => {
                record();
                return Ok(match f.projection {
                    FloatProjection::Value => Value::known(f.width, encode(f64::NAN, f.width)),
                    FloatProjection::Status => Value::known(32, status.bits | 1),
                    FloatProjection::Trapped => {
                        Value::known(1, u64::from(control.bits & (1 << 8) != 0))
                    }
                });
            }
            _ => return self.0.evaluate_float(f, v, control, status),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, bits),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
fn extended_run(word: u32, vl: u16, s: &ExtendedState) -> Transition {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x}"));
    r.validate().unwrap();
    assert_eq!(r.support, Support::Full);
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x} VL{vl}: {e:?}"));
    assert!(t.memory.is_empty() && t.atomics.is_empty() && t.wide_memory.is_empty());
    t
}
fn input_lane(s: &State, n: u16, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    let chunk = *s
        .registers
        .get(&Register {
            bank: "a64.vector64",
            index: n * 32 + bit / 64,
        })
        .unwrap_or(&0);
    chunk >> (bit % 64) & if w == 64 { u64::MAX } else { (1 << w) - 1 }
}
#[test]
fn complex_add_rotations_partial_predication_alias_and_all_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            for rot in [0, 1] {
                for alias in [false, true] {
                    let mut s = ExtendedState::default();
                    for e in 0..vl / u16::from(w) {
                        s.0.lane(0, e, w, encode(if e % 2 == 0 { 10.0 } else { 20.0 }, w));
                        s.0.lane(1, e, w, encode(if e % 2 == 0 { 2.0 } else { 3.0 }, w));
                        if e % 3 != 1 {
                            s.0.pred(0, e, w);
                        }
                    }
                    let source = if alias { 0 } else { 1 };
                    let instruction = word(0x64008000 | (rot << 16), w, 0, source, 0);
                    let t = extended_run(instruction, vl, &s);
                    for e in 0..vl / u16::from(w) {
                        let old = number(input_lane(&s.0, 0, e, w), w);
                        let rhs = number(input_lane(&s.0, source as u16, e ^ 1, w), w);
                        let sign = if (e % 2 == 0 && rot == 0) || (e % 2 == 1 && rot == 1) {
                            -1.0
                        } else {
                            1.0
                        };
                        let expected = if e % 3 == 1 { old } else { old + sign * rhs };
                        assert_eq!(output(&t, 0, e, w), encode(expected, w));
                    }
                }
            }
        }
    }
    let mut s = ExtendedState::default();
    s.0.forbidden = Some(1);
    s.0.lane(0, 0, 32, 0xdeadbeef);
    let t = extended_run(word(0x64008000, 32, 0, 1, 0), 128, &s);
    assert_eq!(output(&t, 0, 0, 32), 0xdeadbeef);
    assert!(s.0.trace().is_empty());
}
#[test]
fn complex_fma_rotations_aliases_segments_and_all_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            for rot in 0..4 {
                for alias in [0, 1, 2] {
                    let mut s = ExtendedState::default();
                    for e in 0..vl / u16::from(w) {
                        for (n, a, b) in [(0, 10.0, 20.0), (1, 2.0, 3.0), (2, 4.0, 5.0)] {
                            s.0.lane(n, e, w, encode(if e % 2 == 0 { a } else { b }, w));
                        }
                        if e % 3 != 1 {
                            s.0.pred(0, e, w);
                        }
                    }
                    let d = alias;
                    let t = extended_run(word(0x64000000 | (rot << 13), w, d, 1, 2), vl, &s);
                    for e in 0..vl / u16::from(w) {
                        let old = number(input_lane(&s.0, d as u16, e, w), w);
                        let a = number(input_lane(&s.0, 1, (e & !1) + (rot & 1) as u16, w), w);
                        let bindex = (e & !1)
                            + if e % 2 == 0 {
                                (rot & 1) as u16
                            } else {
                                1 - (rot & 1) as u16
                            };
                        let rhs = number(input_lane(&s.0, 2, bindex, w), w);
                        let neg = if e % 2 == 0 {
                            rot == 1 || rot == 2
                        } else {
                            rot >= 2
                        };
                        let expected = if e % 3 == 1 {
                            old
                        } else {
                            old + if neg { -a * rhs } else { a * rhs }
                        };
                        assert_eq!(output(&t, d as u16, e, w), encode(expected, w));
                    }
                }
            }
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32] {
            for index in 0..128 / (2 * u32::from(w)) {
                for rot in 0..4 {
                    let mut s = ExtendedState::default();
                    for e in 0..vl / u16::from(w) {
                        s.0.lane(0, e, w, encode(10.0, w));
                        s.0.lane(1, e, w, encode(if e % 2 == 0 { 2.0 } else { 3.0 }, w));
                        s.0.lane(2, e, w, encode(f64::from(e % 8 + 1), w));
                    }
                    let base = if w == 16 {
                        0x64a01000 | (index << 19)
                    } else {
                        0x64e01000 | (index << 20)
                    };
                    let t = extended_run(base | (rot << 10) | (2 << 16) | (1 << 5), vl, &s);
                    for e in 0..vl / u16::from(w) {
                        let select = (rot & 1) as u16;
                        let per = 128 / (2 * u16::from(w));
                        let source_pair = (e / 2 / per * per + index as u16) * 2;
                        let rhs = number(
                            input_lane(
                                &s.0,
                                2,
                                source_pair + if e % 2 == 0 { select } else { 1 - select },
                                w,
                            ),
                            w,
                        );
                        let a = if select == 0 { 2.0 } else { 3.0 };
                        let neg = if e % 2 == 0 {
                            rot == 1 || rot == 2
                        } else {
                            rot >= 2
                        };
                        assert_eq!(
                            output(&t, 0, e, w),
                            encode(10.0 + if neg { -a * rhs } else { a * rhs }, w)
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn complex_late_exception_preserves_cumulative_status_and_suppresses_all_chunks() {
    let mut s = ExtendedState::default();
    s.0.all(0, 32, 256);
    s.0.set("a64.fpsr", 0, 1 << 27);
    s.0.set("a64.fpcr", 0, 1 << 8);
    for e in 0..8 {
        s.0.lane(0, e, 32, encode(10.0, 32));
        s.0.lane(1, e, 32, encode(2.0, 32));
        s.0.lane(2, e, 32, encode(3.0, 32));
    }
    s.0.lane(2, 7, 32, 0x7f800001);
    let t = extended_run(word(0x64000000, 32, 0, 1, 2), 256, &s);
    assert_eq!(reg(&t, "a64.fpsr", 0), (1 << 27) | 1);
    assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
    assert!(!t
        .registers
        .iter()
        .any(|r| r.register.bank == "a64.vector64"));
    assert_eq!(s.0.trace().len(), 8);
    s.0.registers.remove(&Register {
        bank: "a64.fpcr",
        index: 0,
    });
    let t = extended_run(word(0x64000000, 32, 0, 1, 2), 256, &s);
    assert!(t.trap.is_none());
    assert_eq!(reg(&t, "a64.fpsr", 0), (1 << 27) | 1);
}
#[test]
fn top_conversions_preserve_even_halves_zero_only_inactive_odd_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for (base, w, widen, merge, bf) in [
            (0x6489a000, 32, true, true, false),
            (0x6481a000, 32, true, false, false),
            (0x64cba000, 64, true, true, false),
            (0x64c3a000, 64, true, false, false),
            (0x6488a000, 32, false, true, false),
            (0x6480a000, 32, false, false, false),
            (0x64caa000, 64, false, true, false),
            (0x64c2a000, 64, false, false, false),
            (0x648aa000, 32, false, true, true),
            (0x6482a000, 32, false, false, true),
        ] {
            for alias in [false, true] {
                let mut s = ExtendedState::default();
                let n = if alias { 0 } else { 1 };
                for e in 0..vl / u16::from(w) {
                    let initial = if widen {
                        encode(1.5, w / 2) << (w / 2) | 0x1234
                    } else {
                        encode(1.5, w)
                    };
                    s.0.lane(n, e, w, initial);
                    if !alias {
                        s.0.lane(0, e, w, 0xdeadbeefdeadbeef);
                    }
                    if e % 2 == 0 {
                        s.0.pred(0, e, w);
                    }
                }
                let t = extended_run(base | (u32::from(n) << 5), vl, &s);
                for e in 0..vl / u16::from(w) {
                    let old = input_lane(&s.0, 0, e, w);
                    let expected = if widen {
                        if e % 2 == 0 {
                            encode(1.5, w)
                        } else if merge {
                            old
                        } else {
                            0
                        }
                    } else {
                        let top = if e % 2 == 0 {
                            if bf {
                                0x3fc0
                            } else {
                                encode(1.5, w / 2)
                            }
                        } else if merge {
                            old >> (w / 2)
                        } else {
                            0
                        };
                        (old & ((1 << (w / 2)) - 1)) | (top << (w / 2))
                    };
                    assert_eq!(output(&t, 0, e, w), expected);
                }
            }
        }
    }
}
#[test]
fn widening_half_and_bfloat_fused_top_bottom_indexed_and_all_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for bf in [false, true] {
            for indexed in [false, true] {
                for top in [0, 1] {
                    for subtract in [false, true] {
                        for index in 0..if indexed { 8 } else { 1 } {
                            let mut s = ExtendedState::default();
                            for e in 0..vl / 32 {
                                s.0.lane(0, e, 32, encode(10.0, 32));
                            }
                            for e in 0..vl / 16 {
                                let encode_input = |x| {
                                    if bf {
                                        encode(x, 32) >> 16
                                    } else {
                                        encode(x, 16)
                                    }
                                };
                                s.0.lane(
                                    1,
                                    e,
                                    16,
                                    encode_input(if e % 2 == 0 { 2.0 } else { 3.0 }),
                                );
                                s.0.lane(2, e, 16, encode_input(f64::from(e % 8 + 1)));
                            }
                            let base = if bf {
                                if indexed {
                                    0x64e04000
                                } else {
                                    0x64e08000
                                }
                            } else if indexed {
                                0x64a04000
                            } else {
                                0x64a08000
                            };
                            let bits = if indexed {
                                ((index >> 1) << 19) | ((index & 1) << 11)
                            } else {
                                0
                            };
                            let t = extended_run(
                                base | (top << 10)
                                    | if subtract { 1 << 13 } else { 0 }
                                    | bits
                                    | (2 << 16)
                                    | (1 << 5),
                                vl,
                                &s,
                            );
                            for e in 0..vl / 32 {
                                let rhs = if indexed {
                                    f64::from(index + 1)
                                } else {
                                    f64::from((2 * e + top as u16) % 8 + 1)
                                };
                                let lhs = if top == 0 { 2.0 } else { 3.0 };
                                assert_eq!(
                                    output(&t, 0, e, 32),
                                    encode(
                                        10.0 + if subtract { -lhs * rhs } else { lhs * rhs },
                                        32
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    let mut s = ExtendedState::default();
    s.0.set("a64.fpcr", 0, 2);
    let r = recipe(0x64e28020, 128).unwrap();
    assert_eq!(evaluate(&r, &s).unwrap().trap, None);
    assert_eq!(s.0.trace().len(), 4);
}
#[test]
fn bfloat_dot_and_matrix_lane_orders_segments_aliases_and_context() {
    for vl in [128, 256, 512, 1024, 2048] {
        for (base, indexed, matrix) in [
            (0x64608000, false, false),
            (0x64604000, true, false),
            (0x6460e400, false, true),
        ] {
            for index in 0..if indexed { 4 } else { 1 } {
                for d in [0, 1, 2] {
                    let mut s = ExtendedState::default();
                    s.0.set("a64.fpsr", 0, 1 << 27);
                    for e in 0..vl / 32 {
                        s.0.lane(0, e, 32, encode(10.0, 32));
                    }
                    for e in 0..vl / 16 {
                        s.0.lane(1, e, 16, encode(f64::from(e % 8 + 1), 32) >> 16);
                        s.0.lane(2, e, 16, encode(f64::from(e % 8 + 2), 32) >> 16);
                    }
                    let t = extended_run(
                        base | if indexed { index << 19 } else { 0 } | (2 << 16) | (1 << 5) | d,
                        vl,
                        &s,
                    );
                    assert!(!t.registers.iter().any(|w| w.register.bank == "a64.fpsr"));
                    for e in 0..vl / 32 {
                        let old = f32::from_bits(input_lane(&s.0, d as u16, e, 32) as u32) as f64;
                        let pairs = if matrix { 2 } else { 1 };
                        let mut expected = old;
                        for k in 0..pairs {
                            let seg = e / 4 * 8;
                            let left = if matrix {
                                seg + (e % 4 / 2) * 4 + 2 * k
                            } else {
                                2 * e
                            };
                            let right = if matrix {
                                seg + (e % 2) * 4 + 2 * k
                            } else if indexed {
                                2 * (e / 4 * 4 + index as u16)
                            } else {
                                2 * e
                            };
                            for a in 0..2 {
                                expected += number(input_lane(&s.0, 1, left + a, 16) << 16, 32)
                                    * number(input_lane(&s.0, 2, right + a, 16) << 16, 32);
                            }
                        }
                        assert_eq!(output(&t, d as u16, e, 32), encode(expected, 32));
                    }
                }
            }
        }
    }
    let mut s = ExtendedState::default();
    s.0.set("a64.fpcr", 0, 1 << 13);
    let r = recipe(0x64628020, 128).unwrap();
    assert!(evaluate(&r, &s).is_ok());
    assert!(!s.0.trace().is_empty());
    s.0.forbidden = Some(1);
    s.0.set("a64.fpcr", 0, 0);
    s.0.set("a64.svcr", 0, 1);
    let r = recipe(0x6462e420, 128).unwrap();
    assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
    s.0.forbidden = None;
    s.0.set("a64.sme_fa64", 0, 1);
    assert!(evaluate(&r, &s).is_ok());
}
#[test]
fn bfloat_same_width_matrix_is_separate_multiply_then_add_contract() {
    for vl in [128, 256, 512, 1024, 2048] {
        let mut s = ExtendedState::default();
        for e in 0..vl / 16 {
            s.0.lane(0, e, 16, encode(10.0, 32) >> 16);
            s.0.lane(1, e, 16, encode(f64::from(e % 4 + 1), 32) >> 16);
            s.0.lane(2, e, 16, encode(f64::from(e % 4 + 2), 32) >> 16);
        }
        let t = extended_run(0x64e2e020, vl, &s);
        for e in 0..vl / 16 {
            let row = (e % 4) / 2;
            let col = e % 2;
            let expected =
                10.0 + f64::from((row * 2 + 1) * (col * 2 + 2) + (row * 2 + 2) * (col * 2 + 3));
            assert_eq!(output(&t, 0, e, 16), encode(expected, 32) >> 16);
        }
        let trace = s.0.trace();
        assert_eq!(trace.len(), usize::from(vl / 16) * 4);
        assert!(matches!(
            trace[0].0,
            FloatOperation::BFloatBinary {
                operation: BFloatOperation::Multiply
            }
        ));
        assert!(matches!(
            trace[2].0,
            FloatOperation::BFloatBinary {
                operation: BFloatOperation::Add
            }
        ));
    }
}

#[test]
fn widening_fma_snapshots_overlapping_accumulator_and_narrow_sources() {
    for vl in [128, 256, 512, 1024, 2048] {
        for bf in [false, true] {
            for top in [0, 1] {
                let mut s = ExtendedState::default();
                for e in 0..vl / 16 {
                    s.0.lane(
                        0,
                        e,
                        16,
                        if bf {
                            encode(f64::from(e % 4 + 1), 32) >> 16
                        } else {
                            encode(f64::from(e % 4 + 1), 16)
                        },
                    );
                    s.0.lane(
                        1,
                        e,
                        16,
                        if bf {
                            encode(2.0, 32) >> 16
                        } else {
                            encode(2.0, 16)
                        },
                    );
                }
                let instruction =
                    (if bf { 0x64e08000 } else { 0x64a08000 }) | (top << 10) | (1 << 16);
                let t = extended_run(instruction, vl, &s);
                for e in 0..vl / 32 {
                    let incoming = input_lane(&s.0, 0, e, 32);
                    let half = input_lane(&s.0, 0, 2 * e + top as u16, 16);
                    let factor = if bf {
                        number(half << 16, 32)
                    } else {
                        number(half, 16)
                    };
                    let expected = (f32::from_bits(incoming as u32) as f64) + factor * 2.0;
                    assert_eq!(output(&t, 0, e, 32), encode(expected, 32));
                }
            }
        }
    }
}

#[test]
fn narrow_round_to_odd_is_rounding_independent_and_preserves_only_required_halves() {
    for vl in [128, 256, 512, 1024, 2048] {
        for (base, top, merge) in [
            (0x650aa000, false, true),
            (0x641ac000, false, false),
            (0x640aa000, true, true),
            (0x6402a000, true, false),
        ] {
            for alias in [false, true] {
                let mut s = ExtendedState::default();
                s.0.set("a64.fpcr", 0, 3 << 22); // RZ must not override explicit RTO.
                s.0.set("a64.fpsr", 0, 1 << 27);
                let n = if alias { 0 } else { 1 };
                for e in 0..vl / 64 {
                    s.0.lane(n, e, 64, 0x3ff0000010000000 | ((e as u64 & 1) << 63));
                    if !alias {
                        s.0.lane(0, e, 64, 0xdeadbeefcafebabe);
                    }
                    if e % 2 == 0 {
                        s.0.pred(0, e, 64);
                    }
                }
                let t = extended_run(base | (u32::from(n) << 5), vl, &s);
                for e in 0..vl / 64 {
                    let incoming = input_lane(&s.0, 0, e, 64);
                    let expected = if top {
                        (incoming & 0xffffffff)
                            | ((if e % 2 == 0 {
                                0x3f800001
                            } else if merge {
                                incoming >> 32
                            } else {
                                0
                            }) << 32)
                    } else if e % 2 == 0 {
                        0x3f800001
                    } else if merge {
                        incoming
                    } else {
                        0
                    };
                    assert_eq!(output(&t, 0, e, 64), expected);
                }
                assert_eq!(reg(&t, "a64.fpsr", 0), (1 << 27) | 16);
            }
        }
    }
}

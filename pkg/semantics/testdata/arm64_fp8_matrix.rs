#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fp8_matrix::a64(
        word,
        0x1000,
        if word >> 31 != 0 { 128 } else { vl },
        if word >> 31 != 0 {
            vl
        } else if vl == 128 {
            2048
        } else {
            128
        },
    )
}
const FORMS: &[(u32, u8, u8)] = &[
    (0x6e00ec00, 16, 0), // FMMLA_asimd_FP8FP16
    (0x6e80ec00, 32, 0), // FMMLA_asimd_FP8FP32
    (0x6460e000, 16, 1), // fmmla_z16_zz8z8_
    (0x6420e000, 32, 1), // fmmla_z32_zz8z8_
    (0x80300008, 16, 3), // fmop4a_za16_z8z8_b1x2
    (0x80200008, 16, 3), // fmop4a_za16_z8z8_b1x1
    (0x80200208, 16, 3), // fmop4a_za16_z8z8_b2x1
    (0x80300208, 16, 3), // fmop4a_za16_z8z8_b2x2
    (0x80300000, 32, 3), // fmop4a_za32_z8z8_b1x2
    (0x80200000, 32, 3), // fmop4a_za32_z8z8_b1x1
    (0x80200200, 32, 3), // fmop4a_za32_z8z8_b2x1
    (0x80300200, 32, 3), // fmop4a_za32_z8z8_b2x2
    (0x80a00008, 16, 2), // fmopa_za16_pp_z8z8_8
    (0x80a00000, 32, 2), // fmopa_za32_pp_z8z8_8
    (0x80600008, 16, 4), // ftmopa_za16_z8z8zi_b2x1
    (0x80600000, 32, 4), // ftmopa_za32_z8z8zi_b2x1
];
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    p: [[u64; 4]; 16],
    fma: bool,
    ssve: bool,
    calls: Vec<(u8, u8, [u64; 3])>,
    at: Cell<usize>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.za64" => Value::known(
                64,
                self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.svcr" => Value::known(64, self.sm),

            "a64.fpcr" => Value::known(32, 0x07c09f03),
            "a64.fpmr" => Value::known(64, 0x3faf7fc1ff),
            "a64.predicate64" => Value::known(
                64,
                self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
            ),
            "a64.sme_fa64" => Value::known(1, u64::from(self.fma)),
            _ => panic!("unexpected register {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = self.at.get();
        let (w, sw, inputs) = self.calls[i];
        assert_eq!(f.operation, FloatOperation::Fp8Dot { ways: sw / 8 });
        assert_eq!(f.width, w);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(
            v,
            [
                Value::known(w, inputs[0]),
                Value::known(sw, inputs[1]),
                Value::known(sw, inputs[2]),
                Value::known(64, 0x3faf7fc1ff)
            ]
        );
        assert_eq!(control, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(w, 0x500 + i as u64))
    }
}
fn lane(z: &[[u64; 32]], r: usize, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    (z[r][usize::from(bit / 64)] >> (bit % 64)) & if w == 64 { u64::MAX } else { (1u64 << w) - 1 }
}
#[test]
fn all_fp8_matrix_layouts_predicates_controls_aliases_lengths_and_backing() {
    for &(base, width, kind) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if kind == 4 { 4 } else { 1 } {
                    let za = kind >= 2;
                    let bytes = u16::from(width) / 8;
                    let active_vl = if kind == 0 { 128 } else { vl };
                    let dim = active_vl / u16::from(width);
                    let tile = if za { u32::from(width / 8 - 1) } else { 0 };
                    let (n, m, d) = if kind == 3 {
                        (14, 30, tile)
                    } else if kind == 4 {
                        (if pattern == 1 { 20 } else { 28 }, 15, tile)
                    } else {
                        (
                            if pattern == 0 { 0 } else { 31 },
                            if pattern == 0 { 0 } else { 15 },
                            if za {
                                tile
                            } else if pattern == 0 {
                                0
                            } else {
                                31
                            },
                        )
                    };
                    let pn = if pattern == 1 {
                        7
                    } else if pattern == 2 {
                        3
                    } else {
                        0
                    };
                    let pm = if pattern == 1 {
                        6
                    } else if pattern == 2 {
                        5
                    } else {
                        0
                    };
                    let word = base
                        | (n << 5)
                        | ((if kind == 3 { m & 15 } else { m }) << 16)
                        | d
                        | if kind == 4 {
                            index << 4
                        } else if kind == 2 {
                            pn << 10 | pm << 13
                        } else {
                            0
                        };
                    let mut s = State {
                        z: std::array::from_fn(|n| {
                            std::array::from_fn(|k| {
                                0x123456789abcdef0u64.rotate_left((n * 5 + k * 7) as u32)
                            })
                        }),
                        za: (0..256)
                            .map(|n| {
                                std::array::from_fn(|k| {
                                    0xfedcba9876543210u64.rotate_left((n + k) as u32)
                                })
                            })
                            .collect(),
                        p: std::array::from_fn(|n| {
                            std::array::from_fn(|k| match pattern {
                                0 => 0,
                                1 => u64::MAX,
                                _ => 0x965aa5965aa5965au64.rotate_left((n + k) as u32),
                            })
                        }),
                        sm: if za { 3 } else { 0 },
                        fma: false,
                        ssve: false,
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    if kind == 4 {
                        s.z[20] = std::array::from_fn(|k| match pattern {
                            0 => 0,
                            1 => u64::MAX,
                            _ => 0x1965a5969a695a96u64.rotate_left(k as u32),
                        });
                    }
                    let mut expected_z = s.z;
                    let mut expected_za = s.za.clone();
                    let mut emit = |row: usize, col: u16, old: u64, a: u64, b: u64, ways: u8| {
                        let marker = 0x500 + s.calls.len() as u64;
                        s.calls.push((width, ways * 8, [old, a, b]));
                        let bit = col * u16::from(width);
                        let slot = if za {
                            &mut expected_za[row][usize::from(bit / 64)]
                        } else {
                            &mut expected_z[d as usize][usize::from(bit / 64)]
                        };
                        let mask = ((1u64 << width) - 1) << (bit % 64);
                        *slot = (*slot & !mask) | (marker << (bit % 64));
                    };
                    if !za {
                        for e in 0..active_vl / u16::from(width) {
                            let segment = e / 4;
                            let row = (e % 4) / 2;
                            let col = e % 2;
                            let sw = width * 2;
                            emit(
                                0,
                                e,
                                lane(&s.z, d as usize, e, width),
                                lane(&s.z, n as usize, segment * 2 + row, sw),
                                lane(&s.z, m as usize, segment * 2 + col, sw),
                                sw / 8,
                            );
                        }
                        if kind == 0 {
                            for c in 2..vl / 64 {
                                expected_z[d as usize][usize::from(c)] = 0;
                            }
                        }
                    } else {
                        for row in 0..dim {
                            for col in 0..dim {
                                let physical = usize::from(row * bytes + tile as u16);
                                let mut a = 0;
                                let mut b = 0;
                                let mut active = kind != 2;
                                if kind == 4 {
                                    let mut count = 0;
                                    for member in 0..2 {
                                        if width == 32 {
                                            count = 0;
                                        }
                                        for e in 0..bytes {
                                            let control_bit = index as u16 * (vl / 4)
                                                + col * bytes * 2
                                                + member * bytes
                                                + e;
                                            if lane(&s.z, 20, control_bit, 1) != 0 && count < 2 {
                                                a |= lane(
                                                    &s.z,
                                                    (n + u32::from(member)) as usize,
                                                    row * bytes + e,
                                                    8,
                                                ) << ((if width == 32 {
                                                    member * 2
                                                } else {
                                                    0
                                                } + count)
                                                    * 8);
                                                count += 1;
                                            }
                                        }
                                    }
                                    b = lane(&s.z, m as usize, col, width);
                                } else {
                                    let nr = if kind == 3 {
                                        n + ((base >> 9) & 1) * u32::from(col / (dim / 2))
                                    } else {
                                        n
                                    };
                                    let mr = if kind == 3 {
                                        m + ((base >> 20) & 1) * u32::from(row / (dim / 2))
                                    } else {
                                        m
                                    };
                                    for i in 0..bytes {
                                        let pi = |p: u32, byte: u16| {
                                            s.p[p as usize][usize::from(byte / 64)] >> (byte % 64)
                                                & 1
                                                != 0
                                        };
                                        let pa = kind != 2 || pi(pn, row * bytes + i);
                                        let pb = kind != 2 || pi(pm, col * bytes + i);
                                        active |= pa && pb;
                                        if pa {
                                            a |= lane(&s.z, nr as usize, row * bytes + i, 8)
                                                << (i * 8);
                                        }
                                        if pb {
                                            b |= lane(&s.z, mr as usize, col * bytes + i, 8)
                                                << (i * 8);
                                        }
                                    }
                                }
                                if active {
                                    emit(
                                        physical,
                                        col,
                                        lane(&s.za, physical, col, width),
                                        a,
                                        b,
                                        width / 8,
                                    );
                                }
                            }
                        }
                    }
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    assert_eq!(t.trap, None);
                    assert_eq!(s.at.get(), s.calls.len());
                    let mut actual_z = s.z;
                    let mut actual_za = s.za.clone();
                    for w in t.registers {
                        match w.register.bank {
                            "a64.vector64" => {
                                actual_z[usize::from(w.register.index / 32)]
                                    [usize::from(w.register.index % 32)] = w.value.bits
                            }
                            "a64.za64" => {
                                actual_za[usize::from(w.register.index / 32)]
                                    [usize::from(w.register.index % 32)] = w.value.bits
                            }
                            _ => panic!("unexpected matrix status/context write"),
                        }
                    }
                    assert_eq!(actual_z, expected_z, "{word:08x} VL{vl}");
                    assert_eq!(actual_za, expected_za, "{word:08x} VL{vl}");
                }
            }
        }
    }
}
#[test]
fn matrix_mode_guards_reject_before_operands() {
    for &(word, _, kind) in FORMS {
        for sm in 0..4 {
            for fa64 in [false, true] {
                let admitted = if kind >= 2 {
                    sm == 3
                } else if kind == 1 {
                    sm & 1 == 0
                } else {
                    sm & 1 == 0 || fa64
                };
                if !admitted {
                    let s = State {
                        z: [[0; 32]; 32],
                        za: vec![],
                        p: [[0; 4]; 16],
                        sm,
                        fma: fa64,
                        ssve: false,
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
    }
}

#[test]
fn fully_inactive_fp8_outer_products_do_not_consume_fp_context_or_sources() {
    struct Inactive(bool);
    impl Machine for Inactive {
        fn read_register(&self, r: Register) -> Value {
            match r.bank {
                "a64.svcr" => Value::known(64, 3),
                "a64.predicate64" => Value::known(
                    64,
                    if self.0 {
                        if r.index / 4 == 0 {
                            0x5555555555555555
                        } else {
                            0xaaaaaaaaaaaaaaaa
                        }
                    } else {
                        0
                    },
                ),
                "a64.za64" => Value::known(64, 0x71259bd3e4af6801),
                _ => panic!("inactive FP8 outer product read {r:?}"),
            }
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!()
        }
        fn evaluate_float(
            &self,
            _: &FloatExpression,
            _: &[Value],
            _: Value,
            _: Value,
        ) -> Result<Value, EvalError> {
            panic!("inactive FP8 outer product evaluated FP")
        }
    }
    for &(word, _, kind) in FORMS {
        if kind != 2 {
            continue;
        }
        for vl in [128, 256, 512, 1024, 2048] {
            for disjoint in [false, true] {
                let word = word | (1 << 13);
                let t = evaluate(&recipe(word, vl).unwrap(), &Inactive(disjoint)).unwrap();
                assert!(t.registers.iter().all(|w| w.register.bank == "a64.za64"
                    && w.value == Value::known(64, 0x71259bd3e4af6801)));
                assert_eq!(t.trap, None);
            }
        }
    }
}

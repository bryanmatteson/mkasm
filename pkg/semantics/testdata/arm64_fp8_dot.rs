#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fp8_dot::a64(
        word,
        0x1000,
        vl,
        if word >> 31 != 0 {
            vl
        } else if vl == 128 {
            2048
        } else {
            128
        },
    )
}
const FORMS: &[(u32, u8, u8, u16, u16)] = &[
    (0x64608400, 32, 0, 1, 0), // fdot_z32_zz8z8_
    (0x64604400, 32, 1, 1, 0), // fdot_z32_zz8z8i_
    (0xc1500038, 32, 2, 2, 0), // fdot_za32_z8z8i_2xi
    (0xc1508008, 32, 2, 4, 0), // fdot_za32_z8z8i_4xi
    (0xc1201018, 32, 3, 2, 0), // fdot_za32_z8z8v_2x1
    (0xc1301018, 32, 3, 4, 0), // fdot_za32_z8z8v_4x1
    (0xc1a01030, 32, 4, 2, 0), // fdot_za32_z8z8w_2x2
    (0xc1a11030, 32, 4, 4, 0), // fdot_za32_z8z8w_4x4
    (0xc1d00020, 16, 2, 2, 0), // fdot_za_z8z8i_2xi
    (0xc1109040, 16, 2, 4, 0), // fdot_za_z8z8i_4xi
    (0xc1201008, 16, 3, 2, 0), // fdot_za_z8z8v_2x1
    (0xc1301008, 16, 3, 4, 0), // fdot_za_z8z8v_4x1
    (0xc1a01020, 16, 4, 2, 0), // fdot_za_z8z8w_2x2
    (0xc1a11020, 16, 4, 4, 0), // fdot_za_z8z8w_4x4
    (0x64208400, 16, 0, 1, 0), // fdot_z_zz8z8_
    (0x64204400, 16, 1, 1, 0), // fdot_z_zz8z8i_
    (0xc1d00800, 32, 5, 4, 0), // fvdotb_za32_z8z8i_2xi
    (0xc1d00810, 32, 5, 4, 1), // fvdott_za32_z8z8i_2xi
    (0xc1d01020, 16, 5, 2, 0), // fvdot_za_z8z8i_2xi
];
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    w: u32,
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
            "a64.fp8_dot2" | "a64.fp8_dot4" => Value::known(1, u64::from(self.fma)),
            "a64.ssve_fp8_dot2" | "a64.ssve_fp8_dot4" => Value::known(1, u64::from(self.ssve)),
            "a64.fpcr" => Value::known(32, 0x07c09f03),
            "a64.fpmr" => Value::known(64, 0x3faf7fc1ff),
            "a64.gpr" => Value::known(64, u64::from(self.w)),
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
    (z[r][usize::from(bit / 64)] >> (bit % 64)) & ((1u64 << w) - 1)
}
fn word(
    base: u32,
    width: u8,
    kind: u8,
    nreg: u16,
    n: u32,
    m: u32,
    d: u32,
    index: u32,
    offset: u32,
) -> u32 {
    let n = n & if kind == 2 || kind == 4 {
        32 - u32::from(nreg)
    } else if kind == 5 {
        30
    } else {
        31
    };
    let m = m & if kind == 4 {
        32 - u32::from(nreg)
    } else if kind >= 2 {
        15
    } else if kind == 1 {
        7
    } else {
        31
    };
    let mut value = base | (n << 5) | (m << 16) | if kind < 2 { d } else { offset & 7 };
    if kind == 1 {
        value |= if width == 16 {
            ((index >> 1) << 19) | ((index & 1) << 11)
        } else {
            index << 19
        };
    }
    if kind == 2 || kind == 5 {
        value |= if width == 16 {
            ((index >> 1) << 10) | ((index & 1) << 3)
        } else if kind == 5 {
            ((index >> 1) << 10) | ((index & 1) << 3)
        } else {
            index << 10
        };
    }
    value
}
#[test]
fn all_fp8_dot_layouts_indices_aliases_groups_and_lengths() {
    for &(base, width, kind, nreg, top) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for (n, m, d, sm) in [(0, 0, 0, 0), (31, 15, 31, 1), (28, 28, 28, 0)] {
                for index in 0..if kind == 1 || kind == 2 || kind == 5 {
                    if width == 16 {
                        8
                    } else {
                        4
                    }
                } else {
                    1
                } {
                    let za = kind >= 2;
                    let instruction = word(base, width, kind, nreg, n, m, d, index, 7);
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
                        sm: if za { 3 } else { sm },
                        w: u32::MAX - 3,
                        fma: sm == 0,
                        ssve: sm == 1,
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    let mut expected_z = s.z;
                    let mut expected_za = s.za.clone();
                    let nr = n & if kind == 2 || kind == 4 {
                        32 - u32::from(nreg)
                    } else if kind == 5 {
                        30
                    } else {
                        31
                    };
                    let mr = m & if kind == 4 {
                        32 - u32::from(nreg)
                    } else if za {
                        15
                    } else if kind == 1 {
                        7
                    } else {
                        31
                    };
                    let stride = vl / 8 / nreg;
                    let row = ((u64::from(s.w) + 7) % u64::from(stride)) as u16;
                    for member in 0..nreg {
                        for e in 0..vl / u16::from(width) {
                            let sw = if kind == 5 { 16 } else { width };
                            let segment = e / (128 / u16::from(width)) * (128 / u16::from(width))
                                + index as u16;
                            let a = if kind == 5 {
                                let ai = e * (u16::from(width) / 8) + member;
                                lane(&s.z, nr as usize, ai, 8)
                                    | (lane(&s.z, (nr + 1) as usize, ai, 8) << 8)
                            } else {
                                lane(&s.z, ((nr + u32::from(member)) % 32) as usize, e, width)
                            };
                            let bi = if kind == 5 && width == 32 {
                                segment * 2 + top
                            } else if kind == 1 || kind == 2 || kind == 5 {
                                segment
                            } else {
                                e
                            };
                            let b = lane(
                                &s.z,
                                (mr + if kind == 4 { u32::from(member) } else { 0 }) as usize,
                                bi,
                                sw,
                            );
                            let old = if za {
                                lane(&s.za, usize::from(row + member * stride), e, width)
                            } else {
                                lane(&s.z, d as usize, e, width)
                            };
                            let bit = e * u16::from(width);
                            let chunk = usize::from(bit / 64);
                            let shift = bit % 64;
                            let mask = ((1u64 << width) - 1) << shift;
                            let tag = 0x500 + s.calls.len() as u64;
                            let slot = if za {
                                &mut expected_za[usize::from(row + member * stride)][chunk]
                            } else {
                                &mut expected_z[d as usize][chunk]
                            };
                            *slot = (*slot & !mask) | (tag << shift);
                            s.calls.push((width, sw, [old, a, b]));
                        }
                    }
                    let r = recipe(instruction, vl).unwrap();
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
                            _ => panic!("unexpected status/context write"),
                        }
                    }
                    assert_eq!(actual_z, expected_z, "{instruction:08x} VL{vl}");
                    assert_eq!(actual_za, expected_za, "{instruction:08x} VL{vl}");
                }
            }
        }
    }
}
#[test]
fn dot_streaming_and_nonstreaming_capabilities_admit_independently_before_operands() {
    for &(instruction, _, kind, _, _) in FORMS {
        for sm in 0..4 {
            for fma in [false, true] {
                for ssve in [false, true] {
                    let s = State {
                        z: [[0; 32]; 32],
                        za: vec![],
                        sm,
                        w: 0,
                        fma,
                        ssve,
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    let admitted = if kind >= 2 {
                        sm == 3
                    } else if sm & 1 != 0 {
                        ssve
                    } else {
                        fma
                    };
                    if !admitted {
                        assert_eq!(
                            evaluate(&recipe(instruction, 128).unwrap(), &s),
                            Err(EvalError::UnsupportedContext)
                        );
                        assert_eq!(s.at.get(), 0);
                    }
                }
            }
        }
    }
}

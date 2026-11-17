#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8, u16, u8)] = &[
    (0xc120b140, 10, 2, 1), // famax_mz_zzw_2x2
    (0xc120b940, 10, 4, 1), // famax_mz_zzw_4x4
    (0xc120b141, 11, 2, 1), // famin_mz_zzw_2x2
    (0xc120b941, 11, 4, 1), // famin_mz_zzw_4x4
    (0xc120c000, 12, 2, 3), // fclamp_mz_zz_2
    (0xc120c800, 12, 4, 3), // fclamp_mz_zz_4
    (0xc120a120, 3, 2, 0),  // fmaxnm_mz_zzv_2x1
    (0xc120a920, 3, 4, 0),  // fmaxnm_mz_zzv_4x1
    (0xc120b120, 3, 2, 1),  // fmaxnm_mz_zzw_2x2
    (0xc120b920, 3, 4, 1),  // fmaxnm_mz_zzw_4x4
    (0xc120a100, 1, 2, 0),  // fmax_mz_zzv_2x1
    (0xc120a900, 1, 4, 0),  // fmax_mz_zzv_4x1
    (0xc120b100, 1, 2, 1),  // fmax_mz_zzw_2x2
    (0xc120b900, 1, 4, 1),  // fmax_mz_zzw_4x4
    (0xc120a121, 4, 2, 0),  // fminnm_mz_zzv_2x1
    (0xc120a921, 4, 4, 0),  // fminnm_mz_zzv_4x1
    (0xc120b121, 4, 2, 1),  // fminnm_mz_zzw_2x2
    (0xc120b921, 4, 4, 1),  // fminnm_mz_zzw_4x4
    (0xc120a101, 2, 2, 0),  // fmin_mz_zzv_2x1
    (0xc120a901, 2, 4, 0),  // fmin_mz_zzv_4x1
    (0xc120b101, 2, 2, 1),  // fmin_mz_zzw_2x2
    (0xc120b901, 2, 4, 1),  // fmin_mz_zzw_4x4
    (0xc120e800, 0, 2, 0),  // fmul_mz_zzv_2x1
    (0xc121e800, 0, 4, 0),  // fmul_mz_zzv_4x1
    (0xc120e400, 0, 2, 1),  // fmul_mz_zzw_2x2
    (0xc121e400, 0, 4, 1),  // fmul_mz_zzw_4x4
    (0xc1ace000, 6, 2, 2),  // frinta_mz_z_2
    (0xc1bce000, 6, 4, 2),  // frinta_mz_z_4
    (0xc1aae000, 7, 2, 2),  // frintm_mz_z_2
    (0xc1bae000, 7, 4, 2),  // frintm_mz_z_4
    (0xc1a8e000, 8, 2, 2),  // frintn_mz_z_2
    (0xc1b8e000, 8, 4, 2),  // frintn_mz_z_4
    (0xc1a9e000, 9, 2, 2),  // frintp_mz_z_2
    (0xc1b9e000, 9, 4, 2),  // frintp_mz_z_4
    (0xc120a180, 5, 2, 0),  // fscale_mz_zzv_2x1
    (0xc120a980, 5, 4, 0),  // fscale_mz_zzv_4x1
    (0xc120b180, 5, 2, 1),  // fscale_mz_zzw_2x2
    (0xc120b980, 5, 4, 1),  // fscale_mz_zzw_4x4
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_group_float::a64(word, 0x1000, vl)
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn bits(v: f64, w: u8) -> u64 {
    if w == 64 {
        return v.to_bits();
    }
    let b = (v as f32).to_bits();
    if w == 32 {
        return u64::from(b);
    }
    if b & 0x7fffffff == 0 {
        return u64::from(b >> 16) & 0x8000;
    }
    u64::from(((b >> 16) & 0x8000) | ((((b >> 23) & 255) - 112) << 10) | ((b >> 13) & 1023))
}
fn number(v: u64, w: u8) -> f64 {
    if w == 64 {
        f64::from_bits(v)
    } else if w == 32 {
        f64::from(f32::from_bits(v as u32))
    } else {
        let sign = if v & 0x8000 == 0 { 1.0 } else { -1.0 };
        let ex = (v >> 10) & 31;
        let f = v & 1023;
        if ex == 0 {
            sign * (f as f64) * 2f64.powi(-24)
        } else {
            sign * (1.0 + (f as f64) / 1024.0) * 2f64.powi(ex as i32 - 15)
        }
    }
}
fn lane(z: &[[u64; 32]], n: u32, e: u16, w: u8) -> u64 {
    let b = e * u16::from(w);
    (z[n as usize][usize::from(b / 64)] >> (b % 64)) & mask(w)
}
fn put(z: &mut [[u64; 32]], n: u32, e: u16, w: u8, v: u64) {
    let b = e * u16::from(w);
    let chunk = &mut z[n as usize][usize::from(b / 64)];
    let sh = b % 64;
    *chunk = (*chunk & !(mask(w) << sh)) | (v << sh);
}
struct State {
    z: [[u64; 32]; 32],
    sm: u64,
    fa64: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.svcr" => self.sm,
                "a64.sme_fa64" => u64::from(self.fa64),
                "a64.fpcr" => 0x04009f00,
                "a64.fpsr" => 0x08000000,
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
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
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(ctrl, Value::known(32, if self.fa64 { 0x9f00 } else { 0 }));
        assert_eq!(status, Value::known(32, 0x08000000));
        let a = number(v[0].bits, f.width);
        let b = if v.len() > 1 {
            number(v[1].bits, f.width)
        } else {
            0.0
        };
        let out = match f.operation {
            FloatOperation::Multiply => a * b,
            FloatOperation::MinMax { minimum, .. } => {
                if minimum {
                    a.min(b)
                } else {
                    a.max(b)
                }
            }
            FloatOperation::RoundToIntegral {
                rounding,
                exact: false,
            } => match rounding {
                FloatRounding::NearestEven => a.round_ties_even(),
                FloatRounding::NearestAway => a.round(),
                FloatRounding::NegativeInfinity => a.floor(),
                FloatRounding::PositiveInfinity => a.ceil(),
                _ => panic!(),
            },
            _ => panic!("unexpected {:?}", f.operation),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, bits(out, f.width)),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
#[test]
fn every_group_float_class_width_length_alias_and_storage() {
    for &(base, op, nreg, layout) in FORMS {
        for size in 1..=3u32 {
            if layout == 2 && size != 2 {
                continue;
            }
            let w = 8u8 << size;
            for vl in [128, 256, 512, 1024, 2048] {
                for alias in [false, true] {
                    let d = 8;
                    let n = if layout == 3 {
                        8
                    } else if alias {
                        8
                    } else {
                        24
                    };
                    let m = if layout == 3 {
                        9
                    } else if layout == 1 {
                        if op == 5 {
                            16
                        } else {
                            8
                        }
                    } else {
                        15
                    };
                    let word = base
                        | (size << 22)
                        | d
                        | if layout == 2 {
                            0
                        } else if op == 0 && layout == 0 {
                            m << 17
                        } else {
                            m << 16
                        }
                        | if op == 0 || layout == 2 || layout == 3 {
                            n << 5
                        } else {
                            0
                        };
                    let mut s = State {
                        z: [[0; 32]; 32],
                        sm: 1,
                        fa64: alias,
                    };
                    for reg in 0..32u32 {
                        for e in 0..2048 / u16::from(w) {
                            let v = match (reg + u32::from(e)) % 4 {
                                0 => -2.5,
                                1 => 1.5,
                                2 => 3.5,
                                _ => -1.5,
                            };
                            put(&mut s.z, reg, e, w, bits(v, w));
                        }
                    }
                    if op == 5 {
                        for reg in m..m + if layout == 1 { u32::from(nreg) } else { 1 } {
                            for e in 0..2048 / u16::from(w) {
                                put(&mut s.z, reg, e, w, if e % 2 == 0 { 1 } else { mask(w) });
                            }
                        }
                    }
                    let before = s.z;
                    let mut expected = before;
                    for member in 0..nreg {
                        for e in 0..vl / u16::from(w) {
                            let src = if op == 0 || layout == 2 {
                                n + u32::from(member)
                            } else if layout == 3 {
                                n
                            } else {
                                d + u32::from(member)
                            };
                            let a = number(lane(&before, src, e, w), w);
                            let rhs = m + if layout == 1 { u32::from(member) } else { 0 };
                            let b = number(lane(&before, rhs, e, w), w);
                            let result = match op {
                                0 => a * b,
                                1 | 3 => a.max(b),
                                2 | 4 => a.min(b),
                                5 => a * if e % 2 == 0 { 2.0 } else { 0.5 },
                                6 => a.round(),
                                7 => a.floor(),
                                8 => a.round_ties_even(),
                                9 => a.ceil(),
                                10 => a.abs().max(b.abs()),
                                11 => a.abs().min(b.abs()),
                                12 => a
                                    .max(number(lane(&before, d + u32::from(member), e, w), w))
                                    .min(b),
                                _ => panic!(),
                            };
                            put(&mut expected, d + u32::from(member), e, w, bits(result, w));
                        }
                    }
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    let mut actual = before;
                    for out in t.registers {
                        if out.register.bank == "a64.fpsr" {
                            assert_eq!(out.value, Value::known(32, 0x08000000));
                        } else {
                            assert_eq!(out.register.bank, "a64.vector64");
                            actual[usize::from(out.register.index / 32)]
                                [usize::from(out.register.index % 32)] = out.value.bits;
                        }
                    }
                    for reg in 0..32 {
                        for chunk in 0..32 {
                            assert_eq!(
                                actual[reg][chunk], expected[reg][chunk],
                                "{word:08x} VL{vl} alias{alias} Z{reg} chunk{chunk}"
                            );
                        }
                    }
                    assert_eq!(t.trap, None);
                    assert_eq!(t.next_pc, Value::known(64, 0x1004));
                }
            }
        }
    }
}
#[test]
fn group_float_modes_and_lengths() {
    for &(word, _, _, _) in FORMS {
        for sm in [0, 2] {
            let s = State {
                z: [[0; 32]; 32],
                sm,
                fa64: false,
            };
            let r = recipe(word | (2 << 22), 128).unwrap();
            assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
        }
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(word | (2 << 22), vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8, u8)] = &[
    (0x65008000, 0, 1),  // bfadd_z_p_zz_
    (0x65000000, 0, 0),  // bfadd_z_zz_
    (0x64202400, 8, 4),  // bfclamp_z_zz_
    (0x65048000, 5, 1),  // bfmaxnm_z_p_zz_
    (0x65068000, 3, 1),  // bfmax_z_p_zz_
    (0x65058000, 6, 1),  // bfminnm_z_p_zz_
    (0x65078000, 4, 1),  // bfmin_z_p_zz_
    (0x65200000, 9, 3),  // bfmla_z_p_zzz_
    (0x64200800, 9, 2),  // bfmla_z_zzzi_h
    (0x65202000, 10, 3), // bfmls_z_p_zzz_
    (0x64200c00, 10, 2), // bfmls_z_zzzi_h
    (0x65028000, 2, 1),  // bfmul_z_p_zz_
    (0x65000800, 2, 0),  // bfmul_z_zz_
    (0x64202800, 2, 2),  // bfmul_z_zzi_h
    (0x65098000, 7, 1),  // bfscale_z_p_zz_
    (0x65018000, 1, 1),  // bfsub_z_p_zz_
    (0x65000400, 1, 0),  // bfsub_z_zz_
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sve_bfloat_arithmetic::a64(word, 0x1000, vl)
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn bits(v: f64, w: u8) -> u64 {
    if w == 32 {
        u64::from((v as f32).to_bits())
    } else {
        u64::from((v as f32).to_bits() >> 16)
    }
}
fn number(v: u64, w: u8) -> f64 {
    f64::from(f32::from_bits(if w == 32 {
        v as u32
    } else {
        (v as u32) << 16
    }))
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
    pred: [u64; 4],
    sm: u64,
    sme2: bool,
    fa64: bool,
    inactive: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        let value = match r.bank {
            "a64.svcr" => self.sm,
            "a64.sme2" => u64::from(self.sme2),
            "a64.sme_fa64" => u64::from(self.fa64),
            "a64.fpcr" => {
                assert!(!self.inactive);
                0x04009f00
            }
            "a64.fpsr" => {
                assert!(!self.inactive);
                0x08000000
            }
            "a64.predicate64" => {
                assert_eq!(r.index / 4, 3);
                self.pred[usize::from(r.index % 4)]
            }
            "a64.vector64" => {
                if self.inactive {
                    assert_eq!(r.index / 32, 8);
                }
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)]
            }
            _ => panic!("{r:?}"),
        };
        Value::known(64, value)
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        values: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        assert!(!self.inactive);
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(
            control,
            Value::known(32, if self.fa64 || self.sm == 0 { 0x9f00 } else { 0 })
        );
        assert_eq!(status, Value::known(32, 0x08000000));
        let a = number(values[0].bits, f.width);
        let b = number(values[1].bits, f.width);
        let out = match f.operation {
            FloatOperation::BFloatBinary { operation } => match operation {
                BFloatOperation::Add => a + b,
                BFloatOperation::Subtract => a - b,
                BFloatOperation::Multiply => a * b,
                _ => panic!(),
            },
            FloatOperation::BFloatFused => a + b * number(values[2].bits, 16),
            FloatOperation::MinMax { minimum, .. } => {
                if minimum {
                    a.min(b)
                } else {
                    a.max(b)
                }
            }
            _ => panic!(),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, bits(out, f.width)),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}

#[test]
fn all_sve_bfloat_classes_lengths_predicates_indices_aliases_and_storage() {
    for &(base, op, layout) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if layout == 2 { 8 } else { 1 } {
                    let alias = pattern == 2;
                    let d = if alias { 7 } else { 8 };
                    let n = if layout == 1 || alias { d } else { 24 };
                    let m = if op == 7 {
                        15
                    } else if alias {
                        d
                    } else if layout == 2 {
                        3
                    } else {
                        15
                    };
                    let g = 3;
                    let word = base
                        | d
                        | if layout == 1 { m << 5 } else { n << 5 }
                        | if layout != 1 { m << 16 } else { g << 10 }
                        | if layout == 3 { g << 10 } else { 0 }
                        | if layout == 2 {
                            ((index & 3) << 19) | ((index >> 2) << 22)
                        } else {
                            0
                        };
                    let mut s = State {
                        z: [[0; 32]; 32],
                        pred: [0; 4],
                        sm: u64::from(alias),
                        sme2: true,
                        fa64: alias,
                        inactive: false,
                    };
                    for reg in 0..32u32 {
                        for el in 0..128u16 {
                            let value = match (reg + u32::from(el)) % 4 {
                                0 => -2.5,
                                1 => 1.5,
                                2 => 3.5,
                                _ => -1.5,
                            };
                            put(&mut s.z, reg, el, 16, bits(value, 16));
                        }
                    }
                    for el in 0..vl / 16 {
                        if pattern == 2 || pattern == 1 && el % 3 != 0 {
                            let bit = el * 2;
                            s.pred[usize::from(bit / 64)] |= 1 << (bit % 64);
                        }
                    }
                    if op == 7 {
                        for el in 0..128u16 {
                            put(&mut s.z, m, el, 16, if el % 2 == 0 { 1 } else { 0xffff });
                        }
                    }
                    let before = s.z;
                    let mut expected = before;
                    for el in 0..vl / 16 {
                        let active = (layout != 1 && layout != 3)
                            || ((s.pred[usize::from(el * 2 / 64)] >> (el * 2 % 64)) & 1) != 0;
                        if !active {
                            continue;
                        }
                        let a = number(lane(&before, n, el, 16), 16);
                        let rhs = if layout == 2 {
                            el / 8 * 8 + index as u16
                        } else {
                            el
                        };
                        let b = number(lane(&before, m, rhs, 16), 16);
                        let old = number(lane(&before, d, el, 16), 16);
                        let result = match op {
                            0 => a + b,
                            1 => a - b,
                            2 => a * b,
                            3 | 5 => a.max(b),
                            4 | 6 => a.min(b),
                            7 => a * if el % 2 == 0 { 2.0 } else { 0.5 },
                            8 => a.max(old).min(b),
                            9 => old + a * b,
                            10 => old - a * b,
                            _ => panic!(),
                        };
                        put(&mut expected, d, el, 16, bits(result, 16));
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
                    assert_eq!(t.trap, None);
                    assert_eq!(t.next_pc, Value::known(64, 0x1004));
                    for reg in 0..32 {
                        for chunk in 0..32 {
                            assert_eq!(
                                actual[reg][chunk], expected[reg][chunk],
                                "{word:08x} VL{vl} pattern{pattern} idx{index} Z{reg} chunk{chunk}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn inactive_predicates_suppress_fp_context_sources_and_fpsr_write() {
    for &(word, _, layout) in FORMS {
        if layout != 1 && layout != 3 {
            continue;
        }
        let s = State {
            z: [[0xdeadbeefcafebabe; 32]; 32],
            pred: [0; 4],
            sm: 0,
            sme2: false,
            fa64: false,
            inactive: true,
        };
        let r = recipe(word | 8 | (15 << 5) | (3 << 10), 512).unwrap();
        r.validate().unwrap();
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(t.trap, None);
        assert!(t.registers.iter().all(|v| v.register.bank == "a64.vector64"
            && v.register.index / 32 == 8
            && v.value.bits == 0xdeadbeefcafebabe));
    }
}
#[test]
fn streaming_requires_sme2_and_all_invalid_lengths_reject() {
    for &(word, _, _) in FORMS {
        let s = State {
            z: [[0; 32]; 32],
            pred: [0; 4],
            sm: 1,
            sme2: false,
            fa64: false,
            inactive: true,
        };
        assert_eq!(
            evaluate(&recipe(word, 128).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        );
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(word, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

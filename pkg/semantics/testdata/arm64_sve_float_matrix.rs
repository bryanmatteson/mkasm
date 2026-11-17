#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8, u8)] = &[
    (0x64e0e000, 0, 16), //bfmmla_z_zzz_h
    (0x6460e400, 1, 32), //bfmmla_z_zzz_
    (0x6420e400, 2, 32), //fmmla_z32_zzz_h
    (0x64a0e000, 3, 16), //fmmla_z_zzz_h
    (0x64a0e400, 3, 32), //fmmla_z_zzz_s
    (0x64e0e400, 3, 64), //fmmla_z_zzz_d
];
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn lane(z: &[[u64; 32]], n: u32, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    (z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
}
fn put(z: &mut [[u64; 32]], n: u32, e: u16, w: u8, v: u64) {
    let bit = e * u16::from(w);
    let x = &mut z[n as usize][usize::from(bit / 64)];
    let shift = bit % 64;
    *x = (*x & !(mask(w) << shift)) | (v << shift);
}
fn half_value(b: u32) -> f64 {
    let exp = (b >> 10) & 31;
    let frac = b & 1023;
    let value = if exp == 0 {
        f64::from(frac) * 2f64.powi(-24)
    } else {
        f64::from(1024 + frac) * 2f64.powi(exp as i32 - 25)
    };
    if b & 0x8000 != 0 {
        -value
    } else {
        value
    }
}
fn number(v: u64, w: u8, bf: bool) -> f64 {
    match w {
        16 if bf => f64::from(f32::from_bits((v as u32) << 16)),
        16 => half_value(v as u32),
        32 => f64::from(f32::from_bits(v as u32)),
        64 => f64::from_bits(v),
        _ => panic!(),
    }
}
fn rounded(v: f64, w: u8, bf: bool, half: &[f64]) -> u64 {
    match w {
        16 if bf => {
            let bits = (v as f32).to_bits();
            u64::from((bits.wrapping_add(0x7fff + ((bits >> 16) & 1))) >> 16)
        }
        16 => {
            let value = v.abs();
            let at = half.partition_point(|x| *x < value);
            let result = if at == 0 {
                0
            } else if at == half.len() {
                0x7c00
            } else {
                let lo = value - half[at - 1];
                let hi = half[at] - value;
                if lo < hi || lo == hi && (at - 1) & 1 == 0 {
                    at as u64 - 1
                } else {
                    at as u64
                }
            };
            result | if v.is_sign_negative() { 0x8000 } else { 0 }
        }
        32 => u64::from((v as f32).to_bits()),
        64 => v.to_bits(),
        _ => panic!(),
    }
}
fn data(kind: u8, w: u8) -> [[u64; 32]; 32] {
    let src = if kind == 1 || kind == 2 { 16 } else { w };
    let bf = kind <= 1;
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    let mut z = [[0; 32]; 32];
    for n in 0..32 {
        for e in 0..2048 / u16::from(src) {
            let value = f64::from(1 + (n + u32::from(e)) % 4);
            put(&mut z, n, e, src, rounded(value, src, bf, &half));
        }
    }
    z
}
fn operands(alias: u32) -> (u32, u32, u32) {
    let d = if alias == 0 { 30 } else { 31 };
    let n = if alias >= 2 { d } else { 29 };
    let m = if alias == 3 { n } else { 31 };
    (d, n, m)
}
fn expected(
    before: &[[u64; 32]; 32],
    kind: u8,
    w: u8,
    d: u32,
    n: u32,
    m: u32,
    vl: u16,
    half: &[f64],
) -> [[u64; 32]; 32] {
    let mut out = *before;
    let src = if kind == 1 || kind == 2 { 16 } else { w };
    let bf = kind <= 1;
    for e in 0..vl / u16::from(w) {
        let segment = e / 4 * if kind == 1 || kind == 2 { 8 } else { 4 };
        let stride = if kind == 1 || kind == 2 { 4 } else { 2 };
        let row = e % 4 / 2;
        let col = e % 2;
        let a = segment + row * stride;
        let b = segment + col * stride;
        let mut sum = lane(before, d, e, w);
        let mut products = [0; 2];
        for k in 0..2 {
            let product = if kind == 1 || kind == 2 {
                let x = number(lane(before, n, a + 2 * k, 16), 16, bf)
                    * number(lane(before, m, b + 2 * k, 16), 16, bf);
                let y = number(lane(before, n, a + 2 * k + 1, 16), 16, bf)
                    * number(lane(before, m, b + 2 * k + 1, 16), 16, bf);
                x + y
            } else {
                number(lane(before, n, a + k, src), src, bf)
                    * number(lane(before, m, b + k, src), src, bf)
            };
            if kind == 1 {
                sum = rounded(number(sum, 32, false) + product, 32, false, half);
            } else {
                products[k as usize] = rounded(product, w, bf, half);
            }
        }
        if kind != 1 {
            let product = rounded(
                number(products[0], w, bf) + number(products[1], w, bf),
                w,
                bf,
                half,
            );
            sum = rounded(number(sum, w, bf) + number(product, w, bf), w, bf, half);
        }
        put(&mut out, d, e, w, sum);
    }
    out
}
fn instruction(base: u32, d: u32, n: u32, m: u32) -> u32 {
    base | d | (n << 5) | (m << 16)
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sve_float_matrix::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    sm: bool,
    fa64: bool,
    kind: u8,
    half: Vec<f64>,
    fault: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => u64::from(self.sm),
                "a64.sme_fa64" => u64::from(self.fa64),
                "a64.fpcr" => 0x04009f00,
                "a64.fpsr" => {
                    assert_ne!(self.kind, 1, "BFDotAdd must not read FPSR");
                    0x08000000
                }
                _ => panic!("{r:?}"),
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
        assert_eq!(ctrl.bits, if self.kind == 1 { 0x04009f00 } else { 0x9f00 });
        if self.fault {
            let invalid = match f.operation {
                FloatOperation::HalfDotProduct => v[0].bits == 0x7c00 && v[2].bits == 0,
                FloatOperation::Multiply => {
                    v[0].bits
                        == match f.width {
                            16 => 0x7c00,
                            32 => 0x7f800000,
                            _ => 0x7ff0000000000000,
                        }
                        && v[1].bits == 0
                }
                FloatOperation::BFloatBinary {
                    operation: BFloatOperation::Multiply,
                } => v[0].bits == 0x7f80 && v[1].bits == 0,
                _ => false,
            };
            assert!(invalid, "FP work after first fault {f:?}");
            return Ok(match f.projection {
                FloatProjection::Value => Value::known(f.width, 0),
                FloatProjection::Status => Value::known(32, status.bits | 1),
                FloatProjection::Trapped => Value::known(1, 1),
            });
        }
        let bf = self.kind == 0;
        let bits = match f.operation {
            FloatOperation::BFloatDotAdd => {
                assert_eq!(f.projection, FloatProjection::Value);
                let product = number(v[1].bits, 16, true) * number(v[3].bits, 16, true)
                    + number(v[2].bits, 16, true) * number(v[4].bits, 16, true);
                rounded(
                    number(v[0].bits, 32, false) + product,
                    32,
                    false,
                    &self.half,
                )
            }
            FloatOperation::HalfDotProduct => rounded(
                number(v[0].bits, 16, false) * number(v[2].bits, 16, false)
                    + number(v[1].bits, 16, false) * number(v[3].bits, 16, false),
                32,
                false,
                &self.half,
            ),
            FloatOperation::Multiply
            | FloatOperation::BFloatBinary {
                operation: BFloatOperation::Multiply,
            } => rounded(
                number(v[0].bits, f.width, bf) * number(v[1].bits, f.width, bf),
                f.width,
                bf,
                &self.half,
            ),
            FloatOperation::Add
            | FloatOperation::BFloatBinary {
                operation: BFloatOperation::Add,
            } => rounded(
                number(v[0].bits, f.width, bf) + number(v[1].bits, f.width, bf),
                f.width,
                bf,
                &self.half,
            ),
            _ => panic!("{f:?}"),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, bits),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
#[test]
fn sve_float_matrix_all_segments_aliases_lengths_and_backing() {
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    for &(base, kind, w) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            if vl < 4 * u16::from(w) {
                continue;
            }
            for alias in 0..4 {
                let (d, n, m) = operands(alias);
                let word = instruction(base, d, n, m);
                let s = State {
                    z: data(kind, w),
                    sm: alias == 3,
                    fa64: alias == 3,
                    kind,
                    half: half.clone(),
                    fault: false,
                };
                let want = expected(&s.z, kind, w, d, n, m, vl, &half);
                let r = recipe(word, vl).unwrap();
                r.validate().unwrap();
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(t.trap, None);
                let mut out = s.z;
                for wr in t.registers {
                    match wr.register.bank {
                        "a64.vector64" => {
                            out[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits
                        }
                        "a64.fpsr" => {
                            assert_ne!(kind, 1);
                            assert_eq!(wr.value.bits, 0x08000000)
                        }
                        _ => panic!("{wr:?}"),
                    }
                }
                assert_eq!(out, want, "{word:08x} VL{vl} alias{alias}");
            }
        }
    }
}
#[test]
fn sve_float_matrix_first_exception_stops_later_operations_and_destination() {
    for &(base, kind, w) in FORMS {
        if kind == 1 {
            continue;
        }
        let mut s = State {
            z: data(kind, w),
            sm: false,
            fa64: false,
            kind,
            half: vec![],
            fault: true,
        };
        let src = if kind == 2 { 16 } else { w };
        let inf = if kind == 0 {
            0x7f80
        } else {
            match src {
                16 => 0x7c00,
                32 => 0x7f800000,
                _ => 0x7ff0000000000000,
            }
        };
        put(&mut s.z, 29, 0, src, inf);
        put(&mut s.z, 31, 0, src, 0);
        let t = evaluate(&recipe(instruction(base, 30, 29, 31), 2048).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
        assert!(t.registers.iter().all(|wr| wr.register.bank == "a64.fpsr"));
        assert_eq!(t.registers[0].value.bits, 0x08000001);
    }
}
#[test]
fn sve_float_matrix_context_and_reserved_lengths() {
    for &(base, kind, w) in FORMS {
        let s = State {
            z: [[0; 32]; 32],
            sm: true,
            fa64: false,
            kind,
            half: vec![],
            fault: true,
        };
        assert_eq!(
            evaluate(&recipe(base, 256).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        );
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(base, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if w == 64 {
            assert!(matches!(
                recipe(base, 128).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

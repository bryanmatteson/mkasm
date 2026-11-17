#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8)] = &[
    (0x0f409000, 0), // FDOT_asimdelem_FP16FP32
    (0x0e80fc00, 1), // FDOT_asimdsame2_FP16FP32
    (0x4ec0ec00, 2), // FMMLA_asimd_FP16FP16
    (0x4e40ec00, 3), // FMMLA_asimd_FP16FP32
];
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
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
fn half_value(b: u32) -> f64 {
    let ex = (b >> 10) & 31;
    let f = b & 1023;
    let v = if ex == 0 {
        f64::from(f) * 2f64.powi(-24)
    } else {
        f64::from(1024 + f) * 2f64.powi(ex as i32 - 25)
    };
    if b & 0x8000 != 0 {
        -v
    } else {
        v
    }
}
fn half_round(v: f64, table: &[f64]) -> u32 {
    let at = table.partition_point(|x| *x < v);
    if at == 0 {
        0
    } else if at == table.len() {
        0x7c00
    } else {
        let lo = v - table[at - 1];
        let hi = table[at] - v;
        if lo < hi || lo == hi && (at - 1) & 1 == 0 {
            at as u32 - 1
        } else {
            at as u32
        }
    }
}

fn number(v: u64, w: u8) -> f64 {
    if w == 16 {
        half_value(v as u32)
    } else {
        f64::from(f32::from_bits(v as u32))
    }
}
fn rounded(v: f64, w: u8, half: &[f64]) -> u64 {
    if w == 16 {
        u64::from(half_round(v.abs(), half)) | if v.is_sign_negative() { 0x8000 } else { 0 }
    } else {
        u64::from((v as f32).to_bits())
    }
}
fn data() -> [[u64; 32]; 32] {
    std::array::from_fn(|reg| {
        std::array::from_fn(|chunk| {
            let mut x = 0;
            for h in 0..4 {
                x |= [0x3c00u64, 0x4000, 0x4200, 0x4400][(reg + chunk + h) % 4] << (h * 16);
            }
            x
        })
    })
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
    d: u32,
    n: u32,
    m: u32,
    index: u16,
    size: u16,
    vl: u16,
    half: &[f64],
) -> [[u64; 32]; 32] {
    let mut out = *before;
    let w = if kind == 2 { 16 } else { 32 };
    for e in 0..size / u16::from(w) {
        let product = if kind <= 1 {
            let b = if kind == 0 { 2 * index } else { 2 * e };
            rounded(
                number(lane(before, n, 2 * e, 16), 16) * number(lane(before, m, b, 16), 16)
                    + number(lane(before, n, 2 * e + 1, 16), 16)
                        * number(lane(before, m, b + 1, 16), 16),
                32,
                half,
            )
        } else {
            let segment = if kind == 2 { e / 4 * 4 } else { 0 };
            let row = e % 4 / 2;
            let col = e % 2;
            let step = if kind == 2 { 2 } else { 4 };
            let a = segment + row * step;
            let b = segment + col * step;
            let mut products = [0; 2];
            for k in 0..2u16 {
                products[usize::from(k)] = if kind == 2 {
                    rounded(
                        number(lane(before, n, a + k, 16), 16)
                            * number(lane(before, m, b + k, 16), 16),
                        16,
                        half,
                    )
                } else {
                    rounded(
                        number(lane(before, n, a + 2 * k, 16), 16)
                            * number(lane(before, m, b + 2 * k, 16), 16)
                            + number(lane(before, n, a + 2 * k + 1, 16), 16)
                                * number(lane(before, m, b + 2 * k + 1, 16), 16),
                        32,
                        half,
                    )
                };
            }
            rounded(number(products[0], w) + number(products[1], w), w, half)
        };
        let value = rounded(
            number(lane(before, d, e, w), w) + number(product, w),
            w,
            half,
        );
        put(&mut out, d, e, w, value);
    }
    for chunk in size / 64..vl / 64 {
        out[d as usize][usize::from(chunk)] = 0;
    }
    out
}
fn instruction(base: u32, kind: u8, d: u32, n: u32, m: u32, index: u16, q: u32) -> u32 {
    base | d
        | (n << 5)
        | (m << 16)
        | if kind <= 1 { q << 30 } else { 0 }
        | if kind == 0 {
            (u32::from(index >> 1) << 11) | (u32::from(index & 1) << 21)
        } else {
            0
        }
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fixed_half_matrix::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    sm: bool,
    fa64: bool,
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
                "a64.fpsr" => 0x08000000,
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
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        assert_eq!(control, Value::known(32, 0x9f00));
        let invalid = self.fault
            && match f.operation {
                FloatOperation::HalfDotProduct => v[0].bits == 0x7c00 && v[2].bits == 0,
                FloatOperation::Multiply => v[0].bits == 0x7c00 && v[1].bits == 0,
                _ => false,
            };
        if invalid {
            return Ok(match f.projection {
                FloatProjection::Value => {
                    Value::known(f.width, if f.width == 16 { 0x7e00 } else { 0x7fc00000 })
                }
                FloatProjection::Status => Value::known(32, status.bits | 1),
                FloatProjection::Trapped => Value::known(1, 1),
            });
        }
        assert!(!self.fault, "operation after first enabled exception {f:?}");
        let result = match f.operation {
            FloatOperation::HalfDotProduct => {
                assert_eq!(v.iter().map(|v| v.width).collect::<Vec<_>>(), vec![16; 4]);
                rounded(
                    number(v[0].bits, 16) * number(v[2].bits, 16)
                        + number(v[1].bits, 16) * number(v[3].bits, 16),
                    32,
                    &self.half,
                )
            }
            FloatOperation::Add => rounded(
                number(v[0].bits, f.width) + number(v[1].bits, f.width),
                f.width,
                &self.half,
            ),
            FloatOperation::Multiply => rounded(
                number(v[0].bits, f.width) * number(v[1].bits, f.width),
                f.width,
                &self.half,
            ),
            _ => panic!("{f:?}"),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, result),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
#[test]
fn fixed_half_all_dot_matrix_layouts_indices_aliases_lengths_and_upper_storage() {
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    for &(base, kind) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for alias in 0..4 {
                for q in 0..if kind <= 1 { 2 } else { 1 } {
                    for index in 0..if kind == 0 { 4 } else { 1 } {
                        let (d, n, m) = operands(alias);
                        let word = instruction(base, kind, d, n, m, index, q);
                        let s = State {
                            z: data(),
                            sm: alias == 3,
                            fa64: alias == 3,
                            half: half.clone(),
                            fault: false,
                        };
                        let size = if kind <= 1 && q == 0 { 64 } else { 128 };
                        let want = expected(&s.z, kind, d, n, m, index, size, vl, &half);
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
                                "a64.fpsr" => assert_eq!(wr.value.bits, 0x08000000),
                                _ => panic!("{wr:?}"),
                            }
                        }
                        assert_eq!(out, want, "{word:08x} VL{vl}");
                    }
                }
            }
        }
    }
}
#[test]
fn fixed_half_first_exception_stops_fp_evaluation_and_all_vector_writes() {
    for &(base, kind) in FORMS {
        let mut s = State {
            z: data(),
            sm: false,
            fa64: false,
            half: vec![],
            fault: true,
        };
        put(&mut s.z, 29, 0, 16, 0x7c00);
        put(&mut s.z, 31, 0, 16, 0);
        let word = instruction(base, kind, 30, 29, 31, 0, 1);
        let t = evaluate(&recipe(word, 2048).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
        assert!(t.registers.iter().all(|wr| wr.register.bank == "a64.fpsr"));
        assert_eq!(t.registers[0].value.bits, 0x08000001);
    }
}
#[test]
fn fixed_half_contexts_and_reserved_lengths() {
    for &(base, _) in FORMS {
        let s = State {
            z: data(),
            sm: true,
            fa64: false,
            half: vec![],
            fault: true,
        };
        assert_eq!(
            evaluate(&recipe(base, 128).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        );
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(base, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

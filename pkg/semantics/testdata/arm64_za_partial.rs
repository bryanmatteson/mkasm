#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
const FORMS: &[(u32, u8, u8, u8, u8, bool, bool, bool, bool)] = &[
    (0x81100000, 32, 16, 2, 2, false, false, false, false), // bfmop4a_za32_zz_h1x2
    (0x81000000, 32, 16, 2, 2, false, false, false, false), // bfmop4a_za32_zz_h1x1
    (0x81000200, 32, 16, 2, 2, false, false, false, false), // bfmop4a_za32_zz_h2x1
    (0x81100200, 32, 16, 2, 2, false, false, false, false), // bfmop4a_za32_zz_h2x2
    (0x81300008, 16, 16, 1, 2, false, false, false, false), // bfmop4a_za_zz_h1x2
    (0x81200008, 16, 16, 1, 2, false, false, false, false), // bfmop4a_za_zz_h1x1
    (0x81200208, 16, 16, 1, 2, false, false, false, false), // bfmop4a_za_zz_h2x1
    (0x81300208, 16, 16, 1, 2, false, false, false, false), // bfmop4a_za_zz_h2x2
    (0x81100010, 32, 16, 2, 2, false, false, false, true),  // bfmop4s_za32_zz_h1x2
    (0x81000010, 32, 16, 2, 2, false, false, false, true),  // bfmop4s_za32_zz_h1x1
    (0x81000210, 32, 16, 2, 2, false, false, false, true),  // bfmop4s_za32_zz_h2x1
    (0x81100210, 32, 16, 2, 2, false, false, false, true),  // bfmop4s_za32_zz_h2x2
    (0x81300018, 16, 16, 1, 2, false, false, false, true),  // bfmop4s_za_zz_h1x2
    (0x81200018, 16, 16, 1, 2, false, false, false, true),  // bfmop4s_za_zz_h1x1
    (0x81200218, 16, 16, 1, 2, false, false, false, true),  // bfmop4s_za_zz_h2x1
    (0x81300218, 16, 16, 1, 2, false, false, false, true),  // bfmop4s_za_zz_h2x2
    (0x81400000, 32, 16, 2, 2, true, false, false, false),  // bftmopa_za32_zzzi_h2x1
    (0x81600008, 16, 16, 1, 2, true, false, false, false),  // bftmopa_za_zzzi_h2x1
    (0x81300000, 32, 16, 2, 1, false, false, false, false), // fmop4a_za32_zz_h1x2
    (0x81200000, 32, 16, 2, 1, false, false, false, false), // fmop4a_za32_zz_h1x1
    (0x81200200, 32, 16, 2, 1, false, false, false, false), // fmop4a_za32_zz_h2x1
    (0x81300200, 32, 16, 2, 1, false, false, false, false), // fmop4a_za32_zz_h2x2
    (0x81100008, 16, 16, 1, 1, false, false, false, false), // fmop4a_za_zz_h1x2
    (0x81000008, 16, 16, 1, 1, false, false, false, false), // fmop4a_za_zz_h1x1
    (0x81000208, 16, 16, 1, 1, false, false, false, false), // fmop4a_za_zz_h2x1
    (0x81100208, 16, 16, 1, 1, false, false, false, false), // fmop4a_za_zz_h2x2
    (0x80100000, 32, 32, 1, 1, false, false, false, false), // fmop4a_za_zz_s1x2
    (0x80000000, 32, 32, 1, 1, false, false, false, false), // fmop4a_za_zz_s1x1
    (0x80000200, 32, 32, 1, 1, false, false, false, false), // fmop4a_za_zz_s2x1
    (0x80100200, 32, 32, 1, 1, false, false, false, false), // fmop4a_za_zz_s2x2
    (0x80d00008, 64, 64, 1, 1, false, false, false, false), // fmop4a_za_zz_d1x2
    (0x80c00008, 64, 64, 1, 1, false, false, false, false), // fmop4a_za_zz_d1x1
    (0x80c00208, 64, 64, 1, 1, false, false, false, false), // fmop4a_za_zz_d2x1
    (0x80d00208, 64, 64, 1, 1, false, false, false, false), // fmop4a_za_zz_d2x2
    (0x81300010, 32, 16, 2, 1, false, false, false, true),  // fmop4s_za32_zz_h1x2
    (0x81200010, 32, 16, 2, 1, false, false, false, true),  // fmop4s_za32_zz_h1x1
    (0x81200210, 32, 16, 2, 1, false, false, false, true),  // fmop4s_za32_zz_h2x1
    (0x81300210, 32, 16, 2, 1, false, false, false, true),  // fmop4s_za32_zz_h2x2
    (0x81100018, 16, 16, 1, 1, false, false, false, true),  // fmop4s_za_zz_h1x2
    (0x81000018, 16, 16, 1, 1, false, false, false, true),  // fmop4s_za_zz_h1x1
    (0x81000218, 16, 16, 1, 1, false, false, false, true),  // fmop4s_za_zz_h2x1
    (0x81100218, 16, 16, 1, 1, false, false, false, true),  // fmop4s_za_zz_h2x2
    (0x80100010, 32, 32, 1, 1, false, false, false, true),  // fmop4s_za_zz_s1x2
    (0x80000010, 32, 32, 1, 1, false, false, false, true),  // fmop4s_za_zz_s1x1
    (0x80000210, 32, 32, 1, 1, false, false, false, true),  // fmop4s_za_zz_s2x1
    (0x80100210, 32, 32, 1, 1, false, false, false, true),  // fmop4s_za_zz_s2x2
    (0x80d00018, 64, 64, 1, 1, false, false, false, true),  // fmop4s_za_zz_d1x2
    (0x80c00018, 64, 64, 1, 1, false, false, false, true),  // fmop4s_za_zz_d1x1
    (0x80c00218, 64, 64, 1, 1, false, false, false, true),  // fmop4s_za_zz_d2x1
    (0x80d00218, 64, 64, 1, 1, false, false, false, true),  // fmop4s_za_zz_d2x2
    (0x81600000, 32, 16, 2, 1, true, false, false, false),  // ftmopa_za32_zzzi_h2x1
    (0x81400008, 16, 16, 1, 1, true, false, false, false),  // ftmopa_za_zzzi_h2x1
    (0x80400000, 32, 32, 1, 1, true, false, false, false),  // ftmopa_za_zzzi_s2x1
    (0x80108008, 32, 16, 2, 0, false, false, false, false), // smop4a_za32_zz_h1x2
    (0x80008008, 32, 16, 2, 0, false, false, false, false), // smop4a_za32_zz_h1x1
    (0x80008208, 32, 16, 2, 0, false, false, false, false), // smop4a_za32_zz_h2x1
    (0x80108208, 32, 16, 2, 0, false, false, false, false), // smop4a_za32_zz_h2x2
    (0x80108000, 32, 8, 4, 0, false, false, false, false),  // smop4a_za_zz_b1x2
    (0x80008000, 32, 8, 4, 0, false, false, false, false),  // smop4a_za_zz_b1x1
    (0x80008200, 32, 8, 4, 0, false, false, false, false),  // smop4a_za_zz_b2x1
    (0x80108200, 32, 8, 4, 0, false, false, false, false),  // smop4a_za_zz_b2x2
    (0xa0d00008, 64, 16, 4, 0, false, false, false, false), // smop4a_za_zz_h1x2
    (0xa0c00008, 64, 16, 4, 0, false, false, false, false), // smop4a_za_zz_h1x1
    (0xa0c00208, 64, 16, 4, 0, false, false, false, false), // smop4a_za_zz_h2x1
    (0xa0d00208, 64, 16, 4, 0, false, false, false, false), // smop4a_za_zz_h2x2
    (0x80108018, 32, 16, 2, 0, false, false, false, true),  // smop4s_za32_zz_h1x2
    (0x80008018, 32, 16, 2, 0, false, false, false, true),  // smop4s_za32_zz_h1x1
    (0x80008218, 32, 16, 2, 0, false, false, false, true),  // smop4s_za32_zz_h2x1
    (0x80108218, 32, 16, 2, 0, false, false, false, true),  // smop4s_za32_zz_h2x2
    (0x80108010, 32, 8, 4, 0, false, false, false, true),   // smop4s_za_zz_b1x2
    (0x80008010, 32, 8, 4, 0, false, false, false, true),   // smop4s_za_zz_b1x1
    (0x80008210, 32, 8, 4, 0, false, false, false, true),   // smop4s_za_zz_b2x1
    (0x80108210, 32, 8, 4, 0, false, false, false, true),   // smop4s_za_zz_b2x2
    (0xa0d00018, 64, 16, 4, 0, false, false, false, true),  // smop4s_za_zz_h1x2
    (0xa0c00018, 64, 16, 4, 0, false, false, false, true),  // smop4s_za_zz_h1x1
    (0xa0c00218, 64, 16, 4, 0, false, false, false, true),  // smop4s_za_zz_h2x1
    (0xa0d00218, 64, 16, 4, 0, false, false, false, true),  // smop4s_za_zz_h2x2
    (0x80408008, 32, 16, 2, 0, true, false, false, false),  // stmopa_za32_zzzi_h2x1
    (0x80408000, 32, 8, 4, 0, true, false, false, false),   // stmopa_za_zzzi_b2x1
    (0x80308000, 32, 8, 4, 0, false, false, true, false),   // sumop4a_za_zz_b1x2
    (0x80208000, 32, 8, 4, 0, false, false, true, false),   // sumop4a_za_zz_b1x1
    (0x80208200, 32, 8, 4, 0, false, false, true, false),   // sumop4a_za_zz_b2x1
    (0x80308200, 32, 8, 4, 0, false, false, true, false),   // sumop4a_za_zz_b2x2
    (0xa0f00008, 64, 16, 4, 0, false, false, true, false),  // sumop4a_za_zz_h1x2
    (0xa0e00008, 64, 16, 4, 0, false, false, true, false),  // sumop4a_za_zz_h1x1
    (0xa0e00208, 64, 16, 4, 0, false, false, true, false),  // sumop4a_za_zz_h2x1
    (0xa0f00208, 64, 16, 4, 0, false, false, true, false),  // sumop4a_za_zz_h2x2
    (0x80308010, 32, 8, 4, 0, false, false, true, true),    // sumop4s_za_zz_b1x2
    (0x80208010, 32, 8, 4, 0, false, false, true, true),    // sumop4s_za_zz_b1x1
    (0x80208210, 32, 8, 4, 0, false, false, true, true),    // sumop4s_za_zz_b2x1
    (0x80308210, 32, 8, 4, 0, false, false, true, true),    // sumop4s_za_zz_b2x2
    (0xa0f00018, 64, 16, 4, 0, false, false, true, true),   // sumop4s_za_zz_h1x2
    (0xa0e00018, 64, 16, 4, 0, false, false, true, true),   // sumop4s_za_zz_h1x1
    (0xa0e00218, 64, 16, 4, 0, false, false, true, true),   // sumop4s_za_zz_h2x1
    (0xa0f00218, 64, 16, 4, 0, false, false, true, true),   // sumop4s_za_zz_h2x2
    (0x80608000, 32, 8, 4, 0, true, false, true, false),    // sutmopa_za_zzzi_b2x1
    (0x81108008, 32, 16, 2, 0, false, true, true, false),   // umop4a_za32_zz_h1x2
    (0x81008008, 32, 16, 2, 0, false, true, true, false),   // umop4a_za32_zz_h1x1
    (0x81008208, 32, 16, 2, 0, false, true, true, false),   // umop4a_za32_zz_h2x1
    (0x81108208, 32, 16, 2, 0, false, true, true, false),   // umop4a_za32_zz_h2x2
    (0x81308000, 32, 8, 4, 0, false, true, true, false),    // umop4a_za_zz_b1x2
    (0x81208000, 32, 8, 4, 0, false, true, true, false),    // umop4a_za_zz_b1x1
    (0x81208200, 32, 8, 4, 0, false, true, true, false),    // umop4a_za_zz_b2x1
    (0x81308200, 32, 8, 4, 0, false, true, true, false),    // umop4a_za_zz_b2x2
    (0xa1f00008, 64, 16, 4, 0, false, true, true, false),   // umop4a_za_zz_h1x2
    (0xa1e00008, 64, 16, 4, 0, false, true, true, false),   // umop4a_za_zz_h1x1
    (0xa1e00208, 64, 16, 4, 0, false, true, true, false),   // umop4a_za_zz_h2x1
    (0xa1f00208, 64, 16, 4, 0, false, true, true, false),   // umop4a_za_zz_h2x2
    (0x81108018, 32, 16, 2, 0, false, true, true, true),    // umop4s_za32_zz_h1x2
    (0x81008018, 32, 16, 2, 0, false, true, true, true),    // umop4s_za32_zz_h1x1
    (0x81008218, 32, 16, 2, 0, false, true, true, true),    // umop4s_za32_zz_h2x1
    (0x81108218, 32, 16, 2, 0, false, true, true, true),    // umop4s_za32_zz_h2x2
    (0x81308010, 32, 8, 4, 0, false, true, true, true),     // umop4s_za_zz_b1x2
    (0x81208010, 32, 8, 4, 0, false, true, true, true),     // umop4s_za_zz_b1x1
    (0x81208210, 32, 8, 4, 0, false, true, true, true),     // umop4s_za_zz_b2x1
    (0x81308210, 32, 8, 4, 0, false, true, true, true),     // umop4s_za_zz_b2x2
    (0xa1f00018, 64, 16, 4, 0, false, true, true, true),    // umop4s_za_zz_h1x2
    (0xa1e00018, 64, 16, 4, 0, false, true, true, true),    // umop4s_za_zz_h1x1
    (0xa1e00218, 64, 16, 4, 0, false, true, true, true),    // umop4s_za_zz_h2x1
    (0xa1f00218, 64, 16, 4, 0, false, true, true, true),    // umop4s_za_zz_h2x2
    (0x81108000, 32, 8, 4, 0, false, true, false, false),   // usmop4a_za_zz_b1x2
    (0x81008000, 32, 8, 4, 0, false, true, false, false),   // usmop4a_za_zz_b1x1
    (0x81008200, 32, 8, 4, 0, false, true, false, false),   // usmop4a_za_zz_b2x1
    (0x81108200, 32, 8, 4, 0, false, true, false, false),   // usmop4a_za_zz_b2x2
    (0xa1d00008, 64, 16, 4, 0, false, true, false, false),  // usmop4a_za_zz_h1x2
    (0xa1c00008, 64, 16, 4, 0, false, true, false, false),  // usmop4a_za_zz_h1x1
    (0xa1c00208, 64, 16, 4, 0, false, true, false, false),  // usmop4a_za_zz_h2x1
    (0xa1d00208, 64, 16, 4, 0, false, true, false, false),  // usmop4a_za_zz_h2x2
    (0x81108010, 32, 8, 4, 0, false, true, false, true),    // usmop4s_za_zz_b1x2
    (0x81008010, 32, 8, 4, 0, false, true, false, true),    // usmop4s_za_zz_b1x1
    (0x81008210, 32, 8, 4, 0, false, true, false, true),    // usmop4s_za_zz_b2x1
    (0x81108210, 32, 8, 4, 0, false, true, false, true),    // usmop4s_za_zz_b2x2
    (0xa1d00018, 64, 16, 4, 0, false, true, false, true),   // usmop4s_za_zz_h1x2
    (0xa1c00018, 64, 16, 4, 0, false, true, false, true),   // usmop4s_za_zz_h1x1
    (0xa1c00218, 64, 16, 4, 0, false, true, false, true),   // usmop4s_za_zz_h2x1
    (0xa1d00218, 64, 16, 4, 0, false, true, false, true),   // usmop4s_za_zz_h2x2
    (0x81408000, 32, 8, 4, 0, true, true, false, false),    // ustmopa_za_zzzi_b2x1
    (0x81408008, 32, 16, 2, 0, true, true, true, false),    // utmopa_za32_zzzi_h2x1
    (0x81608000, 32, 8, 4, 0, true, true, true, false),     // utmopa_za_zzzi_b2x1
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_partial::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    sm: u64,
    fp: bool,
    calls: Vec<(u8, u8, u8, Vec<u64>)>,
    at: Cell<usize>,
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn marker(i: usize, w: u8) -> u64 {
    0xeb451fcd726398a0u64.wrapping_mul(i as u64 + 1) & mask(w)
}
fn lane(z: &[[u64; 32]], reg: u32, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    (z[reg as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
}
fn signed(x: u64, w: u8, u: bool) -> i128 {
    if u {
        i128::from(x)
    } else {
        let shift = 128 - u32::from(w);
        ((i128::from(x)) << shift) >> shift
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.svcr" => self.sm,
                "a64.fpcr" => {
                    assert!(self.fp, "integer operation consumed FP controls");
                    0x07c09f03
                }
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.za64" => self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                _ => panic!("unexpected read {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        inputs: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = self.at.get();
        let (kind, w, ways, ref args) = self.calls[i];
        let sw = if ways == 2 { 16 } else { w };
        assert_eq!(
            f.operation,
            if ways == 2 {
                if kind == 2 {
                    FloatOperation::BFloatDotAdd
                } else {
                    FloatOperation::ZaHalfDot
                }
            } else {
                FloatOperation::ZaFused { bfloat: kind == 2 }
            }
        );
        assert_eq!(f.width, w);
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        let expected = args
            .iter()
            .enumerate()
            .map(|(at, bits)| Value::known(if at == 0 { w } else { sw }, *bits))
            .collect::<Vec<_>>();
        assert_eq!(inputs, expected);
        assert_eq!(control, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        self.at.set(i + 1);
        Ok(Value::known(w, marker(i, w)))
    }
}
#[test]
fn all_partial_selective_classes_lengths_tiles_quadrants_indices_aliases_and_backing() {
    for &(base, w, sw, ways, kind, selective, u1, u2, subtract) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for pattern in 0..3u32 {
                for index in 0..if selective { 4 } else { 1 } {
                    let tile = if pattern == 0 {
                        0
                    } else {
                        u32::from(w / 8 - 1)
                    };
                    let (n, m, k) = if selective {
                        if pattern == 0 {
                            (0, 31, 20)
                        } else if pattern == 1 {
                            (20, 20, 20)
                        } else {
                            (28, 31, 31)
                        }
                    } else {
                        if pattern == 0 {
                            (0, 16, 20)
                        } else {
                            (14, 30, 20)
                        }
                    };
                    let word = base
                        | (n << 5)
                        | (m << 16)
                        | tile
                        | if selective {
                            ((k - 20) / 8 << 12) | ((k & 3) << 10) | (index << 4)
                        } else {
                            0
                        };
                    let mut s = State {
                        z: std::array::from_fn(|n| {
                            std::array::from_fn(|c| {
                                0x97e1236bc5af8d40u64.wrapping_mul((n * 32 + c + 1) as u64)
                            })
                        }),
                        za: (0..256)
                            .map(|r| {
                                std::array::from_fn(|c| {
                                    0xc85912e73a6dfb04u64.wrapping_mul((r * 32 + c + 1) as u64)
                                })
                            })
                            .collect(),
                        sm: 3,
                        fp: kind != 0,
                        calls: vec![],
                        at: Cell::new(0),
                    };
                    if selective {
                        for c in 0..32 {
                            s.z[k as usize][c] = if pattern == 0 {
                                0
                            } else if pattern == 1 {
                                u64::MAX
                            } else {
                                0x9e653c47a1d82bf0u64.rotate_left(c as u32)
                            };
                        }
                    }
                    let dim = vl / u16::from(w);
                    let count = u16::from(ways);
                    let csize = dim * count * 2;
                    let mut expected = s.za.clone();
                    for row in 0..dim {
                        let physical = usize::from(row * u16::from(w) / 8 + tile as u16);
                        for col in 0..dim {
                            let chunk = usize::from(col * u16::from(w) / 64);
                            let shift = col * u16::from(w) % 64;
                            let old = (s.za[physical][chunk] >> shift) & mask(w);
                            let nr = n + if selective {
                                0
                            } else {
                                ((word >> 9) & 1) * u32::from(col / (dim / 2))
                            };
                            let mr = m + if selective {
                                0
                            } else {
                                ((word >> 20) & 1) * u32::from(row / (dim / 2))
                            };
                            let left = if selective {
                                let mut chosen = vec![];
                                if ways == 4 {
                                    for reg in 0..2u16 {
                                        let mut group = vec![];
                                        for e in 0..count {
                                            let bit = index as u16 * csize
                                                + col * count * 2
                                                + reg * count
                                                + e;
                                            if group.len() < 2
                                                && s.z[k as usize][usize::from(bit / 64)]
                                                    >> (bit % 64)
                                                    & 1
                                                    != 0
                                            {
                                                group.push(lane(
                                                    &s.z,
                                                    n + u32::from(reg),
                                                    row * count + e,
                                                    sw,
                                                ));
                                            }
                                        }
                                        group.resize(2, 0);
                                        chosen.extend(group);
                                    }
                                } else {
                                    for reg in 0..2u16 {
                                        for e in 0..count {
                                            let bit = index as u16 * csize
                                                + col * count * 2
                                                + reg * count
                                                + e;
                                            if chosen.len() < usize::from(ways)
                                                && s.z[k as usize][usize::from(bit / 64)]
                                                    >> (bit % 64)
                                                    & 1
                                                    != 0
                                            {
                                                chosen.push(lane(
                                                    &s.z,
                                                    n + u32::from(reg),
                                                    row * count + e,
                                                    sw,
                                                ));
                                            }
                                        }
                                    }
                                    chosen.resize(usize::from(ways), 0);
                                }
                                chosen
                            } else {
                                (0..count)
                                    .map(|i| lane(&s.z, nr, row * count + i, sw))
                                    .collect::<Vec<_>>()
                            };
                            let right = (0..count)
                                .map(|i| lane(&s.z, mr, col * count + i, sw))
                                .collect::<Vec<_>>();
                            let value = if kind == 0 {
                                let mut sum = old;
                                for j in 0..usize::from(ways) {
                                    let product =
                                        (signed(left[j], sw, u1) * signed(right[j], sw, u2)) as u64;
                                    sum = if subtract {
                                        sum.wrapping_sub(product)
                                    } else {
                                        sum.wrapping_add(product)
                                    };
                                }
                                sum & mask(w)
                            } else {
                                let mut args = vec![old];
                                args.extend(
                                    left.into_iter()
                                        .map(|a| a ^ if subtract { 1u64 << (sw - 1) } else { 0 }),
                                );
                                args.extend(right);
                                let i = s.calls.len();
                                s.calls.push((kind, w, ways, args));
                                marker(i, w)
                            };
                            expected[physical][chunk] = (expected[physical][chunk]
                                & !(mask(w) << shift))
                                | (value << shift);
                        }
                    }
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    assert_eq!(s.at.get(), s.calls.len());
                    let mut actual = s.za.clone();
                    for out in t.registers {
                        assert_eq!(out.register.bank, "a64.za64");
                        assert!(out.value.is_known());
                        actual[usize::from(out.register.index / 32)]
                            [usize::from(out.register.index % 32)] = out.value.bits;
                    }
                    assert_eq!(actual, expected, "{word:08x} VL{vl} pattern{pattern}");
                    assert_eq!(t.next_pc, Value::known(64, 0x1004));
                    assert_eq!(t.trap, None);
                    assert!(t.memory.is_empty() && t.atomics.is_empty());
                }
            }
        }
    }
}
#[test]
fn all_partial_selective_mode_guards_precede_operands() {
    for &(word, _, _, _, _, _, _, _, _) in FORMS {
        for sm in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                sm,
                fp: false,
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

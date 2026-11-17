#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8, bool, bool, u16)] = &[
    (0x0f400000, 16, true, true, 0),   // FDOT_asimdelem_G
    (0x0e40fc00, 16, true, false, 0),  // FDOT_asimdsame2_D
    (0x0f000000, 32, true, true, 0),   // FDOT_asimdelem_D
    (0x0e00fc00, 32, true, false, 0),  // FDOT_asimdsame2_DD
    (0x0fc00000, 16, false, true, 0),  // FMLALB_asimdelem_H
    (0x4fc00000, 16, false, true, 1),  // FMLALT_asimdelem_H
    (0x0ec0fc00, 16, false, false, 0), // FMLALB_asimdsame2_J
    (0x4ec0fc00, 16, false, false, 1), // FMLALT_asimdsame2_J
    (0x2f008000, 32, false, true, 0),  // FMLALLBB_asimdelem_J
    (0x2f408000, 32, false, true, 1),  // FMLALLBT_asimdelem_J
    (0x6f008000, 32, false, true, 2),  // FMLALLTB_asimdelem_J
    (0x6f408000, 32, false, true, 3),  // FMLALLTT_asimdelem_J
    (0x0e00c400, 32, false, false, 0), // FMLALLBB_asimdsame2_G
    (0x0e40c400, 32, false, false, 1), // FMLALLBT_asimdsame2_G
    (0x4e00c400, 32, false, false, 2), // FMLALLTB_asimdsame2_G
    (0x4e40c400, 32, false, false, 3), // FMLALLTT_asimdsame2_G
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

fn index_count(dot: bool, w: u8, indexed: bool) -> u16 {
    if !indexed {
        1
    } else if !dot {
        16
    } else {
        128 / u16::from(w)
    }
}
fn word(base: u32, w: u8, dot: bool, indexed: bool, n: u32, m: u32, d: u32, i: u16, q: u32) -> u32 {
    let mut x = base | (n << 5) | (m << 16) | d;
    if dot {
        x |= q << 30;
    }
    if indexed {
        let i = u32::from(i);
        x |= if !dot {
            ((i >> 3) << 11) | (((i >> 2) & 1) << 21) | (((i >> 1) & 1) << 20) | ((i & 1) << 19)
        } else if w == 16 {
            ((i >> 2) << 11) | (((i >> 1) & 1) << 21) | ((i & 1) << 20)
        } else {
            ((i >> 1) << 11) | ((i & 1) << 21)
        };
    }
    x
}
fn operands(indexed: bool, dot: bool, w: u8, alias: u32) -> (u32, u32, u32) {
    let m = if indexed && !dot {
        7
    } else if indexed && w == 16 {
        15
    } else {
        31
    };
    let d = if alias == 1 || alias == 3 { m } else { 30 };
    let n = if alias >= 2 { d } else { 29 };
    (d, n, m)
}
fn data(d: u32, w: u8, alias: u32) -> [[u64; 32]; 32] {
    let mut z = std::array::from_fn(|reg| {
        std::array::from_fn(|chunk| {
            let mut x = 0;
            for byte in 0..8 {
                x |= [0x30u64, 0x38, 0x40, 0x48][(reg + chunk * 3 + byte) % 4] << (byte * 8);
            }
            x
        })
    });
    if alias == 0 {
        for e in 0..128 / u16::from(w) {
            put(&mut z, d, e, w, if w == 16 { 0x3e00 } else { 0x3fc00000 });
        }
    }
    z
}
fn fp8(x: u64, kind: u64) -> f64 {
    let (f, bias) = if kind == 1 { (3, 7) } else { (2, 15) };
    let exp = (x & 127) >> f;
    let frac = x & ((1 << f) - 1);
    let v = if exp == 0 {
        frac as f64 * 2f64.powi(1 - bias - f)
    } else {
        ((1 << f) + frac) as f64 * 2f64.powi(exp as i32 - bias - f)
    };
    if x & 128 != 0 {
        -v
    } else {
        v
    }
}
fn result(acc: u64, a: u64, b: u64, w: u8, dot: bool, fpmr: u64, half: &[f64]) -> u64 {
    let mut product = 0.;
    for k in 0..if dot { w / 8 } else { 1 } {
        product += fp8((a >> (k * 8)) & 255, fpmr & 7) * fp8((b >> (k * 8)) & 255, (fpmr >> 3) & 7);
    }
    let value = if w == 16 {
        half_value(acc as u32)
    } else {
        f64::from(f32::from_bits(acc as u32))
    } + product * 2f64.powi(-(((fpmr >> 16) & if w == 16 { 15 } else { 63 }) as i32));
    if w == 16 {
        u64::from(half_round(value.abs(), half)) | if value.is_sign_negative() { 0x8000 } else { 0 }
    } else {
        u64::from((value as f32).to_bits())
    }
}
fn expected(
    before: &[[u64; 32]; 32],
    d: u32,
    n: u32,
    m: u32,
    w: u8,
    dot: bool,
    indexed: bool,
    sel: u16,
    i: u16,
    datasize: u16,
    vl: u16,
    fpmr: u64,
    half: &[f64],
) -> [[u64; 32]; 32] {
    let mut out = *before;
    for e in 0..datasize / u16::from(w) {
        let sw = if dot { w } else { 8 };
        let ai = if dot { e } else { e * u16::from(w / 8) + sel };
        let bi = if indexed { i } else { ai };
        put(
            &mut out,
            d,
            e,
            w,
            result(
                lane(before, d, e, w),
                lane(before, n, ai, sw),
                lane(before, m, bi, sw),
                w,
                dot,
                fpmr,
                half,
            ),
        );
    }
    for chunk in datasize / 64..vl / 64 {
        out[d as usize][usize::from(chunk)] = 0;
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fixed_fp8::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    fpmr: u64,
    sm: bool,
    fa64: bool,
    half: Vec<f64>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => u64::from(self.sm),
                "a64.sme_fa64" => u64::from(self.fa64),
                "a64.fpcr" => 0x07c09f03,
                "a64.fpmr" => self.fpmr,
                _ => panic!("unexpected state access {r:?}"),
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
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(control, Value::known(32, 0x07c09f03));
        assert_eq!(status, Value::known(32, 0));
        let dot = match f.operation {
            FloatOperation::Fp8WideningFused => false,
            FloatOperation::Fp8Dot { ways } => {
                assert_eq!(ways, f.width / 8);
                true
            }
            _ => panic!("{f:?}"),
        };
        assert_eq!(v[0].width, f.width);
        assert_eq!(v[1].width, if dot { f.width } else { 8 });
        assert_eq!(v[1].width, v[2].width);
        assert_eq!(v[3], Value::known(64, self.fpmr));
        Ok(Value::known(
            f.width,
            result(
                v[0].bits, v[1].bits, v[2].bits, f.width, dot, self.fpmr, &self.half,
            ),
        ))
    }
}
#[test]
fn fixed_fp8_all_forms_formats_scales_indices_aliases_lengths_and_backing() {
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    for &(base, w, dot, indexed, sel) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for alias in 0..4 {
                let (d, n, m) = operands(indexed, dot, w, alias);
                for q in 0..if dot { 2 } else { 1 } {
                    for i in 0..index_count(dot, w, indexed) {
                        let fpmr = u64::from(alias & 1)
                            | u64::from(alias >> 1) << 3
                            | ([0u64, 3, 15, 63][alias as usize] << 16);
                        let s = State {
                            z: data(d, w, alias),
                            fpmr,
                            sm: alias == 3,
                            fa64: alias == 3,
                            half: half.clone(),
                        };
                        let instruction = word(base, w, dot, indexed, n, m, d, i, q);
                        let size = if dot && q == 0 { 64 } else { 128 };
                        let want = expected(
                            &s.z, d, n, m, w, dot, indexed, sel, i, size, vl, fpmr, &half,
                        );
                        let r = recipe(instruction, vl).unwrap();
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert_eq!(t.trap, None);
                        let mut out = s.z;
                        for wr in t.registers {
                            assert_eq!(wr.register.bank, "a64.vector64");
                            out[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits;
                        }
                        assert_eq!(out, want, "{instruction:08x} VL{vl} index{i} alias{alias}");
                    }
                }
            }
        }
    }
}
#[test]
fn fixed_fp8_context_guards_precede_operand_and_fp_state_access() {
    let s = State {
        z: [[0; 32]; 32],
        fpmr: 0,
        sm: true,
        fa64: false,
        half: vec![],
    };
    for &(base, _, _, _, _) in FORMS {
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

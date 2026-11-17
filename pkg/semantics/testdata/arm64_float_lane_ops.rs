#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8)] = &[
    (0x65088000, 0), //fabd_z_p_zz_
    (0x64208000, 1), //fdot_z_zzz_
    (0x64204000, 2), //fdot_z_zzzi_
    (0x2ec03c00, 8), //FSCALE_asimdsamefp16_only
    (0x2ea0fc00, 7), //FSCALE_asimdsame_only
    (0x650c3800, 4), //scvtflt_z_z_
    (0x650c3000, 3), //scvtf_z_z_
    (0x650c3c00, 6), //ucvtflt_z_z_
    (0x650c3400, 5), //ucvtf_z_z_
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

fn signed(x: u64, w: u8) -> i64 {
    if w == 64 {
        x as i64
    } else {
        ((x << (64 - w)) as i64) >> (64 - w)
    }
}
fn data(kind: u8, w: u8) -> [[u64; 32]; 32] {
    let sw = if kind == 1 || kind == 2 {
        16
    } else if kind <= 6 && kind >= 3 {
        w / 2
    } else {
        w
    };
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    let mut z = [[0; 32]; 32];
    for n in 0..32 {
        for e in 0..2048 / u16::from(sw) {
            let x = if kind >= 3 && kind <= 6 {
                [0, 1, mask(sw), 1u64 << (sw - 1), (1u64 << (sw - 1)) - 1]
                    [(n as usize + e as usize) % 5]
            } else {
                rounded(f64::from(1 + (n + u32::from(e)) % 4), sw, false, &half)
            };
            put(&mut z, n, e, sw, x);
        }
    }
    z
}
fn operands(alias: u32, kind: u8) -> (u32, u32, u32) {
    let d = if kind == 2 { 6 } else { 30 };
    let n = if alias & 1 != 0 { d } else { 29 };
    let m = if kind == 2 {
        if alias & 2 != 0 {
            d
        } else {
            7
        }
    } else {
        if alias & 2 != 0 {
            d
        } else {
            31
        }
    };
    (d, n, m)
}
fn instruction(base: u32, kind: u8, w: u8, q: bool, index: u16, d: u32, n: u32, m: u32) -> u32 {
    base | d
        | (if kind == 0 { m } else { n } << 5)
        | if kind == 1 || kind == 2 || kind >= 7 {
            m << 16
        } else {
            0
        }
        | if kind == 2 { u32::from(index) << 19 } else { 0 }
        | if kind == 0 || kind >= 3 && kind <= 6 {
            u32::from(w.trailing_zeros() - 3) << 22
        } else {
            0
        }
        | if kind == 7 && w == 64 { 1 << 22 } else { 0 }
        | if kind >= 7 && q { 1 << 30 } else { 0 }
}
fn expected(
    before: &[[u64; 32]; 32],
    kind: u8,
    w: u8,
    d: u32,
    n: u32,
    m: u32,
    index: u16,
    q: bool,
    vl: u16,
    pattern: u8,
    half: &[f64],
) -> [[u64; 32]; 32] {
    let mut out = *before;
    let count = if kind >= 7 {
        if q {
            128
        } else {
            64
        }
    } else {
        vl
    };
    for e in 0..count / u16::from(w) {
        let enabled = kind != 0 || pattern == 2 || pattern == 1 && e % 2 == 0;
        let result = if !enabled {
            lane(before, d, e, w)
        } else if kind == 0 {
            rounded(
                (number(lane(before, d, e, w), w, false) - number(lane(before, m, e, w), w, false))
                    .abs(),
                w,
                false,
                half,
            )
        } else if kind == 1 || kind == 2 {
            let ix = if kind == 2 { e / 4 * 4 + index } else { e };
            let p = rounded(
                number(lane(before, n, 2 * e, 16), 16, false)
                    * number(lane(before, m, 2 * ix, 16), 16, false)
                    + number(lane(before, n, 2 * e + 1, 16), 16, false)
                        * number(lane(before, m, 2 * ix + 1, 16), 16, false),
                32,
                false,
                half,
            );
            rounded(
                number(lane(before, d, e, 32), 32, false) + number(p, 32, false),
                32,
                false,
                half,
            )
        } else if kind <= 6 {
            let x = lane(before, n, 2 * e + u16::from(kind == 4 || kind == 6), w / 2);
            let value = if kind == 3 || kind == 4 {
                signed(x, w / 2) as f64
            } else {
                x as f64
            };
            rounded(value, w, false, half)
        } else {
            let exp = signed(lane(before, m, e, w), w) as i32;
            rounded(
                number(lane(before, n, e, w), w, false) * 2f64.powi(exp),
                w,
                false,
                half,
            )
        };
        put(&mut out, d, e, w, result);
    }
    for chunk in count / 64..vl / 64 {
        out[d as usize][usize::from(chunk)] = 0;
    }
    out
}
fn lengths(kind: u8) -> Vec<u8> {
    if kind == 1 || kind == 2 {
        vec![32]
    } else if kind == 8 {
        vec![16]
    } else if kind == 7 {
        vec![32, 64]
    } else {
        vec![16, 32, 64]
    }
}
fn prepare(kind: u8, w: u8, d: u32, n: u32, m: u32, vl: u16, half: &[f64]) -> [[u64; 32]; 32] {
    let mut z = data(kind, w);
    if kind >= 7 {
        for e in 0..128 / u16::from(w) {
            put(&mut z, m, e, w, ((e % 5) as i64 - 2) as u64 & mask(w));
        }
    }
    if (kind == 1 || kind == 2) && d != n && d != m {
        for e in 0..vl / 32 {
            put(
                &mut z,
                d,
                e,
                32,
                rounded(f64::from(e % 4) + 1.0, 32, false, half),
            );
        }
    }
    z
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_float_lane_ops::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    p: [u64; 4],
    kind: u8,
    half: Vec<f64>,
    inactive: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.predicate64" => self.p[usize::from(r.index % 4)],
                "a64.svcr" => 0,
                "a64.sme_fa64" => panic!("FA64 read in non-streaming mode"),
                "a64.fpcr" => {
                    assert!(!self.inactive);
                    0x04000000
                }
                "a64.fpsr" => {
                    assert!(!self.inactive);
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
        assert!(!self.inactive);
        assert_eq!(ctrl.bits, 0);
        let result = match f.operation {
            FloatOperation::Subtract => rounded(
                number(v[0].bits, f.width, false) - number(v[1].bits, f.width, false),
                f.width,
                false,
                &self.half,
            ),
            FloatOperation::Add => rounded(
                number(v[0].bits, f.width, false) + number(v[1].bits, f.width, false),
                f.width,
                false,
                &self.half,
            ),
            FloatOperation::HalfDotProduct => rounded(
                number(v[0].bits, 16, false) * number(v[2].bits, 16, false)
                    + number(v[1].bits, 16, false) * number(v[3].bits, 16, false),
                32,
                false,
                &self.half,
            ),
            FloatOperation::FromInteger {
                source_width,
                signed: sgn,
                ..
            } => rounded(
                if sgn {
                    signed(v[0].bits, source_width) as f64
                } else {
                    v[0].bits as f64
                },
                f.width,
                false,
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
fn float_lane_ops_all_widths_indices_predicates_aliases_lengths_and_backing() {
    let half = (0..0x7c00).map(half_value).collect::<Vec<_>>();
    for &(base, kind) in FORMS {
        for w in lengths(kind) {
            for vl in [128, 256, 512, 1024, 2048] {
                for alias in 0..4 {
                    if kind >= 7 && alias == 3 {
                        continue;
                    }
                    for q in [false, true] {
                        if (kind < 7 && !q) || (kind == 7 && w == 64 && !q) {
                            continue;
                        }
                        for index in 0..if kind == 2 { 4 } else { 1 } {
                            for pattern in 0..if kind == 0 { 3 } else { 1 } {
                                let (d, n, m) = operands(alias, kind);
                                let word = instruction(base, kind, w, q, index, d, n, m);
                                let mut p = [0; 4];
                                for e in 0..vl / u16::from(w) {
                                    if pattern == 2 || pattern == 1 && e % 2 == 0 {
                                        let bit = e * u16::from(w) / 8;
                                        p[usize::from(bit / 64)] |= 1 << (bit % 64);
                                    }
                                }
                                let s = State {
                                    z: prepare(kind, w, d, n, m, vl, &half),
                                    p,
                                    kind,
                                    half: half.clone(),
                                    inactive: kind == 0 && pattern == 0,
                                };
                                let want =
                                    expected(&s.z, kind, w, d, n, m, index, q, vl, pattern, &half);
                                let r = recipe(word, vl).unwrap();
                                r.validate().unwrap();
                                let t = evaluate(&r, &s).unwrap();
                                assert_eq!(t.trap, None);
                                let mut out = s.z;
                                for wr in t.registers {
                                    match wr.register.bank {
                                        "a64.vector64" => {
                                            out[usize::from(wr.register.index / 32)]
                                                [usize::from(wr.register.index % 32)] =
                                                wr.value.bits
                                        }
                                        "a64.fpsr" => {
                                            assert!(!s.inactive);
                                            assert_eq!(wr.value.bits, 0x08000000)
                                        }
                                        _ => panic!("{wr:?}"),
                                    }
                                }
                                assert_eq!(out, want, "{word:08x} kind{kind} VL{vl} alias{alias}");
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn float_lane_ops_reserved_sizes_lengths_and_fixed_q() {
    for &(base, kind) in FORMS {
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(base, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if kind == 0 || kind >= 3 && kind <= 6 {
            assert!(matches!(
                recipe(base, 128).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if kind == 7 {
            assert!(matches!(
                recipe(base | (1 << 22), 128).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

#[test]
fn fixed_scale_full_alias_uses_one_prestate_for_all_lanes() {
    for &(base, kind) in FORMS {
        if kind < 7 {
            continue;
        }
        for w in lengths(kind) {
            let one = match w {
                16 => 0x3c00,
                32 => 0x3f800000,
                _ => 0x3ff0000000000000,
            };
            let infinity = match w {
                16 => 0x7c00,
                32 => 0x7f800000,
                _ => 0x7ff0000000000000,
            };
            let mut s = State {
                z: [[0xdecafbaddecafbad; 32]; 32],
                p: [0; 4],
                kind,
                half: vec![],
                inactive: false,
            };
            for lane in 0..128 / u16::from(w) {
                put(&mut s.z, 30, lane, w, one);
            }
            let mut want = s.z;
            for lane in 0..128 / u16::from(w) {
                put(&mut want, 30, lane, w, infinity);
            }
            for chunk in 2..32 {
                want[30][chunk] = 0;
            }
            let t = evaluate(
                &recipe(instruction(base, kind, w, true, 0, 30, 30, 30), 2048).unwrap(),
                &s,
            )
            .unwrap();
            let mut out = s.z;
            for wr in t.registers {
                match wr.register.bank {
                    "a64.vector64" => {
                        out[usize::from(wr.register.index / 32)]
                            [usize::from(wr.register.index % 32)] = wr.value.bits
                    }
                    "a64.fpsr" => assert_eq!(wr.value.bits, 0x08000014),
                    _ => panic!("{wr:?}"),
                }
            }
            assert_eq!(out, want);
        }
    }
}

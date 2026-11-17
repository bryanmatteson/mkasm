#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xff30ffe1, 0xc120a300, 0, 2, false),  //add_mz_zzv_2x1
    (0xff30ffe3, 0xc120ab00, 0, 4, false),  //add_mz_zzv_4x1
    (0xff20fc01, 0xc120c400, 9, 2, false),  //sclamp_mz_zz_2
    (0xff20fc03, 0xc120cc00, 9, 4, false),  //sclamp_mz_zz_4
    (0xff21e021, 0xc1208000, 11, 2, false), //sel_mz_p_zz_2
    (0xff23e063, 0xc1218000, 11, 4, false), //sel_mz_p_zz_4
    (0xff30ffe1, 0xc120a000, 1, 2, false),  //smax_mz_zzv_2x1
    (0xff30ffe3, 0xc120a800, 1, 4, false),  //smax_mz_zzv_4x1
    (0xff21ffe1, 0xc120b000, 2, 2, false),  //smax_mz_zzw_2x2
    (0xff23ffe3, 0xc120b800, 2, 4, false),  //smax_mz_zzw_4x4
    (0xff30ffe1, 0xc120a020, 3, 2, false),  //smin_mz_zzv_2x1
    (0xff30ffe3, 0xc120a820, 3, 4, false),  //smin_mz_zzv_4x1
    (0xff21ffe1, 0xc120b020, 4, 2, false),  //smin_mz_zzw_2x2
    (0xff23ffe3, 0xc120b820, 4, 4, false),  //smin_mz_zzw_4x4
    (0xff3ffc01, 0xc125e000, 12, 2, false), //sunpk_mz_z_2
    (0xff3ffc23, 0xc135e000, 12, 4, false), //sunpk_mz_z_4
    (0xff20fc01, 0xc120c401, 10, 2, false), //uclamp_mz_zz_2
    (0xff20fc03, 0xc120cc01, 10, 4, false), //uclamp_mz_zz_4
    (0xff30ffe1, 0xc120a001, 5, 2, false),  //umax_mz_zzv_2x1
    (0xff30ffe3, 0xc120a801, 5, 4, false),  //umax_mz_zzv_4x1
    (0xff21ffe1, 0xc120b001, 6, 2, false),  //umax_mz_zzw_2x2
    (0xff23ffe3, 0xc120b801, 6, 4, false),  //umax_mz_zzw_4x4
    (0xff30ffe1, 0xc120a021, 7, 2, false),  //umin_mz_zzv_2x1
    (0xff30ffe3, 0xc120a821, 7, 4, false),  //umin_mz_zzv_4x1
    (0xff21ffe1, 0xc120b021, 8, 2, false),  //umin_mz_zzw_2x2
    (0xff23ffe3, 0xc120b821, 8, 4, false),  //umin_mz_zzw_4x4
    (0xff3ffc01, 0xc125e001, 13, 2, false), //uunpk_mz_z_2
    (0xff3ffc23, 0xc135e001, 13, 4, false), //uunpk_mz_z_4
    (0xff3ffc63, 0xc136e002, 16, 4, false), //uzp_mz_z_4
    (0xfffffc63, 0xc137e002, 16, 4, true),  //uzp_mz_z_4q
    (0xff20fc01, 0xc120d001, 17, 2, false), //uzp_mz_zz_2
    (0xffe0fc01, 0xc120d401, 17, 2, true),  //uzp_mz_zz_2q
    (0xff3ffc63, 0xc136e000, 14, 4, false), //zip_mz_z_4
    (0xfffffc63, 0xc137e000, 14, 4, true),  //zip_mz_z_4q
    (0xff20fc01, 0xc120d000, 15, 2, false), //zip_mz_zz_2
    (0xffe0fc01, 0xc120d400, 15, 2, true),  //zip_mz_zz_2q
];
fn mask(w: u8) -> u128 {
    if w == 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}
fn get(z: &[[u64; 32]; 32], n: u32, e: u16, w: u8) -> u128 {
    let bit = e * u16::from(w);
    let low = u128::from(z[n as usize][usize::from(bit / 64)] >> (bit % 64));
    if w == 128 {
        low | (u128::from(z[n as usize][usize::from(bit / 64 + 1)]) << 64)
    } else {
        low & mask(w)
    }
}
fn put(z: &mut [[u64; 32]; 32], n: u32, e: u16, w: u8, v: u128) {
    let bit = e * u16::from(w);
    if w == 128 {
        z[n as usize][usize::from(bit / 64)] = v as u64;
        z[n as usize][usize::from(bit / 64 + 1)] = (v >> 64) as u64;
    } else {
        let chunk = &mut z[n as usize][usize::from(bit / 64)];
        let sh = bit % 64;
        *chunk = (*chunk & !((mask(w) as u64) << sh)) | ((v as u64) << sh);
    }
}
fn signed(x: u128, w: u8) -> i128 {
    ((x << (128 - w)) as i128) >> (128 - w)
}
fn data() -> [[u64; 32]; 32] {
    std::array::from_fn(|reg| {
        std::array::from_fn(|chunk| {
            let x = 0x9e3779b97f4a7c15u64.wrapping_mul((reg * 32 + chunk + 1) as u64);
            x.rotate_left((reg + chunk) as u32)
        })
    })
}
fn operands(kind: u8, group: u16, alias: u8) -> (u32, u32, u32) {
    let d = if alias < 2 { 28 } else { 8 };
    let n = if alias == 1 || alias == 3 { d } else { 0 };
    let m = if alias >= 2 { d } else { 8 };
    let n = if kind <= 8 { d } else { n };
    let n = if (kind == 12 || kind == 13) && alias == 2 {
        d + u32::from(group / 2)
    } else {
        n
    };
    (d, n, m)
}
fn instruction(mask: u32, base: u32, w: u8, quad: bool, d: u32, n: u32, m: u32, p: u32) -> u32 {
    base | ((d
        | (n << 5)
        | (m << 16)
        | (p << 10)
        | if quad {
            0
        } else {
            u32::from(w.trailing_zeros() - 3) << 22
        })
        & !mask)
}
fn active(encoded: u16, byte: u16, svl: u16) -> bool {
    let tag = (encoded & 0x7fff).trailing_zeros();
    if tag >= 4 || byte % (1 << tag) != 0 {
        return false;
    }
    let count =
        ((u32::from(encoded & 0x7fff) >> (tag + 1)) & ((u32::from(svl) / 8 * 4 >> tag) - 1)) as u16;
    let below = (byte >> tag) < count;
    below ^ (encoded & 0x8000 != 0)
}
fn counters(kind: u8, w: u8, group: u16, svl: u16) -> Vec<u16> {
    if kind != 11 {
        return vec![0];
    };
    let mut out = vec![0, 0xffff];
    for size in 0..4 {
        let capacity = svl / 8 * 4 / (1 << size);
        let lanes = group * svl / u16::from(w);
        for count in [0, 1, lanes / 2, lanes.saturating_sub(1), capacity - 1] {
            let enc = ((count & (capacity - 1)) << (size + 1)) | (1 << size);
            out.extend([enc, enc | 0x8000]);
        }
    }
    out
}
fn expected(
    before: &[[u64; 32]; 32],
    kind: u8,
    group: u16,
    w: u8,
    d: u32,
    n: u32,
    m: u32,
    pn: u16,
    svl: u16,
) -> [[u64; 32]; 32] {
    let mut out = *before;
    let elements = svl / u16::from(w);
    for member in 0..group {
        for e in 0..elements {
            let a = get(before, d + u32::from(member), e, w);
            let choose = |x: u128, y: u128, sgn: bool, min: bool| {
                let lower = if sgn {
                    signed(x, w) < signed(y, w)
                } else {
                    x < y
                };
                if lower == min {
                    x
                } else {
                    y
                }
            };
            let result = match kind {
                0 => a.wrapping_add(get(before, m, e, w)) & mask(w),
                1..=8 => choose(
                    a,
                    get(
                        before,
                        m + if kind % 2 == 0 { u32::from(member) } else { 0 },
                        e,
                        w,
                    ),
                    kind <= 4,
                    matches!(kind, 3 | 4 | 7 | 8),
                ),
                9 | 10 => choose(
                    choose(get(before, n, e, w), a, kind == 9, false),
                    get(before, m, e, w),
                    kind == 9,
                    true,
                ),
                11 => get(
                    before,
                    if active(pn, (member * elements + e) * u16::from(w) / 8, svl) {
                        n
                    } else {
                        m
                    } + u32::from(member),
                    e,
                    w,
                ),
                12 | 13 => {
                    let x = get(
                        before,
                        n + u32::from(member / 2),
                        (member % 2) * elements + e,
                        w / 2,
                    );
                    if kind == 12 {
                        signed(x, w / 2) as u128 & mask(w)
                    } else {
                        x
                    }
                }
                14 | 15 => {
                    let sources = if group == 4 {
                        [n, n + 1, n + 2, n + 3]
                    } else {
                        [n, m, 0, 0]
                    };
                    get(
                        before,
                        sources[usize::from(e % group)],
                        member * (elements / group) + e / group,
                        w,
                    )
                }
                16 | 17 => {
                    let sources = if group == 4 {
                        [n, n + 1, n + 2, n + 3]
                    } else {
                        [n, m, 0, 0]
                    };
                    get(
                        before,
                        sources[usize::from(e / (elements / group))],
                        (e % (elements / group)) * group + member,
                        w,
                    )
                }
                _ => panic!(),
            };
            put(&mut out, d + u32::from(member), e, w, result);
        }
    }
    out
}
fn widths(kind: u8, quad: bool) -> Vec<u8> {
    if quad {
        vec![128]
    } else if kind == 12 || kind == 13 {
        vec![16, 32, 64]
    } else {
        vec![8, 16, 32, 64]
    }
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_group_integer::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    sm: bool,
    pn: u16,
    p: u32,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => u64::from(self.sm),
                "a64.predicate64" => {
                    assert_eq!(u32::from(r.index / 4), self.p);
                    assert_eq!(r.index % 4, 0);
                    u64::from(self.pn)
                }
                _ => panic!("unexpected FP/ZA context {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
}
#[test]
fn grouped_integer_all_encodings_widths_lengths_aliases_and_counter_masks() {
    for &(mask, base, kind, group, quad) in FORMS {
        for w in widths(kind, quad) {
            for vl in [128, 256, 512, 1024, 2048] {
                if kind >= 14 && vl < u16::from(w) * group {
                    continue;
                }
                for alias in 0..4 {
                    let (d, n, m) = operands(kind, group, alias);
                    let pn = if alias & 1 == 0 { 8 } else { 15 };
                    let word = instruction(mask, base, w, quad, d, n, m, pn & 7);
                    for encoded in counters(kind, w, group, vl) {
                        let s = State {
                            z: data(),
                            sm: true,
                            pn: encoded,
                            p: pn,
                        };
                        let want = expected(&s.z, kind, group, w, d, n, m, encoded, vl);
                        let r = recipe(word, vl).unwrap();
                        assert_eq!(r.support, Support::Full, "{word:08x}");
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert_eq!(t.trap, None);
                        let mut out = s.z;
                        for wr in t.registers {
                            assert_eq!(wr.register.bank, "a64.vector64");
                            out[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits;
                        }
                        assert_eq!(
                            out, want,
                            "{word:08x} kind{kind} SVL{vl} PN{encoded:04x} alias{alias}"
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn grouped_integer_requires_streaming_and_legal_svl() {
    for &(mask, base, kind, group, quad) in FORMS {
        let w = widths(kind, quad)[0];
        let word = instruction(mask, base, w, quad, 28, 0, 8, 0);
        let s = State {
            z: data(),
            sm: false,
            pn: 0,
            p: 8,
        };
        assert_eq!(
            evaluate(&recipe(word, 2048).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        );
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(word, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if kind >= 14 {
            for vl in [128, 256] {
                if vl < u16::from(w) * group {
                    assert!(matches!(
                        recipe(word, vl).unwrap().support,
                        Support::Unsupported(_)
                    ));
                }
            }
        }
        if kind == 12 || kind == 13 {
            assert!(matches!(
                recipe(base, 128).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

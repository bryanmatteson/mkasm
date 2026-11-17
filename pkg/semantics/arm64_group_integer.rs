//! Complete SME2 grouped integer arithmetic, select, unpack and permutations.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
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
fn lane(n: u32, e: u16, w: u8, part: u16) -> Expr {
    let bit = e * u16::from(w) + part * 64;
    let value = Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64));
    if w == 128 {
        value
    } else {
        Expr::extract(value, (bit % 64) as u8, w)
    }
}
fn minmax(a: Expr, z: Expr, signed: bool, minimum: bool) -> Expr {
    let lt = b(if signed { B::Slt } else { B::Ult }, a.clone(), z.clone());
    Expr::select(
        lt,
        if minimum { a.clone() } else { z.clone() },
        if minimum { z } else { a },
    )
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, group, quad) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let w = if quad { 128 } else { 8u8 << ((word >> 22) & 3) };
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048)
        || ((kind == 12 || kind == 13) && w == 8)
        || (kind >= 14 && svl < u16::from(w) * group)
    {
        return Some(Recipe::unsupported(
            "invalid grouped integer SVL or element size",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    r.guard = Expr::require_context(
        Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1),
        "grouped integer operation requires streaming mode",
    );
    let d = word & (32 - u32::from(group));
    let n = if kind <= 8 {
        d
    } else if kind == 9 || kind == 10 || kind == 15 || kind == 17 {
        (word >> 5) & 31
    } else if kind == 12 || kind == 13 {
        (word >> 5) & (32 - u32::from(group / 2))
    } else {
        (word >> 5) & (32 - u32::from(group))
    };
    let m = (word >> 16)
        & if kind == 0 || kind <= 8 && kind % 2 == 1 {
            15
        } else if kind <= 8 || kind == 11 {
            32 - u32::from(group)
        } else {
            31
        };
    let counter = if kind == 11 {
        Some(arm64_sve_counter::Counter::read(
            &mut r,
            8 + ((word >> 10) & 7) as u16,
            svl,
        ))
    } else {
        None
    };
    let elements = svl / u16::from(w);
    let mut writes = Vec::new();
    for member in 0..group {
        let dest = d + u32::from(member);
        for chunk in 0..svl / 64 {
            let mut out = c(64, 0);
            for part in 0..if w == 128 { 1 } else { 64 / u16::from(w) } {
                let e = if w == 128 {
                    chunk / 2
                } else {
                    chunk * (64 / u16::from(w)) + part
                };
                let half = if w == 128 { chunk % 2 } else { 0 };
                let value = if kind <= 8 {
                    let a = lane(dest, e, w, 0);
                    let z = lane(
                        m + if kind != 0 && kind % 2 == 0 {
                            u32::from(member)
                        } else {
                            0
                        },
                        e,
                        w,
                        0,
                    );
                    if kind == 0 {
                        b(B::Add, a, z)
                    } else {
                        minmax(
                            a,
                            z,
                            kind <= 4,
                            kind == 3 || kind == 4 || kind == 7 || kind == 8,
                        )
                    }
                } else if kind == 9 || kind == 10 {
                    let lower = lane(n, e, w, 0);
                    let upper = lane(m, e, w, 0);
                    let old = lane(dest, e, w, 0);
                    minmax(minmax(lower, old, kind == 9, false), upper, kind == 9, true)
                } else if kind == 11 {
                    let active = counter
                        .as_ref()
                        .unwrap()
                        .bit((member * elements + e) * u16::from(w) / 8);
                    Expr::select(
                        active,
                        lane(n + u32::from(member), e, w, 0),
                        lane(m + u32::from(member), e, w, 0),
                    )
                } else if kind == 12 || kind == 13 {
                    Expr::cast(
                        lane(
                            n + u32::from(member / 2),
                            (member % 2) * elements + e,
                            w / 2,
                            0,
                        ),
                        w,
                        kind == 12,
                    )
                } else if kind == 14 || kind == 15 {
                    let source = e % group;
                    let src = if kind == 14 {
                        n + u32::from(source)
                    } else if source == 0 {
                        n
                    } else {
                        m
                    };
                    lane(src, member * (elements / group) + e / group, w, half)
                } else {
                    let source = e / (elements / group);
                    let src = if kind == 16 {
                        n + u32::from(source)
                    } else if source == 0 {
                        n
                    } else {
                        m
                    };
                    lane(src, group * (e % (elements / group)) + member, w, half)
                };
                out = if w == 128 {
                    value
                } else {
                    b(
                        B::Or,
                        out,
                        b(
                            B::Shl,
                            Expr::cast(value, 64, false),
                            c(64, u64::from(part * u16::from(w))),
                        ),
                    )
                };
            }
            let value = r.bind(out);
            writes.push((
                register("a64.vector64", dest as u16 * 32 + chunk, 64, 64),
                value,
            ));
        }
    }
    // Every source and predicate is captured before any destination mutation.
    for (dest, value) in writes {
        r.write(dest, WritePolicy::ZeroUpper, value);
    }
    Some(r)
}

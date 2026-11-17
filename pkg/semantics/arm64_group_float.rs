//! Complete IEEE grouped SME floating multiply/minmax/clamp/scale/round category.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, u8)] = &[
    (0xff21ffe1, 0xc120b140, 10, 2, 1), // famax_mz_zzw_2x2
    (0xff23ffe3, 0xc120b940, 10, 4, 1), // famax_mz_zzw_4x4
    (0xff21ffe1, 0xc120b141, 11, 2, 1), // famin_mz_zzw_2x2
    (0xff23ffe3, 0xc120b941, 11, 4, 1), // famin_mz_zzw_4x4
    (0xff20fc01, 0xc120c000, 12, 2, 3), // fclamp_mz_zz_2
    (0xff20fc03, 0xc120c800, 12, 4, 3), // fclamp_mz_zz_4
    (0xff30ffe1, 0xc120a120, 3, 2, 0),  // fmaxnm_mz_zzv_2x1
    (0xff30ffe3, 0xc120a920, 3, 4, 0),  // fmaxnm_mz_zzv_4x1
    (0xff21ffe1, 0xc120b120, 3, 2, 1),  // fmaxnm_mz_zzw_2x2
    (0xff23ffe3, 0xc120b920, 3, 4, 1),  // fmaxnm_mz_zzw_4x4
    (0xff30ffe1, 0xc120a100, 1, 2, 0),  // fmax_mz_zzv_2x1
    (0xff30ffe3, 0xc120a900, 1, 4, 0),  // fmax_mz_zzv_4x1
    (0xff21ffe1, 0xc120b100, 1, 2, 1),  // fmax_mz_zzw_2x2
    (0xff23ffe3, 0xc120b900, 1, 4, 1),  // fmax_mz_zzw_4x4
    (0xff30ffe1, 0xc120a121, 4, 2, 0),  // fminnm_mz_zzv_2x1
    (0xff30ffe3, 0xc120a921, 4, 4, 0),  // fminnm_mz_zzv_4x1
    (0xff21ffe1, 0xc120b121, 4, 2, 1),  // fminnm_mz_zzw_2x2
    (0xff23ffe3, 0xc120b921, 4, 4, 1),  // fminnm_mz_zzw_4x4
    (0xff30ffe1, 0xc120a101, 2, 2, 0),  // fmin_mz_zzv_2x1
    (0xff30ffe3, 0xc120a901, 2, 4, 0),  // fmin_mz_zzv_4x1
    (0xff21ffe1, 0xc120b101, 2, 2, 1),  // fmin_mz_zzw_2x2
    (0xff23ffe3, 0xc120b901, 2, 4, 1),  // fmin_mz_zzw_4x4
    (0xff21fc21, 0xc120e800, 0, 2, 0),  // fmul_mz_zzv_2x1
    (0xff21fc63, 0xc121e800, 0, 4, 0),  // fmul_mz_zzv_4x1
    (0xff21fc21, 0xc120e400, 0, 2, 1),  // fmul_mz_zzw_2x2
    (0xff23fc63, 0xc121e400, 0, 4, 1),  // fmul_mz_zzw_4x4
    (0xfffffc21, 0xc1ace000, 6, 2, 2),  // frinta_mz_z_2
    (0xfffffc63, 0xc1bce000, 6, 4, 2),  // frinta_mz_z_4
    (0xfffffc21, 0xc1aae000, 7, 2, 2),  // frintm_mz_z_2
    (0xfffffc63, 0xc1bae000, 7, 4, 2),  // frintm_mz_z_4
    (0xfffffc21, 0xc1a8e000, 8, 2, 2),  // frintn_mz_z_2
    (0xfffffc63, 0xc1b8e000, 8, 4, 2),  // frintn_mz_z_4
    (0xfffffc21, 0xc1a9e000, 9, 2, 2),  // frintp_mz_z_2
    (0xfffffc63, 0xc1b9e000, 9, 4, 2),  // frintp_mz_z_4
    (0xff30ffe1, 0xc120a180, 5, 2, 0),  // fscale_mz_zzv_2x1
    (0xff30ffe3, 0xc120a980, 5, 4, 0),  // fscale_mz_zzv_4x1
    (0xff21ffe1, 0xc120b180, 5, 2, 1),  // fscale_mz_zzw_2x2
    (0xff23ffe3, 0xc120b980, 5, 4, 1),  // fscale_mz_zzw_4x4
];
fn z(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut v = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    v.offset = (bit % 64) as u8;
    Expr::register(v)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, op, nreg, layout) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let w = 8u8 << ((word >> 22) & 3);
    if w == 8 {
        return None;
    }
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid grouped FP SVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    r.guard = Expr::require_context(
        Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1),
        "grouped FP requires streaming mode",
    );
    let d = word & (32 - u32::from(nreg));
    let n = if layout == 3 {
        (word >> 5) & 31
    } else if op == 0 || layout == 2 {
        (word >> 5) & (32 - u32::from(nreg))
    } else {
        d
    };
    let m = (word >> if op == 0 && layout == 0 { 17 } else { 16 })
        & if layout == 3 {
            31
        } else if layout == 1 {
            32 - u32::from(nreg)
        } else {
            15
        };
    let mut fp = FloatState::new(&mut r);
    // FPCR() masks exception enables in streaming mode without effective FA64.
    // AHP affects format conversions, not these IEEE arithmetic inputs.
    let raw = r.bind(b(B::And, fp.control.clone(), c(32, !(1u64 << 26))));
    fp.control = r.bind(Expr::select(
        Expr::register(register("a64.sme_fa64", 0, 1, 1)),
        raw.clone(),
        b(B::And, raw, c(32, !0x9f00u64)),
    ));
    let mut writes = Vec::new();
    for member in 0..nreg {
        let src = n + if layout == 3 { 0 } else { u32::from(member) };
        for chunk in 0..svl / 64 {
            let mut packed = c(64, 0);
            for part in 0..64 / u16::from(w) {
                let e = chunk * (64 / u16::from(w)) + part;
                let a = z(src, e, w);
                let rhs = z(m + if layout == 1 { u32::from(member) } else { 0 }, e, w);
                let value = match op {
                    5 => fp.scale_logb(&mut r, w, a, Some(rhs), c(1, 1), c(w, 0)),
                    10 | 11 => fp.absolute_minmax(&mut r, a, rhs, op == 11, c(1, 1), c(w, 0)),
                    12 => {
                        let max = fp.step(
                            &mut r,
                            FloatOperation::MinMax {
                                minimum: false,
                                numeric: true,
                            },
                            w,
                            vec![a, z(d + u32::from(member), e, w)],
                            c(1, 1),
                            c(w, 0),
                            true,
                        );
                        fp.step(
                            &mut r,
                            FloatOperation::MinMax {
                                minimum: true,
                                numeric: true,
                            },
                            w,
                            vec![max, rhs],
                            c(1, 1),
                            c(w, 0),
                            true,
                        )
                    }
                    _ => {
                        let operation = match op {
                            0 => FloatOperation::Multiply,
                            1..=4 => FloatOperation::MinMax {
                                minimum: op == 2 || op == 4,
                                numeric: op >= 3,
                            },
                            6..=9 => FloatOperation::RoundToIntegral {
                                rounding: match op {
                                    6 => FloatRounding::NearestAway,
                                    7 => FloatRounding::NegativeInfinity,
                                    8 => FloatRounding::NearestEven,
                                    _ => FloatRounding::PositiveInfinity,
                                },
                                exact: false,
                            },
                            _ => unreachable!(),
                        };
                        let mut args = vec![a];
                        if layout != 2 {
                            args.push(rhs);
                        }
                        fp.step(&mut r, operation, w, args, c(1, 1), c(w, 0), true)
                    }
                };
                packed = b(
                    B::Or,
                    packed,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(part) * u64::from(w)),
                    ),
                );
            }
            writes.push((
                register(
                    "a64.vector64",
                    (d + u32::from(member)) as u16 * 32 + chunk,
                    64,
                    64,
                ),
                packed,
            ));
        }
    }
    fp.finish(&mut r);
    for (dst, value) in writes {
        r.write(dst, WritePolicy::ZeroUpper, value);
    }
    Some(r)
}

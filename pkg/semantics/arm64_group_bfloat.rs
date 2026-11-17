//! Every grouped BF16 multiply, min/max, clamp and scale encoding.
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
    (0xffe0fc01, 0xc120c000, 6, 2, 3), // bfclamp_mz_zz_2
    (0xffe0fc03, 0xc120c800, 6, 4, 3), // bfclamp_mz_zz_4
    (0xfff0ffe1, 0xc120a120, 3, 2, 0), // bfmaxnm_mz_zzv_2x1
    (0xfff0ffe3, 0xc120a920, 3, 4, 0), // bfmaxnm_mz_zzv_4x1
    (0xffe1ffe1, 0xc120b120, 3, 2, 1), // bfmaxnm_mz_zzw_2x2
    (0xffe3ffe3, 0xc120b920, 3, 4, 1), // bfmaxnm_mz_zzw_4x4
    (0xfff0ffe1, 0xc120a100, 1, 2, 0), // bfmax_mz_zzv_2x1
    (0xfff0ffe3, 0xc120a900, 1, 4, 0), // bfmax_mz_zzv_4x1
    (0xffe1ffe1, 0xc120b100, 1, 2, 1), // bfmax_mz_zzw_2x2
    (0xffe3ffe3, 0xc120b900, 1, 4, 1), // bfmax_mz_zzw_4x4
    (0xfff0ffe1, 0xc120a121, 4, 2, 0), // bfminnm_mz_zzv_2x1
    (0xfff0ffe3, 0xc120a921, 4, 4, 0), // bfminnm_mz_zzv_4x1
    (0xffe1ffe1, 0xc120b121, 4, 2, 1), // bfminnm_mz_zzw_2x2
    (0xffe3ffe3, 0xc120b921, 4, 4, 1), // bfminnm_mz_zzw_4x4
    (0xfff0ffe1, 0xc120a101, 2, 2, 0), // bfmin_mz_zzv_2x1
    (0xfff0ffe3, 0xc120a901, 2, 4, 0), // bfmin_mz_zzv_4x1
    (0xffe1ffe1, 0xc120b101, 2, 2, 1), // bfmin_mz_zzw_2x2
    (0xffe3ffe3, 0xc120b901, 2, 4, 1), // bfmin_mz_zzw_4x4
    (0xffe1fc21, 0xc120e800, 0, 2, 0), // bfmul_mz_zzv_2x1
    (0xffe1fc63, 0xc121e800, 0, 4, 0), // bfmul_mz_zzv_4x1
    (0xffe1fc21, 0xc120e400, 0, 2, 1), // bfmul_mz_zzw_2x2
    (0xffe3fc63, 0xc121e400, 0, 4, 1), // bfmul_mz_zzw_4x4
    (0xfff0ffe1, 0xc120a180, 5, 2, 0), // bfscale_mz_zzv_2x1
    (0xfff0ffe3, 0xc120a980, 5, 4, 0), // bfscale_mz_zzv_4x1
    (0xffe1ffe1, 0xc120b180, 5, 2, 1), // bfscale_mz_zzw_2x2
    (0xffe3ffe3, 0xc120b980, 5, 4, 1), // bfscale_mz_zzw_4x4
];
fn z(n: u32, e: u16) -> Expr {
    let bit = e * 16;
    let mut v = register("a64.vector64", n as u16 * 32 + bit / 64, 16, 64);
    v.offset = (bit % 64) as u8;
    Expr::register(v)
}
fn expand(v: Expr) -> Expr {
    b(B::Shl, Expr::cast(v, 32, false), c(32, 16))
}
fn narrow(v: Expr) -> Expr {
    Expr::extract(v, 16, 16)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, op, nreg, layout) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid grouped BF16 SVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    r.guard = Expr::require_context(
        Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1),
        "grouped BF16 requires streaming mode",
    );
    let d = word & (32 - u32::from(nreg));
    let n = if layout == 3 {
        (word >> 5) & 31
    } else if op == 0 {
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
            for part in 0..4u16 {
                let e = chunk * 4 + part;
                let a = z(src, e);
                let rhs = z(m + if layout == 1 { u32::from(member) } else { 0 }, e);
                let value = match op {
                    0 => fp.step(
                        &mut r,
                        FloatOperation::BFloatBinary {
                            operation: BFloatOperation::Multiply,
                        },
                        16,
                        vec![a, rhs],
                        c(1, 1),
                        c(16, 0),
                        true,
                    ),
                    5 => fp.bfloat_scale(&mut r, a, rhs, c(1, 1), c(16, 0)),
                    6 => {
                        let max = fp.step(
                            &mut r,
                            FloatOperation::MinMax {
                                minimum: false,
                                numeric: true,
                            },
                            32,
                            vec![expand(a), expand(z(d + u32::from(member), e))],
                            c(1, 1),
                            c(32, 0),
                            true,
                        );
                        narrow(fp.step(
                            &mut r,
                            FloatOperation::MinMax {
                                minimum: true,
                                numeric: true,
                            },
                            32,
                            vec![max, expand(rhs)],
                            c(1, 1),
                            c(32, 0),
                            true,
                        ))
                    }
                    _ => narrow(fp.step(
                        &mut r,
                        FloatOperation::MinMax {
                            minimum: op == 2 || op == 4,
                            numeric: op >= 3,
                        },
                        32,
                        vec![expand(a), expand(rhs)],
                        c(1, 1),
                        c(32, 0),
                        true,
                    )),
                };
                packed = b(
                    B::Or,
                    packed,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(part) * 16),
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

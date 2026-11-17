//! The full ordinary SVE BF16 arithmetic category (June 2026).
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u8)] = &[
    (0xffffe000, 0x65008000, 0, 1),  // bfadd_z_p_zz_
    (0xffe0fc00, 0x65000000, 0, 0),  // bfadd_z_zz_
    (0xffe0fc00, 0x64202400, 8, 4),  // bfclamp_z_zz_
    (0xffffe000, 0x65048000, 5, 1),  // bfmaxnm_z_p_zz_
    (0xffffe000, 0x65068000, 3, 1),  // bfmax_z_p_zz_
    (0xffffe000, 0x65058000, 6, 1),  // bfminnm_z_p_zz_
    (0xffffe000, 0x65078000, 4, 1),  // bfmin_z_p_zz_
    (0xffe0e000, 0x65200000, 9, 3),  // bfmla_z_p_zzz_
    (0xffa0fc00, 0x64200800, 9, 2),  // bfmla_z_zzzi_h
    (0xffe0e000, 0x65202000, 10, 3), // bfmls_z_p_zzz_
    (0xffa0fc00, 0x64200c00, 10, 2), // bfmls_z_zzzi_h
    (0xffffe000, 0x65028000, 2, 1),  // bfmul_z_p_zz_
    (0xffe0fc00, 0x65000800, 2, 0),  // bfmul_z_zz_
    (0xffa0fc00, 0x64202800, 2, 2),  // bfmul_z_zzi_h
    (0xffffe000, 0x65098000, 7, 1),  // bfscale_z_p_zz_
    (0xffffe000, 0x65018000, 1, 1),  // bfsub_z_p_zz_
    (0xffe0fc00, 0x65000400, 1, 0),  // bfsub_z_zz_
];
fn z(n: u32, e: u16) -> Expr {
    let bit = e * 16;
    let mut v = register("a64.vector64", n as u16 * 32 + bit / 64, 16, 64);
    v.offset = (bit % 64) as u8;
    Expr::register(v)
}
fn pred(g: u32, e: u16) -> Expr {
    let bit = e * 2;
    Expr::extract(
        Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
fn expand(v: Expr) -> Expr {
    b(B::Shl, Expr::cast(v, 32, false), c(32, 16))
}
fn narrow(v: Expr) -> Expr {
    Expr::extract(v, 16, 16)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, op, layout) = FORMS
        .iter()
        .find(|(mask, value, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE BF16 VL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1);
    r.guard = Expr::require_context(
        Expr::select(
            sm.clone(),
            Expr::select(
                Expr::register(register("a64.sme2", 0, 1, 1)),
                c(1, 1),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            ),
            c(1, 1),
        ),
        "SVE BF16 in streaming mode requires SME2 or FA64",
    );
    let d = word & 31;
    let n = if layout == 1 { d } else { (word >> 5) & 31 };
    let m = if layout == 1 {
        (word >> 5) & 31
    } else {
        (word >> 16) & if layout == 2 { 7 } else { 31 }
    };
    let g = (word >> 10) & 7;
    let predicated = layout == 1 || layout == 3;
    let active = (0..vl / 16)
        .map(|e| {
            if predicated {
                r.bind(pred(g, e))
            } else {
                c(1, 1)
            }
        })
        .collect::<Vec<_>>();
    let any = if predicated {
        r.bind(active.iter().cloned().fold(c(1, 0), |a, v| b(B::Or, a, v)))
    } else {
        c(1, 1)
    };
    let mut fp = FloatState::new_conditional(&mut r, any.clone());
    let control = b(B::And, fp.control.clone(), c(32, !(1u64 << 26)));
    let mask = Expr::select(
        sm,
        Expr::select(
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(32, u32::MAX as u64),
            c(32, !0x9f00u64),
        ),
        c(32, u32::MAX as u64),
    );
    fp.control = r.bind(b(B::And, control, mask));
    let index = (((word >> 22) & 1) * 4 + ((word >> 19) & 3)) as u16;
    let mut writes = Vec::new();
    for chunk in 0..vl / 64 {
        let mut packed = c(64, 0);
        for part in 0..4u16 {
            let e = chunk * 4 + part;
            let a = z(n, e);
            let rhs = z(m, if layout == 2 { e / 8 * 8 + index } else { e });
            let old = z(d, e);
            let active = active[e as usize].clone();
            let value = match op {
                7 => fp.bfloat_scale(&mut r, a, rhs, active, old),
                8 => {
                    let max = fp.step(
                        &mut r,
                        FloatOperation::MinMax {
                            minimum: false,
                            numeric: true,
                        },
                        32,
                        vec![expand(a), expand(old.clone())],
                        active.clone(),
                        expand(old.clone()),
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
                        active,
                        expand(old),
                        true,
                    ))
                }
                9 | 10 => {
                    let a = if op == 10 {
                        b(B::Xor, a, c(16, 0x8000))
                    } else {
                        a
                    };
                    fp.step(
                        &mut r,
                        FloatOperation::BFloatFused,
                        16,
                        vec![old.clone(), a, rhs],
                        active,
                        old,
                        true,
                    )
                }
                0..=2 => fp.step(
                    &mut r,
                    FloatOperation::BFloatBinary {
                        operation: match op {
                            0 => BFloatOperation::Add,
                            1 => BFloatOperation::Subtract,
                            _ => BFloatOperation::Multiply,
                        },
                    },
                    16,
                    vec![a, rhs],
                    active,
                    old,
                    true,
                ),
                _ => narrow(fp.step(
                    &mut r,
                    FloatOperation::MinMax {
                        minimum: op == 4 || op == 6,
                        numeric: op >= 5,
                    },
                    32,
                    vec![expand(a), expand(rhs)],
                    active,
                    expand(old),
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
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            packed,
        ));
    }
    fp.finish_conditional(&mut r, any);
    for (dst, value) in writes {
        r.write(dst, WritePolicy::ZeroUpper, value);
    }
    Some(r)
}

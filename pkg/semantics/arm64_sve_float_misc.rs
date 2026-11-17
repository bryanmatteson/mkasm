//! SVE absolute min/max, clamp and trigonometric preprocessing.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8)] = &[
    (0xff3fe000, 0x650e8000, 0), // famax_z_p_zz_
    (0xff3fe000, 0x650f8000, 1), // famin_z_p_zz_
    (0xff20fc00, 0x64202400, 2), // fclamp_z_zz_
    (0xff20fc00, 0x65000c00, 3), // ftsmul_z_zz_
    (0xff20fc00, 0x0420b000, 4), // ftssel_z_zz_
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn nan(v: Expr, w: u8) -> Expr {
    let (exp, frac) = match w {
        16 => (0x7c00, 0x3ff),
        32 => (0x7f800000, 0x7fffff),
        _ => (0x7ff0000000000000, 0xfffffffffffff),
    };
    b(
        B::And,
        b(B::Eq, b(B::And, v.clone(), c(w, exp)), c(w, exp)),
        Expr::unary(UnaryOp::Not, b(B::Eq, b(B::And, v, c(w, frac)), c(w, 0))),
    )
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind) = FORMS
        .iter()
        .find(|(mask, value, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let size = (word >> 22) & 3;
    if size == 0 {
        return Some(Recipe::unsupported(
            "reserved SVE floating miscellaneous size",
            next,
            64,
        ));
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid SVE floating miscellaneous VL",
            next,
            64,
        ));
    }
    let w = 8u8 << size;
    let d = word & 31;
    let n = if kind <= 1 { d } else { (word >> 5) & 31 };
    let m = if kind <= 1 {
        (word >> 5) & 31
    } else {
        (word >> 16) & 31
    };
    let g = (word >> 10) & 7;
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1);
    if kind != 2 {
        r.guard = Expr::require_context(
            Expr::select(
                sm.clone(),
                if kind <= 1 {
                    Expr::select(
                        Expr::register(register("a64.sme2", 0, 1, 1)),
                        c(1, 1),
                        Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                    )
                } else {
                    Expr::register(register("a64.sme_fa64", 0, 1, 1))
                },
                c(1, 1),
            ),
            "SVE floating miscellaneous streaming context",
        );
    }
    let active = (0..vl / u16::from(w))
        .map(|e| {
            if kind <= 1 {
                let bit = e * u16::from(w / 8);
                r.bind(Expr::extract(
                    Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
                    (bit % 64) as u8,
                    1,
                ))
            } else {
                c(1, 1)
            }
        })
        .collect::<Vec<_>>();
    let any = if kind <= 1 {
        r.bind(active.iter().cloned().fold(c(1, 0), |a, v| b(B::Or, a, v)))
    } else {
        c(1, 1)
    };
    let mut fp = if kind == 4 {
        None
    } else {
        let mut fp = FloatState::new_conditional(&mut r, any.clone());
        let raw = b(B::And, fp.control.clone(), c(32, !(1u64 << 26)));
        fp.control = r.bind(Expr::select(
            sm,
            Expr::select(
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                raw.clone(),
                b(B::And, raw.clone(), c(32, !0x9f00u64)),
            ),
            raw,
        ));
        Some(fp)
    };
    let mut values = Vec::new();
    for e in 0..vl / u16::from(w) {
        let a = lane(n, e, w);
        let rhs = lane(m, e, w);
        let old = lane(d, e, w);
        let value = if let Some(fp) = fp.as_mut() {
            match kind {
                0 | 1 => fp.absolute_minmax(
                    &mut r,
                    a,
                    rhs,
                    kind == 1,
                    active[usize::from(e)].clone(),
                    old,
                ),
                2 => {
                    let x = fp.step(
                        &mut r,
                        FloatOperation::MinMax {
                            minimum: false,
                            numeric: true,
                        },
                        w,
                        vec![a, old],
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
                        vec![x, rhs],
                        c(1, 1),
                        c(w, 0),
                        true,
                    )
                }
                _ => {
                    let square = fp.step(
                        &mut r,
                        FloatOperation::Multiply,
                        w,
                        vec![a.clone(), a],
                        c(1, 1),
                        c(w, 0),
                        true,
                    );
                    Expr::select(
                        nan(square.clone(), w),
                        square.clone(),
                        b(
                            B::Or,
                            b(B::And, square, c(w, u64::MAX >> (65 - w))),
                            b(
                                B::Shl,
                                Expr::cast(Expr::extract(rhs, 0, 1), w, false),
                                c(w, u64::from(w - 1)),
                            ),
                        ),
                    )
                }
            }
        } else {
            let choose = Expr::extract(rhs.clone(), 0, 1);
            let negate = Expr::extract(rhs, 1, 1);
            let ah = Expr::extract(Expr::register(register("a64.fpcr", 0, 32, 32)), 1, 1);
            let negated = Expr::select(
                b(B::And, ah, nan(a.clone(), w)),
                a.clone(),
                b(B::Xor, a.clone(), c(w, 1u64 << (w - 1))),
            );
            let one = b(
                B::Or,
                c(
                    w,
                    match w {
                        16 => 0x3c00,
                        32 => 0x3f800000,
                        _ => 0x3ff0000000000000,
                    },
                ),
                b(
                    B::Shl,
                    Expr::cast(negate.clone(), w, false),
                    c(w, u64::from(w - 1)),
                ),
            );
            r.bind(Expr::select(choose, one, Expr::select(negate, negated, a)))
        };
        values.push(value);
    }
    if let Some(fp) = fp {
        fp.finish_conditional(&mut r, any);
    }
    for (chunk, parts) in values.chunks(usize::from(64 / w)).enumerate() {
        let mut packed = c(64, 0);
        for (part, value) in parts.iter().enumerate() {
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value.clone(), 64, false),
                    c(64, part as u64 * u64::from(w)),
                ),
            );
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    Some(r)
}

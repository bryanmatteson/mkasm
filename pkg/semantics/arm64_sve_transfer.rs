//! SVE MUL, MOVPRFX, CTERM and FTSSEL, from June2026 primary definitions.
//! Caller supplies feature/access admission. Predicated transfers suppress
//! unused inputs; CTERM preserves Z/C, and FTSSEL reads AH only for a negated NaN.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut s = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    s.offset = (bit % 64) as u8;
    Expr::register(s)
}
fn pred(g: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w / 8);
    let mut s = register("a64.predicate64", g as u16 * 4 + bit / 64, 1, 64);
    s.offset = (bit % 64) as u8;
    Expr::register(s)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mul = word & 0xff20fc00 == 0x04206000;
    let prefix = word & 0xfffffc00 == 0x0420bc00;
    let predicated = word & 0xff3ee000 == 0x04102000;
    let terminate = matches!(word & 0xffa0fc1f, 0x25a02000 | 0x25a02010);
    let trig = word & 0xff20fc00 == 0x0420b000;
    if !(mul || prefix || predicated || terminate || trig) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    if terminate {
        let w = 32u8 << ((word >> 22) & 1);
        let gp = |n: u32| {
            if n == 31 {
                c(w, 0)
            } else {
                Expr::register(register("a64.gpr", n as u16, w, 64))
            }
        };
        let mut term = b(B::Eq, gp(n), gp(m));
        if word & (1 << 4) != 0 {
            term = not(term);
        }
        let term = r.bind(term);
        r.write(
            register("a64.nzcv", 0, 1, 1),
            WritePolicy::ZeroUpper,
            term.clone(),
        );
        r.write(
            register("a64.nzcv", 3, 1, 1),
            WritePolicy::ZeroUpper,
            Expr::select(
                term,
                c(1, 0),
                not(Expr::register(register("a64.nzcv", 2, 1, 1))),
            ),
        );
        return Some(r);
    }
    let w = if prefix {
        64
    } else {
        8u8 << ((word >> 22) & 3)
    };
    if trig {
        if w == 8 {
            return Some(Recipe::unsupported(
                "reserved SVE FTSSEL element size",
                next,
                64,
            ));
        }
        r.bind(Expr::require_context(
            Expr::select(
                Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
            "SVE FTSSEL requires non-streaming SVE access",
        ));
    }
    let g = (word >> 10) & 7;
    for chunk in 0..vl / 64 {
        let mut packed = c(64, 0);
        for i in 0..64 / u16::from(w) {
            let e = chunk * (64 / u16::from(w)) + i;
            let value = if prefix {
                lane(n, e, w)
            } else if mul {
                b(B::Mul, lane(n, e, w), lane(m, e, w))
            } else if predicated {
                Expr::select(
                    pred(g, e, w),
                    lane(n, e, w),
                    if word & (1 << 16) != 0 {
                        lane(d, e, w)
                    } else {
                        c(w, 0)
                    },
                )
            } else {
                let mut selector = register(
                    "a64.vector64",
                    m as u16 * 32 + (e * u16::from(w)) / 64,
                    2,
                    64,
                );
                selector.offset = ((e * u16::from(w)) % 64) as u8;
                let selector = r.bind(Expr::register(selector));
                let sign = 1u64 << (w - 1);
                let one = match w {
                    16 => 0x3c00,
                    32 => 0x3f800000,
                    _ => 0x3ff0000000000000,
                };
                let exponent = match w {
                    16 => 0x7c00,
                    32 => 0x7f800000,
                    _ => 0x7ff0000000000000,
                };
                let fraction = match w {
                    16 => 0x3ff,
                    32 => 0x7fffff,
                    _ => 0xfffffffffffff,
                };
                // Bind the source only when selecting or negating it. The
                // FPOne branch has no dependency on its source or FPCR.
                let input = r.bind(Expr::select(
                    Expr::extract(selector.clone(), 0, 1),
                    c(w, 0),
                    lane(n, e, w),
                ));
                let nan = b(
                    B::And,
                    b(
                        B::Eq,
                        b(B::And, input.clone(), c(w, exponent)),
                        c(w, exponent),
                    ),
                    not(b(B::Eq, b(B::And, input.clone(), c(w, fraction)), c(w, 0))),
                );
                let negated = Expr::select(
                    Expr::select(
                        nan,
                        Expr::extract(Expr::register(register("a64.fpcr", 0, 32, 32)), 1, 1),
                        c(1, 0),
                    ),
                    input.clone(),
                    b(B::Xor, input.clone(), c(w, sign)),
                );
                Expr::select(
                    Expr::extract(selector.clone(), 0, 1),
                    b(
                        B::Or,
                        c(w, one),
                        b(
                            B::Shl,
                            Expr::cast(Expr::extract(selector.clone(), 1, 1), w, false),
                            c(w, u64::from(w - 1)),
                        ),
                    ),
                    Expr::select(Expr::extract(selector, 1, 1), negated, input),
                )
            };
            let value = r.bind(value);
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(i) * u64::from(w)),
                ),
            );
        }
        let packed = r.bind(packed);
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    Some(r)
}

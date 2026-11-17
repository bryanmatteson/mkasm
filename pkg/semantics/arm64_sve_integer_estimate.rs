//! SVE unsigned integer reciprocal estimates, June2026 primary definitions.
//! Only size=10 (32-bit elements) is allocated. Integer helpers explicitly use
//! classic precision: no FPCR/FPSR/FP exception or enhanced-estimate context.
//! Generated caller owns SVE2/SME or zeroing SVE2p2/SME2p2 feature availability
//! and standard CheckSVEEnabled admission. Preserve Z backing above CurrentVL
//! using the primary accessor's permitted non-SVEZEROUPPER choice.
use super::*;
use BinaryOp as B;
fn c(w: u8, x: u64) -> Expr {
    Expr::constant(w, x)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn z(n: u32, k: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + k, 64, 64))
}
fn lane(n: u32, e: u16) -> Expr {
    Expr::extract(z(n, e / 2), ((e % 2) * 32) as u8, 32)
}
fn reciprocal(r: &mut Recipe, x: Expr) -> Expr {
    let a = r.bind(b(B::Lsr, x.clone(), c(32, 23)));
    let denominator = b(B::Add, b(B::Shl, a, c(32, 1)), c(32, 1));
    let quotient = b(B::Udiv, c(32, 1 << 19), denominator);
    let rounded = b(B::Lsr, b(B::Add, quotient, c(32, 1)), c(32, 1));
    Expr::select(
        b(B::Ult, x, c(32, 0x80000000)),
        c(32, 0xffffffff),
        b(B::Shl, rounded, c(32, 23)),
    )
}
fn reciprocal_sqrt(r: &mut Recipe, x: Expr) -> Expr {
    let a = r.bind(b(B::Lsr, x.clone(), c(32, 23)));
    let low = b(B::Add, b(B::Shl, a.clone(), c(32, 1)), c(32, 1));
    let high = b(
        B::Shl,
        b(B::Add, b(B::And, a.clone(), c(32, !1)), c(32, 1)),
        c(32, 1),
    );
    let a = r.bind(Expr::select(b(B::Ult, a, c(32, 256)), low, high));
    // Exact bounded search for largest b with a*b*b < 2^28, replacing the
    // primary incrementing loop. For valid a=257..1022, b=512..1023; every
    // candidate product fits u32. Inactive/source-below-threshold paths are
    // discarded by the surrounding selects and introduce no host FP operation.
    let mut root = c(32, 512);
    for bit in (0..9).rev() {
        let candidate = r.bind(b(B::Add, root.clone(), c(32, 1 << bit)));
        let square = b(B::Mul, candidate.clone(), candidate.clone());
        let below = b(B::Ult, b(B::Mul, a.clone(), square), c(32, 1 << 28));
        root = r.bind(Expr::select(below, candidate, root));
    }
    let rounded = b(B::Lsr, b(B::Add, root, c(32, 1)), c(32, 1));
    Expr::select(
        b(B::Ult, x, c(32, 0x40000000)),
        c(32, 0xffffffff),
        b(B::Shl, rounded, c(32, 23)),
    )
}
/// None is unowned physical family; invalid owned size/CurrentVL is Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let family = word & 0xff3fe000;
    if !matches!(family, 0x4400a000 | 0x4402a000 | 0x4401a000 | 0x4403a000) {
        return None;
    }
    if (word >> 22) & 3 != 2 {
        return Some(Recipe::unsupported(
            "reserved SVE integer estimate size",
            address.wrapping_add(4),
            64,
        ));
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid SVE CurrentVL",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let g = (word >> 10) & 7;
    let zeroing = word & (1 << 17) != 0;
    let sqrt = word & (1 << 16) != 0;
    let predicates: Vec<_> = (0..(vl / 8).div_ceil(64))
        .map(|k| {
            r.bind(Expr::register(register(
                "a64.predicate64",
                g as u16 * 4 + k,
                (vl / 8 - k * 64).min(64) as u8,
                64,
            )))
        })
        .collect();
    let mut values = vec![];
    for e in 0..vl / 32 {
        let bit = e * 4;
        let active = r.bind(Expr::extract(
            predicates[(bit / 64) as usize].clone(),
            (bit % 64) as u8,
            1,
        ));
        let x = r.bind(Expr::select(active.clone(), lane(n, e), c(32, 0)));
        let value = if sqrt {
            reciprocal_sqrt(&mut r, x)
        } else {
            reciprocal(&mut r, x)
        };
        values.push(r.bind(Expr::select(
            active,
            value,
            if zeroing { c(32, 0) } else { lane(d, e) },
        )));
    }
    for (k, lanes) in values.chunks(2).enumerate() {
        let packed = r.bind(b(
            B::Or,
            Expr::cast(lanes[0].clone(), 64, false),
            b(B::Shl, Expr::cast(lanes[1].clone(), 64, false), c(64, 32)),
        ));
        r.write(
            register("a64.vector64", d as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    Some(r)
}

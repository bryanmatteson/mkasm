//! Whole-vector SVE EXPAND, with lazy prefix-indexed source selection.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn source(n: u32, base: u16, count: u16, bits: &[Expr]) -> Expr {
    if count == 1 {
        return Expr::register(register("a64.vector64", n as u16 * 32 + base, 64, 64));
    }
    let half = count.next_power_of_two() / 2;
    Expr::select(
        bits[half.trailing_zeros() as usize].clone(),
        source(n, base + half, count - half, bits),
        source(n, base, half, bits),
    )
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if word & 0xff3fe000 != 0x05318000 {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    // SME2p2 selects CheckSVEEnabled directly. Only the alternative
    // CheckNonStreamingSVEEnabled path needs effective FA64 in streaming mode.
    let allowed = Expr::select(
        Expr::register(register("a64.sme2p2", 0, 1, 1)),
        c(1, 1),
        Expr::register(register("a64.sme_fa64", 0, 1, 1)),
    );
    r.guard = Expr::require_context(
        Expr::select(sm, allowed, c(1, 1)),
        "EXPAND streaming mode requires effective FA64 or SME2p2",
    );
    let (d, n, g) = (word & 31, (word >> 5) & 31, (word >> 10) & 7);
    let w = 8u8 << ((word >> 22) & 3);
    let per = 64 / u16::from(w);
    let low = per.trailing_zeros() as u8;
    let mut prefix = c(16, 0);
    let mut values = vec![];
    for e in 0..vl / u16::from(w) {
        let bit = e * u16::from(w) / 8;
        let active = r.bind(Expr::extract(
            Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
            (bit % 64) as u8,
            1,
        ));
        // At lane e at most e predecessors can be active. Bound the selector
        // tree by that fact; VL2048 byte graphs stay within native limits.
        // Thus prefix/per < chunks, including non-power-of-two tree sizes;
        // the low prefix bits select an element strictly within that chunk.
        let chunks = e / per + 1;
        let levels = (chunks.next_power_of_two().trailing_zeros()) as u8;
        let bits: Vec<_> = (0..levels)
            .map(|level| r.bind(Expr::extract(prefix.clone(), low + level, 1)))
            .collect();
        let chunk = source(n, 0, chunks, &bits);
        let shift = b(
            B::Shl,
            b(B::And, prefix.clone(), c(16, u64::from(per - 1))),
            c(16, u64::from(w.trailing_zeros())),
        );
        let value = Expr::cast(b(B::Lsr, chunk, Expr::cast(shift, 64, false)), w, false);
        values.push(r.bind(Expr::select(active.clone(), value, c(w, 0))));
        prefix = r.bind(b(B::Add, prefix, Expr::cast(active, 16, false)));
    }
    for (k, lanes) in values.chunks(usize::from(per)).enumerate() {
        let mut out = c(64, 0);
        for (i, v) in lanes.iter().enumerate() {
            out = b(
                B::Or,
                out,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), 64, false),
                    c(64, (i * usize::from(w)) as u64),
                ),
            );
        }
        let out = r.bind(out);
        r.write(
            register("a64.vector64", d as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
    Some(r)
}

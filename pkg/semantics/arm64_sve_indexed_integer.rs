//! SVE2 MLA/MLS/MUL by an indexed element, June2026 physical classes.
//! These nine forms use modulo arithmetic: no rounding, doubling, saturation,
//! QC or NZCV updates. The caller owns SVE2-or-SME/CheckSVEEnabled admission;
//! there is no additional non-streaming restriction. Z backing above CurrentVL
//! is preserved, the permitted non-SVEZEROUPPER accessor choice.
use super::*;
use BinaryOp as B;
fn c(w: u8, value: u64) -> Expr {
    Expr::constant(w, value)
}
fn b(op: B, left: Expr, right: Expr) -> Expr {
    Expr::binary(op, left, right)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut source = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    source.offset = (bit % 64) as u8;
    Expr::register(source)
}
/// None leaves unowned neighbors to their own helpers. All encoded indices are
/// allocated within their 128-bit segment. Owned invalid CurrentVL is Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let operation = word & 0x0000fc00;
    let accumulate = match operation {
        0x0800 => Some(B::Add),
        0x0c00 => Some(B::Sub),
        0xf800 => None,
        _ => return None,
    };
    let (w, index, m) = if word & 0xffa00000 == 0x44200000 {
        (
            16,
            (((word >> 22) & 1) << 2) | ((word >> 19) & 3),
            (word >> 16) & 7,
        )
    } else if word & 0xffe00000 == 0x44a00000 {
        (32, (word >> 19) & 3, (word >> 16) & 7)
    } else if word & 0xffe00000 == 0x44e00000 {
        (64, (word >> 20) & 1, (word >> 16) & 15)
    } else {
        return None;
    };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let lanes_per_segment = 128 / u16::from(w);
    for segment in 0..vl / 128 {
        // Capture exactly the selected lane once per segment. A destination
        // alias never feeds later segments: every register read is incoming.
        let multiplier = r.bind(lane(m, segment * lanes_per_segment + index as u16, w));
        for half in 0..2 {
            let chunk = segment * 2 + half;
            let mut packed = c(64, 0);
            for i in 0..64 / u16::from(w) {
                let e = chunk * (64 / u16::from(w)) + i;
                let product = b(B::Mul, lane(n, e, w), multiplier.clone());
                // Both the product and accumulation have esize-bit types,
                // retaining the primary product-truncate-then-add/sub order.
                let value = r.bind(if let Some(op) = accumulate {
                    b(op, lane(d, e, w), product)
                } else {
                    product
                });
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
    }
    Some(r)
}

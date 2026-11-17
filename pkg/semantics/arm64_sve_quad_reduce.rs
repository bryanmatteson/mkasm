//! SVE2p1/SME2p1 quadword integer reductions, June2026 physical definitions.
//! Each V128 element reduces the corresponding element position across all
//! active 128-bit segments, not adjacent elements within one segment. Feature
//! admission and CheckSVEEnabled are the generated caller's contract.
//! V128 writes zero bits128..CurrentVL and preserve backing above CurrentVL,
//! selecting the permitted non-SVEZEROUPPER accessor alternative.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn z(n: u32, k: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + k, 64, 64))
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
/// Unrelated physical families return None; invalid owned VL returns Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let op = match word & 0xff3fe000 {
        0x04052000 => 0, // ADDQV
        0x040c2000 => 1, // SMAXQV
        0x040e2000 => 2, // SMINQV
        0x040d2000 => 3, // UMAXQV
        0x040f2000 => 4, // UMINQV
        0x041e2000 => 5, // ANDQV
        0x041d2000 => 6, // EORQV
        0x041c2000 => 7, // ORQV
        _ => return None,
    };
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid SVE CurrentVL",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let g = (word >> 10) & 7;
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
    let identity = match op {
        1 => 1u64 << (w - 1),
        2 => (1u64 << (w - 1)) - 1,
        4 | 5 => {
            if w == 64 {
                u64::MAX
            } else {
                (1u64 << w) - 1
            }
        }
        _ => 0,
    };
    let per = 128 / u16::from(w);
    let mut result = Vec::with_capacity(per as usize);
    for e in 0..per {
        let mut accumulator = c(w, identity);
        for segment in 0..vl / 128 {
            let index = segment * per + e;
            let bit = index * u16::from(w / 8);
            let active = r.bind(Expr::extract(
                predicates[(bit / 64) as usize].clone(),
                (bit % 64) as u8,
                1,
            ));
            // Inactive source lanes are not required, even if another lane in
            // this source register is active. Capture once before any writes.
            let value = r.bind(Expr::select(active.clone(), lane(n, index, w), c(w, 0)));
            let combined = match op {
                0 => b(B::Add, accumulator.clone(), value),
                5 => b(B::And, accumulator.clone(), value),
                6 => b(B::Xor, accumulator.clone(), value),
                7 => b(B::Or, accumulator.clone(), value),
                _ => {
                    let cmp = if op <= 2 { B::Slt } else { B::Ult };
                    let less = if op == 1 || op == 3 {
                        b(cmp, accumulator.clone(), value.clone())
                    } else {
                        b(cmp, value.clone(), accumulator.clone())
                    };
                    Expr::select(less, value, accumulator.clone())
                }
            };
            accumulator = r.bind(Expr::select(active, combined, accumulator));
        }
        result.push(accumulator);
    }
    for (k, values) in result.chunks(64 / usize::from(w)).enumerate() {
        let mut packed = c(64, 0);
        for (i, value) in values.iter().enumerate() {
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value.clone(), 64, false),
                    c(64, (i * usize::from(w)) as u64),
                ),
            );
        }
        let packed = r.bind(packed);
        r.write(
            register("a64.vector64", d as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    for k in 2..vl / 64 {
        r.write(
            register("a64.vector64", d as u16 * 32 + k, 64, 64),
            WritePolicy::ZeroUpper,
            c(64, 0),
        );
    }
    Some(r)
}

//! Remaining ordinary integer Advanced SIMD comparisons, modified immediates,
//! and unsigned reciprocal estimates, from the Arm 2026-06 primary XML/ASL.
//! No FP environment, NZCV, or saturation state is read or changed. Feature and
//! FP/Advanced SIMD access checks remain the caller's responsibility.
use super::*;
use BinaryOp as B;
fn c(w: u8, x: u64) -> Expr {
    Expr::constant(w, x)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn not(x: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, x)
}
fn vector(n: u32, chunk: u16) -> RegisterSlice {
    register("a64.vector64", n as u16 * 32 + chunk, 64, 64)
}
fn source(r: &mut Recipe, n: u32, bits: u16) -> Vec<Expr> {
    (0..bits.div_ceil(64))
        .map(|i| r.bind(Expr::register(vector(n, i))))
        .collect()
}
fn lane(chunks: &[Expr], i: u16, w: u8) -> Expr {
    let bit = i * u16::from(w);
    Expr::extract(chunks[(bit / 64) as usize].clone(), (bit % 64) as u8, w)
}
fn finish(mut r: Recipe, d: u32, lanes: Vec<Expr>) -> Option<Recipe> {
    let mut chunks = vec![];
    let mut offset = 0u8;
    let mut chunk = c(64, 0);
    for x in lanes {
        let w = x.ty.width;
        chunk = b(
            B::Or,
            chunk,
            b(B::Shl, Expr::cast(x, 64, false), c(64, u64::from(offset))),
        );
        offset += w;
        if offset == 64 {
            chunks.push(r.bind(chunk));
            chunk = c(64, 0);
            offset = 0;
        }
    }
    if offset != 0 {
        chunks.push(r.bind(chunk));
    }
    // A V{64} or scalar write clears the upper half. Bind all output values
    // before writing either chunk so every source/destination alias is safe.
    for i in 0..2 {
        let value = chunks.get(i).cloned().unwrap_or_else(|| c(64, 0));
        r.write(vector(d, i as u16), WritePolicy::ZeroUpper, value);
    }
    Some(r)
}
fn reserved(mut r: Recipe) -> Option<Recipe> {
    r.support = Support::Unsupported("reserved A64 integer SIMD extra selector");
    Some(r)
}
#[derive(Clone, Copy)]
enum Compare {
    Eq,
    Ge,
    Gt,
    Hi,
    Hs,
    Le,
    Lt,
    Test,
}
fn predicate(op: Compare, x: Expr, y: Expr) -> Expr {
    match op {
        Compare::Eq => b(B::Eq, x, y),
        Compare::Ge => not(b(B::Slt, x, y)),
        Compare::Gt => b(B::Slt, y, x),
        Compare::Hi => b(B::Ult, y, x),
        Compare::Hs => not(b(B::Ult, x, y)),
        Compare::Le => not(b(B::Slt, y, x)),
        Compare::Lt => b(B::Slt, x, y),
        Compare::Test => {
            let w = x.ty.width;
            not(b(B::Eq, b(B::And, x, y), c(w, 0)))
        }
    }
}
fn compare(word: u32, mut r: Recipe) -> Option<Recipe> {
    let scalar = word & (1 << 28) != 0;
    // Scalar diagrams fix size=11; do not take authority over adjacent scalar
    // FP encodings with different fixed size bits.
    let (op, zero) = if scalar {
        match word & 0xffff_fc00 {
            0x5ee0_9800 => (Compare::Eq, true),
            0x7ee0_8800 => (Compare::Ge, true),
            0x5ee0_8800 => (Compare::Gt, true),
            0x7ee0_9800 => (Compare::Le, true),
            0x5ee0_a800 => (Compare::Lt, true),
            _ => match word & 0xffe0_fc00 {
                0x7ee0_8c00 => (Compare::Eq, false),
                0x5ee0_3c00 => (Compare::Ge, false),
                0x5ee0_3400 => (Compare::Gt, false),
                0x7ee0_3400 => (Compare::Hi, false),
                0x7ee0_3c00 => (Compare::Hs, false),
                0x5ee0_8c00 => (Compare::Test, false),
                _ => return None,
            },
        }
    } else {
        match word & 0xbf3f_fc00 {
            0x0e20_9800 => (Compare::Eq, true),
            0x2e20_8800 => (Compare::Ge, true),
            0x0e20_8800 => (Compare::Gt, true),
            0x2e20_9800 => (Compare::Le, true),
            0x0e20_a800 => (Compare::Lt, true),
            _ => match word & 0xbf20_fc00 {
                0x2e20_8c00 => (Compare::Eq, false),
                0x0e20_3c00 => (Compare::Ge, false),
                0x0e20_3400 => (Compare::Gt, false),
                0x2e20_3400 => (Compare::Hi, false),
                0x2e20_3c00 => (Compare::Hs, false),
                0x0e20_8c00 => (Compare::Test, false),
                _ => return None,
            },
        }
    };
    let q = word & (1 << 30) != 0;
    let w = 8u8 << ((word >> 22) & 3);
    if !scalar && w == 64 && !q {
        return reserved(r);
    }
    let bits = if scalar || !q { 64 } else { 128 };
    let xs = source(&mut r, (word >> 5) & 31, bits);
    let ys = if zero {
        vec![]
    } else {
        source(&mut r, (word >> 16) & 31, bits)
    };
    let lanes = (0..bits / u16::from(w))
        .map(|i| {
            let x = lane(&xs, i, w);
            let y = if zero { c(w, 0) } else { lane(&ys, i, w) };
            Expr::select(predicate(op, x, y), c(w, u64::MAX), c(w, 0))
        })
        .collect();
    finish(r, word & 31, lanes)
}
// AdvSIMDExpandImm, integer encodings only. cmode=1111 belongs to FP MOV.
fn expanded(cmode: u32, op: bool, imm: u64) -> u64 {
    let (value, width) = match cmode >> 1 {
        0..=3 => (imm << (8 * (cmode >> 1)), 32),
        4..=5 => (imm << (8 * ((cmode >> 1) - 4)), 16),
        6 => {
            if cmode & 1 == 0 {
                ((imm << 8) | 0xff, 32)
            } else {
                ((imm << 16) | 0xffff, 32)
            }
        }
        7 if !op => (imm, 8),
        7 => {
            return (0..8).fold(0, |v, i| {
                v | (if imm & (1 << i) != 0 {
                    0xffu64 << (8 * i)
                } else {
                    0
                })
            })
        }
        _ => unreachable!(),
    };
    (0..64 / width).fold(0, |v, i| v | (value << (i * width)))
}
fn immediate(word: u32, mut r: Recipe) -> Option<Recipe> {
    if word & 0x9ff8_0c00 != 0x0f00_0400 {
        return None;
    }
    let cmode = (word >> 12) & 15;
    if cmode == 15 {
        return None;
    }
    let op = word & (1 << 29) != 0;
    let imm = u64::from(((word >> 16) & 7) << 5 | ((word >> 5) & 31));
    let value = expanded(cmode, op, imm);
    let modify = cmode < 12 && cmode & 1 != 0;
    let invert = op && cmode != 14;
    let value = if invert { !value } else { value };
    let chunks = if word & (1 << 30) != 0 { 2 } else { 1 };
    let lanes = (0..chunks)
        .map(|i| {
            if modify {
                let old = r.bind(Expr::register(vector(word & 31, i)));
                b(if op { B::And } else { B::Or }, old, c(64, value))
            } else {
                c(64, value)
            }
        })
        .collect();
    finish(r, word & 31, lanes)
}
fn reciprocal(r: &mut Recipe, x: Expr) -> Expr {
    let a = r.bind(b(B::Lsr, x.clone(), c(32, 23)));
    let denominator = b(B::Add, b(B::Shl, a, c(32, 1)), c(32, 1));
    let quotient = b(B::Udiv, c(32, 1 << 19), denominator);
    let rounded = b(B::Lsr, b(B::Add, quotient, c(32, 1)), c(32, 1));
    Expr::select(
        b(B::Ult, x, c(32, 0x8000_0000)),
        c(32, 0xffff_ffff),
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
    // Exact integer binary search replacing RecipSqrtEstimate's bounded loop.
    // For valid inputs a=257..1022, the largest b with a*b*b < 2^28 is
    // 512..1023; every product fits u32. Bind each stage to keep the graph linear.
    let mut root = c(32, 512);
    for bit in (0..9).rev() {
        let candidate = r.bind(b(B::Add, root.clone(), c(32, 1 << bit)));
        let square = b(B::Mul, candidate.clone(), candidate.clone());
        let below = b(B::Ult, b(B::Mul, a.clone(), square), c(32, 1 << 28));
        root = r.bind(Expr::select(below, candidate, root));
    }
    let rounded = b(B::Lsr, b(B::Add, root, c(32, 1)), c(32, 1));
    Expr::select(
        b(B::Ult, x, c(32, 0x4000_0000)),
        c(32, 0xffff_ffff),
        b(B::Shl, rounded, c(32, 23)),
    )
}
fn estimate(word: u32, mut r: Recipe) -> Option<Recipe> {
    let sqrt = match word & 0xbfbf_fc00 {
        0x0ea1_c800 => false,
        0x2ea1_c800 => true,
        _ => return None,
    };
    if word & (1 << 22) != 0 {
        return reserved(r);
    }
    let bits = if word & (1 << 30) != 0 { 128 } else { 64 };
    let xs = source(&mut r, (word >> 5) & 31, bits);
    let mut result = vec![];
    for i in 0..bits / 32 {
        let x = r.bind(lane(&xs, i, 32));
        result.push(if sqrt {
            reciprocal_sqrt(&mut r, x)
        } else {
            reciprocal(&mut r, x)
        });
    }
    finish(r, word & 31, result)
}
/// Physical A64 word to a complete ordinary integer Advanced SIMD recipe.
/// None leaves other integer/FP/scalable/memory families to their own builder.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    let r = Recipe::new(address.wrapping_add(4), 64);
    immediate(word, r.clone())
        .or_else(|| compare(word, r.clone()))
        .or_else(|| estimate(word, r))
}

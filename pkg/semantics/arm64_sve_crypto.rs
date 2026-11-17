//! Single-vector SVE cryptographic operations from Arm June 2026 ASL.
//! AES and SM4 reuse the audited fixed-width pure integer graphs separately
//! for every 128-bit segment. Every graph input and intermediate is captured
//! before pending outputs, including overlapping source/key/destination Zs.
//! Existing SVE bit permutations, ternary logical operations and XAR are
//! delegated to their existing owner. PMULLB/T remain owned there as well.
//! CurrentVL is SVL in streaming mode; feature/access admission is caller-owned.
//! Required effective streaming inputs are a64.sme_fa64, a64.ssve_aes and
//! a64.sme2p1 (one-bit bank0), plus existing a64.ssve_bitperm for bitperm.
//! a64.svcr bank0 bit0 is SM. Writes preserve chunks beyond CurrentVL (the
//! permitted SVEZEROUPPER=false choice). No FP state, memory or opaque engine.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, l: Expr, r: Expr) -> Expr {
    Expr::binary(op, l, r)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn guard(r: &mut Recipe, extension: Option<&'static str>) {
    let fa = Expr::register(register("a64.sme_fa64", 0, 1, 1));
    let allowed = if let Some(bank) = extension {
        // Feature flags are seeded independently; effective FA64 may be
        // unavailable. An enabling extension must not read that fallback.
        Expr::select(Expr::register(register(bank, 0, 1, 1)), c(1, 1), fa)
    } else {
        fa
    };
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    // This check returns true or faults; it never predicates the operation
    // false. Capture it first so subsequent SSA statements need no duplicated
    // guard. Disabled/unavailable context still faults before vector inputs.
    r.bind(Expr::require_context(
        Expr::select(sm, allowed, c(1, 1)),
        "SVE crypto streaming requires effective FA64 or its architectural streaming extension",
    ));
}
// Only pure graph kinds used by audited AES/SM4 are accepted. A future wider
// fixed-helper contract cannot accidentally acquire partial SVE semantics.
fn rebase(mut expression: Expr, segment: u16, temporaries: usize) -> Option<Expr> {
    match &mut expression.kind {
        ExprKind::Constant(_) => {}
        ExprKind::Register(slice) => {
            if slice.register.bank != "a64.vector64" || slice.register.index % 32 >= 2 {
                return None;
            }
            slice.register.index += segment * 2;
        }
        ExprKind::Temporary(index) => *index += temporaries,
        ExprKind::Unary { value, .. }
        | ExprKind::Cast { value, .. }
        | ExprKind::Extract { value, .. } => {
            **value = rebase((**value).clone(), segment, temporaries)?
        }
        ExprKind::Binary { left, right, .. } => {
            **left = rebase((**left).clone(), segment, temporaries)?;
            **right = rebase((**right).clone(), segment, temporaries)?;
        }
        ExprKind::Select { condition, yes, no } => {
            **condition = rebase((**condition).clone(), segment, temporaries)?;
            **yes = rebase((**yes).clone(), segment, temporaries)?;
            **no = rebase((**no).clone(), segment, temporaries)?;
        }
        _ => return None,
    }
    Some(expression)
}
fn segment_graph(r: &mut Recipe, word: u32, address: u64, segment: u16) -> Option<()> {
    let child = arm64_crypto::a64(word, address)?;
    if child.support != Support::Full
        || child.guard != c(1, 1)
        || child.flow.kind != FlowKind::Next
        || !child.atomics.is_empty()
        || !child.wide_loads.is_empty()
        || !child.always_writes.is_empty()
    {
        return None;
    }
    let first = r.temporaries.len();
    for expression in child.temporaries {
        r.temporaries.push(rebase(expression, segment, first)?);
    }
    for effect in child.effects {
        let Effect::WriteRegister {
            mut destination,
            policy,
            value,
        } = effect
        else {
            return None;
        };
        if destination.register.bank != "a64.vector64" || destination.register.index % 32 >= 2 {
            return None;
        }
        destination.register.index += segment * 2;
        r.write(destination, policy, rebase(value, segment, first)?);
    }
    Some(())
}
fn outputs(r: &mut Recipe, d: u32, values: Vec<Expr>, w: u8) {
    let mut chunks = vec![];
    for lanes in values.chunks(64 / usize::from(w)) {
        let value = lanes.iter().enumerate().fold(c(64, 0), |a, (i, v)| {
            b(
                B::Or,
                a,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), 64, false),
                    c(64, i as u64 * u64::from(w)),
                ),
            )
        });
        chunks.push(r.bind(value));
    }
    for (i, value) in chunks.into_iter().enumerate() {
        r.write(
            register("a64.vector64", d as u16 * 32 + i as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
/// AESE/AESD/AESMC/AESIMC, SM4E/SM4EKEY, RAX1, PMUL, and the existing
/// EOR3/BCAX/XAR and BDEP/BEXT/BGRP classes. Polynomial long forms are delegated
/// by normal dispatch to arm64_sve rather than claimed by this helper.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let two = word & 0xfffffc00;
    let one = word & 0xffffffe0;
    let three = word & 0xffe0fc00;
    let variable = word & 0xff20fc00;
    let fixed = match two {
        0x4522e000 => Some((0x4e284800 | (n << 5) | d, true)),
        0x4522e400 => Some((0x4e285800 | (n << 5) | d, true)),
        0x4523e000 => Some((0xcec08400 | (n << 5) | d, false)),
        _ => match one {
            0x4520e000 => Some((0x4e286800 | (d << 5) | d, true)),
            0x4520e400 => Some((0x4e287800 | (d << 5) | d, true)),
            _ => {
                if three == 0x4520f000 {
                    Some((0xce60c800 | (m << 16) | (n << 5) | d, false))
                } else {
                    None
                }
            }
        },
    };
    let delegate = matches!(three, 0x04203800 | 0x04603800)
        || matches!(variable, 0x4500b000 | 0x4500b400 | 0x4500b800)
        || variable == 0x04203400;
    if variable == 0x04203400 && (((word >> 22) & 3) << 2 | ((word >> 19) & 3)) == 0 {
        return None;
    }
    if fixed.is_none() && !delegate && !matches!(three, 0x4520f400 | 0x04206400) {
        return None;
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "SVE crypto CurrentVL must be an architectural power of two from 128 to 2048",
            address.wrapping_add(4),
            64,
        ));
    }
    if delegate {
        return arm64_sve::a64(word, address, Endian::Little, vl);
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if let Some((encoding, aes)) = fixed {
        guard(&mut r, if aes { Some("a64.ssve_aes") } else { None });
        for segment in 0..vl / 128 {
            segment_graph(&mut r, encoding, address, segment)?;
        }
    } else if three == 0x4520f400 {
        guard(&mut r, Some("a64.sme2p1"));
        let values = (0..vl / 64)
            .map(|e| b(B::Xor, lane(n, e, 64), b(B::Ror, lane(m, e, 64), c(64, 63))))
            .collect();
        outputs(&mut r, d, values, 64);
    } else {
        let mut values = vec![];
        for e in 0..vl / 8 {
            let left = r.bind(lane(n, e, 8));
            let right = r.bind(lane(m, e, 8));
            let mut value = c(8, 0);
            for bit in 0..8 {
                value = b(
                    B::Xor,
                    value,
                    Expr::select(
                        Expr::extract(right.clone(), bit, 1),
                        b(B::Shl, left.clone(), c(8, u64::from(bit))),
                        c(8, 0),
                    ),
                );
            }
            values.push(value);
        }
        outputs(&mut r, d, values, 8);
    }
    Some(r)
}

//! Fixed-width A64 integer Advanced SIMD recipes from the 2026-06 Arm corpus.
//! Vector registers use two existing a64.vector64 chunks, index Vn*32+chunk.
//! Feature legality and FP/Advanced SIMD access controls remain caller-owned.
//! Every result is captured before effects, including aliased table registers.
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
fn eq(a: Expr, z: Expr) -> Expr {
    b(B::Eq, a, z)
}
fn sel(p: Expr, a: Expr, z: Expr) -> Expr {
    Expr::select(p, a, z)
}
fn cast(a: Expr, w: u8, signed: bool) -> Expr {
    Expr::cast(a, w, signed)
}
fn ext(a: Expr, o: u8, w: u8) -> Expr {
    Expr::extract(a, o, w)
}
fn vector(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn lane(n: u32, i: u8, w: u8) -> Expr {
    let bit = u16::from(i) * u16::from(w);
    ext(vector(n, bit / 64), (bit % 64) as u8, w)
}
fn pack(parts: &[Expr]) -> Expr {
    let mut result = c(64, 0);
    let mut offset = 0;
    for p in parts {
        result = b(
            B::Or,
            result,
            b(B::Shl, cast(p.clone(), 64, false), c(64, offset)),
        );
        offset += u64::from(p.ty.width);
    }
    result
}
fn write_chunk(r: &mut Recipe, n: u32, chunk: u16, value: Expr) {
    r.write(
        register("a64.vector64", n as u16 * 32 + chunk, 64, 64),
        WritePolicy::ZeroUpper,
        value,
    );
}
// All bindings run before architectural effects. Scalar and 64-bit vector
// writes zero the rest of Vd; *2 narrowing writes preserve the low 64 bits.
fn finish(
    mut r: Recipe,
    d: u32,
    parts: Vec<Expr>,
    high_only: bool,
    qc: Option<Expr>,
) -> Option<Recipe> {
    let mut chunks = vec![];
    let mut group = vec![];
    let mut bits = 0;
    for p in parts {
        bits += u16::from(p.ty.width);
        group.push(p);
        if bits == 64 {
            chunks.push(r.bind(pack(&group)));
            group.clear();
            bits = 0;
        }
    }
    if !group.is_empty() {
        chunks.push(r.bind(pack(&group)));
    }
    let qc = qc.map(|s| {
        let mut flag = register("a64.fpsr", 0, 1, 32);
        flag.offset = 27;
        (flag, r.bind(b(B::Or, Expr::register(flag), s)))
    });
    if high_only {
        write_chunk(&mut r, d, 1, chunks.remove(0));
    } else {
        for chunk in 0..2 {
            write_chunk(
                &mut r,
                d,
                chunk,
                chunks
                    .get(chunk as usize)
                    .cloned()
                    .unwrap_or_else(|| c(64, 0)),
            );
        }
    }
    if let Some((flag, value)) = qc {
        r.write(flag, WritePolicy::Preserve, value);
    }
    Some(r)
}
fn reject(mut r: Recipe) -> Option<Recipe> {
    r.support = Support::Unsupported("reserved A64 integer SIMD encoding");
    Some(r)
}
fn saturation(a: Expr, z: Expr, signed: bool, sub: bool) -> (Expr, Expr) {
    let w = a.ty.width;
    let value = b(if sub { B::Sub } else { B::Add }, a.clone(), z.clone());
    let sat = if signed {
        Expr::overflow(sub, a.clone(), z, value.clone())
    } else if sub {
        Expr::sub_borrow(a.clone(), z, c(1, 0))
    } else {
        Expr::add_carry(a.clone(), z, c(1, 0))
    };
    let bound = if signed {
        sel(ext(a, w - 1, 1), c(w, 1u64 << (w - 1)), c(w, mask(w - 1)))
    } else {
        c(w, if sub { 0 } else { mask(w) })
    };
    (sel(sat.clone(), bound, value), sat)
}
fn clamp(value: Expr, signed_in: bool, w: u8, signed_out: bool) -> (Expr, Expr) {
    let width = value.ty.width;
    let low = if signed_out {
        !mask(w - 1) & mask(width)
    } else {
        0
    };
    let high = if signed_out { mask(w - 1) } else { mask(w) };
    let below = if signed_in {
        b(B::Slt, value.clone(), c(width, low))
    } else {
        c(1, 0)
    };
    let above = b(
        if signed_in { B::Slt } else { B::Ult },
        c(width, high),
        value.clone(),
    );
    (
        cast(
            sel(
                below.clone(),
                c(width, low),
                sel(above.clone(), c(width, high), value),
            ),
            w,
            false,
        ),
        b(B::Or, below, above),
    )
}
// Quotient plus highest discarded bit implements RShr without overflowing a
// 64-bit rounding addition. Width-sized shifts and signed ties remain exact.
fn right(value: Expr, amount: Expr, signed: bool, round: bool) -> Expr {
    let w = value.ty.width;
    let amount = cast(amount, w, false);
    let shifted = b(
        if signed { B::Asr } else { B::Lsr },
        value.clone(),
        amount.clone(),
    );
    if !round {
        return shifted;
    }
    let bit = ext(b(B::Lsr, value, b(B::Sub, amount.clone(), c(w, 1))), 0, 1);
    let valid = b(
        B::And,
        not(eq(amount.clone(), c(w, 0))),
        not(b(B::Ult, c(w, u64::from(w)), amount.clone())),
    );
    let result = b(B::Add, shifted, cast(sel(valid, bit, c(1, 0)), w, false));
    sel(b(B::Ult, c(w, u64::from(w)), amount), c(w, 0), result)
}
fn left_sat(value: Expr, amount: Expr, signed: bool, unsigned_out: bool) -> (Expr, Expr) {
    let w = value.ty.width;
    let amount = cast(amount, w, false);
    let shifted = b(B::Shl, value.clone(), amount.clone());
    let reversed = b(
        if signed && !unsigned_out {
            B::Asr
        } else {
            B::Lsr
        },
        shifted.clone(),
        amount.clone(),
    );
    let large = not(b(B::Ult, amount, c(w, u64::from(w))));
    let negative = if signed {
        ext(value.clone(), w - 1, 1)
    } else {
        c(1, 0)
    };
    let lost = sel(
        large,
        not(eq(value.clone(), c(w, 0))),
        not(eq(value, reversed)),
    );
    let sat = if signed && unsigned_out {
        b(B::Or, lost, negative.clone())
    } else {
        lost
    };
    let bound = if unsigned_out {
        sel(negative, c(w, 0), c(w, mask(w)))
    } else {
        sel(negative, c(w, 1u64 << (w - 1)), c(w, mask(w - 1)))
    };
    (sel(sat.clone(), bound, shifted), sat)
}
fn minmax(a: Expr, z: Expr, signed: bool, minimum: bool) -> Expr {
    let less = b(if signed { B::Slt } else { B::Ult }, a.clone(), z.clone());
    if minimum {
        sel(less, a, z)
    } else {
        sel(less, z, a)
    }
}

/// Return None for an unowned physical group; recognized invalid fields return
/// Unsupported. These recipes do not infer feature availability from encodings.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    // Integer scalar Advanced SIMD occupies the 0x5e/0x7e and0x5f/0x7f
    // major groups. Clearing scalar discriminator bits below is valid only
    // after excluding the adjacent ordinary scalar-FP 0x1e/0x1f groups.
    if word & 0x8e00_0000 != 0x0e00_0000 || (word & (1 << 28) != 0 && word & (1 << 30) == 0) {
        return None;
    }
    let r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let q = word & (1 << 30) != 0;
    let size = (word >> 22) & 3;
    let w = 8u8 << size;
    let scalar = word & (1 << 28) != 0;
    let count = if scalar {
        1
    } else {
        if q {
            128 / w
        } else {
            64 / w
        }
    };
    let unsigned = word & (1 << 29) != 0;
    let v3 = word & 0xbf20fc00;
    let s3 = word & 0xff20fc00;
    let v2 = word & 0xbf3ffc00;
    let s2 = word & 0xff3ffc00;
    // Modular lane add/subtract, including the scalar D forms.
    if matches!(v3, 0x0e208400 | 0x2e208400) || matches!(s3, 0x5e208400 | 0x7e208400) {
        if (scalar && size != 3) || (!scalar && size == 3 && !q) {
            return reject(r);
        }
        let parts = (0..count)
            .map(|i| {
                b(
                    if unsigned { B::Sub } else { B::Add },
                    lane(n, i, w),
                    lane(m, i, w),
                )
            })
            .collect();
        return finish(r, d, parts, false, None);
    }
    // Element copies and general-register transfers. Ignored low source-index
    // bits remain ignored; GPR register 31 is ZR, never SP.
    let copy = word & 0xbfe0fc00;
    let dup_scalar = word & 0xffe0fc00 == 0x5e000400;
    let insert_vector = word & 0xffe08400 == 0x6e000400;
    let insert_general = word & 0xffe0fc00 == 0x4e001c00;
    if dup_scalar
        || insert_vector
        || insert_general
        || matches!(copy, 0x0e000400 | 0x0e000c00 | 0x0e002c00 | 0x0e003c00)
    {
        let imm = ((word >> 16) & 31) as u8;
        let signed_move = copy == 0x0e002c00;
        if imm & if signed_move { 7 } else { 15 } == 0 {
            return reject(r);
        }
        let size = (imm & if signed_move { 7 } else { 15 }).trailing_zeros() as u8;
        let width = 8u8 << size;
        let index = imm >> (size + 1);
        let general = copy == 0x0e000c00 || insert_general;
        let gpr = || {
            if n == 31 {
                c(width, 0)
            } else {
                Expr::register(register("a64.gpr", n as u16, width, 64))
            }
        };
        if insert_vector || insert_general {
            let source = if general {
                gpr()
            } else {
                lane(n, ((word >> 11) & 15) as u8 >> size, width)
            };
            let mut parts = vec![];
            for i in 0..128 / width {
                parts.push(if i == index {
                    source.clone()
                } else {
                    lane(d, i, width)
                });
            }
            return finish(r, d, parts, false, None);
        }
        if matches!(copy, 0x0e002c00 | 0x0e003c00) {
            let datasize = if q { 64 } else { 32 };
            if signed_move {
                if datasize <= width {
                    return reject(r);
                }
            } else if (q && width != 64) || (!q && width == 64) {
                return reject(r);
            }
            let mut r = r;
            if d != 31 {
                let value = r.bind(cast(lane(n, index, width), datasize, signed_move));
                r.write(
                    register("a64.gpr", d as u16, datasize, 64),
                    WritePolicy::ZeroUpper,
                    value,
                );
            }
            return Some(r);
        }
        if !dup_scalar && width == 64 && !q {
            return reject(r);
        }
        let value = if general {
            gpr()
        } else {
            lane(n, index, width)
        };
        let count = if dup_scalar {
            1
        } else if q {
            128 / width
        } else {
            64 / width
        };
        return finish(
            r,
            d,
            (0..count).map(|_| value.clone()).collect(),
            false,
            None,
        );
    }
    // Mixed signed/unsigned accumulate saturates without needing a 65-bit
    // expression for D lanes. Thresholds and carry/borrow remain exact.
    if matches!(v2, 0x0e203800 | 0x2e203800) || matches!(s2, 0x5e203800 | 0x7e203800) {
        if !scalar && w == 64 && !q {
            return reject(r);
        }
        let mut parts = vec![];
        let mut all = c(1, 0);
        for i in 0..count {
            let a = lane(d, i, w);
            let z = lane(n, i, w);
            let sum = b(B::Add, a.clone(), z.clone());
            let (sat, bound) = if unsigned {
                let neg = ext(z.clone(), w - 1, 1);
                (
                    sel(
                        neg.clone(),
                        b(B::Ult, a.clone(), Expr::unary(UnaryOp::Neg, z.clone())),
                        Expr::add_carry(a, z, c(1, 0)),
                    ),
                    sel(neg, c(w, 0), c(w, mask(w))),
                )
            } else {
                (
                    b(B::Ult, b(B::Sub, c(w, mask(w - 1)), a), z),
                    c(w, mask(w - 1)),
                )
            };
            parts.push(sel(sat.clone(), bound, sum));
            all = b(B::Or, all, sat);
        }
        return finish(r, d, parts, false, Some(all));
    }
    // Halving arithmetic widens before addition/subtraction and truncation.
    if matches!(v3 & !0x20000000, 0x0e200400 | 0x0e201400 | 0x0e202400) {
        if size == 3 {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..count {
            let a = cast(lane(n, i, w), w * 2, !unsigned);
            let z = cast(lane(m, i, w), w * 2, !unsigned);
            let mut sum = b(
                if word & (1 << 13) != 0 {
                    B::Sub
                } else {
                    B::Add
                },
                a,
                z,
            );
            if word & (1 << 12) != 0 {
                sum = b(B::Add, sum, c(w * 2, 1));
            }
            parts.push(cast(b(B::Asr, sum, c(w * 2, 1)), w, false));
        }
        return finish(r, d, parts, false, None);
    }
    // Narrow the high half of a modular wide sum/difference, optionally rounded.
    if matches!(v3 & !0x20000000, 0x0e204000 | 0x0e206000) {
        if w == 64 {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..64 / w {
            let mut sum = b(
                if word & (1 << 13) != 0 {
                    B::Sub
                } else {
                    B::Add
                },
                lane(n, i, w * 2),
                lane(m, i, w * 2),
            );
            if unsigned {
                sum = b(B::Add, sum, c(w * 2, 1u64 << (w - 1)));
            }
            parts.push(ext(sum, w, w));
        }
        return finish(r, d, parts, q, None);
    }
    // Pairwise add-long, optionally accumulating into the original wider lane.
    if matches!(v2 & !0x20000000, 0x0e202800 | 0x0e206800) {
        if size == 3 {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..count / 2 {
            let sum = b(
                B::Add,
                cast(lane(n, i * 2, w), w * 2, !unsigned),
                cast(lane(n, i * 2 + 1, w), w * 2, !unsigned),
            );
            parts.push(if word & (1 << 14) != 0 {
                b(B::Add, lane(d, i, w * 2), sum)
            } else {
                sum
            });
        }
        return finish(r, d, parts, false, None);
    }
    // Widening absolute difference, optionally accumulated modulo wide width.
    if matches!(v3 & !0x20000000, 0x0e205000 | 0x0e207000) {
        if size == 3 {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..64 / w {
            let offset = if q { 64 / w } else { 0 };
            let a = cast(lane(n, i + offset, w), w * 2, !unsigned);
            let z = cast(lane(m, i + offset, w), w * 2, !unsigned);
            let less = b(if unsigned { B::Ult } else { B::Slt }, a.clone(), z.clone());
            let diff = sel(less, b(B::Sub, z.clone(), a.clone()), b(B::Sub, a, z));
            parts.push(if word & (1 << 13) == 0 {
                b(B::Add, lane(d, i, w * 2), diff)
            } else {
                diff
            });
        }
        return finish(r, d, parts, false, None);
    }
    // Saturating doubling products and RDM. High products divide before the
    // double, avoiding a 65-bit intermediate; the accumulator is added after
    // exact signed rounding, with one final saturation for RDM.
    let product_vec = if scalar { s3 & !0x50000000 } else { v3 };
    let product_elt = if scalar {
        (word & 0xff00f400) & !0x50000000
    } else {
        word & 0xbf00f400
    };
    let pvec = matches!(
        product_vec,
        0x0e20b400 | 0x2e20b400 | 0x2e008400 | 0x2e008c00 | 0x0e209000 | 0x0e20b000 | 0x0e20d000
    );
    let pelt = matches!(
        product_elt,
        0x0f00c000 | 0x0f00d000 | 0x2f00d000 | 0x2f00f000 | 0x0f003000 | 0x0f007000 | 0x0f00b000
    );
    if pvec || pelt {
        if size != 1 && size != 2 {
            return reject(r);
        }
        let long = if pvec {
            matches!(product_vec, 0x0e209000 | 0x0e20b000 | 0x0e20d000)
        } else {
            matches!(product_elt, 0x0f003000 | 0x0f007000 | 0x0f00b000)
        };
        let accumulate = if pvec {
            matches!(
                product_vec,
                0x2e008400 | 0x2e008c00 | 0x0e209000 | 0x0e20b000
            )
        } else {
            matches!(
                product_elt,
                0x2f00d000 | 0x2f00f000 | 0x0f003000 | 0x0f007000
            )
        };
        let subtract = if pvec {
            matches!(product_vec, 0x2e008c00 | 0x0e20b000)
        } else {
            matches!(product_elt, 0x2f00f000 | 0x0f007000)
        };
        let round = if pvec {
            product_vec == 0x2e20b400 || !long && accumulate
        } else {
            product_elt != 0x0f00c000 && !long
        };
        let index = if size == 1 {
            (((word >> 11) & 1) << 2) | (((word >> 21) & 1) << 1) | ((word >> 20) & 1)
        } else {
            (((word >> 11) & 1) << 1) | ((word >> 21) & 1)
        };
        let rm = if pelt && size == 1 { m & 15 } else { m };
        let mut parts = vec![];
        let mut all = c(1, 0);
        for i in 0..if scalar {
            1
        } else if long {
            64 / w
        } else {
            count
        } {
            let off = if long && !scalar && q { 64 / w } else { 0 };
            let product = b(
                B::Mul,
                cast(lane(n, i + off, w), w * 2, true),
                cast(
                    lane(rm, if pelt { index as u8 } else { i + off }, w),
                    w * 2,
                    true,
                ),
            );
            let (value, sat) = if long {
                let (doubled, s1) = saturation(product.clone(), product, true, false);
                if accumulate {
                    let (v, s2) = saturation(lane(d, i, w * 2), doubled, true, subtract);
                    (v, b(B::Or, s1, s2))
                } else {
                    (doubled, s1)
                }
            } else {
                let product = if subtract {
                    Expr::unary(UnaryOp::Neg, product)
                } else {
                    product
                };
                let mut high = right(product, c(w * 2, u64::from(w - 1)), true, round);
                if accumulate {
                    high = b(B::Add, cast(lane(d, i, w), w * 2, true), high);
                }
                clamp(high, true, w, true)
            };
            parts.push(value);
            all = b(B::Or, all, sat);
        }
        return finish(r, d, parts, false, Some(all));
    }
    // Saturating addition/subtraction, including all scalar lane sizes.
    if matches!(v3, 0x0e200c00 | 0x2e200c00 | 0x0e202c00 | 0x2e202c00)
        || matches!(s3, 0x5e200c00 | 0x7e200c00 | 0x5e202c00 | 0x7e202c00)
    {
        if !scalar && w == 64 && !q {
            return reject(r);
        }
        let mut parts = vec![];
        let mut sat = c(1, 0);
        for i in 0..count {
            let (v, s) = saturation(
                lane(n, i, w),
                lane(m, i, w),
                !unsigned,
                word & (1 << 13) != 0,
            );
            parts.push(v);
            sat = b(B::Or, sat, s);
        }
        return finish(r, d, parts, false, Some(sat));
    }
    // Saturating absolute/negate, with signed MIN -> MAX and cumulative QC.
    if matches!(v2, 0x0e207800 | 0x2e207800) || matches!(s2, 0x5e207800 | 0x7e207800) {
        if !scalar && w == 64 && !q {
            return reject(r);
        }
        let mut parts = vec![];
        let mut sat = c(1, 0);
        for i in 0..count {
            let a = lane(n, i, w);
            let s = eq(a.clone(), c(w, 1u64 << (w - 1)));
            let neg = Expr::unary(UnaryOp::Neg, a.clone());
            let v = if unsigned {
                neg
            } else {
                sel(ext(a.clone(), w - 1, 1), neg, a)
            };
            parts.push(sel(s.clone(), c(w, mask(w - 1)), v));
            sat = b(B::Or, sat, s);
        }
        return finish(r, d, parts, false, Some(sat));
    }
    // Register shifts use only the signed low byte of each shift lane.
    let shift_op = if scalar {
        s3 & !0x20000000
    } else {
        v3 & !0x20000000
    };
    if matches!(
        shift_op,
        0x0e204400
            | 0x0e204c00
            | 0x0e205400
            | 0x0e205c00
            | 0x5e204400
            | 0x5e204c00
            | 0x5e205400
            | 0x5e205c00
    ) {
        let sat_op = word & (1 << 11) != 0;
        let round = word & (1 << 12) != 0;
        if (!scalar && w == 64 && !q) || (scalar && !sat_op && w != 64) {
            return reject(r);
        }
        let mut parts = vec![];
        let mut all = c(1, 0);
        for i in 0..count {
            let a = lane(n, i, w);
            let shift = ext(lane(m, i, w), 0, 8);
            let negative = ext(shift.clone(), 7, 1);
            let magnitude = cast(Expr::unary(UnaryOp::Neg, shift.clone()), w, false);
            let right = right(a.clone(), magnitude, !unsigned, round);
            let (left, sat) = if sat_op {
                left_sat(
                    a.clone(),
                    cast(shift.clone(), w, false),
                    !unsigned,
                    unsigned,
                )
            } else {
                (b(B::Shl, a, cast(shift, w, false)), c(1, 0))
            };
            parts.push(sel(negative.clone(), right, left));
            all = b(B::Or, all, sel(negative, c(1, 0), sat));
        }
        return finish(r, d, parts, false, sat_op.then_some(all));
    }
    // Permutations interleave/extract lanes across both complete operands.
    if matches!(
        v3,
        0x0e001800 | 0x0e005800 | 0x0e002800 | 0x0e006800 | 0x0e003800 | 0x0e007800
    ) {
        if w == 64 && !q {
            return reject(r);
        }
        let count = if q { 128 / w } else { 64 / w };
        let half = count / 2;
        let part = ((word >> 14) & 1) as u8;
        let op = (word >> 12) & 3;
        let mut parts = vec![];
        for i in 0..count {
            let (reg, index) = match op {
                1 => (if i < half { n } else { m }, (i % half) * 2 + part),
                2 => (if i % 2 == 0 { n } else { m }, (i / 2) * 2 + part),
                _ => (if i % 2 == 0 { n } else { m }, i / 2 + part * half),
            };
            parts.push(lane(reg, index, w));
        }
        return finish(r, d, parts, false, None);
    }
    // EXT is a byte window over Vn followed by Vm.
    if word & 0xbfe08400 == 0x2e000000 {
        let bytes = if q { 16 } else { 8 };
        let offset = ((word >> 11) & 15) as u8;
        if offset >= bytes {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..bytes {
            let k = i + offset;
            parts.push(lane(if k < bytes { n } else { m }, k % bytes, 8));
        }
        return finish(r, d, parts, false, None);
    }
    // TBL/TBX concatenate 1..4 full 128-bit table registers with register wrap.
    if matches!(word & 0xbfe09c00, 0x0e000000 | 0x0e001000) {
        let len = ((word >> 13) & 3) + 1;
        let mut r = r;
        let mut table = vec![];
        for j in 0..len {
            for ch in 0..2 {
                table.push(r.bind(vector((n + j) % 32, ch)));
            }
        }
        let mut parts = vec![];
        for i in 0..if q { 16 } else { 8 } {
            let index = r.bind(lane(m, i, 8));
            let mut out = if word & (1 << 12) != 0 {
                lane(d, i, 8)
            } else {
                c(8, 0)
            };
            for (j, chunk) in table.iter().enumerate() {
                let high = ext(index.clone(), 3, 5);
                let shift = b(B::Shl, cast(ext(index.clone(), 0, 3), 64, false), c(64, 3));
                let byte = ext(b(B::Lsr, chunk.clone(), shift), 0, 8);
                out = sel(eq(high, c(5, j as u64)), byte, out);
            }
            parts.push(out);
        }
        return finish(r, d, parts, false, None);
    }
    // Widening arithmetic and multiply-long select the low/high source half;
    // the destination is always 128 bits. Wider-source ADDW/SUBW is independent.
    let long = v3 & !0x20000000;
    // Integer multiply by a selected halfword/word; M is an index bit for
    // halfwords and the high Rm register bit for words.
    let indexed = word & 0xbf00f400;
    if matches!(
        indexed,
        0x2f000000
            | 0x2f004000
            | 0x0f008000
            | 0x0f002000
            | 0x2f002000
            | 0x0f006000
            | 0x2f006000
            | 0x0f00a000
            | 0x2f00a000
    ) {
        if size != 1 && size != 2 {
            return reject(r);
        }
        let index = if size == 1 {
            (((word >> 11) & 1) << 2) | (((word >> 21) & 1) << 1) | ((word >> 20) & 1)
        } else {
            (((word >> 11) & 1) << 1) | ((word >> 21) & 1)
        };
        let rm = if size == 1 { m & 15 } else { m };
        let widening = !matches!(indexed, 0x2f000000 | 0x2f004000 | 0x0f008000);
        let width = if widening { w * 2 } else { w };
        let elements = if widening {
            64 / w
        } else if q {
            128 / w
        } else {
            64 / w
        };
        let mut parts = vec![];
        for i in 0..elements {
            let a = cast(
                lane(n, i + if widening && q { 64 / w } else { 0 }, w),
                width,
                widening && !unsigned,
            );
            let z = cast(lane(rm, index as u8, w), width, widening && !unsigned);
            let product = b(B::Mul, a, z);
            let value = if matches!(indexed, 0x0f008000 | 0x0f00a000 | 0x2f00a000) {
                product
            } else {
                b(
                    if matches!(indexed, 0x2f004000 | 0x0f006000 | 0x2f006000) {
                        B::Sub
                    } else {
                        B::Add
                    },
                    lane(d, i, width),
                    product,
                )
            };
            parts.push(value);
        }
        return finish(r, d, parts, false, None);
    }
    if matches!(
        long,
        0x0e200000 | 0x0e201000 | 0x0e202000 | 0x0e203000 | 0x0e208000 | 0x0e20a000 | 0x0e20c000
    ) {
        if w == 64 {
            return reject(r);
        }
        let offset = if q { 64 / w } else { 0 };
        let wide = w * 2;
        let mut parts = vec![];
        let op = (word >> 12) & 15;
        for i in 0..64 / w {
            let a = if op == 1 || op == 3 {
                lane(n, i, wide)
            } else {
                cast(lane(n, i + offset, w), wide, !unsigned)
            };
            let z = cast(lane(m, i + offset, w), wide, !unsigned);
            let value = match op {
                0 | 1 => b(B::Add, a, z),
                2 | 3 => b(B::Sub, a, z),
                8 | 10 | 12 => {
                    let product = b(B::Mul, a, z);
                    if op == 12 {
                        product
                    } else {
                        b(
                            if op == 8 { B::Add } else { B::Sub },
                            lane(d, i, wide),
                            product,
                        )
                    }
                }
                _ => unreachable!(),
            };
            parts.push(value);
        }
        return finish(r, d, parts, false, None);
    }
    // Vector and indexed dot products accumulate four 8-bit products per 32b lane.
    let dot_vec = matches!(v3, 0x0e009400 | 0x2e009400);
    let dot_elt = matches!(word & 0xbf00f400, 0x0f00e000 | 0x2f00e000);
    if dot_vec || dot_elt {
        if size != 2 {
            return reject(r);
        }
        let index = (((word >> 11) & 1) << 1) | ((word >> 21) & 1);
        let mut parts = vec![];
        for i in 0..if q { 4 } else { 2 } {
            let mut value = lane(d, i, 32);
            for j in 0..4 {
                let a = cast(lane(n, i * 4 + j, 8), 32, !unsigned);
                let z = cast(
                    lane(
                        m,
                        if dot_elt {
                            index as u8 * 4 + j
                        } else {
                            i * 4 + j
                        },
                        8,
                    ),
                    32,
                    !unsigned,
                );
                value = b(B::Add, value, b(B::Mul, a, z));
            }
            parts.push(value);
        }
        return finish(r, d, parts, false, None);
    }
    // Multiply / accumulate and min/max / absolute differences, same-size vectors.
    if matches!(
        long,
        0x0e209400
            | 0x0e209c00
            | 0x0e206400
            | 0x0e206c00
            | 0x0e207400
            | 0x0e207c00
            | 0x0e20a400
            | 0x0e20ac00
            | 0x0e20bc00
    ) {
        // U=1 at these positions belongs to another physical instruction
        // group (including polynomial multiply), not unsigned integer MUL.
        if unsigned && matches!(long, 0x0e209c00 | 0x0e20bc00) {
            return None;
        }
        if w == 64 && long != 0x0e20bc00 || w == 64 && !q {
            return reject(r);
        }
        let mut parts = vec![];
        let op = (word >> 12) & 15;
        for i in 0..count {
            let (pair_a, pair_z) = if [10, 11].contains(&op) {
                let k = i * 2;
                (
                    lane(if k < count { n } else { m }, k % count, w),
                    lane(if k < count { n } else { m }, k % count + 1, w),
                )
            } else {
                (lane(n, i, w), lane(m, i, w))
            };
            let value = match op {
                6 => minmax(pair_a, pair_z, !unsigned, word & (1 << 11) != 0),
                7 => {
                    let less = b(
                        if unsigned { B::Ult } else { B::Slt },
                        pair_a.clone(),
                        pair_z.clone(),
                    );
                    let diff = sel(
                        less,
                        b(B::Sub, pair_z.clone(), pair_a.clone()),
                        b(B::Sub, pair_a, pair_z),
                    );
                    if word & (1 << 11) != 0 {
                        b(B::Add, lane(d, i, w), diff)
                    } else {
                        diff
                    }
                }
                9 => {
                    let p = b(B::Mul, pair_a, pair_z);
                    if word & (1 << 11) != 0 {
                        p
                    } else {
                        b(if unsigned { B::Sub } else { B::Add }, lane(d, i, w), p)
                    }
                }
                10 => minmax(pair_a, pair_z, !unsigned, word & (1 << 11) != 0),
                11 => b(B::Add, pair_a, pair_z),
                _ => unreachable!(),
            };
            parts.push(value);
        }
        return finish(r, d, parts, false, None);
    }
    // Across-lane integer reductions write a scalar and zero the other bits of Vd.
    if matches!(
        v2 & !0x20000000,
        0x0e31b800 | 0x0e303800 | 0x0e30a800 | 0x0e31a800
    ) || word & 0xfffffc00 == 0x5ef1b800
    {
        if unsigned && v2 & !0x20000000 == 0x0e31b800 {
            return None;
        }
        let pair = word & 0xfffffc00 == 0x5ef1b800;
        let wide = v2 & !0x20000000 == 0x0e303800;
        if !pair && (size == 3 || (size == 2 && !q)) {
            return reject(r);
        }
        let width = if pair {
            64
        } else if wide {
            w * 2
        } else {
            w
        };
        let elements = if pair {
            2
        } else {
            if q {
                128 / w
            } else {
                64 / w
            }
        };
        let mut result = cast(
            lane(n, 0, if pair { 64 } else { w }),
            width,
            wide && !unsigned,
        );
        for i in 1..elements {
            let a = cast(
                lane(n, i, if pair { 64 } else { w }),
                width,
                wide && !unsigned,
            );
            result = if matches!(v2 & !0x20000000, 0x0e30a800 | 0x0e31a800) && !pair {
                minmax(result, a, !unsigned, word & (1 << 16) != 0)
            } else {
                b(B::Add, result, a)
            };
        }
        return finish(r, d, vec![result], false, None);
    }
    // XTN, SQXTN, UQXTN, SQXTUN and their scalar/*2 forms.
    let narrow_key = if scalar { s2 & !0x50000000 } else { v2 };
    if matches!(
        narrow_key,
        0x0e212800 | 0x0e214800 | 0x2e214800 | 0x2e212800
    ) {
        if w == 64 {
            return reject(r);
        }
        let plain = narrow_key == 0x0e212800;
        if scalar && plain {
            return None;
        }
        let mut parts = vec![];
        let mut sat = c(1, 0);
        for i in 0..if scalar { 1 } else { 64 / w } {
            let a = lane(n, i, w * 2);
            if plain {
                parts.push(cast(a, w, false));
            } else {
                let (v, s) = clamp(a, narrow_key != 0x2e214800, w, narrow_key == 0x0e214800);
                parts.push(v);
                sat = b(B::Or, sat, s);
            }
        }
        return finish(r, d, parts, !scalar && q, (!plain).then_some(sat));
    }
    // Unary integer vector operations missing from the template, plus the scalar
    // 64-bit ABS form. REV reverses elements within 16/32/64-bit containers.
    let abs_scalar = word & 0xfffffc00 == 0x5ee0b800;
    let reverse = matches!(v2, 0x0e201800 | 0x2e200800 | 0x0e200800);
    if abs_scalar
        || matches!(v2, 0x0e20b800 | 0x0e204800 | 0x2e204800 | 0x0e205800)
        || word & 0xbffffc00 == 0x2e605800
        || reverse
    {
        let rbit = word & 0xbffffc00 == 0x2e605800;
        let byte_op = v2 == 0x0e205800 || rbit;
        let width = if byte_op { 8 } else { w };
        let container = if v2 == 0x0e201800 {
            16
        } else if v2 == 0x2e200800 {
            32
        } else {
            64
        };
        if (reverse && width >= container)
            || ((v2 == 0x0e204800 || v2 == 0x2e204800) && size == 3)
            || (v2 == 0x0e205800 && size != 0)
            || (!abs_scalar && v2 == 0x0e20b800 && w == 64 && !q)
        {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..if abs_scalar {
            1
        } else {
            if q {
                128 / width
            } else {
                64 / width
            }
        } {
            let a = lane(
                n,
                if reverse {
                    let group = container / width;
                    i / group * group + group - 1 - i % group
                } else {
                    i
                },
                width,
            );
            let value = if reverse {
                a
            } else if rbit {
                Expr::unary(UnaryOp::ReverseBits, a)
            } else if v2 == 0x0e205800 {
                Expr::unary(UnaryOp::PopulationCount, a)
            } else if v2 == 0x0e204800 {
                let normalized = sel(ext(a.clone(), width - 1, 1), not(a.clone()), a);
                b(
                    B::Sub,
                    Expr::unary(UnaryOp::CountLeadingZeros, normalized),
                    c(width, 1),
                )
            } else if v2 == 0x2e204800 {
                Expr::unary(UnaryOp::CountLeadingZeros, a)
            } else {
                sel(
                    ext(a.clone(), width - 1, 1),
                    Expr::unary(UnaryOp::Neg, a.clone()),
                    a,
                )
            };
            parts.push(value);
        }
        return finish(r, d, parts, false, None);
    }
    // Shift-immediate class includes normal, inserting, saturating, narrow and
    // widening shifts. immh=0 is a separate modified-immediate physical class.
    let ikey = word & 0xbf80fc00;
    let skey = word & 0xff80fc00;
    let immediate = if scalar { skey & !0x50000000 } else { ikey };
    if matches!(
        immediate,
        0x0f000400
            | 0x2f000400
            | 0x0f001400
            | 0x2f001400
            | 0x0f002400
            | 0x2f002400
            | 0x0f003400
            | 0x2f003400
            | 0x0f005400
            | 0x2f005400
            | 0x2f004400
            | 0x0f007400
            | 0x2f007400
            | 0x2f006400
            | 0x0f008400
            | 0x0f008c00
            | 0x0f009400
            | 0x2f009400
            | 0x0f009c00
            | 0x2f009c00
            | 0x2f008400
            | 0x2f008c00
            | 0x0f00a400
            | 0x2f00a400
    ) {
        let imm = ((word >> 16) & 127) as u8;
        let immh = imm >> 3;
        if immh == 0 {
            return None;
        }
        let width = 1u8 << (7 - imm.leading_zeros());
        let narrow = matches!(
            immediate & !0x20000000,
            0x0f008400 | 0x0f008c00 | 0x0f009400 | 0x0f009c00
        );
        let widen = immediate & !0x20000000 == 0x0f00a400;
        if (narrow || widen) && width == 64 {
            return reject(r);
        }
        if !narrow
            && !widen
            && ((!scalar && width == 64 && !q)
                || (scalar
                    && width != 64
                    && !matches!(immediate, 0x0f007400 | 0x2f007400 | 0x2f006400)))
        {
            return reject(r);
        }
        if scalar && matches!(immediate, 0x0f008400 | 0x0f008c00 | 0x0f00a400 | 0x2f00a400) {
            return None;
        }
        let round =
            word & (1 << 11) != 0 || matches!(immediate & !0x20000000, 0x0f002400 | 0x0f003400);
        let sat = narrow && immediate != 0x0f008400 && immediate != 0x0f008c00
            || matches!(immediate, 0x0f007400 | 0x2f007400 | 0x2f006400);
        let mut parts = vec![];
        let mut all = c(1, 0);
        let elements = if scalar {
            1
        } else if narrow || widen {
            64 / width
        } else if q {
            128 / width
        } else {
            64 / width
        };
        for i in 0..elements {
            let value = if narrow {
                let signed = immediate != 0x0f008400
                    && immediate != 0x0f008c00
                    && immediate != 0x2f009400
                    && immediate != 0x2f009c00;
                let shifted = right(
                    lane(n, i, width * 2),
                    c(width * 2, u64::from(width * 2 - imm)),
                    signed,
                    round,
                );
                if sat {
                    let (v, s) = clamp(
                        shifted,
                        signed,
                        width,
                        matches!(immediate, 0x0f009400 | 0x0f009c00),
                    );
                    all = b(B::Or, all, s);
                    v
                } else {
                    cast(shifted, width, false)
                }
            } else if widen {
                b(
                    B::Shl,
                    cast(
                        lane(n, i + if q { 64 / width } else { 0 }, width),
                        width * 2,
                        !unsigned,
                    ),
                    c(width * 2, u64::from(imm - width)),
                )
            } else {
                let a = lane(n, i, width);
                let op = (word >> 12) & 15;
                let left = matches!(op, 5 | 6 | 7);
                let shift = if left { imm - width } else { width * 2 - imm };
                let shifted = if sat {
                    let (v, s) = left_sat(
                        a,
                        c(width, u64::from(shift)),
                        !unsigned || op == 6,
                        unsigned,
                    );
                    all = b(B::Or, all, s);
                    v
                } else if left {
                    b(B::Shl, a, c(width, u64::from(shift)))
                } else {
                    right(a, c(width, u64::from(shift)), !unsigned, round)
                };
                if op == 1 || op == 3 {
                    b(B::Add, lane(d, i, width), shifted)
                } else if op == 4 || op == 5 && unsigned {
                    let keep = if op == 4 {
                        mask(width) ^ mask(width - shift)
                    } else {
                        mask(shift)
                    };
                    b(B::Or, b(B::And, lane(d, i, width), c(width, keep)), shifted)
                } else {
                    shifted
                }
            };
            parts.push(value);
        }
        return finish(r, d, parts, narrow && !scalar && q, sat.then_some(all));
    }
    // SHLL shifts every selected narrow lane by its own width, no saturation.
    if v2 == 0x2e213800 {
        if w == 64 {
            return reject(r);
        }
        let mut parts = vec![];
        for i in 0..64 / w {
            parts.push(b(
                B::Shl,
                cast(lane(n, i + if q { 64 / w } else { 0 }, w), w * 2, false),
                c(w * 2, u64::from(w)),
            ));
        }
        return finish(r, d, parts, false, None);
    }
    None
}

//! Ordinary SVE scalar VL/address arithmetic and integer shift/product families.
//! Exact June2026 physical selectors; no memory, flags or saturation side effects.
//! Feature availability/CheckSVEEnabled is the generated caller's admission
//! contract, as for the other ordinary SVE helpers. ADR additionally enforces
//! CheckNonStreamingSVEEnabled through effective SVCR.SM / SME_FA64 context.
//! Z chunks alias a64.vector64[register*32+chunk]; CurrentVL is supplied explicitly.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
fn p(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w) / 8;
    Expr::extract(
        Expr::register(register("a64.predicate64", n as u16 * 4 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
fn gp(n: u32, sp: bool) -> Expr {
    if n == 31 && !sp {
        c(64, 0)
    } else {
        Expr::register(register(
            if n == 31 { "a64.sp" } else { "a64.gpr" },
            if n == 31 { 0 } else { n as u16 },
            64,
            64,
        ))
    }
}
fn write_gp(r: &mut Recipe, n: u32, sp: bool, v: Expr) {
    if n != 31 || sp {
        let v = r.bind(v);
        r.write(
            register(
                if n == 31 { "a64.sp" } else { "a64.gpr" },
                if n == 31 { 0 } else { n as u16 },
                64,
                64,
            ),
            WritePolicy::ZeroUpper,
            v,
        );
    }
}
fn write_z(r: &mut Recipe, d: u32, values: Vec<Expr>, w: u8) {
    // Each lane is captured once before packing. All input reads are incoming
    // state, so d=n/m, destructive shifts and adjacent output chunks alias safely.
    let values: Vec<_> = values.into_iter().map(|v| r.bind(v)).collect();
    for (chunk, lanes) in values.chunks(64 / usize::from(w)).enumerate() {
        let mut value = c(64, 0);
        for (i, v) in lanes.iter().enumerate() {
            value = b(
                B::Or,
                value,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), 64, false),
                    c(64, (i * usize::from(w)) as u64),
                ),
            );
        }
        let value = r.bind(value);
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn shift(value: Expr, count: Expr, op: B, w: u8) -> Expr {
    let in_range = b(B::Ult, count.clone(), c(count.ty.width, u64::from(w)));
    if op == B::Asr {
        b(
            op,
            value,
            Expr::select(in_range, count.clone(), c(count.ty.width, u64::from(w - 1))),
        )
    } else {
        Expr::select(in_range, b(op, value, count), c(w, 0))
    }
}
fn non_streaming(r: &mut Recipe) {
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.guard = Expr::require_context(
        Expr::select(
            sm,
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "SVE ADR requires non-streaming mode or effective SME_FA64",
    );
}
// Ordinary integer families with modulo arithmetic and no saturation state.
fn arithmetic(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let base = word & 0xff20fc00;
    let accumulate = matches!(base, 0x4500f800 | 0x4500fc00);
    let long_accumulate = matches!(base, 0x4500c000 | 0x4500c400 | 0x4500c800 | 0x4500cc00);
    let long_difference = matches!(base, 0x45003000 | 0x45003400 | 0x45003800 | 0x45003c00);
    let mixed = matches!(base, 0x45008000 | 0x45008800 | 0x45008c00);
    let clamp = matches!(base, 0x4400c000 | 0x4400c400);
    let complex = word & 0xff3ff800 == 0x4500d800;
    if !(accumulate || long_accumulate || long_difference || mixed || clamp || complex) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let w = 8u8 << ((word >> 22) & 3);
    if (long_accumulate || long_difference || mixed) && w == 8 {
        return Some(Recipe::unsupported(
            "reserved SVE long arithmetic element size",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let values = (0..vl / u16::from(w))
        .map(|e| {
            if complex {
                // Zdn += rotate90/270(Zm), independently per complex pair.
                let subtract = (e % 2 == 0) == (word & (1 << 10) == 0);
                return b(
                    if subtract { B::Sub } else { B::Add },
                    lane(d, e, w),
                    lane(n, e ^ 1, w),
                );
            }
            let signed = if long_accumulate || long_difference {
                word & (1 << 11) == 0
            } else {
                word & (1 << 10) == 0
            };
            if clamp {
                let compare = if signed { B::Slt } else { B::Ult };
                let lower = lane(n, e, w);
                let upper = lane(m, e, w);
                let value = lane(d, e, w);
                let at_least_lower = r.bind(Expr::select(
                    b(compare, lower.clone(), value.clone()),
                    value,
                    lower,
                ));
                return Expr::select(
                    b(compare, upper.clone(), at_least_lower.clone()),
                    upper,
                    at_least_lower,
                );
            }
            if mixed {
                let top = u16::from(word & (1 << 10) != 0);
                return b(
                    if word & (1 << 11) != 0 {
                        B::Sub
                    } else {
                        B::Add
                    },
                    Expr::cast(lane(n, e * 2 + top, w / 2), w, true),
                    Expr::cast(lane(m, e * 2 + (top ^ 1), w / 2), w, true),
                );
            }
            let (a, z) = if long_accumulate || long_difference {
                let index = 2 * e + u16::from(word & (1 << 10) != 0);
                (
                    Expr::cast(lane(n, index, w / 2), w, signed),
                    Expr::cast(lane(m, index, w / 2), w, signed),
                )
            } else {
                (lane(n, e, w), lane(m, e, w))
            };
            let a = r.bind(a);
            let z = r.bind(z);
            let difference = Expr::select(
                b(if signed { B::Slt } else { B::Ult }, a.clone(), z.clone()),
                b(B::Sub, z.clone(), a.clone()),
                b(B::Sub, a, z),
            );
            if accumulate || long_accumulate {
                b(B::Add, lane(d, e, w), difference)
            } else {
                difference
            }
        })
        .collect();
    write_z(&mut r, d, values, w);
    Some(r)
}
/// None denotes an unrelated physical encoding. Reserved fields/invalid VL are
/// explicitly Unsupported. Incoming feature admission is provided by the caller.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if let Some(recipe) = arithmetic(word, address, vl) {
        return Some(recipe);
    }
    let scalar =
        matches!(word & 0xffe0f800, 0x04205000 | 0x04605000) || word & 0xfffff800 == 0x04bf5000;
    let adr =
        word & 0xffa0f000 == 0x04a0a000 || matches!(word & 0xffe0f000, 0x0420a000 | 0x0460a000);
    let asrd = word & 0xff3fe000 == 0x04048000;
    let mul = matches!(word & 0xff20fc00, 0x04206800 | 0x04206c00);
    let wide_pred = matches!(word & 0xff3fe000, 0x04188000 | 0x04198000 | 0x041b8000);
    let wide = matches!(word & 0xff20fc00, 0x04208000 | 0x04208400 | 0x04208c00);
    let reverse = matches!(word & 0xff3fe000, 0x04148000 | 0x04158000 | 0x04178000);
    let widening = matches!(
        word & 0xffa0fc00,
        0x4500a000 | 0x4500a400 | 0x4500a800 | 0x4500ac00
    );
    let accumulate = matches!(word & 0xff20fc00, 0x4500e000 | 0x4500e400);
    let insert = matches!(word & 0xff20fc00, 0x4500f000 | 0x4500f400);
    if !scalar
        && !adr
        && !asrd
        && !mul
        && !wide_pred
        && !wide
        && !reverse
        && !widening
        && !accumulate
        && !insert
    {
        return None;
    }
    let next = address.wrapping_add(4);
    let unsupported = |reason| Some(Recipe::unsupported(reason, next, 64));
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return unsupported("SVE CurrentVL must be 128, 256, 512, 1024 or 2048");
    }
    let mut r = Recipe::new(next, 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    if scalar {
        let imm = ((((word >> 5) & 63) as i64) << 58) >> 58;
        let rdvl = word & 0xfffff800 == 0x04bf5000;
        let amount = imm
            * i64::from(if word & 0xffe0f800 == 0x04605000 {
                vl / 64
            } else {
                vl / 8
            });
        let value = if rdvl {
            c(64, amount as u64)
        } else {
            b(B::Add, gp((word >> 16) & 31, true), c(64, amount as u64))
        };
        write_gp(&mut r, d, !rdvl, value);
        return Some(r);
    }
    if adr {
        non_streaming(&mut r);
        let packed = word & 0xffa0f000 == 0x04a0a000;
        let w = if packed && word & (1 << 22) == 0 {
            32
        } else {
            64
        };
        let source = if packed { w } else { 32 };
        let signed = !packed && word & (1 << 22) == 0;
        let values = (0..vl / u16::from(w))
            .map(|e| {
                let offset = Expr::extract(lane(m, e, w), 0, source);
                let offset = Expr::cast(offset, w, signed);
                b(
                    B::Add,
                    lane(n, e, w),
                    b(B::Shl, offset, c(w, u64::from((word >> 10) & 3))),
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let mut w = 8u8 << ((word >> 22) & 3);
    let mut amount = 0u8;
    if asrd || accumulate || insert {
        let tsize = (((word >> 22) & 3) << 2) | ((word >> 19) & 3);
        if asrd {
            let tsize = (((word >> 22) & 3) << 2) | ((word >> 8) & 3);
            if tsize == 0 {
                return unsupported("Reserved SVE ASRD zero element-size selector");
            }
            w = 8 << tsize.ilog2();
            amount = 2 * w - ((tsize << 3) | ((word >> 5) & 7)) as u8;
        } else {
            if tsize == 0 {
                return unsupported("Reserved SVE shift zero element-size selector");
            }
            w = 8 << tsize.ilog2();
            let encoded = ((tsize << 3) | ((word >> 16) & 7)) as u8;
            amount = if insert && word & (1 << 10) != 0 {
                encoded - w
            } else {
                2 * w - encoded
            };
        }
    }
    if widening {
        let tsize = (((word >> 22) & 1) << 2) | ((word >> 19) & 3);
        if tsize == 0 {
            return unsupported("Reserved SVE widening shift zero element-size selector");
        }
        let source = 8u8 << tsize.ilog2();
        let amount = ((tsize << 3) | ((word >> 16) & 7)) as u8 - source;
        let top = (word >> 10) & 1;
        let signed = word & (1 << 11) == 0;
        w = source * 2;
        let values = (0..vl / u16::from(w))
            .map(|e| {
                b(
                    B::Shl,
                    Expr::cast(lane(n, 2 * e + top as u16, source), w, signed),
                    c(w, u64::from(amount)),
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if (wide || wide_pred) && w == 64 {
        return unsupported("Reserved SVE wide-element shift with 64-bit elements");
    }
    let values = (0..vl / u16::from(w))
        .map(|e| {
            if mul {
                return b(
                    if word & (1 << 10) != 0 {
                        B::UnsignedMultiplyHigh
                    } else {
                        B::SignedMultiplyHigh
                    },
                    lane(n, e, w),
                    lane(m, e, w),
                );
            }
            if accumulate {
                return b(
                    B::Add,
                    lane(d, e, w),
                    shift(
                        lane(n, e, w),
                        c(w, u64::from(amount)),
                        if word & (1 << 10) != 0 {
                            B::Lsr
                        } else {
                            B::Asr
                        },
                        w,
                    ),
                );
            }
            if insert {
                let left = word & (1 << 10) != 0;
                let keep = if left {
                    if amount == 0 {
                        0
                    } else {
                        (1u64 << amount) - 1
                    }
                } else {
                    if amount == w {
                        u64::MAX
                    } else {
                        u64::MAX << (w - amount)
                    }
                };
                return b(
                    B::Or,
                    b(B::And, lane(d, e, w), c(w, keep)),
                    shift(
                        lane(n, e, w),
                        c(w, u64::from(amount)),
                        if left { B::Shl } else { B::Lsr },
                        w,
                    ),
                );
            }
            let old = lane(d, e, w);
            let g = (word >> 10) & 7;
            if asrd {
                let x = old.clone();
                let quotient = shift(x.clone(), c(w, u64::from(amount)), B::Asr, w);
                let discarded = if amount == 64 {
                    u64::MAX
                } else {
                    (1u64 << amount) - 1
                };
                let negative = b(B::Slt, x.clone(), c(w, 0));
                let remainder = Expr::unary(
                    UnaryOp::Not,
                    b(B::Eq, b(B::And, x, c(w, discarded)), c(w, 0)),
                );
                let adjustment = Expr::cast(b(B::And, negative, remainder), w, false);
                return Expr::select(p(g, e, w), b(B::Add, quotient, adjustment), old);
            }
            let selector = if wide {
                (word >> 10) & 3
            } else {
                (word >> 16) & 3
            };
            let op = match selector {
                0 => B::Asr,
                1 => B::Lsr,
                _ => B::Shl,
            };
            if reverse {
                let source = (word >> 5) & 31;
                return Expr::select(
                    p(g, e, w),
                    shift(lane(source, e, w), old.clone(), op, w),
                    old,
                );
            }
            if wide_pred {
                let source = (word >> 5) & 31;
                return Expr::select(
                    p(g, e, w),
                    shift(old.clone(), z(source, e * u16::from(w) / 64), op, w),
                    old,
                );
            }
            shift(lane(n, e, w), z(m, e * u16::from(w) / 64), op, w)
        })
        .collect();
    write_z(&mut r, d, values, w);
    Some(r)
}

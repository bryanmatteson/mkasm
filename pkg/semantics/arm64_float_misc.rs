// A64 FJCVTZS (FPToFixedJS), fixed-width FAMIN/FAMAX (FPAbsMin/Max),
// and scalar/vector FRINT32/64Z/X (FPRoundIntN).
// Exact integer/bit expressions from the June 2026 Arm pseudocode: no host FP
// or approximation of ordinary numeric min/max. The caller owns feature and
// FP access admission and supplies canonical architectural FPCR/FPSR images.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn and(a: Expr, z: Expr) -> Expr {
    b(B::And, a, z)
}
fn or(a: Expr, z: Expr) -> Expr {
    b(B::Or, a, z)
}
fn eq(a: Expr, z: Expr) -> Expr {
    b(B::Eq, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn ext(a: Expr, o: u8, w: u8) -> Expr {
    Expr::extract(a, o, w)
}
fn cast(a: Expr, w: u8) -> Expr {
    Expr::cast(a, w, false)
}
fn reg(bank: &'static str, index: u16, w: u8) -> Expr {
    Expr::register(register(bank, index, w, w))
}
fn vector(n: u32, chunk: u16) -> Expr {
    reg("a64.vector64", n as u16 * 32 + chunk, 64)
}
fn flags(r: &mut Recipe, z: Expr) {
    for i in 0..4 {
        r.write(
            register("a64.nzcv", i, 1, 1),
            WritePolicy::ZeroUpper,
            if i == 1 { z.clone() } else { c(1, 0) },
        );
    }
}
// Exception enables are the canonical FPCR cumulative positions plus eight.
// Preserve every unrelated FPSR bit, then stop before destinations on a trap.
fn finish_status(r: &mut Recipe, control: Expr, status: Expr, raised: Expr) {
    let next = r.bind(or(status, raised.clone()));
    let trapped = r.bind(not(eq(and(b(B::Lsr, control, c(32, 8)), raised), c(32, 0))));
    r.write(
        register("a64.fpsr", 0, 32, 32),
        WritePolicy::ZeroUpper,
        next,
    );
    r.effects.push(Effect::Trap {
        kind: TrapKind::FloatingPoint,
        condition: trapped,
    });
}
/// Independent fixed-width families only. SVE/SME use their own context-aware
/// builders; June 2026 has no scalar FAMIN/FAMAX physical encoding.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    if word & 0xfffffc00 == 0x1e7e0000 {
        return Some(javascript(word, address));
    }
    if let Some(round) = round_int_n(word, address) {
        return Some(round);
    }
    let half = word & 0x9fe0fc00 == 0x0ec01c00;
    let wide = word & 0x9fa0fc00 == 0x0ea0dc00;
    if !half && !wide {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let width = if half { 16 } else { 32 << ((word >> 22) & 1) };
    let q = word & (1 << 30) != 0;
    if width == 64 && !q {
        r.support = Support::Unsupported("reserved FAMIN/FAMAX Q=0 double encoding");
        return Some(r);
    }
    let minimum = word & (1 << 29) != 0;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let d = word & 31;
    let control = r.bind(reg("a64.fpcr", 0, 32));
    let status = r.bind(reg("a64.fpsr", 0, 32));
    let chunks = if q { 2 } else { 1 };
    let mut a = vec![];
    let mut z = vec![];
    for chunk in 0..chunks {
        a.push(r.bind(vector(n, chunk)));
        z.push(r.bind(vector(m, chunk)));
    }
    let mut outputs = vec![];
    let mut invalid = c(1, 0);
    for chunk in 0..chunks {
        let mut packed = c(64, 0);
        for lane in 0..64 / width {
            let left = ext(a[chunk as usize].clone(), lane * width, width);
            let right = ext(z[chunk as usize].clone(), lane * width, width);
            let (value, snan) = absolute_minmax(&mut r, left, right, control.clone(), minimum);
            invalid = or(invalid, snan);
            packed = or(
                packed,
                b(B::Shl, cast(value, 64), c(64, u64::from(lane * width))),
            );
        }
        outputs.push(r.bind(packed));
    }
    let raised = r.bind(cast(invalid, 32));
    finish_status(&mut r, control, status, raised);
    for chunk in 0..2 {
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            outputs
                .get(chunk as usize)
                .cloned()
                .unwrap_or_else(|| c(64, 0)),
        );
    }
    Some(r)
}
pub(super) fn absolute_minmax(r: &mut Recipe, a: Expr, z: Expr, control: Expr, minimum: bool) -> (Expr, Expr) {
    let w = a.ty.width;
    let fraction = match w {
        16 => 10,
        32 => 23,
        _ => 52,
    };
    let exponent_mask = mask(w - 1) & !mask(fraction);
    let classify = |v: Expr| {
        let nan = and(
            eq(and(v.clone(), c(w, exponent_mask)), c(w, exponent_mask)),
            not(eq(and(v.clone(), c(w, mask(fraction))), c(w, 0))),
        );
        let signaling = and(nan.clone(), not(ext(v, fraction - 1, 1)));
        (nan, signaling)
    };
    let (an, asig) = classify(a.clone());
    let (zn, zsig) = classify(z.clone());
    let any_nan = r.bind(or(an.clone(), zn));
    let signaling = r.bind(or(asig.clone(), zsig.clone()));
    // FPProcessNaNs: signaling NaNs have operand-order priority over quiet
    // NaNs. Payload/sign come from the original (not absolute) operand.
    let nan = Expr::select(
        asig,
        a.clone(),
        Expr::select(zsig, z.clone(), Expr::select(an, a.clone(), z.clone())),
    );
    let nan = Expr::select(
        ext(control, 25, 1),
        c(w, exponent_mask | (1 << (fraction - 1))),
        or(nan, c(w, 1 << (fraction - 1))),
    );
    let aa = r.bind(and(a, c(w, mask(w - 1))));
    let zz = r.bind(and(z, c(w, mask(w - 1))));
    // Positive IEEE encodings are monotonically ordered, including zeros,
    // subnormals and infinities. All flush controls are locally disabled.
    let choose = if minimum {
        b(B::Ult, aa.clone(), zz.clone())
    } else {
        b(B::Ult, zz.clone(), aa.clone())
    };
    (
        r.bind(Expr::select(any_nan, nan, Expr::select(choose, aa, zz))),
        signaling,
    )
}
fn javascript(word: u32, address: u64) -> Recipe {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let raw = r.bind(vector((word >> 5) & 31, 0));
    let control = r.bind(reg("a64.fpcr", 0, 32));
    let status = r.bind(reg("a64.fpsr", 0, 32));
    let sign = r.bind(ext(raw.clone(), 63, 1));
    let exponent = r.bind(cast(ext(raw.clone(), 52, 11), 64));
    let fraction = r.bind(and(raw.clone(), c(64, mask(52))));
    let subnormal = r.bind(and(
        eq(exponent.clone(), c(64, 0)),
        not(eq(fraction.clone(), c(64, 0))),
    ));
    let ah = ext(control.clone(), 1, 1);
    let fiz = ext(control.clone(), 0, 1);
    let fz = r.bind(and(ext(control.clone(), 24, 1), not(ah)));
    let flushed = r.bind(and(subnormal.clone(), or(fz.clone(), fiz)));
    let idc = r.bind(and(subnormal, fz));
    let below_one = r.bind(b(B::Ult, exponent.clone(), c(64, 1023)));
    let special = r.bind(eq(exponent.clone(), c(64, 2047)));
    let significand = r.bind(or(fraction, c(64, 1 << 52)));
    let shift = r.bind(b(B::Sub, c(64, 1075), exponent.clone()));
    let truncated = r.bind(b(B::Lsr, significand.clone(), shift.clone()));
    let magnitude = r.bind(Expr::select(
        below_one.clone(),
        c(64, 0),
        Expr::select(
            b(B::Ult, exponent.clone(), c(64, 1075)),
            truncated.clone(),
            b(
                B::Shl,
                significand.clone(),
                b(B::Sub, exponent.clone(), c(64, 1075)),
            ),
        ),
    ));
    let positive_limit = and(
        eq(exponent.clone(), c(64, 1054)),
        not(and(
            sign.clone(),
            eq(b(B::Lsr, significand.clone(), c(64, 21)), c(64, 1 << 31)),
        )),
    );
    let invalid = r.bind(or(b(B::Ult, c(64, 1054), exponent.clone()), positive_limit));
    let remainder = r.bind(b(B::Sub, significand, b(B::Shl, truncated, shift)));
    let fractional = r.bind(Expr::select(
        below_one.clone(),
        not(eq(and(raw.clone(), c(64, mask(63))), c(64, 0))),
        and(
            b(B::Ult, exponent, c(64, 1075)),
            not(eq(remainder, c(64, 0))),
        ),
    ));
    let inexact = r.bind(and(not(or(invalid.clone(), flushed.clone())), fractional));
    let low = cast(magnitude, 32);
    let value = r.bind(Expr::select(
        or(flushed.clone(), or(below_one, special)),
        c(32, 0),
        Expr::select(sign.clone(), Expr::unary(UnaryOp::Neg, low.clone()), low),
    ));
    let negative_zero = and(sign, eq(and(raw, c(64, mask(63))), c(64, 0)));
    let z = r.bind(not(or(
        or(invalid.clone(), inexact.clone()),
        or(flushed, negative_zero),
    )));
    let raised = r.bind(or(
        cast(invalid, 32),
        or(
            b(B::Shl, cast(inexact, 32), c(32, 4)),
            b(B::Shl, cast(idc, 32), c(32, 7)),
        ),
    ));
    finish_status(&mut r, control, status, raised);
    let d = word & 31;
    if d != 31 {
        r.write(
            register("a64.gpr", d as u16, 32, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    flags(&mut r, z);
    r
}

// FEAT_FRINTTS: unlike ordinary FRINT, every NaN/infinity and rounded signed
// range overflow returns the floating representation of the signed minimum,
// raises Invalid (without Inexact), and never propagates a NaN payload.
fn round_int_n(word: u32, address: u64) -> Option<Recipe> {
    let scalar = matches!(
        word & 0xffbffc00,
        0x1e284000 | 0x1e28c000 | 0x1e294000 | 0x1e29c000
    );
    let vector_form = matches!(word & 0x9fbfec00, 0x0e21e800);
    if !scalar && !vector_form {
        return None;
    }
    let width = 32u8 << ((word >> 22) & 1);
    let intsize = if word & (if scalar { 1 << 16 } else { 1 << 12 }) != 0 {
        64
    } else {
        32
    };
    let environment = word & (if scalar { 1 << 15 } else { 1 << 29 }) != 0;
    let q = word & (1 << 30) != 0;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if !scalar && width == 64 && !q {
        r.support = Support::Unsupported("reserved FRINTTS Q=0 double encoding");
        return Some(r);
    }
    let control = r.bind(reg("a64.fpcr", 0, 32));
    let status = r.bind(reg("a64.fpsr", 0, 32));
    let d = word & 31;
    let n = (word >> 5) & 31;
    let count = if scalar {
        1
    } else {
        if q {
            128 / width
        } else {
            64 / width
        }
    };
    let mut source = vec![r.bind(vector(n, 0))];
    if !scalar && q {
        source.push(r.bind(vector(n, 1)));
    }
    let mut results = vec![];
    let mut raised = c(32, 0);
    for i in 0..count {
        let raw = ext(
            source[usize::from(i / (64 / width))].clone(),
            (i % (64 / width)) * width,
            width,
        );
        let (value, exceptions) = bounded_round(&mut r, raw, intsize, environment, control.clone());
        results.push(value);
        raised = or(raised, exceptions);
    }
    let mut chunks = vec![];
    for chunk in 0..if scalar {
        1
    } else {
        if q {
            2
        } else {
            1
        }
    } {
        let mut packed = c(64, 0);
        for i in 0..if scalar { 1 } else { 64 / width } {
            packed = or(
                packed,
                b(
                    B::Shl,
                    cast(results[usize::from(chunk * (64 / width) + i)].clone(), 64),
                    c(64, u64::from(i * width)),
                ),
            );
        }
        chunks.push(r.bind(packed));
    }
    let (low, high) = if scalar {
        let merging = ext(control.clone(), 2, 1);
        let keep = Expr::select(
            merging.clone(),
            and(vector(d, 0), c(64, !mask(width))),
            c(64, 0),
        );
        (
            r.bind(or(chunks.remove(0), keep)),
            r.bind(Expr::select(merging, vector(d, 1), c(64, 0))),
        )
    } else {
        (
            chunks[0].clone(),
            chunks.get(1).cloned().unwrap_or_else(|| c(64, 0)),
        )
    };
    let raised = r.bind(raised);
    finish_status(&mut r, control, status, raised);
    for (chunk, value) in [low, high].into_iter().enumerate() {
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(r)
}
pub(super) fn bounded_round(
    r: &mut Recipe,
    raw: Expr,
    intsize: u8,
    environment: bool,
    control: Expr,
) -> (Expr, Expr) {
    let w = raw.ty.width;
    let fraction = if w == 32 { 23 } else { 52 };
    let bias = if w == 32 { 127 } else { 1023 };
    let raw = r.bind(raw);
    let sign = r.bind(ext(raw.clone(), w - 1, 1));
    let abs = r.bind(and(raw, c(w, mask(w - 1))));
    let exponent = r.bind(cast(ext(abs.clone(), fraction, w - fraction - 1), w));
    let subnormal = r.bind(and(
        eq(exponent.clone(), c(w, 0)),
        not(eq(abs.clone(), c(w, 0))),
    ));
    let fz = r.bind(and(
        ext(control.clone(), 24, 1),
        not(ext(control.clone(), 1, 1)),
    ));
    let flushed = r.bind(and(
        subnormal.clone(),
        or(fz.clone(), ext(control.clone(), 0, 1)),
    ));
    let idc = r.bind(and(subnormal, fz));
    let below_one = r.bind(b(B::Ult, exponent.clone(), c(w, bias)));
    let partial = r.bind(b(
        B::Ult,
        exponent.clone(),
        c(w, bias + u64::from(fraction)),
    ));
    let amount = r.bind(b(
        B::Sub,
        c(w, bias + u64::from(fraction)),
        exponent.clone(),
    ));
    let unit = r.bind(b(B::Shl, c(w, 1), amount));
    let lowmask = r.bind(b(B::Sub, unit.clone(), c(w, 1)));
    let remainder = r.bind(and(abs.clone(), lowmask.clone()));
    let truncated = r.bind(and(abs.clone(), not(lowmask)));
    let halfway = r.bind(b(B::Lsr, unit.clone(), c(w, 1)));
    let normal_nearest = or(
        b(B::Ult, halfway.clone(), remainder.clone()),
        and(
            eq(halfway, remainder.clone()),
            not(eq(and(truncated.clone(), unit.clone()), c(w, 0))),
        ),
    );
    let tiny_nearest = and(
        eq(exponent, c(w, bias - 1)),
        not(eq(and(abs.clone(), c(w, mask(fraction))), c(w, 0))),
    );
    let nonzero = not(eq(abs.clone(), c(w, 0)));
    let has_fraction = r.bind(Expr::select(
        below_one.clone(),
        nonzero,
        and(partial.clone(), not(eq(remainder, c(w, 0)))),
    ));
    let mode = if environment {
        ext(control, 22, 2)
    } else {
        c(2, 3)
    };
    let increment = r.bind(and(
        has_fraction.clone(),
        Expr::select(
            eq(mode.clone(), c(2, 0)),
            Expr::select(below_one.clone(), tiny_nearest, normal_nearest),
            Expr::select(
                eq(mode.clone(), c(2, 1)),
                and(not(sign.clone()), has_fraction.clone()),
                Expr::select(
                    eq(mode, c(2, 2)),
                    and(sign.clone(), has_fraction.clone()),
                    c(1, 0),
                ),
            ),
        ),
    ));
    let integral = r.bind(Expr::select(
        below_one,
        c(w, 0),
        Expr::select(partial.clone(), truncated, abs.clone()),
    ));
    let step = Expr::select(
        b(B::Ult, abs.clone(), c(w, bias << fraction)),
        c(w, bias << fraction),
        unit,
    );
    let rounded = r.bind(Expr::select(
        flushed.clone(),
        c(w, 0),
        Expr::select(increment, b(B::Add, integral.clone(), step), integral),
    ));
    let bound = (bias + u64::from(intsize) - 1) << fraction;
    let invalid = r.bind(Expr::select(
        sign.clone(),
        b(B::Ult, c(w, bound), rounded.clone()),
        not(b(B::Ult, rounded.clone(), c(w, bound))),
    ));
    let inexact = r.bind(and(not(or(invalid.clone(), flushed)), has_fraction));
    let raised = r.bind(or(
        cast(invalid.clone(), 32),
        or(
            b(B::Shl, cast(inexact, 32), c(32, 4)),
            b(B::Shl, cast(idc, 32), c(32, 7)),
        ),
    ));
    let signed = or(rounded, b(B::Shl, cast(sign, w), c(w, u64::from(w - 1))));
    (
        r.bind(Expr::select(
            invalid,
            c(w, (1u64 << (w - 1)) | bound),
            signed,
        )),
        raised,
    )
}

// Exact FPScale/FPLogB expression algebra from the June 2026 Arm ASL.
// Callers capture inputs/control/status once, predicate all selected outcomes,
// and own FPSR/trap/destination commit order. No register or memory writes.
use super::*;
use BinaryOp as B;
#[derive(Clone, Debug)]
pub struct Outcome {
    pub value: Expr,
    pub status: Expr,
    pub trapped: Expr,
}
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
fn choose(p: Expr, a: Expr, z: Expr) -> Expr {
    Expr::select(p, a, z)
}
fn valid(w: u8, v: &Expr, control: &Expr, status: &Expr) -> bool {
    matches!(w, 16 | 32 | 64) && v.ty.width == w && control.ty.width == 32 && status.ty.width == 32
}
fn finish(value: Expr, status: Expr, control: Expr, raised: Expr, nontrapping: Expr) -> Outcome {
    let enables = and(b(B::Lsr, control.clone(), c(32, 8)), not(nontrapping));
    let enabled = and(raised.clone(), enables.clone());
    let any = |mask| not(eq(and(enabled.clone(), c(32, mask)), c(32, 0)));
    let ah = ext(control, 1, 1);
    // Scale/LogB never raise divide-by-zero. Invalid excludes rounding;
    // underflow and overflow are mutually exclusive. Only their shared later
    // inexact, and AH's final input-denormal stage, need separate suppression.
    // FZ UFC writes are excluded from enables even when UFE is set.
    let allowed = and(
        and(
            choose(and(not(ah.clone()), any(128)), c(32, 0), c(32, 0x9f)),
            choose(any(1), c(32, 128), c(32, 0x9f)),
        ),
        and(
            choose(any(12), c(32, 0x8f), c(32, 0x9f)),
            choose(and(ah, any(29)), c(32, 0x1f), c(32, 0x9f)),
        ),
    );
    let accrued = and(raised.clone(), and(not(enables.clone()), allowed));
    Outcome {
        value,
        // The common fully masked case avoids reevaluating the unbound
        // numeric expression for each ordered-exception predicate.
        status: or(status, choose(eq(enables, c(32, 0)), raised, accrued)),
        trapped: not(eq(enabled, c(32, 0))),
    }
}

struct Parts {
    sign: Expr,
    exp: Expr,
    subnormal: Expr,
    zero: Expr,
    infinity: Expr,
    nan: Expr,
    snan: Expr,
    shift: Expr,
    normalized: Expr,
    bias: u64,
    f: u8,
    max: u64,
}
fn parts(w: u8, value: Expr) -> Parts {
    let f = match w {
        16 => 10,
        32 => 23,
        _ => 52,
    };
    parts_format(w, value, f)
}
fn parts_format(w: u8, value: Expr, f: u8) -> Parts {
    let e = w - f - 1;
    let max = mask(e);
    let bias = max / 2;
    let sign = and(value.clone(), c(w, 1u64 << (w - 1)));
    let exp = cast(ext(value.clone(), f, e), w);
    let fraction = and(value, c(w, mask(f)));
    let frac_zero = eq(fraction.clone(), c(w, 0));
    let exp_zero = eq(exp.clone(), c(w, 0));
    let exp_max = eq(exp.clone(), c(w, max));
    let subnormal = and(exp_zero.clone(), not(frac_zero.clone()));
    let zero = and(exp_zero.clone(), frac_zero.clone());
    let infinity = and(exp_max.clone(), frac_zero.clone());
    let nan = and(exp_max, not(frac_zero));
    let snan = and(nan.clone(), not(ext(fraction.clone(), f - 1, 1)));
    let significand = or(fraction.clone(), choose(exp_zero, c(w, 0), c(w, 1 << f)));
    let shift = b(
        B::Sub,
        Expr::unary(UnaryOp::CountLeadingZeros, significand.clone()),
        c(w, u64::from(w - f - 1)),
    );
    let normalized = b(B::Shl, significand, shift.clone());
    Parts {
        sign,
        exp,
        subnormal,
        zero,
        infinity,
        nan,
        snan,
        shift,
        normalized,
        bias,
        f,
        max,
    }
}
fn flush(w: u8, p: &Parts, control: Expr) -> (Expr, Expr) {
    if w == 16 {
        return (and(p.subnormal.clone(), ext(control, 19, 1)), c(1, 0));
    }
    let fz = and(ext(control.clone(), 24, 1), not(ext(control.clone(), 1, 1)));
    (
        and(p.subnormal.clone(), or(fz.clone(), ext(control, 0, 1))),
        and(p.subnormal.clone(), fz),
    )
}
/// Signed integer exponent has the same lane width as the IEEE input. AFP
/// AH/FIZ, IEEE half (ignoring AHP), and all FPCR rounding modes are explicit.
pub fn scale(
    width: u8,
    value: Expr,
    exponent: Expr,
    control: Expr,
    status: Expr,
) -> Option<Outcome> {
    scale_format(width, value, exponent, control, status, false, None)
}
/// BFScale uses the BF16 significand and FP32 unpacking controls, ignoring FZ16.
pub fn bfloat_scale(value: Expr, exponent: Expr, control: Expr, status: Expr) -> Option<Outcome> {
    scale_format(16, value, exponent, control, status, true, None)
}
pub(super) fn scale_bound(
    r: &mut Recipe,
    guard: Expr,
    width: u8,
    value: Expr,
    exponent: Expr,
    control: Expr,
    status: Expr,
    bfloat: bool,
) -> Option<Outcome> {
    scale_format(
        width,
        value,
        exponent,
        control,
        status,
        bfloat,
        Some((r, guard)),
    )
}
fn scale_format(
    width: u8,
    value: Expr,
    exponent: Expr,
    control: Expr,
    status: Expr,
    bfloat: bool,
    mut capture: Option<(&mut Recipe, Expr)>,
) -> Option<Outcome> {
    if !valid(width, &value, &control, &status) || exponent.ty.width != width {
        return None;
    }
    let mut capture = |value: Expr| {
        let width = value.ty.width;
        match &mut capture {
            Some((r, guard)) => r.bind(choose(guard.clone(), value, c(width, 0))),
            None => value,
        }
    };
    let w = width;
    let mut p = if bfloat {
        parts_format(w, value.clone(), 7)
    } else {
        parts(w, value.clone())
    };
    p.sign = capture(p.sign);
    p.exp = capture(p.exp);
    p.subnormal = capture(p.subnormal);
    p.zero = capture(p.zero);
    p.infinity = capture(p.infinity);
    p.nan = capture(p.nan);
    p.snan = capture(p.snan);
    p.shift = capture(p.shift);
    p.normalized = capture(p.normalized);
    let (input_flush, idc) = flush(if bfloat { 32 } else { w }, &p, control.clone());
    let input_flush = capture(input_flush);
    let idc = capture(idc);
    let ah = capture(ext(control.clone(), 1, 1));
    // FPScale only changes a binary exponent: the unconstrained normalized
    // mantissa is already exact in F+1 bits. FPRoundBase's AFP unconstrained
    // rounding therefore never increments it, and its post-round tininess
    // test is exactly `biased < 1`, even if constrained rounding later carries
    // a subnormal up to the minimum normal destination encoding.
    // FPClampScale bounds before signed addition, including MIN/MAX integer
    // operands. The bounded sums cannot overflow even for 16-bit lanes.
    let min = capture(b(
        B::Sub,
        c(w, (0u64).wrapping_sub(u64::from(p.f + 1))),
        p.exp.clone(),
    ));
    let max = capture(b(B::Sub, c(w, p.max + u64::from(p.f + 1)), p.exp.clone()));
    let clamped = capture(choose(
        b(B::Slt, exponent.clone(), min.clone()),
        min,
        choose(b(B::Slt, max.clone(), exponent.clone()), max, exponent),
    ));
    let effective = capture(choose(eq(p.exp.clone(), c(w, 0)), c(w, 1), p.exp.clone()));
    let biased = capture(b(B::Sub, b(B::Add, effective, clamped), p.shift.clone()));
    let tiny = capture(b(B::Slt, biased.clone(), c(w, 1)));
    let overflow = capture(not(b(B::Slt, biased.clone(), c(w, p.max))));
    let distance = capture(b(B::Sub, c(w, 1), biased.clone()));
    let truncated = capture(b(B::Lsr, p.normalized.clone(), distance.clone()));
    let rem = capture(b(
        B::Sub,
        p.normalized.clone(),
        b(B::Shl, truncated.clone(), distance.clone()),
    ));
    let inexact = capture(not(eq(rem.clone(), c(w, 0))));
    let half = capture(b(B::Shl, c(w, 1), b(B::Sub, distance.clone(), c(w, 1))));
    let nearest = capture(and(
        not(b(B::Ult, c(w, u64::from(p.f + 1)), distance)),
        or(
            b(B::Ult, half.clone(), rem.clone()),
            and(eq(half, rem), ext(truncated.clone(), 0, 1)),
        ),
    ));
    let negative = capture(ext(p.sign.clone(), w - 1, 1));
    let mode = capture(ext(control.clone(), 22, 2));
    let directed = capture(choose(
        eq(mode.clone(), c(2, 1)),
        not(negative.clone()),
        choose(eq(mode.clone(), c(2, 2)), negative.clone(), c(1, 0)),
    ));
    let increment = capture(and(
        inexact.clone(),
        choose(eq(mode.clone(), c(2, 0)), nearest, directed.clone()),
    ));
    // A carry into bit F naturally encodes minimum normal, so this is exactly
    // one rounding, including ties on the subnormal-to-normal boundary.
    let subnormal = capture(b(B::Add, truncated, cast(increment, w)));
    let normal = capture(or(
        b(B::Shl, biased, c(w, u64::from(p.f))),
        and(p.normalized, c(w, mask(p.f))),
    ));
    let to_inf = capture(or(eq(mode, c(2, 0)), directed));
    let over = capture(choose(to_inf, c(w, p.max << p.f), c(w, (p.max << p.f) - 1)));
    let flush_out = capture(and(
        tiny.clone(),
        ext(control.clone(), if w == 16 && !bfloat { 19 } else { 24 }, 1),
    ));
    let numeric = capture(or(
        p.sign.clone(),
        choose(
            flush_out.clone(),
            c(w, 0),
            choose(
                tiny.clone(),
                subnormal,
                choose(overflow.clone(), over, normal),
            ),
        ),
    ));
    let default_nan = (p.max << p.f) | (1 << (p.f - 1));
    let nan = capture(choose(
        ext(control.clone(), 25, 1),
        or(
            c(w, default_nan),
            b(B::Shl, cast(ah.clone(), w), c(w, u64::from(w - 1))),
        ),
        or(value.clone(), c(w, 1 << (p.f - 1))),
    ));
    let exceptional = capture(or(
        or(p.zero.clone(), p.infinity.clone()),
        or(p.nan.clone(), input_flush.clone()),
    ));
    let result = capture(choose(
        p.nan,
        nan,
        choose(
            or(input_flush.clone(), p.zero),
            p.sign.clone(),
            choose(p.infinity, value, numeric),
        ),
    ));
    // Special operands bypass FPRound. FZ result flushing raises UFC directly
    // and never traps UF. AFP additionally raises Inexact on every result
    // flush (including exact subnormals), and that IX exception may trap.
    // Gradual exact subnormals raise UF when UFE is set in either AH mode.
    let uf = capture(and(
        tiny.clone(),
        or(inexact.clone(), ext(control.clone(), 11, 1)),
    ));
    let gradual = capture(or(
        b(B::Shl, cast(uf, 32), c(32, 3)),
        b(B::Shl, cast(and(tiny, inexact), 32), c(32, 4)),
    ));
    let round_raised = capture(choose(
        flush_out.clone(),
        or(c(32, 8), b(B::Shl, cast(ah.clone(), 32), c(32, 4))),
        choose(overflow, c(32, 20), gradual),
    ));
    // AH suppresses the single/double input FZ path. Any remaining denormal
    // input is reported by FPProcessDenorm *after* FPRound, including when the
    // result overflows or is flushed. FIZ-flushed inputs are zero, not denormal.
    let alt_denorm = capture(if w == 16 && !bfloat {
        c(1, 0)
    } else {
        and(and(p.subnormal, not(input_flush)), ah)
    });
    // FPProcessDenorm follows FPRound: a rounding exception stops before
    // this final IDC stage. FZ directly sets UFC without trapping on UFE.
    let round_enabled = capture(and(
        and(round_raised.clone(), b(B::Lsr, control.clone(), c(32, 8))),
        choose(flush_out.clone(), c(32, !8u64), c(32, u32::MAX as u64)),
    ));
    let alt_denorm = capture(and(alt_denorm, eq(round_enabled, c(32, 0))));
    let raised = capture(or(
        cast(p.snan, 32),
        or(
            b(B::Shl, cast(or(idc, alt_denorm), 32), c(32, 7)),
            choose(exceptional.clone(), c(32, 0), round_raised),
        ),
    ));
    // Only a genuine nonzero finite result-flush exempts UFC from trapping.
    let nontrapping = capture(choose(and(not(exceptional), flush_out), c(32, 8), c(32, 0)));
    Some(finish(result, status, control, raised, nontrapping))
}
/// Returns the signed integer floor(log2(abs(input))) in the same lane width.
/// Zeros/NaNs return MinInt and Invalid; infinities return MaxInt. AH/FIZ and
/// FZ/FZ16 unpacking and AH input-denormal reporting are represented exactly.
pub fn logb(width: u8, value: Expr, control: Expr, status: Expr) -> Option<Outcome> {
    if !valid(width, &value, &control, &status) {
        return None;
    }
    let w = width;
    let p = parts(w, value);
    let (flushed, idc) = flush(w, &p, control.clone());
    let invalid = or(p.nan, or(p.zero, flushed.clone()));
    let exponent = b(
        B::Sub,
        b(
            B::Sub,
            choose(eq(p.exp.clone(), c(w, 0)), c(w, 1), p.exp),
            c(w, p.bias),
        ),
        p.shift,
    );
    let result = choose(
        invalid.clone(),
        c(w, 1u64 << (w - 1)),
        choose(p.infinity, c(w, mask(w - 1)), exponent),
    );
    let alt_denorm = if w == 16 {
        c(1, 0)
    } else {
        and(and(p.subnormal, not(flushed)), ext(control.clone(), 1, 1))
    };
    let raised = or(
        cast(invalid, 32),
        b(B::Shl, cast(or(idc, alt_denorm), 32), c(32, 7)),
    );
    Some(finish(result, status, control, raised, c(32, 0)))
}

/// Fixed-width BFDOT (vector/indexed) and BFMMLA from the June A64 diagrams.
/// Feature/FP-access admission belongs to the caller. FPCR must be the target's
/// effective image: EBF is RES0 without EBF16, AH/FIZ are RES0 without AFP.
/// BFDotAdd suppresses every FP exception, so no FPSR/NZCV read or write is
/// required. All source chunks are bound before outputs, including aliases.
pub fn fixed_bfloat(word: u32, address: u64) -> Option<Recipe> {
    let vector = word & 0xbfe0fc00 == 0x2e40fc00;
    let indexed = word & 0xbfc0f400 == 0x0f40f000;
    let matrix = word & 0xffe0fc00 == 0x6e40ec00;
    if !vector && !indexed && !matrix {
        return None;
    }
    let d = (word & 31) as u16;
    let n = ((word >> 5) & 31) as u16;
    let m = ((word >> 16) & 31) as u16;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let wide = matrix || word & (1 << 30) != 0;
    let index = (((word >> 11) & 1) * 2 + ((word >> 21) & 1)) as u8;
    let mut chunks = Vec::new();
    for (operand, reg) in [d, n, m].into_iter().enumerate() {
        chunks.push([0, 1].map(|chunk| {
            let needed = if operand == 2 && indexed {
                chunk == u16::from(index / 2)
            } else {
                wide || chunk == 0
            };
            if needed {
                r.bind(Expr::register(register(
                    "a64.vector64",
                    reg * 32 + chunk,
                    64,
                    64,
                )))
            } else {
                c(64, 0)
            }
        }));
    }
    let lane = |operand: usize, index: u8, width: u8| {
        let bit = u16::from(index) * u16::from(width);
        ext(
            chunks[operand][(bit / 64) as usize].clone(),
            (bit % 64) as u8,
            width,
        )
    };
    let count = if wide { 4 } else { 2 };
    let mut output = [c(64, 0), c(64, 0)];
    for e in 0..count {
        let mut sum = lane(0, e, 32);
        for k in 0..if matrix { 2 } else { 1 } {
            let left = if matrix { 4 * (e / 2) + 2 * k } else { 2 * e };
            let right = if matrix {
                4 * (e % 2) + 2 * k
            } else if indexed {
                2 * index
            } else {
                2 * e
            };
            sum = r.bind(Expr::float(FloatExpression {
                operation: FloatOperation::BFloatDotAdd,
                environment: FloatEnvironment::A64,
                width: 32,
                inputs: vec![
                    sum,
                    lane(1, left, 16),
                    lane(1, left + 1, 16),
                    lane(2, right, 16),
                    lane(2, right + 1, 16),
                ],
                control: Box::new(control.clone()),
                status: Box::new(c(32, 0)),
                projection: FloatProjection::Value,
            }));
        }
        output[e as usize / 2] = or(
            output[e as usize / 2].clone(),
            b(B::Shl, cast(sum, 64), c(64, u64::from(e % 2) * 32)),
        );
    }
    for (chunk, value) in output.into_iter().enumerate() {
        r.write(
            register("a64.vector64", d * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(r)
}

//! Fixed-environment x86 BF16 expressions. Intel's BF16 narrowing and dot
//! instructions neither read nor update MXCSR. Dot accumulation uses two native
//! IEEE binary32 fused operations with fixed RNE/DAZ/FTZ controls; integer
//! expressions implement the architectural NaN priority explicitly.
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
fn nan32(a: Expr) -> Expr {
    b(B::Ult, c(32, 0x7f80_0000), b(B::And, a, c(32, 0x7fff_ffff)))
}
fn quiet32(a: Expr) -> Expr {
    b(B::Or, a, c(32, 0x0040_0000))
}
/// Intel VCVTNE[2]PS2BF16's fixed RNE conversion, including sign-preserving
/// DAZ and payload-preserving quiet NaNs. No floating-point status is touched.
pub fn bf16_from_f32(r: &mut Recipe, input: Expr) -> Option<Expr> {
    if input.ty.width != 32 {
        return None;
    }
    let input = r.bind(input);
    let exponent = r.bind(b(B::And, input.clone(), c(32, 0x7f80_0000)));
    let high = r.bind(Expr::extract(input.clone(), 16, 16));
    let bias = b(
        B::Add,
        c(32, 0x7fff),
        Expr::cast(Expr::extract(input.clone(), 16, 1), 32, false),
    );
    let rounded = Expr::extract(b(B::Add, input.clone(), bias), 16, 16);
    Some(r.bind(Expr::select(
        b(B::Eq, exponent, c(32, 0)),
        b(B::And, high.clone(), c(16, 0x8000)),
        Expr::select(nan32(input), b(B::Or, high, c(16, 0x0040)), rounded),
    )))
}
fn fixed_fma(addend: Expr, a: Expr, z: Expr) -> Expr {
    Expr::float(FloatExpression {
        operation: FloatOperation::FusedMultiplyAdd {
            negate_product: false,
            negate_addend: false,
        },
        environment: FloatEnvironment::X86Mxcsr,
        width: 32,
        inputs: vec![addend, a, z],
        // RNE, all exceptions masked, DAZ and FTZ. These are fixed controls,
        // not architectural state and not a speculative write to MXCSR.
        control: Box::new(c(32, 0x9fc0)),
        status: Box::new(c(32, 0)),
        projection: FloatProjection::Value,
    })
}
fn widen_bfloat(pair: Expr, offset: u8) -> Expr {
    b(
        B::Shl,
        Expr::cast(Expr::extract(pair, offset, 16), 32, false),
        c(32, 16),
    )
}
/// VDPBF16PS lane: high-pair FMA first, then low-pair FMA, with one RNE
/// rounding and DAZ/FTZ at each step. NaN priority is a.low, b.low, a.high,
/// b.high, accumulator; every selected payload is quieted. Inactive lanes
/// evaluate neither inputs nor floating-point operations.
pub fn bf16_dot_add(
    r: &mut Recipe,
    accumulator: Expr,
    a: Expr,
    z: Expr,
    active: Expr,
    fallback: Expr,
) -> Option<Expr> {
    if [
        accumulator.ty.width,
        a.ty.width,
        z.ty.width,
        fallback.ty.width,
    ] != [32; 4]
        || active.ty.width != 1
    {
        return None;
    }
    let active = r.bind(active);
    let accumulator = r.bind(Expr::select(active.clone(), accumulator, c(32, 0)));
    let a = r.bind(Expr::select(active.clone(), a, c(32, 0)));
    let z = r.bind(Expr::select(active.clone(), z, c(32, 0)));
    let values = [
        widen_bfloat(a.clone(), 0),
        widen_bfloat(z.clone(), 0),
        widen_bfloat(a, 16),
        widen_bfloat(z, 16),
        accumulator.clone(),
    ];
    let mut nan = c(32, 0);
    let mut any_nan = c(1, 0);
    for value in values.iter().rev() {
        let is_nan = r.bind(nan32(value.clone()));
        nan = r.bind(Expr::select(is_nan.clone(), quiet32(value.clone()), nan));
        any_nan = b(B::Or, any_nan, is_nan);
    }
    let any_nan = r.bind(any_nan);
    let calculate = r.bind(b(B::And, active.clone(), not(any_nan.clone())));
    let high = r.bind(Expr::select(
        calculate.clone(),
        fixed_fma(accumulator, values[2].clone(), values[3].clone()),
        c(32, 0),
    ));
    let low = r.bind(Expr::select(
        calculate,
        fixed_fma(high, values[0].clone(), values[1].clone()),
        c(32, 0),
    ));
    Some(r.bind(Expr::select(
        active,
        Expr::select(any_nan, nan, low),
        fallback,
    )))
}

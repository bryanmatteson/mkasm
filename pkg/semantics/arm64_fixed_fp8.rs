//! Complete fixed-width AdvSIMD FP8 widening FMA and two/four-way dot products.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
// Mask, value, destination precision, dot product, indexed source, byte selector.
const FORMS: &[(u32, u32, u8, bool, bool, u16)] = &[
    (0xbfc0f400, 0x0f400000, 16, true, true, 0), // FDOT_asimdelem_G
    (0xbfe0fc00, 0x0e40fc00, 16, true, false, 0), // FDOT_asimdsame2_D
    (0xbfc0f400, 0x0f000000, 32, true, true, 0), // FDOT_asimdelem_D
    (0xbfe0fc00, 0x0e00fc00, 32, true, false, 0), // FDOT_asimdsame2_DD
    (0xffc0f400, 0x0fc00000, 16, false, true, 0), // FMLALB_asimdelem_H
    (0xffc0f400, 0x4fc00000, 16, false, true, 1), // FMLALT_asimdelem_H
    (0xffe0fc00, 0x0ec0fc00, 16, false, false, 0), // FMLALB_asimdsame2_J
    (0xffe0fc00, 0x4ec0fc00, 16, false, false, 1), // FMLALT_asimdsame2_J
    (0xffc0f400, 0x2f008000, 32, false, true, 0), // FMLALLBB_asimdelem_J
    (0xffc0f400, 0x2f408000, 32, false, true, 1), // FMLALLBT_asimdelem_J
    (0xffc0f400, 0x6f008000, 32, false, true, 2), // FMLALLTB_asimdelem_J
    (0xffc0f400, 0x6f408000, 32, false, true, 3), // FMLALLTT_asimdelem_J
    (0xffe0fc00, 0x0e00c400, 32, false, false, 0), // FMLALLBB_asimdsame2_G
    (0xffe0fc00, 0x0e40c400, 32, false, false, 1), // FMLALLBT_asimdsame2_G
    (0xffe0fc00, 0x4e00c400, 32, false, false, 2), // FMLALLTB_asimdsame2_G
    (0xffe0fc00, 0x4e40c400, 32, false, false, 3), // FMLALLTT_asimdsame2_G
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, w, dot, indexed, sel) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid fixed FP8 CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.guard = Expr::require_context(
        Expr::select(
            sm,
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "AdvSIMD FP8 streaming requires FA64",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let fpmr = r.bind(Expr::register(register("a64.fpmr", 0, 64, 64)));
    let n = (word >> 5) & 31;
    let d = word & 31;
    let m = (word >> 16)
        & if !indexed || dot && w == 32 {
            31
        } else if dot {
            15
        } else {
            7
        };
    let index = if !dot {
        ((word >> 11) & 1) * 8
            + ((word >> 21) & 1) * 4
            + ((word >> 20) & 1) * 2
            + ((word >> 19) & 1)
    } else if w == 16 {
        ((word >> 11) & 1) * 4 + ((word >> 21) & 1) * 2 + ((word >> 20) & 1)
    } else {
        ((word >> 11) & 1) * 2 + ((word >> 21) & 1)
    } as u16;
    let datasize = if dot && word & (1 << 30) == 0 {
        64
    } else {
        128
    };
    // All temporaries read incoming state, including D/N/M aliases. FP8 arithmetic
    // suppresses every FP exception; FPSR is neither consumed nor rewritten.
    for chunk in 0..datasize / 64 {
        let old = r.bind(lane(d, chunk, 64));
        let mut packed = c(64, 0);
        for sub in 0..64 / u16::from(w) {
            let e = chunk * (64 / u16::from(w)) + sub;
            let sw = if dot { w } else { 8 };
            let ai = if dot { e } else { e * u16::from(w / 8) + sel };
            let bi = if indexed { index } else { ai };
            let a = r.bind(lane(n, ai, sw));
            let rhs = r.bind(lane(m, bi, sw));
            let value = r.bind(Expr::float(FloatExpression {
                operation: if dot {
                    FloatOperation::Fp8Dot { ways: w / 8 }
                } else {
                    FloatOperation::Fp8WideningFused
                },
                environment: FloatEnvironment::A64,
                width: w,
                inputs: vec![
                    Expr::extract(old.clone(), (sub * u16::from(w)) as u8, w),
                    a,
                    rhs,
                    fpmr.clone(),
                ],
                control: Box::new(control.clone()),
                status: Box::new(c(32, 0)),
                projection: FloatProjection::Value,
            }));
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(sub * u16::from(w))),
                ),
            );
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    for chunk in datasize / 64..vl / 64 {
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            c(64, 0),
        );
    }
    Some(r)
}

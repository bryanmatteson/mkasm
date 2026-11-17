//! Complete classic predicated FP/BF16 ZA outer products.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, bool, bool, bool)] = &[
    (0xffe0001c, 0x81a00000, 32, false, true, false), // fmopa_za32_pp_zz_
    (0xffe0001c, 0x81a00010, 32, false, true, true),  // fmops_za32_pp_zz_
    (0xffe0001c, 0x81800000, 32, true, true, false),  // bfmopa_za32_pp_zz_
    (0xffe0001e, 0x81a00008, 16, true, false, false), // bfmopa_za_pp_zz_16
    (0xffe0001c, 0x81800010, 32, true, true, true),   // bfmops_za32_pp_zz_
    (0xffe0001e, 0x81a00018, 16, true, false, true),  // bfmops_za_pp_zz_16
    (0xffe0001e, 0x81800008, 16, false, false, false), // fmopa_za_pp_zz_16
    (0xffe0001c, 0x80800000, 32, false, false, false), // fmopa_za_pp_zz_32
    (0xffe00018, 0x80c00000, 64, false, false, false), // fmopa_za_pp_zz_64
    (0xffe0001e, 0x81800018, 16, false, false, true), // fmops_za_pp_zz_16
    (0xffe0001c, 0x80800010, 32, false, false, true), // fmops_za_pp_zz_32
    (0xffe00018, 0x80c00010, 64, false, false, true), // fmops_za_pp_zz_64
];
fn part(bank: &'static str, base: u16, bit: u16, w: u8) -> Expr {
    let mut r = register(bank, base + bit / 64, w, 64);
    r.offset = (bit % 64) as u8;
    Expr::register(r)
}
fn z(n: u32, e: u16, w: u8) -> Expr {
    part("a64.vector64", n as u16 * 32, e * u16::from(w), w)
}
fn pred(n: u32, e: u16, w: u8) -> Expr {
    part("a64.predicate64", n as u16 * 4, e * u16::from(w) / 8, 1)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, width, bfloat, dot, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid outer-product SVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    r.guard = Expr::require_context(
        b(
            B::Eq,
            b(
                B::And,
                Expr::register(register("a64.svcr", 0, 2, 2)),
                c(2, 3),
            ),
            c(2, 3),
        ),
        "outer product requires streaming and ZA enabled",
    );
    // Keep controls inside the conditional FP expression: a wholly
    // inactive tile does not consume FP context.
    let control = Expr::register(register("a64.fpcr", 0, 32, 32));
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pn = (word >> 10) & 7;
    let pm = (word >> 13) & 7;
    let tile = (word & u32::from(width / 8 - 1)) as u16;
    let dim = svl / u16::from(width);
    for row in 0..dim {
        let physical = row * u16::from(width) / 8 + tile;
        for chunk in 0..svl / 64 {
            let old = r.bind(part("a64.za64", physical * 32, chunk * 64, 64));
            let mut out = c(64, 0);
            for sub in 0..64 / u16::from(width) {
                let col = chunk * (64 / u16::from(width)) + sub;
                let acc = Expr::extract(old.clone(), (sub * u16::from(width)) as u8, width);
                let mut active = c(1, 0);
                let mut inputs = vec![acc.clone()];
                if dot {
                    let mut left = vec![];
                    let mut right = vec![];
                    for i in 0..2 {
                        let pa = r.bind(pred(pn, row * 2 + i, 16));
                        let pb = r.bind(pred(pm, col * 2 + i, 16));
                        active = b(B::Or, active, b(B::And, pa.clone(), pb.clone()));
                        let a = z(n, row * 2 + i, 16);
                        let a = if subtract {
                            b(B::Xor, a, c(16, 0x8000))
                        } else {
                            a
                        };
                        left.push(Expr::select(pa, a, c(16, 0)));
                        right.push(Expr::select(pb, z(m, col * 2 + i, 16), c(16, 0)));
                    }
                    inputs.extend(left);
                    inputs.extend(right);
                } else {
                    active = b(B::And, pred(pn, row, width), pred(pm, col, width));
                    let a = z(n, row, width);
                    inputs.push(if subtract {
                        b(B::Xor, a, c(width, 1u64 << (width - 1)))
                    } else {
                        a
                    });
                    inputs.push(z(m, col, width));
                }
                let value = Expr::float(FloatExpression {
                    operation: if dot {
                        if bfloat {
                            FloatOperation::BFloatDotAdd
                        } else {
                            FloatOperation::ZaHalfDot
                        }
                    } else {
                        FloatOperation::ZaFused { bfloat }
                    },
                    environment: FloatEnvironment::A64,
                    width,
                    inputs,
                    control: Box::new(control.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                });
                let value = r.bind(Expr::select(active, value, acc));
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(sub) * u64::from(width)),
                    ),
                );
            }
            r.write(
                register("a64.za64", physical * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                out,
            );
        }
    }
    Some(r)
}

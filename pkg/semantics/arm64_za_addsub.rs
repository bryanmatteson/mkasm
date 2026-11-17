//! All non-widening SME ZA ADD/SUB FP16/32/64 and BF16 groups.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, bool, bool)] = &[
    (0xffff9c38, 0xc1e41c00, 16, 2, true, false), // bfadd_za_zw_2x2_16
    (0xffff9c78, 0xc1e51c00, 16, 4, true, false), // bfadd_za_zw_4x4_16
    (0xffff9c38, 0xc1e41c08, 16, 2, true, true),  // bfsub_za_zw_2x2_16
    (0xffff9c78, 0xc1e51c08, 16, 4, true, true),  // bfsub_za_zw_4x4_16
    (0xffbf9c38, 0xc1a01c00, 0, 2, false, false), // fadd_za_zw_2x2
    (0xffff9c38, 0xc1a41c00, 16, 2, false, false), // fadd_za_zw_2x2_16
    (0xffbf9c78, 0xc1a11c00, 0, 4, false, false), // fadd_za_zw_4x4
    (0xffff9c78, 0xc1a51c00, 16, 4, false, false), // fadd_za_zw_4x4_16
    (0xffbf9c38, 0xc1a01c08, 0, 2, false, true),  // fsub_za_zw_2x2
    (0xffff9c38, 0xc1a41c08, 16, 2, false, true), // fsub_za_zw_2x2_16
    (0xffbf9c78, 0xc1a11c08, 0, 4, false, true),  // fsub_za_zw_4x4
    (0xffff9c78, 0xc1a51c08, 16, 4, false, true), // fsub_za_zw_4x4_16
];
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, fixed_width, nreg, bfloat, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid ZA add/sub SVL", next, 64));
    }
    let width = if fixed_width == 0 {
        32 << ((word >> 22) & 1)
    } else {
        fixed_width
    };
    let mut r = Recipe::new(next, 64);
    r.guard = Expr::require_context(
        b(
            B::Eq,
            b(
                B::And,
                Expr::register(register("a64.svcr", 0, 64, 64)),
                c(64, 3),
            ),
            c(64, 3),
        ),
        "ZA add/sub requires streaming and ZA enabled",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let stride = svl / 8 / nreg;
    let sum = b(
        B::Add,
        Expr::cast(
            Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
            64,
            false,
        ),
        c(64, u64::from(word & 7)),
    );
    let base = r.bind(b(B::Urem, sum, c(64, u64::from(stride))));
    let m = ((word >> 5) & 31) & (32 - u32::from(nreg));
    for member in 0..nreg {
        let row = b(B::Add, base.clone(), c(64, u64::from(member * stride)));
        for chunk in 0..svl / 64 {
            let dst = IndexedRegister {
                bank: "a64.za64",
                base: chunk,
                stride: 32,
                count: svl / 8,
                index: Box::new(row.clone()),
                offset: 0,
                width: 64,
                parent_width: 64,
            };
            let old = r.bind(Expr::indexed_register(dst.clone()));
            let source = r.bind(Expr::register(register(
                "a64.vector64",
                (m as u16 + member) * 32 + chunk,
                64,
                64,
            )));
            let mut out = c(64, 0);
            for part in 0..64 / u16::from(width) {
                let shift = (part * u16::from(width)) as u8;
                let value = r.bind(Expr::float(FloatExpression {
                    operation: FloatOperation::ZaBinary { bfloat, subtract },
                    environment: FloatEnvironment::A64,
                    width,
                    inputs: vec![
                        Expr::extract(old.clone(), shift, width),
                        Expr::extract(source.clone(), shift, width),
                    ],
                    control: Box::new(control.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                }));
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(shift)),
                    ),
                );
            }
            r.write_indexed(dst, WritePolicy::ZeroUpper, out);
        }
    }
    Some(r)
}

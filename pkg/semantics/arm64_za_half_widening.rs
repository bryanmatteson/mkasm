//! All SME2 FP16-to-FP32 ZA widening FMLAL/FMLSL forms.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xfff01018, 0xc1801000, 0, 1, false), // fmlal_za_zzi_1
    (0xfff09038, 0xc1901000, 0, 2, false), // fmlal_za_zzi_2xi
    (0xfff09078, 0xc1909000, 0, 4, false), // fmlal_za_zzi_4xi
    (0xfff09c18, 0xc1200c00, 1, 1, false), // fmlal_za_zzv_1
    (0xfff09c1c, 0xc1200800, 1, 2, false), // fmlal_za_zzv_2x1
    (0xfff09c1c, 0xc1300800, 1, 4, false), // fmlal_za_zzv_4x1
    (0xffe19c3c, 0xc1a00800, 2, 2, false), // fmlal_za_zzw_2x2
    (0xffe39c7c, 0xc1a10800, 2, 4, false), // fmlal_za_zzw_4x4
    (0xfff01018, 0xc1801008, 0, 1, true),  // fmlsl_za_zzi_1
    (0xfff09038, 0xc1901008, 0, 2, true),  // fmlsl_za_zzi_2xi
    (0xfff09078, 0xc1909008, 0, 4, true),  // fmlsl_za_zzi_4xi
    (0xfff09c18, 0xc1200c08, 1, 1, true),  // fmlsl_za_zzv_1
    (0xfff09c1c, 0xc1200808, 1, 2, true),  // fmlsl_za_zzv_2x1
    (0xfff09c1c, 0xc1300808, 1, 4, true),  // fmlsl_za_zzv_4x1
    (0xffe19c3c, 0xc1a00808, 2, 2, true),  // fmlsl_za_zzw_2x2
    (0xffe39c7c, 0xc1a10808, 2, 4, true),  // fmlsl_za_zzw_4x4
];
fn z(n: u32, e: u16) -> Expr {
    let bit = e * 16;
    let mut r = register("a64.vector64", n as u16 * 32 + bit / 64, 16, 64);
    r.offset = (bit % 64) as u8;
    Expr::register(r)
}
// Exact IEEE half expansion. FPMulAddH uses FPUnpack16, so FZ16 applies
// to half inputs independently of the FP32 accumulator's FZ/FIZ controls.
// AHP only affects conversions; it does not alter this arithmetic format.
fn expand(r: &mut Recipe, h: Expr, control: Expr) -> Expr {
    let h = r.bind(Expr::cast(h, 32, false));
    let sign = r.bind(b(B::Shl, b(B::And, h.clone(), c(32, 0x8000)), c(32, 16)));
    let exp = r.bind(b(B::And, h.clone(), c(32, 0x7c00)));
    let frac = r.bind(b(B::And, h.clone(), c(32, 0x3ff)));
    let mut sub = c(32, 0);
    for top in 0..10 {
        let value = b(
            B::Or,
            c(32, (top + 103) << 23),
            b(
                B::Shl,
                b(B::Sub, frac.clone(), c(32, 1 << top)),
                c(32, 23 - top),
            ),
        );
        sub = Expr::select(b(B::Ult, c(32, (1 << top) - 1), frac.clone()), value, sub);
    }
    let sub = Expr::select(Expr::extract(control, 19, 1), c(32, 0), sub);
    let normal = b(
        B::Or,
        b(B::Add, b(B::Shl, exp.clone(), c(32, 13)), c(32, 112 << 23)),
        b(B::Shl, frac.clone(), c(32, 13)),
    );
    let special = b(B::Or, c(32, 0x7f800000), b(B::Shl, frac, c(32, 13)));
    let magnitude = Expr::select(
        b(B::Eq, exp.clone(), c(32, 0)),
        sub,
        Expr::select(b(B::Eq, exp, c(32, 0x7c00)), special, normal),
    );
    r.bind(b(B::Or, sign, magnitude))
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, nreg, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid half ZA widening SVL",
            next,
            64,
        ));
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
        "half ZA widening requires streaming and ZA enabled",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let n = (word >> 5) & if kind == 1 { 31 } else { 32 - u32::from(nreg) };
    let m = (word >> 16) & if kind == 2 { 32 - u32::from(nreg) } else { 15 };
    let index = if nreg == 1 {
        ((word >> 15) & 1) * 4 + ((word >> 10) & 3)
    } else {
        ((word >> 10) & 3) * 2 + ((word >> 2) & 1)
    } as u16;
    let stride = svl / 8 / nreg;
    let off = (word & if nreg == 1 { 7 } else { 3 }) * 2;
    let row = r.bind(b(
        B::And,
        b(
            B::Urem,
            b(
                B::Add,
                Expr::cast(
                    Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                    64,
                    false,
                ),
                c(64, u64::from(off)),
            ),
            c(64, u64::from(stride)),
        ),
        c(64, !1u64),
    ));
    for member in 0..nreg {
        for pair in 0..2 {
            let row = b(
                B::Add,
                row.clone(),
                c(64, u64::from(member * stride + pair)),
            );
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
                let mut out = c(64, 0);
                for part in 0..2 {
                    let e = chunk * 2 + part;
                    let lane = e * 2 + pair;
                    let right = if kind == 0 {
                        2 * (e / 4 * 4) + index
                    } else {
                        lane
                    };
                    let a = z((n + u32::from(member)) % 32, lane);
                    let a = if subtract {
                        b(B::Xor, a, c(16, 0x8000))
                    } else {
                        a
                    };
                    let a = expand(&mut r, a, control.clone());
                    let y = z(m + if kind == 2 { u32::from(member) } else { 0 }, right);
                    let y = expand(&mut r, y, control.clone());
                    let v = r.bind(Expr::float(FloatExpression {
                        operation: FloatOperation::ZaFused { bfloat: false },
                        environment: FloatEnvironment::A64,
                        width: 32,
                        inputs: vec![Expr::extract(old.clone(), (part * 32) as u8, 32), a, y],
                        control: Box::new(control.clone()),
                        status: Box::new(c(32, 0)),
                        projection: FloatProjection::Value,
                    }));
                    out = b(
                        B::Or,
                        out,
                        b(
                            B::Shl,
                            Expr::cast(v, 64, false),
                            c(64, u64::from(part * 32)),
                        ),
                    );
                }
                r.write_indexed(dst, WritePolicy::ZeroUpper, out);
            }
        }
    }
    Some(r)
}

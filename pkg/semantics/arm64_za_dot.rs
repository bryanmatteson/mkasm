//! SME2 half-precision dot and FP16/BF16 vertical dot products into ZA.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xfff09038, 0xc1500018, 3, 2, true),  // bfvdot_za_zzi_2xi
    (0xfff09038, 0xc1501008, 0, 2, false), // fdot_za_zzi_2xi
    (0xfff09078, 0xc1509008, 0, 4, false), // fdot_za_zzi_4xi
    (0xfff09c18, 0xc1201000, 1, 2, false), // fdot_za_zzv_2x1
    (0xfff09c18, 0xc1301000, 1, 4, false), // fdot_za_zzv_4x1
    (0xffe19c38, 0xc1a01000, 2, 2, false), // fdot_za_zzw_2x2
    (0xffe39c78, 0xc1a11000, 2, 4, false), // fdot_za_zzw_4x4
    (0xfff09038, 0xc1500008, 3, 2, false), // fvdot_za_zzi_2xi
];
fn z(n: u32, e: u16) -> Expr {
    let bit = e * 16;
    let mut v = register("a64.vector64", n as u16 * 32 + bit / 64, 16, 64);
    v.offset = (bit % 64) as u8;
    Expr::register(v)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, nreg, bfloat) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid ZA dot SVL", next, 64));
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
        "ZA dot requires streaming and ZA enabled",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let n = (word >> 5) & if kind == 1 { 31 } else { 32 - u32::from(nreg) };
    let m = (word >> 16) & if kind == 2 { 32 - u32::from(nreg) } else { 15 };
    let index = ((word >> 10) & 3) as u16;
    let stride = svl / 8 / nreg;
    let row = r.bind(b(
        B::Urem,
        b(
            B::Add,
            Expr::cast(
                Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                64,
                false,
            ),
            c(64, u64::from(word & 7)),
        ),
        c(64, u64::from(stride)),
    ));
    for member in 0..nreg {
        let row = b(B::Add, row.clone(), c(64, u64::from(member * stride)));
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
                let src = if kind == 0 || kind == 3 {
                    2 * (e / 4 * 4 + index)
                } else {
                    2 * e
                };
                let (a0, a1) = if kind == 3 {
                    (z(n, 2 * e + member), z(n + 1, 2 * e + member))
                } else {
                    let reg = (n + u32::from(member)) % 32;
                    (z(reg, 2 * e), z(reg, 2 * e + 1))
                };
                let m = m + if kind == 2 { u32::from(member) } else { 0 };
                let value = r.bind(Expr::float(FloatExpression {
                    operation: if bfloat {
                        FloatOperation::BFloatDotAdd
                    } else {
                        FloatOperation::ZaHalfDot
                    },
                    environment: FloatEnvironment::A64,
                    width: 32,
                    inputs: vec![
                        Expr::extract(old.clone(), (part * 32) as u8, 32),
                        a0,
                        a1,
                        z(m, src),
                        z(m, src + 1),
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
                        c(64, u64::from(part * 32)),
                    ),
                );
            }
            r.write_indexed(dst, WritePolicy::ZeroUpper, out);
        }
    }
    Some(r)
}

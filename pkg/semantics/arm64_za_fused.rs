//! All non-widening ZA FMLA/FMLS and BFMLA/BFMLS classes.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, u8, bool, bool)] = &[
    (0xfff09030, 0xc1101020, 16, 2, 0, true, false), // bfmla_za_zzi_h2xi
    (0xfff09070, 0xc1109020, 16, 4, 0, true, false), // bfmla_za_zzi_h4xi
    (0xfff09c18, 0xc1601c00, 16, 2, 1, true, false), // bfmla_za_zzv_2x1_16
    (0xfff09c18, 0xc1701c00, 16, 4, 1, true, false), // bfmla_za_zzv_4x1_16
    (0xffe19c38, 0xc1e01008, 16, 2, 2, true, false), // bfmla_za_zzw_2x2_16
    (0xffe39c78, 0xc1e11008, 16, 4, 2, true, false), // bfmla_za_zzw_4x4_16
    (0xfff09030, 0xc1101030, 16, 2, 0, true, true),  // bfmls_za_zzi_h2xi
    (0xfff09070, 0xc1109030, 16, 4, 0, true, true),  // bfmls_za_zzi_h4xi
    (0xfff09c18, 0xc1601c08, 16, 2, 1, true, true),  // bfmls_za_zzv_2x1_16
    (0xfff09c18, 0xc1701c08, 16, 4, 1, true, true),  // bfmls_za_zzv_4x1_16
    (0xffe19c38, 0xc1e01018, 16, 2, 2, true, true),  // bfmls_za_zzw_2x2_16
    (0xffe39c78, 0xc1e11018, 16, 4, 2, true, true),  // bfmls_za_zzw_4x4_16
    (0xfff09030, 0xc1101000, 16, 2, 0, false, false), // fmla_za_zzi_h2xi
    (0xfff09038, 0xc1500000, 32, 2, 0, false, false), // fmla_za_zzi_s2xi
    (0xfff09838, 0xc1d00000, 64, 2, 0, false, false), // fmla_za_zzi_d2xi
    (0xfff09070, 0xc1109000, 16, 4, 0, false, false), // fmla_za_zzi_h4xi
    (0xfff09078, 0xc1508000, 32, 4, 0, false, false), // fmla_za_zzi_s4xi
    (0xfff09878, 0xc1d08000, 64, 4, 0, false, false), // fmla_za_zzi_d4xi
    (0xffb09c18, 0xc1201800, 0, 2, 1, false, false), // fmla_za_zzv_2x1
    (0xfff09c18, 0xc1201c00, 16, 2, 1, false, false), // fmla_za_zzv_2x1_16
    (0xffb09c18, 0xc1301800, 0, 4, 1, false, false), // fmla_za_zzv_4x1
    (0xfff09c18, 0xc1301c00, 16, 4, 1, false, false), // fmla_za_zzv_4x1_16
    (0xffa19c38, 0xc1a01800, 0, 2, 2, false, false), // fmla_za_zzw_2x2
    (0xffe19c38, 0xc1a01008, 16, 2, 2, false, false), // fmla_za_zzw_2x2_16
    (0xffa39c78, 0xc1a11800, 0, 4, 2, false, false), // fmla_za_zzw_4x4
    (0xffe39c78, 0xc1a11008, 16, 4, 2, false, false), // fmla_za_zzw_4x4_16
    (0xfff09030, 0xc1101010, 16, 2, 0, false, true), // fmls_za_zzi_h2xi
    (0xfff09038, 0xc1500010, 32, 2, 0, false, true), // fmls_za_zzi_s2xi
    (0xfff09838, 0xc1d00010, 64, 2, 0, false, true), // fmls_za_zzi_d2xi
    (0xfff09070, 0xc1109010, 16, 4, 0, false, true), // fmls_za_zzi_h4xi
    (0xfff09078, 0xc1508010, 32, 4, 0, false, true), // fmls_za_zzi_s4xi
    (0xfff09878, 0xc1d08010, 64, 4, 0, false, true), // fmls_za_zzi_d4xi
    (0xffb09c18, 0xc1201808, 0, 2, 1, false, true),  // fmls_za_zzv_2x1
    (0xfff09c18, 0xc1201c08, 16, 2, 1, false, true), // fmls_za_zzv_2x1_16
    (0xffb09c18, 0xc1301808, 0, 4, 1, false, true),  // fmls_za_zzv_4x1
    (0xfff09c18, 0xc1301c08, 16, 4, 1, false, true), // fmls_za_zzv_4x1_16
    (0xffa19c38, 0xc1a01808, 0, 2, 2, false, true),  // fmls_za_zzw_2x2
    (0xffe19c38, 0xc1a01018, 16, 2, 2, false, true), // fmls_za_zzw_2x2_16
    (0xffa39c78, 0xc1a11808, 0, 4, 2, false, true),  // fmls_za_zzw_4x4
    (0xffe39c78, 0xc1a11018, 16, 4, 2, false, true), // fmls_za_zzw_4x4_16
];
fn z(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut r = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    r.offset = (bit % 64) as u8;
    Expr::register(r)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, fixed_width, nreg, kind, bfloat, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid ZA fused SVL", next, 64));
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
        "ZA fused requires streaming and ZA enabled",
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
    let n = (word >> 5) & if kind == 1 { 31 } else { 32 - u32::from(nreg) };
    let m = (word >> 16) & if kind == 2 { 32 - u32::from(nreg) } else { 15 };
    let index = if width == 16 {
        ((word >> 10) & 3) * 2 + ((word >> 3) & 1)
    } else if width == 32 {
        (word >> 10) & 3
    } else {
        (word >> 10) & 1
    } as u16;
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
            let mut out = c(64, 0);
            for part in 0..64 / u16::from(width) {
                let e = chunk * (64 / u16::from(width)) + part;
                let rhs = if kind == 0 {
                    e / (128 / u16::from(width)) * (128 / u16::from(width)) + index
                } else {
                    e
                };
                let a = r.bind(z((n + u32::from(member)) % 32, e, width));
                // FPNeg/BFNeg preserve a NaN sign under AFP.AH. The subsequent
                // ZA FMA forces a default NaN, so either sign gives the same result.
                let a = if subtract {
                    b(B::Xor, a, c(width, 1u64 << (width - 1)))
                } else {
                    a
                };
                let b_ = r.bind(z(
                    m + if kind == 2 { u32::from(member) } else { 0 },
                    rhs,
                    width,
                ));
                let shift = (part * u16::from(width)) as u8;
                let result = r.bind(Expr::float(FloatExpression {
                    operation: FloatOperation::ZaFused { bfloat },
                    environment: FloatEnvironment::A64,
                    width,
                    inputs: vec![Expr::extract(old.clone(), shift, width), a, b_],
                    control: Box::new(control.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                }));
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(result, 64, false),
                        c(64, u64::from(shift)),
                    ),
                );
            }
            r.write_indexed(dst, WritePolicy::ZeroUpper, out);
        }
    }
    Some(r)
}

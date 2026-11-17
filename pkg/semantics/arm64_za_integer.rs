//! SME2 ZA integer ADD/SUB: accumulated, vector-broadcast and paired groups.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xffbf9c38, 0xc1a01c10, 0, 2, false), //add_za_zw_2x2
    (0xffbf9c78, 0xc1a11c10, 0, 4, false), //add_za_zw_4x4
    (0xffb09c18, 0xc1201810, 1, 2, false), //add_za_zzv_2x1
    (0xffb09c18, 0xc1301810, 1, 4, false), //add_za_zzv_4x1
    (0xffa19c38, 0xc1a01810, 2, 2, false), //add_za_zzw_2x2
    (0xffa39c78, 0xc1a11810, 2, 4, false), //add_za_zzw_4x4
    (0xffbf9c38, 0xc1a01c18, 0, 2, true),  //sub_za_zw_2x2
    (0xffbf9c78, 0xc1a11c18, 0, 4, true),  //sub_za_zw_4x4
    (0xffb09c18, 0xc1201818, 1, 2, true),  //sub_za_zzv_2x1
    (0xffb09c18, 0xc1301818, 1, 4, true),  //sub_za_zzv_4x1
    (0xffa19c38, 0xc1a01818, 2, 2, true),  //sub_za_zzw_2x2
    (0xffa39c78, 0xc1a11818, 2, 4, true),  //sub_za_zzw_4x4
];
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, layout, group, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid ZA integer SVL", next, 64));
    }
    let w = 32u8 << ((word >> 22) & 1);
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
        "ZA integer arithmetic requires streaming and ZA enabled",
    );
    let stride = svl / 8 / group;
    let base = r.bind(b(
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
    let n = (word >> 5)
        & if layout == 1 {
            31
        } else {
            32 - u32::from(group)
        };
    let m = if layout == 0 {
        n
    } else {
        (word >> 16)
            & if layout == 1 {
                15
            } else {
                32 - u32::from(group)
            }
    };
    let mut writes = Vec::new();
    for member in 0..group {
        let row = r.bind(b(B::Add, base.clone(), c(64, u64::from(member * stride))));
        for chunk in 0..svl / 64 {
            let dest = IndexedRegister {
                bank: "a64.za64",
                base: chunk,
                stride: 32,
                count: svl / 8,
                index: Box::new(row.clone()),
                offset: 0,
                width: 64,
                parent_width: 64,
            };
            let a = if layout == 0 {
                Expr::indexed_register(dest.clone())
            } else {
                Expr::register(register(
                    "a64.vector64",
                    ((n + u32::from(member)) % 32) as u16 * 32 + chunk,
                    64,
                    64,
                ))
            };
            let z = Expr::register(register(
                "a64.vector64",
                (m + if layout == 1 { 0 } else { u32::from(member) }) as u16 * 32 + chunk,
                64,
                64,
            ));
            let mut out = c(64, 0);
            for part in 0..64 / u16::from(w) {
                let shift = (part * u16::from(w)) as u8;
                let value = b(
                    if subtract { B::Sub } else { B::Add },
                    Expr::extract(a.clone(), shift, w),
                    Expr::extract(z.clone(), shift, w),
                );
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
            let value = r.bind(out);
            writes.push((dest, value));
        }
    }
    for (dest, value) in writes {
        r.write_indexed(dest, WritePolicy::ZeroUpper, value);
    }
    Some(r)
}

//! SVE pair arithmetic from the June 2026 physical instruction definitions.
//! Caller owns feature and SVE access admission. Preserve Z backing above VL.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn active(g: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w) / 8;
    Expr::extract(
        Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
fn abs_difference(r: &mut Recipe, a: Expr, z: Expr, signed: bool) -> Expr {
    let a = r.bind(a);
    let z = r.bind(z);
    Expr::select(
        b(if signed { B::Slt } else { B::Ult }, a.clone(), z.clone()),
        b(B::Sub, z.clone(), a.clone()),
        b(B::Sub, a, z),
    )
}
/// Unowned words return None; reserved size or invalid VL returns Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let base = word & 0xff20fc00;
    let quad = base == 0x04207800;
    let interleaved = base == 0x04207c00;
    let accumulate = matches!(base, 0x4400d400 | 0x4400dc00);
    let predicated = word & 0xff3fe000 == 0x4410a000;
    let complex = word & 0xff3ff800 == 0x4501d800;
    if !(quad || interleaved || accumulate || predicated || complex) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let w = 8u8 << ((word >> 22) & 3);
    if accumulate && w == 8 {
        return Some(Recipe::unsupported(
            "reserved SVE pair accumulation element size",
            next,
            64,
        ));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let mut r = Recipe::new(next, 64);
    let mut values = vec![];
    for e in 0..vl / u16::from(w) {
        let value = if quad {
            let per = 128 / u16::from(w);
            let segment = e / per;
            let pair = e % per;
            let source = if pair < per / 2 { n } else { m };
            let index = segment * per + (pair % (per / 2)) * 2;
            b(B::Add, lane(source, index, w), lane(source, index + 1, w))
        } else if interleaved {
            let source = if e % 2 == 0 { n } else { m };
            let index = e & !1;
            b(
                if e % 2 == 0 { B::Add } else { B::Sub },
                lane(source, index, w),
                lane(source, index + 1, w),
            )
        } else if accumulate {
            let signed = word & (1 << 11) == 0;
            let mut diff = vec![];
            for half in 0..2 {
                diff.push(abs_difference(
                    &mut r,
                    Expr::cast(lane(n, e * 2 + half, w / 2), w, signed),
                    Expr::cast(lane(m, e * 2 + half, w / 2), w, signed),
                    signed,
                ));
            }
            b(
                B::Add,
                lane(d, e, w),
                b(B::Add, diff.remove(0), diff.remove(0)),
            )
        } else if predicated {
            let source = if e % 2 == 0 { d } else { n };
            let index = e & !1;
            Expr::select(
                active((word >> 10) & 7, e, w),
                b(B::Sub, lane(source, index, w), lane(source, index + 1, w)),
                lane(d, e, w),
            )
        } else {
            let a = r.bind(lane(d, e, w));
            let z = r.bind(lane(n, e ^ 1, w));
            let sub = (e % 2 == 0) == (word & (1 << 10) == 0);
            let sum = r.bind(b(if sub { B::Sub } else { B::Add }, a.clone(), z.clone()));
            let overflow = Expr::overflow(sub, a.clone(), z, sum.clone());
            let bound = Expr::select(
                Expr::extract(a, w - 1, 1),
                c(w, 1u64 << (w - 1)),
                c(w, mask(w - 1)),
            );
            // SignedSat, rather than SignedSatQ, leaves FPSR.QC unchanged.
            Expr::select(overflow, bound, sum)
        };
        values.push(r.bind(value));
    }
    // Capture every source lane before writes, including destructive aliases.
    for (k, lanes) in values.chunks(64 / usize::from(w)).enumerate() {
        let mut out = c(64, 0);
        for (i, value) in lanes.iter().enumerate() {
            out = b(
                B::Or,
                out,
                b(
                    B::Shl,
                    Expr::cast(value.clone(), 64, false),
                    c(64, (i * usize::from(w)) as u64),
                ),
            );
        }
        let out = r.bind(out);
        r.write(
            register("a64.vector64", d as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
    Some(r)
}

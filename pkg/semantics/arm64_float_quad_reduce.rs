//! Every SVE2p1/SME2p1 floating quadword reduction.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8)] = &[
    (0xff3fe000, 0x6410a000, 0), // faddqv_z_p_z_
    (0xff3fe000, 0x6414a000, 3), // fmaxnmqv_z_p_z_
    (0xff3fe000, 0x6416a000, 1), // fmaxqv_z_p_z_
    (0xff3fe000, 0x6415a000, 4), // fminnmqv_z_p_z_
    (0xff3fe000, 0x6417a000, 2), // fminqv_z_p_z_
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn tree(r: &mut Recipe, fp: &mut FloatState, values: &[Expr], op: FloatOperation, w: u8) -> Expr {
    if values.len() == 1 {
        return values[0].clone();
    }
    // FPReduce evaluates high recursively before low, then combines (low,high).
    let half = values.len() / 2;
    let hi = tree(r, fp, &values[half..], op, w);
    let lo = tree(r, fp, &values[..half], op, w);
    fp.step(r, op, w, vec![lo, hi], c(1, 1), c(w, 0), true)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind) = FORMS
        .iter()
        .find(|(mask, value, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let size = (word >> 22) & 3;
    if size == 0 {
        return Some(Recipe::unsupported(
            "reserved floating quadword reduction size",
            next,
            64,
        ));
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid floating quadword reduction VL",
            next,
            64,
        ));
    }
    let w = 8u8 << size;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let g = (word >> 10) & 7;
    let per = 128 / u16::from(w);
    let mut r = Recipe::new(next, 64);
    let raw = Expr::register(register("a64.fpcr", 0, 32, 32));
    let identity = match kind {
        0 => c(w, 0),
        1 | 2 => c(
            w,
            match w {
                16 => 0x7c00,
                32 => 0x7f800000,
                _ => 0x7ff0000000000000,
            } | if kind == 1 { 1u64 << (w - 1) } else { 0 },
        ),
        _ => r.bind(b(
            B::Or,
            c(
                w,
                match w {
                    16 => 0x7e00,
                    32 => 0x7fc00000,
                    _ => 0x7ff8000000000000,
                },
            ),
            b(
                B::Shl,
                Expr::cast(Expr::extract(raw.clone(), 1, 1), w, false),
                c(w, u64::from(w - 1)),
            ),
        )),
    };
    let mut fp = if vl == 128 {
        None
    } else {
        let mut fp = FloatState::new(&mut r);
        let raw = b(B::And, raw, c(32, !(1u64 << 26)));
        fp.control = r.bind(Expr::select(
            Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1),
            Expr::select(
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                raw.clone(),
                b(B::And, raw.clone(), c(32, !0x9f00u64)),
            ),
            raw,
        ));
        Some(fp)
    };
    let operation = if kind == 0 {
        FloatOperation::Add
    } else {
        FloatOperation::MinMax {
            minimum: kind == 2 || kind == 4,
            numeric: kind >= 3,
        }
    };
    let mut output = Vec::new();
    for e in 0..per {
        let values = (0..vl / 128)
            .map(|segment| {
                let index = segment * per + e;
                let bit = index * u16::from(w / 8);
                let active = Expr::extract(
                    Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
                    (bit % 64) as u8,
                    1,
                );
                Expr::select(active, lane(n, index, w), identity.clone())
            })
            .collect::<Vec<_>>();
        output.push(if let Some(fp) = fp.as_mut() {
            tree(&mut r, fp, &values, operation, w)
        } else {
            r.bind(values[0].clone())
        });
    }
    if let Some(fp) = fp {
        fp.finish(&mut r);
    }
    for chunk in 0..vl / 64 {
        let mut packed = c(64, 0);
        if chunk < 2 {
            for part in 0..64 / u16::from(w) {
                let e = chunk * (64 / u16::from(w)) + part;
                packed = b(
                    B::Or,
                    packed,
                    b(
                        B::Shl,
                        Expr::cast(output[usize::from(e)].clone(), 64, false),
                        c(64, u64::from(part) * u64::from(w)),
                    ),
                );
            }
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    Some(r)
}

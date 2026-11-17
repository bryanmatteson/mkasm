//! SVE FFR transfers, conditional-not and scalar/immediate vector copies.
//! June2026 physical selectors. Feature/CheckSVEEnabled admission is caller-owned;
//! FFR additionally enforces non-streaming or effective SME_FA64 context.
//! P/FFR alias a64.predicate64[P*4+chunk], FFR=P16. Writes preserve MAX backing
//! above CurrentVL (the permitted non-SVEZEROUPPER alternative).
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn inv(v: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, v)
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn ps(n: u32, k: u16, w: u8) -> RegisterSlice {
    register("a64.predicate64", n as u16 * 4 + k, w, 64)
}
fn pc(n: u32, k: u16, w: u8) -> Expr {
    Expr::register(ps(n, k, w))
}
fn z(n: u32, k: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + k, 64, 64))
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
fn predicate(r: &mut Recipe, n: u32, vl: u16, w: u8) -> Vec<Expr> {
    let chunks: Vec<_> = (0..(vl / 8).div_ceil(64))
        .map(|k| r.bind(pc(n, k, ((vl / 8 - k * 64).min(64)) as u8)))
        .collect();
    (0..vl / u16::from(w))
        .map(|e| {
            let bit = e * u16::from(w / 8);
            Expr::extract(chunks[(bit / 64) as usize].clone(), (bit % 64) as u8, 1)
        })
        .collect()
}
fn write_p(r: &mut Recipe, n: u32, chunks: Vec<Expr>) {
    for (k, v) in chunks.into_iter().enumerate() {
        let w = v.ty.width;
        let v = r.bind(v);
        r.write(ps(n, k as u16, w), WritePolicy::Preserve, v);
    }
}
fn write_z(r: &mut Recipe, n: u32, values: Vec<Expr>, w: u8) {
    let values: Vec<_> = values.into_iter().map(|v| r.bind(v)).collect();
    for (k, ls) in values.chunks(64 / usize::from(w)).enumerate() {
        let mut out = c(64, 0);
        for (i, v) in ls.iter().enumerate() {
            out = b(
                B::Or,
                out,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), 64, false),
                    c(64, (i * usize::from(w)) as u64),
                ),
            );
        }
        let out = r.bind(out);
        r.write(
            register("a64.vector64", n as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
}
fn flags(r: &mut Recipe, m: &[Expr], v: &[Expr]) {
    let (mut first, mut last, mut any) = (c(1, 0), c(1, 0), c(1, 0));
    for (a, z) in m.iter().zip(v).rev() {
        first = r.bind(Expr::select(a.clone(), z.clone(), first));
    }
    for (a, z) in m.iter().zip(v) {
        last = r.bind(Expr::select(a.clone(), z.clone(), last));
        any = r.bind(b(B::Or, any, b(B::And, a.clone(), z.clone())));
    }
    for (i, v) in [first, inv(any), inv(last), c(1, 0)]
        .into_iter()
        .enumerate()
    {
        let v = r.bind(v);
        r.write(
            register("a64.nzcv", i as u16, 1, 1),
            WritePolicy::ZeroUpper,
            v,
        );
    }
}
fn non_streaming(r: &mut Recipe) {
    r.guard = Expr::require_context(
        Expr::select(
            Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "SVE FFR requires non-streaming mode or effective SME_FA64",
    );
}
fn fp_imm(i: u32, w: u8) -> u64 {
    let e = match w {
        16 => 5,
        32 => 8,
        _ => 11,
    };
    let f = u32::from(w) - e - 1;
    let bit = (i >> 6) & 1;
    let exp = ((bit ^ 1) << (e - 1))
        | ((if bit != 0 { (1 << (e - 3)) - 1 } else { 0 }) << 2)
        | ((i >> 4) & 3);
    (u64::from(i >> 7) << (w - 1)) | (u64::from(exp) << f) | (u64::from(i & 15) << (f - 4))
}
/// None means unowned physical family. Invalid owned selectors/VL are Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let rd = word & 0xfffffff0 == 0x2519f000;
    let rdp = matches!(word & 0xfffffe10, 0x2518f000 | 0x2558f000);
    let wr = word & 0xfffffe1f == 0x25289000;
    let set = word == 0x252c9000;
    let cn = matches!(word & 0xff3fe000, 0x041ba000 | 0x040ba000);
    let ci = matches!(word & 0xff30c000, 0x05100000 | 0x05104000);
    let cr = word & 0xff3fe000 == 0x0528a000;
    let cv = word & 0xff3fe000 == 0x05208000;
    let fc = word & 0xff30e000 == 0x0510c000;
    let fd = word & 0xff3fe000 == 0x2539c000;
    if !(rd || rdp || wr || set || cn || ci || cr || cv || fc || fd) {
        return None;
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid SVE CurrentVL",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    if rd || rdp || wr || set {
        non_streaming(&mut r);
        let pl = vl / 8;
        if wr {
            // Monotonic means low contiguous ones followed by zeros, across chunk edges.
            // Choice conditions use incoming registers, since entropy precedes bindings.
            let mut monotonic = c(1, 1);
            let mut lower_full = c(1, 1);
            for k in 0..pl.div_ceil(64) {
                let w = (pl - k * 64).min(64) as u8;
                let x = pc(n & 15, k, w);
                let lowones = b(
                    B::Eq,
                    b(B::And, x.clone(), b(B::Add, x.clone(), c(w, 1))),
                    c(w, 0),
                );
                let allowed = b(B::Or, lower_full.clone(), b(B::Eq, x.clone(), c(w, 0)));
                monotonic = b(B::And, monotonic, b(B::And, lowones, allowed));
                lower_full = b(B::And, lower_full, b(B::Eq, x, c(w, mask(w))));
            }
            let values = (0..pl.div_ceil(64))
                .map(|k| {
                    let w = (pl - k * 64).min(64) as u8;
                    let arbitrary = r.choose(w, Some(inv(monotonic.clone())));
                    Expr::select(monotonic.clone(), pc(n & 15, k, w), arbitrary)
                })
                .collect();
            write_p(&mut r, 16, values);
        } else {
            let mut out = vec![];
            for k in 0..pl.div_ceil(64) {
                let w = (pl - k * 64).min(64) as u8;
                let v = if set {
                    c(w, mask(w))
                } else if rdp {
                    b(B::And, pc(16, k, w), pc((word >> 5) & 15, k, w))
                } else {
                    pc(16, k, w)
                };
                out.push(r.bind(v));
            }
            if rdp && word & (1 << 22) != 0 {
                let m = predicate(&mut r, (word >> 5) & 15, vl, 8);
                let v = (0..pl)
                    .map(|e| Expr::extract(out[(e / 64) as usize].clone(), (e % 64) as u8, 1))
                    .collect::<Vec<_>>();
                flags(&mut r, &m, &v);
            }
            write_p(&mut r, if set { 16 } else { d & 15 }, out);
        }
        return Some(r);
    }
    let w = 8u8 << ((word >> 22) & 3);
    let sh = (word >> 13) & 1;
    if (ci && w == 8 && sh != 0) || ((fc || fd) && w == 8) {
        return Some(Recipe::unsupported(
            "reserved SVE copy size/shift",
            address.wrapping_add(4),
            64,
        ));
    }
    let pg = if ci || fc {
        (word >> 16) & 15
    } else {
        (word >> 10) & 7
    };
    let pred = if fd {
        vec![c(1, 1); usize::from(vl / u16::from(w))]
    } else {
        predicate(&mut r, pg, vl, w)
    };
    let mut any = c(1, 0);
    for a in &pred {
        any = r.bind(b(B::Or, any, a.clone()));
    }
    let scalar = if cr || cv {
        let src = if cv {
            lane(n, 0, w)
        } else {
            Expr::register(register(
                if n == 31 { "a64.sp" } else { "a64.gpr" },
                if n == 31 { 0 } else { n as u16 },
                w,
                64,
            ))
        };
        Some(r.bind(Expr::select(any, src, c(w, 0))))
    } else {
        None
    };
    let merge = if cn {
        word & (1 << 20) != 0
    } else {
        !fd && (!ci || word & (1 << 14) != 0)
    };
    let imm = (word >> 5) & 255;
    let constant = if fc || fd {
        fp_imm(imm, w)
    } else {
        (((imm as u8 as i8 as i64) as u64) << (sh * 8)) & mask(w)
    };
    let values = pred
        .into_iter()
        .enumerate()
        .map(|(e, a)| {
            let e = e as u16;
            let value = if cn {
                Expr::cast(b(B::Eq, lane(n, e, w), c(w, 0)), w, false)
            } else if let Some(v) = &scalar {
                v.clone()
            } else {
                c(w, constant)
            };
            Expr::select(a, value, if merge { lane(d, e, w) } else { c(w, 0) })
        })
        .collect();
    write_z(&mut r, d, values, w);
    Some(r)
}

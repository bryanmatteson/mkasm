//! Segment-local SVE quadword table, extract, duplicate, reverse and interleave.
//! June2026 physical masks. Caller owns feature/CheckSVEEnabled admission.
//! Z writes preserve MAX backing above CurrentVL (non-SVEZEROUPPER choice).
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn z(n: u32, k: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + k, 64, 64))
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
fn write(r: &mut Recipe, d: u32, values: Vec<Expr>, w: u8) {
    let values: Vec<_> = values.into_iter().map(|v| r.bind(v)).collect();
    for (k, lanes) in values.chunks(64 / usize::from(w)).enumerate() {
        let mut out = c(64, 0);
        for (i, v) in lanes.iter().enumerate() {
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
            register("a64.vector64", d as u16 * 32 + k as u16, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
}
/// None means unowned physical family; invalid owned selector/VL is Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let dup = word & 0xffe0fc00 == 0x05202400;
    let ext = word & 0xfff0fc00 == 0x05602400;
    let rev = matches!(word & 0xffffe000, 0x052e8000 | 0x052ea000);
    let op = match word & 0xff20fc00 {
        0x4400f800 => 0,
        0x05203400 => 1,
        0x4400e000 => 2,
        0x4400e400 => 3,
        0x4400e800 => 4,
        0x4400ec00 => 5,
        _ => 6,
    };
    if !(dup || ext || rev || op != 6) {
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
    let m = (word >> 16) & 31;
    let w = 8u8 << ((word >> 22) & 3);
    if dup {
        let imm = (word >> 16) & 31;
        let tsz = imm & 15;
        if tsz == 0 {
            return Some(Recipe::unsupported(
                "reserved SVE DUPQ tsz",
                address.wrapping_add(4),
                64,
            ));
        }
        let lsb = tsz.trailing_zeros();
        let w = 8u8 << lsb;
        let index = (imm >> (lsb + 1)) as u16;
        let per = 128 / u16::from(w);
        let mut values = vec![];
        for segment in 0..vl / 128 {
            let value = r.bind(lane(n, segment * per + index, w));
            values.extend((0..per).map(|_| value.clone()));
        }
        write(&mut r, d, values, w);
    } else if ext {
        let imm = ((word >> 16) & 15) as u16;
        let mut out = vec![];
        for s in 0..vl / 128 {
            for k in 0..2 {
                let byte = imm + k * 8;
                let q = byte / 8;
                let shift = byte % 8 * 8;
                let chunk = |i: u16| {
                    if i < 2 {
                        z(d, s * 2 + i)
                    } else {
                        z(n, s * 2 + i - 2)
                    }
                };
                let v = if shift == 0 {
                    chunk(q)
                } else {
                    b(
                        B::Or,
                        b(B::Lsr, chunk(q), c(64, u64::from(shift))),
                        b(B::Shl, chunk(q + 1), c(64, u64::from(64 - shift))),
                    )
                };
                out.push(v);
            }
        }
        write(&mut r, d, out, 64);
    } else if rev {
        let g = (word >> 10) & 7;
        let merging = word & (1 << 13) == 0;
        let pred: Vec<_> = (0..(vl / 8).div_ceil(64))
            .map(|k| {
                r.bind(Expr::register(register(
                    "a64.predicate64",
                    g as u16 * 4 + k,
                    (vl / 8 - k * 64).min(64) as u8,
                    64,
                )))
            })
            .collect();
        let mut out = vec![];
        for s in 0..vl / 128 {
            let bit = s * 16;
            let active = r.bind(Expr::extract(
                pred[(bit / 64) as usize].clone(),
                (bit % 64) as u8,
                1,
            ));
            for k in 0..2 {
                out.push(Expr::select(
                    active.clone(),
                    z(n, s * 2 + 1 - k),
                    if merging { z(d, s * 2 + k) } else { c(64, 0) },
                ));
            }
        }
        write(&mut r, d, out, 64);
    } else {
        let per = 128 / u16::from(w);
        let half = per / 2;
        let mut out = vec![];
        for s in 0..vl / 128 {
            for e in 0..per {
                let value = if op <= 1 {
                    let idx = r.bind(lane(m, s * per + e, w));
                    let inside = r.bind(b(B::Ult, idx.clone(), c(w, u64::from(per))));
                    // The range check surrounds every table read. Select exactly one64-bit
                    // table chunk, then shift within it; no128-bit expression/lookup chain.
                    let chunk = Expr::select(
                        b(B::Ult, idx.clone(), c(w, u64::from(half))),
                        z(n, s * 2),
                        z(n, s * 2 + 1),
                    );
                    let shift = b(
                        B::Shl,
                        b(
                            B::And,
                            Expr::cast(idx, 64, false),
                            c(64, u64::from(half - 1)),
                        ),
                        c(64, u64::from(w.trailing_zeros())),
                    );
                    let entry = Expr::cast(b(B::Lsr, chunk, shift), w, false);
                    Expr::select(
                        inside,
                        entry,
                        if op == 1 {
                            lane(d, s * per + e, w)
                        } else {
                            c(w, 0)
                        },
                    )
                } else if op <= 3 {
                    let source = if e % 2 == 0 { n } else { m };
                    lane(source, s * per + (op as u16 - 2) * half + e / 2, w)
                } else {
                    let source = if e < half { n } else { m };
                    lane(source, s * per + 2 * (e % half) + (op as u16 - 4), w)
                };
                out.push(value);
            }
        }
        write(&mut r, d, out, w);
    }
    Some(r)
}

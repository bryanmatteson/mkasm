//! SVE predicate/vector packed moves, indexed predicate select and first/last
//! intersection indices. June2026 physical forms; feature/CheckSVEEnabled
//! admission belongs to the caller. CurrentVL is explicit, MAX backing above
//! CurrentVL is preserved, and no flags, FP state or memory are accessed.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn slice(bank: &'static str, n: u32, stride: u16, bit: u16, width: u8) -> RegisterSlice {
    let mut s = register(bank, n as u16 * stride + bit / 64, width, 64);
    s.offset = (bit % 64) as u8;
    s
}
fn pbit(n: u32, bit: u16) -> Expr {
    Expr::register(slice("a64.predicate64", n, 4, bit, 1))
}
fn packed(r: &mut Recipe, bits: Vec<Expr>, width: u8) -> Expr {
    let mut v = c(width, 0);
    for (i, bit) in bits.into_iter().enumerate() {
        v = b(
            B::Or,
            v,
            b(B::Shl, Expr::cast(bit, width, false), c(width, i as u64)),
        );
    }
    r.bind(v)
}
fn pmov_size(word: u32, vector: bool) -> Option<(u8, u16)> {
    let (mask, base) = if vector {
        (0xfffffe00, 0x052b3800)
    } else {
        (0xfffffc10, 0x052a3800)
    };
    if word & mask == base {
        return Some((8, 0));
    }
    if word & (mask & !0x00020000) == base + 0x00020000 {
        return Some((16, ((word >> 17) & 1) as u16));
    }
    if word & (mask & !0x00060000) == base + 0x003e0000 {
        return Some((32, ((word >> 17) & 3) as u16));
    }
    if word & (mask & !0x00460000) == base + 0x007e0000 {
        return Some((64, ((((word >> 22) & 1) << 2) | ((word >> 17) & 3)) as u16));
    }
    None
}
// A balanced lazy selector reads only the selected predicate element, including
// when other elements or register chunks are unavailable.
fn select_element(n: u32, first: u16, count: u16, step: u16, index: &Expr) -> Expr {
    if count == 1 {
        return pbit(n, first * step);
    }
    let lower = count / 2;
    Expr::select(
        b(B::Ult, index.clone(), c(32, u64::from(first + lower))),
        select_element(n, first, lower, step, index),
        select_element(n, first + lower, count - lower, step, index),
    )
}
/// Unrelated physical neighbors return None. Invalid owned selectors or VL
/// explicitly return Unsupported; all allocated size/immediate forms are exact.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let to_z = pmov_size(word, true);
    let to_p = pmov_size(word, false);
    let psel = word & 0xff20c210 == 0x25204000;
    let first = word & 0xff3fc200 == 0x25218000;
    let last = word & 0xff3fc200 == 0x25228000;
    if to_z.is_none() && to_p.is_none() && !psel && !first && !last {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let pl = vl / 8;
    if let Some((width, imm)) = to_z.or(to_p) {
        let elements = vl / u16::from(width);
        let offset = elements * imm;
        if to_z.is_some() {
            let d = word & 31;
            let n = (word >> 5) & 15;
            let bits: Vec<_> = (0..elements)
                .map(|e| r.bind(pbit(n, e * u16::from(width / 8))))
                .collect();
            if imm == 0 {
                for k in 0..vl / 64 {
                    let from = k * 64;
                    let values = if from < elements {
                        bits[from as usize..usize::from((from + 64).min(elements))].to_vec()
                    } else {
                        vec![]
                    };
                    let v = packed(&mut r, values, 64);
                    r.write(
                        register("a64.vector64", d as u16 * 32 + k, 64, 64),
                        WritePolicy::ZeroUpper,
                        v,
                    );
                }
            } else {
                // Narrow architectural writes avoid an eager old-destination
                // expression; preservation retains unselected bits, including
                // their availability, through the ordinary write contract.
                let mut done = 0;
                while done < elements {
                    let at = offset + done;
                    let count = (64 - at % 64).min(elements - done);
                    let v = packed(
                        &mut r,
                        bits[done as usize..usize::from(done + count)].to_vec(),
                        count as u8,
                    );
                    r.write(
                        slice("a64.vector64", d, 32, at, count as u8),
                        WritePolicy::Preserve,
                        v,
                    );
                    done += count;
                }
            }
        } else {
            let d = word & 15;
            let n = (word >> 5) & 31;
            for k in 0..pl.div_ceil(64) {
                let w = (pl - k * 64).min(64) as u8;
                let mut out = c(w, 0);
                for at in 0..u16::from(w) {
                    let bit = k * 64 + at;
                    if bit % u16::from(width / 8) != 0 {
                        continue;
                    }
                    let e = bit / u16::from(width / 8);
                    let v = r.bind(Expr::register(slice("a64.vector64", n, 32, offset + e, 1)));
                    out = b(
                        B::Or,
                        out,
                        b(B::Shl, Expr::cast(v, w, false), c(w, u64::from(at))),
                    );
                }
                let out = r.bind(out);
                r.write(
                    slice("a64.predicate64", d, 4, k * 64, w),
                    WritePolicy::Preserve,
                    out,
                );
            }
        }
    } else if psel {
        let tsz = ((word >> 19) & 8) | ((word >> 18) & 7);
        if tsz == 0 {
            return Some(Recipe::unsupported("reserved PSEL element size", next, 64));
        }
        let size = tsz.trailing_zeros();
        let width = 8u16 << size;
        let imm = ((((word >> 23) & 1) << 4) | tsz) >> (size + 1);
        let x = Expr::register(register("a64.gpr", 12 + ((word >> 16) & 3) as u16, 32, 64));
        let index = r.bind(b(
            B::And,
            b(B::Add, x, c(32, u64::from(imm))),
            c(32, u64::from(vl / width - 1)),
        ));
        let active = r.bind(select_element(
            (word >> 5) & 15,
            0,
            vl / width,
            width / 8,
            &index,
        ));
        for k in 0..pl.div_ceil(64) {
            let w = (pl - k * 64).min(64) as u8;
            let v = r.bind(Expr::select(
                active.clone(),
                Expr::register(slice("a64.predicate64", (word >> 10) & 15, 4, k * 64, w)),
                c(w, 0),
            ));
            r.write(
                slice("a64.predicate64", word & 15, 4, k * 64, w),
                WritePolicy::Preserve,
                v,
            );
        }
    } else if word & 31 != 31 {
        let width = 8u16 << ((word >> 22) & 3);
        let mut index = c(64, u64::MAX);
        for i in 0..vl / width {
            let e = if first { i } else { vl / width - i - 1 };
            let active = Expr::select(
                pbit((word >> 10) & 15, e * (width / 8)),
                pbit((word >> 5) & 15, e * (width / 8)),
                c(1, 0),
            );
            index = r.bind(Expr::select(
                b(B::Eq, index.clone(), c(64, u64::MAX)),
                Expr::select(active, c(64, u64::from(e)), index.clone()),
                index,
            ));
        }
        r.write(
            register("a64.gpr", (word & 31) as u16, 64, 64),
            WritePolicy::ZeroUpper,
            index,
        );
    }
    Some(r)
}

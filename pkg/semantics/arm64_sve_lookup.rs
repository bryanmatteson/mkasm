//! June2026 packed SVE LUTI2/4/6. Tables start at the bottom of their source
//! vectors; they do not repeat per 128-bit segment. Packed indices span the
//! whole vector, and two-source tables wrap register numbers modulo 32.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn packed_index(n: u32, bit: u16, width: u8) -> Expr {
    let offset = (bit % 64) as u8;
    let first = width.min(64 - offset);
    let low = Expr::extract(z(n, bit / 64), offset, first);
    if first == width {
        return low;
    }
    let high = Expr::extract(z(n, bit / 64 + 1), 0, width - first);
    b(
        B::Or,
        Expr::cast(low, width, false),
        b(
            B::Shl,
            Expr::cast(high, width, false),
            c(width, u64::from(first)),
        ),
    )
}
fn selected_chunk(chunks: &[Expr], index: Expr, base: u64) -> Expr {
    if chunks.len() == 1 {
        return chunks[0].clone();
    }
    let half = chunks.len() / 2;
    Expr::select(
        b(B::Ult, index.clone(), c(8, base + half as u64)),
        selected_chunk(&chunks[..half], index.clone(), base),
        selected_chunk(&chunks[half..], index, base + half as u64),
    )
}
// Fixed AdvSIMD forms use 128-bit tables and indices independently of CurrentVL.
// Keeping the packed extraction and balanced selector shared avoids a separate
// interpretation of register wrapping or variable element selection.
fn fixed(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let (width, index_width, part, sources) = if word & 0xffa08c00 == 0x4e800000 {
        if word & (1 << 22) == 0 {
            if word & (1 << 12) == 0 {
                return None;
            }
            (8u8, 2u8, (word >> 13) & 3, 1)
        } else {
            (16, 2, (word >> 12) & 7, 1)
        }
    } else if word & 0xffe08c00 == 0x4e400000 {
        if word & (1 << 12) == 0 {
            if word & (1 << 13) == 0 {
                return None;
            }
            (8, 4, (word >> 14) & 1, 1)
        } else {
            (16, 4, (word >> 13) & 3, 2)
        }
    } else {
        return None;
    };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "AdvSIMD lookup requires an allocated CurrentVL",
            next,
            64,
        ));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let mut r = Recipe::new(next, 64);
    let chunks: Vec<_> = (0..sources)
        .flat_map(|source| (0..2).map(move |chunk| z((n + source) % 32, chunk)))
        .collect();
    for output in 0..2 {
        let mut packed = c(64, 0);
        for lane in 0..64 / u16::from(width) {
            let element = output * (64 / u16::from(width)) + lane;
            let at = ((128 / u16::from(width)) * part as u16 + element) * u16::from(index_width);
            let index = r.bind(Expr::cast(packed_index(m, at, index_width), 8, false));
            let chunk = selected_chunk(
                &chunks,
                b(
                    B::Lsr,
                    index.clone(),
                    c(8, (64 / width).trailing_zeros() as u64),
                ),
                0,
            );
            let shift = b(
                B::Mul,
                b(B::And, index, c(8, u64::from(64 / width - 1))),
                c(8, u64::from(width)),
            );
            let value = r.bind(Expr::cast(
                b(B::Lsr, chunk, Expr::cast(shift, 64, false)),
                width,
                false,
            ));
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(lane) * u64::from(width)),
                ),
            );
        }
        let packed = r.bind(packed);
        r.write(
            register("a64.vector64", d as u16 * 32 + output, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    for chunk in 2..vl / 64 {
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            c(64, 0),
        );
    }
    Some(r)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if let Some(r) = fixed(word, address, vl) {
        return Some(r);
    }

    let (width, index_width, part, per_source, sources, minimum, sme_context) =
        if word & 0xff20fc00 == 0x4520b000 {
            (8u8, 2u8, (word >> 22) & 3, 1, 1, 128, true)
        } else if word & 0xff20ec00 == 0x4520a800 {
            (
                16,
                2,
                (((word >> 22) & 3) << 1) | ((word >> 12) & 1),
                1,
                1,
                128,
                true,
            )
        } else if word & 0xff60fc00 == 0x4560a400 {
            (8, 4, (word >> 23) & 1, 2, 1, 128, true)
        } else if word & 0xff20fc00 == 0x4520b400 {
            (16, 4, (word >> 22) & 3, 2, 2, 128, true)
        } else if word & 0xff20fc00 == 0x4520bc00 {
            (16, 4, (word >> 22) & 3, 4, 1, 256, true)
        } else if word & 0xff60fc00 == 0x4560ac00 {
            (16, 6, (word >> 23) & 1, 8, 2, 512, false)
        } else if word & 0xffe0fc00 == 0x4520ac00 {
            (8, 6, 0, 4, 2, 256, false)
        } else {
            return None;
        };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) || vl < minimum {
        return Some(Recipe::unsupported(
            "SVE lookup requires an allocated CurrentVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    if sme_context || width == 8 && index_width == 6 {
        let non_streaming = Expr::select(
            Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        );
        let permitted = if sme_context {
            Expr::select(
                Expr::register(register("a64.sme2", 0, 1, 1)),
                c(1, 1),
                non_streaming,
            )
        } else {
            non_streaming
        };
        r.bind(Expr::require_context(
            permitted,
            "SVE lookup requires SME2 or non-streaming SVE access",
        ));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let chunks: Vec<_> = (0..sources)
        .flat_map(|source| (0..per_source).map(move |chunk| z((n + source) % 32, chunk)))
        .collect();
    let elements = vl / u16::from(width);
    for output in 0..vl / 64 {
        let mut packed = c(64, 0);
        for lane in 0..64 / u16::from(width) {
            let element = output * (64 / u16::from(width)) + lane;
            let at = (elements * part as u16 + element) * u16::from(index_width);
            let index = r.bind(Expr::cast(packed_index(m, at, index_width), 8, false));
            let chunk_index = b(
                B::Lsr,
                index.clone(),
                c(8, (64 / width).trailing_zeros() as u64),
            );
            let chunk = selected_chunk(&chunks, chunk_index, 0);
            let shift = b(
                B::Mul,
                b(B::And, index, c(8, u64::from(64 / width - 1))),
                c(8, u64::from(width)),
            );
            let value = r.bind(Expr::cast(
                b(B::Lsr, chunk, Expr::cast(shift, 64, false)),
                width,
                false,
            ));
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(lane) * u64::from(width)),
                ),
            );
        }
        let packed = r.bind(packed);
        r.write(
            register("a64.vector64", d as u16 * 32 + output, 64, 64),
            WritePolicy::ZeroUpper,
            packed,
        );
    }
    Some(r)
}

// SME table lookup, including multi-register indices and the vector-table
// LUTI6 forms. Chunk addresses follow CurrentSVL, never the physical MAX_VL
// backing stride when crossing from one index register into the next.
fn sme_index(n: u32, bit: u16, width: u8, vl: u16) -> Expr {
    let chunk = |at: u16| z((n + u32::from(at / vl)) % 32, (at % vl) / 64);
    let offset = (bit % 64) as u8;
    let first = width.min(64 - offset);
    let low = Expr::extract(chunk(bit), offset, first);
    if first == width {
        return low;
    }
    b(
        B::Or,
        Expr::cast(low, width, false),
        b(
            B::Shl,
            Expr::cast(
                Expr::extract(chunk(bit + u16::from(first)), 0, width - first),
                width,
                false,
            ),
            c(width, u64::from(first)),
        ),
    )
}
/// All seventeen physical SME LUTI2/4/6 classes from the June2026 corpus.
pub fn sme(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    // mask,base,outputs,strided,index bits,imm shift,bits,kind
    // kind0:32-bit ZT0 entries;1:two index vectors;2:byte ZT0;
    // kind3:three index vectors;4:two512-bit vector tables.
    const FORMS: [(u32, u32, u16, bool, u8, u8, u8, u8); 17] = [
        (0xfffc4c01, 0xc08c4000, 2, false, 2, 15, 3, 0),
        (0xfffc4c08, 0xc09c4000, 2, true, 2, 15, 3, 0),
        (0xfffccc03, 0xc08c8000, 4, false, 2, 16, 2, 0),
        (0xfffccc0c, 0xc09c8000, 4, true, 2, 16, 2, 0),
        (0xfffc0c00, 0xc0cc0000, 1, false, 2, 14, 4, 0),
        (0xfffe4c01, 0xc08a4000, 2, false, 4, 15, 2, 0),
        (0xfffe4c08, 0xc09a4000, 2, true, 4, 15, 2, 0),
        (0xffffcc23, 0xc08b0000, 4, false, 4, 0, 0, 1),
        (0xffffcc2c, 0xc09b0000, 4, true, 4, 0, 0, 1),
        (0xfffecc03, 0xc08a8000, 4, false, 4, 16, 1, 0),
        (0xfffecc0c, 0xc09a8000, 4, true, 4, 16, 1, 0),
        (0xfffe0c00, 0xc0ca0000, 1, false, 4, 14, 3, 0),
        (0xffa0fc03, 0xc120f400, 4, false, 6, 22, 1, 4),
        (0xffa0fc0c, 0xc120fc00, 4, true, 6, 22, 1, 4),
        (0xfffffc63, 0xc08a0000, 4, false, 6, 0, 0, 3),
        (0xfffffc6c, 0xc09a0000, 4, true, 6, 0, 0, 3),
        (0xfffffc00, 0xc0c84000, 1, false, 6, 0, 0, 2),
    ];
    let &(_, _, count, strided, iw, shift, ibits, kind) = FORMS
        .iter()
        .find(|&&(mask, base, ..)| word & mask == base)?;
    let next = address.wrapping_add(4);
    let width = if kind >= 2 {
        if kind == 4 {
            16
        } else {
            8
        }
    } else {
        8u8 << ((word >> 12) & 3)
    };
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048)
        || kind == 4 && vl < 512
        || width > 32
        || strided && kind == 0 && width == 32
        || kind == 0 && count == 4 && iw == 4 && width == 8
        || kind == 1 && width != 8
    {
        return Some(Recipe::unsupported(
            "reserved SME lookup size or streaming vector length",
            next,
            64,
        ));
    }
    let d = if count == 1 {
        word & 31
    } else if strided {
        (word & 16) | (word & (16 / u32::from(count) - 1))
    } else {
        word & (32 - u32::from(count))
    };
    let stride = if strided { 16 / count } else { 1 };
    let n = if kind == 1 {
        (word >> 5) & 30
    } else if kind == 3 {
        (word >> 7) & 7
    } else {
        (word >> 5) & 31
    };
    let imm = (word >> shift) & ((1 << ibits) - 1);
    let segment = if kind == 0 {
        imm % (u32::from(width) / (u32::from(iw) * u32::from(count)))
    } else {
        0
    };
    let elements = vl / u16::from(width);
    let mut r = Recipe::new(next, 64);
    let state = Expr::register(register("a64.svcr", 0, 2, 2));
    let required = if kind == 4 { 1 } else { 3 };
    r.guard = Expr::require_context(
        b(B::Eq, b(B::And, state, c(2, required)), c(2, required)),
        "SME lookup requires streaming mode and enabled table state",
    );
    let table: Vec<_> = if kind == 4 {
        (0..2)
            .flat_map(|source| {
                (0..8).map(move |chunk| z((((word >> 5) & 31) + source) % 32, chunk))
            })
            .collect()
    } else {
        (0..8)
            .map(|chunk| Expr::register(register("a64.zt064", chunk, 64, 64)))
            .collect()
    };
    let source = if kind == 4 { (word >> 16) & 31 } else { n };
    for member in 0..count {
        let target = d + u32::from(member * stride);
        for output in 0..vl / 64 {
            let mut packed = c(64, 0);
            for lane in 0..64 / u16::from(width) {
                let e = output * (64 / u16::from(width)) + lane;
                let at = if kind == 4 {
                    imm as u16 * (vl / 2) + (member * elements + e) * u16::from(iw)
                } else {
                    ((segment as u16 * count + member) * elements + e) * u16::from(iw)
                };
                let index = r.bind(Expr::cast(sme_index(source, at, iw, vl), 8, false));
                let table_width = if kind <= 1 { 32 } else { width };
                let chunk = selected_chunk(
                    &table,
                    b(
                        B::Lsr,
                        index.clone(),
                        c(8, (64 / table_width).trailing_zeros() as u64),
                    ),
                    0,
                );
                let position = b(
                    B::Mul,
                    b(B::And, index, c(8, u64::from(64 / table_width - 1))),
                    c(8, u64::from(table_width)),
                );
                let value = r.bind(Expr::cast(
                    b(B::Lsr, chunk, Expr::cast(position, 64, false)),
                    width,
                    false,
                ));
                packed = b(
                    B::Or,
                    packed,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(lane) * u64::from(width)),
                    ),
                );
            }
            let packed = r.bind(packed);
            r.write(
                register("a64.vector64", target as u16 * 32 + output, 64, 64),
                WritePolicy::ZeroUpper,
                packed,
            );
        }
    }
    Some(r)
}

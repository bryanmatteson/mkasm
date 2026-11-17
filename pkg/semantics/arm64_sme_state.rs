//! SME extract-and-zero, selected ZA zeroing and complete ZT0 state moves.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn z(n: u16, chunk: u16) -> RegisterSlice {
    register("a64.vector64", n * 32 + chunk, 64, 64)
}
fn za(row: u16, chunk: u16) -> RegisterSlice {
    register("a64.za64", row * 32 + chunk, 64, 64)
}
fn indexed(row: Expr, chunk: u16, svl: u16) -> IndexedRegister {
    IndexedRegister {
        bank: "a64.za64",
        base: chunk,
        stride: 32,
        count: svl / 8,
        index: Box::new(row),
        offset: 0,
        width: 64,
        parent_width: 64,
    }
}
const FORMS: &[(u32, u32, u8, u16, u16, u16)] = &[
    (0xffff1f01, 0xc0060200, 0, 8, 2, 1),   //movaz_mz2_za_b1
    (0xffff1f01, 0xc0460200, 0, 16, 2, 1),  //movaz_mz2_za_h1
    (0xffff1f01, 0xc0860200, 0, 32, 2, 1),  //movaz_mz2_za_w1
    (0xffff1f01, 0xc0c60200, 0, 64, 2, 1),  //movaz_mz2_za_d1
    (0xffff1f83, 0xc0060600, 0, 8, 4, 1),   //movaz_mz4_za_b1
    (0xffff1f83, 0xc0460600, 0, 16, 4, 1),  //movaz_mz4_za_h1
    (0xffff1f83, 0xc0860600, 0, 32, 4, 1),  //movaz_mz4_za_w1
    (0xffff1f03, 0xc0c60600, 0, 64, 4, 1),  //movaz_mz4_za_d1
    (0xffff9f01, 0xc0060a00, 1, 8, 2, 1),   //movaz_mz_za2_1
    (0xffff9f03, 0xc0060e00, 1, 8, 4, 1),   //movaz_mz_za4_1
    (0xffff1e00, 0xc0020200, 0, 8, 1, 1),   //movaz_z_rza_b
    (0xffff1e00, 0xc0420200, 0, 16, 1, 1),  //movaz_z_rza_h
    (0xffff1e00, 0xc0820200, 0, 32, 1, 1),  //movaz_z_rza_w
    (0xffff1e00, 0xc0c20200, 0, 64, 1, 1),  //movaz_z_rza_d
    (0xffff1e00, 0xc0c30200, 0, 128, 1, 1), //movaz_z_rza_q
    (0xffff8fe0, 0xc04c03e0, 5, 8, 1, 1),   //movt_r_zt_
    (0xffff8fe0, 0xc04e03e0, 4, 8, 1, 1),   //movt_zt_r_
    (0xffffcfe0, 0xc04f03e0, 6, 8, 1, 1),   //movt_zt_z_
    (0xffff9ff8, 0xc00c0000, 2, 8, 2, 1),   //zero_za1_ri_2
    (0xffff9ff8, 0xc00e0000, 2, 8, 4, 1),   //zero_za1_ri_4
    (0xffff9ff8, 0xc00c8000, 2, 8, 1, 2),   //zero_za2_ri_1
    (0xffff9ffc, 0xc00d0000, 2, 8, 2, 2),   //zero_za2_ri_2
    (0xffff9ffc, 0xc00d8000, 2, 8, 4, 2),   //zero_za2_ri_4
    (0xffff9ffc, 0xc00e8000, 2, 8, 1, 4),   //zero_za4_ri_1
    (0xffff9ffe, 0xc00f0000, 2, 8, 2, 4),   //zero_za4_ri_2
    (0xffff9ffe, 0xc00f8000, 2, 8, 4, 4),   //zero_za4_ri_4
    (0xffffffff, 0xc0480001, 3, 8, 1, 1),   //zero_zt_i_
];
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, width, group, rows) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let mut r = Recipe::new(next, 64);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048)
        || kind == 0 && group == 4 && width == 64 && svl < 256
    {
        return Some(Recipe::unsupported(
            "SME state move requires a legal streaming length and enough slices",
            next,
            64,
        ));
    }
    let required = if matches!(kind, 3 | 4 | 5) { 2 } else { 3 };
    let mode = b(
        B::Eq,
        b(
            B::And,
            Expr::register(register("a64.svcr", 0, 2, 2)),
            c(2, required),
        ),
        c(2, required),
    );
    r.guard=Expr::require_context(if matches!(kind,4|5){Expr::select(mode,Expr::register(register("a64.debug_halted",0,1,1)),c(1,0))}else{mode},"SME state move requires enabled SM/ZA; scalar ZT0 moves additionally require debug Halted state");
    if kind >= 3 {
        let t = (word & 31) as u16;
        let offset = ((word >> 12) & 7) as u16;
        match kind {
            3 => {
                for chunk in 0..8 {
                    r.write(
                        register("a64.zt064", chunk, 64, 64),
                        WritePolicy::ZeroUpper,
                        c(64, 0),
                    );
                }
            }
            4 => {
                let value = if t == 31 {
                    c(64, 0)
                } else {
                    Expr::register(register("a64.gpr", t, 64, 64))
                };
                r.write(
                    register("a64.zt064", offset, 64, 64),
                    WritePolicy::ZeroUpper,
                    value,
                );
            }
            5 => {
                if t != 31 {
                    r.write(
                        register("a64.gpr", t, 64, 64),
                        WritePolicy::ZeroUpper,
                        Expr::register(register("a64.zt064", offset, 64, 64)),
                    );
                }
            }
            6 => {
                let imm = ((word >> 12) & 3) as u16;
                let chunks = svl.min(512) / 64;
                let offset = (imm % (8 / chunks)) * chunks;
                for chunk in 0..8 {
                    let value = if (offset..offset + chunks).contains(&chunk) {
                        Expr::register(z(t, chunk - offset))
                    } else if imm == 0 {
                        c(64, 0)
                    } else {
                        Expr::register(register("a64.zt064", chunk, 64, 64))
                    };
                    r.write(
                        register("a64.zt064", chunk, 64, 64),
                        WritePolicy::ZeroUpper,
                        value,
                    );
                }
            }
            _ => unreachable!(),
        }
        return Some(r);
    }
    let selector = Expr::cast(
        Expr::register(register(
            "a64.gpr",
            (if kind == 0 { 12 } else { 8 }) + ((word >> 13) & 3) as u16,
            32,
            64,
        )),
        64,
        false,
    );
    if kind == 1 || kind == 2 {
        let offset = if kind == 1 {
            (word >> 5) & 7
        } else {
            (word
                & if rows == 1 {
                    7
                } else if rows == 2 && group == 1 {
                    7
                } else if rows == 4 && group != 1 {
                    1
                } else {
                    3
                })
                * u32::from(rows)
        };
        let stride = svl / 8 / group;
        let first = r.bind(b(
            B::And,
            b(
                B::Urem,
                b(B::Add, selector, c(64, u64::from(offset))),
                c(64, u64::from(stride)),
            ),
            c(64, !(u64::from(rows) - 1)),
        ));
        for member in 0..group {
            for row in 0..rows {
                let index = r.bind(b(
                    B::Add,
                    first.clone(),
                    c(64, u64::from(member * stride + row)),
                ));
                for chunk in 0..svl / 64 {
                    let dst = indexed(index.clone(), chunk, svl);
                    if kind == 1 {
                        let value = r.bind(Expr::indexed_register(dst.clone()));
                        r.write(
                            z((word & 31) as u16 + member, chunk),
                            WritePolicy::ZeroUpper,
                            value,
                        );
                    }
                    r.write_indexed(dst, WritePolicy::ZeroUpper, c(64, 0));
                }
            }
            if kind == 1 {
                for chunk in svl / 64..32 {
                    r.write(
                        z((word & 31) as u16 + member, chunk),
                        WritePolicy::ZeroUpper,
                        c(64, 0),
                    );
                }
            }
        }
        return Some(r);
    }
    let offbits = (4 - (width / 8).trailing_zeros()).saturating_sub(group.trailing_zeros());
    let low = (word >> 5) & 15;
    let tile = (low >> offbits) as u16;
    let offset = (low & ((1 << offbits) - 1)) * u32::from(group);
    let vertical = word & (1 << 15) != 0;
    let d = (word & 31) as u16;
    let first = r.bind(b(
        B::Urem,
        b(
            B::Add,
            b(B::And, selector, c(64, !u64::from(group - 1))),
            c(64, u64::from(offset)),
        ),
        c(64, u64::from(svl / width)),
    ));
    let selected = (0..group)
        .map(|member| r.bind(b(B::Add, first.clone(), c(64, u64::from(member)))))
        .collect::<Vec<_>>();
    if !vertical {
        for (member, slice) in selected.iter().enumerate() {
            let row = r.bind(b(
                B::Add,
                b(B::Mul, slice.clone(), c(64, u64::from(width / 8))),
                c(64, u64::from(tile)),
            ));
            for chunk in 0..svl / 64 {
                let dst = indexed(row.clone(), chunk, svl);
                let value = r.bind(Expr::indexed_register(dst.clone()));
                r.write(z(d + member as u16, chunk), WritePolicy::ZeroUpper, value);
                r.write_indexed(dst, WritePolicy::ZeroUpper, c(64, 0));
            }
            for chunk in svl / 64..32 {
                r.write(
                    z(d + member as u16, chunk),
                    WritePolicy::ZeroUpper,
                    c(64, 0),
                );
            }
        }
    } else {
        let lane = width.min(64) as u8;
        let halves = (width / 64).max(1);
        let positions = selected
            .iter()
            .map(|slice| {
                let bit = r.bind(b(B::Mul, slice.clone(), c(64, u64::from(width))));
                let chunk = r.bind(b(B::Lsr, bit.clone(), c(64, 6)));
                let shift = r.bind(b(B::And, bit, c(64, 63)));
                (chunk, shift)
            })
            .collect::<Vec<_>>();
        for (member, (source_chunk, shift)) in positions.iter().enumerate() {
            for chunk in 0..svl / 64 {
                let mut packed = c(64, 0);
                for part in 0..64 / u16::from(lane) {
                    let bit = chunk * 64 + part * u16::from(lane);
                    let row = bit / width * width / 8 + tile;
                    let half = (bit % width) / 64;
                    let target = r.bind(b(B::Add, source_chunk.clone(), c(64, u64::from(half))));
                    let mut value = c(64, 0);
                    for src in (0..svl / 64).rev() {
                        value = Expr::select(
                            b(B::Eq, target.clone(), c(64, u64::from(src))),
                            Expr::register(za(row, src)),
                            value,
                        );
                    }
                    let value = Expr::extract(b(B::Lsr, value, shift.clone()), 0, lane);
                    packed = b(
                        B::Or,
                        packed,
                        b(
                            B::Shl,
                            Expr::cast(value, 64, false),
                            c(64, u64::from(part) * u64::from(lane)),
                        ),
                    );
                }
                let value = r.bind(packed);
                r.write(z(d + member as u16, chunk), WritePolicy::ZeroUpper, value);
            }
            for chunk in svl / 64..32 {
                r.write(
                    z(d + member as u16, chunk),
                    WritePolicy::ZeroUpper,
                    c(64, 0),
                );
            }
        }
        let mut masks = Vec::new();
        for chunk in 0..svl / 64 {
            let mut clear = c(64, 0);
            for (source_chunk, shift) in &positions {
                for half in 0..halves {
                    clear = b(
                        B::Or,
                        clear,
                        Expr::select(
                            b(
                                B::Eq,
                                b(B::Add, source_chunk.clone(), c(64, u64::from(half))),
                                c(64, u64::from(chunk)),
                            ),
                            b(B::Shl, c(64, mask(lane)), shift.clone()),
                            c(64, 0),
                        ),
                    );
                }
            }
            masks.push(r.bind(clear));
        }
        for row in 0..svl / width {
            for chunk in 0..svl / 64 {
                let dst = za(row * width / 8 + tile, chunk);
                r.write(
                    dst,
                    WritePolicy::ZeroUpper,
                    b(
                        B::And,
                        Expr::register(dst),
                        Expr::unary(UnaryOp::Not, masks[chunk as usize].clone()),
                    ),
                );
            }
        }
    }
    Some(r)
}

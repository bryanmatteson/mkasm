//! All fixed AdvSIMD FP8 conversion classes in the June 2026 primary tables.
use super::*;
use arm64_sve::FloatState;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn lane(n: u32, bit: u16, w: u8) -> Expr {
    let mut s = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    s.offset = (bit % 64) as u8;
    Expr::register(s)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if matches!(word & !31, 0xd51b4440 | 0xd53b4440) {
        let mut r = Recipe::new(address.wrapping_add(4), 64);
        let rt = (word & 31) as u16;
        let fpmr = register("a64.fpmr", 0, 64, 64);
        if word & (1 << 21) != 0 {
            if rt != 31 {
                r.write(
                    register("a64.gpr", rt, 64, 64),
                    WritePolicy::ZeroUpper,
                    Expr::register(fpmr),
                );
            }
        } else {
            let value = if rt == 31 {
                c(64, 0)
            } else {
                Expr::register(register("a64.gpr", rt, 64, 64))
            };
            let mask = (63u64 << 32) | (255 << 24) | (127 << 16) | (3 << 14) | 511;
            r.write(
                fpmr,
                WritePolicy::ZeroUpper,
                Expr::binary(BinaryOp::And, value, c(64, mask)),
            );
        }
        return Some(r);
    }
    let widen = word & 0xbf3ffc00 == 0x2e217800;
    let narrow16 = word & 0xbfe0fc00 == 0x0e40f400;
    let narrow32 = word & 0xbfe0fc00 == 0x0e00f400;
    if !(widen || narrow16 || narrow32) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid A64 CurrentVL", next, 64));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let q = word & (1 << 30) != 0;
    let (source_width, target_width, elements) = if widen {
        (8, 16, 8)
    } else if narrow16 {
        (16, 8, if q { 8 } else { 4 })
    } else {
        (32, 8, 4)
    };
    let mut r = Recipe::new(next, 64);
    let fpmr = r.bind(Expr::register(register("a64.fpmr", 0, 64, 64)));
    let mut fp = FloatState::new(&mut r);
    let operation = FloatOperation::Fp8Convert {
        source_width,
        bfloat: widen && word & (1 << 23) != 0,
        source2: widen && word & (1 << 22) != 0,
    };
    let mut chunks = vec![c(64, 0); usize::from(vl / 64)];
    // Vpart(d,1) preserves low 64 bits. Vpart(d,0) clears all upper Z bits.
    if narrow32 && q {
        chunks[0] = r.bind(lane(d, 0, 64));
    }
    // Primary narrowing order interleaves source1[e], source2[e], so an
    // enabled exception stops at the architecturally first failing element.
    for e in 0..elements {
        for source in 0..if widen { 1 } else { 2 } {
            let input_bit = e * u16::from(source_width) + if widen && q { 64 } else { 0 };
            let input = r.bind(lane(
                if source == 0 { n } else { m },
                input_bit,
                source_width,
            ));
            let value = fp.step(
                &mut r,
                operation,
                target_width,
                vec![input, fpmr.clone()],
                c(1, 1),
                c(target_width, 0),
                false,
            );
            let output_bit = if widen {
                e * 16
            } else {
                (source * elements + e) * 8 + if narrow32 && q { 64 } else { 0 }
            };
            let chunk = &mut chunks[usize::from(output_bit / 64)];
            *chunk = Expr::binary(
                BinaryOp::Or,
                chunk.clone(),
                Expr::binary(
                    BinaryOp::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(output_bit % 64)),
                ),
            );
        }
    }
    fp.finish(&mut r);
    for (i, value) in chunks.into_iter().enumerate() {
        r.write(
            register("a64.vector64", d as u16 * 32 + i as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(r)
}

// Fixed physical diagrams, June 2026: mask, value, lane layout, BF16, source2.
const SCALABLE: &[(u32, u32, u8, bool, bool)] = &[
    (0xfffffc00, 0x65093800, 1, true, false), // bf1cvtlt_z_z8_b2bf
    (0xfffffc00, 0x65093c00, 1, true, true),  // bf2cvtlt_z_z8_b2bf
    (0xfffffc01, 0xc166e001, 3, true, false), // bf1cvtl_mz2_z8_
    (0xfffffc01, 0xc1e6e001, 3, true, true),  // bf2cvtl_mz2_z8_
    (0xfffffc01, 0xc166e000, 2, true, false), // bf1cvt_mz2_z8_
    (0xfffffc01, 0xc1e6e000, 2, true, true),  // bf2cvt_mz2_z8_
    (0xfffffc00, 0x65083800, 0, true, false), // bf1cvt_z_z8_b2bf
    (0xfffffc00, 0x65083c00, 0, true, true),  // bf2cvt_z_z8_b2bf
    (0xfffffc00, 0x65093000, 1, false, false), // f1cvtlt_z_z8_b2h
    (0xfffffc00, 0x65093400, 1, false, true), // f2cvtlt_z_z8_b2h
    (0xfffffc01, 0xc126e001, 3, false, false), // f1cvtl_mz2_z8_
    (0xfffffc01, 0xc1a6e001, 3, false, true), // f2cvtl_mz2_z8_
    (0xfffffc01, 0xc126e000, 2, false, false), // f1cvt_mz2_z8_
    (0xfffffc01, 0xc1a6e000, 2, false, true), // f2cvt_mz2_z8_
    (0xfffffc00, 0x65083000, 0, false, false), // f1cvt_z_z8_b2h
    (0xfffffc00, 0x65083400, 0, false, true), // f2cvt_z_z8_b2h
    (0xfffffc20, 0x650a3400, 5, false, false), // fcvtnb_z8_mz2_s2b
    (0xfffffc20, 0x650a3c00, 6, false, false), // fcvtnt_z8_mz2_s2b
    (0xfffffc20, 0x650a3000, 4, false, false), // fcvtn_z8_mz2_h2b
    (0xfffffc60, 0xc134e020, 9, false, false), // fcvtn_z8_mz4_
    (0xfffffc20, 0xc164e000, 7, true, false), // bfcvt_z8_mz2_
    (0xfffffc20, 0x650a3800, 4, true, false), // bfcvtn_z8_mz2_bf2b
    (0xfffffc20, 0xc124e000, 7, false, false), // fcvt_z8_mz2_
    (0xfffffc60, 0xc134e000, 8, false, false), // fcvt_z8_mz4_
];
/// SVE and SME conversion layouts. CurrentVL and SVL are independent context
/// values; SME-only groups use SVL and require SM, while ordinary SVE forms
/// use CurrentVL and permit streaming only when effective SME2 is present.
pub fn scalable(word: u32, address: u64, current_vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, bfloat, source2) = SCALABLE
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let streaming = matches!(kind, 2 | 3 | 7 | 8 | 9);
    let vl = if streaming { svl } else { current_vl };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid FP8 CurrentVL/SVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.guard = Expr::require_context(
        if streaming {
            sm
        } else {
            Expr::select(
                sm,
                Expr::binary(
                    BinaryOp::Or,
                    Expr::register(register("a64.sme2", 0, 1, 1)),
                    Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                ),
                c(1, 1),
            )
        },
        "FP8 conversion streaming admission",
    );
    let d = word & if matches!(kind, 2 | 3) { 30 } else { 31 };
    let n = (word >> 5)
        & if matches!(kind, 4 | 5 | 6 | 7) {
            30
        } else if matches!(kind, 8 | 9) {
            28
        } else {
            31
        };
    let source_width = if kind < 4 {
        8
    } else if matches!(kind, 4 | 7) {
        16
    } else {
        32
    };
    let width = if kind < 4 { 16 } else { 8 };
    let source_count = if kind < 4 {
        1
    } else if matches!(kind, 8 | 9) {
        4
    } else {
        2
    };
    let elements = vl / u16::from(if kind < 2 { 16 } else { source_width });
    let mut chunks =
        vec![vec![c(64, 0); usize::from(vl / 64)]; if matches!(kind, 2 | 3) { 2 } else { 1 }];
    if kind == 6 {
        for (chunk, value) in chunks[0].iter_mut().enumerate() {
            *value = r.bind(lane(d, chunk as u16 * 64, 64));
        }
    }
    let fpmr = r.bind(Expr::register(register("a64.fpmr", 0, 64, 64)));
    let mut fp = FloatState::new(&mut r);
    // FPProcessException suppresses traps in streaming SVE when full A64 is
    // disabled. Preserve cumulative flags and every other effective control.
    let control = fp.control.clone();
    fp.control = Expr::select(
        Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
        Expr::select(
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            control.clone(),
            Expr::binary(BinaryOp::And, control.clone(), c(32, !0x9f00u64)),
        ),
        control,
    );

    let operation = FloatOperation::Fp8Convert {
        source_width,
        bfloat,
        source2,
    };
    for e in 0..elements {
        for source in 0..source_count {
            let bit = if kind < 2 {
                e * 16 + u16::from(kind == 1) * 8
            } else {
                e * u16::from(source_width)
            };
            let value = fp.step(
                &mut r,
                operation,
                width,
                vec![lane(n + u32::from(source), bit, source_width), fpmr.clone()],
                c(1, 1),
                c(width, 0),
                false,
            );
            let (destination, outbit) = match kind {
                0 | 1 => (0, e * 16),
                2 => (usize::from(e / (vl / 16)), e % (vl / 16) * 16),
                3 => (usize::from(e % 2), e / 2 * 16),
                4 => (0, (e * 2 + source) * 8),
                5 => (0, (e * 2 + source) * 16),
                6 => (0, (e * 2 + source) * 16 + 8),
                7 | 8 => (0, (source * elements + e) * 8),
                9 => (0, (e * 4 + source) * 8),
                _ => unreachable!(),
            };
            let chunk = &mut chunks[destination][usize::from(outbit / 64)];
            if kind == 6 {
                *chunk = Expr::binary(
                    BinaryOp::And,
                    chunk.clone(),
                    c(64, !(255u64 << (outbit % 64))),
                );
            }
            *chunk = Expr::binary(
                BinaryOp::Or,
                chunk.clone(),
                Expr::binary(
                    BinaryOp::Shl,
                    Expr::cast(value, 64, false),
                    c(64, u64::from(outbit % 64)),
                ),
            );
        }
    }
    fp.finish(&mut r);
    for (i, mut values) in chunks.into_iter().enumerate() {
        // A Z{VL} assignment zeros the entire retained backing above VL.
        values.resize(32, c(64, 0));
        for (chunk, value) in values.into_iter().enumerate() {
            r.write(
                register(
                    "a64.vector64",
                    (d as u16 + i as u16) * 32 + chunk as u16,
                    64,
                    64,
                ),
                WritePolicy::ZeroUpper,
                value,
            );
        }
    }
    Some(r)
}

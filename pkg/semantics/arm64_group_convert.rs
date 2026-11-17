//! Grouped IEEE/BF16 and integer conversion, including SVE2p3 narrowing.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u16)] = &[
    (0xfffffc20, 0xc160e020, 5, 2),  // bfcvtn_z_mz2_
    (0xfffffc20, 0xc160e000, 4, 2),  // bfcvt_z_mz2_
    (0xfffffc01, 0xc1a0e001, 1, 2),  // fcvtl_mz2_z_
    (0xfffffc20, 0xc120e020, 3, 2),  // fcvtn_z_mz2_
    (0xff3ffc20, 0x650d3000, 8, 2),  // fcvtzsn_z_mz2_
    (0xfffffc21, 0xc121e000, 6, 2),  // fcvtzs_mz_z_2
    (0xfffffc63, 0xc131e000, 6, 4),  // fcvtzs_mz_z_4
    (0xff3ffc20, 0x650d3400, 9, 2),  // fcvtzun_z_mz2_
    (0xfffffc21, 0xc121e020, 7, 2),  // fcvtzu_mz_z_2
    (0xfffffc63, 0xc131e020, 7, 4),  // fcvtzu_mz_z_4
    (0xfffffc01, 0xc1a0e000, 0, 2),  // fcvt_mz2_z_
    (0xfffffc20, 0xc120e000, 2, 2),  // fcvt_z_mz2_
    (0xfffffc21, 0xc122e000, 10, 2), // scvtf_mz_z_2
    (0xfffffc63, 0xc132e000, 10, 4), // scvtf_mz_z_4
    (0xfffffc21, 0xc122e020, 11, 2), // ucvtf_mz_z_2
    (0xfffffc63, 0xc132e020, 11, 4), // ucvtf_mz_z_4
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
pub fn a64(word: u32, address: u64, vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, nreg) = FORMS
        .iter()
        .find(|(mask, value, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let narrow_int = kind == 8 || kind == 9;
    let len = if narrow_int { vl } else { svl };
    if !matches!(len, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid grouped conversion vector length",
            next,
            64,
        ));
    }
    let (src, dst) = if narrow_int {
        let size = (word >> 22) & 3;
        if size == 0 {
            return Some(Recipe::unsupported(
                "reserved grouped conversion size",
                next,
                64,
            ));
        }
        let src = 8u8 << size;
        (src, src / 2)
    } else if kind <= 1 {
        (16, 32)
    } else if kind <= 5 {
        (32, 16)
    } else {
        (32, 32)
    };
    let wide = kind <= 1;
    let format = kind <= 5;
    let d = if wide || kind >= 6 && !narrow_int {
        word & (32 - u32::from(nreg))
    } else {
        word & 31
    };
    let n = if wide {
        (word >> 5) & 31
    } else {
        (word >> 5)
            & if format || narrow_int {
                30
            } else {
                32 - u32::from(nreg)
            }
    };
    let mut r = Recipe::new(next, 64);
    if !narrow_int {
        r.guard = Expr::require_context(
            Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1),
            "grouped conversion requires streaming mode",
        );
    }
    let mut fp = FloatState::new(&mut r);
    // Streaming exception enables are RES0 without effective FA64; AHP is
    // ignored by FPConvertSVE and has no effect on integer or BF16 conversion.
    let raw = b(B::And, fp.control.clone(), c(32, !(1u64 << 26)));
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 2, 2)), 0, 1);
    fp.control = r.bind(Expr::select(
        if narrow_int { sm } else { c(1, 1) },
        Expr::select(
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            raw.clone(),
            b(B::And, raw.clone(), c(32, !0x9f00u64)),
        ),
        raw,
    ));
    let operation = if kind <= 3 {
        FloatOperation::Convert {
            source_width: src,
            round_to_odd: false,
        }
    } else if kind <= 5 {
        FloatOperation::ToBFloat16
    } else if kind == 10 || kind == 11 {
        FloatOperation::FromInteger {
            source_width: src,
            signed: kind == 10,
            fractional_bits: 0,
        }
    } else {
        FloatOperation::ToInteger {
            source_width: src,
            signed: kind == 6 || kind == 8,
            fractional_bits: 0,
            rounding: FloatRounding::Zero,
        }
    };
    let outputs = if wide || !format && !narrow_int {
        nreg
    } else {
        1
    };
    let mut values = vec![vec![c(dst, 0); usize::from(len / u16::from(dst))]; usize::from(outputs)];
    // Append operations in primary pseudocode order, separately from physical
    // destination packing. This matters when the second source traps first.
    let mut convert = |r: &mut Recipe, sn: u32, se: u16, dn: u16, de: u16| {
        let value = fp.step(
            r,
            operation,
            dst,
            vec![lane(sn, se, src)],
            c(1, 1),
            c(dst, 0),
            true,
        );
        values[usize::from(dn)][usize::from(de)] = value;
    };
    if wide {
        for e in 0..len / 16 {
            let (out, el) = if kind == 0 {
                (e / (len / 32), e % (len / 32))
            } else {
                (e % 2, e / 2)
            };
            convert(&mut r, n, e, out, el);
        }
    } else if format || narrow_int {
        for e in 0..len / u16::from(src) {
            for member in 0..2u16 {
                let de = if kind == 2 || kind == 4 {
                    member * (len / u16::from(src)) + e
                } else {
                    e * 2 + member
                };
                convert(&mut r, n + u32::from(member), e, 0, de);
            }
        }
    } else {
        for member in 0..nreg {
            for e in 0..len / 32 {
                convert(&mut r, n + u32::from(member), e, member, e);
            }
        }
    }
    fp.finish(&mut r);
    for (member, lanes) in values.into_iter().enumerate() {
        for (chunk, parts) in lanes.chunks(usize::from(64 / dst)).enumerate() {
            let mut packed = c(64, 0);
            for (part, v) in parts.iter().enumerate() {
                packed = b(
                    B::Or,
                    packed,
                    b(
                        B::Shl,
                        Expr::cast(v.clone(), 64, false),
                        c(64, part as u64 * u64::from(dst)),
                    ),
                );
            }
            r.write(
                register(
                    "a64.vector64",
                    (d as u16 + member as u16) * 32 + chunk as u16,
                    64,
                    64,
                ),
                WritePolicy::ZeroUpper,
                packed,
            );
        }
    }
    Some(r)
}

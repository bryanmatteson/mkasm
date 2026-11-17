//! Complete classic AdvSIMD FHM, complex arithmetic and FP immediates.
//! FP operations share ordered FPSR/trap handling with scalable arithmetic;
//! all fixed-width writes clear active upper Z state and preserve backing.
use super::*;
use arm64_sve::{fp_abs, fp_neg, FloatState};
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut s = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    s.offset = (bit % 64) as u8;
    Expr::register(s)
}
fn finish(r: &mut Recipe, d: u32, w: u8, values: Vec<Expr>, vl: u16) {
    let mut chunks = vec![c(64, 0); usize::from(vl / 64)];
    for (e, value) in values.into_iter().enumerate() {
        let bit = e * u32::from(w) as usize;
        let slot = &mut chunks[bit / 64];
        *slot = Expr::binary(
            BinaryOp::Or,
            slot.clone(),
            Expr::binary(
                BinaryOp::Shl,
                Expr::cast(value, 64, false),
                c(64, (bit % 64) as u64),
            ),
        );
    }
    for (chunk, value) in chunks.into_iter().enumerate() {
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
// Scalar arithmetic merges from the source selected by its primary operation.
// Only the 128-bit V image participates in merging; remaining active Z is zero.
fn finish_scalar(r: &mut Recipe, d: u32, source: u32, w: u8, value: Expr, control: Expr, vl: u16) {
    let merging = Expr::extract(control, 2, 1);
    let low = if w == 64 {
        c(64, 0)
    } else {
        Expr::select(
            merging.clone(),
            Expr::binary(BinaryOp::And, lane(source, 0, 64), c(64, !mask(w))),
            c(64, 0),
        )
    };
    let low = r.bind(Expr::binary(
        BinaryOp::Or,
        low,
        Expr::cast(value, 64, false),
    ));
    let high = r.bind(Expr::select(merging, lane(source, 1, 64), c(64, 0)));
    let mut chunks = vec![low, high];
    chunks.resize(usize::from(vl / 64), c(64, 0));
    finish(r, d, 64, chunks, vl);
}
fn sign_distance(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let scalar_sign = matches!(word & 0xff3ffc00, 0x1e20c000 | 0x1e214000);
    let sign_half = matches!(word & 0xbffffc00, 0x0ef8f800 | 0x2ef8f800);
    let sign_wide = matches!(word & 0xbfbffc00, 0x0ea0f800 | 0x2ea0f800);
    let distance_half = matches!(word & 0xffe0fc00, 0x7ec01400) || word & 0xbfe0fc00 == 0x2ec01400;
    let distance_wide = word & 0xffa0fc00 == 0x7ea0d400 || word & 0xbfa0fc00 == 0x2ea0d400;
    if !(scalar_sign || sign_half || sign_wide || distance_half || distance_wide) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid A64 CurrentVL", next, 64));
    }
    let w = if scalar_sign {
        match (word >> 22) & 3 {
            0 => 32,
            1 => 64,
            3 => 16,
            _ => {
                return Some(Recipe::unsupported(
                    "reserved scalar FP sign width",
                    next,
                    64,
                ))
            }
        }
    } else if sign_half || distance_half {
        16
    } else {
        32 << ((word >> 22) & 1)
    };
    let scalar = scalar_sign || word & (1 << 28) != 0;
    let q = word & (1 << 30) != 0;
    if !scalar && w == 64 && !q {
        return Some(Recipe::unsupported(
            "reserved FP sign/difference Q=0 double",
            next,
            64,
        ));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let elements = if scalar {
        1
    } else {
        (if q { 128 } else { 64 }) / u16::from(w)
    };
    let mut r = Recipe::new(next, 64);
    let control = Expr::register(register("a64.fpcr", 0, 32, 32));
    let mut values = Vec::new();
    if distance_half || distance_wide {
        let mut fp = FloatState::new(&mut r);
        for e in 0..elements {
            let difference = fp.step(
                &mut r,
                FloatOperation::Subtract,
                w,
                vec![lane(n, e, w), lane(m, e, w)],
                c(1, 1),
                c(w, 0),
                false,
            );
            values.push(fp_abs(difference, w, control.clone()));
        }
        fp.finish(&mut r);
    } else {
        let neg = if scalar_sign {
            word & 0xff3ffc00 == 0x1e214000
        } else {
            word & (1 << 29) != 0
        };
        for e in 0..elements {
            let input = r.bind(lane(n, e, w));
            values.push(if neg {
                fp_neg(input, control.clone())
            } else {
                fp_abs(input, w, control.clone())
            });
        }
    }
    if scalar {
        finish_scalar(
            &mut r,
            d,
            if scalar_sign { d } else { n },
            w,
            values.remove(0),
            control,
            vl,
        );
    } else {
        finish(&mut r, d, w, values, vl);
    }
    Some(r)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if let Some(recipe) = sign_distance(word, address, vl) {
        return Some(recipe);
    }
    let vector = word & 0xbfe0fc00;
    let indexed = word & 0xbfc0f400;
    let widening = matches!(vector, 0x0e20ec00 | 0x2e20cc00 | 0x0ea0ec00 | 0x2ea0cc00);
    let wide_index = matches!(indexed, 0x0f800000 | 0x2f808000 | 0x0f804000 | 0x2f80c000);
    let complex = word & 0xbf20e400 == 0x2e00c400;
    let complex_index = word & 0xbf009400 == 0x2f001000;
    let add = word & 0xbf20ec00 == 0x2e00e400;
    let immediate = word & 0xbff8fc00;
    let imm = matches!(immediate, 0x0f00f400 | 0x2f00f400 | 0x0f00fc00);
    if !(widening || wide_index || complex || complex_index || add || imm) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid A64 CurrentVL", next, 64));
    }
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let q = word & (1 << 30) != 0;
    let datasize = if q { 128 } else { 64 };
    let mut r = Recipe::new(next, 64);
    if imm {
        let w = if immediate == 0x0f00fc00 {
            16
        } else if immediate == 0x2f00f400 {
            64
        } else {
            32
        };
        if w == 64 && !q {
            return Some(Recipe::unsupported(
                "reserved AdvSIMD FP immediate Q=0 double",
                next,
                64,
            ));
        }
        let literal = u64::from((((word >> 16) & 7) << 5) | ((word >> 5) & 31));
        let fraction = match w {
            16 => 10,
            32 => 23,
            _ => 52,
        };
        let exponent = w - 1 - fraction;
        let bit = (literal >> 6) & 1;
        let exp = ((bit ^ 1) << (exponent - 1))
            | ((if bit != 0 {
                (1u64 << (exponent - 3)) - 1
            } else {
                0
            }) << 2)
            | ((literal >> 4) & 3);
        let value =
            ((literal >> 7) << (w - 1)) | (exp << fraction) | ((literal & 15) << (fraction - 4));
        finish(
            &mut r,
            d,
            w,
            vec![c(w, value); usize::from(datasize / u16::from(w))],
            vl,
        );
        return Some(r);
    }
    let w = if widening || wide_index {
        32
    } else {
        8u8 << ((word >> 22) & 3)
    };
    if (!widening && !wide_index && (w == 8 || w == 64 && !q))
        || complex_index
            && (w == 64
                || w == 32 && (word & (1 << 21) != 0 || !q)
                || w == 16 && !q && word & (1 << 11) != 0)
    {
        return Some(Recipe::unsupported(
            "reserved AdvSIMD complex selector",
            next,
            64,
        ));
    }
    let mut fp = FloatState::new(&mut r);
    let mut values = vec![];
    let elements = datasize / u16::from(w);
    if widening || wide_index {
        let part = u16::from(word & (1 << 29) != 0) * elements;
        let subtract = word & (1 << if wide_index { 14 } else { 23 }) != 0;
        let index = (((word >> 11) & 1) << 2) | (((word >> 21) & 1) << 1) | ((word >> 20) & 1);
        for e in 0..elements {
            let a = lane(n, part + e, 16);
            let a = if subtract {
                fp_neg(a, fp.control.clone())
            } else {
                a
            };
            values.push(fp.step(
                &mut r,
                FloatOperation::WideningFusedMultiplyAdd { source_width: 16 },
                32,
                vec![
                    lane(d, e, 32),
                    a,
                    lane(
                        if wide_index { m & 15 } else { m },
                        if wide_index { index as u16 } else { part + e },
                        16,
                    ),
                ],
                c(1, 1),
                c(32, 0),
                false,
            ));
        }
    } else {
        let rotation = if add {
            ((word >> 12) & 1) * 2 + 1
        } else if complex_index {
            (word >> 13) & 3
        } else {
            (word >> 11) & 3
        };
        let index = if w == 16 {
            (((word >> 11) & 1) << 1) | ((word >> 21) & 1)
        } else {
            (word >> 11) & 1
        };
        for e in 0..elements / 2 {
            let selected = if complex_index { index as u16 } else { e };
            for component in 0..2u16 {
                let source = if rotation & 1 != 0 {
                    1 - component
                } else {
                    component
                };
                let negate = match rotation {
                    0 => false,
                    1 => component == 0,
                    2 => true,
                    _ => component == 1,
                };
                let b = lane(m, selected * 2 + source, w);
                let b = if negate {
                    fp_neg(b, fp.control.clone())
                } else {
                    b
                };
                let inputs = if add {
                    vec![lane(n, e * 2 + component, w), b]
                } else {
                    vec![
                        lane(d, e * 2 + component, w),
                        lane(n, e * 2 + (rotation & 1) as u16, w),
                        b,
                    ]
                };
                values.push(fp.step(
                    &mut r,
                    if add {
                        FloatOperation::Add
                    } else {
                        FloatOperation::FusedMultiplyAdd {
                            negate_product: false,
                            negate_addend: false,
                        }
                    },
                    w,
                    inputs,
                    c(1, 1),
                    c(w, 0),
                    false,
                ));
            }
        }
    }
    fp.finish(&mut r);
    finish(&mut r, d, w, values, vl);
    Some(r)
}

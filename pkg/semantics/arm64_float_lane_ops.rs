//! SVE half dots, widening integer conversions and absolute difference;
//! fixed-width FPScale, sharing the exact ordered FP state contract.
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
    (0xff3fe000, 0x65088000, 0), //fabd_z_p_zz_
    (0xffe0fc00, 0x64208000, 1), //fdot_z_zzz_
    (0xffe0fc00, 0x64204000, 2), //fdot_z_zzzi_
    (0xbfe0fc00, 0x2ec03c00, 8), //FSCALE_asimdsamefp16_only
    (0xbfa0fc00, 0x2ea0fc00, 7), //FSCALE_asimdsame_only
    (0xff3ffc00, 0x650c3800, 4), //scvtflt_z_z_
    (0xff3ffc00, 0x650c3000, 3), //scvtf_z_z_
    (0xff3ffc00, 0x650c3c00, 6), //ucvtflt_z_z_
    (0xff3ffc00, 0x650c3400, 5), //ucvtf_z_z_
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn pred(g: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w) / 8;
    Expr::extract(
        Expr::register(register("a64.predicate64", g as u16 * 4 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind) = FORMS
        .iter()
        .find(|(mask, value, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let size = (word >> 22) & 3;
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048)
        || ((kind == 0 || (3..=6).contains(&kind)) && size == 0)
        || (kind == 7 && size == 3 && word & (1 << 30) == 0)
    {
        return Some(Recipe::unsupported(
            "reserved FP lane size or CurrentVL",
            next,
            64,
        ));
    }
    let w = if kind == 1 || kind == 2 {
        32
    } else if kind == 8 {
        16
    } else {
        8u8 << size
    };
    let count = if kind >= 7 {
        if word & (1 << 30) == 0 {
            64
        } else {
            128
        }
    } else {
        vl
    };
    let d = word & 31;
    let n = if kind == 0 { d } else { (word >> 5) & 31 };
    let m = if kind == 0 {
        (word >> 5) & 31
    } else if kind == 2 {
        (word >> 16) & 7
    } else {
        (word >> 16) & 31
    };
    let g = (word >> 10) & 7;
    let mut r = Recipe::new(next, 64);
    if kind >= 7 {
        let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
        r.guard = Expr::require_context(
            Expr::select(
                sm,
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
            "AdvSIMD FPScale streaming requires FA64",
        );
    }
    let active = (0..count / u16::from(w))
        .map(|e| {
            if kind == 0 {
                r.bind(pred(g, e, w))
            } else {
                c(1, 1)
            }
        })
        .collect::<Vec<_>>();
    let any = if kind == 0 {
        r.bind(active.iter().cloned().fold(c(1, 0), |a, x| b(B::Or, a, x)))
    } else {
        c(1, 1)
    };
    let mut fp = FloatState::new_conditional(&mut r, any.clone());
    let mut values = Vec::new();
    for e in 0..count / u16::from(w) {
        let enable = active[e as usize].clone();
        let old = lane(d, e, w);
        let result = if kind == 0 {
            let value = fp.step(
                &mut r,
                FloatOperation::Subtract,
                w,
                vec![old.clone(), lane(m, e, w)],
                enable.clone(),
                old.clone(),
                true,
            );
            Expr::select(enable, arm64_sve::fp_abs(value, w, fp.control.clone()), old)
        } else if kind == 1 || kind == 2 {
            let index = if kind == 2 {
                e / 4 * 4 + ((word >> 19) & 3) as u16
            } else {
                e
            };
            let product = fp.step(
                &mut r,
                FloatOperation::HalfDotProduct,
                32,
                vec![
                    lane(n, 2 * e, 16),
                    lane(n, 2 * e + 1, 16),
                    lane(m, 2 * index, 16),
                    lane(m, 2 * index + 1, 16),
                ],
                c(1, 1),
                c(32, 0),
                true,
            );
            fp.step(
                &mut r,
                FloatOperation::Add,
                32,
                vec![old, product],
                c(1, 1),
                c(32, 0),
                true,
            )
        } else if kind <= 6 {
            let signed = kind == 3 || kind == 4;
            let top = kind == 4 || kind == 6;
            // Extending first represents the byte input with the existing closed
            // integer-to-float contract; no intermediate FP conversion occurs.
            let value = Expr::cast(lane(n, 2 * e + u16::from(top), w / 2), w, signed);
            fp.step(
                &mut r,
                FloatOperation::FromInteger {
                    source_width: w,
                    signed,
                    fractional_bits: 0,
                },
                w,
                vec![value],
                c(1, 1),
                c(w, 0),
                true,
            )
        } else {
            fp.scale_logb(
                &mut r,
                w,
                lane(n, e, w),
                Some(lane(m, e, w)),
                c(1, 1),
                c(w, 0),
            )
        };
        values.push(result);
    }
    if kind == 0 {
        fp.finish_conditional(&mut r, any);
    } else {
        fp.finish(&mut r);
    }
    for chunk in 0..vl / 64 {
        let mut out = c(64, 0);
        for part in 0..64 / u16::from(w) {
            let e = chunk * (64 / u16::from(w)) + part;
            if let Some(value) = values.get(e as usize) {
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(value.clone(), 64, false),
                        c(64, u64::from(part * u16::from(w))),
                    ),
                );
            }
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
    Some(r)
}

//! June2026 SVE predicate-pair WHILE and WHILERW/WHILEWR physical families.
//! All ten pages use X64 operands, including XZR (never SP) at index31.
//! Pair classes require SVE2p1 or SME2; RW/WR require SVE2 or SME. Generated
//! caller owns those features and standard CheckSVEEnabled admission: there is
//! no additional non-streaming restriction in these operations.
//! P writes preserve MAX_PL backing above CurrentVL/8 (permitted accessor choice).
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(v: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, v)
}
fn gp(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
fn write_p(r: &mut Recipe, d: u32, values: &[Expr], w: u8, vl: u16) {
    let pl = vl / 8;
    for k in 0..pl.div_ceil(64) {
        let width = (pl - k * 64).min(64) as u8;
        let mut packed = c(width, 0);
        for (e, v) in values.iter().enumerate() {
            let bit = e as u16 * u16::from(w / 8);
            if bit / 64 != k {
                continue;
            }
            packed = b(
                B::Or,
                packed,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), width, false),
                    c(width, u64::from(bit % 64)),
                ),
            );
        }
        let packed = r.bind(packed);
        r.write(
            register("a64.predicate64", d as u16 * 4 + k, width, 64),
            WritePolicy::Preserve,
            packed,
        );
    }
}
fn flags(r: &mut Recipe, values: &[Expr]) {
    let mut any = c(1, 0);
    for v in values {
        any = r.bind(b(B::Or, any, v.clone()));
    }
    for (i, v) in [
        values[0].clone(),
        not(any),
        not(values[values.len() - 1].clone()),
        c(1, 0),
    ]
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
/// None means unowned encoding; owned invalid CurrentVL is Unsupported.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let pair = matches!(
        word & 0xff20fc11,
        0x25205010
            | 0x25205011
            | 0x25205811
            | 0x25205810
            | 0x25205411
            | 0x25205c10
            | 0x25205c11
            | 0x25205410
    );
    let memory = matches!(word & 0xff20fc10, 0x25203010 | 0x25203000);
    if !pair && !memory {
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
    let w = 8u8 << ((word >> 22) & 3);
    let elements = vl / u16::from(w);
    let a = r.bind(gp((word >> 5) & 31));
    let z = r.bind(gp((word >> 16) & 31));
    let mut values = vec![c(1, 0); usize::from(elements) * if pair { 2 } else { 1 }];
    if pair {
        let ascending = word & (1 << 10) != 0;
        let inclusive = (word & 1 != 0) == ascending;
        let cmp = if word & (1 << 11) != 0 {
            B::Ult
        } else {
            B::Slt
        };
        let mut last = c(1, 1);
        for i in 0..elements * 2 {
            let current = r.bind(b(
                if ascending { B::Add } else { B::Sub },
                a.clone(),
                c(64, u64::from(i)),
            ));
            let condition = if ascending {
                if inclusive {
                    not(b(cmp, z.clone(), current))
                } else {
                    b(cmp, current, z.clone())
                }
            } else if inclusive {
                not(b(cmp, current, z.clone()))
            } else {
                b(cmp, z.clone(), current)
            };
            last = r.bind(b(B::And, last, condition));
            let e = if ascending { i } else { elements * 2 - 1 - i };
            values[usize::from(e)] = last.clone();
        }
    } else {
        let rw = word & (1 << 4) != 0;
        let distance = r.bind(if rw {
            Expr::select(
                b(B::Ult, a.clone(), z.clone()),
                b(B::Sub, z.clone(), a.clone()),
                b(B::Sub, a.clone(), z.clone()),
            )
        } else {
            b(B::Sub, z.clone(), a.clone())
        });
        let diff = r.bind(b(
            B::Lsr,
            distance,
            c(64, u64::from(w.trailing_zeros() - 3)),
        ));
        let zero = b(B::Eq, diff.clone(), c(64, 0));
        let all = r.bind(if rw {
            zero
        } else {
            b(B::Or, not(b(B::Ult, a, z)), zero)
        });
        for e in 0..elements {
            values[usize::from(e)] = r.bind(b(
                B::Or,
                all.clone(),
                b(B::Ult, c(64, u64::from(e)), diff.clone()),
            ));
        }
    }
    flags(&mut r, &values);
    if pair {
        let d = word & 14;
        write_p(&mut r, d, &values[..usize::from(elements)], w, vl);
        write_p(&mut r, d + 1, &values[usize::from(elements)..], w, vl);
    } else {
        write_p(&mut r, word & 15, &values, w, vl);
    }
    Some(r)
}

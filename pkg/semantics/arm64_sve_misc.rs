// Single-vector SVE match, histogram and checked-pointer operations. Physical
// masks and algorithms follow the Arm A-profile June 2026 XML. Feature admission
// is caller-owned; effective streaming and CPA controls are explicit inputs.
use super::*;
use BinaryOp as B;
fn c(w: u8, value: u64) -> Expr {
    Expr::constant(w, value)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn lane(chunks: &[Expr], e: u16, width: u8) -> Expr {
    let bit = e * u16::from(width);
    Expr::extract(chunks[(bit / 64) as usize].clone(), (bit % 64) as u8, width)
}
fn inputs(r: &mut Recipe, n: u32, vl: u16, active: Expr) -> Vec<Expr> {
    (0..vl / 64)
        .map(|chunk| r.bind(Expr::select(active.clone(), z(n, chunk), c(64, 0))))
        .collect()
}
fn predicate(r: &mut Recipe, n: u32, vl: u16, width: u8) -> Vec<Expr> {
    let chunks: Vec<_> = (0..(vl / 8).div_ceil(64))
        .map(|chunk| {
            r.bind(Expr::register(register(
                "a64.predicate64",
                n as u16 * 4 + chunk,
                64,
                64,
            )))
        })
        .collect();
    (0..vl / u16::from(width))
        .map(|e| {
            let bit = e * u16::from(width / 8);
            Expr::extract(chunks[(bit / 64) as usize].clone(), (bit % 64) as u8, 1)
        })
        .collect()
}
fn any(r: &mut Recipe, mask: &[Expr]) -> Expr {
    let mut result = c(1, 0);
    for bit in mask {
        result = r.bind(b(B::Or, result, bit.clone()));
    }
    result
}
fn write_z(r: &mut Recipe, d: u32, values: &[Expr], width: u8) {
    for (chunk, lanes) in values.chunks(64 / width as usize).enumerate() {
        let mut value = c(64, 0);
        for (i, lane) in lanes.iter().enumerate() {
            value = b(
                B::Or,
                value,
                b(
                    B::Shl,
                    Expr::cast(lane.clone(), 64, false),
                    c(64, (i * width as usize) as u64),
                ),
            );
        }
        let value = r.bind(value);
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn write_p(r: &mut Recipe, d: u32, values: &[Expr], width: u8) {
    // Choose the architecture's permitted zero-extension to MAX_PL.
    for chunk in 0..4u16 {
        let mut value = c(64, 0);
        for (e, bit) in values.iter().enumerate() {
            let index = e as u16 * u16::from(width / 8);
            if index / 64 == chunk {
                value = b(
                    B::Or,
                    value,
                    b(
                        B::Shl,
                        Expr::cast(bit.clone(), 64, false),
                        c(64, u64::from(index % 64)),
                    ),
                );
            }
        }
        let value = r.bind(value);
        r.write(
            register("a64.predicate64", d as u16 * 4 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn flags(r: &mut Recipe, mask: &[Expr], values: &[Expr]) {
    let (mut first, mut last, mut found) = (c(1, 0), c(1, 0), c(1, 0));
    for (m, value) in mask.iter().zip(values).rev() {
        first = r.bind(Expr::select(m.clone(), value.clone(), first));
    }
    for (m, value) in mask.iter().zip(values) {
        last = r.bind(Expr::select(m.clone(), value.clone(), last));
        found = r.bind(b(B::Or, found, b(B::And, m.clone(), value.clone())));
    }
    for (index, value) in [first, not(found), not(last), c(1, 0)]
        .into_iter()
        .enumerate()
    {
        r.write(
            register("a64.nzcv", index as u16, 1, 1),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn checked_pointer(result: Expr, base: Expr) -> Expr {
    // PointerAddCheck uses effective CPTA only, never CPTM. Require a known
    // control only when this lane is selected, preserving inactive suppression.
    let enabled = Expr::register(register("a64.cpta", 0, 1, 1));
    let known = Expr::require_context(
        b(B::Eq, enabled.clone(), enabled.clone()),
        "SVE checked pointer requires effective CPTA control",
    );
    let detected = b(
        B::Or,
        b(
            B::Xor,
            Expr::extract(base.clone(), 55, 1),
            Expr::extract(base.clone(), 54, 1),
        ),
        not(b(
            B::Eq,
            Expr::extract(result.clone(), 56, 8),
            Expr::extract(base.clone(), 56, 8),
        )),
    );
    let marked = b(
        B::Or,
        b(
            B::Or,
            b(B::And, base.clone(), c(64, 0xff80000000000000)),
            b(
                B::Shl,
                Expr::cast(not(Expr::extract(base, 55, 1)), 64, false),
                c(64, 54),
            ),
        ),
        b(B::And, result.clone(), c(64, (1u64 << 54) - 1)),
    );
    Expr::select(
        known,
        Expr::select(
            enabled,
            Expr::select(detected, marked, result.clone()),
            result,
        ),
        c(64, 0),
    )
}
/// Exact single-vector MATCH/NMATCH, HISTCNT/HISTSEG and ADDPT/SUBPT.
/// Vector chunks are Z*32+chunk; predicate chunks are P*4+chunk. All forms
/// require non-streaming mode or effective SME_FA64 before operand access.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if !(128..=2048).contains(&vl) || !vl.is_power_of_two() {
        return None;
    }
    if matches!(word & 0xffe0fc00, 0x44c0d000 | 0x44c0d800) {
        return Some(pointer_multiply(word, address, vl));
    }
    let matching = word & 0xffa0e000 == 0x45208000;
    let histcnt = word & 0xff20e000 == 0x4520c000;
    let histseg = word & 0xff20fc00 == 0x4520a000;
    let pointer_plain = matches!(word & 0xffe0fc00, 0x04e00800 | 0x04e00c00);
    let pointer_pred = matches!(word & 0xffffe000, 0x04c40000 | 0x04c50000);
    if !(matching || histcnt || histseg || pointer_plain || pointer_pred) {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let size = (word >> 22) & 3;
    if (histcnt && size < 2) || (histseg && size != 0) {
        r.support = Support::Unsupported("reserved SVE histogram element size");
        return Some(r);
    }
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.bind(Expr::require_context(
        Expr::select(
            sm,
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "SVE misc operation requires non-streaming mode or effective FA64",
    ));
    let d = word & if matching { 15 } else { 31 };
    let n = if pointer_pred { d } else { (word >> 5) & 31 };
    let m = if pointer_pred {
        (word >> 5) & 31
    } else {
        (word >> 16) & 31
    };
    let width = if matching {
        8 << ((word >> 22) & 1)
    } else if pointer_plain || pointer_pred {
        64
    } else {
        8 << size
    };
    let mask = if matching || histcnt || pointer_pred {
        predicate(&mut r, (word >> 10) & 7, vl, width)
    } else {
        vec![c(1, 1); (vl / u16::from(width)) as usize]
    };
    let active = any(&mut r, &mask);
    let a = inputs(
        &mut r,
        n,
        vl,
        if pointer_pred {
            c(1, 1)
        } else {
            active.clone()
        },
    );
    let z = inputs(&mut r, m, vl, active);
    let elements = vl / u16::from(width);
    let per_segment = 128 / u16::from(width);
    let mut values = Vec::new();
    for e in 0..elements {
        let value = if matching || histseg {
            let start = e / per_segment * per_segment;
            let mut count = c(if matching { 1 } else { width }, 0);
            for i in start..start + per_segment {
                let equal = b(B::Eq, lane(&a, e, width), lane(&z, i, width));
                count = r.bind(if matching {
                    b(B::Or, count, equal)
                } else {
                    b(B::Add, count, Expr::cast(equal, width, false))
                });
            }
            if matching {
                Expr::select(
                    mask[e as usize].clone(),
                    if word & 16 != 0 { not(count) } else { count },
                    c(1, 0),
                )
            } else {
                count
            }
        } else if histcnt {
            let mut count = c(width, 0);
            for i in 0..=e {
                let equal = b(B::Eq, lane(&a, e, width), lane(&z, i, width));
                let counted = Expr::select(mask[i as usize].clone(), equal, c(1, 0));
                count = r.bind(b(B::Add, count, Expr::cast(counted, width, false)));
            }
            Expr::select(mask[e as usize].clone(), count, c(width, 0))
        } else {
            let base = lane(&a, e, 64);
            let result = b(
                if word & (if pointer_pred { 1 << 16 } else { 1 << 10 }) != 0 {
                    B::Sub
                } else {
                    B::Add
                },
                base.clone(),
                lane(&z, e, 64),
            );
            Expr::select(
                mask[e as usize].clone(),
                checked_pointer(result, base.clone()),
                base,
            )
        };
        values.push(r.bind(value));
    }
    if matching {
        flags(&mut r, &mask, &values);
        write_p(&mut r, d, &values, width);
    } else {
        write_z(&mut r, d, &values, width);
    }
    Some(r)
}

// MADPT multiplies old Zd by Zm and adds Zn; MLAPT multiplies Zn by Zm and
// adds old Zd. Signed product overflow is independent of modular addition.
fn pointer_multiply(word: u32, address: u64, vl: u16) -> Recipe {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    r.bind(Expr::require_context(
        Expr::select(
            Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "SVE pointer multiply requires non-streaming SVE access",
    ));
    let (d, n, m) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let mad = word & (1 << 11) != 0;
    let mut results = vec![];
    for chunk in 0..vl / 64 {
        let a = r.bind(z(if mad { d } else { n }, chunk));
        let multiplier = r.bind(z(m, chunk));
        let base = r.bind(z(if mad { n } else { d }, chunk));
        let product = r.bind(b(B::Mul, a.clone(), multiplier.clone()));
        let overflow = not(b(
            B::Eq,
            b(B::SignedMultiplyHigh, a, multiplier),
            b(B::Asr, product.clone(), c(64, 63)),
        ));
        let result = r.bind(b(B::Add, base.clone(), product));
        let addition_detected = b(
            B::Or,
            b(
                B::Xor,
                Expr::extract(base.clone(), 55, 1),
                Expr::extract(base.clone(), 54, 1),
            ),
            not(b(
                B::Eq,
                Expr::extract(result.clone(), 56, 8),
                Expr::extract(base.clone(), 56, 8),
            )),
        );
        let control = |bank| {
            let value = Expr::register(register(bank, 0, 1, 1));
            Expr::select(
                Expr::require_context(
                    b(B::Eq, value.clone(), value.clone()),
                    "SVE pointer multiply requires an effective checked-pointer control",
                ),
                value,
                c(1, 0),
            )
        };
        let mark = Expr::select(
            Expr::select(addition_detected, control("a64.cpta"), c(1, 0)),
            c(1, 1),
            Expr::select(overflow, control("a64.cptm"), c(1, 0)),
        );
        let marked = b(
            B::Or,
            b(
                B::Or,
                b(B::And, base.clone(), c(64, 0xff80000000000000)),
                b(
                    B::Shl,
                    Expr::cast(not(Expr::extract(base, 55, 1)), 64, false),
                    c(64, 54),
                ),
            ),
            b(B::And, result.clone(), c(64, (1u64 << 54) - 1)),
        );
        results.push(r.bind(Expr::select(mark, marked, result)));
    }
    write_z(&mut r, d, &results, 64);
    r
}

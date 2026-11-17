//! Fixed-width A64 cryptographic, polynomial and integer matrix recipes.
//! Physical groups and round rules follow the Arm A-profile 2026-06 corpus.
//! Operations expand to closed typed integer expressions; feature admission and
//! Advanced SIMD access controls remain caller-owned. Intermediate bindings keep
//! rounds linear in graph size and capture every incoming aliased operand.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn xor(a: Expr, z: Expr) -> Expr {
    b(B::Xor, a, z)
}
fn add(a: Expr, z: Expr) -> Expr {
    b(B::Add, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn cast(a: Expr, w: u8, s: bool) -> Expr {
    Expr::cast(a, w, s)
}
fn ext(a: Expr, o: u8, w: u8) -> Expr {
    Expr::extract(a, o, w)
}
fn ror(a: Expr, n: u8) -> Expr {
    let w = a.ty.width;
    b(B::Ror, a, c(w, u64::from(n)))
}
fn rol(a: Expr, n: u8) -> Expr {
    let w = a.ty.width;
    ror(a, (w - n % w) % w)
}
fn shr(a: Expr, n: u8) -> Expr {
    let w = a.ty.width;
    b(B::Lsr, a, c(w, u64::from(n)))
}
fn choose(a: Expr, z: Expr, k: Expr) -> Expr {
    xor(b(B::And, a.clone(), z), b(B::And, not(a), k))
}
fn majority(a: Expr, z: Expr, k: Expr) -> Expr {
    xor(
        xor(b(B::And, a.clone(), z.clone()), b(B::And, a, k.clone())),
        b(B::And, z, k),
    )
}
fn parity(a: Expr, z: Expr, k: Expr) -> Expr {
    xor(xor(a, z), k)
}
fn lane(n: u32, i: u8, w: u8) -> Expr {
    let bit = u16::from(i) * u16::from(w);
    ext(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn input(r: &mut Recipe, n: u32, w: u8) -> Vec<Expr> {
    (0..128 / w).map(|i| r.bind(lane(n, i, w))).collect()
}
fn finish(mut r: Recipe, d: u32, parts: Vec<Expr>) -> Option<Recipe> {
    let mut chunks = vec![];
    let mut value = c(64, 0);
    let mut bit = 0;
    for p in parts {
        let w = p.ty.width;
        let part = cast(p, 64, false);
        value = if bit == 0 {
            part
        } else {
            b(B::Or, value, b(B::Shl, part, c(64, bit)))
        };
        bit += u64::from(w);
        if bit == 64 {
            chunks.push(r.bind(value));
            value = c(64, 0);
            bit = 0;
        }
    }
    if bit != 0 {
        chunks.push(r.bind(value));
    }
    for i in 0..2 {
        r.write(
            register("a64.vector64", d as u16 * 32 + i, 64, 64),
            WritePolicy::ZeroUpper,
            chunks.get(i as usize).cloned().unwrap_or_else(|| c(64, 0)),
        );
    }
    Some(r)
}
fn unsupported(mut r: Recipe, reason: &'static str) -> Option<Recipe> {
    r.support = Support::Unsupported(reason);
    Some(r)
}
// Push bit extraction through XOR and nested lane extracts. Register bits can
// then lower directly to slices, instead of shift/truncate pairs on byte SSA
// values. This does not look through snapshots or duplicate arithmetic graphs.
fn lookup_bit(value: &Expr, offset: u8) -> Expr {
    match &value.kind {
        ExprKind::Extract {
            value,
            offset: inner,
        } => lookup_bit(value, inner + offset),
        ExprKind::Binary {
            op: B::Xor,
            left,
            right,
        } => xor(lookup_bit(left, offset), lookup_bit(right, offset)),
        _ if offset == 0 => cast(value.clone(), 1, false),
        ExprKind::Temporary(_) if offset + 1 == value.ty.width => {
            b(B::Slt, value.clone(), c(value.ty.width, 0))
        }
        _ => ext(value.clone(), offset, 1),
    }
}
// Group by bits [0,1,2,6,7], packing bits [3,4,5] inside each chunk.
// This permutation makes byte-zero's first selector a simple truncation and
// the rotation count a mask, avoiding redundant extract/shift conversions.
fn lookup_rotation(value: Expr) -> Expr {
    let value = if let ExprKind::Extract { value, offset } = value.kind {
        let w = value.ty.width;
        if offset == 0 {
            *value
        } else {
            b(B::Lsr, *value, c(w, u64::from(offset)))
        }
    } else {
        value
    };
    let w = value.ty.width;
    b(B::And, value, c(w, 56))
}
fn lookup_chunk(r: &mut Recipe, value: Expr, table: &[u64; 32], position: u8) -> Expr {
    let bits: Vec<_> = [0, 1, 2, 6]
        .into_iter()
        .map(|i| r.bind(lookup_bit(&value, i)))
        .collect();
    let mut level: Vec<_> = (0..32)
        .map(|group| {
            let mut chunk = 0u64;
            for slot in 0..8 {
                let index = (group & 7) | ((group & 24) << 3) | (slot << 3);
                let byte = (table[index / 8] >> (index % 8 * 8)) & 255;
                chunk |= byte << (slot * 8);
            }
            c(64, chunk.rotate_left(u32::from(position)))
        })
        .collect();
    for bit in 0..5 {
        let selector = if bit == 4 {
            lookup_bit(&value, 7)
        } else {
            bits[bit].clone()
        };
        level = level
            .chunks_exact(2)
            .map(|pair| Expr::select(selector.clone(), pair[1].clone(), pair[0].clone()))
            .collect();
    }
    b(B::Ror, level.pop().unwrap(), lookup_rotation(value))
}
fn sbox(r: &mut Recipe, value: Expr, table: &[u64; 32]) -> Expr {
    // Neither chunk nor result is reused. Keeping them inline avoids extra SSA
    // statements/predicates; casting avoids an unnecessary zero-bit extraction.
    cast(lookup_chunk(r, value, table, 0), 8, false)
}
fn xtime(r: &mut Recipe, a: Expr) -> Expr {
    let high = ext(a.clone(), 7, 1);
    let v = xor(
        b(B::Shl, a, c(8, 1)),
        Expr::select(high, c(8, 0x1b), c(8, 0)),
    );
    r.bind(v)
}
// InvMixColumns = MixColumns after doubling the opposite-byte differences
// twice. This shares the GF powers per column instead of recomputing each of
// sixteen coefficients independently, preserving the ASL row/column ordering.
fn mix_column(r: &mut Recipe, mut a: Vec<Expr>, inverse: bool) -> Vec<Expr> {
    if inverse {
        for i in 0..2 {
            let difference = xor(a[i].clone(), a[i + 2].clone());
            let twice = xtime(r, difference);
            let four = xtime(r, twice);
            a[i] = r.bind(xor(a[i].clone(), four.clone()));
            a[i + 2] = r.bind(xor(a[i + 2].clone(), four));
        }
    }
    let total = r.bind(xor(
        xor(a[0].clone(), a[1].clone()),
        xor(a[2].clone(), a[3].clone()),
    ));
    (0..4)
        .map(|i| {
            let adjacent = xor(a[i].clone(), a[(i + 1) % 4].clone());
            let doubled = xtime(r, adjacent);
            xor(xor(a[i].clone(), total.clone()), doubled)
        })
        .collect()
}
fn sigma(a: Expr, rot: [u8; 3]) -> Expr {
    parity(
        ror(a.clone(), rot[0]),
        ror(a.clone(), rot[1]),
        ror(a, rot[2]),
    )
}
fn small(a: Expr, rot: [u8; 3]) -> Expr {
    parity(
        ror(a.clone(), rot[0]),
        ror(a.clone(), rot[1]),
        shr(a, rot[2]),
    )
}
fn p1(a: Expr) -> Expr {
    parity(a.clone(), rol(a.clone(), 15), rol(a, 23))
}
pub(super) fn polynomial(r: &mut Recipe, a: Expr, z: Expr, width: u8) -> (Expr, Option<Expr>) {
    let a = r.bind(a);
    let z = r.bind(z);
    let outw = if width == 64 { 64 } else { width * 2 };
    let mut low = c(outw, 0);
    let mut high = c(64, 0);
    for i in 0..width {
        let bit = ext(a.clone(), i, 1);
        let term = b(B::Shl, cast(z.clone(), outw, false), c(outw, u64::from(i)));
        low = r.bind(xor(low, Expr::select(bit.clone(), term, c(outw, 0))));
        if width == 64 && i != 0 {
            high = r.bind(xor(
                high,
                Expr::select(bit, shr(z.clone(), 64 - i), c(64, 0)),
            ));
        }
    }
    (low, (width == 64).then_some(high))
}

pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let a = (word >> 10) & 31;
    let q = word & (1 << 30) != 0;
    let size = (word >> 22) & 3;
    let two = word & 0xfffffc00;
    let three = word & 0xffe0fc00;
    if matches!(two, 0x4e284800 | 0x4e285800) {
        // Every byte is consumed once; selector bindings and final chunk
        // bindings snapshot all inputs before either architectural output.
        let left: Vec<_> = (0..16).map(|i| lane(d, i, 8)).collect();
        let key: Vec<_> = (0..16).map(|i| lane(n, i, 8)).collect();
        let inverse = two == 0x4e285800;
        let mut parts = vec![];
        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            let source = ((col + if inverse { 4 - row } else { row }) % 4) * 4 + row;
            let x = xor(left[source].clone(), key[source].clone());
            parts.push(sbox(
                &mut r,
                x,
                if inverse { &AES_INVERSE } else { &AES_FORWARD },
            ));
        }
        return finish(r, d, parts);
    }
    if matches!(two, 0x4e286800 | 0x4e287800) {
        let source = input(&mut r, n, 8);
        let inverse = two == 0x4e287800;
        let mut parts = vec![];
        for column in source.chunks_exact(4) {
            parts.extend(mix_column(&mut r, column.to_vec(), inverse));
        }
        return finish(r, d, parts);
    }
    if matches!(word & 0xffe08000, 0xce000000 | 0xce200000) {
        let x = input(&mut r, n, 64);
        let y = input(&mut r, m, 64);
        let z = input(&mut r, a, 64);
        let parts = (0..2)
            .map(|i| {
                xor(
                    x[i].clone(),
                    if word & (1 << 21) != 0 {
                        b(B::And, y[i].clone(), not(z[i].clone()))
                    } else {
                        xor(y[i].clone(), z[i].clone())
                    },
                )
            })
            .collect();
        return finish(r, d, parts);
    }
    if three == 0xce608c00 || word & 0xffe00000 == 0xce800000 {
        let x = input(&mut r, n, 64);
        let y = input(&mut r, m, 64);
        let parts = (0..2)
            .map(|i| {
                if three == 0xce608c00 {
                    xor(x[i].clone(), rol(y[i].clone(), 1))
                } else {
                    ror(xor(x[i].clone(), y[i].clone()), ((word >> 10) & 63) as u8)
                }
            })
            .collect();
        return finish(r, d, parts);
    }
    if word & 0xbf20fc00 == 0x2e209c00 {
        if size != 0 {
            return unsupported(r, "reserved PMUL element width");
        }
        let mut parts = vec![];
        for i in 0..if q { 16 } else { 8 } {
            let (v, _) = polynomial(&mut r, lane(n, i, 8), lane(m, i, 8), 8);
            parts.push(cast(v, 8, false));
        }
        return finish(r, d, parts);
    }
    if word & 0xbf20fc00 == 0x0e20e000 {
        if size != 0 && size != 3 {
            return unsupported(r, "reserved PMULL element width");
        }
        let width = if size == 3 { 64 } else { 8 };
        let mut parts = vec![];
        for i in 0..64 / width {
            let offset = if q { 64 / width } else { 0 };
            let (low, high) = polynomial(
                &mut r,
                lane(n, i + offset, width),
                lane(m, i + offset, width),
                width,
            );
            parts.push(low);
            if let Some(high) = high {
                parts.push(high);
            }
        }
        return finish(r, d, parts);
    }
    if matches!(three, 0x4e80a400 | 0x6e80a400 | 0x4e80ac00) {
        let x = input(&mut r, n, 8);
        let y = input(&mut r, m, 8);
        let acc = input(&mut r, d, 32);
        let signed_x = three == 0x4e80a400;
        let signed_y = three != 0x6e80a400;
        let mut parts = vec![];
        for i in 0..2 {
            for j in 0..2 {
                let mut value = acc[i * 2 + j].clone();
                for k in 0..8 {
                    value = r.bind(add(
                        value,
                        b(
                            B::Mul,
                            cast(x[i * 8 + k].clone(), 32, signed_x),
                            cast(y[j * 8 + k].clone(), 32, signed_y),
                        ),
                    ));
                }
                parts.push(value);
            }
        }
        return finish(r, d, parts);
    }
    let mixed_vec = word & 0xbfe0fc00 == 0x0e809c00;
    let mixed_elt = matches!(word & 0xbfc0f400, 0x0f00f000 | 0x0f80f000);
    if mixed_vec || mixed_elt {
        let x = input(&mut r, n, 8);
        let y = input(&mut r, m, 8);
        let acc = input(&mut r, d, 32);
        let signed_x = word & 0xbfc0f400 == 0x0f00f000;
        let index = ((((word >> 11) & 1) << 1) | ((word >> 21) & 1)) as usize;
        let mut parts = vec![];
        for i in 0..if q { 4 } else { 2 } {
            let mut value = acc[i].clone();
            for k in 0..4 {
                value = r.bind(add(
                    value,
                    b(
                        B::Mul,
                        cast(x[i * 4 + k].clone(), 32, signed_x),
                        cast(
                            y[(if mixed_elt { index } else { i }) * 4 + k].clone(),
                            32,
                            !signed_x,
                        ),
                    ),
                ));
            }
            parts.push(value);
        }
        return finish(r, d, parts);
    }
    if three == 0x5e000000 || three == 0x5e001000 || three == 0x5e002000 {
        let mut x = input(&mut r, d, 32);
        let mut y = r.bind(lane(n, 0, 32));
        let w = input(&mut r, m, 32);
        for key in w {
            let f = match three {
                0x5e000000 => choose(x[1].clone(), x[2].clone(), x[3].clone()),
                0x5e002000 => majority(x[1].clone(), x[2].clone(), x[3].clone()),
                _ => parity(x[1].clone(), x[2].clone(), x[3].clone()),
            };
            let temp = r.bind(add(add(add(y, rol(x[0].clone(), 5)), f), key));
            y = x[3].clone();
            x = vec![
                temp,
                x[0].clone(),
                r.bind(rol(x[1].clone(), 30)),
                x[2].clone(),
            ];
        }
        return finish(r, d, x);
    }
    if two == 0x5e280800 {
        let value = rol(r.bind(lane(n, 0, 32)), 30);
        return finish(r, d, vec![value]);
    }
    if three == 0x5e003000 {
        let x = input(&mut r, d, 64);
        let y = r.bind(lane(n, 0, 64));
        let z = input(&mut r, m, 64);
        return finish(
            r,
            d,
            vec![
                parity(x[1].clone(), x[0].clone(), z[0].clone()),
                parity(y, x[1].clone(), z[1].clone()),
            ],
        );
    }
    if two == 0x5e281800 {
        let x = input(&mut r, d, 32);
        let y = input(&mut r, n, 32);
        let mut t = vec![];
        for i in 0..4 {
            t.push(r.bind(xor(
                x[i].clone(),
                if i < 3 { y[i + 1].clone() } else { c(32, 0) },
            )));
        }
        let mut out: Vec<_> = t.iter().cloned().map(|v| rol(v, 1)).collect();
        out[3] = xor(out[3].clone(), rol(t[0].clone(), 2));
        return finish(r, d, out);
    }
    if matches!(three, 0x5e004000 | 0x5e005000) {
        let part1 = three == 0x5e004000;
        let mut x = input(&mut r, if part1 { d } else { n }, 32);
        let mut y = input(&mut r, if part1 { n } else { d }, 32);
        let keys = input(&mut r, m, 32);
        for key in keys {
            let ch = choose(y[0].clone(), y[1].clone(), y[2].clone());
            let maj = majority(x[0].clone(), x[1].clone(), x[2].clone());
            let t = r.bind(add(
                add(add(y[3].clone(), sigma(y[0].clone(), [6, 11, 25])), ch),
                key,
            ));
            let e = r.bind(add(t.clone(), x[3].clone()));
            let a = r.bind(add(add(t, sigma(x[0].clone(), [2, 13, 22])), maj));
            x = vec![a, x[0].clone(), x[1].clone(), x[2].clone()];
            y = vec![e, y[0].clone(), y[1].clone(), y[2].clone()];
        }
        return finish(r, d, if part1 { x } else { y });
    }
    if two == 0x5e282800 {
        let x = input(&mut r, d, 32);
        let y = r.bind(lane(n, 0, 32));
        let mut out = vec![];
        for i in 0..4 {
            out.push(add(
                x[i].clone(),
                small(if i < 3 { x[i + 1].clone() } else { y.clone() }, [7, 18, 3]),
            ));
        }
        return finish(r, d, out);
    }
    if three == 0x5e006000 {
        let x = input(&mut r, d, 32);
        let y = input(&mut r, n, 32);
        let z = input(&mut r, m, 32);
        let mut out: Vec<Expr> = vec![];
        for i in 0..4 {
            let src = if i < 2 {
                z[i + 2].clone()
            } else {
                out[i - 2].clone()
            };
            let base = if i < 3 {
                y[i + 1].clone()
            } else {
                z[0].clone()
            };
            out.push(r.bind(add(add(x[i].clone(), base), small(src, [17, 19, 10]))));
        }
        return finish(r, d, out);
    }
    if matches!(three, 0xce608000 | 0xce608400 | 0xce608800) || two == 0xcec08000 {
        let x = input(&mut r, n, 64);
        let w = input(&mut r, d, 64);
        if two == 0xcec08000 {
            return finish(
                r,
                d,
                vec![
                    add(w[0].clone(), small(w[1].clone(), [1, 8, 7])),
                    add(w[1].clone(), small(x[0].clone(), [1, 8, 7])),
                ],
            );
        }
        let y = input(&mut r, m, 64);
        if three == 0xce608800 {
            return finish(
                r,
                d,
                (0..2)
                    .map(|i| {
                        add(
                            add(w[i].clone(), small(x[i].clone(), [19, 61, 6])),
                            y[i].clone(),
                        )
                    })
                    .collect(),
            );
        }
        if three == 0xce608400 {
            let high = r.bind(add(
                add(
                    majority(x[0].clone(), y[1].clone(), y[0].clone()),
                    sigma(y[0].clone(), [28, 34, 39]),
                ),
                w[1].clone(),
            ));
            let low = add(
                add(
                    majority(high.clone(), y[0].clone(), y[1].clone()),
                    sigma(high.clone(), [28, 34, 39]),
                ),
                w[0].clone(),
            );
            return finish(r, d, vec![low, high]);
        }
        let high = r.bind(add(
            add(
                choose(y[1].clone(), x[0].clone(), x[1].clone()),
                sigma(y[1].clone(), [14, 18, 41]),
            ),
            w[1].clone(),
        ));
        let temp = r.bind(add(high.clone(), y[0].clone()));
        let low = add(
            add(
                choose(temp.clone(), y[1].clone(), x[0].clone()),
                sigma(temp, [14, 18, 41]),
            ),
            w[0].clone(),
        );
        return finish(r, d, vec![low, high]);
    }
    if word & 0xffe08000 == 0xce400000 {
        let x = r.bind(lane(n, 3, 32));
        let y = r.bind(lane(m, 3, 32));
        let z = r.bind(lane(a, 3, 32));
        return finish(
            r,
            d,
            vec![
                c(32, 0),
                c(32, 0),
                c(32, 0),
                rol(add(add(rol(x, 12), y), z), 7),
            ],
        );
    }
    if matches!(
        word & 0xffe0cc00,
        0xce408000 | 0xce408400 | 0xce408800 | 0xce408c00
    ) {
        let x = input(&mut r, d, 32);
        let ss = r.bind(lane(n, 3, 32));
        let keyword = r.bind(lane(m, ((word >> 12) & 3) as u8, 32));
        let second = word & (1 << 11) != 0;
        let boolean = if word & (1 << 10) == 0 {
            parity(x[3].clone(), x[2].clone(), x[1].clone())
        } else if second {
            choose(x[3].clone(), x[2].clone(), x[1].clone())
        } else {
            majority(x[3].clone(), x[2].clone(), x[1].clone())
        };
        let ss = if second {
            ss
        } else {
            xor(ss, rol(x[3].clone(), 12))
        };
        let tt = r.bind(add(add(add(boolean, x[0].clone()), ss), keyword));
        let tt = if second {
            parity(tt.clone(), rol(tt.clone(), 9), rol(tt, 17))
        } else {
            tt
        };
        return finish(
            r,
            d,
            vec![
                x[1].clone(),
                rol(x[2].clone(), if second { 19 } else { 9 }),
                x[3].clone(),
                tt,
            ],
        );
    }
    if matches!(three, 0xce60c000 | 0xce60c400) {
        let x = input(&mut r, d, 32);
        let y = input(&mut r, n, 32);
        let z = input(&mut r, m, 32);
        let mut out: Vec<Expr> = vec![];
        if three == 0xce60c000 {
            for i in 0..4 {
                let shifted = if i < 3 {
                    rol(z[i + 1].clone(), 15)
                } else {
                    rol(out[0].clone(), 15)
                };
                out.push(r.bind(p1(parity(x[i].clone(), y[i].clone(), shifted))));
            }
        } else {
            let tmp: Vec<_> = (0..4)
                .map(|i| r.bind(xor(y[i].clone(), rol(z[i].clone(), 7))))
                .collect();
            for i in 0..4 {
                out.push(xor(x[i].clone(), tmp[i].clone()));
            }
            out[3] = xor(out[3].clone(), p1(rol(tmp[0].clone(), 15)));
        }
        return finish(r, d, out);
    }
    if three == 0xce60c800 || two == 0xcec08400 {
        let key_schedule = three == 0xce60c800;
        // Lane register references are immutable incoming operands until the
        // final two writes. Intermediate round values remain explicit snapshots.
        let mut x: Vec<_> = (0..4)
            .map(|i| lane(if key_schedule { n } else { d }, i, 32))
            .collect();
        let keys: Vec<_> = (0..4)
            .map(|i| lane(if key_schedule { m } else { n }, i, 32))
            .collect();
        let mut shared = c(32, 0);
        for (round, key) in keys.into_iter().enumerate() {
            // Consecutive rounds share the same middle pair of state words.
            if round % 2 == 0 {
                shared = r.bind(xor(x[2].clone(), x[3].clone()));
            }
            let other = if round % 2 == 0 {
                x[1].clone()
            } else {
                x[3].clone()
            };
            let t = r.bind(xor(xor(shared.clone(), other), key));
            let mut substituted = c(64, 0);
            for i in 0..4 {
                // Rotate the compile-time table constants into their output
                // byte positions. Mask and join at 64 bits, truncating once per
                // word instead of twice per byte plus three positioning shifts.
                let chunk = lookup_chunk(&mut r, ext(t.clone(), i * 8, 8), &SM4_SBOX, i * 8);
                let byte = b(B::And, chunk, c(64, 0xff << (i * 8)));
                substituted = if i == 0 {
                    byte
                } else {
                    b(B::Or, substituted, byte)
                };
            }
            let substituted = cast(substituted, 32, false);
            let t = r.bind(substituted);
            let linear = if key_schedule {
                parity(t.clone(), rol(t.clone(), 13), rol(t, 23))
            } else {
                xor(
                    xor(
                        parity(t.clone(), rol(t.clone(), 2), rol(t.clone(), 10)),
                        rol(t.clone(), 18),
                    ),
                    rol(t, 24),
                )
            };
            let next = r.bind(xor(x[0].clone(), linear));
            x = vec![x[1].clone(), x[2].clone(), x[3].clone(), next];
        }
        // All round operands are bound before these outputs. Each low word
        // initializes the whole numeric chunk; the upper-word slice completes
        // it without reading an unavailable incoming destination register.
        for (i, value) in x.into_iter().enumerate() {
            let mut destination = register("a64.vector64", d as u16 * 32 + i as u16 / 2, 32, 64);
            destination.offset = (i % 2 * 32) as u8;
            r.write(
                destination,
                if i % 2 == 0 {
                    WritePolicy::ZeroUpper
                } else {
                    WritePolicy::Preserve
                },
                value,
            );
        }
        return Some(r);
    }
    // Floating-point dot/matrix encodings remain unclaimed so that the FP
    // recipe owner can apply the exact BF16 arithmetic/environment contract.

    None
}

const AES_FORWARD: [u64; 32] = [
    0xc56f6bf27b777c63,
    0x76abd7fe2b670130,
    0xf04759fa7dc982ca,
    0xc072a49cafa2d4ad,
    0xccf73f362693fdb7,
    0x1531d871f1e5a534,
    0x9a059618c323c704,
    0x75b227ebe2801207,
    0xa05a6e1b1a2c8309,
    0x842fe329b3d63b52,
    0x5bb1fc20ed00d153,
    0xcf584c4a39becb6a,
    0x85334d43fbaaefd0,
    0xa89f3c507f02f945,
    0xf5389d928f40a351,
    0xd2f3ff1021dab6bc,
    0x1744975fec130ccd,
    0x73195d643d7ea7c4,
    0x88902a22dc4f8160,
    0xdb0b5ede14b8ee46,
    0x5c2406490a3a32e0,
    0x79e4959162acd3c2,
    0xa94ed58d6d37c8e7,
    0x08ae7a65eaf4566c,
    0xc6b4a61c2e2578ba,
    0x8a8bbd4b1f74dde8,
    0x0ef6034866b53e70,
    0x9e1dc186b9573561,
    0x948ed9691198f8e1,
    0xdf2855cee9871e9b,
    0x6842e6bf0d89a18c,
    0x16bb54b00f2d9941,
];

const AES_INVERSE: [u64; 32] = [
    0x38a53630d56a0952,
    0xfbd7f3819ea340bf,
    0x87ff2f9b8239e37c,
    0xcbe9dec444438e34,
    0x3d23c2a632947b54,
    0x4ec3fa420b954cee,
    0xb224d92866a12e08,
    0x25d18b6d49a25b76,
    0x1698688664f6f872,
    0x92b6655dcc5ca4d4,
    0xdab9edfd5048706c,
    0x849d8da75746155e,
    0x0ad3bc8c00abd890,
    0x0645b3b80558e4f7,
    0x020f3fca8f1e2cd0,
    0x6b8a130103bdafc1,
    0xeadc674f4111913a,
    0x73e6b4f0cecff297,
    0x8535ade72274ac96,
    0x6edf751ce837f9e2,
    0x89c5291d711af147,
    0x1bbe18aa0e62b76f,
    0x2079d2c64b3e56fc,
    0xf45acd78fec0db9a,
    0x31c7078833a8dd1f,
    0x5fec8027591012b1,
    0x0d4ab519a97f5160,
    0xef9cc9939f7ae52d,
    0xb0f52aae4d3be0a0,
    0x619953833cbbebc8,
    0x26d677ba7e042b17,
    0x7d0c2155631469e1,
];

const SM4_SBOX: [u64; 32] = [
    0xb73de1ccfee990d6,
    0x052cfb28c214b616,
    0xc304be2a769a672b,
    0x99068649261344aa,
    0x7a98ef91f450429c,
    0x62accfed430b5433,
    0x95e808c9a91cb3e4,
    0xa63f8f75fa94df80,
    0xba1773f3fca70747,
    0xa84f85e6193c5983,
    0x8bda6471b2816b68,
    0x359d56704b0febf8,
    0xa2d158635e0e241e,
    0x877821013b7c2225,
    0x5227d39f574600d4,
    0x9ec8c4a0e702364c,
    0xb538c740d28abfea,
    0xa11561f9cef2f7a3,
    0x551a349ba45daee0,
    0xe3b18cf5303293ad,
    0x60ca66822ee2f61d,
    0x6f4e530dab2329c0,
    0x2f8efdde4537dbd5,
    0x515b6c6d726aff03,
    0x7fbcddbb92af1b8d,
    0xd85a101f415cd911,
    0xbd7bcda58831c10a,
    0xb0b4e5b812d0742d,
    0x7e77960c4a976989,
    0x84c66ec509f1b965,
    0x204ddc3aec7df018,
    0x4839cbd73e5fee79,
];

// Audited A32/Thumb AES, SHA1/SHA256, polynomial and byte-permutation recipes.
// Physical masks and register restrictions follow the Arm A-profile 2026-06
// corpus. The caller supplies feature/access admission and an existing recipe
// with the architectural predicate and IT pipeline writes. All input D chunks
// are captured before any output writes; Qn always aliases D2n,D2n+1.
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
fn sbox(r: &mut Recipe, value: Expr, table: &[u64; 32]) -> Expr {
    let index = r.bind(value);
    let group = ext(index.clone(), 3, 5);
    let mut chunk = c(64, table[31]);
    for i in (0..31).rev() {
        chunk = Expr::select(
            b(B::Eq, group.clone(), c(5, i as u64)),
            c(64, table[i]),
            chunk,
        );
    }
    let chunk = r.bind(chunk);
    let shift = b(B::Shl, cast(ext(index, 0, 3), 64, false), c(64, 3));
    r.bind(ext(b(B::Lsr, chunk, shift), 0, 8))
}
fn xtime(r: &mut Recipe, a: Expr) -> Expr {
    let high = ext(a.clone(), 7, 1);
    let v = xor(
        b(B::Shl, a, c(8, 1)),
        Expr::select(high, c(8, 0x1b), c(8, 0)),
    );
    r.bind(v)
}
fn gf(r: &mut Recipe, a: Expr, k: u8) -> Expr {
    let a = r.bind(a);
    let mut power = a.clone();
    let mut out = c(8, 0);
    for i in 0..4 {
        if k & (1 << i) != 0 {
            out = xor(out, power.clone());
        }
        if i < 3 {
            power = xtime(r, power);
        }
    }
    r.bind(out)
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
fn polynomial(r: &mut Recipe, a: Expr, z: Expr, width: u8) -> (Expr, Option<Expr>) {
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

fn d(n: u32) -> Expr {
    Expr::register(register("a32.vector64", n as u16, 64, 64))
}
fn input(r: &mut Recipe, n: u32, width: u8, regs: u8) -> Vec<Expr> {
    let chunks: Vec<_> = (0..regs).map(|i| r.bind(d(n + u32::from(i)))).collect();
    (0..u16::from(regs) * 64 / u16::from(width))
        .map(|i| {
            let bit = i * u16::from(width);
            ext(
                chunks[usize::from(bit / 64)].clone(),
                (bit % 64) as u8,
                width,
            )
        })
        .collect()
}
fn finish(mut r: Recipe, dd: u32, regs: u8, parts: Vec<Expr>) -> Option<Recipe> {
    let mut chunks = vec![];
    let mut value = c(64, 0);
    let mut bit = 0;
    for part in parts {
        let width = part.ty.width;
        value = b(B::Or, value, b(B::Shl, cast(part, 64, false), c(64, bit)));
        bit += u64::from(width);
        if bit == 64 {
            chunks.push(r.bind(value));
            value = c(64, 0);
            bit = 0;
        }
    }
    if bit != 0 {
        chunks.push(r.bind(value));
    }
    for i in 0..regs {
        r.write(
            register("a32.vector64", (dd + u32::from(i)) as u16, 64, 64),
            WritePolicy::ZeroUpper,
            chunks
                .get(usize::from(i))
                .cloned()
                .unwrap_or_else(|| c(64, 0)),
        );
    }
    Some(r)
}
fn unsupported(mut r: Recipe, reason: &'static str) -> Option<Recipe> {
    r.support = Support::Unsupported(reason);
    Some(r)
}
fn forbid_it(r: &mut Recipe, thumb: bool) {
    if thumb {
        let state = Expr::register(register("a32.itstate", 0, 8, 8));
        r.guard = Expr::select(
            r.guard.clone(),
            Expr::require_context(
                b(B::Eq, ext(state, 0, 4), c(4, 0)),
                "cryptographic instruction cannot execute in IT",
            ),
            c(1, 0),
        );
    }
}
pub fn a32(word: u32, base: Recipe) -> Option<Recipe> {
    dispatch(word, base, false)
}
pub fn thumb(word: u32, length: u8, base: Recipe) -> Option<Recipe> {
    if length != 4 || word & 0xef000000 != 0xef000000 {
        return None;
    }
    dispatch(
        (word & 0x00ffffff) | 0xf2000000 | ((word & 0x10000000) >> 4),
        base,
        true,
    )
}
fn dispatch(word: u32, mut r: Recipe, thumb: bool) -> Option<Recipe> {
    if word & 0xfe000000 != 0xf2000000 {
        return None;
    }
    let dd = ((word >> 12) & 15) | ((word >> 18) & 16);
    let dn = ((word >> 16) & 15) | ((word >> 3) & 16);
    let dm = (word & 15) | ((word >> 1) & 16);
    let q = word & 0x40 != 0;
    let two = word & 0xffbf0fd0;
    let two_family = word & 0xffb30fd0;
    let crypto_two = matches!(
        two_family,
        0xf3b00300 | 0xf3b00340 | 0xf3b00380 | 0xf3b003c0 | 0xf3b102c0 | 0xf3b20380 | 0xf3b203c0
    );
    let three = word & 0xffb00f10;
    let crypto_three = matches!(
        three,
        0xf2000c00 | 0xf2100c00 | 0xf2200c00 | 0xf2300c00 | 0xf3000c00 | 0xf3100c00 | 0xf3200c00
    );
    if crypto_two || crypto_three {
        if dd & 1 != 0 || dm & 1 != 0 || (crypto_three && (dn & 1 != 0 || !q)) {
            return unsupported(r, "crypto instruction requires aligned Q operands");
        }
        let size = (word >> 18) & 3;
        if crypto_two
            && size
                != if matches!(
                    two_family,
                    0xf3b00300 | 0xf3b00340 | 0xf3b00380 | 0xf3b003c0
                ) {
                    0
                } else {
                    2
                }
        {
            return unsupported(r, "reserved crypto element width");
        }
        forbid_it(&mut r, thumb);
    }
    if matches!(two, 0xf3b00300 | 0xf3b00340) {
        let left = input(&mut r, dd, 8, 2);
        let key = input(&mut r, dm, 8, 2);
        let inverse = two == 0xf3b00340;
        let mut parts = vec![];
        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            let source = ((col + if inverse { 4 - row } else { row }) % 4) * 4 + row;
            parts.push(sbox(
                &mut r,
                xor(left[source].clone(), key[source].clone()),
                if inverse { &AES_INVERSE } else { &AES_FORWARD },
            ));
        }
        return finish(r, dd, 2, parts);
    }
    if matches!(two, 0xf3b00380 | 0xf3b003c0) {
        let source = input(&mut r, dm, 8, 2);
        let coefficients = if two == 0xf3b003c0 {
            [14, 11, 13, 9]
        } else {
            [2, 3, 1, 1]
        };
        let mut parts = vec![];
        for i in 0..16 {
            let mut value = c(8, 0);
            for k in 0..4 {
                value = xor(
                    value,
                    gf(
                        &mut r,
                        source[(i / 4) * 4 + (i % 4 + k) % 4].clone(),
                        coefficients[k],
                    ),
                );
            }
            parts.push(value);
        }
        return finish(r, dd, 2, parts);
    }
    if matches!(three, 0xf2000c00 | 0xf2100c00 | 0xf2200c00) {
        let mut x = input(&mut r, dd, 32, 2);
        let y_input = input(&mut r, dn, 32, 1);
        let mut y = y_input[0].clone();
        let keys = input(&mut r, dm, 32, 2);
        for key in keys {
            let f = match three {
                0xf2000c00 => choose(x[1].clone(), x[2].clone(), x[3].clone()),
                0xf2200c00 => majority(x[1].clone(), x[2].clone(), x[3].clone()),
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
        return finish(r, dd, 2, x);
    }
    if two == 0xf3b902c0 {
        let x = input(&mut r, dm, 32, 1);
        return finish(r, dd, 2, vec![rol(x[0].clone(), 30)]);
    }
    if three == 0xf2300c00 {
        let x = input(&mut r, dd, 64, 2);
        let y = input(&mut r, dn, 64, 1);
        let z = input(&mut r, dm, 64, 2);
        return finish(
            r,
            dd,
            2,
            vec![
                parity(x[0].clone(), x[1].clone(), z[0].clone()),
                parity(x[1].clone(), y[0].clone(), z[1].clone()),
            ],
        );
    }
    if two == 0xf3ba0380 {
        let x = input(&mut r, dd, 32, 2);
        let y = input(&mut r, dm, 32, 2);
        let mut t = vec![];
        for i in 0..4 {
            t.push(r.bind(xor(
                x[i].clone(),
                if i < 3 { y[i + 1].clone() } else { c(32, 0) },
            )));
        }
        let mut out: Vec<_> = t.iter().cloned().map(|v| rol(v, 1)).collect();
        out[3] = xor(out[3].clone(), rol(t[0].clone(), 2));
        return finish(r, dd, 2, out);
    }
    if matches!(three, 0xf3000c00 | 0xf3100c00) {
        let part1 = three == 0xf3000c00;
        let mut x = input(&mut r, if part1 { dd } else { dn }, 32, 2);
        let mut y = input(&mut r, if part1 { dn } else { dd }, 32, 2);
        let keys = input(&mut r, dm, 32, 2);
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
        return finish(r, dd, 2, if part1 { x } else { y });
    }
    if two == 0xf3ba03c0 {
        let x = input(&mut r, dd, 32, 2);
        let y = input(&mut r, dm, 32, 1);
        let out = (0..4)
            .map(|i| {
                add(
                    x[i].clone(),
                    small(
                        if i < 3 {
                            x[i + 1].clone()
                        } else {
                            y[0].clone()
                        },
                        [7, 18, 3],
                    ),
                )
            })
            .collect();
        return finish(r, dd, 2, out);
    }
    if three == 0xf3200c00 {
        let x = input(&mut r, dd, 32, 2);
        let y = input(&mut r, dn, 32, 2);
        let z = input(&mut r, dm, 32, 2);
        let mut out: Vec<Expr> = vec![];
        for i in 0..4 {
            let source = if i < 2 {
                z[i + 2].clone()
            } else {
                out[i - 2].clone()
            };
            let base = if i < 3 {
                y[i + 1].clone()
            } else {
                z[0].clone()
            };
            out.push(r.bind(add(add(x[i].clone(), base), small(source, [17, 19, 10]))));
        }
        return finish(r, dd, 2, out);
    }
    let polynomial_short = word & 0xff800f10 == 0xf3000910;
    let polynomial_long = word & 0xfe800f50 == 0xf2800e00;
    if polynomial_short || polynomial_long {
        let size = (word >> 20) & 3;
        if (polynomial_short && size != 0)
            || (polynomial_long && (word & 0x01000000 != 0 || !matches!(size, 0 | 2)))
        {
            return unsupported(r, "reserved polynomial element width");
        }
        if (polynomial_long && dd & 1 != 0)
            || (polynomial_short && q && (dd & 1 != 0 || dn & 1 != 0 || dm & 1 != 0))
        {
            return unsupported(r, "polynomial instruction requires aligned Q operands");
        }
        if polynomial_long && size == 2 {
            forbid_it(&mut r, thumb);
        }
        let width = if polynomial_long && size == 2 { 64 } else { 8 };
        let regs = if polynomial_short && q { 2 } else { 1 };
        let x = input(&mut r, dn, width, regs);
        let y = input(&mut r, dm, width, regs);
        let mut parts = vec![];
        for (a, z) in x.into_iter().zip(y) {
            let (low, high) = polynomial(&mut r, a, z, width);
            parts.push(if polynomial_short {
                cast(low, 8, false)
            } else {
                low
            });
            if let Some(high) = high {
                parts.push(high);
            }
        }
        return finish(r, dd, if polynomial_long { 2 } else { regs }, parts);
    }
    if word & 0xffb00010 == 0xf2b00000 {
        let offset = ((word >> 8) & 15) as usize;
        let regs = if q { 2 } else { 1 };
        if (q && (dd & 1 != 0 || dn & 1 != 0 || dm & 1 != 0)) || (!q && offset >= 8) {
            return unsupported(r, "constrained VEXT register or immediate");
        }
        let mut source = input(&mut r, dn, 8, regs);
        source.extend(input(&mut r, dm, 8, regs));
        return finish(
            r,
            dd,
            regs,
            source[offset..offset + usize::from(regs) * 8].to_vec(),
        );
    }
    if word & 0xffb00c10 == 0xf3b00800 {
        let length = ((word >> 8) & 3) + 1;
        if dn + length > 32 {
            return unsupported(r, "VTBL/VTBX table crosses D31");
        }
        let table = input(&mut r, dn, 8, length as u8);
        let indices = input(&mut r, dm, 8, 1);
        let old = if q {
            input(&mut r, dd, 8, 1)
        } else {
            vec![c(8, 0); 8]
        };
        let mut parts = vec![];
        for (index, old) in indices.into_iter().zip(old) {
            let mut value = old;
            for (n, entry) in table.iter().enumerate().rev() {
                value = Expr::select(
                    b(B::Eq, index.clone(), c(8, n as u64)),
                    entry.clone(),
                    value,
                );
            }
            parts.push(value);
        }
        return finish(r, dd, 1, parts);
    }
    let unary = word & 0xffb30f90;
    if matches!(unary, 0xf3b00500 | 0xf3b00480 | 0xf3b00400) {
        let size = (word >> 18) & 3;
        if (unary == 0xf3b00500 && size != 0) || size == 3 || (q && (dd & 1 != 0 || dm & 1 != 0)) {
            return unsupported(r, "constrained vector count operands");
        }
        let regs = if q { 2 } else { 1 };
        let width = 8 << size;
        let x = input(&mut r, dm, width, regs);
        let parts = x
            .into_iter()
            .map(|value| {
                if unary == 0xf3b00500 {
                    Expr::unary(UnaryOp::PopulationCount, value)
                } else if unary == 0xf3b00480 {
                    Expr::unary(UnaryOp::CountLeadingZeros, value)
                } else {
                    let sign = ext(value.clone(), width - 1, 1);
                    let norm = Expr::select(sign, not(value.clone()), value);
                    b(
                        B::Sub,
                        Expr::unary(UnaryOp::CountLeadingZeros, norm),
                        c(width, 1),
                    )
                }
            })
            .collect();
        return finish(r, dd, regs, parts);
    }
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

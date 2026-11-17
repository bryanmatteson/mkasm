//! SVE2.1/SME2 predicate-as-counter families from the June-2026 Arm operations.
//! PN is an interpretation of P's low16 bits, not a separate register file.
//! P/PN aliases use a64.predicate64[P*4+chunk], fixed MAX_PL256 storage. Writes
//! choose permitted SVEZEROUPPER zero-extension; reads consume only low16.
//! The effective FEAT_SVE2p1 bit is a64.sve2p1[0] (width/parent1). Without
//! that feature the primary operations require SVCR.SM=1 (a64.svcr[0],64).
//! The supplied VL is effective CurrentVL; feature/permission admission is
//! otherwise the caller's existing architectural admission contract.
use super::*;
use BinaryOp as B;
fn c(width: u8, value: u64) -> Expr {
    Expr::constant(width, value)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn p(n: u16, chunk: u16) -> RegisterSlice {
    register("a64.predicate64", n * 4 + chunk, 64, 64)
}
fn gp(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
fn write(r: &mut Recipe, destination: RegisterSlice, value: Expr) {
    let value = r.bind(value);
    r.write(destination, WritePolicy::ZeroUpper, value);
}
fn write_counter(r: &mut Recipe, n: u16, value: Expr) {
    write(r, p(n, 0), value);
    for chunk in 1..4 {
        write(r, p(n, chunk), c(64, 0));
    }
}
fn encode_count(count: Expr, elements: u16, size: u32, invert: bool) -> Expr {
    let full = b(B::Eq, count.clone(), c(64, u64::from(elements)));
    let encoded_count = if invert {
        b(B::Sub, c(64, u64::from(elements)), count.clone())
    } else {
        Expr::select(full.clone(), c(64, 0), count.clone())
    };
    let encoded_invert = if invert {
        c(64, 1 << 15)
    } else {
        Expr::select(full, c(64, 1 << 15), c(64, 0))
    };
    Expr::select(
        b(B::Eq, count, c(64, 0)),
        c(64, 0),
        b(
            B::Or,
            encoded_invert,
            b(
                B::Or,
                b(B::Shl, encoded_count, c(64, u64::from(size + 1))),
                c(64, 1 << size),
            ),
        ),
    )
}
fn while_count(r: &mut Recipe, word: u32, elements: u16) -> Expr {
    let unsigned = word & (1 << 11) != 0;
    let invert = word & (1 << 10) == 0;
    let inclusive = (word & (1 << 3) != 0) != invert;
    let a = gp((word >> 5) & 31);
    let z = gp((word >> 16) & 31);
    // XORing the sign bit is an exact order-preserving bijection between
    // the signed domain and unsigned ordinals. Distances are then bounded
    // before the inclusive +1, so mathematical 2^64 never wraps to zero.
    let a = r.bind(if unsigned {
        a
    } else {
        b(B::Xor, a, c(64, 1 << 63))
    });
    let z = r.bind(if unsigned {
        z
    } else {
        b(B::Xor, z, c(64, 1 << 63))
    });
    let (first, last) = if invert {
        (z.clone(), a)
    } else {
        (a, z.clone())
    };
    let distance = r.bind(b(B::Sub, last.clone(), first.clone()));
    let initial = if inclusive {
        not(b(B::Ult, last, first))
    } else {
        b(B::Ult, first, last)
    };
    let bounded = Expr::select(
        b(B::Ult, distance.clone(), c(64, u64::from(elements))),
        b(B::Add, distance, c(64, u64::from(inclusive))),
        c(64, u64::from(elements)),
    );
    // Inclusive comparison with a domain endpoint remains true after the
    // operand wraps. The primary loop's sticky condition therefore stays set.
    let count = if inclusive {
        Expr::select(
            b(B::Eq, z, c(64, if invert { 0 } else { u64::MAX })),
            c(64, u64::from(elements)),
            bounded,
        )
    } else {
        bounded
    };
    r.bind(Expr::select(initial, count, c(64, 0)))
}
fn flags(r: &mut Recipe, count: Expr, elements: u16, invert: bool) {
    let zero = r.bind(b(B::Eq, count.clone(), c(64, 0)));
    let full = r.bind(b(B::Eq, count, c(64, u64::from(elements))));
    for (i, value) in [
        if invert {
            full.clone()
        } else {
            not(zero.clone())
        },
        zero.clone(),
        if invert { zero } else { not(full) },
        c(1, 0),
    ]
    .into_iter()
    .enumerate()
    {
        write(r, register("a64.nzcv", i as u16, 1, 1), value);
    }
}
pub(super) struct Counter {
    tags: Vec<Expr>,
    counts: Vec<Expr>,
    invert: Expr,
}
impl Counter {
    pub(super) fn read(r: &mut Recipe, n: u16, vl: u16) -> Self {
        Self::read_with(r, n, vl, false)
    }
    pub(super) fn read_before_reads(r: &mut Recipe, n: u16, vl: u16) -> Self {
        Self::read_with(r, n, vl, true)
    }
    fn read_with(r: &mut Recipe, n: u16, vl: u16, before: bool) -> Self {
        let bind = |r: &mut Recipe, value: Expr| {
            if before {
                r.bind_before_reads(value)
                    .expect("counter captures are pure incoming state")
            } else {
                r.bind(value)
            }
        };
        let counter = bind(r, Expr::extract(Expr::register(p(n, 0)), 0, 16));
        let top = (vl / 8 * 4).ilog2() as u8;
        let mut tags = Vec::new();
        let mut counts = Vec::new();
        for size in 0..4u8 {
            tags.push(bind(
                r,
                b(
                    B::Eq,
                    b(B::And, counter.clone(), c(16, (1 << (size + 1)) - 1)),
                    c(16, 1 << size),
                ),
            ));
            counts.push(bind(
                r,
                Expr::cast(
                    Expr::extract(counter.clone(), size + 1, top - size),
                    64,
                    false,
                ),
            ));
        }
        let invert = bind(r, Expr::extract(counter, 15, 1));
        Self {
            tags,
            counts,
            invert,
        }
    }
    pub(super) fn bit(&self, byte: u16) -> Expr {
        let mut out = c(1, 0);
        for size in 0..4usize {
            if byte % (1 << size) != 0 {
                continue;
            }
            let below = b(
                B::Ult,
                c(64, u64::from(byte >> size)),
                self.counts[size].clone(),
            );
            out = b(
                B::Or,
                out,
                b(
                    B::And,
                    self.tags[size].clone(),
                    b(B::Xor, below, self.invert.clone()),
                ),
            );
        }
        out
    }
    fn count(&self, requested_size: u32, width: u16, vl: u16) -> Expr {
        let requested_step = 1u16 << requested_size;
        let bytes = width * vl / 8;
        let mut result = c(64, 0);
        for size in 0..4usize {
            let source_step = 1u16 << size;
            let maximum = bytes / source_step.max(requested_step);
            let prefix = if source_step < requested_step {
                let ratio = requested_step / source_step;
                b(
                    B::Udiv,
                    b(
                        B::Add,
                        self.counts[size].clone(),
                        c(64, u64::from(ratio - 1)),
                    ),
                    c(64, u64::from(ratio)),
                )
            } else {
                self.counts[size].clone()
            };
            let prefix = Expr::select(
                b(B::Ult, prefix.clone(), c(64, u64::from(maximum))),
                prefix,
                c(64, u64::from(maximum)),
            );
            let count = Expr::select(
                self.invert.clone(),
                b(B::Sub, c(64, u64::from(maximum)), prefix.clone()),
                prefix,
            );
            result = b(
                B::Add,
                result,
                Expr::select(self.tags[size].clone(), count, c(64, 0)),
            );
        }
        result
    }
}
fn extract(r: &mut Recipe, counter: &Counter, d: u16, part: u16, size: u32, vl: u16) {
    let pl = vl / 8;
    for chunk in 0..4u16 {
        let mut value = c(64, 0);
        for bit in 0..64u16 {
            let byte = chunk * 64 + bit;
            if byte >= pl || byte % (1 << size) != 0 {
                continue;
            }
            value = b(
                B::Or,
                value,
                b(
                    B::Shl,
                    Expr::cast(counter.bit(part * pl + byte), 64, false),
                    c(64, u64::from(bit)),
                ),
            );
        }
        write(r, p(d, chunk), value);
    }
}
/// Exact predicate-as-counter operations at effective CurrentVL. Unrelated
/// ordinary predicate words return None; context failures are explicit guards.
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let ptrue = word & 0xff3ffff8 == 0x25207810;
    let while_form = word & 0xff20d010 == 0x25204010;
    let extract_one = word & 0xff3ffc10 == 0x25207010;
    let extract_pair = word & 0xff3ffe10 == 0x25207410;
    let count_form = word & 0xff3ffa00 == 0x25208200;
    if !ptrue && !while_form && !extract_one && !extract_pair && !count_form {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        r.guard = Expr::require_context(
            c(1, 0),
            "Predicate-counter CurrentVL must be an architectural power of two from128 to2048 bits",
        );
        return Some(r);
    }
    let sve2p1 = Expr::register(register("a64.sve2p1", 0, 1, 1));
    let streaming = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.guard = Expr::require_context(
        Expr::select(sve2p1, c(1, 1), streaming),
        "Predicate-counter instruction requires effective SVE2p1 or streaming mode",
    );
    let size = (word >> 22) & 3;
    if ptrue {
        write_counter(&mut r, 8 + (word & 7) as u16, c(64, 0x8000 | (1 << size)));
    } else if while_form {
        let elements = (2u16 << ((word >> 13) & 1)) * (vl / (8u16 << size));
        let count = while_count(&mut r, word, elements);
        let invert = word & (1 << 10) == 0;
        let encoded = r.bind(encode_count(count.clone(), elements, size, invert));
        flags(&mut r, count, elements, invert);
        write_counter(&mut r, 8 + (word & 7) as u16, encoded);
    } else if count_form {
        let counter = Counter::read(&mut r, ((word >> 5) & 15) as u16, vl);
        let count = counter.count(size, 2u16 << ((word >> 10) & 1), vl);
        let d = word & 31;
        if d != 31 {
            write(&mut r, register("a64.gpr", d as u16, 64, 64), count);
        }
    } else {
        let counter = Counter::read(&mut r, 8 + ((word >> 5) & 7) as u16, vl);
        let d = (word & 15) as u16;
        let part = ((word >> 8) & if extract_pair { 1 } else { 3 }) as u16;
        if extract_pair {
            extract(&mut r, &counter, d, part * 2, size, vl);
            extract(&mut r, &counter, (d + 1) % 16, part * 2 + 1, size, vl);
        } else {
            extract(&mut r, &counter, d, part, size, vl);
        }
    }
    Some(r)
}

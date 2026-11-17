//! A64 ordered accesses from the June 2026 Arm instruction diagrams.
//! The default profile has no FEAT_LSE2 guarantee. Pair accesses therefore
//! retain two separately atomic observations. Environments with an applicable
//! single-copy guarantee must select `a64_with_pair_atomicity` explicitly.
use super::*;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn bin(op: BinaryOp, a: Expr, b: Expr) -> Expr {
    Expr::binary(op, a, b)
}
fn gpr(n: u32, w: u8) -> Expr {
    if n == 31 {
        c(w, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, w, 64))
    }
}
fn base(n: u32) -> RegisterSlice {
    register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    )
}
fn vector(n: u32, chunk: u16) -> RegisterSlice {
    register("a64.vector64", n as u16 * 32 + chunk, 64, 64)
}
fn write(r: &mut Recipe, n: u32, w: u8, v: Expr) {
    if n != 31 {
        r.write(
            register("a64.gpr", n as u16, w, 64),
            WritePolicy::ZeroUpper,
            Expr::cast(v, w, false),
        );
    }
}
fn start(pc: u64, n: u32) -> Recipe {
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    if n == 31 {
        r.preflight_traps.push((
            TrapKind::Protection,
            bin(
                BinaryOp::And,
                Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
                Expr::unary(
                    UnaryOp::Not,
                    bin(
                        BinaryOp::Eq,
                        bin(BinaryOp::And, Expr::register(base(n)), c(64, 15)),
                        c(64, 0),
                    ),
                ),
            ),
        ));
    }
    r
}
fn aligned(r: &mut Recipe, address: Expr, bytes: u8) {
    if bytes > 1 {
        r.guard = bin(
            BinaryOp::And,
            r.guard.clone(),
            Expr::require_context(
                bin(
                    BinaryOp::Eq,
                    bin(BinaryOp::And, address, c(64, u64::from(bytes - 1))),
                    c(64, 0),
                ),
                "A64 ordered-access alignment controls",
            ),
        );
    }
}
fn access(
    address: Expr,
    width: u8,
    endian: Endian,
    ordering: MemoryOrdering,
    kind: AtomicOperationKind,
) -> AtomicOperation {
    AtomicOperation {
        memory: Memory {
            kind: Default::default(), privilege: Default::default(),
            address: Box::new(address),
            width,
            endian,
        },
        ordering,
        scope: MemoryScope::System,
        kind,
    }
}
fn load(r: &mut Recipe, address: Expr, width: u8, endian: Endian) -> Expr {
    load_ordered(r, address, width, endian, MemoryOrdering::AcquireRcpc)
}
fn load_ordered(
    r: &mut Recipe,
    address: Expr,
    width: u8,
    endian: Endian,
    ordering: MemoryOrdering,
) -> Expr {
    r.atomic(access(
        address,
        width,
        endian,
        ordering,
        AtomicOperationKind::Load,
    ))
    .value
    .unwrap()
}
fn store(r: &mut Recipe, address: Expr, width: u8, endian: Endian, value: Expr) {
    r.atomic(access(
        address,
        width,
        endian,
        MemoryOrdering::Release,
        AtomicOperationKind::Store { value },
    ));
}
fn offset(word: u32) -> u64 {
    ((((word >> 12) & 511) as i64) << 55 >> 55) as u64
}
fn add(a: Expr, n: u64) -> Expr {
    bin(BinaryOp::Add, a, c(64, n))
}
/// Baseline without FEAT_LSE2 pair single-copy guarantees.
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    a64_with_pair_atomicity(word, pc, endian, false)
}
/// `pair_atomic` guarantees that this pair access is single-copy atomic at its
/// effective address. It is not inferred from host atomic support or LRCPC3.
pub fn a64_with_pair_atomicity(
    word: u32,
    pc: u64,
    endian: Endian,
    pair_atomic: bool,
) -> Option<Recipe> {
    let rt = word & 31;
    let rn = (word >> 5) & 31;
    let size = (word >> 30) & 3;
    let width = 8u8 << size;
    let ordinary = word & 0x3fff_fc00 == 0x38bf_c000;
    let post = word & 0xbfff_fc00 == 0x99c0_0800;
    let scalar = word & 0x3f20_0c00 == 0x1900_0000;
    if ordinary || post || scalar {
        let opc = (word >> 22) & 3;
        // The signed word form is opc=2; opc=3 is reserved for sizes >=32.
        if scalar && ((opc == 3 && size >= 2) || (opc == 2 && size == 3)) {
            return Some(Recipe::unsupported(
                "A64 reserved unscaled ordered access",
                pc.wrapping_add(4),
                64,
            ));
        }
        let mut r = start(pc, rn);
        let address = if scalar {
            add(Expr::register(base(rn)), offset(word))
        } else {
            Expr::register(base(rn))
        };
        aligned(&mut r, address.clone(), width / 8);
        if scalar && opc == 0 {
            store(&mut r, address.clone(), width, endian, gpr(rt, width));
        } else {
            let signed = scalar && opc >= 2;
            let regwidth = if signed {
                if opc == 3 {
                    32
                } else {
                    64
                }
            } else if width == 64 {
                64
            } else {
                32
            };
            let value = load(&mut r, address.clone(), width, endian);
            write(&mut r, rt, regwidth, Expr::cast(value, regwidth, signed));
        }
        // Choose WBSUPPRESS for architectural constrained writeback overlap.
        if post && (rn == 31 || rn != rt) {
            r.write(
                base(rn),
                WritePolicy::ZeroUpper,
                add(address, u64::from(width / 8)),
            );
        }
        return Some(r);
    }
    // SIMD unscaled whole-register accesses, including the 128-bit split form.
    let simd = word & 0x3f20_0c00 == 0x1d00_0800;
    let lane = matches!(word & 0xbfbf_fc00, 0x0d01_8400);
    if simd || lane {
        let opc = (word >> 22) & 3;
        let load_op = word & (1 << 22) != 0;
        if simd && opc & 2 != 0 && size != 0 {
            return Some(Recipe::unsupported(
                "A64 reserved SIMD ordered access size",
                pc.wrapping_add(4),
                64,
            ));
        }
        let bits = if lane {
            64
        } else if opc & 2 != 0 {
            128
        } else {
            width as u16
        };
        let mut r = start(pc, rn);
        let address = if lane {
            Expr::register(base(rn))
        } else {
            add(Expr::register(base(rn)), offset(word))
        };
        aligned(&mut r, address.clone(), (bits.min(64) / 8) as u8);
        if lane {
            let chunk = ((word >> 30) & 1) as u16;
            if load_op {
                let value = load(&mut r, address, 64, endian);
                r.write(vector(rt, chunk), WritePolicy::ZeroUpper, value);
            } else {
                store(
                    &mut r,
                    address,
                    64,
                    endian,
                    Expr::register(vector(rt, chunk)),
                );
            }
        } else if bits <= 64 {
            if load_op {
                let value = load(&mut r, address, bits as u8, endian);
                r.write(
                    vector(rt, 0),
                    WritePolicy::ZeroUpper,
                    Expr::cast(value, 64, false),
                );
                r.write(vector(rt, 1), WritePolicy::ZeroUpper, c(64, 0));
            } else {
                store(
                    &mut r,
                    address,
                    bits as u8,
                    endian,
                    Expr::cast(Expr::register(vector(rt, 0)), bits as u8, false),
                );
            }
        } else {
            // Mem{128} for ASIMD uses two 64-bit accesses, including with LSE2.
            for address_chunk in 0..2u16 {
                let numeric_chunk = if endian == Endian::Little {
                    address_chunk
                } else {
                    1 - address_chunk
                };
                let at = add(address.clone(), u64::from(address_chunk) * 8);
                if load_op {
                    let value = load(&mut r, at, 64, endian);
                    r.write(vector(rt, numeric_chunk), WritePolicy::ZeroUpper, value);
                } else {
                    store(
                        &mut r,
                        at,
                        64,
                        endian,
                        Expr::register(vector(rt, numeric_chunk)),
                    );
                }
            }
        }
        // Lane loads assign V{128}, preserving the other D lane but clearing Zn
        // above bit127 through the ordinary generated CurrentVL write completion.
        return Some(r);
    }
    let lscp = matches!(word & 0xffe0_fc00, 0xd940_5800 | 0xd940_7800 | 0xd900_5800);
    let pair = matches!(word & 0xbfa0_ec00, 0x9900_0800);
    if pair || lscp {
        let load_op = word & (1 << 22) != 0;
        let wb = !lscp && word & (1 << 12) == 0;
        let rt2 = (word >> 16) & 31;
        let element = if size & 1 != 0 { 64 } else { 32 };
        let bytes = element / 8;
        let ordering = if lscp && (rt == 31 || rt2 == 31) {
            MemoryOrdering::Monotonic
        } else if lscp && word & (1 << 13) == 0 {
            MemoryOrdering::Acquire
        } else {
            MemoryOrdering::AcquireRcpc
        };
        // A permitted LDPOVERLAP choice is NOP, before any SP check or memory access.
        if load_op && rt == rt2 {
            return Some(Recipe::new(pc.wrapping_add(4), 64));
        }
        let mut r = start(pc, rn);
        let delta = u64::from(bytes) * 2;
        let address = if wb && !load_op {
            add(Expr::register(base(rn)), delta.wrapping_neg())
        } else {
            Expr::register(base(rn))
        };
        aligned(&mut r, address.clone(), bytes);
        if pair_atomic {
            // The supplied guarantee covers the whole pair, not two host accesses.
            let (first, second) = if load_op {
                if element == 64 {
                    let out = r.atomic(access(
                        address.clone(),
                        128,
                        endian,
                        ordering,
                        AtomicOperationKind::LoadPair,
                    ));
                    let a = out.value.unwrap();
                    let b = out.value_high.unwrap();
                    if endian == Endian::Little {
                        (a, b)
                    } else {
                        (b, a)
                    }
                } else {
                    let value = load_ordered(&mut r, address.clone(), 64, endian, ordering);
                    let low = Expr::extract(value.clone(), 0, 32);
                    let high = Expr::extract(value, 32, 32);
                    if endian == Endian::Little {
                        (low, high)
                    } else {
                        (high, low)
                    }
                }
            } else {
                (gpr(rt, element), gpr(rt2, element))
            };
            if load_op {
                write(&mut r, rt, element, first);
                write(&mut r, rt2, element, second);
            } else if element == 64 {
                let (low, high) = if endian == Endian::Little {
                    (first, second)
                } else {
                    (second, first)
                };
                r.atomic(access(
                    address.clone(),
                    128,
                    endian,
                    MemoryOrdering::Release,
                    AtomicOperationKind::StorePair { low, high },
                ));
            } else {
                let (low, high) = if endian == Endian::Little {
                    (first, second)
                } else {
                    (second, first)
                };
                let packed = bin(
                    BinaryOp::Or,
                    Expr::cast(low, 64, false),
                    bin(BinaryOp::Shl, Expr::cast(high, 64, false), c(64, 32)),
                );
                store(&mut r, address.clone(), 64, endian, packed);
            }
        } else if load_op {
            let first = load_ordered(&mut r, address.clone(), element, endian, ordering);
            let second = load_ordered(
                &mut r,
                add(address.clone(), u64::from(bytes)),
                element,
                endian,
                ordering,
            );
            write(&mut r, rt, element, first);
            write(&mut r, rt2, element, second);
        } else {
            // Pre-index STILP sets highestaddressfirst, independently of endian.
            for index in if wb { [1, 0] } else { [0, 1] } {
                store(
                    &mut r,
                    add(address.clone(), u64::from(bytes) * index),
                    element,
                    endian,
                    gpr(if index == 0 { rt } else { rt2 }, element),
                );
            }
        }
        if wb && (!load_op || rn == 31 || (rn != rt && rn != rt2)) {
            let value = if load_op {
                add(address, delta)
            } else {
                address
            };
            r.write(base(rn), WritePolicy::ZeroUpper, value);
        }
        return Some(r);
    }
    None
}

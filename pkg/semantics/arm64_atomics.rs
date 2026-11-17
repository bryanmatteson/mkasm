//! A64 native atomic families, decoded from the Arm register diagrams.
//!
//! Feature admission and memory faults/access permissions remain consumer-owned.
//! RCpc, limited ordering and unprivileged accesses retain distinct contracts.
//! X-pair exclusive loads retain independently atomic doubleword observations
//! under one reservation unless the caller supplies a pair-atomic guarantee.
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AtomicContext {
    /// The execution environment guarantees a single-copy-atomic X-pair
    /// exclusive load (for example its applicable FEAT_LSE2 access contract).
    pub exclusive_pair_atomic: bool,
}

fn read(number: u32, width: u8) -> Expr {
    if number == 31 {
        Expr::constant(width, 0)
    } else {
        Expr::register(register("a64.gpr", number as u16, width, 64))
    }
}
fn base(number: u32) -> Expr {
    Expr::register(register(
        if number == 31 { "a64.sp" } else { "a64.gpr" },
        if number == 31 { 0 } else { number as u16 },
        64,
        64,
    ))
}
fn write(recipe: &mut Recipe, number: u32, width: u8, value: Expr) {
    if number != 31 {
        recipe.write(
            register("a64.gpr", number as u16, width, 64),
            WritePolicy::ZeroUpper,
            Expr::cast(value, width, false),
        );
    }
}
fn order(acquire: bool, release: bool) -> MemoryOrdering {
    match (acquire, release) {
        (false, false) => MemoryOrdering::Monotonic,
        (true, false) => MemoryOrdering::Acquire,
        (false, true) => MemoryOrdering::Release,
        (true, true) => MemoryOrdering::AcquireRelease,
    }
}
fn reject(address: u64, reason: &'static str) -> Option<Recipe> {
    Some(Recipe::unsupported(reason, address.wrapping_add(4), 64))
}
fn start(address: u64, rn: u32) -> Recipe {
    let mut recipe = Recipe::new(address.wrapping_add(4), 64);
    if rn == 31 {
        recipe.preflight_traps.push((
            TrapKind::Protection,
            Expr::binary(
                BinaryOp::And,
                Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
                Expr::unary(
                    UnaryOp::Not,
                    Expr::binary(
                        BinaryOp::Eq,
                        Expr::binary(BinaryOp::And, base(rn), Expr::constant(64, 15)),
                        Expr::constant(64, 0),
                    ),
                ),
            ),
        ));
    }
    recipe
}
fn operation(
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
fn chunks(first: Expr, second: Expr, endian: Endian) -> (Expr, Expr) {
    match endian {
        Endian::Little => (first, second),
        Endian::Big => (second, first),
    }
}
fn pack32(first: Expr, second: Expr, endian: Endian) -> Expr {
    let (low, high) = chunks(first, second, endian);
    Expr::binary(
        BinaryOp::Or,
        Expr::cast(low, 64, false),
        Expr::binary(
            BinaryOp::Shl,
            Expr::cast(high, 64, false),
            Expr::constant(64, 32),
        ),
    )
}
fn pair_writes(
    recipe: &mut Recipe,
    first: u32,
    second: u32,
    width: u8,
    results: AtomicResults,
    endian: Endian,
) {
    let low = results.value.expect("pair read has a value");
    let (low, high) = if width == 64 {
        (
            low,
            results.value_high.expect("128-bit read has a high value"),
        )
    } else {
        (
            Expr::extract(low.clone(), 0, 32),
            Expr::extract(low, 32, 32),
        )
    };
    let (first_value, second_value) = chunks(low, high, endian);
    write(recipe, first, width, first_value);
    write(recipe, second, width, second_value);
}
fn status(recipe: &mut Recipe, destination: u32, success: Expr) {
    write(
        recipe,
        destination,
        32,
        Expr::select(success, Expr::constant(32, 0), Expr::constant(32, 1)),
    );
}

/// Decode with architectural split X-pair exclusive observations. A caller may
/// supply an explicit single-copy guarantee through `a64_with_context`.
pub fn a64(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    a64_with_context(word, address, endian, AtomicContext::default())
}

pub fn a64_with_context(
    word: u32,
    address: u64,
    endian: Endian,
    context: AtomicContext,
) -> Option<Recipe> {
    let rt = word & 31;
    let rn = (word >> 5) & 31;
    let rt2 = (word >> 10) & 31;
    let rs = (word >> 16) & 31;
    let size = (word >> 30) & 3;
    let width = 8u8 << size;
    let regwidth = if width == 64 { 64 } else { 32 };

    // CASP reserves odd register-pair starts; X30/XZR and W30/WZR are legal.
    if word & 0xbfa0_7c00 == 0x0820_7c00 {
        if rs & 1 != 0 || rt & 1 != 0 {
            return reject(address, "A64 CASP odd register pair");
        }
        let element = if word & (1 << 30) != 0 { 64 } else { 32 };
        let acquire = word & (1 << 22) != 0;
        let release = word & (1 << 15) != 0;
        let failure_ordering = if acquire {
            MemoryOrdering::Acquire
        } else {
            MemoryOrdering::Monotonic
        };
        let kind = if element == 64 {
            let (expected_low, expected_high) = chunks(read(rs, 64), read(rs + 1, 64), endian);
            let (replacement_low, replacement_high) =
                chunks(read(rt, 64), read(rt + 1, 64), endian);
            AtomicOperationKind::CompareExchangePair {
                expected_low,
                expected_high,
                replacement_low,
                replacement_high,
                failure_ordering,
            }
        } else {
            AtomicOperationKind::CompareExchange {
                expected: pack32(read(rs, 32), read(rs + 1, 32), endian),
                replacement: pack32(read(rt, 32), read(rt + 1, 32), endian),
                failure_ordering,
            }
        };
        let mut recipe = start(address, rn);
        let results = recipe.atomic(operation(
            base(rn),
            element * 2,
            endian,
            order(acquire, release),
            kind,
        ));
        pair_writes(&mut recipe, rs, rs + 1, element, results, endian);
        return Some(recipe);
    }
    // CAS byte/halfword/word/doubleword: acquire is suppressed for compare ZR.
    if word & 0x3fa0_7c00 == 0x08a0_7c00 {
        let acquire = word & (1 << 22) != 0 && rs != 31;
        let release = word & (1 << 15) != 0;
        let kind = AtomicOperationKind::CompareExchange {
            expected: read(rs, width),
            replacement: read(rt, width),
            failure_ordering: if acquire {
                MemoryOrdering::Acquire
            } else {
                MemoryOrdering::Monotonic
            },
        };
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            width,
            endian,
            order(acquire, release),
            kind,
        ));
        write(&mut recipe, rs, regwidth, result.value.unwrap());
        return Some(recipe);
    }
    // LDXP/LDAXP and STXP/STLXP. W-pair loads and all successful pair
    // conditional stores are single-copy atomic. X-pair loads may tear, while
    // retaining a reservation over the complete 128-bit region.
    let pair_load = word & 0xbfff_0000 == 0x887f_0000;
    let pair_store = word & 0xbfe0_0000 == 0x8820_0000;
    if pair_load || pair_store {
        let element = if word & (1 << 30) != 0 { 64 } else { 32 };
        if pair_load && rt == rt2 {
            return Some(Recipe::new(address.wrapping_add(4), 64));
        }
        if pair_store && (rs == rt || rs == rt2 || (rs == rn && rn != 31)) {
            return Some(Recipe::new(address.wrapping_add(4), 64));
        }
        let acqrel = word & (1 << 15) != 0;
        let kind = if pair_load {
            if element == 64 {
                if context.exclusive_pair_atomic {
                    AtomicOperationKind::LoadLinkedPair
                } else {
                    AtomicOperationKind::LoadLinkedPairSplit
                }
            } else {
                AtomicOperationKind::LoadLinked
            }
        } else if element == 64 {
            let (low, high) = chunks(read(rt, 64), read(rt2, 64), endian);
            AtomicOperationKind::StoreConditionalPair { low, high }
        } else {
            AtomicOperationKind::StoreConditional {
                value: pack32(read(rt, 32), read(rt2, 32), endian),
            }
        };
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            element * 2,
            endian,
            order(pair_load && acqrel, pair_store && acqrel),
            kind,
        ));
        if pair_load {
            pair_writes(&mut recipe, rt, rt2, element, result, endian);
        } else {
            status(&mut recipe, rs, result.success.unwrap());
        }
        return Some(recipe);
    }
    let exclusive_load = word & 0x3fff_7c00 == 0x085f_7c00;
    let exclusive_store = word & 0x3fe0_7c00 == 0x0800_7c00;
    if exclusive_load || exclusive_store {
        if exclusive_store && (rs == rt || (rs == rn && rn != 31)) {
            return Some(Recipe::new(address.wrapping_add(4), 64));
        }
        let acqrel = word & (1 << 15) != 0;
        let kind = if exclusive_load {
            AtomicOperationKind::LoadLinked
        } else {
            AtomicOperationKind::StoreConditional {
                value: read(rt, width),
            }
        };
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            width,
            endian,
            order(exclusive_load && acqrel, exclusive_store && acqrel),
            kind,
        ));
        if exclusive_load {
            write(&mut recipe, rt, regwidth, result.value.unwrap());
        } else {
            status(&mut recipe, rs, result.success.unwrap());
        }
        return Some(recipe);
    }
    let load_acquire = word & 0x3fff_fc00 == 0x08df_fc00;
    let store_release = word & 0x3fff_fc00 == 0x089f_fc00;
    if load_acquire || store_release {
        let kind = if load_acquire {
            AtomicOperationKind::Load
        } else {
            AtomicOperationKind::Store {
                value: read(rt, width),
            }
        };
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            width,
            endian,
            order(load_acquire, store_release),
            kind,
        ));
        if load_acquire {
            write(&mut recipe, rt, regwidth, result.value.unwrap());
        }
        return Some(recipe);
    }
    // FEAT_LRCPC3 STLR pre-index has ordinary release ordering plus writeback.
    if word & 0xbfff_fc00 == 0x9980_0800 {
        if rn == rt && rn != 31 {
            return reject(address, "A64 STLR pre-index source/base overlap");
        }
        let target = Expr::binary(
            BinaryOp::Sub,
            base(rn),
            Expr::constant(64, u64::from(width / 8)),
        );
        let mut recipe = start(address, rn);
        recipe.atomic(operation(
            target.clone(),
            width,
            endian,
            MemoryOrdering::Release,
            AtomicOperationKind::Store {
                value: read(rt, width),
            },
        ));
        recipe.write(
            register(
                if rn == 31 { "a64.sp" } else { "a64.gpr" },
                if rn == 31 { 0 } else { rn as u16 },
                64,
                64,
            ),
            WritePolicy::ZeroUpper,
            target,
        );
        return Some(recipe);
    }
    if word & 0x3fff_fc00 == 0x08df_7c00 || word & 0x3fff_fc00 == 0x089f_7c00 {
        let load = word & (1 << 22) != 0;
        let mut recipe = Recipe::new(address.wrapping_add(4), 64);
        if rn == 31 {
            let misaligned = Expr::unary(
                UnaryOp::Not,
                Expr::binary(
                    BinaryOp::Eq,
                    Expr::binary(BinaryOp::And, base(rn), Expr::constant(64, 15)),
                    Expr::constant(64, 0),
                ),
            );
            recipe.preflight_traps.push((
                TrapKind::Protection,
                Expr::binary(
                    BinaryOp::And,
                    Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
                    misaligned,
                ),
            ));
        }
        let result = recipe.atomic(operation(
            base(rn),
            width,
            endian,
            if load {
                MemoryOrdering::AcquireLimited
            } else {
                MemoryOrdering::ReleaseLimited
            },
            if load {
                AtomicOperationKind::Load
            } else {
                AtomicOperationKind::Store {
                    value: read(rt, width),
                }
            },
        ));
        if load {
            write(&mut recipe, rt, width.max(32), result.value.unwrap());
        }
        return Some(recipe);
    }
    if word & 0x3fff_fc00 == 0x38bf_c000 || word & 0xbfff_fc00 == 0x99c0_0800 {
        return reject(address, "A64 RCpc acquire needs an exact RCpc contract");
    }
    if word & 0xffa0_7c00 == 0x4980_7c00
        || word & 0xffa0_7c00 == 0xc980_7c00
        || word & 0xbf20_fc00 == 0x1920_8400
    {
        return reject(
            address,
            "A64 unprivileged atomic access needs an exact access contract",
        );
    }
    if matches!(word & 0xff20_fc00, 0x1920_1000 | 0x1920_3000 | 0x1920_8000) {
        if rt == 31 || rs == 31 {
            return reject(address, "A64 LSE128 reserves XZR operands");
        }
        // One of the primary's permitted LSE128OVERLAP choices is NOP. It
        // performs no access or SP check and has no arbitrary register result.
        if rt == rs {
            return Some(Recipe::new(address.wrapping_add(4), 64));
        }
        let opcode = (word >> 12) & 15;
        let rmw = match opcode {
            1 => AtomicPairRmwOp::And,
            3 => AtomicPairRmwOp::Or,
            8 => AtomicPairRmwOp::Exchange,
            _ => unreachable!(),
        };
        let value = |number| {
            if opcode == 1 {
                Expr::unary(UnaryOp::Not, read(number, 64))
            } else {
                read(number, 64)
            }
        };
        // Rt and Rt2 are independent registers, not an aligned consecutive pair.
        let (low, high) = chunks(value(rt), value(rs), endian);
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            128,
            endian,
            order(word & (1 << 23) != 0, word & (1 << 22) != 0),
            AtomicOperationKind::ReadModifyWritePair {
                operation: rmw,
                low,
                high,
            },
        ));
        pair_writes(&mut recipe, rt, rs, 64, result, endian);
        return Some(recipe);
    }
    // LSE atomic memory operations. LDCLR is AND with the complemented source;
    // the ST aliases (Rt=ZR) discard the result and suppress acquire semantics.
    if word & 0x3f20_0c00 == 0x3820_0000 {
        let opcode = (word >> 12) & 15;
        let rmw = match opcode {
            0 => AtomicRmwOp::Add,
            1 => AtomicRmwOp::And,
            2 => AtomicRmwOp::Xor,
            3 => AtomicRmwOp::Or,
            4 => AtomicRmwOp::SignedMax,
            5 => AtomicRmwOp::SignedMin,
            6 => AtomicRmwOp::UnsignedMax,
            7 => AtomicRmwOp::UnsignedMin,
            8 => AtomicRmwOp::Exchange,
            _ => {
                return reject(
                    address,
                    "A64 atomic memory opcode needs a distinct contract",
                )
            }
        };
        let source = if opcode == 1 {
            Expr::unary(UnaryOp::Not, read(rs, width))
        } else {
            read(rs, width)
        };
        let acquire = word & (1 << 23) != 0 && rt != 31;
        let release = word & (1 << 22) != 0;
        let mut recipe = start(address, rn);
        let result = recipe.atomic(operation(
            base(rn),
            width,
            endian,
            order(acquire, release),
            AtomicOperationKind::ReadModifyWrite {
                operation: rmw,
                value: source,
            },
        ));
        write(&mut recipe, rt, regwidth, result.value.unwrap());
        return Some(recipe);
    }
    if word & 0x3f00_0000 == 0x0800_0000 {
        return reject(address, "A64 reserved exclusive/atomic encoding fields");
    }
    None
}

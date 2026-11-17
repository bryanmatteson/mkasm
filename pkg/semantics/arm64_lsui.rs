//! Complete FEAT_LSUI physical families, including aliases (June 2026).
//! The access privilege is a typed architectural selection: the environment
//! resolves AArch64_IsUnprivAccessPriv, including EL/NV/UAO controls.
use super::*;
const FORMS: &[(u32, u32, u8, u8, u8)] = &[
    (0xffe0fc00, 0x49807c00, 1, 64, 0),  // CASPT_CP64_comswappr_unpriv
    (0xffe0fc00, 0x49c07c00, 1, 64, 0),  // CASPAT_CP64_comswappr_unpriv
    (0xffe0fc00, 0x49c0fc00, 1, 64, 0),  // CASPALT_CP64_comswappr_unpriv
    (0xffe0fc00, 0x4980fc00, 1, 64, 0),  // CASPLT_CP64_comswappr_unpriv
    (0xffe0fc00, 0xc9807c00, 0, 64, 0),  // CAST_C64_comswap_unpriv
    (0xffe0fc00, 0xc9c07c00, 0, 64, 0),  // CASAT_C64_comswap_unpriv
    (0xffe0fc00, 0xc9c0fc00, 0, 64, 0),  // CASALT_C64_comswap_unpriv
    (0xffe0fc00, 0xc980fc00, 0, 64, 0),  // CASLT_C64_comswap_unpriv
    (0xffe08000, 0x89408000, 2, 32, 0),  // LDATXR_LR32_ldstexclr_unpriv
    (0xffe08000, 0xc9408000, 2, 64, 0),  // LDATXR_LR64_ldstexclr_unpriv
    (0xffe0fc00, 0x19200400, 4, 32, 0),  // LDTADD_32_memop_unpriv
    (0xffe0fc00, 0x19a00400, 4, 32, 0),  // LDTADDA_32_memop_unpriv
    (0xffe0fc00, 0x19e00400, 4, 32, 0),  // LDTADDAL_32_memop_unpriv
    (0xffe0fc00, 0x19600400, 4, 32, 0),  // LDTADDL_32_memop_unpriv
    (0xffe0fc00, 0x59200400, 4, 64, 0),  // LDTADD_64_memop_unpriv
    (0xffe0fc00, 0x59a00400, 4, 64, 0),  // LDTADDA_64_memop_unpriv
    (0xffe0fc00, 0x59e00400, 4, 64, 0),  // LDTADDAL_64_memop_unpriv
    (0xffe0fc00, 0x59600400, 4, 64, 0),  // LDTADDL_64_memop_unpriv
    (0xffe0fc00, 0x19201400, 4, 32, 1),  // LDTCLR_32_memop_unpriv
    (0xffe0fc00, 0x19a01400, 4, 32, 1),  // LDTCLRA_32_memop_unpriv
    (0xffe0fc00, 0x19e01400, 4, 32, 1),  // LDTCLRAL_32_memop_unpriv
    (0xffe0fc00, 0x19601400, 4, 32, 1),  // LDTCLRL_32_memop_unpriv
    (0xffe0fc00, 0x59201400, 4, 64, 1),  // LDTCLR_64_memop_unpriv
    (0xffe0fc00, 0x59a01400, 4, 64, 1),  // LDTCLRA_64_memop_unpriv
    (0xffe0fc00, 0x59e01400, 4, 64, 1),  // LDTCLRAL_64_memop_unpriv
    (0xffe0fc00, 0x59601400, 4, 64, 1),  // LDTCLRL_64_memop_unpriv
    (0xffc00000, 0xec400000, 5, 128, 0), // LDTNP_Q_ldstnapair_offs
    (0xffc00000, 0xe8400000, 5, 64, 0),  // LDTNP_64_ldstnapair_offs
    (0xffc00000, 0xecc00000, 5, 128, 0), // LDTP_Q_ldstpair_post
    (0xffc00000, 0xedc00000, 5, 128, 0), // LDTP_Q_ldstpair_pre
    (0xffc00000, 0xed400000, 5, 128, 0), // LDTP_Q_ldstpair_off
    (0xffc00000, 0xe8c00000, 5, 64, 0),  // LDTP_64_ldstpair_post
    (0xffc00000, 0xe9c00000, 5, 64, 0),  // LDTP_64_ldstpair_pre
    (0xffc00000, 0xe9400000, 5, 64, 0),  // LDTP_64_ldstpair_off
    (0xffe0fc00, 0x19203400, 4, 32, 2),  // LDTSET_32_memop_unpriv
    (0xffe0fc00, 0x19a03400, 4, 32, 2),  // LDTSETA_32_memop_unpriv
    (0xffe0fc00, 0x19e03400, 4, 32, 2),  // LDTSETAL_32_memop_unpriv
    (0xffe0fc00, 0x19603400, 4, 32, 2),  // LDTSETL_32_memop_unpriv
    (0xffe0fc00, 0x59203400, 4, 64, 2),  // LDTSET_64_memop_unpriv
    (0xffe0fc00, 0x59a03400, 4, 64, 2),  // LDTSETA_64_memop_unpriv
    (0xffe0fc00, 0x59e03400, 4, 64, 2),  // LDTSETAL_64_memop_unpriv
    (0xffe0fc00, 0x59603400, 4, 64, 2),  // LDTSETL_64_memop_unpriv
    (0xffe08000, 0x89400000, 2, 32, 0),  // LDTXR_LR32_ldstexclr_unpriv
    (0xffe08000, 0xc9400000, 2, 64, 0),  // LDTXR_LR64_ldstexclr_unpriv
    (0xffe08000, 0x89008000, 3, 32, 0),  // STLTXR_SR32_ldstexclr_unpriv
    (0xffe08000, 0xc9008000, 3, 64, 0),  // STLTXR_SR64_ldstexclr_unpriv
    (0xffc00000, 0xec000000, 5, 128, 0), // STTNP_Q_ldstnapair_offs
    (0xffc00000, 0xe8000000, 5, 64, 0),  // STTNP_64_ldstnapair_offs
    (0xffc00000, 0xec800000, 5, 128, 0), // STTP_Q_ldstpair_post
    (0xffc00000, 0xed800000, 5, 128, 0), // STTP_Q_ldstpair_pre
    (0xffc00000, 0xed000000, 5, 128, 0), // STTP_Q_ldstpair_off
    (0xffc00000, 0xe8800000, 5, 64, 0),  // STTP_64_ldstpair_post
    (0xffc00000, 0xe9800000, 5, 64, 0),  // STTP_64_ldstpair_pre
    (0xffc00000, 0xe9000000, 5, 64, 0),  // STTP_64_ldstpair_off
    (0xffe08000, 0x89000000, 3, 32, 0),  // STTXR_SR32_ldstexclr_unpriv
    (0xffe08000, 0xc9000000, 3, 64, 0),  // STTXR_SR64_ldstexclr_unpriv
    (0xffe0fc00, 0x19208400, 4, 32, 3),  // SWPT_32_memop_unpriv
    (0xffe0fc00, 0x19a08400, 4, 32, 3),  // SWPTA_32_memop_unpriv
    (0xffe0fc00, 0x19e08400, 4, 32, 3),  // SWPTAL_32_memop_unpriv
    (0xffe0fc00, 0x19608400, 4, 32, 3),  // SWPTL_32_memop_unpriv
    (0xffe0fc00, 0x59208400, 4, 64, 3),  // SWPT_64_memop_unpriv
    (0xffe0fc00, 0x59a08400, 4, 64, 3),  // SWPTA_64_memop_unpriv
    (0xffe0fc00, 0x59e08400, 4, 64, 3),  // SWPTAL_64_memop_unpriv
    (0xffe0fc00, 0x59608400, 4, 64, 3),  // SWPTL_64_memop_unpriv
];
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn reg(n: u32) -> RegisterSlice {
    register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    )
}
fn gpr(n: u32, w: u8) -> Expr {
    if n == 31 {
        c(w, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, w, 64))
    }
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
fn vector(n: u32, k: u16) -> RegisterSlice {
    register("a64.vector64", n as u16 * 32 + k, 64, 64)
}
fn order(a: bool, r: bool) -> MemoryOrdering {
    match (a, r) {
        (false, false) => MemoryOrdering::Monotonic,
        (true, false) => MemoryOrdering::Acquire,
        (false, true) => MemoryOrdering::Release,
        (true, true) => MemoryOrdering::AcquireRelease,
    }
}
fn pair(a: Expr, b: Expr, endian: Endian) -> (Expr, Expr) {
    if endian == Endian::Little {
        (a, b)
    } else {
        (b, a)
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
            kind: Default::default(), address: Box::new(address),
            width,
            endian,
            privilege: MemoryPrivilege::AArch64Unprivileged,
        },
        ordering,
        scope: MemoryScope::System,
        kind,
    }
}
fn invalid(pc: u64) -> Recipe {
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    r.effects.push(Effect::Trap {
        kind: TrapKind::InvalidInstruction,
        condition: c(1, 1),
    });
    r
}
pub fn recognizes(word: u32) -> bool {
    FORMS.iter().any(|&(mask, value, ..)| word & mask == value)
}
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    let &(_, _, family, width, op) = FORMS
        .iter()
        .find(|&&(mask, value, ..)| word & mask == value)?;
    let (s, n, t, t2) = (
        (word >> 16) & 31,
        (word >> 5) & 31,
        word & 31,
        (word >> 10) & 31,
    );
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    if family == 1 && (s & 1 != 0 || t & 1 != 0) {
        return Some(invalid(pc));
    }
    if family == 3 && (s == t || (s == n && n != 31)) {
        // The permitted UNDEF outcome preserves memory, status and monitor.
        return Some(invalid(pc));
    }
    if family == 5 {
        let load = word & (1 << 22) != 0;
        let mode = (word >> 23) & 3;
        let wback = mode == 1 || mode == 3;
        let vector = width == 128;
        if (load && t == t2) || (!vector && wback && n != 31 && (n == t || n == t2)) {
            // Choose the primary's permitted NOP constrained-unpredictable outcome.
            return Some(r);
        }
    }
    let base = Expr::register(reg(n));
    if n == 31 {
        let misaligned = Expr::unary(
            UnaryOp::Not,
            Expr::binary(
                BinaryOp::Eq,
                Expr::binary(BinaryOp::And, base.clone(), c(64, 15)),
                c(64, 0),
            ),
        );
        r.preflight_traps.push((
            TrapKind::Protection,
            Expr::binary(
                BinaryOp::And,
                Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
                misaligned,
            ),
        ));
    }
    if family == 5 {
        let load = word & (1 << 22) != 0;
        let mode = (word >> 23) & 3;
        let wback = mode == 1 || mode == 3;
        let offset =
            ((((word >> 15) & 127) as i64) << 57 >> 57).wrapping_mul(i64::from(width / 8)) as u64;
        let advanced = Expr::binary(BinaryOp::Add, base.clone(), c(64, offset));
        let address = if mode == 1 { base } else { advanced.clone() };
        let memory = WideMemory {
            kind: Default::default(), address: Box::new(address),
            width: u16::from(width) * 2,
            endian,
            privilege: MemoryPrivilege::AArch64Unprivileged,
        };
        let vector = width == 128;
        if load {
            let mut chunks = r.load_wide(memory);
            // Numeric chunks are low first. Big endian reverses both pair
            // element order and chunk order inside each 128-bit vector.
            if endian == Endian::Big {
                chunks.reverse();
            }
            if vector {
                for (dest, at) in [(t, 0), (t2, 2)] {
                    let (low, high) = if endian == Endian::Big {
                        (chunks[at + 1].clone(), chunks[at].clone())
                    } else {
                        (chunks[at].clone(), chunks[at + 1].clone())
                    };
                    for k in 0..32 {
                        r.write(
                            vector_register(dest, k),
                            WritePolicy::ZeroUpper,
                            if k == 0 {
                                low.clone()
                            } else if k == 1 {
                                high.clone()
                            } else {
                                c(64, 0)
                            },
                        );
                    }
                }
            } else {
                write(&mut r, t, 64, chunks[0].clone());
                write(&mut r, t2, 64, chunks[1].clone());
            }
        } else {
            let mut chunks = if vector {
                vec![
                    Expr::register(vector_register(t, 0)),
                    Expr::register(vector_register(t, 1)),
                    Expr::register(vector_register(t2, 0)),
                    Expr::register(vector_register(t2, 1)),
                ]
            } else {
                vec![gpr(t, 64), gpr(t2, 64)]
            };
            if endian == Endian::Big {
                if vector {
                    chunks.rotate_left(2);
                } else {
                    chunks.reverse();
                }
            }
            r.effects.push(Effect::StoreWide { memory, chunks });
        }
        if wback {
            r.write(reg(n), WritePolicy::ZeroUpper, advanced);
        }
        return Some(r);
    }
    if family == 0 || family == 1 {
        let acquire = word & (1 << 22) != 0 && (family == 1 || s != 31);
        let release = word & (1 << 15) != 0;
        let failure_ordering = if acquire {
            MemoryOrdering::Acquire
        } else {
            MemoryOrdering::Monotonic
        };
        if family == 1 {
            let (expected_low, expected_high) = pair(gpr(s, 64), gpr(s + 1, 64), endian);
            let (replacement_low, replacement_high) = pair(gpr(t, 64), gpr(t + 1, 64), endian);
            let result = r.atomic(access(
                base,
                128,
                endian,
                order(acquire, release),
                AtomicOperationKind::CompareExchangePair {
                    expected_low,
                    expected_high,
                    replacement_low,
                    replacement_high,
                    failure_ordering,
                },
            ));
            let (a, b) = pair(result.value.unwrap(), result.value_high.unwrap(), endian);
            write(&mut r, s, 64, a);
            write(&mut r, s + 1, 64, b);
        } else {
            let result = r.atomic(access(
                base,
                64,
                endian,
                order(acquire, release),
                AtomicOperationKind::CompareExchange {
                    expected: gpr(s, 64),
                    replacement: gpr(t, 64),
                    failure_ordering,
                },
            ));
            write(&mut r, s, 64, result.value.unwrap());
        }
    } else if family == 2 || family == 3 {
        let acqrel = word & (1 << 15) != 0;
        let kind = if family == 2 {
            AtomicOperationKind::LoadLinked
        } else {
            AtomicOperationKind::StoreConditional {
                value: gpr(t, width),
            }
        };
        let result = r.atomic(access(
            base,
            width,
            endian,
            order(family == 2 && acqrel, family == 3 && acqrel),
            kind,
        ));
        if family == 2 {
            write(&mut r, t, width, result.value.unwrap());
        } else {
            write(
                &mut r,
                s,
                32,
                Expr::unary(UnaryOp::Not, result.success.unwrap()),
            );
        }
    } else {
        let acquire = word & (1 << 23) != 0 && t != 31;
        let release = word & (1 << 22) != 0;
        let operation = match op {
            0 => AtomicRmwOp::Add,
            1 => AtomicRmwOp::And,
            2 => AtomicRmwOp::Or,
            _ => AtomicRmwOp::Exchange,
        };
        let value = if op == 1 {
            Expr::unary(UnaryOp::Not, gpr(s, width))
        } else {
            gpr(s, width)
        };
        let result = r.atomic(access(
            base,
            width,
            endian,
            order(acquire, release),
            AtomicOperationKind::ReadModifyWrite { operation, value },
        ));
        write(&mut r, t, width, result.value.unwrap());
    }
    Some(r)
}
fn vector_register(n: u32, k: u16) -> RegisterSlice {
    vector(n, k)
}

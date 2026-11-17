//! Explicit GCS stores and synchronization. Privileged trap routing is a
//! resolved control input; GCS memory remains distinct from ordinary storage.
use super::*;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn input(bank: &'static str, w: u8) -> Expr {
    Expr::register(register(bank, 0, w, w))
}
fn not(e: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, e)
}
pub fn a64(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if word == 0xd503227f {
        r.effects.push(Effect::Barrier {
            kind: BarrierKind::GuardedControlStackSynchronization,
            scope: BarrierScope::System,
            access: BarrierAccess::All,
            condition: Some(input("a64.gcs_present", 1)),
        });
        return Some(r);
    }
    if !matches!(word & 0xfffffc00, 0xd91f0c00 | 0xd91f1c00) {
        return None;
    }
    let unpriv = word & (1 << 12) != 0;
    r.preflight_traps.push((
        TrapKind::InvalidInstruction,
        not(input("a64.gcs_present", 1)),
    ));
    // GCSSTTR bypasses STREn only when it actually selects a different EL.
    // UAO/nested-virtualization resolution is supplied explicitly, as it is for
    // ordinary A64 unprivileged accesses. EL0 always checks its current STREn.
    let check = if unpriv {
        Expr::select(
            Expr::binary(BinaryOp::Eq, input("a64.current_el", 2), c(2, 0)),
            c(1, 1),
            input("a64.unprivileged_is_privileged", 1),
        )
    } else {
        c(1, 1)
    };
    r.preflight_traps.push((
        TrapKind::AArch64GcsStore,
        Expr::select(check, not(input("a64.gcs_store_permitted", 1)), c(1, 0)),
    ));
    let n = (word >> 5) & 31;
    let base = if n == 31 {
        input("a64.sp", 64)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    };
    if n == 31 {
        r.preflight_traps.push((
            TrapKind::Protection,
            Expr::select(
                input("a64.sp_alignment_enforced", 1),
                not(Expr::binary(
                    BinaryOp::Eq,
                    Expr::binary(BinaryOp::And, base.clone(), c(64, 15)),
                    c(64, 0),
                )),
                c(1, 0),
            ),
        ));
    }
    let t = word & 31;
    let value = if t == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", t as u16, 64, 64))
    };
    r.effects.push(Effect::Store {
        memory: Memory {
            kind: MemoryKind::GuardedControlStack, privilege: if unpriv {
                MemoryPrivilege::AArch64Unprivileged
            } else {
                MemoryPrivilege::Current
            },
            address: Box::new(base),
            width: 64,
            endian,
        },
        value,
    });
    Some(r)
}

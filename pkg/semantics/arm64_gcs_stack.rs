//! Guarded control stack records and stack-switch protocol. Effective system
//! instruction permission is supplied separately from GCS presence and PCRSEL.
//! Translation, memory attributes and exception routing remain target contracts.
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
fn and(a: Expr, z: Expr) -> Expr {
    Expr::select(a, z, c(1, 0))
}
fn input(name: &'static str, w: u8) -> Expr {
    Expr::register(register(name, 0, w, w))
}
fn pointer() -> Expr {
    b(B::And, input("a64.gcs_pointer", 64), c(64, !7))
}
fn memory(address: Expr, endian: Endian) -> Memory {
    Memory {
        kind: MemoryKind::GuardedControlStack,
        privilege: MemoryPrivilege::Current,
        address: Box::new(address),
        width: 64,
        endian,
    }
}
fn put(r: &mut Recipe, name: &'static str, width: u8, value: Expr) {
    r.write(
        register(name, 0, width, width),
        WritePolicy::ZeroUpper,
        value,
    );
}
fn gp(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
fn output(r: &mut Recipe, n: u32, value: Expr) {
    if n != 31 {
        r.write(
            register("a64.gpr", n as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn fail(r: &mut Recipe, kind: TrapKind, condition: Expr) {
    r.effects.push(Effect::Trap { kind, condition });
}
fn store(r: &mut Recipe, address: Expr, value: Expr, endian: Endian) {
    r.effects.push(Effect::Store {
        memory: memory(address, endian),
        value,
    });
}
fn load(r: &mut Recipe, address: Expr, endian: Endian) -> Expr {
    r.bind(Expr::load(memory(address, endian)))
}
/// SYS/SYSL aliases. The low five register bits remain operands, including XZR.
pub fn operation(word: u32) -> Option<u8> {
    match word & !31 {
        0xd50b7700 => Some(0), // GCSPUSHM
        0xd52b7720 => Some(1), // GCSPOPM
        0xd50b7740 => Some(2), // GCSSS1
        0xd52b7760 => Some(3), // GCSSS2
        0xd5087780 => Some(4), // GCSPUSHX
        0xd50877a0 => Some(5), // GCSPOPCX
        0xd50877c0 => Some(6), // GCSPOPX
        _ => None,
    }
}
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    if word & !31 == 0xd53b2520 {
        let mut r = Recipe::new(pc.wrapping_add(4), 64);
        r.preflight_traps.push((
            TrapKind::InvalidInstruction,
            not(input("a64.gcs_present", 1)),
        ));
        output(&mut r, word & 31, pointer());
        return Some(r);
    }
    let op = operation(word)?;
    let t = word & 31;
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    r.preflight_traps.push((
        TrapKind::InvalidInstruction,
        not(input("a64.gcs_present", 1)),
    ));
    // The SYS owner resolves GCSCRE*/HCR*/SCR*/FGT and privilege checks. Missing
    // policy is unavailable, rather than assuming that a privileged op is legal.
    r.preflight_traps.push((
        TrapKind::Protection,
        not(input("a64.gcs_stack_permitted", 1)),
    ));
    if op >= 4 {
        r.preflight_traps.push((
            TrapKind::Protection,
            b(B::Eq, input("a64.current_el", 2), c(2, 0)),
        ));
    }
    let ptr = pointer();
    match op {
        0 => {
            store(&mut r, b(B::Sub, ptr.clone(), c(64, 8)), gp(t), endian);
            put(&mut r, "a64.gcs_pointer", 64, b(B::Sub, ptr, c(64, 8)));
        }
        1 => {
            let value = load(&mut r, ptr.clone(), endian);
            fail(
                &mut r,
                TrapKind::AArch64GcsPop,
                not(b(B::Eq, b(B::And, value.clone(), c(64, 3)), c(64, 0))),
            );
            put(&mut r, "a64.gcs_pointer", 64, b(B::Add, ptr, c(64, 8)));
            output(&mut r, t, value);
        }
        2 => {
            let incoming = gp(t);
            let expected = b(B::Or, b(B::And, incoming.clone(), c(64, !4095)), c(64, 1));
            let replacement = b(B::Or, ptr, c(64, 5));
            let result = r.atomic(AtomicOperation {
                memory: memory(incoming.clone(), endian),
                ordering: MemoryOrdering::Monotonic,
                scope: MemoryScope::System,
                kind: AtomicOperationKind::CompareExchange {
                    expected: expected.clone(),
                    replacement,
                    failure_ordering: MemoryOrdering::Monotonic,
                },
            });
            fail(
                &mut r,
                TrapKind::AArch64GcsSwitch1,
                not(b(B::Eq, result.value?, expected)),
            );
            put(
                &mut r,
                "a64.gcs_pointer",
                64,
                b(B::And, incoming, c(64, !7)),
            );
        }
        3 => {
            let value = load(&mut r, ptr.clone(), endian);
            fail(
                &mut r,
                TrapKind::AArch64GcsSwitch2,
                not(b(B::Eq, b(B::And, value.clone(), c(64, 7)), c(64, 5))),
            );
            let outgoing = b(B::And, b(B::Sub, value, c(64, 8)), c(64, !7));
            let token = b(B::Or, b(B::And, outgoing.clone(), c(64, !4095)), c(64, 1));
            store(&mut r, outgoing.clone(), token, endian);
            put(&mut r, "a64.gcs_pointer", 64, b(B::Add, ptr, c(64, 8)));
            r.effects.push(Effect::Barrier {
                kind: BarrierKind::GuardedControlStackSynchronization,
                scope: BarrierScope::System,
                access: BarrierAccess::All,
                condition: None,
            });
            output(&mut r, t, outgoing);
        }
        4 => {
            for (offset, value) in [
                (8, gp(30)),
                (16, input("a64.gcs_spsr", 64)),
                (24, input("a64.gcs_elr", 64)),
                (32, c(64, 9)),
            ] {
                store(&mut r, b(B::Sub, ptr.clone(), c(64, offset)), value, endian);
            }
            put(&mut r, "a64.gcs_pointer", 64, b(B::Sub, ptr, c(64, 32)));
            put(&mut r, "a64.gcs_exlock", 1, c(1, 0));
        }
        5 | 6 => {
            let first = load(&mut r, ptr.clone(), endian);
            let mut valid = b(B::Eq, first, c(64, 9));
            let kind = if op == 5 {
                TrapKind::AArch64GcsPopCompareException
            } else {
                TrapKind::AArch64GcsPopException
            };
            fail(&mut r, kind, not(valid.clone()));
            for (offset, expected) in [
                (8, input("a64.gcs_elr", 64)),
                (16, input("a64.gcs_spsr", 64)),
                (24, gp(30)),
            ] {
                // Suppress later loads after an earlier data-check failure. All
                // selected reads still occur even when the destination is XZR.
                let value = r.bind(Expr::select(
                    valid.clone(),
                    Expr::load(memory(b(B::Add, ptr.clone(), c(64, offset)), endian)),
                    c(64, 0),
                ));
                if op == 5 {
                    let this = b(B::Eq, value, expected);
                    fail(&mut r, kind, and(valid.clone(), not(this.clone())));
                    valid = and(valid, this);
                }
            }
            put(&mut r, "a64.gcs_pointer", 64, b(B::Add, ptr, c(64, 32)));
            if op == 5 {
                put(
                    &mut r,
                    "a64.gcs_exlock",
                    1,
                    input("a64.gcs_exlock_enabled", 1),
                );
            }
        }
        _ => unreachable!(),
    }
    Some(r)
}
/// Add implicit GCS call/return behavior to a complete instruction recipe.
/// Operand/authentication captures retain their incoming-state identity. The
/// guarded load/store and pointer update precede link writes and control flow.
pub fn complete(word: u32, mut r: Recipe, endian: Endian) -> Recipe {
    if r.support != Support::Full || !matches!(r.flow.kind, FlowKind::Call | FlowKind::Return) {
        return r;
    }
    let active = and(input("a64.gcs_present", 1), input("a64.gcs_enabled", 1));
    let ptr = pointer();
    let mut prefix = vec![];
    if r.flow.kind == FlowKind::Call {
        prefix.push(Effect::StoreConditional {
            condition: active.clone(),
            memory: memory(b(B::Sub, ptr.clone(), c(64, 8)), endian),
            value: r.flow.fallthrough.clone(),
        });
        prefix.push(Effect::WriteRegisterConditional {
            condition: active,
            destination: register("a64.gcs_pointer", 0, 64, 64),
            policy: WritePolicy::ZeroUpper,
            value: b(B::Sub, ptr, c(64, 8)),
        });
    } else {
        let target = r.flow.target.clone();
        let recorded = r.bind(Expr::select(
            active.clone(),
            Expr::load(memory(ptr.clone(), endian)),
            target.clone(),
        ));
        let kind = if word & 0xfffffc1f == 0xd65f0000 {
            TrapKind::AArch64GcsReturn
        } else if word
            & (if word & 0xffc0001f == 0x5500001f {
                1 << 21
            } else {
                1 << 10
            })
            == 0
        {
            TrapKind::AArch64GcsReturnA
        } else {
            TrapKind::AArch64GcsReturnB
        };
        prefix.push(Effect::Trap {
            kind,
            condition: and(
                active.clone(),
                and(
                    input("a64.gcs_return_check", 1),
                    not(b(B::Eq, recorded.clone(), target)),
                ),
            ),
        });
        prefix.push(Effect::WriteRegisterConditional {
            condition: active,
            destination: register("a64.gcs_pointer", 0, 64, 64),
            policy: WritePolicy::ZeroUpper,
            value: b(B::Add, ptr, c(64, 8)),
        });
        // When checking is disabled the recorded address supplies the return.
        r.flow.target = recorded;
    }
    prefix.append(&mut r.effects);
    r.effects = prefix;
    r
}

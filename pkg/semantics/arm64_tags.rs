//! A64 allocation-tag memory: MTE scalar/pair and MTE2 bulk families.
//! Tag translation, enablement and memory type are explicit callback policy;
//! tag metadata never aliases ordinary data memory.
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
fn read(n: u32, sp: bool) -> Expr {
    if n == 31 && !sp {
        c(64, 0)
    } else {
        Expr::register(reg(n))
    }
}
fn reg(n: u32) -> RegisterSlice {
    register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    )
}
fn write(r: &mut Recipe, n: u32, sp: bool, v: Expr) {
    if n != 31 || sp {
        r.write(reg(n), WritePolicy::ZeroUpper, v);
    }
}
fn state(name: &'static str, w: u8) -> Expr {
    Expr::register(register(name, 0, w, w))
}
fn aligned(a: Expr, n: u64) -> Expr {
    b(B::And, a, c(64, !(n - 1)))
}
fn tag(a: Expr) -> Expr {
    Expr::extract(a, 56, 4)
}
fn add(a: Expr, z: u64) -> Expr {
    b(B::Add, a, c(64, z))
}
fn sign(v: u32, w: u8) -> u64 {
    (((v as i64) << (64 - w)) >> (64 - w)) as u64
}
fn trap(r: &mut Recipe, kind: TrapKind, condition: Expr) {
    r.preflight_traps.push((kind, condition));
}
fn zero(r: &mut Recipe, a: Expr, width: u16) {
    r.effects.push(Effect::StoreWide {
        memory: WideMemory {
            kind: Default::default(), address: Box::new(a),
            width,
            endian: Endian::Little,
            privilege: MemoryPrivilege::Current,
        },
        chunks: vec![c(64, 0); usize::from(width / 64)],
    });
}
fn storetag(r: &mut Recipe, a: Expr, t: Expr, condition: Option<Expr>) {
    r.store_allocation_tag(a, t, MemoryPrivilege::Current, condition);
}
pub fn recognizes(w: u32) -> bool {
    w & 0xff200000 == 0xd9200000 || w & 0xfe400000 == 0x68000000
}
pub fn a64(w: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    let pair = w & 0xfe400000 == 0x68000000;
    if !pair && w & 0xff200000 != 0xd9200000 {
        return None;
    }
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    let n = (w >> 5) & 31;
    let t = w & 31;
    if n == 31 {
        r.preflight_traps.push((
            TrapKind::Protection,
            b(
                B::And,
                state("a64.sp_alignment_enforced", 1),
                not(b(B::Eq, b(B::And, read(n, true), c(64, 15)), c(64, 0))),
            ),
        ));
    }
    if pair {
        let mode = (w >> 23) & 3;
        if mode == 0 {
            return None;
        }
        let offset = sign((w >> 15) & 127, 7).wrapping_mul(16);
        let address = if mode == 1 {
            read(n, true)
        } else {
            add(read(n, true), offset)
        };
        trap(
            &mut r,
            TrapKind::Protection,
            not(b(B::Eq, b(B::And, address.clone(), c(64, 15)), c(64, 0))),
        );
        let second = read((w >> 10) & 31, false);
        let first = read(t, false);
        let chunks = if endian == Endian::Little {
            vec![first, second]
        } else {
            vec![second, first]
        };
        r.effects.push(Effect::StoreWide {
            memory: WideMemory {
                kind: Default::default(), address: Box::new(address.clone()),
                width: 128,
                endian,
                privilege: MemoryPrivilege::Current,
            },
            chunks,
        });
        storetag(&mut r, address.clone(), tag(address), None);
        if mode != 2 {
            write(&mut r, n, true, add(read(n, true), offset));
        }
        return Some(r);
    }
    let op = (w >> 22) & 3;
    let mode = (w >> 10) & 3;
    let imm = (w >> 12) & 511;
    let address = if mode == 1 {
        read(n, true)
    } else {
        add(read(n, true), sign(imm, 9).wrapping_mul(16))
    };
    if mode == 0 && op == 1 {
        // LDG modifies only tag bits of the incoming destination.
        let value = r.bind(Expr::load_allocation_tag(
            aligned(address, 16),
            MemoryPrivilege::Current,
        ));
        let value = b(
            B::Or,
            b(B::And, read(t, false), c(64, !(15u64 << 56))),
            b(B::Shl, Expr::cast(value, 64, false), c(64, 56)),
        );
        write(&mut r, t, false, value);
        return Some(r);
    }
    if mode == 0 {
        // MTE2 bulk operations, privileged at EL0.
        if imm != 0 {
            return None;
        }
        r.preflight_traps.push((
            TrapKind::InvalidInstruction,
            b(B::Eq, state("a64.current_el", 2), c(2, 0)),
        ));
        let zgm = op == 0;
        let load = op == 3;
        let bs = state(if zgm { "a64.dczid_bs" } else { "a64.gmid_bs" }, 4);
        let upper = if zgm { 9 } else { 6 };
        r.guard = Expr::select(
            b(B::Eq, state("a64.current_el", 2), c(2, 0)),
            c(1, 1),
            Expr::require_context(
                b(
                    B::And,
                    not(b(B::Ult, bs.clone(), c(4, 2))),
                    not(b(B::Ult, c(4, upper), bs.clone())),
                ),
                "A64 allocation tag block size",
            ),
        );
        let size = b(B::Shl, c(64, 4), Expr::cast(bs, 64, false));
        let base = b(
            B::And,
            read(n, true),
            not(b(B::Sub, size.clone(), c(64, 1))),
        );
        let count = b(B::Lsr, size, c(64, 4));
        let mut output = c(64, 0);
        for i in 0..if zgm { 128 } else { 16 } {
            let active = b(B::Ult, c(64, i), count.clone());
            let address = add(base.clone(), i * 16);
            let index = b(B::And, b(B::Lsr, address.clone(), c(64, 4)), c(64, 15));
            if load {
                let value = r.bind(Expr::select(
                    active,
                    Expr::load_allocation_tag(address, MemoryPrivilege::Current),
                    c(4, 0),
                ));
                output = b(
                    B::Or,
                    output,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        b(B::Shl, index, c(64, 2)),
                    ),
                );
            } else {
                let value = if zgm {
                    Expr::extract(read(t, false), 0, 4)
                } else {
                    Expr::extract(b(B::Lsr, read(t, false), b(B::Shl, index, c(64, 2))), 0, 4)
                };
                storetag(&mut r, address.clone(), value, Some(active.clone()));
                if zgm {
                    r.effects.push(Effect::StoreWideConditional {
                        memory: WideMemory {
                            kind: Default::default(), address: Box::new(address),
                            width: 128,
                            endian,
                            privilege: MemoryPrivilege::Current,
                        },
                        chunks: vec![c(64, 0); 2],
                        condition: active,
                    });
                }
            }
        }
        if load {
            write(&mut r, t, false, output);
        }
        return Some(r);
    }
    if op & 1 != 0 {
        // STZG/STZ2G data is written before allocation tags.
        trap(
            &mut r,
            TrapKind::Protection,
            not(b(B::Eq, b(B::And, address.clone(), c(64, 15)), c(64, 0))),
        );
        zero(&mut r, address.clone(), if op == 3 { 256 } else { 128 });
    }
    let value = tag(read(t, true));
    storetag(&mut r, address.clone(), value.clone(), None);
    if op >= 2 {
        storetag(&mut r, add(address, 16), value, None);
    }
    if mode != 2 {
        write(
            &mut r,
            n,
            true,
            add(read(n, true), sign(imm, 9).wrapping_mul(16)),
        );
    }
    Some(r)
}

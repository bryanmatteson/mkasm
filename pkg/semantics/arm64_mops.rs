//! FEAT_MOPS: Option B, zero prologue/epilogue work, one restartable
//! byte (copy/set) or allocation granule (SETG) in each main transition.
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
fn reg(n: u32) -> RegisterSlice {
    register("a64.gpr", n as u16, 64, 64)
}
fn read(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(reg(n))
    }
}
fn write(r: &mut Recipe, n: u32, v: Expr) {
    r.write(reg(n), WritePolicy::ZeroUpper, v);
}
fn trap(r: &mut Recipe, kind: TrapKind, condition: Expr) {
    r.preflight_traps.push((kind, condition));
}
fn nz(v: Expr) -> Expr {
    not(b(B::Eq, v, c(64, 0)))
}
fn privilege(v: bool) -> MemoryPrivilege {
    if v {
        MemoryPrivilege::AArch64Unprivileged
    } else {
        MemoryPrivilege::Current
    }
}
/// Returns (stage 0/1/2, set, tag-setting) for all 120 physical forms.
pub fn recognizes(word: u32) -> Option<(u8, bool, bool)> {
    if word & 0xfb200c00 != 0x19000400 || word >> 30 != 0 {
        return None;
    }
    let op1 = (word >> 22) & 3;
    let stage = if op1 == 3 { (word >> 14) & 3 } else { op1 };
    if stage == 3 {
        return None;
    }
    Some((stage as u8, op1 == 3, op1 == 3 && word & (1 << 26) != 0))
}
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    let (stage, set, tags) = recognizes(word)?;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let s = (word >> 16) & 31;
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    r.preflight_traps.push((
        TrapKind::InvalidInstruction,
        not(Expr::register(register("a64.mops_enabled", 0, 1, 1))),
    ));
    if d == 31
        || n == 31
        || d == n
        || (set && (s == d || s == n))
        || (!set && (s == 31 || s == d || s == n))
    {
        r.preflight_traps
            .push((TrapKind::InvalidInstruction, c(1, 1)));
        return Some(r);
    }
    let dst = read(d);
    let src = read(s);
    let count = read(n);
    let forward_only = !set && word & (1 << 26) == 0;
    if stage == 0 {
        let max = if tags {
            0x7fff_ffff_ffff_fff0
        } else if set || forward_only {
            0x7fff_ffff_ffff_ffff
        } else {
            0x007f_ffff_ffff_ffff
        };
        let size = if forward_only {
            Expr::select(Expr::extract(count.clone(), 63, 1), c(64, max), count)
        } else {
            Expr::select(b(B::Ult, c(64, max), count.clone()), c(64, max), count)
        };

        if tags {
            let unaligned = b(
                B::Or,
                b(
                    B::And,
                    nz(size.clone()),
                    nz(b(B::And, dst.clone(), c(64, 15))),
                ),
                nz(b(B::And, size.clone(), c(64, 15))),
            );
            trap(&mut r, TrapKind::Protection, unaligned);
        }
        let size = r.bind(size);
        let backwards = if set || forward_only {
            c(1, 0)
        } else {
            let a = b(B::And, src.clone(), c(64, 0x00ff_ffff_ffff_ffff));
            let z = b(B::And, dst.clone(), c(64, 0x00ff_ffff_ffff_ffff));
            b(
                B::And,
                b(B::Ult, a.clone(), z.clone()),
                b(B::Ult, z, b(B::Add, a, size.clone())),
            )
        };
        let backwards = r.bind(backwards);
        write(&mut r, n, size.clone());
        if !set && !forward_only {
            write(
                &mut r,
                d,
                Expr::select(backwards.clone(), b(B::Add, dst, size.clone()), read(d)),
            );
            write(
                &mut r,
                s,
                Expr::select(backwards.clone(), b(B::Add, src, size), read(s)),
            );
        }
        for (i, v) in [backwards, c(1, 0), c(1, 1), c(1, 0)]
            .into_iter()
            .enumerate()
        {
            r.write(
                register("a64.nzcv", i as u16, 1, 1),
                WritePolicy::ZeroUpper,
                v,
            );
        }
        return Some(r);
    }
    let active = nz(count.clone());
    if stage == 2 {
        trap(&mut r, TrapKind::AArch64MopsParameters, active);
        return Some(r);
    }
    let carry = Expr::register(register("a64.nzcv", 2, 1, 1));
    trap(
        &mut r,
        TrapKind::AArch64MopsWrongOption,
        b(B::And, active.clone(), not(carry)),
    );
    trap(
        &mut r,
        TrapKind::AArch64MopsParameters,
        Expr::extract(count.clone(), 63, 1),
    );
    if tags {
        trap(
            &mut r,
            TrapKind::Protection,
            b(
                B::And,
                active.clone(),
                nz(b(
                    B::Or,
                    b(B::And, count.clone(), c(64, 15)),
                    b(B::And, dst.clone(), c(64, 15)),
                )),
            ),
        );
    }
    let backwards = if set || forward_only {
        c(1, 0)
    } else {
        Expr::register(register("a64.nzcv", 0, 1, 1))
    };
    let step = if tags { 16 } else { 1 };
    let target = Expr::select(
        backwards.clone(),
        b(B::Sub, dst.clone(), c(64, step)),
        dst.clone(),
    );
    let source = Expr::select(
        backwards.clone(),
        b(B::Sub, src.clone(), c(64, step)),
        src.clone(),
    );
    let options = (word >> 12) & 15;
    let wp = privilege(options & 1 != 0);
    let rp = privilege(options & 2 != 0);
    if set {
        let byte = Expr::extract(src, 0, 8);
        if tags {
            let mut fill = c(64, 0);
            for i in 0..8 {
                fill = b(
                    B::Or,
                    fill,
                    b(B::Shl, Expr::cast(byte.clone(), 64, false), c(64, i * 8)),
                );
            }
            r.effects.push(Effect::StoreWideConditional {
                memory: WideMemory {
                    kind: Default::default(), address: Box::new(target.clone()),
                    width: 128,
                    endian,
                    privilege: wp,
                },
                chunks: vec![fill.clone(), fill],
                condition: active.clone(),
            });
            r.store_allocation_tag(
                target.clone(),
                Expr::extract(target.clone(), 56, 4),
                wp,
                Some(active.clone()),
            );
        } else {
            r.effects.push(Effect::StoreConditional {
                memory: Memory {
                    kind: Default::default(), address: Box::new(target.clone()),
                    width: 8,
                    endian,
                    privilege: wp,
                },
                value: byte,
                condition: active.clone(),
            });
        }
    } else {
        let value = r.bind(Expr::select(
            active.clone(),
            Expr::load(Memory {
                kind: Default::default(), address: Box::new(source),
                width: 8,
                endian,
                privilege: rp,
            }),
            c(8, 0),
        ));
        r.effects.push(Effect::StoreConditional {
            memory: Memory {
                kind: Default::default(), address: Box::new(target.clone()),
                width: 8,
                endian,
                privilege: wp,
            },
            value,
            condition: active.clone(),
        });
    }
    let nextcount = Expr::select(active.clone(), b(B::Sub, count.clone(), c(64, step)), count);
    let nextdst = Expr::select(
        backwards.clone(),
        target,
        b(B::Add, dst.clone(), c(64, step)),
    );
    write(&mut r, d, Expr::select(active.clone(), nextdst, dst));
    if !set {
        let nextsrc = Expr::select(
            backwards,
            b(B::Sub, read(s), c(64, step)),
            b(B::Add, read(s), c(64, step)),
        );
        write(&mut r, s, Expr::select(active.clone(), nextsrc, read(s)));
    }
    write(&mut r, n, nextcount.clone());
    r.flow = ControlFlow {
        kind: FlowKind::Branch,
        condition: nz(nextcount),
        target: c(64, pc),
        fallthrough: c(64, pc.wrapping_add(4)),
    };
    Some(r)
}

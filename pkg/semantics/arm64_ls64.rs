//! FEAT_LS64, LS64_V and LS64_ACCDATA. One typed 64-byte event preserves
//! accelerator status and indivisibility; memory type, alignment, translation
//! and tag policy are resolved by the target's evaluate_block64 capability.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn bin(op: B, a: Expr, b: Expr) -> Expr {
    Expr::binary(op, a, b)
}
fn reg(n: u32) -> RegisterSlice {
    register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    )
}
fn read(n: u32) -> Expr {
    Expr::register(reg(n))
}
fn state(bank: &'static str, index: u16, width: u8) -> Expr {
    Expr::register(register(bank, index, width, width))
}
fn result(step: usize, projection: AtomicProjection) -> Expr {
    Expr {
        ty: Type {
            width: 64,
            signedness: Signedness::Unsigned,
        },
        kind: ExprKind::AtomicResult { step, projection },
    }
}
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    let fixed = word & 0xffe0fc00;
    let (load, status, accdata) = match fixed {
        0xf820d000 if (word >> 16) & 31 == 31 => (true, false, false),
        0xf8209000 if (word >> 16) & 31 == 31 => (false, false, false),
        0xf820b000 => (false, true, false),
        0xf820a000 => (false, true, true),
        _ => return None,
    };
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    let t = word & 31;
    let n = (word >> 5) & 31;
    let s = (word >> 16) & 31;
    if t >= 24 || t & 1 != 0 {
        r.preflight_traps
            .push((TrapKind::InvalidInstruction, c(1, 1)));
        return Some(r);
    }
    let control = if accdata {
        2
    } else if status {
        1
    } else {
        0
    };
    r.preflight_traps.push((
        TrapKind::Protection,
        Expr::unary(UnaryOp::Not, state("a64.ls64_enabled", control, 1)),
    ));
    if n == 31 {
        r.preflight_traps.push((
            TrapKind::Protection,
            bin(
                B::And,
                state("a64.sp_alignment_enforced", 0, 1),
                Expr::unary(
                    UnaryOp::Not,
                    bin(B::Eq, bin(B::And, read(n), c(64, 15)), c(64, 0)),
                ),
            ),
        ));
    }
    let step = r.atomics.len();
    let kind = if load {
        Block64Kind::Load
    } else {
        let chunks = std::array::from_fn(|i| {
            let mut value = read(t + i as u32);
            if accdata && i == 0 {
                value = bin(
                    B::Or,
                    bin(B::And, value, c(64, 0xffff_ffff_0000_0000)),
                    Expr::cast(state("a64.accdata_el1", 0, 32), 64, false),
                );
            }
            if endian == Endian::Big {
                Expr::unary(UnaryOp::ReverseBytes, value)
            } else {
                value
            }
        });
        Block64Kind::Store {
            chunks,
            with_status: status,
        }
    };
    r.atomics.push(AtomicStep::Block64(Block64Operation {
        address: read(n),
        tagchecked: n != 31,
        kind,
    }));
    if load {
        for i in 0..8 {
            let value = result(step, AtomicProjection::BlockChunk(i));
            let value = if endian == Endian::Big {
                Expr::unary(UnaryOp::ReverseBytes, value)
            } else {
                value
            };
            r.write(reg(t + u32::from(i)), WritePolicy::ZeroUpper, value);
        }
    } else if status && s != 31 {
        r.write(
            reg(s),
            WritePolicy::ZeroUpper,
            result(step, AtomicProjection::Value),
        );
    }
    Some(r)
}

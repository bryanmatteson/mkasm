//! FEAT_THE RCW/RCWS scalar and D128 pair families, June2026 primary.
use super::*;
use AtomicRcwOp as O;
use BinaryOp as B;
const FORMS: &[(u32, O, bool, bool)] = &[
    (0x19200800, O::CompareExchange, false, false),
    (0x19200c00, O::CompareExchange, false, true),
    (0x38209000, O::Clear, false, false),
    (0x19209000, O::Clear, false, true),
    (0x59200800, O::CompareExchange, true, false),
    (0x59200c00, O::CompareExchange, true, true),
    (0x78209000, O::Clear, true, false),
    (0x59209000, O::Clear, true, true),
    (0x3820b000, O::Set, false, false),
    (0x1920b000, O::Set, false, true),
    (0x7820b000, O::Set, true, false),
    (0x5920b000, O::Set, true, true),
    (0x7820a000, O::Exchange, true, false),
    (0x5920a000, O::Exchange, true, true),
    (0x3820a000, O::Exchange, false, false),
    (0x1920a000, O::Exchange, false, true),
];
pub fn recognizes(word: u32) -> Option<bool> {
    FORMS.iter().find(|x| word & 0xff20fc00 == x.0).map(|x| x.3)
}
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn bin(op: B, a: Expr, b: Expr) -> Expr {
    Expr::binary(op, a, b)
}
fn inv(v: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, v)
}
fn bit(v: Expr, i: u8) -> Expr {
    Expr::extract(v, i, 1)
}
fn read(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
fn state(bank: &'static str) -> Expr {
    Expr::register(register(bank, 0, 1, 1))
}
fn pair(a: Expr, b: Expr, endian: Endian) -> [Expr; 2] {
    if endian == Endian::Little {
        [a, b]
    } else {
        [b, a]
    }
}
fn neq(a: Expr, b: Expr) -> Expr {
    inv(bin(B::Eq, a, b))
}
fn changed(old: &[Expr; 2], new: &[Expr; 2], mask: &[Expr; 2]) -> Expr {
    let chunks = std::array::from_fn::<_, 2, _>(|i| {
        bin(
            B::And,
            bin(B::Xor, old[i].clone(), new[i].clone()),
            inv(mask[i].clone()),
        )
    });
    neq(bin(B::Or, chunks[0].clone(), chunks[1].clone()), c(64, 0))
}
fn candidate(op: O, old: &[Expr; 2], operand: &[Expr; 2]) -> [Expr; 2] {
    std::array::from_fn(|i| match op {
        O::Clear => bin(B::And, old[i].clone(), inv(operand[i].clone())),
        O::Set => bin(B::Or, old[i].clone(), operand[i].clone()),
        _ => operand[i].clone(),
    })
}
/// NZCV expressions use the same effective mask contract as the atomic event.
fn flags(
    op: O,
    soft: bool,
    width: u8,
    old: &[Expr; 2],
    expected: &[Expr; 2],
    operand: &[Expr; 2],
    mask: &[Expr; 2],
    soft_mask: &[Expr; 2],
    protection: Expr,
) -> [Expr; 4] {
    let new = candidate(op, old, operand);
    let (chunk, pbit) = if width == 128 { (1, 50) } else { (0, 52) };
    let protected = bit(old[chunk].clone(), pbit);
    let valid = bit(old[0].clone(), 0);
    let state_fail = bin(
        B::Or,
        neq(bit(new[chunk].clone(), pbit), protected.clone()),
        bin(
            B::And,
            protected.clone(),
            neq(bit(new[0].clone(), 0), valid.clone()),
        ),
    );
    let hard = bin(
        B::And,
        protection.clone(),
        bin(
            B::Or,
            state_fail,
            bin(
                B::And,
                bin(B::And, protected.clone(), valid.clone()),
                changed(old, &new, mask),
            ),
        ),
    );
    let soft_fail = if soft {
        bin(
            B::Or,
            bin(
                B::And,
                bin(
                    B::Or,
                    valid.clone(),
                    inv(bin(B::And, protection, protected)),
                ),
                neq(bit(new[0].clone(), 0), valid.clone()),
            ),
            bin(B::And, valid, changed(old, &new, soft_mask)),
        )
    } else {
        c(1, 0)
    };
    let cmpfail = if op == O::CompareExchange {
        bin(
            B::Or,
            neq(old[0].clone(), expected[0].clone()),
            neq(old[1].clone(), expected[1].clone()),
        )
    } else {
        c(1, 0)
    };
    [
        cmpfail.clone(),
        bin(B::And, inv(cmpfail.clone()), hard),
        bin(B::Or, cmpfail, inv(soft_fail)),
        c(1, 0),
    ]
}
fn effective_mask(bank: &'static str, width: u8, soft: bool, protection: Expr) -> [Expr; 2] {
    let raw = |i| Expr::register(register(bank, i, 64, 64));
    if width == 64 {
        let keep = !(0xffff_ffffu64 << 18) & !1;
        let low = bin(
            B::Or,
            bin(B::And, raw(0), c(64, keep)),
            bin(
                B::Mul,
                Expr::cast(bit(raw(0), 17), 64, false),
                c(64, 0xffff_ffffu64 << 18),
            ),
        );
        [
            if soft {
                bin(
                    B::And,
                    low,
                    inv(bin(B::Shl, Expr::cast(protection, 64, false), c(64, 52))),
                )
            } else {
                low
            },
            c(64, 0),
        ]
    } else {
        let lowkeep = !((u64::MAX >> 25) << 17) & !3 & !(0xffu64 << 56);
        let low = bin(
            B::Or,
            bin(B::And, raw(0), c(64, lowkeep)),
            bin(
                B::Mul,
                Expr::cast(bit(raw(0), 16), 64, false),
                c(64, (u64::MAX >> 25) << 17),
            ),
        );
        let mut highkeep = u64::MAX;
        for (lo, hi) in [(0, 26), (37, 43), (55, 56), (61, 62)] {
            highkeep &= !(((1u64 << (hi - lo + 1)) - 1) << lo);
        }
        if soft {
            highkeep &= !(1u64 << 50);
        }
        [low, bin(B::And, raw(1), c(64, highkeep))]
    }
}
pub fn a64(word: u32, pc: u64, endian: Endian) -> Option<Recipe> {
    let &(_, op, soft, is_pair) = FORMS.iter().find(|x| word & 0xff20fc00 == x.0)?;
    let (s, t, n) = ((word >> 16) & 31, word & 31, (word >> 5) & 31);
    let width = if is_pair { 128 } else { 64 };
    let cas = op == O::CompareExchange;
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    if is_pair && ((cas && (s & 1 != 0 || t & 1 != 0)) || (!cas && (s == 31 || t == 31))) {
        r.preflight_traps
            .push((TrapKind::InvalidInstruction, c(1, 1)));
        return Some(r);
    }
    if is_pair && !cas && s == t {
        return Some(r);
    } // permitted LSE128OVERLAP NOP, before context/memory
    let d128 = state("a64.d128_enabled");
    r.preflight_traps.push((
        TrapKind::InvalidInstruction,
        if is_pair { inv(d128) } else { d128 },
    ));
    let base = if n == 31 {
        Expr::register(register("a64.sp", 0, 64, 64))
    } else {
        read(n)
    };
    if n == 31 {
        r.preflight_traps.push((
            TrapKind::Protection,
            bin(
                B::And,
                state("a64.sp_alignment_enforced"),
                neq(bin(B::And, base.clone(), c(64, 15)), c(64, 0)),
            ),
        ));
    }
    let protection = state("a64.protection_enabled");
    let mask = effective_mask("a64.rcwmask64", width, false, protection.clone());
    let soft_mask = if soft {
        effective_mask("a64.rcwsmask64", width, true, protection.clone())
    } else {
        [c(64, 0), c(64, 0)]
    };
    let expected = if cas {
        if is_pair {
            pair(read(s), read(s + 1), endian)
        } else {
            [read(s), c(64, 0)]
        }
    } else {
        [c(64, 0), c(64, 0)]
    };
    let operand = if is_pair {
        if cas {
            pair(read(t), read(t + 1), endian)
        } else {
            pair(read(t), read(s), endian)
        }
    } else {
        [read(if cas { t } else { s }), c(64, 0)]
    };
    let acquire = word & (1 << 23) != 0 && (is_pair || if cas { s != 31 } else { t != 31 });
    let release = word & (1 << 22) != 0;
    let ordering = match (acquire, release) {
        (false, false) => MemoryOrdering::Monotonic,
        (true, false) => MemoryOrdering::Acquire,
        (false, true) => MemoryOrdering::Release,
        _ => MemoryOrdering::AcquireRelease,
    };
    let result = r.atomic(AtomicOperation {
        memory: Memory {
            kind: Default::default(), privilege: MemoryPrivilege::Current,
            address: Box::new(base),
            width,
            endian,
        },
        ordering,
        scope: MemoryScope::System,
        kind: AtomicOperationKind::RestrictedReadModifyWrite {
            operation: op,
            soft,
            expected: expected.clone(),
            operand: operand.clone(),
            mask: mask.clone(),
            soft_mask: soft_mask.clone(),
            protection: protection.clone(),
        },
    });
    let old = [
        result.value.unwrap(),
        result.value_high.unwrap_or_else(|| c(64, 0)),
    ];
    let nzcv = flags(
        op, soft, width, &old, &expected, &operand, &mask, &soft_mask, protection,
    );
    for (i, value) in nzcv.into_iter().enumerate() {
        r.write(
            register("a64.nzcv", i as u16, 1, 1),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    let outputs = if is_pair {
        pair(old[0].clone(), old[1].clone(), endian)
    } else {
        old
    };
    let dest = if cas { s } else { t };
    if dest != 31 {
        r.write(
            register("a64.gpr", dest as u16, 64, 64),
            WritePolicy::ZeroUpper,
            outputs[0].clone(),
        );
    }
    if is_pair {
        let dest = if cas { s + 1 } else { s };
        if dest != 31 {
            r.write(
                register("a64.gpr", dest as u16, 64, 64),
                WritePolicy::ZeroUpper,
                outputs[1].clone(),
            );
        }
    }
    Some(r)
}

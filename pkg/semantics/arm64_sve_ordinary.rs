//! Ordinary contiguous SVE, whole-register spills and quadword gather/scatter.
//! Memory effects retain original access widths, byte order and lane order.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn reg(bank: &'static str, index: u16) -> RegisterSlice {
    register(bank, index, 64, 64)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(reg("a64.vector64", n as u16 * 32 + chunk))
}
fn lane(n: u32, bit: u16, w: u8) -> Expr {
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
fn p(n: u32, bit: u16, w: u8) -> Expr {
    Expr::extract(
        Expr::register(reg("a64.predicate64", n as u16 * 4 + bit / 64)),
        (bit % 64) as u8,
        w,
    )
}
fn gp(n: u32, sp: bool) -> Expr {
    if n == 31 && !sp {
        c(64, 0)
    } else {
        Expr::register(reg(
            if n == 31 { "a64.sp" } else { "a64.gpr" },
            if n == 31 { 0 } else { n as u16 },
        ))
    }
}
fn capture(r: &mut Recipe, value: Expr) -> Expr {
    r.bind_before_reads(value)
        .expect("pure ordinary memory pre-read capture")
}
fn aligned(base: Expr, size: u64) -> Expr {
    b(B::Eq, b(B::And, base, c(64, size - 1)), c(64, 0))
}
fn alignment_fault(r: &mut Recipe, base: Expr, n: u32, any: Expr, spill: Option<u64>) -> Expr {
    // Effective target policy inputs are demanded only by a misaligned use.
    // Empty predicates choose CHECKSPNONEACTIVE=false, as permitted by the ISA.
    let sp = if n == 31 {
        Expr::select(
            any,
            Expr::select(
                aligned(base.clone(), 16),
                c(1, 0),
                Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
            ),
            c(1, 0),
        )
    } else {
        c(1, 0)
    };
    let access = if let Some(size) = spill {
        Expr::select(
            aligned(base, size),
            c(1, 0),
            Expr::register(register("a64.alignment_enforced", 0, 1, 1)),
        )
    } else {
        c(1, 0)
    };
    let fault = capture(r, b(B::Or, sp, access));
    r.effects.push(Effect::Trap {
        kind: TrapKind::Protection,
        condition: fault.clone(),
    });
    not(fault)
}
fn write_chunks(r: &mut Recipe, n: u32, values: Vec<Expr>, predicate: bool) {
    let bank = if predicate {
        "a64.predicate64"
    } else {
        "a64.vector64"
    };
    let count = if predicate { 4 } else { 32 };
    for chunk in 0..count {
        let value = values.get(chunk).cloned().unwrap_or_else(|| c(64, 0));
        let value = r.bind(value);
        r.write(
            reg(bank, n as u16 * count as u16 + chunk as u16),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
pub fn a64(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    let spill = match word & 0xffc0e010 {
        0x85800000 => Some((true, true)),
        0xe5800000 => Some((false, true)),
        _ => match word & 0xffc0e000 {
            0x85804000 => Some((true, false)),
            0xe5804000 => Some((false, false)),
            _ => None,
        },
    };
    let quad = match word & 0xffe0e000 {
        0xc400a000 => Some(true),
        0xe4202000 => Some(false),
        _ => None,
    };
    let shape = arm64_sve::memory_shape(word);
    if spill.is_none() && quad.is_none() && shape.is_none() {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid SVE CurrentVL",
            address.wrapping_add(4),
            64,
        ));
    }
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let g = (word >> 10) & 7;
    if let Some((load, predicate)) = spill {
        let d = if predicate { d & 15 } else { d };
        let bytes = if predicate { vl / 64 } else { vl / 8 };
        let base = capture(&mut r, gp(n, true));
        let allowed = alignment_fault(
            &mut r,
            base.clone(),
            n,
            c(1, 1),
            Some(if predicate { 2 } else { 16 }),
        );
        let imm = ((((word >> 16) & 63) << 3) | ((word >> 10) & 7)) as i64;
        let imm = if imm & 256 != 0 { imm - 512 } else { imm };
        let start = b(B::Add, base, c(64, (imm * i64::from(bytes)) as u64));
        let mut values = vec![c(64, 0); usize::from(bytes.div_ceil(8))];
        for e in 0..bytes {
            let memory = Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(b(B::Add, start.clone(), c(64, u64::from(e)))),
                width: 8,
                endian,
            };
            if load {
                let value = r
                    .load_ordered_conditional(allowed.clone(), memory)
                    .expect("byte spill");
                values[usize::from(e / 8)] = b(
                    B::Or,
                    values[usize::from(e / 8)].clone(),
                    b(
                        B::Shl,
                        Expr::cast(Expr::select(allowed.clone(), value, c(8, 0)), 64, false),
                        c(64, u64::from(e % 8) * 8),
                    ),
                );
            } else {
                let value = if predicate {
                    p(d, e * 8, 8)
                } else {
                    lane(d, e * 8, 8)
                };
                r.store_conditional(allowed.clone(), memory, value);
            }
        }
        if load {
            write_chunks(&mut r, d, values, predicate);
        }
        return Some(r);
    }
    let (load, mw, ew, offset, signed) = if let Some(load) = quad {
        (load, 128, 128, true, false)
    } else {
        shape.unwrap()
    };
    if ew == 128 {
        r.guard = Expr::require_context(
            Expr::select(
                Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
            "128-bit SVE ordinary transfers require non-streaming mode or effective FA64",
        );
    }
    if quad.is_none() && offset && m == 31 {
        return Some(Recipe::unsupported(
            "reserved contiguous SVE Rm=31",
            address.wrapping_add(4),
            64,
        ));
    }
    let count = vl / u16::from(ew);
    let active = (0..count)
        .map(|e| capture(&mut r, p(g, e * u16::from(ew / 8), 1)))
        .collect::<Vec<_>>();
    let any = capture(
        &mut r,
        active.iter().cloned().fold(c(1, 0), |a, z| b(B::Or, a, z)),
    );
    let base = if quad.is_none() {
        capture(&mut r, Expr::select(any.clone(), gp(n, true), c(64, 0)))
    } else {
        c(64, 0)
    };
    let allowed = if quad.is_none() {
        alignment_fault(&mut r, base.clone(), n, any.clone(), None)
    } else {
        c(1, 1)
    };
    let access = capture(&mut r, b(B::And, any, allowed.clone()));
    let delta = if offset {
        b(
            B::Mul,
            gp(m, false),
            c(64, if quad.is_some() { 1 } else { u64::from(mw / 8) }),
        )
    } else {
        let imm = (((word >> 16) & 15) as i8) << 4 >> 4;
        c(
            64,
            (i64::from(imm) * i64::from(count) * i64::from(mw / 8)) as u64,
        )
    };
    let delta = capture(&mut r, Expr::select(access, delta, c(64, 0)));
    let start = capture(&mut r, b(B::Add, base, delta.clone()));
    let mut values = vec![c(64, 0); usize::from(vl / 64)];
    for e in 0..count {
        let condition = capture(
            &mut r,
            b(B::And, active[usize::from(e)].clone(), allowed.clone()),
        );
        let addr = if quad.is_some() {
            b(B::Add, lane(n, e * 128, 64), delta.clone())
        } else {
            b(
                B::Add,
                start.clone(),
                c(64, u64::from(e) * u64::from(mw / 8)),
            )
        };
        let chunks = if mw == 128 {
            let memory = WideMemory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(addr),
                width: 128,
                endian,
            };
            if load {
                r.load_wide_conditional(condition.clone(), memory)
            } else {
                r.store_wide_conditional(
                    condition.clone(),
                    memory,
                    vec![lane(d, e * 128, 64), lane(d, e * 128 + 64, 64)],
                );
                vec![]
            }
        } else {
            let memory = Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(addr),
                width: mw,
                endian,
            };
            if load {
                let v = r
                    .load_ordered_conditional(condition.clone(), memory)
                    .expect("ordinary scalar width");
                vec![Expr::cast(v, ew.min(64), signed)]
            } else {
                r.store_conditional(condition.clone(), memory, lane(d, e * u16::from(ew), mw));
                vec![]
            }
        };
        if load {
            for (part, value) in chunks.into_iter().enumerate() {
                let bit = e * u16::from(ew) + part as u16 * 64;
                let value = Expr::cast(
                    Expr::select(condition.clone(), value, c(ew.min(64), 0)),
                    64,
                    false,
                );
                values[usize::from(bit / 64)] = b(
                    B::Or,
                    values[usize::from(bit / 64)].clone(),
                    b(B::Shl, value, c(64, u64::from(bit % 64))),
                );
            }
        }
    }
    if load {
        write_chunks(&mut r, d, values, false);
    }
    Some(r)
}

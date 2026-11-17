// Pointer arithmetic and PAuth/PAuth_LR from Arm A-profile June2026 ASL.
// Feature legality, privilege/exception routing, BTI/GCS/FPAC and enhanced
// pointer-authentication configurations belong to consumer admission. Ordinary
// memory faults retain Recipe's consumer-owned contract. Effective PAC feature,
// key enable and PACM controls are separate guest inputs; missing context rejects
// execution and disabled controls suppress their reads. The typed PAC backend
// owns explicit policy, keys, VA/TBI and supported cipher configuration.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn context(bank: &'static str, width: u8) -> Expr {
    Expr::register(register(bank, 0, width, width))
}
fn gp(n: u32, sp: bool) -> Expr {
    if n == 31 {
        if sp {
            context("a64.sp", 64)
        } else {
            c(64, 0)
        }
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
fn put(r: &mut Recipe, d: u32, sp: bool, value: Expr) {
    if d == 31 {
        if sp {
            r.write(register("a64.sp", 0, 64, 64), WritePolicy::ZeroUpper, value);
        }
    } else {
        r.write(
            register("a64.gpr", d as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn check(result: Expr, base: Expr, overflow: Option<Expr>) -> Expr {
    let detected = b(
        B::Or,
        b(
            B::Xor,
            Expr::extract(base.clone(), 55, 1),
            Expr::extract(base.clone(), 54, 1),
        ),
        Expr::unary(
            UnaryOp::Not,
            b(
                B::Eq,
                Expr::extract(result.clone(), 56, 8),
                Expr::extract(base.clone(), 56, 8),
            ),
        ),
    );
    let add = Expr::select(context("a64.cpta", 1), detected, c(1, 0));
    let detected = if let Some(over) = overflow {
        b(
            B::Or,
            add,
            Expr::select(context("a64.cptm", 1), over, c(1, 0)),
        )
    } else {
        add
    };
    let marked = b(
        B::Or,
        b(
            B::Or,
            b(B::And, base.clone(), c(64, 0xff80000000000000)),
            b(
                B::Shl,
                Expr::cast(
                    Expr::unary(UnaryOp::Not, Expr::extract(base, 55, 1)),
                    64,
                    false,
                ),
                c(64, 54),
            ),
        ),
        b(B::And, result.clone(), c(64, (1u64 << 54) - 1)),
    );
    Expr::select(detected, marked, result)
}
fn first(r: &mut Recipe, start: Expr, included: Expr) -> Expr {
    let rotated = r.bind(b(B::Ror, included, Expr::cast(start.clone(), 16, false)));
    let lowest = r.bind(b(
        B::And,
        rotated.clone(),
        Expr::unary(UnaryOp::Neg, rotated),
    ));
    let zeros = Expr::unary(UnaryOp::PopulationCount, b(B::Sub, lowest, c(16, 1)));
    Expr::cast(b(B::Add, Expr::cast(start, 16, false), zeros), 4, false)
}
/// Default little-endian entrypoint; authenticated loads should use the
/// caller's explicit data order through a64_with_endian.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    a64_with_endian(word, address, Endian::Little)
}
pub fn a64_with_endian(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    if let Some(recipe) = authentication(word, address, endian) {
        return Some(recipe);
    }
    arithmetic(word, address)
}
// IRG's deterministic paths follow the architectural RGSR LFSR/EIRG
// algorithms. RRND selects a bin with a full-width multiply-high entropy
// sample; the provider owns replay and the implementation leaves RGSR intact.
fn irg(r: &mut Recipe, d: u32, n: u32, m: u32) {
    let enabled = context("a64.mte_enabled", 1);
    let rrnd = Expr::select(enabled.clone(), context("a64.tag_rrnd", 1), c(1, 0));
    let eirg = Expr::select(enabled.clone(), context("a64.tag_eirg", 1), c(1, 0));
    let included = Expr::select(
        enabled.clone(),
        Expr::unary(
            UnaryOp::Not,
            b(
                B::Or,
                Expr::extract(gp(m, false), 0, 16),
                context("a64.tag_exclude", 16),
            ),
        ),
        c(16, 0),
    );
    let any = Expr::unary(UnaryOp::Not, b(B::Eq, included.clone(), c(16, 0)));
    // Choice guards precede all bindings and therefore contain incoming state
    // expressions only. Neither disabled MTE nor an empty set consumes entropy.
    let random = r.choose(64, Some(b(B::And, rrnd.clone(), any.clone())));
    let enabled = r.bind(enabled);
    let rrnd = r.bind(rrnd);
    let eirg = r.bind(eirg);
    let included = r.bind(included);
    let any = r.bind(any);
    let deterministic = r.bind(b(
        B::And,
        b(
            B::And,
            enabled.clone(),
            Expr::unary(UnaryOp::Not, rrnd.clone()),
        ),
        Expr::select(eirg.clone(), any.clone(), c(1, 1)),
    ));
    let seed = r.bind(Expr::select(
        deterministic.clone(),
        context("a64.tag_seed", 16),
        c(16, 0),
    ));
    let incoming = r.bind(Expr::select(
        deterministic.clone(),
        context("a64.tag_state", 4),
        c(4, 0),
    ));
    let mut next_seed = seed.clone();
    let mut offset = c(4, 0);
    for i in 0..4 {
        let top = r.bind(b(
            B::Xor,
            b(
                B::Xor,
                Expr::extract(next_seed.clone(), 5, 1),
                Expr::extract(next_seed.clone(), 3, 1),
            ),
            b(
                B::Xor,
                Expr::extract(next_seed.clone(), 2, 1),
                Expr::extract(next_seed.clone(), 0, 1),
            ),
        ));
        next_seed = r.bind(b(
            B::Or,
            b(B::Lsr, next_seed, c(16, 1)),
            b(B::Shl, Expr::cast(top.clone(), 16, false), c(16, 15)),
        ));
        offset = r.bind(b(
            B::Or,
            offset,
            b(B::Shl, Expr::cast(top, 4, false), c(4, i)),
        ));
    }
    let initial = first(r, incoming.clone(), included.clone());
    let mut normal_tag = r.bind(initial);
    // For a nonzero offset, the first step starts at incoming+1 even when the
    // incoming tag itself is excluded. Subsequent steps start after the last bin.
    for i in 0..15 {
        let start = if i == 0 {
            incoming.clone()
        } else {
            normal_tag.clone()
        };
        let next = first(r, b(B::Add, start, c(4, 1)), included.clone());
        normal_tag = r.bind(Expr::select(
            b(B::Ult, c(4, i), offset.clone()),
            next,
            normal_tag,
        ));
    }
    let normal_tag = r.bind(Expr::select(any.clone(), normal_tag, c(4, 0)));
    let count = r.bind(Expr::unary(UnaryOp::PopulationCount, included.clone()));
    let next_state = r.bind(b(B::Add, Expr::cast(incoming, 16, false), c(16, 1)));
    let next_state = r.bind(Expr::select(
        b(B::Ult, next_state.clone(), count.clone()),
        next_state,
        c(16, 0),
    ));
    // ASL shifts bind more tightly than addition: state + ((N*seed)>>16).
    let scaled = r.bind(Expr::cast(
        b(
            B::Lsr,
            b(
                B::Mul,
                Expr::cast(count.clone(), 32, false),
                Expr::cast(seed.clone(), 32, false),
            ),
            c(32, 16),
        ),
        16,
        false,
    ));
    let rank = r.bind(b(B::Add, next_state.clone(), scaled));
    let rank = r.bind(Expr::select(
        b(B::Ult, rank.clone(), count.clone()),
        rank.clone(),
        b(B::Sub, rank, count.clone()),
    ));
    let random_rank = Expr::cast(
        b(
            B::UnsignedMultiplyHigh,
            random,
            Expr::cast(count.clone(), 64, false),
        ),
        16,
        false,
    );
    let rank = r.bind(Expr::select(
        rrnd.clone(),
        Expr::select(any.clone(), random_rank, c(16, 0)),
        rank,
    ));
    let mut seen = c(16, 0);
    let mut selected = c(4, 0);
    for i in 0..16 {
        let present = Expr::extract(included.clone(), i, 1);
        selected = r.bind(Expr::select(
            b(
                B::And,
                present.clone(),
                b(B::Eq, seen.clone(), rank.clone()),
            ),
            c(4, i as u64),
            selected,
        ));
        seen = r.bind(b(B::Add, seen, Expr::cast(present, 16, false)));
    }
    let chosen = r.bind(Expr::select(
        rrnd.clone(),
        selected.clone(),
        Expr::select(eirg.clone(), selected, normal_tag.clone()),
    ));
    let chosen = r.bind(Expr::select(
        b(B::And, enabled, any.clone()),
        chosen,
        c(4, 0),
    ));
    let advance = r.bind(b(
        B::And,
        deterministic,
        Expr::select(eirg.clone(), any, c(1, 1)),
    ));
    let top = b(
        B::Xor,
        b(
            B::Xor,
            Expr::extract(seed.clone(), 5, 1),
            Expr::extract(seed.clone(), 3, 1),
        ),
        b(
            B::Xor,
            Expr::extract(seed.clone(), 2, 1),
            Expr::extract(seed.clone(), 0, 1),
        ),
    );
    let eirg_seed = b(
        B::Or,
        b(B::Lsr, seed, c(16, 1)),
        b(B::Shl, Expr::cast(top, 16, false), c(16, 15)),
    );
    r.write_conditional(
        advance.clone(),
        register("a64.tag_seed", 0, 16, 16),
        WritePolicy::ZeroUpper,
        Expr::select(eirg.clone(), eirg_seed, next_seed),
    );
    r.write_conditional(
        advance,
        register("a64.tag_state", 0, 4, 4),
        WritePolicy::ZeroUpper,
        Expr::select(eirg, Expr::cast(next_state, 4, false), normal_tag),
    );
    let result = b(
        B::Or,
        b(B::And, gp(n, true), c(64, !(15u64 << 56))),
        b(B::Shl, Expr::cast(chosen, 64, false), c(64, 56)),
    );
    put(r, d, true, result);
}

fn arithmetic(word: u32, address: u64) -> Option<Recipe> {
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if word & 0xffe0fc00 == 0x9ac01000 {
        irg(&mut r, d, n, m);
        return Some(r);
    }
    if matches!(word & 0xffe0e000, 0x9a002000 | 0xda002000) {
        let base = r.bind(gp(n, true));
        let offset = r.bind(b(B::Shl, gp(m, false), c(64, u64::from((word >> 10) & 7))));
        let result = r.bind(b(
            if word & (1 << 30) == 0 {
                B::Add
            } else {
                B::Sub
            },
            base.clone(),
            offset,
        ));
        put(&mut r, d, true, check(result, base, None));
        return Some(r);
    }
    if matches!(word & 0xffe08000, 0x9b600000 | 0x9b608000) {
        let a = r.bind(gp(n, false));
        let z = r.bind(gp(m, false));
        let base = r.bind(gp((word >> 10) & 31, false));
        let product = r.bind(b(B::Mul, a.clone(), z.clone()));
        let high = r.bind(b(B::SignedMultiplyHigh, a, z));
        let over = Expr::unary(
            UnaryOp::Not,
            b(B::Eq, high, b(B::Asr, product.clone(), c(64, 63))),
        );
        let result = r.bind(b(
            if word & (1 << 15) == 0 {
                B::Add
            } else {
                B::Sub
            },
            base.clone(),
            product,
        ));
        put(&mut r, d, false, check(result, base, Some(over)));
        return Some(r);
    }
    if matches!(word & 0xffc0c000, 0x91800000 | 0xd1800000) {
        let base = r.bind(gp(n, true));
        let enabled = r.bind(context("a64.mte_enabled", 1));
        let included = r.bind(Expr::select(
            enabled.clone(),
            Expr::unary(UnaryOp::Not, context("a64.tag_exclude", 16)),
            c(16, 0),
        ));
        let mut tag = r.bind(Expr::extract(base.clone(), 56, 4));
        let offset = (word >> 10) & 15;
        for _ in 0..offset.max(1) {
            let start = if offset == 0 {
                tag
            } else {
                b(B::Add, tag, c(4, 1))
            };
            let next = first(&mut r, start, included.clone());
            tag = r.bind(next);
        }
        let tag = Expr::select(
            enabled,
            Expr::select(b(B::Eq, included, c(16, 0)), c(4, 0), tag),
            c(4, 0),
        );
        let address = b(
            if word & (1 << 30) == 0 {
                B::Add
            } else {
                B::Sub
            },
            base,
            c(64, u64::from((word >> 16) & 63) * 16),
        );
        let value = b(
            B::Or,
            b(B::And, address, c(64, !(15u64 << 56))),
            b(B::Shl, Expr::cast(tag, 64, false), c(64, 56)),
        );
        put(&mut r, d, true, value);
        return Some(r);
    }
    if matches!(word & 0xffe0fc00, 0x9ac00000 | 0xbac00000) {
        let a = r.bind(Expr::cast(Expr::extract(gp(n, true), 0, 56), 64, true));
        let z = r.bind(Expr::cast(Expr::extract(gp(m, true), 0, 56), 64, true));
        let result = r.bind(b(B::Sub, a.clone(), z.clone()));
        if word & (1 << 29) != 0 {
            let flags = [
                Expr::extract(result.clone(), 63, 1),
                b(B::Eq, result.clone(), c(64, 0)),
                Expr::unary(
                    UnaryOp::Not,
                    Expr::sub_borrow(a.clone(), z.clone(), c(1, 0)),
                ),
                Expr::overflow(true, a, z, result.clone()),
            ];
            for (i, v) in flags.into_iter().enumerate() {
                r.write(
                    register("a64.nzcv", i as u16, 1, 1),
                    WritePolicy::ZeroUpper,
                    v,
                );
            }
        }
        put(&mut r, d, false, result);
        return Some(r);
    }
    if word & 0xffe0fc00 == 0x9ac01400 {
        let tag = Expr::cast(Expr::extract(gp(n, true), 56, 4), 64, false);
        put(
            &mut r,
            d,
            false,
            b(B::Or, gp(m, false), b(B::Shl, c(64, 1), tag)),
        );
        return Some(r);
    }
    None
}

// Effective guest context, not host capability. Unknown control input must
// reject execution rather than silently choose a PAC mode or disable a key.
fn pac_context(bank: &'static str, index: u16) -> Expr {
    let value = Expr::register(register(bank, index, 1, 1));
    Expr::select(
        Expr::require_context(
            b(B::Eq, value.clone(), value.clone()),
            "A64 PAC effective context unavailable",
        ),
        value,
        c(1, 0),
    )
}
fn pac_start(address: u64, hint: bool, lr: bool) -> Recipe {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let present = pac_context(
        if lr {
            "a64.pauth_lr_present"
        } else {
            "a64.pauth_present"
        },
        0,
    );
    r.guard = if hint {
        present
    } else {
        Expr::require_context(present, "A64 pointer authentication feature unavailable")
    };
    r
}
fn pac_lr() -> Expr {
    Expr::select(
        pac_context("a64.pauth_lr_present", 0),
        pac_context("a64.pacm", 0),
        c(1, 0),
    )
}
fn pac_raw(
    op: PointerAuthOperation,
    key: PointerAuthKey,
    pointer: Expr,
    modifier: Option<Expr>,
    second: Option<Expr>,
) -> Expr {
    let mut inputs = vec![pointer];
    inputs.extend(modifier);
    inputs.extend(second);
    Expr::pointer_authentication(PointerAuthenticationExpression {
        operation: op,
        key,
        inputs,
    })
    .expect("static PAC dimensions")
}
fn pac_enabled(key: PointerAuthKey, pointer: Expr, value: Expr) -> Expr {
    let index = match key {
        PointerAuthKey::InstructionA => 0,
        PointerAuthKey::InstructionB => 1,
        PointerAuthKey::DataA => 2,
        PointerAuthKey::DataB => 3,
        _ => return value,
    };
    Expr::select(pac_context("a64.pac_key_enabled", index), value, pointer)
}
fn pac_value(
    op: PointerAuthOperation,
    key: PointerAuthKey,
    pointer: Expr,
    modifier: Option<Expr>,
    second: Option<Expr>,
) -> Expr {
    let value = pac_raw(op, key, pointer.clone(), modifier, second);
    pac_enabled(key, pointer, value)
}
fn pac_instruction(
    op: PointerAuthOperation,
    key: PointerAuthKey,
    pointer: Expr,
    modifier: Expr,
    second: Option<Expr>,
    conditional: bool,
) -> Expr {
    let value = if let Some(second) = second {
        let dual = pac_raw(
            op,
            key,
            pointer.clone(),
            Some(modifier.clone()),
            Some(second),
        );
        if conditional {
            Expr::select(
                pac_lr(),
                dual,
                pac_raw(op, key, pointer.clone(), Some(modifier), None),
            )
        } else {
            dual
        }
    } else {
        pac_raw(op, key, pointer.clone(), Some(modifier), None)
    };
    // Disabled keys return their input independently of PACM/modifier state.
    // Keep that selector outside the PAC/PAC2 choice so unneeded context and
    // register values remain unread, as do unavailable cryptographic keys.
    pac_enabled(key, pointer, value)
}
fn put_auth(r: &mut Recipe, d: u32, value: Expr) {
    let value = r.bind(value);
    put(r, d, false, value);
}
fn authentication(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    use PointerAuthKey as K;
    use PointerAuthOperation as O;
    // Base one-source register and zero-modifier forms. R31 is ZR in the
    // pointer operand, SP only in the ordinary modifier operand.
    if word & 0xffffc000 == 0xdac10000 {
        let opcode = (word >> 10) & 7;
        if opcode < 8 {
            let zero = word & (1 << 13) != 0;
            let n = (word >> 5) & 31;
            let d = word & 31;
            if zero && n != 31 {
                return None;
            }
            let op = if opcode < 4 { O::Sign } else { O::Authenticate };
            let key = [K::InstructionA, K::InstructionB, K::DataA, K::DataB][(opcode & 3) as usize];
            let modifier = if zero { c(64, 0) } else { gp(n, true) };
            let code = matches!(key, K::InstructionA | K::InstructionB);
            let second = if !zero && n == 31 && code {
                Some(if op == O::Sign {
                    c(64, address)
                } else {
                    gp(16, false)
                })
            } else {
                None
            };
            let mut r = pac_start(address, false, false);
            let value = pac_instruction(op, key, gp(d, false), modifier, second, true);
            put_auth(&mut r, d, value);
            return Some(r);
        }
    }
    if word & 0xfffffbe0 == 0xdac143e0 || word == 0xd50320ff {
        let hint = word == 0xd50320ff;
        let d = if hint { 30 } else { word & 31 };
        let op = if !hint && word & (1 << 10) != 0 {
            O::StripData
        } else {
            O::Strip
        };
        let mut r = pac_start(address, hint, false);
        put_auth(&mut r, d, pac_value(op, K::None, gp(d, false), None, None));
        return Some(r);
    }
    // HINT-space PAC/AUT: disabled feature is a true NOP, including no
    // modifier/context/key reads. SP forms may use PAC2 under PSTATE.PACM.
    let hint = match word {
        0xd503211f => Some((O::Sign, K::InstructionA, 17, Some(16))),
        0xd503215f => Some((O::Sign, K::InstructionB, 17, Some(16))),
        0xd503219f => Some((O::Authenticate, K::InstructionA, 17, Some(16))),
        0xd50321df => Some((O::Authenticate, K::InstructionB, 17, Some(16))),
        0xd503231f => Some((O::Sign, K::InstructionA, 30, None)),
        0xd503235f => Some((O::Sign, K::InstructionB, 30, None)),
        0xd503239f => Some((O::Authenticate, K::InstructionA, 30, None)),
        0xd50323df => Some((O::Authenticate, K::InstructionB, 30, None)),
        0xd503233f => Some((O::Sign, K::InstructionA, 30, Some(31))),
        0xd503237f => Some((O::Sign, K::InstructionB, 30, Some(31))),
        0xd50323bf => Some((O::Authenticate, K::InstructionA, 30, Some(31))),
        0xd50323ff => Some((O::Authenticate, K::InstructionB, 30, Some(31))),
        _ => None,
    };
    if let Some((op, key, d, n)) = hint {
        let modifier = n.map(|n| gp(n, true)).unwrap_or_else(|| c(64, 0));
        let second = n.map(|n| {
            if n == 16 {
                gp(15, false)
            } else if op == O::Sign {
                c(64, address)
            } else {
                gp(16, false)
            }
        });
        let mut r = pac_start(address, true, false);
        put_auth(
            &mut r,
            d,
            pac_instruction(op, key, gp(d, false), modifier, second, true),
        );
        return Some(r);
    }
    if word == 0xd50324ff {
        let mut r = pac_start(address, true, true);
        r.write(
            register("a64.pacm", 0, 1, 1),
            WritePolicy::ZeroUpper,
            pac_context("a64.pacm_enabled", 0),
        );
        return Some(r);
    }
    // FEAT_PAuth_LR fixed dual-modifier signing/authentication forms.
    let fixed = match word {
        0xdac1a3fe | 0xdac183fe => Some((O::Sign, K::InstructionA, 30)),
        0xdac1a7fe | 0xdac187fe => Some((O::Sign, K::InstructionB, 30)),
        0xdac18bfe => Some((O::Sign, K::InstructionA, 17)),
        0xdac18ffe => Some((O::Sign, K::InstructionB, 17)),
        0xdac1bbfe => Some((O::Authenticate, K::InstructionA, 17)),
        0xdac1bffe => Some((O::Authenticate, K::InstructionB, 17)),
        _ => None,
    };
    if let Some((op, key, d)) = fixed {
        let (modifier, second) = if d == 17 {
            (gp(16, false), gp(15, false))
        } else {
            (gp(31, true), c(64, address))
        };
        let mut r = pac_start(address, false, true);
        put_auth(
            &mut r,
            d,
            pac_instruction(op, key, gp(d, false), modifier, Some(second), false),
        );
        return Some(r);
    }
    if matches!(word & 0xfffffc1f, 0xdac1901e | 0xdac1941e)
        || matches!(word & 0xffe0001f, 0xf380001f | 0xf3a0001f)
    {
        let immediate = word & 0xffe0001f == 0xf380001f || word & 0xffe0001f == 0xf3a0001f;
        let key = if word & (if immediate { 1 << 21 } else { 1 << 10 }) == 0 {
            K::InstructionA
        } else {
            K::InstructionB
        };
        let second = if immediate {
            c(
                64,
                address.wrapping_sub(u64::from((word >> 5) & 0xffff) << 2),
            )
        } else {
            gp((word >> 5) & 31, false)
        };
        let mut r = pac_start(address, false, true);
        put_auth(
            &mut r,
            30,
            pac_instruction(
                O::Authenticate,
                key,
                gp(30, false),
                gp(31, true),
                Some(second),
                false,
            ),
        );
        return Some(r);
    }
    if word & 0xffe0fc00 == 0x9ac03000 {
        let mut r = pac_start(address, false, false);
        let value = pac_value(
            O::Generic,
            K::Generic,
            gp((word >> 5) & 31, false),
            Some(gp((word >> 16) & 31, true)),
            None,
        );
        put_auth(&mut r, word & 31, value);
        return Some(r);
    }
    // Authenticated branches/calls, base returns and the LR explicit-return
    // forms share the typed authentication primitive, never an opcode callback.
    if matches!(word & 0xfefff800, 0xd61f0800 | 0xd63f0800) {
        let register_modifier = word & (1 << 24) != 0;
        let m = word & 31;
        if !register_modifier && m != 31 {
            return None;
        }
        let key = if word & (1 << 10) == 0 {
            K::InstructionA
        } else {
            K::InstructionB
        };
        let modifier = if register_modifier {
            gp(m, true)
        } else {
            c(64, 0)
        };
        let target = pac_instruction(
            O::Authenticate,
            key,
            gp((word >> 5) & 31, false),
            modifier,
            None,
            false,
        );
        let mut r = pac_start(address, false, false);
        let call = word & (1 << 21) != 0;
        r.branch(
            if call {
                FlowKind::Call
            } else {
                FlowKind::Branch
            },
            c(1, 1),
            target,
        );
        if call {
            put(&mut r, 30, false, c(64, address.wrapping_add(4)));
        }
        return Some(r);
    }
    if matches!(word, 0xd65f0bff | 0xd65f0fff)
        || word & 0xfffffbe0 == 0xd65f0be0
        || word & 0xffc0001f == 0x5500001f
    {
        let immediate = word & 0xffc0001f == 0x5500001f;
        let base = matches!(word, 0xd65f0bff | 0xd65f0fff);
        let key = if word & (if immediate { 1 << 21 } else { 1 << 10 }) == 0 {
            K::InstructionA
        } else {
            K::InstructionB
        };
        let second = if base {
            gp(16, false)
        } else if immediate {
            c(
                64,
                address.wrapping_sub(u64::from((word >> 5) & 0xffff) << 2),
            )
        } else {
            gp(word & 31, false)
        };
        let mut r = pac_start(address, false, !base);
        let target = pac_instruction(
            O::Authenticate,
            key,
            gp(30, false),
            gp(31, true),
            Some(second),
            base,
        );
        r.branch(FlowKind::Return, c(1, 1), target);
        return Some(r);
    }
    if word & 0xff200400 == 0xf8200400 {
        let n = (word >> 5) & 31;
        let t = word & 31;
        let writeback = word & (1 << 11) != 0;
        if writeback && n == t && n != 31 {
            return Some(Recipe::unsupported(
                "A64 authenticated load writeback overlap",
                address.wrapping_add(4),
                64,
            ));
        }
        let key = if word & (1 << 23) == 0 {
            K::DataA
        } else {
            K::DataB
        };
        let mut r = pac_start(address, false, false);
        if n == 31 {
            r.guard = Expr::select(
                r.guard,
                Expr::require_context(
                    b(B::Eq, b(B::And, gp(31, true), c(64, 15)), c(64, 0)),
                    "A64 SP alignment controls",
                ),
                c(1, 0),
            );
        }
        let authenticated =
            pac_instruction(O::Authenticate, key, gp(n, true), c(64, 0), None, false);
        let imm = (((word >> 12) & 511) | ((word >> 22) & 1) << 9) as i64;
        let offset = ((imm << 54) >> 54).wrapping_mul(8) as u64;
        let effective = r.bind(b(B::Add, authenticated, c(64, offset)));
        let loaded = Expr::load(Memory {
            kind: Default::default(), privilege: Default::default(),
            address: Box::new(effective.clone()),
            width: 64,
            endian,
        });
        // Preserve the load even for Rt==ZR: it can fault and authenticates its
        // base before any writeback. Ordinary memory fault routing is consumer-owned.
        let loaded = r.bind(loaded);
        put(&mut r, t, false, loaded);
        if writeback {
            put(&mut r, n, true, effective);
        }
        return Some(r);
    }
    if matches!(word, 0xd69f0bff | 0xd69f0fff) {
        return Some(Recipe::unsupported(
            "A64 authenticated exception return context",
            address.wrapping_add(4),
            64,
        ));
    }
    None
}

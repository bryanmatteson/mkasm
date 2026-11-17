//! A64 instruction-fetch branch-target context. Guarded-page status is an
//! explicit input for the current fetch, not a guessed property of an address.
use super::*;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn input(bank: &'static str, width: u8) -> Expr {
    Expr::register(register(bank, 0, width, width))
}
fn eq(a: Expr, b: Expr) -> Expr {
    Expr::binary(BinaryOp::Eq, a, b)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
// Select is intentional: absent capability and bypassed checks do not read
// unavailable state, including PAC controls for ordinary instructions.
fn and(a: Expr, b: Expr) -> Expr {
    Expr::select(a, b, c(1, 0))
}
pub fn complete(word: u32, mut recipe: Recipe) -> Recipe {
    let enabled = input("a64.bti_enabled", 1);
    let btype = input("a64.btype", 2);
    let guarded = input("a64.bti_guarded_page", 1);
    let compatible = if word & 0xffffff3f == 0xd503241f {
        match (word >> 6) & 3 {
            0 => eq(btype.clone(), c(2, 0)),
            1 => not(eq(btype.clone(), c(2, 3))),
            2 => not(eq(btype.clone(), c(2, 2))),
            _ => c(1, 1),
        }
    } else if word & 0xffe0001f == 0xd4200000 || word & 0xffe0001f == 0xd4400000 {
        c(1, 1)
    } else if matches!(word, 0xd503233f | 0xd503237f | 0xdac1a3fe | 0xdac1a7fe) {
        let sp = matches!(word, 0xd503233f | 0xd503237f);
        let normal = Expr::select(
            eq(btype.clone(), c(2, 3)),
            not(input("a64.bti_pac_strict", 1)),
            c(1, 1),
        );
        let compatible = if sp {
            Expr::select(
                input("a64.bti_pac_disabled", 1),
                eq(btype.clone(), c(2, 0)),
                normal,
            )
        } else {
            normal
        };
        and(
            input(
                if sp {
                    "a64.pauth_present"
                } else {
                    "a64.pauth_lr_present"
                },
                1,
            ),
            compatible,
        )
    } else {
        c(1, 0)
    };
    let failure = and(
        enabled.clone(),
        and(
            not(input("a64.debug_halted", 1)),
            and(
                not(eq(btype, c(2, 0))),
                and(guarded.clone(), not(compatible)),
            ),
        ),
    );
    recipe
        .entry_traps
        .insert(0, (TrapKind::AArch64BranchTarget, failure));
    let branch = word & 0xfffffc1f == 0xd61f0000;
    let call = word & 0xfffffc1f == 0xd63f0000;
    let auth = matches!(word & 0xfefff800, 0xd61f0800 | 0xd63f0800);
    let next = if call || (auth && word & (1 << 21) != 0) {
        c(2, 2)
    } else if branch || auth {
        let n = (word >> 5) & 31;
        if n == 16 || n == 17 {
            c(2, 1)
        } else {
            Expr::select(guarded, c(2, 3), c(2, 1))
        }
    } else {
        c(2, 0)
    };
    recipe.completion_writes.push((
        RegisterUpdate {
            destination: register("a64.btype", 0, 2, 2),
            policy: WritePolicy::ZeroUpper,
            value: next,
        },
        enabled,
    ));
    recipe
}

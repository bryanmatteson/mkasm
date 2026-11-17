//! WFxT readiness is evaluated from incoming architectural state. A selected
//! environment boundary owns wakeup, TWED and EL3 undefined/trap priority.
use super::*;
fn bit(bank: &'static str) -> Expr {
    Expr::register(register(bank, 0, 1, 1))
}
pub fn a64(word: u32, pc: u64) -> Option<Recipe> {
    let fixed = word & !31;
    if !matches!(fixed, 0xd5031000 | 0xd5031020) {
        return None;
    }
    let interrupt = fixed == 0xd5031020;
    let rd = word & 31;
    let deadline = if rd == 31 {
        Expr::constant(64, 0)
    } else {
        Expr::register(register("a64.gpr", rd as u16, 64, 64))
    };
    let ready = if interrupt {
        bit("a64.interrupt_pending")
    } else {
        bit("a64.event_register")
    };
    let expired = Expr::unary(
        UnaryOp::Not,
        Expr::binary(
            BinaryOp::Ult,
            Expr::register(register("a64.virtual_counter", 0, 64, 64)),
            deadline.clone(),
        ),
    );
    let mut r = Recipe::new(pc.wrapping_add(4), 64);
    if !interrupt {
        r.write_conditional(
            bit("a64.event_register"),
            register("a64.event_register", 0, 1, 1),
            WritePolicy::ZeroUpper,
            Expr::constant(1, 0),
        );
    }
    let selected = Expr::select(
        ready,
        Expr::constant(1, 0),
        Expr::unary(UnaryOp::Not, expired),
    );
    let selected = r.bind(selected);
    r.effects.push(Effect::TimedWait {
        interrupt,
        source: rd as u8,
        deadline,
        condition: selected,
    });
    Some(r)
}

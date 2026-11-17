#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
struct State {
    enabled: bool,
    halted: bool,
    guarded: bool,
    btype: u64,
    strict: bool,
    disabled: bool,
    pac: bool,
    lr: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        let (w, v) = match r.bank {
            "a64.bti_enabled" => (1, self.enabled as u64),
            "a64.debug_halted" => (1, self.halted as u64),
            "a64.bti_guarded_page" => (1, self.guarded as u64),
            "a64.btype" => (2, self.btype),
            "a64.bti_pac_strict" => (1, self.strict as u64),
            "a64.bti_pac_disabled" => (1, self.disabled as u64),
            "a64.pauth_present" => (1, self.pac as u64),
            "a64.pauth_lr_present" => (1, self.lr as u64),
            _ => panic!("operand evaluated before entry check: {r:?}"),
        };
        Value::known(w, v)
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory evaluated before entry check")
    }
}
fn state() -> State {
    State {
        enabled: true,
        halted: false,
        guarded: true,
        btype: 0,
        strict: false,
        disabled: false,
        pac: true,
        lr: true,
    }
}
fn pipeline(word: u32) -> Recipe {
    arm64_bti::complete(word, Recipe::new(0x1004, 64))
}
fn next(t: &Transition) -> Option<u64> {
    t.registers
        .iter()
        .find(|w| w.register.bank == "a64.btype")
        .map(|w| {
            assert_eq!(w.value.width, 2);
            w.value.bits
        })
}
#[test]
fn every_landing_pad_incoming_type_fetch_and_halt_combination() {
    for code in 0..4 {
        for btype in 0..4 {
            for guarded in [false, true] {
                for halted in [false, true] {
                    let mut s = state();
                    s.btype = btype;
                    s.guarded = guarded;
                    s.halted = halted;
                    let compatible = match code {
                        0 => btype == 0,
                        1 => btype != 3,
                        2 => btype != 2,
                        _ => true,
                    };
                    let t = evaluate(&pipeline(0xd503241f | code << 6), &s).unwrap();
                    let fault = guarded && !halted && btype != 0 && !compatible;
                    assert_eq!(
                        t.trap,
                        if fault {
                            Some(TrapKind::AArch64BranchTarget)
                        } else {
                            None
                        }
                    );
                    assert_eq!(next(&t), if fault { None } else { Some(0) });
                }
            }
        }
    }
}
#[test]
fn ordinary_instructions_check_before_predication_operands_and_effects() {
    for active in [false, true] {
        let mut s = state();
        s.btype = 3;
        let mut r = Recipe::new(0x1004, 64);
        r.guard = if active {
            Expr::register(register("unavailable.guard", 0, 1, 1))
        } else {
            Expr::constant(1, 0)
        };
        r.write(
            register("unavailable.destination", 0, 64, 64),
            WritePolicy::ZeroUpper,
            Expr::register(register("unavailable.source", 0, 64, 64)),
        );
        let t = evaluate(&arm64_bti::complete(0x91000400, r), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::AArch64BranchTarget));
        assert!(t.registers.is_empty());
    }
    let mut r = Recipe::new(0x1004, 64);
    r.guard = Expr::constant(1, 0);
    let mut s = state();
    s.guarded = false;
    s.btype = 2;
    let t = evaluate(&arm64_bti::complete(0x91000400, r), &s).unwrap();
    assert_eq!(next(&t), Some(0));
}
#[test]
fn direct_indirect_call_return_and_authenticated_branch_types() {
    for guarded in [false, true] {
        for n in 0..31 {
            for (base, call) in [
                (0xd61f0000, false),
                (0xd63f0000, true),
                (0xd71f0800, false),
                (0xd71f0c00, false),
                (0xd73f0800, true),
                (0xd73f0c00, true),
                (0xd61f081f, false),
                (0xd63f081f, true),
            ] {
                let word = base | n << 5;
                let mut s = state();
                s.guarded = guarded;
                let expected = if call {
                    2
                } else if guarded && n != 16 && n != 17 {
                    3
                } else {
                    1
                };
                assert_eq!(
                    next(&evaluate(&pipeline(word), &s).unwrap()),
                    Some(expected),
                    "{word:08x}"
                );
            }
        }
    }
    for word in [
        0xd65f0000, 0xd65f03c0, 0xd65f0bff, 0xd65f0fff, 0x14000000, 0x94000000, 0x54000000,
        0x91000400,
    ] {
        assert_eq!(
            next(&evaluate(&pipeline(word), &state()).unwrap()),
            Some(0),
            "{word:08x}"
        );
    }
}
#[test]
fn pac_landing_pads_respect_presence_effective_bt_and_btd_controls() {
    for word in [0xd503233f, 0xd503237f, 0xdac1a3fe, 0xdac1a7fe] {
        for btype in 0..4 {
            for strict in [false, true] {
                for disabled in [false, true] {
                    for present in [false, true] {
                        let sp = word >> 24 == 0xd5;
                        let mut s = state();
                        s.btype = btype;
                        s.strict = strict;
                        s.disabled = disabled;
                        s.pac = present;
                        s.lr = present;
                        let compatible = present
                            && if sp && disabled {
                                btype == 0
                            } else {
                                btype != 3 || !strict
                            };
                        let t = evaluate(&pipeline(word), &s).unwrap();
                        assert_eq!(t.trap.is_some(),btype!=0&&!compatible,"{word:08x} type={btype} strict={strict} disabled={disabled} present={present}");
                    }
                }
            }
        }
    }
}
#[test]
fn absent_bti_is_lazy_and_exceptions_never_publish_completion() {
    struct Absent;
    impl Machine for Absent {
        fn read_register(&self, r: Register) -> Value {
            assert_eq!(r.bank, "a64.bti_enabled");
            Value::known(1, 0)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!()
        }
    }
    for word in [
        0xd503241f, 0xd503245f, 0xd61f0000, 0xd63f0000, 0xd503233f, 0xdac1a3fe,
    ] {
        let t = evaluate(&pipeline(word), &Absent).unwrap();
        assert!(t.registers.is_empty());
        assert_eq!(t.trap, None);
    }
    for word in [0xd4200000, 0xd4400000] {
        let mut r = Recipe::new(0x1004, 64);
        r.effects.push(Effect::Trap {
            kind: TrapKind::Breakpoint,
            condition: Expr::constant(1, 1),
        });
        let mut s = state();
        s.btype = 3;
        let t = evaluate(&arm64_bti::complete(word, r), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::Breakpoint));
        assert_eq!(next(&t), None);
    }
}
#[test]
fn pipeline_contract_rejects_nonincoming_bindings_even_when_disabled() {
    let mut r = pipeline(0xd50324df);
    r.entry_traps[0].1 = Expr {
        ty: Type {
            width: 1,
            signedness: Signedness::Unsigned,
        },
        kind: ExprKind::Temporary(0),
    };
    assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
    let mut r = pipeline(0xd50324df);
    r.completion_writes[0].1 = Expr::constant(2, 0);
    assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
}

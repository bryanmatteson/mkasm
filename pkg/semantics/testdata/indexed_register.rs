#[cfg(test)]
mod indexed_register_tests {
    use super::*;
    use std::{cell::RefCell, collections::HashMap};
    #[derive(Default)]
    struct State {
        regs: HashMap<Register, Value>,
        reads: RefCell<Vec<Register>>,
    }
    impl State {
        fn set(&mut self, bank: &'static str, index: u16, width: u8, value: u64) {
            self.regs
                .insert(Register { bank, index }, Value::known(width, value));
        }
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            self.reads.borrow_mut().push(r);
            *self
                .regs
                .get(&r)
                .unwrap_or_else(|| panic!("unexpected selected register {r:?}"))
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("invalid index evaluated write value")
        }
    }
    fn bank(index: Expr) -> IndexedRegister {
        IndexedRegister {
            bank: "finite",
            base: 7,
            stride: 3,
            count: 4,
            index: Box::new(index),
            offset: 8,
            width: 8,
            parent_width: 32,
        }
    }
    fn eval(e: &Expr, state: &State) -> Result<Value, EvalError> {
        evaluate_expression(e, state, &[])
    }
    fn index_register() -> Expr {
        Expr::register(register("index", 0, 64, 64))
    }
    #[test]
    fn finite_bank_selects_last_register_and_extracts_original_slice() {
        let mut s = State::default();
        s.set("finite", 16, 32, 0x12345678);
        let d = bank(Expr::constant(64, 3));
        assert_eq!(
            eval(&Expr::indexed_register(d), &s),
            Ok(Value::known(8, 0x56))
        );
        assert_eq!(
            *s.reads.borrow(),
            [Register {
                bank: "finite",
                index: 16
            }]
        );
    }
    #[test]
    fn partial_and_zero_upper_writes_compose_but_reads_stay_incoming() {
        let mut s = State::default();
        s.set("finite", 10, 32, 0xaabbccdd);
        let d = bank(Expr::constant(64, 1));
        let mut r = Recipe::new(4, 64);
        r.write_indexed(d.clone(), WritePolicy::Preserve, Expr::constant(8, 0x11));
        let mut low = d.clone();
        low.offset = 0;
        r.write_indexed(
            low.clone(),
            WritePolicy::Preserve,
            Expr::indexed_register(d),
        );
        r.write(
            register("out", 0, 32, 32),
            WritePolicy::ZeroUpper,
            Expr::cast(Expr::indexed_register(low.clone()), 32, false),
        );
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(
            t.registers[0].register,
            Register {
                bank: "finite",
                index: 10
            }
        );
        assert_eq!(t.registers[0].value, Value::known(32, 0xaabb11dd));
        assert_eq!(t.registers[1].value, Value::known(32, 0xaabb11cc));
        assert_eq!(t.registers[2].value, Value::known(32, 0xdd));
        r.effects.clear();
        r.write_indexed(
            low,
            WritePolicy::ZeroUpper,
            Expr::undefined(8, "architectural data"),
        );
        let t = evaluate(&r, &State::default()).unwrap();
        assert_eq!(
            t.registers[0].value,
            Value {
                width: 32,
                bits: 0,
                defined: 0xffff_ff00
            }
        );
    }
    #[test]
    fn dynamic_write_selector_uses_incoming_state_after_an_earlier_index_write() {
        let mut s = State::default();
        s.set("index", 0, 64, 1);
        s.set("finite", 10, 32, 0x12345678);
        let mut r = Recipe::new(4, 64);
        r.write(
            register("index", 0, 64, 64),
            WritePolicy::ZeroUpper,
            Expr::constant(64, 3),
        );
        r.write_indexed(
            bank(index_register()),
            WritePolicy::Preserve,
            Expr::cast(index_register(), 8, false),
        );
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(t.registers[0].value, Value::known(64, 3));
        assert_eq!(
            t.registers[1].register,
            Register {
                bank: "finite",
                index: 10
            }
        );
        assert_eq!(t.registers[1].value, Value::known(32, 0x12340178));
    }
    #[test]
    fn selected_unknown_or_out_of_range_indices_reject_before_data_or_value_access() {
        let mut s = State::default();
        s.regs.insert(
            Register {
                bank: "index",
                index: 0,
            },
            Value::unknown(64),
        );
        let d = bank(index_register());
        assert_eq!(
            eval(&Expr::indexed_register(d.clone()), &s),
            Err(EvalError::UnknownRegisterIndex)
        );
        let mut r = Recipe::new(4, 64);
        r.write_indexed(
            d,
            WritePolicy::Preserve,
            Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(Expr::constant(64, 0)),
                width: 8,
                endian: Endian::Little,
            }),
        );
        for index in [4, u64::MAX] {
            s.set("index", 0, 64, index);
            assert_eq!(evaluate(&r, &s), Err(EvalError::RegisterIndexOutOfRange));
        }
        assert!(s.reads.borrow().iter().all(|reg| reg.bank == "index"));
    }
    #[test]
    fn unselected_indices_and_false_guard_are_lazy() {
        let bad = Expr::indexed_register(bank(Expr::constant(64, 4)));
        let unknown = Expr::indexed_register(bank(Expr::undefined(64, "unavailable index")));
        let s = State::default();
        for branch in [bad, unknown] {
            assert_eq!(
                eval(
                    &Expr::select(Expr::constant(1, 0), branch, Expr::constant(8, 0x5a)),
                    &s
                ),
                Ok(Value::known(8, 0x5a))
            );
        }
        let mut r = Recipe::new(4, 64);
        r.guard = Expr::constant(1, 0);
        r.write_indexed(
            bank(index_register()),
            WritePolicy::Preserve,
            Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(Expr::constant(64, 0)),
                width: 8,
                endian: Endian::Little,
            }),
        );
        assert!(evaluate(&r, &s).unwrap().registers.is_empty());
        assert!(s.reads.borrow().is_empty());
    }
    #[test]
    fn descriptor_validation_checks_all_dimensions_even_in_unselected_branch() {
        let good = bank(Expr::constant(64, 0));
        let mut variants = vec![];
        let mut d = good.clone();
        d.bank = "";
        variants.push(d);
        let mut d = good.clone();
        d.count = 0;
        variants.push(d);
        let mut d = good.clone();
        d.stride = 0;
        variants.push(d);
        let mut d = good.clone();
        d.base = u16::MAX;
        variants.push(d);
        let mut d = good.clone();
        d.parent_width = 0;
        variants.push(d);
        let mut d = good.clone();
        d.parent_width = 65;
        variants.push(d);
        let mut d = good.clone();
        d.offset = 31;
        variants.push(d);
        let mut d = good.clone();
        d.width = 0;
        variants.push(d);
        let mut d = good.clone();
        d.width = 65;
        variants.push(d);
        let mut d = good.clone();
        d.index.ty.width = 0;
        variants.push(d);
        let mut d = good.clone();
        d.index.ty.width = 65;
        variants.push(d);
        for d in variants {
            let e = Expr::indexed_register(d.clone());
            assert_eq!(
                validate_expression(&e, &[]),
                Err(EvalError::InvalidExpression)
            );
            let mut r = Recipe::new(4, 64);
            r.write_indexed(d, WritePolicy::Preserve, Expr::constant(8, 0));
            assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
        }
        let mut wrong = Expr::indexed_register(good.clone());
        wrong.ty.width = 16;
        assert_eq!(
            validate_expression(&wrong, &[]),
            Err(EvalError::InvalidExpression)
        );
        let mut wrong = good.clone();
        wrong.index = Box::new(Expr::binary(
            BinaryOp::Add,
            Expr::constant(8, 0),
            Expr::constant(16, 0),
        ));
        let wrong = Expr::select(
            Expr::constant(1, 0),
            Expr::indexed_register(wrong),
            Expr::constant(8, 0),
        );
        assert_eq!(
            validate_expression(&wrong, &[]),
            Err(EvalError::InvalidExpression)
        );
        let mut r = Recipe::new(4, 64);
        r.write_indexed(good.clone(), WritePolicy::ZeroUpper, Expr::constant(8, 0));
        assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
        r.effects.clear();
        r.write_indexed(good, WritePolicy::Preserve, Expr::constant(16, 0));
        assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
    }
    #[test]
    fn recursive_index_dependencies_reject_forward_temporaries_and_accept_bound_input() {
        let mut s = State::default();
        s.set("index", 0, 64, 3);
        s.set("finite", 16, 32, 0x12345678);
        let mut r = Recipe::new(4, 64);
        let at = r.bind(index_register());
        let read = r.bind(Expr::indexed_register(bank(at)));
        r.write(register("out", 0, 8, 8), WritePolicy::ZeroUpper, read);
        assert_eq!(
            evaluate(&r, &s).unwrap().registers[0].value,
            Value::known(8, 0x56)
        );
        let forward = Expr {
            ty: Type {
                width: 64,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Temporary(1),
        };
        r.temporaries[0] = Expr::cast(Expr::indexed_register(bank(forward)), 64, false);
        assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
        let forward = Expr {
            ty: Type {
                width: 64,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Temporary(99),
        };
        let mut r = Recipe::new(4, 64);
        r.write_indexed(bank(forward), WritePolicy::Preserve, Expr::constant(8, 0));
        assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
    }
    #[test]
    fn selected_parent_width_and_read_type_are_enforced() {
        let mut s = State::default();
        s.set("finite", 7, 16, 0x1234);
        assert_eq!(
            eval(&Expr::indexed_register(bank(Expr::constant(64, 0))), &s),
            Err(EvalError::InvalidExpression)
        );
        let mut r = Recipe::new(4, 64);
        r.write_indexed(
            bank(Expr::constant(64, 0)),
            WritePolicy::Preserve,
            Expr::constant(8, 1),
        );
        assert_eq!(evaluate(&r, &s), Err(EvalError::InvalidExpression));
    }
}

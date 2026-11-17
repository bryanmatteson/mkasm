package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustPredicatedWideAndOrderedReads(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime+predicatedWideTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", "wide-conditional-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile wide predication: %v\n%s", err, out)
	}
	if out, err := exec.Command(filepath.Join(dir, "wide-conditional-tests"), "predicated_wide_behavior::").CombinedOutput(); err != nil {
		t.Fatalf("wide predication behavior: %v\n%s", err, out)
	}
}

const predicatedWideTests = `
#[cfg(test)]
mod predicated_wide_behavior {
    use super::*;
    use std::cell::RefCell;
    struct State {
        calls: RefCell<Vec<(u64, u16)>>,
        fail: bool,
    }
    impl State {
        fn new() -> Self {
            Self {
                calls: RefCell::new(vec![]),
                fail: false,
            }
        }
    }
    impl Machine for State {
        fn read_register(&self, _: Register) -> Value {
            panic!("unexpected register")
        }
        fn read_memory(&self, a: u64, w: u8, _: Endian) -> Result<Value, EvalError> {
            self.calls.borrow_mut().push((a, u16::from(w)));
            if self.fail {
                return Err(EvalError::Memory);
            }
            Ok(Value::known(w, if a == 0 { 1 } else { 0x1234 }))
        }
        fn read_wide_memory(&self, a: u64, w: u16, _: Endian) -> Result<Vec<Value>, EvalError> {
            self.calls.borrow_mut().push((a, w));
            if self.fail {
                return Err(EvalError::Memory);
            }
            assert_eq!(w, 80);
            Ok(vec![
                Value::known(64, 0x1122334455667788),
                Value::known(16, 0xbeef),
            ])
        }
    }
    fn scalar(a: u64, w: u8) -> Memory {
        Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, a)),
            width: w,
            endian: Endian::Little,
        }
    }
    fn wide(a: Expr) -> WideMemory {
        WideMemory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(a),
            width: 80,
            endian: Endian::Big,
        }
    }
    #[test]
    fn false_store_skips_address_and_all_chunks_but_checks_inactive_graph() {
        let st = State::new();
        let mut r = Recipe::new(4, 64);
        let faulting = Expr::load(scalar(usize::MAX as u64, 64));
        r.store_wide_conditional(
            Expr::constant(1, 0),
            wide(Expr::undefined(64, "inactive address")),
            vec![faulting, Expr::undefined(16, "inactive data")],
        );
        let t = evaluate(&r, &st).unwrap();
        assert!(t.wide_memory.is_empty() && t.events.is_empty() && st.calls.borrow().is_empty());
        if let Effect::StoreWideConditional { chunks, .. } = &mut r.effects[0] {
            chunks[1] = Expr::constant(8, 0);
        }
        assert_eq!(evaluate(&r, &st), Err(EvalError::InvalidExpression));
        assert!(st.calls.borrow().is_empty());
    }
    #[test]
    fn enabled_store_retains_one_80bit_event_endian_and_pending_commit() {
        let st = State::new();
        let mut r = Recipe::new(4, 64);
        r.store_wide_conditional(
            Expr::constant(1, 1),
            wide(Expr::constant(64, 16)),
            vec![
                Expr::constant(64, 0x1122334455667788),
                Expr::constant(16, 0xaabb),
            ],
        );
        let t = evaluate(&r, &st).unwrap();
        assert_eq!(t.events, vec![OrderedEvent::WideStore(0)]);
        assert!(t.memory.is_empty() && st.calls.borrow().is_empty());
        let w = &t.wide_memory[0];
        assert_eq!((w.address, w.width, w.endian), (16, 80, Endian::Big));
        let mut bytes = vec![];
        for chunk in &w.chunks {
            bytes.extend_from_slice(&chunk.bits.to_le_bytes()[..usize::from(chunk.width / 8)]);
        }
        bytes.reverse();
        assert_eq!(
            bytes,
            [0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
    }
    #[test]
    fn unknown_predicate_and_malformed_predicate_never_access_memory() {
        let st = State::new();
        for (condition, error) in [
            (Expr::undefined(1, "unknown"), EvalError::UnknownCondition),
            (Expr::constant(8, 0), EvalError::InvalidExpression),
        ] {
            let mut r = Recipe::new(4, 64);
            r.store_wide_conditional(
                condition,
                wide(Expr::undefined(64, "address")),
                vec![Expr::constant(64, 1), Expr::constant(16, 2)],
            );
            assert_eq!(evaluate(&r, &st), Err(error));
        }
        assert!(st.calls.borrow().is_empty());
    }
    #[test]
    fn scalar_and_wide_reads_share_one_order_without_repeated_callbacks() {
        let st = State::new();
        let mut r = Recipe::new(4, 64);
        let first = r.load_ordered(scalar(0, 32)).unwrap();
        let chunks = r.load_wide_conditional(
            Expr::binary(BinaryOp::Eq, first.clone(), Expr::constant(32, 1)),
            wide(Expr::constant(64, 16)),
        );
        let last = r
            .load_ordered_conditional(
                Expr::binary(BinaryOp::Eq, chunks[1].clone(), Expr::constant(16, 0xbeef)),
                scalar(32, 16),
            )
            .unwrap();
        r.write(register("test", 0, 16, 16), WritePolicy::ZeroUpper, last);
        let t = evaluate(&r, &st).unwrap();
        assert_eq!(t.registers[0].value, Value::known(16, 0x1234));
        assert_eq!(*st.calls.borrow(), [(0, 32), (16, 80), (32, 16)]);
        let before = r.clone();
        assert!(r.load_ordered(scalar(0, 0)).is_err());
        assert!(r.load_ordered(scalar(0, 72)).is_err());
        assert_eq!(r, before);
    }
    #[test]
    fn validation_and_first_fault_precede_all_architectural_outputs() {
        let mut st = State::new();
        let mut r = Recipe::new(4, 64);
        let value = r.load_ordered(scalar(0, 32)).unwrap();
        r.write(register("test", 0, 32, 32), WritePolicy::ZeroUpper, value);
        r.load_wide(wide(Expr::constant(64, 16)));
        st.fail = true;
        assert_eq!(evaluate(&r, &st), Err(EvalError::Memory));
        assert_eq!(*st.calls.borrow(), [(0, 32)]);
        let mut invalid = Recipe::new(4, 64);
        let future = Expr {
            ty: Type {
                width: 1,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::WideLoadChunk { step: 0, chunk: 0 },
        };
        invalid
            .load_ordered_conditional(future, scalar(0, 8))
            .unwrap();
        st.calls.borrow_mut().clear();
        assert_eq!(evaluate(&invalid, &st), Err(EvalError::InvalidExpression));
        assert!(st.calls.borrow().is_empty());
    }
    #[test]
    fn x86_half_admission_matches_exact_native_operation_and_integer_widths() {
        let build = |operation, width, inputs: Vec<Expr>| {
            Expr::float(FloatExpression {
                operation,
                environment: FloatEnvironment::X86Mxcsr,
                width,
                inputs,
                control: Box::new(Expr::constant(32, 0x1f80)),
                status: Box::new(Expr::constant(32, 0x1f80)),
                projection: FloatProjection::Value,
            })
        };
        for (operation, width, widths) in [
            (FloatOperation::Add, 16, vec![16, 16]),
            (FloatOperation::Divide, 16, vec![16, 16]),
            (FloatOperation::SquareRoot, 16, vec![16]),
            (
                FloatOperation::FusedMultiplyAdd {
                    negate_product: false,
                    negate_addend: true,
                },
                16,
                vec![16; 3],
            ),
            (
                FloatOperation::Compare {
                    source_width: 16,
                    signal_all_nans: false,
                },
                4,
                vec![16, 16],
            ),
            (
                FloatOperation::RoundToIntegral {
                    rounding: FloatRounding::Zero,
                    exact: true,
                },
                16,
                vec![16],
            ),
            (
                FloatOperation::Convert {
                    source_width: 16,
                    round_to_odd: false,
                },
                64,
                vec![16],
            ),
            (
                FloatOperation::Convert {
                    source_width: 64,
                    round_to_odd: false,
                },
                16,
                vec![64],
            ),
            (
                FloatOperation::ToInteger {
                    source_width: 16,
                    signed: true,
                    fractional_bits: 0,
                    rounding: FloatRounding::Zero,
                },
                64,
                vec![16],
            ),
            (
                FloatOperation::FromInteger {
                    source_width: 32,
                    signed: false,
                    fractional_bits: 0,
                },
                16,
                vec![32],
            ),
            (FloatOperation::ToInteger{source_width:16,signed:false,fractional_bits:0,rounding:FloatRounding::Zero},16,vec![16]),
            (FloatOperation::FromInteger{source_width:16,signed:true,fractional_bits:0},16,vec![16]),
        ] {
            validate_expression(
                &build(
                    operation,
                    width,
                    widths.into_iter().map(|w| Expr::constant(w, 0)).collect(),
                ),
                &[],
            )
            .unwrap();
        }
        for (operation, width, source) in [
            (
                FloatOperation::ToInteger {
                    source_width: 16,
                    signed: true,
                    fractional_bits: 0,
                    rounding: FloatRounding::Zero,
                },
                8,
                16,
            ),
            (
                FloatOperation::FromInteger {
                    source_width: 8,
                    signed: false,
                    fractional_bits: 0,
                },
                16,
                8,
            ),
            (FloatOperation::ReciprocalEstimate, 16, 16),
            (
                FloatOperation::Convert {
                    source_width: 8,
                    round_to_odd: false,
                },
                16,
                8,
            ),
        ] {
            assert_eq!(
                validate_expression(
                    &build(operation, width, vec![Expr::constant(source, 0)]),
                    &[]
                ),
                Err(EvalError::InvalidExpression)
            );
        }
    }
}
`

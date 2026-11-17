package semantics

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed x87.rs
var x87HelperSource string

func TestRustX87TypedExpressions(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod x87") {
		source += "\npub mod x87 {\n" + x87HelperSource + "\n}\n"
	}
	for name, data := range map[string]string{"semantics.rs": source, "consumer.rs": x87BehaviorTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "x87-tests")
	cmd := exec.Command("rustc", "--edition=2021", "--test", "consumer.rs", "-Dwarnings", "-o", binary)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile typed x87 runtime: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary, "x87_behavior::").CombinedOutput(); err != nil {
		t.Fatalf("execute typed x87 runtime: %v\n%s", err, out)
	}
}

const x87BehaviorTests = `
#[allow(dead_code)]
mod semantics;
mod x87_behavior {
    use super::semantics::x87::capture;
    use super::semantics::*;
    use std::cell::{Cell, RefCell};
    #[derive(Clone, Copy)]
    enum Mode {
        Exact,
        Blocked,
        Unavailable,
        WrongWidth,
        UnknownResult,
        OutOfRangeBits,
        OutOfRangeDefined,
        Unsupported,
    }
    struct Engine {
        mode: Mode,
        calls: Cell<usize>,
        reads: Cell<usize>,
        wide: Cell<usize>,
        seen: RefCell<Vec<(X87Projection, Vec<Value>, [Value; 3])>>,
    }
    impl Engine {
        fn new(mode: Mode) -> Self {
            Self {
                mode,
                calls: Cell::new(0),
                reads: Cell::new(0),
                wide: Cell::new(0),
                seen: RefCell::new(vec![]),
            }
        }
    }
    impl Machine for Engine {
        fn read_register(&self, _: Register) -> Value {
            self.reads.set(self.reads.get() + 1);
            Value::known(64, 0)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("unexpected scalar memory read")
        }
        fn read_wide_memory(
            &self,
            address: u64,
            width: u16,
            endian: Endian,
        ) -> Result<Vec<Value>, EvalError> {
            assert_eq!((address, width, endian), (0x1000, 80, Endian::Little));
            self.wide.set(self.wide.get() + 1);
            Ok(vec![
                Value::known(64, 0x8000000000000000),
                Value::known(16, 0x3fff),
            ])
        }
        fn evaluate_x87(
            &self,
            e: &X87Expression,
            inputs: &[Value],
            control: Value,
            status: Value,
            tags: Value,
        ) -> Result<Value, EvalError> {
            self.calls.set(self.calls.get() + 1);
            self.seen
                .borrow_mut()
                .push((e.projection, inputs.to_vec(), [control, status, tags]));
            assert!(inputs.iter().all(|v| v.is_known()));
            assert_eq!([control.width, status.width, tags.width], [16; 3]);
            assert!(control.is_known() && status.is_known() && tags.is_known());
            let width = e.operation.projection_width(e.projection).unwrap();
            let data = matches!(
                e.projection,
                X87Projection::Result { .. }
                    | X87Projection::Store { .. }
                    | X87Projection::CompareFlag(_)
            );
            match self.mode {
                Mode::Unsupported => return Err(EvalError::Unsupported),
                Mode::WrongWidth => return Ok(Value::known(if width == 64 { 32 } else { 64 }, 0)),
                Mode::UnknownResult => return Ok(Value::unknown(width)),
                Mode::OutOfRangeBits => {
                    return Ok(Value {
                        bits: 1 << width,
                        defined: mask(width),
                        width,
                    })
                }
                Mode::OutOfRangeDefined => {
                    return Ok(Value {
                        bits: 0,
                        defined: u64::MAX,
                        width,
                    })
                }
                Mode::Blocked | Mode::Unavailable if data => {
                    return Err(EvalError::UnavailableX87Result)
                }
                _ => {}
            }
            Ok(Value::known(
                width,
                match e.projection {
                    X87Projection::Result { register, chunk } => {
                        if chunk == 0 {
                            0x8000000000000000 | u64::from(register)
                        } else {
                            0x3fff
                        }
                    }
                    X87Projection::Store { .. } => 0x123456789abcdef0 & mask(width),
                    X87Projection::Status => status.bits | 0x4000,
                    X87Projection::Tags => 0xfffc,
                    X87Projection::Commit => u64::from(!matches!(self.mode, Mode::Blocked)),
                    X87Projection::CompareFlag(flag) => u64::from(flag != X87CompareFlag::Parity),
                },
            ))
        }
    }
    struct NoEngine;
    impl Machine for NoEngine {
        fn read_register(&self, _: Register) -> Value {
            panic!("unexpected register")
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("unexpected memory")
        }
    }
    fn operand(w: u8) -> X87Operand {
        if w == 80 {
            X87Operand::extended(
                Expr::constant(64, 0x8000000000000000),
                Expr::constant(16, 0x3fff),
            )
        } else {
            X87Operand::scalar(Expr::constant(w, 1))
        }
    }
    fn expression(operation: X87Operation, projection: X87Projection) -> X87Expression {
        X87Expression {
            operation,
            inputs: operation
                .input_widths()
                .unwrap()
                .into_iter()
                .map(operand)
                .collect(),
            control: Box::new(Expr::constant(16, 0x037f)),
            status: Box::new(Expr::constant(16, 0)),
            tags: Box::new(Expr::constant(16, 0xffff)),
            projection,
        }
    }
    fn scalar(e: X87Expression) -> Expr {
        Expr::x87(e).unwrap()
    }
    fn evaluate_x(e: X87Expression, engine: &impl Machine) -> Result<Value, EvalError> {
        evaluate_expression(&scalar(e), engine, &[])
    }
    #[test]
    fn exact_chunks_formats_and_environment_cross_the_explicit_capability() {
        let engine = Engine::new(Mode::Exact);
        let op = X87Operation::Binary {
            operation: X87BinaryOperation::Add,
            source_width: 32,
            reverse: true,
            destination_register: 7,
            source_register: None,
            pop: true,
        };
        for (chunk, width, bits) in [(0, 64, 0x8000000000000007), (1, 16, 0x3fff)] {
            let result = evaluate_x(
                expression(op, X87Projection::Result { register: 7, chunk }),
                &engine,
            )
            .unwrap();
            assert_eq!(result, Value::known(width, bits));
        }
        let seen = engine.seen.borrow();
        assert_eq!(
            seen[0].1,
            [
                Value::known(64, 0x8000000000000000),
                Value::known(16, 0x3fff),
                Value::known(32, 1)
            ]
        );
        assert_eq!(
            seen[0].2,
            [
                Value::known(16, 0x037f),
                Value::known(16, 0),
                Value::known(16, 0xffff)
            ]
        );
        drop(seen);
        for w in [32, 64, 80] {
            let op = X87Operation::LoadFloat { source_width: w };
            let _ = evaluate_x(
                expression(
                    op,
                    X87Projection::Result {
                        register: 0,
                        chunk: 1,
                    },
                ),
                &engine,
            )
            .unwrap();
            let seen = engine.seen.borrow();
            let got = &seen.last().unwrap().1;
            assert_eq!(
                got.iter().map(|x| x.width).collect::<Vec<_>>(),
                if w == 80 { vec![64, 16] } else { vec![w] }
            );
        }
        let op = X87Operation::ConditionalMove { register: 3 };
        let _ = evaluate_x(expression(op, X87Projection::Commit), &engine).unwrap();
        assert_eq!(
            engine
                .seen
                .borrow()
                .last()
                .unwrap()
                .1
                .iter()
                .map(|v| v.width)
                .collect::<Vec<_>>(),
            [64, 16, 64, 16, 1]
        );
    }
    #[test]
    fn all_closed_operations_have_exact_logical_dimensions_and_outputs() {
        let cases = vec![
            (
                X87Operation::LoadInteger { source_width: 16 },
                vec![16],
                1,
                None,
            ),
            (
                X87Operation::StoreFloat {
                    destination_width: 80,
                    pop: true,
                },
                vec![80],
                0,
                Some(80),
            ),
            (
                X87Operation::StoreInteger {
                    destination_width: 64,
                    pop: false,
                },
                vec![80],
                0,
                Some(64),
            ),
            (
                X87Operation::Unary {
                    negate: true,
                    register: 7,
                },
                vec![80],
                128,
                None,
            ),
            (
                X87Operation::Exchange { register: 7 },
                vec![80, 80],
                129,
                None,
            ),
            (
                X87Operation::Compare {
                    ordered: true,
                    pop: true,
                    left_register: 0,
                    right_register: 7,
                },
                vec![80, 80],
                0,
                None,
            ),
            (
                X87Operation::LoadConstant {
                    constant: X87Constant::Pi,
                },
                vec![],
                1,
                None,
            ),
            (
                X87Operation::LoadRegister { register: 7 },
                vec![80],
                1,
                None,
            ),
            (
                X87Operation::StoreRegister {
                    register: 7,
                    pop: true,
                },
                vec![80],
                128,
                None,
            ),
            (
                X87Operation::StoreTruncatedInteger {
                    destination_width: 32,
                },
                vec![80],
                0,
                Some(32),
            ),
            (X87Operation::LoadBcd, vec![80], 1, None),
            (X87Operation::StoreBcd, vec![80], 0, Some(80)),
            (
                X87Operation::CompareStatus {
                    ordered: false,
                    source_width: 64,
                    source_register: None,
                    pops: 2,
                },
                vec![80, 64],
                0,
                None,
            ),
            (
                X87Operation::ConditionalMove { register: 7 },
                vec![80, 80, 1],
                1,
                None,
            ),
        ];
        for (op, widths, results, store) in cases {
            assert_eq!(op.input_widths(), Some(widths));
            assert_eq!(op.result_registers(), results);
            assert_eq!(op.store_width(), store);
            for p in [
                X87Projection::Status,
                X87Projection::Tags,
                X87Projection::Commit,
            ] {
                let e = scalar(expression(op, p));
                validate_expression(&e, &[]).unwrap();
            }
            for register in 0..8 {
                for chunk in 0..3 {
                    assert_eq!(
                        op.projection_width(X87Projection::Result { register, chunk }),
                        if results & (1 << register) != 0 && chunk < 2 {
                            Some(if chunk == 0 { 64 } else { 16 })
                        } else {
                            None
                        }
                    );
                }
            }
            for chunk in 0..3 {
                assert_eq!(
                    op.projection_width(X87Projection::Store { chunk }),
                    store.and_then(|w| match (w, chunk) {
                        (80, 0) => Some(64),
                        (80, 1) => Some(16),
                        (1..=64, 0) => Some(w),
                        _ => None,
                    })
                );
            }
        }
        for (op, arity, pops, pushes, results) in [
            (X87MathOperation::SquareRoot, 1, false, false, 1),
            (X87MathOperation::Round, 1, false, false, 1),
            (X87MathOperation::Scale, 2, false, false, 1),
            (X87MathOperation::Remainder, 2, false, false, 1),
            (X87MathOperation::RemainderNearest, 2, false, false, 1),
            (X87MathOperation::Extract, 1, false, true, 3),
            (X87MathOperation::Sine, 1, false, false, 1),
            (X87MathOperation::Cosine, 1, false, false, 1),
            (X87MathOperation::SineCosine, 1, false, true, 3),
            (X87MathOperation::Tangent, 1, false, true, 3),
            (X87MathOperation::Arctangent, 2, true, false, 2),
            (X87MathOperation::Exp2MinusOne, 1, false, false, 1),
            (X87MathOperation::YLog2X, 2, true, false, 2),
            (X87MathOperation::YLog2XPlusOne, 2, true, false, 2),
            (X87MathOperation::Examine, 1, false, false, 0),
        ] {
            assert_eq!((op.arity(), op.pops(), op.pushes()), (arity, pops, pushes));
            let op = X87Operation::Math { operation: op };
            assert_eq!(op.input_widths(), Some(vec![80; arity]));
            assert_eq!(op.result_registers(), results);
        }
        for c in [
            X87Constant::Pi,
            X87Constant::Log2E,
            X87Constant::Log2Ten,
            X87Constant::Log10Two,
            X87Constant::LnTwo,
        ] {
            assert_eq!(
                X87Operation::LoadConstant { constant: c }.input_widths(),
                Some(vec![])
            );
        }
    }
    #[test]
    fn constructor_and_graph_validation_reject_malformed_dimensions_before_state() {
        let valid = expression(
            X87Operation::LoadFloat { source_width: 80 },
            X87Projection::Result {
                register: 0,
                chunk: 0,
            },
        );
        for mutation in 0..8 {
            let mut e = valid.clone();
            match mutation {
                0 => e.inputs[0].width = 64,
                1 => {
                    e.inputs[0].chunks.pop();
                }
                2 => e.inputs[0].chunks[1] = Expr::constant(64, 0),
                3 => e.control = Box::new(Expr::constant(32, 0)),
                4 => e.tags = Box::new(Expr::constant(8, 0)),
                5 => {
                    e.projection = X87Projection::Result {
                        register: 1,
                        chunk: 0,
                    }
                }
                6 => {
                    e.projection = X87Projection::Result {
                        register: 0,
                        chunk: 2,
                    }
                }
                _ => e.projection = X87Projection::Store { chunk: 0 },
            }
            assert_eq!(Expr::x87(e), Err(EvalError::InvalidExpression));
        }
        let engine = Engine::new(Mode::Exact);
        let mut e = scalar(valid.clone());
        e.ty.width = 32;
        assert_eq!(
            evaluate_expression(&e, &engine, &[]),
            Err(EvalError::InvalidExpression)
        );
        assert_eq!(engine.calls.get(), 0);
        let mut e = valid;
        e.inputs[0].chunks[1] = Expr {
            ty: Type {
                width: 16,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Temporary(0),
        };
        let e = scalar(e);
        let select = Expr::select(Expr::constant(1, 0), e, Expr::constant(64, 3));
        assert_eq!(
            evaluate_expression(&select, &engine, &[]),
            Err(EvalError::InvalidExpression)
        );
        assert_eq!(engine.calls.get(), 0);
        let malformed = [
            X87Operation::LoadFloat { source_width: 16 },
            X87Operation::LoadInteger { source_width: 80 },
            X87Operation::StoreFloat {
                destination_width: 16,
                pop: false,
            },
            X87Operation::StoreInteger {
                destination_width: 80,
                pop: false,
            },
            X87Operation::StoreTruncatedInteger {
                destination_width: 8,
            },
            X87Operation::LoadRegister { register: 8 },
            X87Operation::Unary {
                register: 8,
                negate: false,
            },
            X87Operation::Exchange { register: 8 },
            X87Operation::Compare {
                ordered: false,
                pop: false,
                left_register: 8,
                right_register: 0,
            },
            X87Operation::CompareStatus {
                ordered: false,
                source_width: 80,
                source_register: Some(8),
                pops: 0,
            },
            X87Operation::CompareStatus {
                ordered: false,
                source_width: 80,
                source_register: None,
                pops: 3,
            },
            X87Operation::ConditionalMove { register: 8 },
        ];
        for op in malformed {
            assert!(op.input_widths().is_none());
            assert!(op.projection_width(X87Projection::Commit).is_none());
        }
    }
    #[test]
    fn unknown_chunks_and_environment_propagate_typed_unknown_without_engine() {
        let op = X87Operation::Unary {
            negate: true,
            register: 0,
        };
        for slot in 0..5 {
            let engine = Engine::new(Mode::Exact);
            for projection in [
                X87Projection::Result {
                    register: 0,
                    chunk: 0,
                },
                X87Projection::Result {
                    register: 0,
                    chunk: 1,
                },
                X87Projection::Status,
                X87Projection::Tags,
                X87Projection::Commit,
            ] {
                let mut e = expression(op, projection);
                match slot {
                    0 => e.inputs[0].chunks[0] = Expr::undefined(64, "unknown significand"),
                    1 => e.inputs[0].chunks[1] = Expr::undefined(16, "unknown exponent"),
                    2 => e.control = Box::new(Expr::undefined(16, "unknown CW")),
                    3 => e.status = Box::new(Expr::undefined(16, "unknown SW")),
                    _ => e.tags = Box::new(Expr::undefined(16, "unknown TW")),
                };
                assert_eq!(
                    evaluate_x(e, &engine),
                    Ok(Value::unknown(op.projection_width(projection).unwrap()))
                );
            }
            assert_eq!(engine.calls.get(), 0);
        }
    }
    #[test]
    fn missing_malformed_and_unavailable_capability_never_fabricates_results() {
        let e = expression(
            X87Operation::LoadConstant {
                constant: X87Constant::Pi,
            },
            X87Projection::Result {
                register: 0,
                chunk: 1,
            },
        );
        assert_eq!(
            evaluate_x(e.clone(), &NoEngine),
            Err(EvalError::Unsupported)
        );
        for mode in [
            Mode::WrongWidth,
            Mode::UnknownResult,
            Mode::OutOfRangeBits,
            Mode::OutOfRangeDefined,
        ] {
            assert_eq!(
                evaluate_x(e.clone(), &Engine::new(mode)),
                Err(EvalError::InvalidX87Outcome)
            );
        }
        assert_eq!(
            evaluate_x(e.clone(), &Engine::new(Mode::Unavailable)),
            Err(EvalError::UnavailableX87Result)
        );
        assert_eq!(
            evaluate_x(e, &Engine::new(Mode::Unsupported)),
            Err(EvalError::Unsupported)
        );
    }
    #[test]
    fn inactive_select_and_instruction_guard_do_not_call_or_read_x87() {
        let e = scalar(expression(
            X87Operation::LoadFloat { source_width: 80 },
            X87Projection::Result {
                register: 0,
                chunk: 0,
            },
        ));
        let selected = Expr::select(Expr::constant(1, 0), e.clone(), Expr::constant(64, 7));
        assert_eq!(
            evaluate_expression(&selected, &NoEngine, &[]),
            Ok(Value::known(64, 7))
        );
        let engine = Engine::new(Mode::Exact);
        let mut r = Recipe::new(4, 64);
        r.guard = Expr::constant(1, 0);
        let mut x = expression(
            X87Operation::LoadFloat { source_width: 32 },
            X87Projection::Status,
        );
        x.inputs[0] = X87Operand::scalar(Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, 0)),
            width: 32,
            endian: Endian::Little,
        }));
        r.bind(scalar(x));
        r.write(register("result", 0, 64, 64), WritePolicy::ZeroUpper, e);
        let t = evaluate(&r, &engine).unwrap();
        assert!(t.registers.is_empty());
        assert_eq!((engine.calls.get(), engine.reads.get()), (0, 0));
    }
    #[test]
    fn store_formats_compare_flags_and_80_bit_wide_memory_are_exact() {
        let engine = Engine::new(Mode::Exact);
        for w in [32, 64, 80] {
            let op = X87Operation::StoreFloat {
                destination_width: w,
                pop: true,
            };
            for chunk in 0..if w == 80 { 2 } else { 1 } {
                let v =
                    evaluate_x(expression(op, X87Projection::Store { chunk }), &engine).unwrap();
                assert_eq!(
                    v.width,
                    if w == 80 && chunk == 0 {
                        64
                    } else if w == 80 {
                        16
                    } else {
                        w
                    }
                );
            }
        }
        let compare = X87Operation::Compare {
            ordered: true,
            pop: true,
            left_register: 0,
            right_register: 7,
        };
        for flag in [
            X87CompareFlag::Zero,
            X87CompareFlag::Parity,
            X87CompareFlag::Carry,
        ] {
            let v = evaluate_x(
                expression(compare, X87Projection::CompareFlag(flag)),
                &engine,
            )
            .unwrap();
            assert_eq!(
                v,
                Value::known(1, u64::from(flag != X87CompareFlag::Parity))
            );
        }
        assert!(X87Operation::CompareStatus {
            ordered: true,
            source_width: 80,
            source_register: Some(7),
            pops: 0
        }
        .projection_width(X87Projection::CompareFlag(X87CompareFlag::Zero))
        .is_none());
        let mut r = Recipe::new(4, 64);
        let chunks = r.load_wide(WideMemory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, 0x1000)),
            width: 80,
            endian: Endian::Little,
        });
        let mut e = expression(
            X87Operation::LoadFloat { source_width: 80 },
            X87Projection::Status,
        );
        e.inputs = vec![X87Operand { width: 80, chunks }];
        let outputs = capture(&mut r, e).unwrap();
        for (chunk, width) in [(0, 64), (1, 16)] {
            let value = outputs
                .value_or(
                    X87Projection::Result { register: 0, chunk },
                    Expr::constant(width, 0),
                )
                .unwrap();
            r.write(
                register("result", u16::from(chunk), width, width),
                WritePolicy::ZeroUpper,
                value,
            );
        }
        let t = evaluate(&r, &engine).unwrap();
        assert_eq!(engine.wide.get(), 1);
        assert_eq!(
            t.registers
                .iter()
                .map(|x| x.value.width)
                .collect::<Vec<_>>(),
            [64, 16]
        );
        assert_eq!(t.registers[1].value.bits, 0x3fff);
    }
    #[test]
    fn coupled_helpers_gate_data_but_keep_exception_status_and_tags() {
        let engine = Engine::new(Mode::Blocked);
        let mut r = Recipe::new(4, 64);
        let outputs = capture(
            &mut r,
            expression(
                X87Operation::Unary {
                    negate: true,
                    register: 0,
                },
                X87Projection::Status,
            ),
        )
        .unwrap();
        let low = outputs
            .value_or(
                X87Projection::Result {
                    register: 0,
                    chunk: 0,
                },
                Expr::constant(64, 0x1234),
            )
            .unwrap();
        r.write(register("result", 0, 64, 64), WritePolicy::ZeroUpper, low);
        r.write(
            register("status", 0, 16, 16),
            WritePolicy::ZeroUpper,
            outputs.status.clone(),
        );
        r.write(
            register("tags", 0, 16, 16),
            WritePolicy::ZeroUpper,
            outputs.tags.clone(),
        );
        let t = evaluate(&r, &engine).unwrap();
        assert_eq!(
            t.registers.iter().map(|x| x.value.bits).collect::<Vec<_>>(),
            [0x1234, 0x4000, 0xfffc]
        );
        assert_eq!(engine.calls.get(), 3);
        assert!(engine.seen.borrow().iter().all(|x| matches!(
            x.0,
            X87Projection::Status | X87Projection::Tags | X87Projection::Commit
        )));
        assert!(outputs
            .value_or(X87Projection::Status, Expr::constant(16, 0))
            .is_err());
        assert!(outputs
            .value_or(
                X87Projection::Result {
                    register: 0,
                    chunk: 1
                },
                Expr::constant(64, 0)
            )
            .is_err());
        let mut invalid = expression(
            X87Operation::LoadFloat { source_width: 80 },
            X87Projection::Status,
        );
        invalid.inputs.clear();
        let before = r.clone();
        assert!(capture(&mut r, invalid).is_err());
        assert_eq!(r, before);
        let engine = Engine::new(Mode::Unavailable);
        let mut r = Recipe::new(4, 64);
        let outputs = capture(
            &mut r,
            expression(
                X87Operation::Math {
                    operation: X87MathOperation::SineCosine,
                },
                X87Projection::Status,
            ),
        )
        .unwrap();
        let high = outputs
            .value_when(
                X87Projection::Result {
                    register: 1,
                    chunk: 1,
                },
                Expr::constant(1, 0),
                Expr::constant(16, 0xbeef),
            )
            .unwrap();
        r.write(register("result", 0, 16, 16), WritePolicy::ZeroUpper, high);
        assert_eq!(
            evaluate(&r, &engine).unwrap().registers[0].value.bits,
            0xbeef
        );
        assert_eq!(engine.calls.get(), 3);
    }
}
`

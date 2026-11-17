#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_atomics::a64(word, 0x1000, endian)
}
struct State {
    address: u64,
    unknown: bool,
    enforce_sp: bool,
    fault: bool,
    calls: RefCell<Vec<AtomicRequest>>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.sp_alignment_enforced" => Value::known(1, u64::from(self.enforce_sp)),
            "a64.gpr" if r.index == 5 => {
                if self.unknown {
                    Value::unknown(64)
                } else {
                    Value::known(64, self.address)
                }
            }
            "a64.sp" => Value::known(64, self.address),
            "a64.gpr" => Value::known(64, 0xfedcba9876543281),
            _ => panic!("unexpected register {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("ordinary memory fallback")
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        previous: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        assert!(previous.is_empty());
        self.calls.borrow_mut().push(r.clone());
        if self.fault {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Permission));
        }
        Ok(AtomicObservation {
            old: matches!(r.kind, AtomicRequestKind::Load)
                .then(|| Value::known(r.width, 0xfedcba9876543281)),
            store_succeeded: None,
            reservation_token: None,
            witness: 42,
        })
    }
}
fn state() -> State {
    State {
        address: 0x2001,
        unknown: false,
        enforce_sp: false,
        fault: false,
        calls: RefCell::new(vec![]),
    }
}
fn output(t: &Transition, n: u16) -> Option<u64> {
    t.registers
        .iter()
        .find(|w| w.register.bank == "a64.gpr" && w.register.index == n)
        .map(|w| w.value.bits)
}
#[test]
fn every_lor_form_endian_register_and_zero_register_retains_one_exact_event() {
    for size in 0..4 {
        let width = 8u8 << size;
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        for load in [false, true] {
            for endian in [Endian::Little, Endian::Big] {
                for t in [0, 4, 5, 30, 31] {
                    for n in [5, 31] {
                        let word = (if load { 0x08df7c00 } else { 0x089f7c00 })
                            | (size << 30)
                            | (n << 5)
                            | t;
                        let r = recipe(word, 128, endian).unwrap();
                        assert_eq!(r.support, Support::Full);
                        r.validate().unwrap();
                        let s = state();
                        let transition = evaluate(&r, &s).unwrap();
                        let requests = s.calls.borrow();
                        assert_eq!(requests.len(), 1);
                        let request = &requests[0];
                        assert_eq!(request.address, s.address);
                        assert_eq!(request.width, width);
                        assert_eq!(request.endian, endian);
                        assert_eq!(request.privilege, MemoryPrivilege::Current);
                        assert_eq!(request.scope, MemoryScope::System);
                        assert_eq!(
                            request.ordering,
                            if load {
                                MemoryOrdering::AcquireLimited
                            } else {
                                MemoryOrdering::ReleaseLimited
                            }
                        );
                        assert_eq!(transition.atomics.len(), 1);
                        assert!(transition.memory.is_empty());
                        assert_eq!(
                            transition.atomics[0].monitor,
                            ExclusiveMonitorEffect::Preserved
                        );
                        if load {
                            assert_eq!(
                                output(&transition, t as u16),
                                if t == 31 {
                                    None
                                } else {
                                    Some(0xfedcba9876543281 & mask)
                                }
                            );
                        } else {
                            let value = if t == 31 {
                                0
                            } else if t == 5 {
                                s.address
                            } else {
                                0xfedcba9876543281
                            };
                            assert_eq!(
                                transition.atomics[0].stored,
                                Some(Value::known(width, value))
                            );
                            assert!(transition.registers.is_empty());
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn lor_sp_preflight_unknown_and_permission_failure_publish_no_transition() {
    for size in 0..4 {
        for load in [false, true] {
            let word = (if load { 0x08df7c00 } else { 0x089f7c00 }) | (size << 30) | (31 << 5) | 4;
            let r = recipe(word, 128, Endian::Little).unwrap();
            let mut s = state();
            s.enforce_sp = true;
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.trap, Some(TrapKind::Protection));
            assert!(t.registers.is_empty());
            assert!(t.atomics.is_empty());
            assert!(s.calls.borrow().is_empty());
            s.enforce_sp = false;
            s.fault = true;
            assert!(matches!(
                evaluate(&r, &s),
                Err(EvalError::MemoryFault(MemoryFaultKind::Permission))
            ));
            assert_eq!(s.calls.borrow().len(), 1);
            let word = (word & !(31 << 5)) | (5 << 5);
            let r = recipe(word, 128, Endian::Little).unwrap();
            let mut s = state();
            s.unknown = true;
            assert!(evaluate(&r, &s).is_err());
            assert!(s.calls.borrow().is_empty());
        }
    }
}
#[test]
fn limited_ordering_rejects_wrong_direction_exclusive_rmw_pair_and_cas() {
    let memory = Memory {
        kind: Default::default(), privilege: MemoryPrivilege::Current,
        address: Box::new(Expr::constant(64, 0x2000)),
        width: 64,
        endian: Endian::Little,
    };
    for order in [
        MemoryOrdering::AcquireLimited,
        MemoryOrdering::ReleaseLimited,
    ] {
        let kinds = vec![
            AtomicOperationKind::LoadLinked,
            AtomicOperationKind::StoreConditional {
                value: Expr::constant(64, 1),
            },
            AtomicOperationKind::ReadModifyWrite {
                operation: AtomicRmwOp::Exchange,
                value: Expr::constant(64, 1),
            },
            AtomicOperationKind::CompareExchange {
                expected: Expr::constant(64, 0),
                replacement: Expr::constant(64, 1),
                failure_ordering: MemoryOrdering::Monotonic,
            },
            if order == MemoryOrdering::AcquireLimited {
                AtomicOperationKind::Store {
                    value: Expr::constant(64, 1),
                }
            } else {
                AtomicOperationKind::Load
            },
        ];
        for kind in kinds {
            let mut r = Recipe::new(0x1004, 64);
            r.atomic(AtomicOperation {
                memory: memory.clone(),
                ordering: order,
                scope: MemoryScope::System,
                kind,
            });
            assert!(r.validate().is_err());
        }
        let mut r = Recipe::new(0x1004, 64);
        r.atomic(AtomicOperation {
            memory: Memory {
                kind: Default::default(), width: 128,
                ..memory.clone()
            },
            ordering: order,
            scope: MemoryScope::System,
            kind: AtomicOperationKind::LoadPair,
        });
        assert!(r.validate().is_err());
    }
}

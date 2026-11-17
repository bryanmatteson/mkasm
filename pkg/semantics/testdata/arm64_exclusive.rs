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
    x: [u64; 32],
    sp: u64,
    monitor: Option<ExclusiveReservation>,
    torn: bool,
    fail_sc: bool,
    bad: bool,
    fault: Option<usize>,
    reads: RefCell<Vec<(u64, u8)>>,
}
impl State {
    fn new() -> Self {
        Self {
            x: [0x2000; 32],
            sp: 0x2000,
            monitor: None,
            torn: false,
            fail_sc: false,
            bad: false,
            fault: None,
            reads: RefCell::new(vec![]),
        }
    }
    fn observe(&self, address: u64, width: u8) -> Result<(), EvalError> {
        let i = self.reads.borrow().len();
        self.reads.borrow_mut().push((address, width));
        if self.fault == Some(i) {
            Err(EvalError::UnsupportedContext)
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, t: &Transition) {
        for a in &t.atomics {
            match a.monitor {
                ExclusiveMonitorEffect::Set(m) => self.monitor = Some(m),
                ExclusiveMonitorEffect::Cleared => self.monitor = None,
                _ => {}
            }
        }
        for r in &t.registers {
            if r.register.bank == "a64.gpr" {
                self.x[r.register.index as usize] = r.value.bits;
            }
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => Value::known(64, self.x[r.index as usize]),
            "a64.sp" => Value::known(64, self.sp),
            "a64.sp_alignment_enforced" => Value::known(1, 1),
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("ordinary fallback")
    }
    fn read_exclusive_monitor(&self) -> Result<Option<ExclusiveReservation>, EvalError> {
        Ok(self.monitor)
    }
    fn evaluate_exclusive_pair(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<ExclusivePairObservation, EvalError> {
        assert!(p.is_empty());
        assert_eq!(r.kind, AtomicRequestKind::LoadLinkedPairSplit);
        assert_eq!(r.width, 128);
        self.observe(r.address, 64)?;
        self.observe(r.address + 8, 64)?;
        let address_values = [
            0x1111222233334444,
            if self.torn {
                0xaaaabbbbccccdddd
            } else {
                0x5555666677778888
            },
        ];
        let [low, high] = if r.endian == Endian::Little {
            address_values
        } else {
            [address_values[1], address_values[0]]
        };
        Ok(ExclusivePairObservation {
            low: Value::known(64, low),
            high: Value::known(if self.bad { 32 } else { 64 }, high),
            reservation_token: 7,
            witnesses: [101, if self.torn { 103 } else { 102 }],
        })
    }
    fn evaluate_atomic_pair(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicPairObservation, EvalError> {
        assert!(p.is_empty());
        assert_eq!(r.width, 128);
        let load = matches!(r.kind, AtomicRequestKind::LoadLinkedPair);
        if load {
            self.observe(r.address, 128)?;
        } else {
            assert!(matches!(
                r.kind,
                AtomicRequestKind::StoreConditionalPair { .. }
            ));
        }
        Ok(AtomicPairObservation {
            observation: AtomicObservation {
                old: load.then(|| Value::known(64, 11)),
                store_succeeded: (!load).then(|| {
                    !self.torn
                        && !self.fail_sc
                        && r.reservation.is_some_and(|m| {
                            m.token == 7 && m.address == r.address && m.width == 128
                        })
                }),
                reservation_token: load.then_some(7),
                witness: 100,
            },
            old_high: load.then(|| Value::known(64, 22)),
        })
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        assert!(p.is_empty());
        let load = matches!(r.kind, AtomicRequestKind::LoadLinked);
        if load {
            self.observe(r.address, r.width)?;
        } else {
            assert!(matches!(r.kind, AtomicRequestKind::StoreConditional { .. }));
        }
        Ok(AtomicObservation {
            old: load.then(|| Value::known(r.width, 0x7766554433221100)),
            reservation_token: load.then_some(7),
            store_succeeded: (!load).then(|| {
                !self.fail_sc
                    && r.reservation.is_some_and(|m| {
                        m.token == 7 && m.address == r.address && m.width == r.width
                    })
            }),
            witness: 100,
        })
    }
}
fn output(t: &Transition, n: u32) -> Option<u64> {
    t.registers
        .iter()
        .find(|r| r.register.bank == "a64.gpr" && r.register.index == n as u16)
        .map(|r| r.value.bits)
}
#[test]
fn exclusive_pair_loads_all_registers_aliases_orders_and_observation_profiles() {
    for endian in [Endian::Little, Endian::Big] {
        for bits in [32, 64] {
            for acquire in [false, true] {
                for t in 0..32 {
                    for t2 in 0..32 {
                        for n in [t, t2, 31] {
                            let word = 0x887f0000
                                | if bits == 64 { 1 << 30 } else { 0 }
                                | if acquire { 1 << 15 } else { 0 }
                                | t
                                | t2 << 10
                                | n << 5;
                            let s = State::new();
                            let r = recipe(word, 128, endian).unwrap();
                            assert_eq!(r.support, Support::Full);
                            r.validate().unwrap();
                            let tr = evaluate(&r, &s).unwrap();
                            if t == t2 {
                                assert!(s.reads.borrow().is_empty());
                                assert!(tr.atomics.is_empty());
                                continue;
                            }
                            let a = &tr.atomics[0];
                            let req = a.request.as_ref().unwrap();
                            assert_eq!(
                                req.ordering,
                                if acquire {
                                    MemoryOrdering::Acquire
                                } else {
                                    MemoryOrdering::Monotonic
                                }
                            );
                            let expected = if bits == 64 {
                                [0x1111222233334444, 0x5555666677778888]
                            } else if endian == Endian::Little {
                                [0x33221100, 0x77665544]
                            } else {
                                [0x77665544, 0x33221100]
                            };
                            for (n, v) in [(t, expected[0]), (t2, expected[1])] {
                                if n != 31 {
                                    assert_eq!(output(&tr, n), Some(v));
                                }
                            }
                            assert_eq!(
                                a.monitor,
                                ExclusiveMonitorEffect::Set(ExclusiveReservation {
                                    address: 0x2000,
                                    width: bits * 2,
                                    scope: MemoryScope::System,
                                    token: 7
                                })
                            );
                            if bits == 64 {
                                assert_eq!(*s.reads.borrow(), [(0x2000, 64), (0x2008, 64)]);
                                assert_eq!(a.split_pair_witnesses, Some([101, 102]));
                            } else {
                                assert_eq!(*s.reads.borrow(), [(0x2000, 64)]);
                                assert_eq!(a.split_pair_witnesses, None);
                            }
                        }
                    }
                }
            }
        }
        let s = State::new();
        let r = arm64_atomics::a64_with_context(
            0xc87f0440,
            0x1000,
            endian,
            arm64_atomics::AtomicContext {
                exclusive_pair_atomic: true,
            },
        )
        .unwrap();
        let tr = evaluate(&r, &s).unwrap();
        assert_eq!(*s.reads.borrow(), [(0x2000, 128)]);
        assert_eq!(tr.atomics[0].split_pair_witnesses, None);
    }
}
#[test]
fn torn_observations_preserve_one_reservation_and_force_conditional_store_failure() {
    for endian in [Endian::Little, Endian::Big] {
        for torn in [false, true] {
            for spurious in [false, true] {
                let mut s = State::new();
                s.torn = torn;
                s.fail_sc = spurious;
                let load = recipe(0xc87f0440, 128, endian).unwrap();
                let t = evaluate(&load, &s).unwrap();
                s.commit(&t);
                assert_eq!(s.x[0], 0x1111222233334444);
                assert_eq!(
                    s.x[1],
                    if torn {
                        0xaaaabbbbccccdddd
                    } else {
                        0x5555666677778888
                    }
                );
                assert_eq!(
                    t.atomics[0].split_pair_witnesses,
                    Some([101, if torn { 103 } else { 102 }])
                );
                let store = recipe(0xc8230440, 128, endian).unwrap();
                let tr = evaluate(&store, &s).unwrap();
                let success = !torn && !spurious;
                assert_eq!(output(&tr, 3), Some(u64::from(!success)));
                assert_eq!(tr.atomics[0].success, Some(success));
                assert_eq!(tr.atomics[0].stored.is_some(), success);
                assert_eq!(tr.atomics[0].stored_high.is_some(), success);
                assert_eq!(tr.atomics[0].monitor, ExclusiveMonitorEffect::Cleared);
                s.commit(&tr);
                assert_eq!(s.monitor, None);
            }
        }
    }
}
#[test]
fn faults_constrained_nops_and_missing_split_capability_are_explicit() {
    for i in 0..2 {
        let mut s = State::new();
        s.fault = Some(i);
        let r = recipe(0xc87f0440, 128, Endian::Little).unwrap();
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
        assert_eq!(s.monitor, None);
        assert_eq!(s.reads.borrow().len(), i + 1);
    }
    // Every permitted NOP is selected before SP checks, source reads or monitor changes.
    for word in [0xc87f03e0, 0xc82003e0, 0xc8207fe0, 0xc81f7fff] {
        let mut s = State::new();
        s.sp = 1;
        let r = recipe(word, 128, Endian::Little).unwrap();
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(t.trap, None, "{word:08x}");
        assert!(t.atomics.is_empty());
        assert!(s.reads.borrow().is_empty());
    }
    let mut malformed = State::new();
    malformed.bad = true;
    assert_eq!(
        evaluate(
            &recipe(0xc87f0440, 128, Endian::Little).unwrap(),
            &malformed
        ),
        Err(EvalError::InvalidAtomicOutcome)
    );
    struct ScalarOnly;
    impl Machine for ScalarOnly {
        fn read_register(&self, _: Register) -> Value {
            Value::known(64, 0x2000)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!()
        }
    }
    assert_eq!(
        evaluate(
            &recipe(0xc87f0440, 128, Endian::Little).unwrap(),
            &ScalarOnly
        ),
        Err(EvalError::Unsupported)
    );
}

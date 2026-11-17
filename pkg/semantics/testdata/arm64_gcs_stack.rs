#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::BTreeMap};
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_gcs_stack::a64(word, 0x1000, endian)
}
struct State {
    gpr: [u64; 31],
    pointer: u64,
    present: bool,
    enabled: bool,
    permitted: bool,
    check: bool,
    el: u64,
    spsr: u64,
    elr: u64,
    exlock: bool,
    exlocken: bool,
    bytes: BTreeMap<u64, u8>,
    reads: RefCell<Vec<u64>>,
    fault: Option<u64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            gpr: [0; 31],
            pointer: 0x3000,
            present: true,
            enabled: true,
            permitted: true,
            check: true,
            el: 1,
            spsr: 0x123456,
            elr: 0x1004,
            exlock: true,
            exlocken: true,
            bytes: BTreeMap::new(),
            reads: RefCell::new(vec![]),
            fault: None,
        }
    }
}
impl State {
    fn store(&mut self, address: u64, value: u64, endian: Endian) {
        let bytes = if endian == Endian::Little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        for (i, b) in bytes.into_iter().enumerate() {
            self.bytes.insert(address + i as u64, b);
        }
    }
    fn apply(&mut self, t: &Transition) {
        assert!(t.trap.is_none());
        for w in &t.registers {
            match w.register.bank {
                "a64.gpr" => self.gpr[w.register.index as usize] = w.value.bits,
                "a64.gcs_pointer" => self.pointer = w.value.bits,
                "a64.gcs_exlock" => self.exlock = w.value.bits != 0,
                _ => {}
            }
        }
        for w in &t.memory {
            assert!(w.guarded_control_stack);
            self.store(w.address, w.value.bits, w.endian);
        }
        for a in &t.atomics {
            if let (Some(request), Some(value)) = (&a.request, a.stored) {
                assert_eq!(request.memory_kind, MemoryKind::GuardedControlStack);
                self.store(request.address, value.bits, request.endian);
            }
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        let (w, v) = match r.bank {
            "a64.pauth_present" | "a64.pauth_lr_present" => (1, 1),
            "a64.pac_key_enabled" | "a64.pacm" => (1, 0),
            "a64.gpr" => (64, self.gpr[r.index as usize]),
            "a64.gcs_pointer" => (64, self.pointer),
            "a64.gcs_spsr" => (64, self.spsr),
            "a64.gcs_elr" => (64, self.elr),
            "a64.current_el" => (2, self.el),
            "a64.gcs_present" => (1, self.present as u64),
            "a64.gcs_enabled" => (1, self.enabled as u64),
            "a64.gcs_stack_permitted" => (1, self.permitted as u64),
            "a64.gcs_return_check" => (1, self.check as u64),
            "a64.gcs_exlock" => (1, self.exlock as u64),
            "a64.gcs_exlock_enabled" => (1, self.exlocken as u64),
            _ => panic!("unexpected register {r:?}"),
        };
        Value::known(w, v)
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("GCS downgraded to ordinary bytes")
    }
    fn read_guarded_control_stack(
        &self,
        address: u64,
        endian: Endian,
        _: MemoryPrivilege,
    ) -> Result<Value, EvalError> {
        self.reads.borrow_mut().push(address);
        if address % 8 != 0 {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Alignment));
        }
        if self.fault == Some(address) {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Permission));
        }
        let mut bytes = [0; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self
                .bytes
                .get(&(address + i as u64))
                .ok_or(EvalError::MemoryFault(MemoryFaultKind::Translation))?;
        }
        Ok(Value::known(
            64,
            if endian == Endian::Little {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            },
        ))
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        pending: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        assert!(pending.is_empty());
        assert_eq!(r.memory_kind, MemoryKind::GuardedControlStack);
        assert!(matches!(r.kind, AtomicRequestKind::CompareExchange { .. }));
        assert_eq!(r.ordering, MemoryOrdering::Monotonic);
        Ok(AtomicObservation {
            old: Some(self.read_guarded_control_stack(r.address, r.endian, r.privilege)?),
            store_succeeded: None,
            reservation_token: None,
            witness: 73,
        })
    }
}
#[test]
fn all_stack_aliases_preserve_sources_discarded_destinations_and_byte_order() {
    for endian in [Endian::Little, Endian::Big] {
        for t in 0..32 {
            let mut s = State::default();
            s.gpr.fill(0x123456789abcdef0);
            let push = recipe(0xd50b7700 | t, 128, endian).unwrap();
            push.validate().unwrap();
            let out = evaluate(&push, &s).unwrap();
            assert_eq!(out.memory.len(), 1);
            assert!(out.memory[0].guarded_control_stack);
            assert_eq!(out.memory[0].address, 0x2ff8);
            assert_eq!(
                out.memory[0].value.bits,
                if t == 31 { 0 } else { s.gpr[t as usize] }
            );
            s.apply(&out);
            assert_eq!(s.pointer, 0x2ff8);
            let pop = recipe(0xd52b7720 | t, 128, endian).unwrap();
            let out = evaluate(&pop, &s).unwrap();
            assert!(out.trap.is_none());
            assert_eq!(s.reads.borrow().as_slice(), &[0x2ff8]);
            s.apply(&out);
            assert_eq!(s.pointer, 0x3000);
            if t != 31 {
                assert_eq!(s.gpr[t as usize], 0x123456789abcdef0);
            }
        }
    }
}
#[test]
fn stack_switch_is_one_protected_cas_then_validated_token_and_barrier() {
    for endian in [Endian::Little, Endian::Big] {
        for t in [0, 30] {
            for valid in [false, true] {
                let mut s = State::default();
                s.gpr[t as usize] = 0x4000;
                s.store(0x4000, if valid { 0x4001 } else { 0x4000 }, endian);
                let first = evaluate(&recipe(0xd50b7740 | t, 128, endian).unwrap(), &s).unwrap();
                assert_eq!(first.atomics.len(), 1);
                assert_eq!(first.atomics[0].observation.as_ref().unwrap().witness, 73);
                if !valid {
                    assert_eq!(first.trap, Some(TrapKind::AArch64GcsSwitch1));
                    assert!(first.atomics[0].stored.is_none());
                    assert!(first.registers.is_empty());
                    continue;
                }
                s.apply(&first);
                assert_eq!(s.pointer, 0x4000);
                let second = evaluate(&recipe(0xd52b7760 | t, 128, endian).unwrap(), &s).unwrap();
                assert_eq!(second.memory[0].address, 0x2ff8);
                assert_eq!(second.memory[0].value.bits, 0x2001);
                assert!(matches!(
                    second.events.as_slice(),
                    [
                        OrderedEvent::Store(0),
                        OrderedEvent::Barrier(Barrier {
                            kind: BarrierKind::GuardedControlStackSynchronization,
                            ..
                        })
                    ]
                ));
                s.apply(&second);
                assert_eq!(s.pointer, 0x4008);
                assert_eq!(s.gpr[t as usize], 0x2ff8);
            }
        }
    }
}
#[test]
fn exception_records_preserve_order_and_stop_reading_at_the_first_bad_field() {
    for endian in [Endian::Little, Endian::Big] {
        let mut s = State::default();
        s.gpr[30] = 0x8000;
        let push = evaluate(&recipe(0xd508779f, 128, endian).unwrap(), &s).unwrap();
        assert_eq!(
            push.memory.iter().map(|m| m.address).collect::<Vec<_>>(),
            vec![0x2ff8, 0x2ff0, 0x2fe8, 0x2fe0]
        );
        s.apply(&push);
        assert!(!s.exlock);
        for bad in 0..4 {
            let mut case = State::default();
            case.gpr[30] = s.gpr[30];
            case.pointer = s.pointer;
            case.bytes = s.bytes.clone();
            case.store(s.pointer + bad * 8, 0xdead, endian);
            let pop = evaluate(&recipe(0xd50877bf, 128, endian).unwrap(), &case).unwrap();
            assert_eq!(pop.trap, Some(TrapKind::AArch64GcsPopCompareException));
            assert_eq!(case.reads.borrow().len(), bad as usize + 1);
            assert!(pop.registers.is_empty());
        }
        s.reads.borrow_mut().clear();
        let pop = evaluate(&recipe(0xd50877bf, 128, endian).unwrap(), &s).unwrap();
        assert_eq!(s.reads.borrow().len(), 4);
        s.apply(&pop);
        assert_eq!(s.pointer, 0x3000);
        assert!(s.exlock);
        s.pointer = 0x2fe0;
        s.fault = Some(0x2ff8);
        assert_eq!(
            evaluate(&recipe(0xd50877df, 128, endian).unwrap(), &s),
            Err(EvalError::MemoryFault(MemoryFaultKind::Permission))
        );
    }
}
#[test]
fn feature_permission_format_and_privilege_checks_precede_memory() {
    for base in [
        0xd50b7700, 0xd52b7720, 0xd50b7740, 0xd52b7760, 0xd5087780, 0xd50877a0, 0xd50877c0,
    ] {
        let mut s = State::default();
        s.present = false;
        assert_eq!(
            evaluate(&recipe(base, 128, Endian::Little).unwrap(), &s)
                .unwrap()
                .trap,
            Some(TrapKind::InvalidInstruction)
        );
        s.present = true;
        s.permitted = false;
        assert_eq!(
            evaluate(&recipe(base, 128, Endian::Little).unwrap(), &s)
                .unwrap()
                .trap,
            Some(TrapKind::Protection)
        );
        assert!(s.reads.borrow().is_empty());
        if base & 0xfffff800 == 0xd5087000 {
            s.permitted = true;
            s.el = 0;
            assert_eq!(
                evaluate(&recipe(base, 128, Endian::Little).unwrap(), &s)
                    .unwrap()
                    .trap,
                Some(TrapKind::Protection)
            );
            assert!(s.reads.borrow().is_empty());
        }
    }
    for (base, value, kind) in [
        (0xd52b7720, 3, TrapKind::AArch64GcsPop),
        (0xd52b7760, 1, TrapKind::AArch64GcsSwitch2),
    ] {
        let mut s = State::default();
        s.store(s.pointer, value, Endian::Little);
        let t = evaluate(&recipe(base, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(kind));
        assert!(t.memory.is_empty() && t.registers.is_empty());
    }
}
#[test]
fn implicit_calls_and_returns_gate_memory_and_use_checked_or_recorded_address() {
    for enabled in [false, true] {
        for check in [false, true] {
            for matching in [false, true] {
                let mut s = State::default();
                s.enabled = enabled;
                s.check = check;
                s.gpr[0] = 0x8000;
                let mut call = Recipe::new(0x1004, 64);
                call.flow.kind = FlowKind::Call;
                call.flow.condition = Expr::constant(1, 1);
                call.flow.target = Expr::constant(64, 0x8000);
                let call = arm64_gcs_stack::complete(0x94000001, call, Endian::Little);
                let t = evaluate(&call, &s).unwrap();
                assert_eq!(t.next_pc, Value::known(64, 0x8000));
                assert_eq!(t.memory.len(), enabled as usize);
                s.apply(&t);
                assert_eq!(s.pointer, if enabled { 0x2ff8 } else { 0x3000 });
                if enabled {
                    s.store(
                        s.pointer,
                        if matching { 0x1004 } else { 0x9000 },
                        Endian::Little,
                    );
                }
                let mut ret = Recipe::new(0x8004, 64);
                ret.flow.kind = FlowKind::Return;
                ret.flow.condition = Expr::constant(1, 1);
                ret.flow.target = Expr::constant(64, 0x1004);
                let ret = arm64_gcs_stack::complete(0xd65f03c0, ret, Endian::Little);
                let t = evaluate(&ret, &s).unwrap();
                if enabled && check && !matching {
                    assert_eq!(t.trap, Some(TrapKind::AArch64GcsReturn));
                    assert!(t.registers.is_empty());
                } else {
                    assert_eq!(
                        t.next_pc,
                        Value::known(64, if enabled && !matching { 0x9000 } else { 0x1004 })
                    );
                    s.apply(&t);
                    assert_eq!(s.pointer, 0x3000);
                }
            }
        }
    }
}

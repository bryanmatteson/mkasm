#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_lsui::a64(word, 0x1000, endian)
}
const CASES: &[(u32, u8, u8)] = &[
    (0x49807c00, 1, 64),  // CASPT_CP64_comswappr_unpriv
    (0x49c07c00, 1, 64),  // CASPAT_CP64_comswappr_unpriv
    (0x49c0fc00, 1, 64),  // CASPALT_CP64_comswappr_unpriv
    (0x4980fc00, 1, 64),  // CASPLT_CP64_comswappr_unpriv
    (0xc9807c00, 0, 64),  // CAST_C64_comswap_unpriv
    (0xc9c07c00, 0, 64),  // CASAT_C64_comswap_unpriv
    (0xc9c0fc00, 0, 64),  // CASALT_C64_comswap_unpriv
    (0xc980fc00, 0, 64),  // CASLT_C64_comswap_unpriv
    (0x89408000, 2, 32),  // LDATXR_LR32_ldstexclr_unpriv
    (0xc9408000, 2, 64),  // LDATXR_LR64_ldstexclr_unpriv
    (0x19200400, 4, 32),  // LDTADD_32_memop_unpriv
    (0x19a00400, 4, 32),  // LDTADDA_32_memop_unpriv
    (0x19e00400, 4, 32),  // LDTADDAL_32_memop_unpriv
    (0x19600400, 4, 32),  // LDTADDL_32_memop_unpriv
    (0x59200400, 4, 64),  // LDTADD_64_memop_unpriv
    (0x59a00400, 4, 64),  // LDTADDA_64_memop_unpriv
    (0x59e00400, 4, 64),  // LDTADDAL_64_memop_unpriv
    (0x59600400, 4, 64),  // LDTADDL_64_memop_unpriv
    (0x19201400, 4, 32),  // LDTCLR_32_memop_unpriv
    (0x19a01400, 4, 32),  // LDTCLRA_32_memop_unpriv
    (0x19e01400, 4, 32),  // LDTCLRAL_32_memop_unpriv
    (0x19601400, 4, 32),  // LDTCLRL_32_memop_unpriv
    (0x59201400, 4, 64),  // LDTCLR_64_memop_unpriv
    (0x59a01400, 4, 64),  // LDTCLRA_64_memop_unpriv
    (0x59e01400, 4, 64),  // LDTCLRAL_64_memop_unpriv
    (0x59601400, 4, 64),  // LDTCLRL_64_memop_unpriv
    (0xec400000, 5, 128), // LDTNP_Q_ldstnapair_offs
    (0xe8400000, 5, 64),  // LDTNP_64_ldstnapair_offs
    (0xecc00000, 5, 128), // LDTP_Q_ldstpair_post
    (0xedc00000, 5, 128), // LDTP_Q_ldstpair_pre
    (0xed400000, 5, 128), // LDTP_Q_ldstpair_off
    (0xe8c00000, 5, 64),  // LDTP_64_ldstpair_post
    (0xe9c00000, 5, 64),  // LDTP_64_ldstpair_pre
    (0xe9400000, 5, 64),  // LDTP_64_ldstpair_off
    (0x19203400, 4, 32),  // LDTSET_32_memop_unpriv
    (0x19a03400, 4, 32),  // LDTSETA_32_memop_unpriv
    (0x19e03400, 4, 32),  // LDTSETAL_32_memop_unpriv
    (0x19603400, 4, 32),  // LDTSETL_32_memop_unpriv
    (0x59203400, 4, 64),  // LDTSET_64_memop_unpriv
    (0x59a03400, 4, 64),  // LDTSETA_64_memop_unpriv
    (0x59e03400, 4, 64),  // LDTSETAL_64_memop_unpriv
    (0x59603400, 4, 64),  // LDTSETL_64_memop_unpriv
    (0x89400000, 2, 32),  // LDTXR_LR32_ldstexclr_unpriv
    (0xc9400000, 2, 64),  // LDTXR_LR64_ldstexclr_unpriv
    (0x89008000, 3, 32),  // STLTXR_SR32_ldstexclr_unpriv
    (0xc9008000, 3, 64),  // STLTXR_SR64_ldstexclr_unpriv
    (0xec000000, 5, 128), // STTNP_Q_ldstnapair_offs
    (0xe8000000, 5, 64),  // STTNP_64_ldstnapair_offs
    (0xec800000, 5, 128), // STTP_Q_ldstpair_post
    (0xed800000, 5, 128), // STTP_Q_ldstpair_pre
    (0xed000000, 5, 128), // STTP_Q_ldstpair_off
    (0xe8800000, 5, 64),  // STTP_64_ldstpair_post
    (0xe9800000, 5, 64),  // STTP_64_ldstpair_pre
    (0xe9000000, 5, 64),  // STTP_64_ldstpair_off
    (0x89000000, 3, 32),  // STTXR_SR32_ldstexclr_unpriv
    (0xc9000000, 3, 64),  // STTXR_SR64_ldstexclr_unpriv
    (0x19208400, 4, 32),  // SWPT_32_memop_unpriv
    (0x19a08400, 4, 32),  // SWPTA_32_memop_unpriv
    (0x19e08400, 4, 32),  // SWPTAL_32_memop_unpriv
    (0x19608400, 4, 32),  // SWPTL_32_memop_unpriv
    (0x59208400, 4, 64),  // SWPT_64_memop_unpriv
    (0x59a08400, 4, 64),  // SWPTA_64_memop_unpriv
    (0x59e08400, 4, 64),  // SWPTAL_64_memop_unpriv
    (0x59608400, 4, 64),  // SWPTL_64_memop_unpriv
];
struct State {
    address: u64,
    old: [u64; 4],
    success: bool,
    reservation_width: u8,
    fault: bool,
    unknown: bool,
    calls: Cell<usize>,
}
fn state() -> State {
    State {
        address: 0x2000,
        old: [0x12, 0x13, 0x24, 0x25],
        success: true,
        reservation_width: 64,
        fault: false,
        unknown: false,
        calls: Cell::new(0),
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => {
                if r.index == 5 {
                    if self.unknown {
                        Value::unknown(64)
                    } else {
                        Value::known(64, self.address)
                    }
                } else {
                    Value::known(64, 0x10 + u64::from(r.index))
                }
            }
            "a64.sp" => Value::known(64, self.address),
            "a64.sp_alignment_enforced" => Value::known(1, 1),
            "a64.vector64" => Value::known(64, 0x100 + u64::from(r.index)),
            _ => panic!("unexpected register {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("ordinary access lost LSUI privilege")
    }
    fn read_wide_memory_for_access(
        &self,
        address: u64,
        width: u16,
        _: Endian,
        p: MemoryPrivilege,
    ) -> Result<Vec<Value>, EvalError> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(p, MemoryPrivilege::AArch64Unprivileged);
        assert!((0x1c00..=0x2400).contains(&address));
        if self.fault {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Permission));
        }
        Ok(self.old[..usize::from(width / 64)]
            .iter()
            .map(|&v| Value::known(64, v))
            .collect())
    }
    fn read_exclusive_monitor(&self) -> Result<Option<ExclusiveReservation>, EvalError> {
        Ok(Some(ExclusiveReservation {
            address: self.address,
            width: self.reservation_width,
            scope: MemoryScope::System,
            token: 99,
        }))
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        self.calls.set(self.calls.get() + 1);
        assert!(p.is_empty());
        assert_eq!(r.privilege, MemoryPrivilege::AArch64Unprivileged);
        assert_eq!(r.address, self.address);
        if self.fault {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Permission));
        }
        let conditional = matches!(r.kind, AtomicRequestKind::StoreConditional { .. });
        Ok(AtomicObservation {
            old: if conditional {
                None
            } else {
                Some(Value::known(r.width.min(64), self.old[0]))
            },
            store_succeeded: conditional.then_some(self.success),
            reservation_token: matches!(r.kind, AtomicRequestKind::LoadLinked).then_some(99),
            witness: 7,
        })
    }
    fn evaluate_atomic_pair(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicPairObservation, EvalError> {
        let observation = self.evaluate_atomic(r, p)?;
        Ok(AtomicPairObservation {
            observation,
            old_high: Some(Value::known(64, self.old[1])),
        })
    }
}
fn written(t: &Transition, bank: &str, index: u16) -> Option<u64> {
    t.registers
        .iter()
        .find(|w| w.register.bank == bank && w.register.index == index)
        .map(|w| w.value.bits)
}
fn ordering(a: bool, r: bool) -> MemoryOrdering {
    match (a, r) {
        (false, false) => MemoryOrdering::Monotonic,
        (true, false) => MemoryOrdering::Acquire,
        (false, true) => MemoryOrdering::Release,
        _ => MemoryOrdering::AcquireRelease,
    }
}
#[test]
fn all_atomic_forms_orders_endian_results_and_failures() {
    for &(base, family, width) in CASES.iter().filter(|c| c.1 != 5) {
        for endian in [Endian::Little, Endian::Big] {
            for success in [false, true] {
                let mut word = base | (2 << 16) | (5 << 5) | 4;
                if family == 2 {
                    word |= (31 << 16) | (31 << 10);
                }
                if family == 3 {
                    word |= 31 << 10;
                }
                let r = recipe(word, 128, endian).unwrap();
                r.validate().unwrap();
                assert_eq!(r.support, Support::Full);
                let mut s = state();
                s.success = success;
                s.reservation_width = width;
                if family == 1 && endian == Endian::Big {
                    s.old.swap(0, 1);
                }
                if !success && family < 2 {
                    s.old[0] = 0xff;
                }
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(t.next_pc, Value::known(64, 0x1004));
                assert_eq!(s.calls.get(), 1);
                assert!(t.memory.is_empty() && t.wide_memory.is_empty());
                assert_eq!(t.events, [OrderedEvent::Atomic(0)]);
                let a = &t.atomics[0];
                let q = a.request.as_ref().unwrap();
                assert_eq!(q.width, if family == 1 { 128 } else { width });
                assert_eq!(q.endian, endian);
                assert_eq!(q.scope, MemoryScope::System);
                let acquire = match family {
                    0 | 1 => base & (1 << 22) != 0,
                    2 => base & (1 << 15) != 0,
                    3 => false,
                    _ => base & (1 << 23) != 0,
                };
                let release = match family {
                    0 | 1 | 3 => base & (1 << 15) != 0,
                    2 => false,
                    _ => base & (1 << 22) != 0,
                };
                assert_eq!(q.ordering, ordering(acquire, release));
                match family {
                    0 | 1 => {
                        assert_eq!(a.success, Some(success));
                        assert_eq!(a.stored.is_some(), success);
                        if success {
                            assert_eq!(
                                a.stored.unwrap().bits,
                                if family == 1 && endian == Endian::Big {
                                    0x2000
                                } else {
                                    0x14
                                }
                            );
                        }
                        let first = if family == 1 && endian == Endian::Big {
                            s.old[1]
                        } else {
                            s.old[0]
                        };
                        assert_eq!(written(&t, "a64.gpr", 2), Some(first));
                        if family == 1 {
                            assert_eq!(
                                written(&t, "a64.gpr", 3),
                                Some(if endian == Endian::Big {
                                    s.old[0]
                                } else {
                                    s.old[1]
                                })
                            );
                        }
                    }
                    2 => {
                        assert_eq!(written(&t, "a64.gpr", 4), Some(s.old[0]));
                        assert!(matches!(a.monitor, ExclusiveMonitorEffect::Set(_)));
                        assert!(a.stored.is_none());
                    }
                    3 => {
                        assert_eq!(written(&t, "a64.gpr", 2), Some(u64::from(!success)));
                        assert_eq!(a.stored, success.then_some(Value::known(width, 0x14)));
                        assert_eq!(a.monitor, ExclusiveMonitorEffect::Cleared);
                    }
                    _ => {
                        let expected = match (base >> 12) & 15 {
                            0 => 0x24,
                            1 => 0,
                            3 => 0x12,
                            8 => 0x12,
                            _ => panic!(),
                        };
                        assert_eq!(a.stored, Some(Value::known(width, expected)));
                        assert_eq!(written(&t, "a64.gpr", 4), Some(0x12));
                    }
                }
            }
        }
    }
}
#[test]
fn pair_forms_original_width_offsets_writeback_and_vector_zeroing() {
    for &(base, _, width) in CASES.iter().filter(|c| c.1 == 5) {
        for endian in [Endian::Little, Endian::Big] {
            for imm in [-64i32, -1, 0, 1, 63] {
                let word = base | (((imm as u32) & 127) << 15) | (5 << 5) | 4 | (6 << 10);
                let r = recipe(word, 128, endian).unwrap();
                r.validate().unwrap();
                let s = state();
                let t = evaluate(&r, &s).unwrap();
                assert!(t.atomics.is_empty());
                let load = base & (1 << 22) != 0;
                let mode = (base >> 23) & 3;
                let offset = (i64::from(imm) * i64::from(width / 8)) as u64;
                let advanced = 0x2000u64.wrapping_add(offset);
                let address = if mode == 1 { 0x2000 } else { advanced };
                assert_eq!(
                    written(&t, "a64.gpr", 5),
                    if mode == 1 || mode == 3 {
                        Some(advanced)
                    } else {
                        None
                    }
                );
                if load {
                    assert_eq!(s.calls.get(), 1);
                    assert_eq!(r.wide_loads.len(), 1);
                    assert_eq!(r.wide_loads[0].width, u16::from(width) * 2);
                    if width == 64 {
                        assert_eq!(
                            written(&t, "a64.gpr", 4),
                            Some(s.old[if endian == Endian::Little { 0 } else { 1 }])
                        );
                        assert_eq!(
                            written(&t, "a64.gpr", 6),
                            Some(s.old[if endian == Endian::Little { 1 } else { 0 }])
                        );
                    } else {
                        for (dest, at) in [
                            (4u16, if endian == Endian::Little { 0 } else { 2 }),
                            (6, if endian == Endian::Little { 2 } else { 0 }),
                        ] {
                            for k in 0..32 {
                                assert_eq!(
                                    written(&t, "a64.vector64", dest * 32 + k),
                                    Some(if k < 2 { s.old[at + usize::from(k)] } else { 0 })
                                );
                            }
                        }
                    }
                } else {
                    assert_eq!(s.calls.get(), 0);
                    assert_eq!(t.wide_memory.len(), 1);
                    let m = &t.wide_memory[0];
                    assert_eq!(m.address, address);
                    assert_eq!(m.width, u16::from(width) * 2);
                    assert_eq!(m.privilege, MemoryPrivilege::AArch64Unprivileged);
                    let mut expected = if width == 64 {
                        vec![0x14, 0x16]
                    } else {
                        vec![0x180, 0x181, 0x1c0, 0x1c1]
                    };
                    if endian == Endian::Big {
                        if width == 64 {
                            expected.reverse()
                        } else {
                            expected.rotate_left(2)
                        }
                    }
                    assert_eq!(
                        m.chunks.iter().map(|v| v.bits).collect::<Vec<_>>(),
                        expected
                    );
                }
            }
        }
    }
}
#[test]
fn aliases_zero_registers_and_constrained_outcomes() {
    for base in [
        0x19200400, 0x19201400, 0x19203400, 0x59200400, 0x59201400, 0x59203400,
    ] {
        for a in [0, 1 << 23] {
            let r = recipe(base | a | (2 << 16) | (5 << 5) | 31, 128, Endian::Little).unwrap();
            let t = evaluate(&r, &state()).unwrap();
            assert!(t.registers.is_empty());
            assert_eq!(
                t.atomics[0].request.as_ref().unwrap().ordering,
                MemoryOrdering::Monotonic
            );
        }
    }
    for word in [
        0xc9007c00 | (4 << 16) | (5 << 5) | 4,
        0xc9007c00 | (5 << 16) | (5 << 5) | 4,
        0x49807c00 | (3 << 16) | (5 << 5) | 4,
    ] {
        let Some(r) = recipe(word, 128, Endian::Little) else {
            assert_eq!(word, 0x49807c00 | (3 << 16) | (5 << 5) | 4);
            continue; // A generated public decoder may reject this reserved register pair.
        };
        let t = evaluate(&r, &state()).unwrap();
        assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
        assert!(t.atomics.is_empty());
    }
    for word in [
        0xe9400000 | (4 << 10) | (5 << 5) | 4,
        0xe9c00000 | (6 << 10) | (5 << 5) | 5,
    ] {
        let s = state();
        let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).unwrap();
        assert!(t.registers.is_empty() && t.wide_memory.is_empty());
        assert_eq!(s.calls.get(), 0);
    }
    let word = 0xc9c07c00 | (31 << 16) | (5 << 5) | 31;
    let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &state()).unwrap();
    assert!(t.registers.is_empty());
    assert_eq!(
        t.atomics[0].request.as_ref().unwrap().ordering,
        MemoryOrdering::Monotonic
    );
}
#[test]
fn faults_unknown_addresses_and_sp_preflight_do_not_commit() {
    for word in [
        0xc9807c00 | (2 << 16) | (5 << 5) | 4,
        0xe9400000 | (6 << 10) | (5 << 5) | 4,
    ] {
        let r = recipe(word, 128, Endian::Little).unwrap();
        let mut s = state();
        s.fault = true;
        assert_eq!(
            evaluate(&r, &s),
            Err(EvalError::MemoryFault(MemoryFaultKind::Permission))
        );
        s.fault = false;
        s.unknown = true;
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnknownAddress));
    }
    for word in [
        0xc9807c00 | (2 << 16) | (31 << 5) | 4,
        0xe9400000 | (6 << 10) | (31 << 5) | 4,
        0xe9000000 | (6 << 10) | (31 << 5) | 4,
    ] {
        let mut s = state();
        s.address = 0x2001;
        let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::Protection));
        assert_eq!(s.calls.get(), 0);
        assert!(t.registers.is_empty() && t.wide_memory.is_empty());
    }
}
#[test]
fn generic_backends_cannot_erase_unprivileged_policy() {
    struct Ordinary;
    impl Machine for Ordinary {
        fn read_register(&self, _: Register) -> Value {
            Value::known(64, 0x2000)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("must reject before ordinary callback")
        }
    }
    assert_eq!(
        evaluate(
            &recipe(0xe9400000 | (6 << 10) | (5 << 5) | 4, 128, Endian::Little).unwrap(),
            &Ordinary
        ),
        Err(EvalError::Unsupported)
    );
}

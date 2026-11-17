#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const HINTS: &[(u32, BarrierKind, Option<u8>)] = &[
    (0xd503229f, BarrierKind::ConsumptionSpeculativeData, None),
    (0xd50322df, BarrierKind::ClearBranchHistory, Some(0)),
    (0xd50320df, BarrierKind::DataGatheringHint, Some(1)),
    (
        0xd503269f,
        BarrierKind::StoreConcurrentPriorityHint,
        Some(2),
    ),
    (0xd503261f, BarrierKind::StoreSharedKeepHint, Some(3)),
    (0xd503263f, BarrierKind::StoreSharedStreamHint, Some(3)),
    (0xd503265f, BarrierKind::SharedUpdateHint, Some(2)),
    (0xd503267f, BarrierKind::SharedUpdatePriorityHint, Some(2)),
    (0xd503223f, BarrierKind::ProfilingSynchronization, Some(4)),
    (0xd503225f, BarrierKind::TraceSynchronization, Some(5)),
    (0xd503309f, BarrierKind::StoreBypass, None),
    (0xd503349f, BarrierKind::PhysicalStoreBypass, None),
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    let _ = vl;
    system::a64(word, 0x1000)
}
struct State {
    features: u64,
    controls: [Option<u64>; 4],
    x16: Option<u64>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        assert_eq!(r.index, if r.bank == "a64.gpr" { 16 } else { 0 });
        let (width, bits) = match r.bank {
            "a64.system_hint_features" => (8, Some(self.features)),
            "a64.psb_trap" => (1, self.controls[0]),
            "a64.tsb_trap" => (1, self.controls[1]),
            "a64.gcs_enabled" => (1, self.controls[2]),
            "a64.dsb_nxs" => (1, self.controls[3]),
            "a64.gpr" => (64, self.x16),
            _ => panic!("unexpected system input {r:?}"),
        };
        bits.map(|bits| Value::known(width, bits))
            .unwrap_or_else(|| Value::unknown(width))
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("system hint accessed memory")
    }
}
fn barrier(kind: BarrierKind, scope: BarrierScope, access: BarrierAccess) -> OrderedEvent {
    OrderedEvent::Barrier(Barrier {
        kind,
        scope,
        access,
    })
}
#[test]
fn hints_preserve_distinct_events_and_feature_absence_is_a_state_free_nop() {
    for &(word, kind, feature) in HINTS {
        let r = recipe(word, 128).unwrap();
        assert_eq!(r.support, Support::Full);
        r.validate().unwrap();
        for mask in 0..256 {
            let active = feature.map(|f| mask & (1 << f) != 0).unwrap_or(true);
            let state = State {
                features: mask,
                controls: if active { [Some(0); 4] } else { [None; 4] },
                x16: None,
            };
            let t = evaluate(&r, &state).unwrap();
            assert_eq!(t.next_pc.bits, 0x1004);
            assert_eq!(t.trap, None);
            assert!(t.registers.is_empty() && t.memory.is_empty() && t.atomics.is_empty());
            assert_eq!(
                t.events,
                if active {
                    vec![barrier(kind, BarrierScope::System, BarrierAccess::All)]
                } else {
                    vec![]
                },
                "{word:08x} mask={mask:x}"
            );
        }
    }
}
#[test]
fn profiling_and_trace_traps_precede_sync_and_do_not_require_the_other_policy() {
    for (word, bit, policy) in [(0xd503223f, 4, 0), (0xd503225f, 5, 1)] {
        let r = recipe(word, 128).unwrap();
        for enabled in [false, true] {
            let mut state = State {
                features: if enabled { 1 << bit } else { 0 },
                controls: [None; 4],
                x16: None,
            };
            if !enabled {
                assert!(evaluate(&r, &state).unwrap().events.is_empty());
                continue;
            }
            assert_eq!(evaluate(&r, &state), Err(EvalError::UnknownCondition));
            state.controls[policy] = Some(1);
            let t = evaluate(&r, &state).unwrap();
            assert_eq!(t.trap, Some(TrapKind::Protection));
            assert!(t.events.is_empty() && t.registers.is_empty());
        }
    }
}
#[test]
fn chkfeat_clears_only_effective_gcs_selector_and_preserves_unknown_selectors() {
    for enabled in [false, true] {
        for gcs in [false, true] {
            for selected in [0, 1, 2, 3, u64::MAX, 0xa5a55a5a00000001] {
                let r = recipe(0xd503251f, 128).unwrap();
                let state = State {
                    features: if enabled { 1 << 6 } else { 0 },
                    controls: if enabled {
                        [None, None, Some(u64::from(gcs)), None]
                    } else {
                        [None; 4]
                    },
                    x16: enabled.then_some(selected),
                };
                let t = evaluate(&r, &state).unwrap();
                assert!(t.events.is_empty());
                if enabled {
                    assert_eq!(t.registers.len(), 1);
                    assert_eq!(
                        t.registers[0].register,
                        Register {
                            bank: "a64.gpr",
                            index: 16
                        }
                    );
                    assert_eq!(t.registers[0].value.bits, selected & !u64::from(gcs));
                } else {
                    assert!(t.registers.is_empty());
                }
            }
        }
    }
}
#[test]
fn all_dsb_scopes_accesses_and_effective_nxs_remain_distinct() {
    for option in 0..16 {
        for nxs in [false, true] {
            if [0, 4].contains(&option) {
                continue;
            }
            let word = 0xd503309f | (option << 8);
            let r = recipe(word, 128).unwrap();
            let state = State {
                features: 255,
                controls: [None, None, None, Some(u64::from(nxs))],
                x16: None,
            };
            let t = evaluate(&r, &state).unwrap();
            let scope = if option == 7 {
                BarrierScope::NonShareable
            } else if option == 11 {
                BarrierScope::InnerShareable
            } else {
                BarrierScope::System
            };
            let access = match option & 3 {
                1 => BarrierAccess::Reads,
                2 => BarrierAccess::Writes,
                _ => BarrierAccess::All,
            };
            assert_eq!(
                t.events,
                [barrier(
                    if nxs {
                        BarrierKind::DataSynchronizationNoXS
                    } else {
                        BarrierKind::DataSynchronization
                    },
                    scope,
                    access
                )]
            );
        }
    }
    for imm in 0..4 {
        for enabled in [false, true] {
            let r = recipe(0xd503323f | (imm << 10), 128).unwrap();
            let state = State {
                features: if enabled { 128 } else { 0 },
                controls: [None; 4],
                x16: None,
            };
            let t = evaluate(&r, &state).unwrap();
            if enabled {
                let scope = match imm {
                    1 => BarrierScope::NonShareable,
                    2 => BarrierScope::InnerShareable,
                    _ => BarrierScope::System,
                };
                assert_eq!(
                    t.events,
                    [barrier(
                        BarrierKind::DataSynchronizationNoXS,
                        scope,
                        BarrierAccess::All
                    )]
                );
                assert_eq!(t.trap, None);
            } else {
                assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
                assert!(t.events.is_empty());
            }
        }
    }
    let r = recipe(0xd5033b9f, 128).unwrap();
    assert_eq!(
        evaluate(
            &r,
            &State {
                features: 255,
                controls: [None; 4],
                x16: None
            }
        ),
        Err(EvalError::UnknownCondition)
    );
}
#[test]
fn conditional_barrier_rejects_non_boolean_predicates() {
    let mut r = Recipe::new(4, 64);
    r.effects.push(Effect::Barrier {
        kind: BarrierKind::DataGatheringHint,
        scope: BarrierScope::System,
        access: BarrierAccess::All,
        condition: Some(Expr::constant(8, 1)),
    });
    assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
}

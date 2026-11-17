#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_ls64::a64(word, 0x1000, endian)
}
struct State {
    regs: [u64; 32],
    enabled: [bool; 3],
    accdata: u32,
    calls: Cell<usize>,
    mode: u8,
    status: u64,
    clear: bool,
    observed: [u64; 8],
}
impl State {
    fn new() -> Self {
        Self {
            regs: std::array::from_fn(|i| 0xaabbccdd00000000 | i as u64),
            enabled: [true; 3],
            accdata: 0x87654321,
            calls: Cell::new(0),
            mode: 0,
            status: 0x123456789abcdef0,
            clear: true,
            observed: std::array::from_fn(|i| 0x0102030405060708u64.wrapping_mul(1 + i as u64)),
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => Value::known(64, self.regs[r.index as usize]),
            "a64.sp" => Value::known(64, self.regs[31]),
            "a64.ls64_enabled" => Value::known(1, self.enabled[r.index as usize] as u64),
            "a64.accdata_el1" => Value::known(32, self.accdata as u64),
            "a64.sp_alignment_enforced" => Value::known(1, 1),
            _ => panic!("unexpected {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("LS64 must not split into scalar memory")
    }
    fn evaluate_block64(&self, r: &Block64Request) -> Result<Block64Observation, EvalError> {
        self.calls.set(self.calls.get() + 1);
        if self.mode == 1 {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Translation));
        }
        if self.mode == 2 {
            return Err(EvalError::Unsupported);
        }
        match &r.kind {
            Block64RequestKind::Load => Ok(Block64Observation::Load {
                chunks: std::array::from_fn(|i| {
                    if self.mode == 3 {
                        Value::unknown(64)
                    } else {
                        Value::known(64, self.observed[i])
                    }
                }),
                clear_reservation: self.clear,
                witness: 19,
            }),
            Block64RequestKind::Store { with_status, .. } => Ok(Block64Observation::Store {
                status: if self.mode == 3 {
                    Some(Value::unknown(64))
                } else {
                    with_status.then(|| Value::known(64, self.status))
                },
                committed: self.mode != 4,
                clear_reservation: self.clear,
                witness: 23,
            }),
        }
    }
}
fn word(kind: u32, t: u32, n: u32, s: u32) -> u32 {
    let base = [0xf83fd000, 0xf83f9000, 0xf820b000, 0xf820a000][kind as usize];
    base | t | (n << 5) | if kind >= 2 { s << 16 } else { 0 }
}
fn make(word: u32, endian: Endian) -> Recipe {
    let r = recipe(word, 128, endian).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    r
}
#[test]
fn complete_family_captures_register_overlap_word_order_status_and_accdata() {
    for endian in [Endian::Little, Endian::Big] {
        for kind in 0..4 {
            for t in (0..24).step_by(2) {
                for n in 0..32 {
                    for s in [t, t + 1, 30, 31] {
                        let mut state = State::new();
                        state.regs[n as usize] = 0x2000;
                        let r = make(word(kind, t, n, s), endian);
                        let out = evaluate(&r, &state).unwrap();
                        assert_eq!(state.calls.get(), 1);
                        assert_eq!(out.trap, None);
                        assert_eq!(out.next_pc.bits, 0x1004);
                        assert!(out.memory.is_empty() && out.wide_memory.is_empty());
                        assert_eq!(out.atomics.len(), 1);
                        assert_eq!(out.events, vec![OrderedEvent::Atomic(0)]);
                        let atomic = &out.atomics[0];
                        assert_eq!(atomic.monitor, ExclusiveMonitorEffect::Cleared);
                        let block = atomic.block64.as_ref().unwrap();
                        assert_eq!(block.request.address, 0x2000);
                        assert_eq!(block.request.tagchecked, n != 31);
                        if kind == 0 {
                            assert_eq!(block.request.kind, Block64RequestKind::Load);
                            assert_eq!(out.registers.len(), 8);
                            for i in 0..8 {
                                let write = &out.registers[i];
                                assert_eq!(write.register.bank, "a64.gpr");
                                assert_eq!(write.register.index, t as u16 + i as u16);
                                assert_eq!(
                                    write.value.bits,
                                    if endian == Endian::Big {
                                        state.observed[i].swap_bytes()
                                    } else {
                                        state.observed[i]
                                    }
                                );
                            }
                        } else {
                            let Block64RequestKind::Store {
                                chunks,
                                with_status,
                            } = &block.request.kind
                            else {
                                panic!()
                            };
                            assert_eq!(*with_status, kind >= 2);
                            for i in 0..8 {
                                let mut expected = state.regs[t as usize + i];
                                if kind == 3 && i == 0 {
                                    expected =
                                        (expected & 0xffffffff00000000) | u64::from(state.accdata);
                                }
                                if endian == Endian::Big {
                                    expected = expected.swap_bytes();
                                }
                                assert_eq!(chunks[i], Value::known(64, expected));
                            }
                            if kind >= 2 && s != 31 {
                                assert_eq!(out.registers.len(), 1);
                                assert_eq!(out.registers[0].register.index, s as u16);
                                assert_eq!(out.registers[0].value.bits, state.status);
                            } else {
                                assert!(out.registers.is_empty());
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn traps_and_callback_failures_are_lazy_and_do_not_publish_partial_results() {
    for kind in 0..4 {
        let control = if kind == 3 {
            2
        } else if kind == 2 {
            1
        } else {
            0
        };
        let mut state = State::new();
        state.regs[30] = 0x2000;
        state.regs[31] = 0x2001;
        state.enabled[control] = false;
        let out = evaluate(&make(word(kind, 0, 30, 4), Endian::Little), &state).unwrap();
        assert_eq!(out.trap, Some(TrapKind::Protection));
        assert_eq!(state.calls.get(), 0);
        assert!(out.atomics.is_empty() && out.registers.is_empty());
        state.enabled[control] = true;
        let out = evaluate(&make(word(kind, 0, 31, 4), Endian::Little), &state).unwrap();
        assert_eq!(out.trap, Some(TrapKind::Protection));
        assert_eq!(state.calls.get(), 0);
        for mode in [1, 2, 3] {
            state.mode = mode;
            state.calls.set(0);
            let error = evaluate(&make(word(kind, 0, 30, 4), Endian::Little), &state).unwrap_err();
            assert_eq!(
                error,
                match mode {
                    1 => EvalError::MemoryFault(MemoryFaultKind::Translation),
                    2 => EvalError::Unsupported,
                    _ => EvalError::InvalidAtomicOutcome,
                }
            );
            assert_eq!(state.calls.get(), 1);
        }
        // A target may decline a status-returning store, but cannot silently
        // drop ST64B. The status is preserved independently of commitment.
        state.mode = 4;
        state.clear = false;
        state.status = u64::MAX;
        let out = evaluate(&make(word(kind, 0, 30, 4), Endian::Little), &state);
        if kind == 1 {
            assert_eq!(out.unwrap_err(), EvalError::InvalidAtomicOutcome);
        } else {
            let out = out.unwrap();
            assert_eq!(out.atomics[0].monitor, ExclusiveMonitorEffect::Preserved);
            if kind >= 2 {
                assert_eq!(out.registers[0].value.bits, u64::MAX);
                assert!(matches!(
                    out.atomics[0].block64.as_ref().unwrap().observation,
                    Block64Observation::Store {
                        committed: false,
                        ..
                    }
                ));
            }
        }
    }
}
#[test]
fn block_results_are_typed_and_reserved_register_lists_are_rejected() {
    for kind in 0..4 {
        for t in 0..32 {
            if t < 24 && t & 1 == 0 {
                continue;
            }
            let state = State::new();
            if let Some(r) = recipe(word(kind, t, 30, 4), 128, Endian::Little) {
                let out = evaluate(&r, &state).unwrap();
                assert_eq!(out.trap, Some(TrapKind::InvalidInstruction));
                assert!(out.atomics.is_empty());
                assert_eq!(state.calls.get(), 0);
            }
        }
    }
    for (kind, index) in [(0, 8), (1, 0), (2, 0), (3, 0)] {
        let mut r = make(word(kind, 0, 30, 4), Endian::Little);
        r.effects.clear();
        r.write(
            register("a64.gpr", 0, 64, 64),
            WritePolicy::ZeroUpper,
            Expr {
                ty: Type {
                    width: 64,
                    signedness: Signedness::Unsigned,
                },
                kind: ExprKind::AtomicResult {
                    step: 0,
                    projection: AtomicProjection::BlockChunk(index),
                },
            },
        );
        assert_eq!(r.validate(), Err(EvalError::InvalidExpression));
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = (vl, endian);
    system::a64(word, 0x1000)
}
struct State {
    value: u64,
    counter: u64,
    event: bool,
    pending: bool,
    unavailable: bool,
    outcome: TimedWaitOutcome,
    calls: Cell<usize>,
    source: Cell<u8>,
}
impl State {
    fn new() -> Self {
        Self {
            value: 99,
            counter: 10,
            event: false,
            pending: false,
            unavailable: false,
            outcome: TimedWaitOutcome::FallThrough,
            calls: Cell::new(0),
            source: Cell::new(0),
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.event_register" => Value::known(1, self.event as u64),
            "a64.interrupt_pending" => Value::known(1, self.pending as u64),
            "a64.virtual_counter" => {
                assert!(!self.unavailable, "unselected timer");
                Value::known(64, self.counter)
            }
            "a64.gpr" => {
                assert!(!self.unavailable, "unselected deadline");
                self.source.set(r.index as u8);
                Value::known(64, self.value)
            }
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("wait memory")
    }
    fn timed_wait(&self, r: &TimedWaitRequest) -> Result<TimedWaitOutcome, EvalError> {
        assert!(r.source < 31);
        assert_eq!(r.deadline, self.value);
        self.calls.set(self.calls.get() + 1);
        Ok(self.outcome)
    }
}
fn make(interrupt: bool, source: u32) -> Recipe {
    let r = recipe(
        0xd5031000 | if interrupt { 32 } else { 0 } | source,
        128,
        Endian::Little,
    )
    .unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    r
}
#[test]
fn waits_preserve_deadline_kind_and_source_and_stage_only_declared_outcomes() {
    for interrupt in [false, true] {
        for source in 0..31 {
            for outcome in [
                TimedWaitOutcome::FallThrough,
                TimedWaitOutcome::ClearEvent,
                TimedWaitOutcome::ProtectionTrap,
                TimedWaitOutcome::InvalidInstruction,
            ] {
                let mut s = State::new();
                s.outcome = outcome;
                let out = evaluate(&make(interrupt, source), &s);
                assert_eq!(s.source.get(), source as u8);
                assert_eq!(s.calls.get(), 1);
                if interrupt && outcome == TimedWaitOutcome::ClearEvent {
                    assert_eq!(out.unwrap_err(), EvalError::InvalidEnvironmentOutcome);
                    continue;
                }
                let out = out.unwrap();
                assert_eq!(
                    out.events,
                    vec![OrderedEvent::TimedWait {
                        request: TimedWaitRequest {
                            interrupt,
                            source: source as u8,
                            deadline: 99
                        },
                        outcome
                    }]
                );
                assert_eq!(
                    out.trap,
                    match outcome {
                        TimedWaitOutcome::ProtectionTrap => Some(TrapKind::Protection),
                        TimedWaitOutcome::InvalidInstruction => Some(TrapKind::InvalidInstruction),
                        _ => None,
                    }
                );
                assert_eq!(
                    out.registers.len(),
                    usize::from(outcome == TimedWaitOutcome::ClearEvent)
                );
                if !out.registers.is_empty() {
                    assert_eq!(out.registers[0].register.bank, "a64.event_register");
                    assert_eq!(out.registers[0].value, Value::known(1, 0));
                }
                assert!(out.memory.is_empty() && out.atomics.is_empty());
            }
        }
    }
}
#[test]
fn incoming_readiness_suppresses_timer_deadline_and_environment_inputs() {
    for interrupt in [false, true] {
        let mut s = State::new();
        s.event = !interrupt;
        s.pending = interrupt;
        s.unavailable = true;
        let out = evaluate(&make(interrupt, 5), &s).unwrap();
        assert_eq!(out.trap, None);
        assert_eq!(s.calls.get(), 0);
        assert!(out.events.is_empty());
        assert_eq!(out.registers.len(), usize::from(!interrupt));
    }
    for interrupt in [false, true] {
        for (counter, deadline) in [(0, 0), (10, 9), (10, 10), (u64::MAX, u64::MAX)] {
            let mut s = State::new();
            s.counter = counter;
            s.value = deadline;
            let out = evaluate(&make(interrupt, 4), &s).unwrap();
            assert_eq!(out.trap, None);
            assert!(out.events.is_empty() && out.registers.is_empty());
            assert_eq!(s.calls.get(), 0);
        }
    }
    for interrupt in [false, true] {
        let s = State::new();
        let out = evaluate(&make(interrupt, 31), &s).unwrap();
        assert_eq!(out.trap, None);
        assert_eq!(s.calls.get(), 0);
    }
}
#[test]
fn all_extended_hint_immediates_are_nops_outside_the_legacy_subspace() {
    let s = State::new();
    for imm in 0..65536u32 {
        let word = 0xd5002000 | ((imm >> 15) << 21) | (((imm >> 12) & 7) << 16) | (imm & 4095);
        let legacy = imm >> 15 == 0 && (imm >> 12) & 7 == 3 && imm & 31 == 31;
        if legacy {
            continue;
        }
        let r = recipe(word, 128, Endian::Little).unwrap();
        r.validate().unwrap();
        assert_eq!(r.support, Support::Full);
        assert!(r.effects.is_empty() && r.atomics.is_empty());
        let out = evaluate(&r, &s).unwrap();
        assert_eq!(out.next_pc.bits, 0x1004);
        assert_eq!(out.trap, None);
    }
    assert_eq!(s.calls.get(), 0);
}

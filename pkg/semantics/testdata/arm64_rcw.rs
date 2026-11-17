#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
include!("arm64_rcw_cases.rs");
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_rcw::a64(word, 0x1000, endian)
}
struct State {
    x: [u64; 32],
    old: [u64; 2],
    mask: [u64; 2],
    soft_mask: [u64; 2],
    protection: bool,
    d128: bool,
    sp: u64,
    spcheck: bool,
    fault: bool,
    unknown: Option<&'static str>,
    calls: RefCell<Vec<AtomicRequest>>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        if self.unknown == Some(r.bank) {
            return Value::unknown(
                if matches!(
                    r.bank,
                    "a64.protection_enabled" | "a64.d128_enabled" | "a64.sp_alignment_enforced"
                ) {
                    1
                } else {
                    64
                },
            );
        }
        Value::known(
            if matches!(
                r.bank,
                "a64.protection_enabled" | "a64.d128_enabled" | "a64.sp_alignment_enforced"
            ) {
                1
            } else {
                64
            },
            match r.bank {
                "a64.gpr" => self.x[r.index as usize],
                "a64.rcwmask64" => self.mask[r.index as usize],
                "a64.rcwsmask64" => self.soft_mask[r.index as usize],
                "a64.protection_enabled" => u64::from(self.protection),
                "a64.d128_enabled" => u64::from(self.d128),
                "a64.sp" => self.sp,
                "a64.sp_alignment_enforced" => u64::from(self.spcheck),
                _ => panic!("{r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("non-atomic fallback")
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        assert!(p.is_empty());
        self.calls.borrow_mut().push(r.clone());
        if self.fault {
            return Err(EvalError::MemoryFault(MemoryFaultKind::Permission));
        }
        Ok(AtomicObservation {
            old: Some(Value::known(64, self.old[0])),
            store_succeeded: None,
            reservation_token: None,
            witness: 7,
        })
    }
    fn evaluate_atomic_pair(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicPairObservation, EvalError> {
        Ok(AtomicPairObservation {
            observation: self.evaluate_atomic(r, p)?,
            old_high: Some(Value::known(64, self.old[1])),
        })
    }
}
fn state() -> State {
    State {
        x: [0; 32],
        old: [0; 2],
        mask: [0; 2],
        soft_mask: [0; 2],
        protection: false,
        d128: false,
        sp: 0x2000,
        spcheck: false,
        fault: false,
        unknown: None,
        calls: RefCell::new(vec![]),
    }
}
fn pack(v: [u64; 2]) -> u128 {
    u128::from(v[0]) | (u128::from(v[1]) << 64)
}
fn split(v: u128) -> [u64; 2] {
    [v as u64, (v >> 64) as u64]
}
fn reverse(v: [u64; 2], endian: Endian) -> [u64; 2] {
    if endian == Endian::Little {
        v
    } else {
        [v[1], v[0]]
    }
}
// Independent bit-by-bit transcription of RCW mask expansion, including every
// replicated and forced-zero bit. No implementation helper supplies expectations.
fn effective(raw: u128, width: u8, soft: bool, protection: bool) -> u128 {
    let bit = |n: u32| raw & (1u128 << n) != 0;
    let mut out = raw;
    let mut assign = |n: u32, value: bool| {
        if value {
            out |= 1u128 << n
        } else {
            out &= !(1u128 << n)
        }
    };
    if width == 64 {
        for n in 18..=49 {
            assign(n, bit(17));
        }
        assign(0, false);
        if soft && protection {
            assign(52, false)
        }
        out & u128::from(u64::MAX)
    } else {
        for n in 17..=55 {
            assign(n, bit(16));
        }
        for (lo, hi) in [(0, 1), (56, 90), (101, 107), (119, 120), (125, 126)] {
            for n in lo..=hi {
                assign(n, false)
            }
        }
        if soft {
            assign(114, false)
        }
        out
    }
}
fn reference(
    op: u8,
    soft: bool,
    width: u8,
    old: u128,
    expected: u128,
    operand: u128,
    mask: u128,
    smask: u128,
    protection: bool,
) -> (u8, Option<u128>) {
    let keep = if width == 128 {
        u128::MAX
    } else {
        u128::from(u64::MAX)
    };
    let new = match op {
        0 => old & !operand,
        1 => old | operand,
        _ => operand,
    } & keep;
    if op == 3 && old != expected {
        return (10, None);
    }
    let p = if width == 128 { 114 } else { 52 };
    let changed = old ^ new;
    let mut hard = false;
    let mut weak = false;
    if protection {
        if old & (1 << p) != 0 {
            hard = changed & ((1 << p) | 1) != 0
        } else {
            hard = changed & (1 << p) != 0
        }
        if old & (1 << p) != 0 && old & 1 != 0 {
            hard |= changed & !mask & keep != 0
        }
    }
    if soft {
        if old & 1 != 0 || !protection || old & (1 << p) == 0 {
            weak = changed & 1 != 0
        }
        if old & 1 != 0 {
            weak |= changed & !smask & keep != 0
        }
    }
    let flags = (if hard { 4 } else { 0 }) | (if weak { 0 } else { 2 });
    (flags, if flags == 2 { Some(new) } else { None })
}
fn written(t: &Transition, bank: &str, index: u16) -> Option<u64> {
    t.registers
        .iter()
        .find(|v| v.register.bank == bank && v.register.index == index)
        .map(|v| v.value.bits)
}
#[test]
fn every_rcw_encoding_endian_mask_state_and_compare_outcome() {
    for &(base, op, soft, pair) in CASES {
        for endian in [Endian::Little, Endian::Big] {
            for protection in [false, true] {
                for policy in [0u128, u128::MAX, 0x0001_0000_0000_0001_0012_0000_0002_0001] {
                    for case in 0..6 {
                        let width = if pair { 128 } else { 64 };
                        let p = if pair { 114 } else { 52 };
                        let keep = if pair {
                            u128::MAX
                        } else {
                            u128::from(u64::MAX)
                        };
                        let old = (0x1234u128
                            | if case & 1 != 0 { 1 } else { 0 }
                            | if case & 2 != 0 { 1 << p } else { 0 })
                            & keep;
                        let operand = match case {
                            0 => 0x80,
                            1 => old ^ 0x80,
                            2 => old ^ (1 << p),
                            3 => old ^ 1,
                            4 => old ^ 0x100000000,
                            _ => old,
                        };
                        let expected = if case == 5 { old ^ 2 } else { old };
                        let mut s = state();
                        s.d128 = pair;
                        s.protection = protection;
                        s.mask = split(policy);
                        s.soft_mask = split(!policy & keep);
                        s.old = split(old);
                        s.x[9] = 0x2000;
                        let cmp = if pair {
                            reverse(split(expected), endian)
                        } else {
                            split(expected)
                        };
                        let input = if pair {
                            reverse(split(operand), endian)
                        } else {
                            split(operand)
                        };
                        if op == 3 {
                            s.x[2] = cmp[0];
                            s.x[3] = cmp[1];
                            s.x[4] = input[0];
                            s.x[5] = input[1];
                        } else if pair {
                            s.x[4] = input[0];
                            s.x[2] = input[1];
                        } else {
                            s.x[2] = input[0];
                        }
                        let word = base | (2 << 16) | (9 << 5) | 4;
                        let r = recipe(word, 128, endian).unwrap();
                        assert_eq!(r.support, Support::Full);
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert!(t.trap.is_none());
                        assert_eq!(t.atomics.len(), 1);
                        assert_eq!(s.calls.borrow().len(), 1);
                        let mask = effective(policy, width, false, protection);
                        let smask = effective(!policy & keep, width, true, protection);
                        let (flags, stored) = reference(
                            op, soft, width, old, expected, operand, mask, smask, protection,
                        );
                        let actual = (0..4)
                            .fold(0, |a, i| a | written(&t, "a64.nzcv", i).unwrap() << (3 - i));
                        assert_eq!(actual, u64::from(flags), "{word:08x} case{case} {endian:?}");
                        let event = &t.atomics[0];
                        assert_eq!(event.stored.map(|v| v.bits), stored.map(|v| v as u64));
                        assert_eq!(
                            event.stored_high.map(|v| v.bits),
                            if pair {
                                stored.map(|v| (v >> 64) as u64)
                            } else {
                                None
                            }
                        );
                        let returned = if pair {
                            reverse(split(old), endian)
                        } else {
                            split(old)
                        };
                        assert_eq!(
                            written(&t, "a64.gpr", if op == 3 { 2 } else { 4 }),
                            Some(returned[0])
                        );
                        if pair {
                            assert_eq!(
                                written(&t, "a64.gpr", if op == 3 { 3 } else { 2 }),
                                Some(returned[1])
                            );
                        }
                        let request = event.request.as_ref().unwrap();
                        assert_eq!(request.width, width);
                        assert_eq!(request.endian, endian);
                        assert_eq!(request.address, 0x2000);
                        assert_eq!(request.privilege, MemoryPrivilege::Current);
                    }
                }
            }
        }
    }
}
#[test]
fn rcw_mode_sp_fault_and_constrained_paths_have_no_atomic_effect() {
    for &(base, op, _, pair) in CASES {
        let word = base | (2 << 16) | (9 << 5) | 4;
        let mut s = state();
        s.d128 = !pair;
        let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
        assert!(s.calls.borrow().is_empty());
        s.d128 = pair;
        s.sp = 0x2001;
        s.spcheck = true;
        let spword = (word & !(31 << 5)) | (31 << 5);
        let t = evaluate(&recipe(spword, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::Protection));
        assert!(s.calls.borrow().is_empty());
        s.spcheck = false;
        s.x[9] = 0x2000;
        s.fault = true;
        assert!(matches!(
            evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s),
            Err(EvalError::MemoryFault(MemoryFaultKind::Permission))
        ));
        if pair {
            let invalid = if op == 3 { word | 1 } else { (word & !31) | 31 };
            if let Some(r) = recipe(invalid, 128, Endian::Little) {
                let t = evaluate(&r, &state()).unwrap();
                assert_eq!(t.trap, Some(TrapKind::InvalidInstruction));
            }
            if op != 3 {
                let overlap = (word & !(31 << 16)) | (4 << 16);
                let r = recipe(overlap, 128, Endian::Little).unwrap();
                assert!(r.atomics.is_empty());
                assert!(r.effects.is_empty());
                assert!(r.preflight_traps.is_empty());
            }
        }
    }
}

#[test]
fn rcw_zero_discard_acquire_and_upper_pair_registers() {
    for &(base, op, _, pair) in CASES {
        for endian in [Endian::Little, Endian::Big] {
            let mut s = state();
            s.d128 = pair;
            s.x[9] = 0x2000;
            s.old = [0x80, 0];
            let word = if pair && op == 3 {
                base | (30 << 16) | (9 << 5) | 30
            } else if pair {
                base | (30 << 16) | (9 << 5) | 4
            } else if op == 3 {
                base | (31 << 16) | (9 << 5) | 31
            } else {
                base | (31 << 16) | (9 << 5) | 31
            };
            let r = recipe(word, 128, endian).unwrap();
            let t = evaluate(&r, &s).unwrap();
            assert!(t.trap.is_none());
            let q = t.atomics[0].request.as_ref().unwrap();
            let acquire = base & (1 << 23) != 0 && pair;
            let release = base & (1 << 22) != 0;
            let order = match (acquire, release) {
                (false, false) => MemoryOrdering::Monotonic,
                (true, false) => MemoryOrdering::Acquire,
                (false, true) => MemoryOrdering::Release,
                _ => MemoryOrdering::AcquireRelease,
            };
            assert_eq!(q.ordering, order, "{word:08x}");
            assert!(!t
                .registers
                .iter()
                .any(|w| w.register.bank == "a64.gpr" && w.register.index == 31));
            assert_eq!(
                t.registers
                    .iter()
                    .filter(|w| w.register.bank == "a64.gpr")
                    .count(),
                if pair && op == 3 {
                    1
                } else if pair {
                    2
                } else {
                    0
                }
            );
        }
    }
}
#[test]
fn rcw_missing_context_and_atomic_capability_reject_before_publication() {
    struct NoAtomic;
    impl Machine for NoAtomic {
        fn read_register(&self, r: Register) -> Value {
            Value::known(
                if matches!(
                    r.bank,
                    "a64.protection_enabled" | "a64.d128_enabled" | "a64.sp_alignment_enforced"
                ) {
                    1
                } else {
                    64
                },
                0,
            )
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("no ordinary fallback")
        }
    }
    for &(base, _, soft, pair) in CASES {
        let r = recipe(base | (2 << 16) | (9 << 5) | 4, 128, Endian::Little).unwrap();
        for bank in [
            "a64.gpr",
            "a64.d128_enabled",
            "a64.protection_enabled",
            "a64.rcwmask64",
            "a64.rcwsmask64",
        ] {
            if bank == "a64.rcwsmask64" && !soft {
                continue;
            }
            let mut s = state();
            s.d128 = pair;
            s.unknown = Some(bank);
            assert!(
                matches!(
                    evaluate(&r, &s),
                    Err(EvalError::UnknownCondition
                        | EvalError::UnknownAddress
                        | EvalError::UnknownAtomicValue)
                ),
                "{base:08x} {bank}"
            );
            assert!(s.calls.borrow().is_empty());
        }
        if !pair {
            assert_eq!(evaluate(&r, &NoAtomic), Err(EvalError::Unsupported));
        }
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_ordered::a64(word, 0x1000, endian)
}
struct State {
    x: [u64; 32],
    sp: u64,
    v: [[u64; 32]; 32],
    calls: RefCell<Vec<AtomicRequest>>,
    fault: Option<usize>,
    sp_alignment: bool,
}
fn observed(a: u64, w: u8) -> u64 {
    (a.wrapping_mul(0x9e3779b97f4a7c15) ^ 0xfedcba9876543280)
        & if w == 64 { u64::MAX } else { (1u64 << w) - 1 }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            if r.bank == "a64.sp_alignment_enforced" { 1 } else { 64 },
            match r.bank {
                "a64.gpr" => self.x[r.index as usize],
                "a64.sp" => self.sp,
                "a64.sp_alignment_enforced" => u64::from(self.sp_alignment),
                "a64.vector64" => self.v[r.index as usize / 32][r.index as usize % 32],
                _ => panic!("unexpected register {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("ordinary memory fallback")
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        let index = self.calls.borrow().len();
        assert_eq!(p.len(), index);
        self.calls.borrow_mut().push(r.clone());
        if self.fault == Some(index) {
            return Err(EvalError::UnsupportedContext);
        }
        assert_eq!(r.scope, MemoryScope::System);
        Ok(AtomicObservation {
            old: matches!(r.kind, AtomicRequestKind::Load)
                .then(|| Value::known(r.width, observed(r.address, r.width))),
            store_succeeded: None,
            reservation_token: None,
            witness: index as u64 + 1,
        })
    }
    fn evaluate_atomic_pair(
        &self,
        r: &AtomicRequest,
        p: &[AtomicTransition],
    ) -> Result<AtomicPairObservation, EvalError> {
        assert!(p.is_empty());
        self.calls.borrow_mut().push(r.clone());
        if self.fault == Some(0) { return Err(EvalError::UnsupportedContext); }
        Ok(AtomicPairObservation {
            observation: AtomicObservation {
                old: matches!(r.kind, AtomicRequestKind::LoadPair).then(|| Value::known(64, 11)),
                store_succeeded: None,
                reservation_token: None,
                witness: 1,
            },
            old_high: matches!(r.kind, AtomicRequestKind::LoadPair).then(|| Value::known(64, 22)),
        })
    }
}
fn state() -> State {
    State {
        x: [0x4000; 32],
        sp: 0x4000,
        v: std::array::from_fn(|v| {
            std::array::from_fn(|i| 0x8000000000000001u64.wrapping_mul((v * 32 + i + 1) as u64))
        }),
        calls: RefCell::new(vec![]),
        fault: None,
        sp_alignment: true,
    }
}
fn signed(x: u64, bits: u8, dest: u8) -> u64 {
    let x = ((x << (64 - bits)) as i64 >> (64 - bits)) as u64;
    if dest == 32 {
        x & 0xffffffff
    } else {
        x
    }
}
fn output(t: &Transition, n: u32) -> Option<u64> {
    t.registers
        .iter()
        .find(|w| w.register.bank == "a64.gpr" && w.register.index == n as u16)
        .map(|w| w.value.bits)
}
#[test]
fn scalar_all_offsets_widths_signs_zero_and_writeback() {
    let formats = [
        (0x19400000, 8, 32, false, false),
        (0x59400000, 16, 32, false, false),
        (0x99400000, 32, 32, false, false),
        (0xd9400000, 64, 64, false, false),
        (0x19800000, 8, 64, true, false),
        (0x19c00000, 8, 32, true, false),
        (0x59800000, 16, 64, true, false),
        (0x59c00000, 16, 32, true, false),
        (0x99800000, 32, 64, true, false),
        (0x19000000, 8, 32, false, true),
        (0x59000000, 16, 32, false, true),
        (0x99000000, 32, 32, false, true),
        (0xd9000000, 64, 64, false, true),
    ];
    let mut count = 0;
    for endian in [Endian::Little, Endian::Big] {
        for &(base, bits, dest, sign, store) in &formats {
            for imm in -256i64..256 {
                for rt in [0, 17, 31] {
                    let rn = if rt == 17 { 17 } else { 31 };
                    let word = base | (((imm as u32) & 511) << 12) | (rn << 5) | rt;
                    let mut s = state();
                    let at = (0x4000i64 + imm) as u64;
                    let bytes = bits / 8;
                    // Choose aligned base independently of the encoded offset.
                    let incoming = (0x4000i64 - imm) as u64;
                    if rn == 31 {
                        s.sp = incoming;
                    } else {
                        s.x[rn as usize] = incoming;
                    }
                    // SP must itself be aligned; arbitrary imm still exercises unscaled bases.
                    if rn == 31 && incoming % 16 != 0 {
                        continue;
                    }
                    let r = recipe(word, 128, endian).unwrap();
                    assert_eq!(r.support, Support::Full, "{word:08x}");
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    let calls = s.calls.borrow();
                    assert_eq!(calls.len(), 1);
                    let a = &calls[0];
                    assert_eq!(a.address, 0x4000);
                    assert_eq!(a.width, bits);
                    assert_eq!(a.endian, endian);
                    assert_eq!(
                        a.ordering,
                        if store {
                            MemoryOrdering::Release
                        } else {
                            MemoryOrdering::AcquireRcpc
                        }
                    );
                    if store {
                        let AtomicRequestKind::Store { value } = &a.kind else {
                            panic!()
                        };
                        assert_eq!(
                            value.bits,
                            if rt == 31 {
                                0
                            } else {
                                s.x[rt as usize]
                                    & if bits == 64 {
                                        u64::MAX
                                    } else {
                                        (1u64 << bits) - 1
                                    }
                            }
                        );
                        assert!(t.registers.is_empty());
                    } else if rt == 31 {
                        assert!(t.registers.is_empty());
                    } else {
                        let v = observed(0x4000, bits);
                        assert_eq!(
                            output(&t, rt),
                            Some(if sign { signed(v, bits, dest) } else { v })
                        );
                    }
                    assert!(t.memory.is_empty());
                    let _ = (at, bytes);
                    count += 1;
                }
            }
        }
    }
    assert!(count > 14000, "{count}");
    for endian in [Endian::Little, Endian::Big] {
        for (base, bits) in [
            (0x38bfc000, 8),
            (0x78bfc000, 16),
            (0xb8bfc000, 32),
            (0xf8bfc000, 64),
            (0x99c00800, 32),
            (0xd9c00800, 64),
        ] {
            for (rt, rn) in [(0, 1), (1, 1), (31, 1), (0, 31), (31, 31)] {
                let s = state();
                let r = recipe(base | (rn << 5) | rt, 128, endian).unwrap();
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(s.calls.borrow()[0].ordering, MemoryOrdering::AcquireRcpc);
                assert_eq!(
                    output(&t, rt),
                    if rt == 31 {
                        None
                    } else {
                        Some(observed(0x4000, bits))
                    }
                );
                if base & 0xbffffc00 == 0x99c00800 {
                    let wb = t.registers.iter().find(|w| {
                        w.register.bank == if rn == 31 { "a64.sp" } else { "a64.gpr" }
                            && w.register.index == if rn == 31 { 0 } else { rn as u16 }
                            && w.value.bits == 0x4000 + u64::from(bits / 8)
                    });
                    assert_eq!(wb.is_some(), rn == 31 || rn != rt);
                }
            }
        }
    }
}
#[test]
fn simd_all_widths_endians_offsets_and_both_lanes() {
    for endian in [Endian::Little, Endian::Big] {
        for (load, base) in [(true, 0x1d400800), (false, 0x1d000800)] {
            for (bits, size, opc) in [
                (8u16, 0, 0),
                (16, 1, 0),
                (32, 2, 0),
                (64, 3, 0),
                (128, 0, 2),
            ] {
                for imm in -256i64..256 {
                    for rt in [0, 31] {
                        let word = base
                            | (size << 30)
                            | (opc << 22)
                            | (((imm as u32) & 511) << 12)
                            | (2 << 5)
                            | rt;
                        let mut s = state();
                        s.x[2] = (0x4000i64 - imm) as u64;
                        let r = recipe(word, 128, endian).unwrap();
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        let calls = s.calls.borrow();
                        assert_eq!(calls.len(), usize::from(bits.div_ceil(64)));
                        for (i, a) in calls.iter().enumerate() {
                            assert_eq!(a.width, bits.min(64) as u8);
                            assert_eq!(a.address, 0x4000 + i as u64 * 8);
                            assert_eq!(
                                a.ordering,
                                if load {
                                    MemoryOrdering::AcquireRcpc
                                } else {
                                    MemoryOrdering::Release
                                }
                            );
                            let chunk = if bits == 128 && endian == Endian::Big {
                                1 - i
                            } else {
                                i
                            };
                            if load {
                                let out = t
                                    .registers
                                    .iter()
                                    .find(|w| w.register.index == rt as u16 * 32 + chunk as u16)
                                    .unwrap();
                                assert_eq!(out.value.bits, observed(a.address, a.width));
                            } else {
                                let AtomicRequestKind::Store { value } = &a.kind else {
                                    panic!()
                                };
                                let mask = if a.width == 64 {
                                    u64::MAX
                                } else {
                                    (1u64 << a.width) - 1
                                };
                                assert_eq!(value.bits, s.v[rt as usize][chunk] & mask);
                            }
                        }
                        if load && bits <= 64 {
                            assert_eq!(
                                t.registers
                                    .iter()
                                    .find(|w| w.register.index == rt as u16 * 32 + 1)
                                    .unwrap()
                                    .value
                                    .bits,
                                0
                            );
                        }
                    }
                }
            }
        }
        for load in [false, true] {
            for lane in 0..2u32 {
                let s = state();
                let word = 0x0d018400 | ((load as u32) << 22) | (lane << 30) | (2 << 5) | 31;
                let r = recipe(word, 128, endian).unwrap();
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(s.calls.borrow().len(), 1);
                if load {
                    assert_eq!(t.registers.len(), 1);
                    assert_eq!(t.registers[0].register.index, 31 * 32 + lane as u16);
                    assert_eq!(t.registers[0].value.bits, observed(0x4000, 64));
                } else {
                    assert!(t.registers.is_empty());
                    assert!(
                        matches!(&s.calls.borrow()[0].kind,AtomicRequestKind::Store{value}if value.bits==s.v[31][lane as usize])
                    );
                }
            }
        }
    }
}
#[test]
fn pairs_independent_registers_writeback_and_store_observation_order() {
    for endian in [Endian::Little, Endian::Big] {
        for load in [false, true] {
            for wb in [false, true] {
                for bits in [32u8, 64] {
                    for rt in 0..32u32 {
                        for rt2 in 0..32u32 {
                            for rn in [rt, rt2, 31] {
                                let word = 0x99000800
                                    | ((load as u32) << 22)
                                    | (((bits == 64) as u32) << 30)
                                    | (((!wb) as u32) << 12)
                                    | (rt2 << 16)
                                    | (rn << 5)
                                    | rt;
                                let s = state();
                                let r = recipe(word, 128, endian).unwrap();
                                let t = evaluate(&r, &s).unwrap();
                                let calls = s.calls.borrow();
                                if load && rt == rt2 {
                                    assert!(calls.is_empty());
                                    assert!(t.registers.is_empty());
                                    continue;
                                }
                                let bytes = u64::from(bits / 8);
                                let at = if wb && !load {
                                    0x4000 - 2 * bytes
                                } else {
                                    0x4000
                                };
                                assert_eq!(calls.len(), 2);
                                for (i, a) in calls.iter().enumerate() {
                                    let index = if !load && wb { 1 - i } else { i };
                                    assert_eq!(a.address, at + index as u64 * bytes);
                                    assert_eq!(a.width, bits);
                                    assert_eq!(
                                        a.ordering,
                                        if load {
                                            MemoryOrdering::AcquireRcpc
                                        } else {
                                            MemoryOrdering::Release
                                        }
                                    );
                                    if !load {
                                        let n = if index == 0 { rt } else { rt2 };
                                        assert!(
                                            matches!(&a.kind,AtomicRequestKind::Store{value}if value.bits==if n==31{0}else{0x4000})
                                        );
                                    }
                                }
                                if load {
                                    for (n, a) in [(rt, at), (rt2, at + bytes)] {
                                        if n != 31 {
                                            assert_eq!(output(&t, n), Some(observed(a, bits)));
                                        }
                                    }
                                }
                                let written = if load { 0x4000 + 2 * bytes } else { at };
                                let update = wb && (!load || rn == 31 || (rn != rt && rn != rt2));
                                if update {
                                    assert!(t.registers.iter().any(|w| w.register.bank
                                        == if rn == 31 { "a64.sp" } else { "a64.gpr" }
                                        && w.value.bits == written));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn faults_alignment_and_load_only_ordering_are_explicit() {
    for word in [0xf8bfc020, 0xd9400020, 0xdd400820, 0xd9c00820, 0xd9410820] {
        let mut s = state();
        s.fault = Some(0);
        let r = recipe(word, 128, Endian::Little).unwrap();
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
    }
    let mut s = state();
    s.x[1] = 0x4001;
    let r = recipe(0xf8bfc020, 128, Endian::Little).unwrap();
    assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
    assert!(s.calls.borrow().is_empty());
    let mut r = Recipe::new(4, 64);
    r.atomic(AtomicOperation {
        memory: Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, 0)),
            width: 64,
            endian: Endian::Little,
        },
        ordering: MemoryOrdering::AcquireRcpc,
        scope: MemoryScope::System,
        kind: AtomicOperationKind::Store {
            value: Expr::constant(64, 0),
        },
    });
    assert!(r.validate().is_err());
    for bits in [32u8, 64] {
        for load in [false, true] {
            for endian in [Endian::Little, Endian::Big] {
                let word = 0x99001800
                    | ((load as u32) << 22)
                    | (((bits == 64) as u32) << 30)
                    | (2 << 16)
                    | (1 << 5);
                let r = arm64_ordered::a64_with_pair_atomicity(word, 0x1000, endian, true).unwrap();
                let s = state();
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(t.atomics.len(), 1);
                assert_eq!(s.calls.borrow()[0].width, bits * 2);
            }
        }
    }
}

#[test]
fn lscp_all_destinations_aliases_orders_endians_and_atomicity_profiles() {
    for endian in [Endian::Little, Endian::Big] {
        for pair_atomic in [false, true] {
            for (fixed, load, acquire) in [
                (0xd9405800, true, MemoryOrdering::Acquire),
                (0xd9407800, true, MemoryOrdering::AcquireRcpc),
                (0xd9005800, false, MemoryOrdering::Release),
            ] {
                for t in 0..32 {
                    for t2 in 0..32 {
                        for n in [t, t2, 30, 31] {
                            let mut s = state();
                            s.x = std::array::from_fn(|i| 0x1234000000000000 | i as u64);
                            if n == 31 { s.sp = 0x4000; } else { s.x[n as usize] = 0x4000; }
                            let word = fixed | t | t2 << 16 | n << 5;
                            let r = arm64_ordered::a64_with_pair_atomicity(word, 0x1000, endian, pair_atomic).unwrap();
                            assert_eq!(r.support, Support::Full);
                            r.validate().unwrap();
                            let tr = evaluate(&r, &s).unwrap();
                            assert_eq!(tr.next_pc.bits, 0x1004);
                            let calls = s.calls.borrow();
                            if load && t == t2 {
                                assert!(calls.is_empty());assert!(tr.registers.is_empty());continue;
                            }
                            assert_eq!(calls.len(), if pair_atomic {1} else {2});
                            let order = if load && (t == 31 || t2 == 31) { MemoryOrdering::Monotonic } else { acquire };
                            for (i, a) in calls.iter().enumerate() {
                                assert_eq!(a.address, 0x4000 + i as u64 * 8);
                                assert_eq!(a.ordering, order);
                                assert_eq!(a.width, if pair_atomic {128} else {64});
                                assert_eq!(a.endian, endian);
                            }
                            if load {
                                let values = if pair_atomic {
                                    if endian == Endian::Little {[11,22]} else {[22,11]}
                                } else {[observed(0x4000,64),observed(0x4008,64)]};
                                for (reg,value) in [(t,values[0]),(t2,values[1])] {
                                    if reg != 31 { assert_eq!(output(&tr, reg), Some(value)); }
                                }
                                assert_eq!(tr.registers.len(), usize::from(t != 31) + usize::from(t2 != 31));
                            } else {
                                assert!(tr.registers.is_empty());
                                let value = |reg:u32| if reg == 31 {0} else {s.x[reg as usize]};
                                if pair_atomic {
                                    let AtomicRequestKind::StorePair {low,high} = &calls[0].kind else {panic!()};
                                    let expected = if endian == Endian::Little {[value(t),value(t2)]} else {[value(t2),value(t)]};
                                    assert_eq!([low.bits,high.bits],expected);
                                } else {
                                    for (a,reg) in calls.iter().zip([t,t2]) {
                                        let AtomicRequestKind::Store {value:v} = &a.kind else {panic!()};
                                        assert_eq!(v.bits,value(reg));
                                    }
                                }
                            }
                            assert!(tr.memory.is_empty());
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn ordered_sp_control_faults_and_decode_nops_precede_all_accesses() {
    // SP is not 16-byte aligned but every element is naturally aligned.
    for word in [0xf8bfc3e0,0xd94003e0,0xdd400be0,0xd9411be0,0xd9415be0,0xd9417be0,0xd9015be0] {
        for enforced in [false,true] {
            let mut s=state();s.sp=0x4008;s.sp_alignment=enforced;
            let r=recipe(word,128,Endian::Little).unwrap();
            let t=evaluate(&r,&s).unwrap();
            assert_eq!(t.trap, enforced.then_some(TrapKind::Protection),"{word:08x}");
            assert_eq!(s.calls.borrow().is_empty(),enforced);
        }
    }
    for fixed in [0xd9405800,0xd9407800,0xd9401800] {
        let mut s=state();s.sp=1;
        let r=recipe(fixed | 31 << 5,128,Endian::Little).unwrap();
        let t=evaluate(&r,&s).unwrap();
        assert_eq!(t.trap,None);assert!(s.calls.borrow().is_empty());assert!(t.registers.is_empty());
    }
    for fixed in [0xd9405800,0xd9407800,0xd9005800] {
        for atomic in [false,true] {
            for fault in 0..if atomic {1} else {2} {
                let mut s=state();s.fault=Some(fault);
                let r=arm64_ordered::a64_with_pair_atomicity(fixed|1<<16|2<<5,0x1000,Endian::Little,atomic).unwrap();
                assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));
                assert_eq!(s.calls.borrow().len(),fault+1);
                assert_eq!(s.x,[0x4000;32]);
            }
        }
    }
}

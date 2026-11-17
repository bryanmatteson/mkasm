#[allow(dead_code)]
mod runtime;
use runtime::arm64_sve_nontemporal::a64;
use runtime::*;
use std::{cell::RefCell, collections::BTreeMap};
#[derive(Default)]
struct State {
    regs: BTreeMap<(&'static str, u16), Value>,
    memory: BTreeMap<u64, u8>,
    reads: RefCell<Vec<(u64, u8, Endian)>>,
    register_reads: RefCell<Vec<Register>>,
    fail: Option<u64>,
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.register_reads.borrow_mut().push(r);
        self.regs
            .get(&(r.bank, r.index))
            .copied()
            .unwrap_or(Value::unknown(64))
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        self.reads.borrow_mut().push((a, w, e));
        if self.fail == Some(a) {
            return Err(EvalError::Memory);
        }
        let mut v = 0;
        for i in 0..w / 8 {
            let b = self
                .memory
                .get(&a.wrapping_add(u64::from(i)))
                .ok_or(EvalError::Memory)?;
            let shift = if e == Endian::Little {
                i
            } else {
                w / 8 - 1 - i
            };
            v |= u64::from(*b) << (shift * 8);
        }
        Ok(Value::known(w, v))
    }
}
impl State {
    fn set(&mut self, b: &'static str, n: u16, w: u8, v: u64) {
        self.regs.insert((b, n), Value::known(w, v));
    }
    fn context(&mut self, sm: bool, fa: bool) {
        self.set("a64.svcr", 0, 64, u64::from(sm));
        self.set("a64.sme_fa64", 0, 1, u64::from(fa));
    }
    fn pred(&mut self, pg: u16, vl: u16, w: u8, active: impl Fn(usize) -> bool) {
        for ch in 0..4 {
            let mut v = 0;
            for e in 0..usize::from(vl) / usize::from(w) {
                let bit = e * usize::from(w) / 8;
                if bit / 64 == ch && active(e) {
                    v |= 1 << (bit % 64);
                }
            }
            self.set("a64.predicate64", pg * 4 + ch as u16, 64, v);
        }
    }
    fn vector(&mut self, n: u16, v: &[u64], w: u8) {
        for (ch, es) in v.chunks(64 / usize::from(w)).enumerate() {
            let b = es
                .iter()
                .enumerate()
                .fold(0, |b, (i, e)| b | ((e & mask(w)) << (i * usize::from(w))));
            self.set("a64.vector64", n * 32 + ch as u16, 64, b);
        }
    }
    fn fill(&mut self, a: u64, w: u8, v: u64, e: Endian) {
        for i in 0..w / 8 {
            let shift = if e == Endian::Little {
                i
            } else {
                w / 8 - 1 - i
            };
            self.memory
                .insert(a.wrapping_add(u64::from(i)), (v >> (shift * 8)) as u8);
        }
    }
}
// Independent lane oracles below use the primary's literal diagrams.
const CASES: &[(u32, u8, u8, bool, bool, u8)] = &[
    (0x8400a000, 32, 8, false, false, 0),
    (0xc400c000, 64, 8, false, false, 0),
    (0xa400e000, 8, 8, false, false, 2),
    (0xa400c000, 8, 8, false, false, 1),
    (0xc580c000, 64, 64, false, false, 0),
    (0xa580e000, 64, 64, false, false, 2),
    (0xa580c000, 64, 64, false, false, 1),
    (0x8480a000, 32, 16, false, false, 0),
    (0xc480c000, 64, 16, false, false, 0),
    (0xa480e000, 16, 16, false, false, 2),
    (0xa480c000, 16, 16, false, false, 1),
    (0x84008000, 32, 8, false, true, 0),
    (0xc4008000, 64, 8, false, true, 0),
    (0x84808000, 32, 16, false, true, 0),
    (0xc4808000, 64, 16, false, true, 0),
    (0xc5008000, 64, 32, false, true, 0),
    (0x8500a000, 32, 32, false, false, 0),
    (0xc500c000, 64, 32, false, false, 0),
    (0xa500e000, 32, 32, false, false, 2),
    (0xa500c000, 32, 32, false, false, 1),
    (0xe4402000, 32, 8, true, false, 0),
    (0xe4002000, 64, 8, true, false, 0),
    (0xe410e000, 8, 8, true, false, 2),
    (0xe4006000, 8, 8, true, false, 1),
    (0xe5802000, 64, 64, true, false, 0),
    (0xe590e000, 64, 64, true, false, 2),
    (0xe5806000, 64, 64, true, false, 1),
    (0xe4c02000, 32, 16, true, false, 0),
    (0xe4802000, 64, 16, true, false, 0),
    (0xe490e000, 16, 16, true, false, 2),
    (0xe4806000, 16, 16, true, false, 1),
    (0xe5402000, 32, 32, true, false, 0),
    (0xe5002000, 64, 32, true, false, 0),
    (0xe510e000, 32, 32, true, false, 2),
    (0xe5006000, 32, 32, true, false, 1),
];
#[cfg(test)]
mod nontemporal {
    use super::*;
    const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
    #[test]
    fn all_classes_match_independent_bytes_lanes_aliases_and_endian() {
        assert_eq!(CASES.len(), 35);
        for &(base, w, mw, store, signed, mode) in CASES {
            for vl in VLS {
                for endian in [Endian::Little, Endian::Big] {
                    for alias in [false, true] {
                        for variant in 0..4 {
                            let n = if mode == 0 { 31 } else { 1 };
                            let d = if alias && mode == 0 { 31 } else { 30 };
                            let m = if mode == 2 {
                                [0, 7, 8, 15][variant]
                            } else {
                                [0, 17, 30, if mode == 0 { 31 } else { 1 }][variant]
                            };
                            let word = base | (n << 5) | (m << 16) | d | (7 << 10);
                            let count = usize::from(vl) / usize::from(w);
                            let bases: Vec<_> = (0..count)
                                .map(|e| {
                                    if w == 32 {
                                        0xffff_0000 + e as u64 * 16
                                    } else {
                                        u64::MAX - 0x3000 + e as u64 * 16
                                    }
                                })
                                .collect();
                            let data: Vec<_> = (0..count)
                                .map(|e| {
                                    0xfedc_ba98_7654_3210u64.rotate_left((e * 7) as u32) & mask(w)
                                })
                                .collect();
                            let mut state = State::default();
                            state.context(mode != 0, false);
                            state.pred(7, vl, w, |e| e % 3 != 1);
                            state.vector(31, &bases, w);
                            if d != 31 {
                                state.vector(d as u16, &data, w);
                            }
                            let scalarbase = u64::MAX - 0x100;
                            state.set("a64.gpr", 1, 64, scalarbase);
                            let offset = if m == 31 {
                                0
                            } else {
                                [0, u64::MAX - 7, 0x1000, 0x1001][variant]
                            };
                            if mode != 2 && m != 31 {
                                state.set("a64.gpr", m as u16, 64, offset);
                            }
                            let scalarbase = if mode != 2 && m == 1 {
                                offset
                            } else {
                                scalarbase
                            };
                            let mut accesses = vec![];
                            let mut expected = vec![0; count];
                            let mut stores = vec![];
                            for e in 0..count {
                                if e % 3 == 1 {
                                    continue;
                                }
                                let a = if mode == 0 {
                                    (bases[e] & mask(w)).wrapping_add(offset)
                                } else {
                                    let off = if mode == 1 {
                                        offset.wrapping_mul(u64::from(mw / 8))
                                    } else {
                                        let signed = [0i64, 7, -8, -1][variant];
                                        (signed * i64::from(vl / 8)) as u64
                                    };
                                    scalarbase
                                        .wrapping_add(off)
                                        .wrapping_add(e as u64 * u64::from(mw / 8))
                                };
                                if store {
                                    stores.push((
                                        a,
                                        if d == 31 { bases[e] } else { data[e] } & mask(mw),
                                    ));
                                } else {
                                    let raw = (0x80fedcba98765481u64.rotate_left((e * 3) as u32))
                                        & mask(mw);
                                    state.fill(a, mw, raw, endian);
                                    let v = if signed {
                                        ((raw << (64 - mw)) as i64 >> (64 - mw)) as u64
                                    } else {
                                        raw
                                    };
                                    expected[e] = v & mask(w);
                                    accesses.push((a, mw, endian));
                                }
                            }
                            let before = state.regs.clone();
                            let r = a64(word, u64::MAX - 1, endian, vl).unwrap();
                            r.validate().unwrap();
                            let t = evaluate(&r, &state).unwrap();
                            assert_eq!(t.next_pc, Value::known(64, 2));
                            assert_eq!(state.regs, before);
                            if store {
                                assert!(t.registers.is_empty());
                                assert_eq!(t.memory.len(), stores.len());
                                for (actual, (a, v)) in t.memory.iter().zip(stores) {
                                    assert_eq!(
                                        (actual.address, actual.value, actual.endian),
                                        (a, Value::known(mw, v), endian)
                                    );
                                }
                                assert_eq!(
                                    t.events,
                                    (0..t.memory.len())
                                        .map(OrderedEvent::Store)
                                        .collect::<Vec<_>>()
                                );
                            } else {
                                assert_eq!(*state.reads.borrow(), accesses);
                                assert!(t.memory.is_empty());
                                assert_eq!(t.registers.len(), usize::from(vl / 64));
                                for (e, v) in expected.iter().enumerate() {
                                    let bit = e * usize::from(w);
                                    let ch = t
                                        .registers
                                        .iter()
                                        .find(|r| {
                                            r.register
                                                == Register {
                                                    bank: "a64.vector64",
                                                    index: d as u16 * 32 + (bit / 64) as u16,
                                                }
                                        })
                                        .unwrap();
                                    assert_eq!(
                                        (ch.value.bits >> (bit % 64)) & mask(w),
                                        *v,
                                        "{word:08x} VL{vl} e{e}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn empty_masks_suppress_unknown_addresses_sources_sp_and_memory() {
        for &(base, w, _, store, _, mode) in CASES {
            for vl in VLS {
                let word = base | (31 << 5) | (if mode == 2 { 15 } else { 30 } << 16);
                let mut s = State::default();
                if mode == 0 {
                    s.context(false, false);
                }
                s.pred(0, vl, w, |_| false);
                let t = evaluate(&a64(word, 0, Endian::Little, vl).unwrap(), &s).unwrap();
                assert!(s.reads.borrow().is_empty());
                assert!(t.memory.is_empty());
                assert!(s
                    .register_reads
                    .borrow()
                    .iter()
                    .all(|r| matches!(r.bank, "a64.predicate64" | "a64.svcr")));
                if !store {
                    assert!(t.registers.iter().all(|r| r.value == Value::known(64, 0)));
                }
            }
        }
    }
    #[test]
    fn nonstreaming_checks_precede_operands_but_contiguous_forms_allow_streaming() {
        for &(base, w, _, _, _, mode) in CASES {
            let mut s = State::default();
            s.context(true, false);
            let r = a64(base, 0, Endian::Little, 128).unwrap();
            if mode == 0 {
                assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
                assert!(s.reads.borrow().is_empty());
                assert!(s
                    .register_reads
                    .borrow()
                    .iter()
                    .all(|r| matches!(r.bank, "a64.svcr" | "a64.sme_fa64")));
                s.context(true, true);
            }
            s.pred(0, 128, w, |_| false);
            assert!(evaluate(&r, &s).is_ok());
        }
    }
    #[test]
    fn scalar_register_offset_31_is_reserved_vector_offset_31_is_xzr() {
        for &(base, w, _, _, _, mode) in CASES {
            if mode == 1 {
                assert!(a64(base | (31 << 16), 0, Endian::Little, 128).is_none());
            } else if mode == 0 {
                let mut s = State::default();
                s.context(false, false);
                s.pred(0, 128, w, |_| false);
                evaluate(&a64(base | (31 << 16), 0, Endian::Little, 128).unwrap(), &s).unwrap();
                assert!(!s
                    .register_reads
                    .borrow()
                    .iter()
                    .any(|r| r.bank == "a64.sp" || r.bank == "a64.gpr"));
            }
        }
    }
    #[test]
    fn sp_alignment_context_is_checked_before_active_access_and_empty_masks_choose_no_check() {
        for &(base, w, mw, store, _, mode) in CASES {
            if mode == 0 {
                continue;
            }
            for vl in VLS {
                let word = base | (31 << 5);
                let mut s = State::default();
                s.pred(0, vl, w, |e| e == 0);
                s.set("a64.sp", 0, 64, 0x1004);
                s.set("a64.gpr", 0, 64, 0);
                let r = a64(word, 0, Endian::Little, vl).unwrap();
                assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
                assert!(s.reads.borrow().is_empty());
                s.set("a64.sp", 0, 64, 0x1000);
                s.vector(0, &vec![17; usize::from(vl) / usize::from(w)], w);
                s.fill(0x1000, mw, 17, Endian::Little);
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(
                    if store {
                        t.memory.len()
                    } else {
                        s.reads.borrow().len()
                    },
                    1
                );
            }
        }
    }
    #[test]
    fn faults_stop_in_active_lane_order_without_publishing_alias_outputs() {
        for &(base, w, mw, store, _, mode) in CASES {
            if store {
                continue;
            }
            for vl in VLS {
                let n = if mode == 0 { 2 } else { 1 };
                let word = base | (n << 5) | 2;
                let count = usize::from(vl) / usize::from(w);
                let mut s = State::default();
                if mode == 0 {
                    s.context(false, false);
                }
                s.pred(0, vl, w, |e| count <= 2 || e != 1);
                s.set("a64.gpr", 0, 64, 0);
                s.set("a64.gpr", 1, 64, u64::MAX - 1);
                let bases: Vec<_> = (0..count)
                    .map(|e| {
                        if e == 0 {
                            u64::MAX - 1
                        } else {
                            0x2000 + e as u64 * 16
                        }
                    })
                    .collect();
                s.vector(2, &bases, w);
                let address = |e: usize| {
                    if mode == 0 {
                        bases[e] & mask(w)
                    } else {
                        (u64::MAX - 1).wrapping_add(e as u64 * u64::from(mw / 8))
                    }
                };
                s.fill(address(0), mw, 7, Endian::Little);
                let fail = 2.min(count - 1);
                s.fail = Some(address(fail));
                let before = s.regs.clone();
                assert_eq!(
                    evaluate(&a64(word, 0, Endian::Little, vl).unwrap(), &s),
                    Err(EvalError::Memory)
                );
                assert_eq!(s.regs, before);
                let expected = (0..=fail)
                    .filter(|e| count <= 2 || *e != 1)
                    .map(|e| (address(e), mw, Endian::Little))
                    .collect::<Vec<_>>();
                assert_eq!(*s.reads.borrow(), expected);
            }
        }
    }
    #[test]
    fn reserved_unrelated_and_invalid_lengths_do_not_inherit_semantics() {
        assert!(a64(0xd503201f, 0, Endian::Little, 128).is_none());
        for vl in [0, 64, 192, 384, 4096] {
            let r = a64(0xa400e000, 0, Endian::Little, vl).unwrap();
            assert!(matches!(r.support, Support::Unsupported(_)));
            assert!(r.effects.is_empty());
        }
    }
    #[test]
    fn actual_primary_diagrams_decode_and_execute_every_class() {
        assert_eq!(PRIMARY.len(), 140);
        for &(word, name) in PRIMARY {
            for vl in VLS {
                let r = a64(word, 0x1000, Endian::Big, vl)
                    .unwrap_or_else(|| panic!("{name} {word:08x}"));
                r.validate().unwrap();
                let mut s = State::default();
                s.context(false, false);
                for pg in 0..8 {
                    s.pred(pg, vl, 8, |_| false);
                }
                let t = evaluate(&r, &s).unwrap();
                assert!(t.memory.is_empty());
                assert!(s.reads.borrow().is_empty());
            }
        }
    }
}

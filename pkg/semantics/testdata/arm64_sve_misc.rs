#[allow(dead_code)]
#[path = "misc.rs"]
mod misc;
#[allow(dead_code)]
mod runtime;
use runtime::*;
fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    misc::a64(word, address, vl)
}
use std::{cell::RefCell, collections::HashMap};
#[derive(Default)]
struct State {
    registers: HashMap<Register, u64>,
    reads: RefCell<Vec<Register>>,
    forbidden_vectors: bool,
    forbidden_vector: Option<u16>,
    missing_cpta: bool,
}
impl State {
    fn set(&mut self, bank: &'static str, index: u16, value: u64) {
        self.registers.insert(Register { bank, index }, value);
    }
    fn element(&mut self, n: u16, e: u16, w: u8, value: u64) {
        let bit = e * u16::from(w);
        let r = Register {
            bank: "a64.vector64",
            index: n * 32 + bit / 64,
        };
        let old = *self.registers.get(&r).unwrap_or(&0);
        let mask = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
        self.registers.insert(
            r,
            (old & !(mask << (bit % 64))) | ((value & mask) << (bit % 64)),
        );
    }
    fn pred(&mut self, n: u16, e: u16, w: u8) {
        let bit = e * u16::from(w / 8);
        let r = Register {
            bank: "a64.predicate64",
            index: n * 4 + bit / 64,
        };
        let old = *self.registers.get(&r).unwrap_or(&0);
        self.registers.insert(r, old | (1 << (bit % 64)));
    }
    fn incoming(&self, n: u16, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        let mask = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
        self.registers
            .get(&Register {
                bank: "a64.vector64",
                index: n * 32 + bit / 64,
            })
            .copied()
            .unwrap_or(0)
            >> (bit % 64)
            & mask
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        if r.bank == "a64.vector64" {
            assert!(!self.forbidden_vectors, "inactive vector read");
            assert_ne!(
                self.forbidden_vector,
                Some(r.index / 32),
                "inactive second source read"
            );
        }
        let w = if matches!(r.bank, "a64.cpta" | "a64.sme_fa64" | "a64.nzcv") {
            1
        } else {
            64
        };
        if self.missing_cpta && r.bank == "a64.cpta" {
            Value::unknown(1)
        } else {
            Value::known(w, *self.registers.get(&r).unwrap_or(&0))
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("integer operation read memory")
    }
}
fn execute(word: u32, vl: u16, s: &State) -> Transition {
    let r = a64(word, 0xfffffffffffffffcu64, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    assert_eq!(t.next_pc.bits, 0);
    assert!(t.events.is_empty());
    t
}
fn written(t: &Transition, bank: &str, index: u16) -> u64 {
    t.registers
        .iter()
        .find(|v| v.register.bank == bank && v.register.index == index)
        .unwrap()
        .value
        .bits
}
fn result(t: &Transition, n: u16, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    let mask = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
    written(t, "a64.vector64", n * 32 + bit / 64) >> (bit % 64) & mask
}
fn active(e: u16, phase: u16) -> bool {
    (e + phase) % 5 != 1 && (e + phase) % 5 != 4
}
#[test]
fn match_segment_flags_padding_aliases_and_all_vls() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8u8, 16] {
            for inverse in [false, true] {
                for pg in [0u16, 3, 7] {
                    for pd in [0u16, 3, 15] {
                        for same in [false, true] {
                            let n = 31u16;
                            let m = if same { 31 } else { 2 };
                            let mut s = State::default();
                            for e in 0..vl / u16::from(w) {
                                s.element(
                                    n,
                                    e,
                                    w,
                                    u64::from((e * 7 + e / (128 / u16::from(w))) % 23),
                                );
                                if !same {
                                    s.element(m, e, w, u64::from((e * 11 + 3) % 23));
                                }
                                if active(e, pg) {
                                    s.pred(pg, e, w);
                                }
                            }
                            let word = 0x45208000
                                | ((w == 16) as u32) << 22
                                | ((inverse as u32) << 4)
                                | ((m as u32) << 16)
                                | ((pg as u32) << 10)
                                | ((n as u32) << 5)
                                | u32::from(pd);
                            let t = execute(word, vl, &s);
                            let mut expected = [0u64; 4];
                            let mut selected = Vec::new();
                            for e in 0..vl / u16::from(w) {
                                let per = 128 / u16::from(w);
                                let found = (e / per * per..e / per * per + per)
                                    .any(|i| s.incoming(n, e, w) == s.incoming(m, i, w));
                                let v = active(e, pg) && (found ^ inverse);
                                if active(e, pg) {
                                    selected.push(v);
                                }
                                if v {
                                    let bit = e * u16::from(w / 8);
                                    expected[(bit / 64) as usize] |= 1 << (bit % 64);
                                }
                            }
                            for chunk in 0..4 {
                                assert_eq!(
                                    written(&t, "a64.predicate64", pd * 4 + chunk),
                                    expected[chunk as usize],
                                    "{word:08x} VL{vl}"
                                );
                            }
                            for (i, v) in [
                                *selected.first().unwrap_or(&false),
                                !selected.iter().any(|v| *v),
                                !*selected.last().unwrap_or(&false),
                                false,
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                assert_eq!(written(&t, "a64.nzcv", i as u16), v as u64);
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn match_searches_inactive_second_source_lanes_but_not_other_segments() {
    for vl in [128, 256, 512, 1024, 2048] {
        let mut s = State::default();
        for e in 0..vl / 8 {
            s.element(1, e, 8, 42);
            s.element(2, e, 8, 99);
        }
        s.element(2, 15, 8, 42);
        s.pred(0, 0, 8);
        if vl > 128 {
            s.pred(0, 16, 8);
        }
        let t = execute(0x45228020, vl, &s);
        assert_eq!(written(&t, "a64.predicate64", 0), 1);
    }
}
#[test]
fn histcnt_prefix_is_whole_vl_and_counts_only_active_lanes_with_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32u8, 64] {
            for d in [0u16, 1, 2, 31] {
                for same in [false, true] {
                    let n = 1;
                    let m = if same { 1 } else { 2 };
                    let mut s = State::default();
                    for e in 0..vl / u16::from(w) {
                        s.element(n, e, w, u64::from(e % 3));
                        if !same {
                            s.element(m, e, w, u64::from((e + 1) % 3));
                        }
                        if active(e, 0) {
                            s.pred(0, e, w);
                        }
                    }
                    let word = 0x4520c000
                        | ((w.trailing_zeros() - 3) << 22)
                        | ((m as u32) << 16)
                        | ((n as u32) << 5)
                        | u32::from(d);
                    let t = execute(word, vl, &s);
                    for e in 0..vl / u16::from(w) {
                        let count = if active(e, 0) {
                            (0..=e)
                                .filter(|i| {
                                    active(*i, 0) && s.incoming(n, e, w) == s.incoming(m, *i, w)
                                })
                                .count() as u64
                        } else {
                            0
                        };
                        assert_eq!(result(&t, d, e, w), count, "{word:08x} e{e} VL{vl}");
                    }
                    assert!(!t.registers.iter().any(|v| v.register.bank == "a64.nzcv"));
                }
            }
        }
    }
    // Every lane equal: later segments must include earlier segments' matches.
    for vl in [128, 256, 512, 1024, 2048] {
        let mut s = State::default();
        for e in 0..vl / 32 {
            s.pred(0, e, 32);
        }
        let t = execute(0x45a2c020, vl, &s);
        assert_eq!(result(&t, 0, vl / 32 - 1, 32), u64::from(vl / 32));
    }
}
#[test]
fn histseg_counts_all_sixteen_bytes_in_each_segment_alias_and_boundaries() {
    for vl in [128, 256, 512, 1024, 2048] {
        for d in [0u16, 1, 2, 31] {
            for same in [false, true] {
                let n = 1;
                let m = if same { 1 } else { 2 };
                let mut s = State::default();
                for e in 0..vl / 8 {
                    s.element(n, e, 8, u64::from((e + e / 16) % 7));
                    if !same {
                        s.element(m, e, 8, u64::from((e * 3 + e / 16) % 7));
                    }
                }
                let word = 0x4520a000 | ((m as u32) << 16) | ((n as u32) << 5) | u32::from(d);
                let t = execute(word, vl, &s);
                for e in 0..vl / 8 {
                    let count = (e / 16 * 16..e / 16 * 16 + 16)
                        .filter(|i| s.incoming(n, e, 8) == s.incoming(m, *i, 8))
                        .count() as u64;
                    assert_eq!(result(&t, d, e, 8), count);
                }
            }
        }
        let t = execute(0x4522a020, vl, &State::default());
        for e in 0..vl / 8 {
            assert_eq!(result(&t, 0, e, 8), 16);
        }
    }
}
fn pointer_reference(base: u64, offset: u64, sub: bool, enabled: bool) -> u64 {
    let result = if sub {
        base.wrapping_sub(offset)
    } else {
        base.wrapping_add(offset)
    };
    if enabled && (((base >> 55) ^ (base >> 54)) & 1 != 0 || result >> 56 != base >> 56) {
        (base & 0xff80000000000000) | ((!(base >> 55) & 1) << 54) | (result & 0x003fffffffffffff)
    } else {
        result
    }
}
#[test]
fn checked_pointer_wrap_poison_disabled_predicates_aliases_and_all_vls() {
    let bases = [
        0,
        1,
        u64::MAX,
        0x003fffffffffffff,
        0x0040000000000000,
        0x0080000000000000,
        0x00ffffffffffffff,
        0xab00000000000001,
    ];
    let offsets = [0, 1, u64::MAX, 0x0100000000000000, 0xff00000000000000];
    for vl in [128, 256, 512, 1024, 2048] {
        for sub in [false, true] {
            for pred in [false, true] {
                for enabled in [false, true] {
                    for d in [0u16, 1, 2, 31] {
                        for phase in 0..8 {
                            let n = if pred { d } else { 1 };
                            let m = 2;
                            let mut s = State::default();
                            s.set("a64.cpta", 0, enabled as u64);
                            for e in 0..vl / 64 {
                                s.element(n, e, 64, bases[(e as usize + phase) % bases.len()]);
                                s.element(m, e, 64, offsets[(e as usize + phase) % offsets.len()]);
                                if active(e, 0) {
                                    s.pred(0, e, 64);
                                }
                            }
                            let word = if pred {
                                0x04c40000 | ((sub as u32) << 16) | ((m as u32) << 5) | u32::from(d)
                            } else {
                                0x04e00800
                                    | ((sub as u32) << 10)
                                    | ((m as u32) << 16)
                                    | ((n as u32) << 5)
                                    | u32::from(d)
                            };
                            let t = execute(word, vl, &s);
                            for e in 0..vl / 64 {
                                let base = s.incoming(n, e, 64);
                                let want = if !pred || active(e, 0) {
                                    pointer_reference(base, s.incoming(m, e, 64), sub, enabled)
                                } else {
                                    base
                                };
                                assert_eq!(result(&t, d, e, 64), want, "{word:08x} e{e} VL{vl}");
                            }
                            assert!(!t.registers.iter().any(|v| v.register.bank == "a64.nzcv"));
                            assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.cptm"));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn inactive_sources_and_cpta_are_lazy_empty_flags_are_exact() {
    for vl in [128, 256, 512, 1024, 2048] {
        for word in [0x45228020, 0x45228030, 0x45a2c020, 0x45e2c020] {
            let s = State {
                forbidden_vectors: true,
                ..State::default()
            };
            let t = execute(word, vl, &s);
            if word & 0xe000 == 0x8000 {
                for (i, v) in [0, 1, 1, 0].into_iter().enumerate() {
                    assert_eq!(written(&t, "a64.nzcv", i as u16), v);
                }
            }
        }
        let mut s = State {
            missing_cpta: true,
            forbidden_vector: Some(2),
            ..State::default()
        };
        for e in 0..vl / 64 {
            s.element(0, e, 64, u64::from(e) + 1);
        }
        let t = execute(0x04c40040, vl, &s);
        for e in 0..vl / 64 {
            assert_eq!(result(&t, 0, e, 64), u64::from(e) + 1);
        }
        assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.cpta"));
        s.forbidden_vector = None;
        s.pred(0, 0, 64);
        assert!(matches!(
            evaluate(&a64(0x04c40040, 0, vl).unwrap(), &s),
            Err(EvalError::UnknownCondition)
        ));
    }
}
#[test]
fn context_precedes_operands_and_reserved_sizes_and_vls_are_rejected() {
    for word in [
        0x45228020, 0x45228030, 0x45a2c020, 0x4522a020, 0x04e20820, 0x04e20c20, 0x04c40040,
        0x04c50040,
    ] {
        let mut s = State {
            forbidden_vectors: true,
            ..State::default()
        };
        s.set("a64.svcr", 0, 1);
        assert!(matches!(
            evaluate(&a64(word, 0, 128).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        ));
        assert!(s
            .reads
            .borrow()
            .iter()
            .all(|r| matches!(r.bank, "a64.svcr" | "a64.sme_fa64")));
        s.forbidden_vectors = false;
        s.set("a64.sme_fa64", 0, 1);
        assert!(evaluate(&a64(word, 0, 128).unwrap(), &s).is_ok());
        for vl in [0, 64, 192, 4096] {
            assert!(a64(word, 0, vl).is_none());
        }
    }
    for size in 0..4 {
        for base in [0x4520c000, 0x4520a000] {
            let admitted =
                a64(base | (size << 22), 0, 128).is_some_and(|r| r.support == Support::Full);
            assert_eq!(
                admitted,
                if base == 0x4520c000 {
                    size >= 2
                } else {
                    size == 0
                }
            );
        }
    }
}

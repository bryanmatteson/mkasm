#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::HashMap};
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
fn reg(bank: &'static str, index: u16) -> Register {
    Register { bank, index }
}
#[derive(Clone)]
struct State {
    p: [[u64; 4]; 16],
    x: [u64; 31],
    flags: [u64; 4],
    svcr: u64,
    cap: u64,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            p: std::array::from_fn(|n| {
                std::array::from_fn(|c| 0xfedcba9876543210u64.rotate_right((n + c) as u32))
            }),
            x: std::array::from_fn(|n| n as u64 * 13),
            flags: [0, 1, 0, 1],
            svcr: 0,
            cap: 1,
            reads: RefCell::new(Vec::new()),
        }
    }
    fn value(&self, r: Register) -> Value {
        match r.bank {
            "a64.predicate64" => {
                Value::known(64, self.p[(r.index / 4) as usize][(r.index % 4) as usize])
            }
            "a64.gpr" => Value::known(64, self.x[r.index as usize]),
            "a64.nzcv" => Value::known(1, self.flags[r.index as usize]),
            "a64.svcr" => Value::known(64, self.svcr),
            "a64.sve2p1" => Value::known(1, self.cap),
            _ => panic!("unexpected counter input {r:?}"),
        }
    }
    fn set_counter(&mut self, n: u16, value: u16) {
        self.p[n as usize][0] = (self.p[n as usize][0] & !0xffff) | u64::from(value);
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        self.value(r)
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("predicate counter accessed memory")
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_counter::a64(word, 0x1000, vl)
}
fn evaluate_case(r: &Recipe, s: &State, wanted: HashMap<Register, u64>) {
    s.reads.borrow_mut().clear();
    let t = evaluate(r, s).unwrap();
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    let mut actual = HashMap::new();
    for w in t.registers {
        assert_eq!(
            w.value,
            Value::known(
                if w.register.bank == "a64.nzcv" { 1 } else { 64 },
                wanted
                    .get(&w.register)
                    .copied()
                    .unwrap_or_else(|| s.value(w.register).bits)
            ),
            "{:?}",
            w.register
        );
        assert!(actual.insert(w.register, w.value.bits).is_none());
    }
    for (reg, v) in wanted {
        assert_eq!(
            actual
                .get(&reg)
                .copied()
                .unwrap_or_else(|| s.value(reg).bits),
            v,
            "missing {reg:?}"
        );
    }
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x} VL{vl}"));
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    r
}
fn put_p(out: &mut HashMap<Register, u64>, d: u16, bits: &[bool]) {
    for chunk in 0..4u16 {
        let value = (0..64u16).fold(0, |a, b| {
            a | if bits
                .get(usize::from(chunk * 64 + b))
                .copied()
                .unwrap_or(false)
            {
                1 << b
            } else {
                0
            }
        });
        out.insert(reg("a64.predicate64", d * 4 + chunk), value);
    }
}
fn put_counter(out: &mut HashMap<Register, u64>, d: u16, value: u16) {
    for chunk in 0..4 {
        out.insert(
            reg("a64.predicate64", d * 4 + chunk),
            if chunk == 0 { u64::from(value) } else { 0 },
        );
    }
}
// Literal primary CounterToPredicate: trailing tag selects stride, the count
// precision depends on CurrentVL, zero tag is empty even when inverted.
fn expanded(counter: u16, vl: u16) -> Vec<bool> {
    let pl = usize::from(vl / 8);
    let mut bits = vec![false; pl * 4];
    if counter & 15 == 0 {
        return bits;
    }
    let stride = 1usize << counter.trailing_zeros();
    let top = (pl * 4).ilog2();
    let count = usize::from(counter & ((1u16 << (top + 1)) - 1)) / (stride * 2);
    let invert = counter & 0x8000 != 0;
    for e in 0..bits.len() / stride {
        bits[e * stride] = (e < count) ^ invert;
    }
    bits
}
fn oracle_encode(size: u32, elements: u16, mut count: u16, mut invert: bool) -> u16 {
    if count == 0 {
        return 0;
    }
    if invert {
        count = elements - count;
    } else if count == elements {
        count = 0;
        invert = true;
    }
    (u16::from(invert) << 15) | (count << (size + 1)) | (1 << size)
}
fn while_word(
    size: u32,
    width: u16,
    unsigned: bool,
    up: bool,
    eq: bool,
    n: u32,
    m: u32,
    d: u32,
) -> u32 {
    0x25204010
        | (size << 22)
        | (m << 16)
        | (u32::from(width == 4) << 13)
        | (u32::from(unsigned) << 11)
        | (u32::from(up) << 10)
        | (n << 5)
        | (u32::from(eq) << 3)
        | d
}
fn oracle_while(
    mut a: u64,
    b: u64,
    size: u32,
    width: u16,
    unsigned: bool,
    up: bool,
    eq: bool,
    vl: u16,
) -> (u16, [u64; 4]) {
    let elements = width * vl / (8 << size);
    let mut last = true;
    let mut count = 0;
    for _ in 0..elements {
        let cond = if unsigned {
            if up {
                if eq {
                    a <= b
                } else {
                    a < b
                }
            } else if eq {
                a > b
            } else {
                a >= b
            }
        } else if up {
            if eq {
                (a as i64) <= (b as i64)
            } else {
                (a as i64) < (b as i64)
            }
        } else if eq {
            (a as i64) > (b as i64)
        } else {
            (a as i64) >= (b as i64)
        };
        last &= cond;
        count += u16::from(last);
        a = if up {
            a.wrapping_add(1)
        } else {
            a.wrapping_sub(1)
        };
    }
    let invert = !up;
    let flags = [
        u64::from(if invert {
            count == elements
        } else {
            count != 0
        }),
        u64::from(count == 0),
        u64::from(if invert {
            count == 0
        } else {
            count != elements
        }),
        0,
    ];
    (oracle_encode(size, elements, count, invert), flags)
}
#[test]
fn ptrue_pn_aliases_p_and_clears_upper_storage_without_flags_or_source_reads() {
    for vl in VLS {
        for size in 0..4 {
            for d in 0..8 {
                let s = State::new();
                let mut out = HashMap::new();
                put_counter(&mut out, d + 8, 0x8000 | (1 << size));
                evaluate_case(
                    &build(0x25207810 | (size << 22) | u32::from(d), vl),
                    &s,
                    out,
                );
                assert!(s.reads.borrow().iter().all(|r| r.bank == "a64.sve2p1"));
            }
        }
    }
}
#[test]
fn all_while_relations_widths_lengths_bounds_and_64bit_wrap_match_literal_loop() {
    let values = [
        0,
        1,
        2,
        31,
        32,
        255,
        256,
        1023,
        1024,
        u64::MAX,
        u64::MAX - 1,
        0x7fff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_fffe,
        0x8000_0000_0000_0000,
        0x8000_0000_0000_0001,
    ];
    for vl in VLS {
        for size in 0..4 {
            for width in [2, 4] {
                for unsigned in [false, true] {
                    for up in [false, true] {
                        for eq in [false, true] {
                            let word = while_word(size, width, unsigned, up, eq, 5, 6, 7);
                            let r = build(word, vl);
                            for a in values {
                                for b in values {
                                    let mut s = State::new();
                                    s.x[5] = a;
                                    s.x[6] = b;
                                    let (counter, flags) =
                                        oracle_while(a, b, size, width, unsigned, up, eq, vl);
                                    let mut out = HashMap::new();
                                    put_counter(&mut out, 15, counter);
                                    for (i, v) in flags.into_iter().enumerate() {
                                        out.insert(reg("a64.nzcv", i as u16), v);
                                    }
                                    evaluate_case(&r, &s, out);
                                    assert!(s
                                        .reads
                                        .borrow()
                                        .iter()
                                        .all(|r| r.bank != "a64.predicate64"));
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
fn while_xzr_inputs_and_equal_register_aliases_do_not_read_sp() {
    for vl in VLS {
        for size in 0..4 {
            for up in [false, true] {
                for eq in [false, true] {
                    for (n, m) in [(31, 31), (31, 5), (5, 31), (5, 5)] {
                        let mut s = State::new();
                        s.x[5] = u64::MAX;
                        let a = if n == 31 { 0 } else { s.x[n as usize] };
                        let b = if m == 31 { 0 } else { s.x[m as usize] };
                        let (counter, flags) = oracle_while(a, b, size, 4, false, up, eq, vl);
                        let mut out = HashMap::new();
                        put_counter(&mut out, 8, counter);
                        for (i, v) in flags.into_iter().enumerate() {
                            out.insert(reg("a64.nzcv", i as u16), v);
                        }
                        evaluate_case(
                            &build(while_word(size, 4, false, up, eq, n, m, 0), vl),
                            &s,
                            out,
                        );
                    }
                }
            }
        }
    }
}
fn extraction_expected(
    raw: u16,
    vl: u16,
    size: u32,
    part: u16,
    d: u16,
    pair: bool,
) -> HashMap<Register, u64> {
    let bits = expanded(raw, vl);
    let pl = usize::from(vl / 8);
    let mut out = HashMap::new();
    for member in 0..if pair { 2 } else { 1 } {
        let base = usize::from(if pair { part * 2 + member } else { part }) * pl;
        let mut result = vec![false; pl];
        for bit in (0..pl).step_by(1 << size) {
            result[bit] = bits[base + bit];
        }
        put_p(&mut out, (d + member) % 16, &result);
    }
    out
}
fn counter_samples(vl: u16) -> Vec<u16> {
    let mut samples = vec![
        0, 0x8000, 0xffff, 0x7fff, 0xaaaa, 0x5555, 0x0010, 0x8010, 0x0080, 0x1234,
    ];
    for size in 0..4 {
        let elements = vl / (8 << size);
        for count in [
            0,
            1,
            2,
            elements - 1,
            elements,
            elements + 1,
            elements * 2 - 1,
            elements * 2,
            elements * 2 + 1,
            elements * 3 - 1,
            elements * 3,
            elements * 3 + 1,
            elements * 4 - 1,
        ] {
            for inv in [0, 0x8000] {
                samples.push((count << (size + 1)) | (1 << size) | inv);
            }
        }
    }
    samples.sort_unstable();
    samples.dedup();
    samples
}
#[test]
fn pext_all_parts_sizes_lengths_source_aliases_and_pair_wrap() {
    for vl in VLS {
        for size in 0..4 {
            for pair in [false, true] {
                for (n, d) in [(8u16, 8u16), (15, 15), (8, 7), (15, 0)] {
                    for part in 0..if pair { 2 } else { 4 } {
                        let r = build(
                            (if pair { 0x25207410 } else { 0x25207010 })
                                | (size << 22)
                                | (u32::from(part) << 8)
                                | (u32::from(n - 8) << 5)
                                | u32::from(d),
                            vl,
                        );
                        for raw in counter_samples(vl) {
                            let mut s = State::new();
                            s.set_counter(n, raw);
                            evaluate_case(
                                &r,
                                &s,
                                extraction_expected(raw, vl, size, part, d, pair),
                            );
                            assert!(s
                                .reads
                                .borrow()
                                .iter()
                                .filter(|r| r.bank == "a64.predicate64")
                                .all(|r| r.index == n * 4));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn cntp_interprets_counter_tag_and_precision_not_ordinary_predicate_popcount() {
    for vl in VLS {
        let top = (vl / 8 * 4).ilog2();
        for size in 0..4 {
            for width in [2, 4] {
                let r = build(
                    0x25208200 | (size << 22) | (u32::from(width == 4) << 10) | (3 << 5) | 5,
                    vl,
                );
                let mut s = State::new();
                for low in 0..1u16 << (top + 1) {
                    for inv in [0, 0x8000] {
                        for ignored in [0, 0x7fff & !((1u16 << (top + 1)) - 1)] {
                            let raw = low | inv | ignored;
                            s.set_counter(3, raw);
                            let bits = expanded(raw, vl);
                            let count = (0..usize::from(width * vl / 8))
                                .step_by(1 << size)
                                .filter(|&b| bits[b])
                                .count() as u64;
                            evaluate_case(&r, &s, HashMap::from([(reg("a64.gpr", 5), count)]));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn cntp_all_16bit_patterns_and_pn_registers_including_discarded_xzr() {
    let r = build(0x25208600 | (3 << 5) | 5, 128);
    let mut s = State::new();
    for raw in 0..=u16::MAX {
        s.set_counter(3, raw);
        let expected = expanded(raw, 128).into_iter().filter(|v| *v).count() as u64;
        evaluate_case(&r, &s, HashMap::from([(reg("a64.gpr", 5), expected)]));
    }
    for vl in VLS {
        for n in 0..16u16 {
            for d in [0, 31] {
                let mut s = State::new();
                s.set_counter(n, 0xffff);
                let expected = expanded(0xffff, vl).into_iter().filter(|v| *v).count() as u64;
                let r = build(0x25208600 | (u32::from(n) << 5) | d, vl);
                let out = if d == 31 {
                    HashMap::new()
                } else {
                    HashMap::from([(reg("a64.gpr", 0), expected)])
                };
                evaluate_case(&r, &s, out);
            }
        }
    }
}
#[test]
fn feature_and_streaming_context_guards_precede_inputs() {
    for word in [
        0x25207810,
        0x25204410 | (5 << 5) | (6 << 16),
        0x25207010,
        0x25207410,
        0x25208200,
    ] {
        for vl in VLS {
            let r = build(word, vl);
            for (cap, sm, allowed) in [
                (0, 0, false),
                (0, 2, false),
                (0, 1, true),
                (0, 3, true),
                (1, 0, true),
                (1, 1, true),
            ] {
                let mut s = State::new();
                s.cap = cap;
                s.svcr = sm;
                let actual = evaluate(&r, &s);
                if allowed {
                    assert!(actual.is_ok());
                    if cap == 1 {
                        assert!(s.reads.borrow().iter().all(|r| r.bank != "a64.svcr"));
                    }
                } else {
                    assert!(matches!(actual, Err(EvalError::UnsupportedContext)));
                    assert!(s
                        .reads
                        .borrow()
                        .iter()
                        .all(|r| matches!(r.bank, "a64.sve2p1" | "a64.svcr")));
                }
            }
        }
    }
    for vl in [0, 64, 192, 384, 768, 1536, 4096] {
        let s = State::new();
        if let Some(r) = recipe(0x25207810, vl) {
            assert!(matches!(
                evaluate(&r, &s),
                Err(EvalError::UnsupportedContext)
            ));
        }
        assert!(s.reads.borrow().is_empty());
    }
}
#[test]
fn ordinary_predicate_and_reserved_forms_are_outside_counter_dispatch() {
    for word in [
        0x2518e3e0, 0x25208020, 0x25201400, 0x25207818, 0x25207000, 0x25207400, 0x2520a200,
        0x25205410,
    ] {
        assert!(
            semantics::arm64_sve_counter::a64(word, 0x1000, 128).is_none(),
            "overadmitted {word:08x}"
        );
    }
}

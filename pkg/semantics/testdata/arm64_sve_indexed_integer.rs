#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
const OPS: [u32; 3] = [0x0800, 0x0c00, 0xf800];
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    defined: [[u64; 32]; 32],
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|k| {
                    0x9e3779b97f4a7c15u64
                        .wrapping_mul((n * 37 + k + 1) as u64)
                        .rotate_left((k * 13 % 64) as u32)
                })
            }),
            defined: [[u64::MAX; 32]; 32],
            reads: RefCell::new(vec![]),
        }
    }
    fn get(&self, n: u32, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        (self.z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
    }
    fn put(&mut self, n: u32, e: u16, w: u8, value: u64) {
        let bit = e * u16::from(w);
        let chunk = &mut self.z[n as usize][usize::from(bit / 64)];
        *chunk = (*chunk & !(mask(w) << (bit % 64))) | ((value & mask(w)) << (bit % 64));
    }
    fn unavailable(&mut self, n: u32, e: u16, w: u8) {
        let bit = e * u16::from(w);
        self.defined[n as usize][usize::from(bit / 64)] &= !(mask(w) << (bit % 64));
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        assert_eq!(
            r.bank, "a64.vector64",
            "unexpected indexed integer input {r:?}"
        );
        Value {
            bits: self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            defined: self.defined[usize::from(r.index / 32)][usize::from(r.index % 32)],
            width: 64,
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("indexed integer accessed memory")
    }
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1 << w) - 1
    }
}
fn word(w: u8, op: usize, index: u16, d: u32, n: u32, m: u32) -> u32 {
    assert!(index < 128 / u16::from(w));
    assert!(m < if w == 64 { 16 } else { 8 });
    let base = match w {
        16 => 0x44200000,
        32 => 0x44a00000,
        64 => 0x44e00000,
        _ => panic!("unallocated width"),
    };
    let selector = match w {
        16 => ((u32::from(index) & 4) << 20) | ((u32::from(index) & 3) << 19),
        32 => u32::from(index) << 19,
        _ => u32::from(index) << 20,
    };
    base | OPS[op] | selector | (m << 16) | (n << 5) | d
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_indexed_integer::a64(word, 0x1000, vl)
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full, "{word:08x} VL{vl}");
    r.validate().unwrap();
    r
}
fn result(a: u64, b: u64, old: u64, w: u8, op: usize) -> u64 {
    // Independent wide arithmetic explicitly truncates the product before
    // accumulation, retaining the primary's two modulo boundaries.
    let product = (u128::from(a) * u128::from(b)) & u128::from(mask(w));
    let value = match op {
        0 => u128::from(old) + product,
        1 => u128::from(old).wrapping_sub(product),
        _ => product,
    };
    (value & u128::from(mask(w))) as u64
}
fn check_recipe(
    r: &Recipe,
    vl: u16,
    s: &State,
    w: u8,
    op: usize,
    index: u16,
    d: u32,
    n: u32,
    m: u32,
) {
    let t = evaluate(r, s).unwrap();
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert!(
        t.memory.is_empty()
            && t.wide_memory.is_empty()
            && t.atomics.is_empty()
            && t.events.is_empty()
            && t.trap.is_none()
    );
    assert_eq!(t.registers.len(), usize::from(vl / 64));
    let mut actual = s.z[d as usize];
    for out in &t.registers {
        assert_eq!(out.register.bank, "a64.vector64");
        assert_eq!(out.register.index / 32, d as u16);
        assert!(out.register.index % 32 < vl / 64);
        assert!(out.value.is_known());
        actual[usize::from(out.register.index % 32)] = out.value.bits;
    }
    let mut expected = s.z[d as usize];
    for e in 0..vl / u16::from(w) {
        // Division into 128-bit segments, independently from helper chunk loops.
        let selected = (e * u16::from(w) / 128) * (128 / u16::from(w)) + index;
        let value = result(s.get(n, e, w), s.get(m, selected, w), s.get(d, e, w), w, op);
        let bit = e * u16::from(w);
        let at = usize::from(bit / 64);
        expected[at] = (expected[at] & !(mask(w) << (bit % 64))) | (value << (bit % 64));
    }
    assert_eq!(
        actual, expected,
        "op{op} esize{w} index{index} VL{vl} d{d} n{n} m{m}"
    );
    for read in s.reads.borrow().iter() {
        assert_eq!(read.bank, "a64.vector64");
        assert!(read.index % 32 < vl / 64);
        assert!(
            read.index / 32 == n as u16
                || read.index / 32 == m as u16
                || (op < 2 && read.index / 32 == d as u16)
        );
    }
    s.reads.borrow_mut().clear();
}
#[test]
fn every_index_width_vl_source_register_boundary_and_snapshot_alias() {
    for vl in VLS {
        for w in [16, 32, 64] {
            for op in 0..3 {
                for index in 0..128 / u16::from(w) {
                    let maxm = if w == 64 { 15 } else { 7 };
                    for (d, n, m) in [
                        (31, 30, maxm),
                        (0, 1, 2),
                        (2, 2, 3),
                        (3, 2, 3),
                        (2, 3, 3),
                        (3, 3, 3),
                        (maxm, maxm, maxm),
                    ] {
                        let s = State::new();
                        let r = build(word(w, op, index, d, n, m), vl);
                        check_recipe(&r, vl, &s, w, op, index, d, n, m);
                    }
                }
            }
        }
    }
}
#[test]
fn independent_arithmetic_boundaries_truncate_then_accumulate() {
    for w in [16, 32, 64] {
        let values = [
            0,
            1,
            2,
            3,
            mask(w),
            mask(w) - 1,
            1 << (w - 1),
            (1 << (w - 1)) - 1,
            (1 << (w - 1)) + 1,
            0xaaaa_aaaa_aaaa_aaaa & mask(w),
            0x5555_5555_5555_5555 & mask(w),
        ];
        for op in 0..3 {
            for index in [0, 128 / u16::from(w) - 1] {
                let r = build(word(w, op, index, 3, 2, 1), 128);
                for a in values {
                    for b in values {
                        for old in [0, 1, mask(w), 1 << (w - 1)] {
                            let mut s = State::new();
                            for e in 0..128 / u16::from(w) {
                                s.put(2, e, w, a);
                                s.put(3, e, w, old);
                                s.put(1, e, w, b);
                            }
                            check_recipe(&r, 128, &s, w, op, index, 3, 2, 1);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn exhaustive_byte_pairs_in_allocated_halfword_lanes() {
    let graphs: Vec<_> = (0..3)
        .map(|op| build(word(16, op, 7, 3, 2, 1), 128))
        .collect();
    let mut s = State::new();
    for b in 0..256 {
        for first in (0..256).step_by(8) {
            for e in 0..8 {
                s.put(2, e, 16, first + u64::from(e));
                s.put(
                    3,
                    e,
                    16,
                    [0, 1, 0x7fff, 0x8000, 0xffff, 0xfffe, 0x5555, 0xaaaa][e as usize],
                );
            }
            s.put(1, 7, 16, b);
            for (op, r) in graphs.iter().enumerate() {
                check_recipe(r, 128, &s, 16, op, 7, 3, 2, 1);
            }
        }
    }
}
#[test]
fn exhaustive_halfword_values_against_multiplier_boundaries() {
    let graphs: Vec<_> = (0..3)
        .map(|op| build(word(16, op, 4, 3, 2, 1), 128))
        .collect();
    let mut s = State::new();
    for b in [0, 1, 2, 0x7fff, 0x8000, 0xffff] {
        for first in (0..65536).step_by(8) {
            for e in 0..8 {
                s.put(2, e, 16, first + u64::from(e));
                s.put(
                    3,
                    e,
                    16,
                    [0, 1, 0x7fff, 0x8000, 0xffff, 0xfffe, 0x5555, 0xaaaa][e as usize],
                );
            }
            s.put(1, 4, 16, b);
            for (op, r) in graphs.iter().enumerate() {
                check_recipe(r, 128, &s, 16, op, 4, 3, 2, 1);
            }
        }
    }
}
#[test]
fn segment_local_selection_and_fresh_mul_destination_need_no_other_lanes() {
    for vl in VLS {
        for w in [16, 32, 64] {
            for index in 0..128 / u16::from(w) {
                for op in 0..3 {
                    let mut s = State::new();
                    for e in 0..vl / u16::from(w) {
                        if e % (128 / u16::from(w)) != index {
                            s.unavailable(1, e, w);
                        }
                    }
                    if op == 2 {
                        s.defined[3] = [0; 32];
                    }
                    let r = build(word(w, op, index, 3, 2, 1), vl);
                    check_recipe(&r, vl, &s, w, op, index, 3, 2, 1);
                    let selected_chunks: Vec<_> = (0..vl / 128)
                        .map(|seg| (seg * 128 + index * u16::from(w)) / 64)
                        .collect();
                    // check_recipe clears the log, so evaluate once more to inspect all
                    // source storage touches. Inactive whole chunks are never requested.
                    evaluate(&r, &s).unwrap();
                    assert!(s
                        .reads
                        .borrow()
                        .iter()
                        .filter(|r| r.index / 32 == 1)
                        .all(|r| selected_chunks.contains(&(r.index % 32))));
                    if op == 2 {
                        assert!(!s.reads.borrow().iter().any(|r| r.index / 32 == 3));
                    }
                }
            }
        }
    }
}
#[test]
fn required_lane_unavailability_propagates_without_fabricated_known_result() {
    for vl in VLS {
        for w in [16, 32, 64] {
            for op in 0..3 {
                for missing in [1, 2, 3] {
                    if missing == 3 && op == 2 {
                        continue;
                    }
                    let mut s = State::new();
                    s.unavailable(missing, 0, w);
                    let t = evaluate(&build(word(w, op, 0, 3, 2, 1), vl), &s).unwrap();
                    let first = t
                        .registers
                        .iter()
                        .find(|r| r.register.index == 3 * 32)
                        .unwrap();
                    assert_eq!(first.value.defined & mask(w), 0);
                    for out in &t.registers {
                        if out.register.index % 32 >= 2 {
                            assert!(out.value.is_known());
                        }
                    }
                }
            }
        }
    }
}
const MASKS: [(u32, u32); 9] = [
    (0xffa0fc00, 0x44200800),
    (0xffe0fc00, 0x44a00800),
    (0xffe0fc00, 0x44e00800),
    (0xffa0fc00, 0x44200c00),
    (0xffe0fc00, 0x44a00c00),
    (0xffe0fc00, 0x44e00c00),
    (0xffa0fc00, 0x4420f800),
    (0xffe0fc00, 0x44a0f800),
    (0xffe0fc00, 0x44e0f800),
];
#[test]
fn exact_physical_neighbors_no_byte_form_and_invalid_vl() {
    for (mask, base) in MASKS {
        for variables in [0, u32::MAX, 0xaaaaaaaa, 0x55555555] {
            for bit in 0..32 {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let neighbor = (base | (variables & !mask)) ^ (1 << bit);
                assert_eq!(
                    semantics::arm64_sve_indexed_integer::a64(neighbor, 0x1000, 128).is_some(),
                    MASKS.iter().any(|(m, b)| neighbor & m == *b),
                    "{neighbor:08x}"
                );
            }
        }
        for vl in [0, 64, 384, 768, 4096] {
            assert!(matches!(
                semantics::arm64_sve_indexed_integer::a64(base, 0, vl)
                    .unwrap()
                    .support,
                Support::Unsupported(_)
            ));
        }
    }
    for op in OPS {
        assert!(semantics::arm64_sve_indexed_integer::a64(0x44000000 | op, 0, 128).is_none());
    }
}
#[test]
fn all_physical_sample_words_and_address_wrap() {
    for raw in [
        0x44ef0ba4, 0x44270ba4, 0x44a70ba4, 0x44ef0fa4, 0x44270fa4, 0x44a70fa4, 0x44effadd,
        0x4427fadd, 0x44a7fadd,
    ] {
        for vl in VLS {
            let r = semantics::arm64_sve_indexed_integer::a64(raw, u64::MAX - 2, vl).unwrap();
            r.validate().unwrap();
            let s = State::new();
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.next_pc, Value::known(64, 1));
        }
    }
}

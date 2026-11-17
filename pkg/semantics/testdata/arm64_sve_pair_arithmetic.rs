#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
const BASES: [u32; 6] = [
    0x04207800, 0x04207c00, 0x4400d400, 0x4400dc00, 0x4410a000, 0x4501d800,
];
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    missing: Option<u16>,
    unavailable_chunks: Vec<u16>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|k| 0x9e3779b97f4a7c15u64.wrapping_mul((n * 37 + k + 1) as u64))
            }),
            p: [[u64::MAX; 4]; 16],
            missing: None,
            unavailable_chunks: vec![],
            reads: RefCell::new(vec![]),
        }
    }
    fn get(&self, n: u32, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        self.z[n as usize][usize::from(bit / 64)] >> (bit % 64) & mask(w)
    }
    fn put(&mut self, n: u32, e: u16, w: u8, v: u64) {
        let bit = e * u16::from(w);
        let out = &mut self.z[n as usize][usize::from(bit / 64)];
        *out = (*out & !(mask(w) << (bit % 64))) | ((v & mask(w)) << (bit % 64));
    }
    fn active(&self, g: usize, e: u16, w: u8) -> bool {
        let bit = e * u16::from(w) / 8;
        self.p[g][usize::from(bit / 64)] >> (bit % 64) & 1 != 0
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        match r.bank {
            "a64.vector64"
                if self.missing == Some(r.index / 32)
                    || self.unavailable_chunks.contains(&r.index) =>
            {
                Value::unknown(64)
            }
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.predicate64" => Value::known(
                64,
                self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
            ),
            _ => panic!("pair arithmetic read unexpected state {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("arithmetic accessed memory")
    }
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1 << w) - 1
    }
}
fn signed(v: u64, w: u8) -> i128 {
    let v = (v & mask(w)) as i128;
    if v & (1i128 << (w - 1)) != 0 {
        v - (1i128 << w)
    } else {
        v
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_pair_arithmetic::a64(word, 0x1000, vl)
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x}"));
    assert_eq!(r.support, Support::Full, "{word:08x}");
    r.validate().unwrap();
    r
}
fn word(op: usize, size: u32, d: u32, n: u32, m: u32, rot: u32) -> u32 {
    BASES[op]
        | (size << 22)
        | d
        | (n << 5)
        | if op <= 3 {
            m << 16
        } else if op == 5 {
            rot << 10
        } else {
            0
        }
}
fn reference(s: &State, op: usize, w: u8, vl: u16, d: u32, n: u32, m: u32, rot: u32) -> Vec<u64> {
    (0..vl / u16::from(w))
        .map(|e| match op {
            0 => {
                let per = 128 / u16::from(w);
                let pair = e % per;
                let source = if pair < per / 2 { n } else { m };
                let index = e / per * per + (pair % (per / 2)) * 2;
                s.get(source, index, w)
                    .wrapping_add(s.get(source, index + 1, w))
                    & mask(w)
            }
            1 => {
                let source = if e % 2 == 0 { n } else { m };
                let i = e & !1;
                (if e % 2 == 0 {
                    s.get(source, i, w).wrapping_add(s.get(source, i + 1, w))
                } else {
                    s.get(source, i, w).wrapping_sub(s.get(source, i + 1, w))
                }) & mask(w)
            }
            2 | 3 => {
                let mut total = s.get(d, e, w) as u128;
                for h in 0..2 {
                    let a = s.get(n, 2 * e + h, w / 2);
                    let b = s.get(m, 2 * e + h, w / 2);
                    total += if op == 2 {
                        (signed(a, w / 2) - signed(b, w / 2)).unsigned_abs()
                    } else {
                        u128::from(a.abs_diff(b))
                    };
                }
                total as u64 & mask(w)
            }
            4 => {
                if s.active(0, e, w) {
                    let source = if e % 2 == 0 { d } else { n };
                    let i = e & !1;
                    s.get(source, i, w).wrapping_sub(s.get(source, i + 1, w)) & mask(w)
                } else {
                    s.get(d, e, w)
                }
            }
            _ => {
                let a = signed(s.get(d, e, w), w);
                let b = signed(s.get(n, e ^ 1, w), w);
                let total = if (e % 2 == 0) == (rot == 0) {
                    a - b
                } else {
                    a + b
                };
                total.clamp(-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1) as u64 & mask(w)
            }
        })
        .collect()
}
fn check(word: u32, vl: u16, s: &State, d: u32, w: u8, want: &[u64]) {
    let r = build(word, vl);
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x} VL{vl}: {e:?}"));
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert_eq!(t.trap, None);
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    assert_eq!(t.registers.len(), usize::from(vl / 64));
    let mut out = s.z;
    for (k, wr) in t.registers.iter().enumerate() {
        assert_eq!(
            wr.register,
            Register {
                bank: "a64.vector64",
                index: d as u16 * 32 + k as u16
            }
        );
        let per = 64 / usize::from(w);
        let expected = (0..per).fold(0, |a, i| {
            a | ((want[k * per + i] & mask(w)) << (i * usize::from(w)))
        });
        assert_eq!(
            wr.value,
            Value::known(64, expected),
            "{word:08x} VL{vl} chunk{k}"
        );
        out[d as usize][k] = wr.value.bits;
    }
    assert_eq!(
        &out[d as usize][usize::from(vl / 64)..],
        &s.z[d as usize][usize::from(vl / 64)..]
    );
}
#[test]
fn all_families_sizes_lengths_and_aliases_match_independent_integer_references() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for op in 0..6 {
                if matches!(op, 2 | 3) && w == 8 {
                    continue;
                }
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                    for rot in 0..if op == 5 { 2 } else { 1 } {
                        let mut s = State::new();
                        for k in 0..4 {
                            s.p[0][k] = 0xa55a_f00f_5aa5_0ff0;
                        }
                        for reg in [0, 1, 2, 31] {
                            for e in 0..vl / u16::from(w) {
                                s.put(
                                    reg,
                                    e,
                                    w,
                                    [
                                        0,
                                        1,
                                        mask(w),
                                        1u64 << (w - 1),
                                        mask(w - 1),
                                        1u64 << (w - 2),
                                        3,
                                        mask(w) - 2,
                                    ][(usize::from(e) + reg as usize) % 8],
                                );
                            }
                        }
                        let want = reference(&s, op, w, vl, d, n, m, rot);
                        check(word(op, size, d, n, m, rot), vl, &s, d, w, &want);
                    }
                }
            }
        }
    }
}
#[test]
fn saturating_complex_fixed_goldens_and_signed_64_bit_boundaries_leave_fpsr_untouched() {
    for w in [8u8, 16, 32, 64] {
        let size = w.trailing_zeros() - 3;
        let mut s = State::new();
        let min = 1u64 << (w - 1);
        let max = mask(w - 1);
        for e in 0..128 / u16::from(w) {
            s.put(0, e, w, if e % 2 == 0 { min } else { max });
            s.put(1, e, w, if e % 2 == 0 { 1 } else { 1 });
        }
        let r = build(word(5, size, 0, 1, 0, 0), 128);
        let t = evaluate(&r, &s).unwrap();
        assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.fpsr"));
        assert!(!t.registers.iter().any(|r| r.register.bank == "a64.fpsr"));
        let want: Vec<_> = (0..128 / u16::from(w))
            .map(|e| if e % 2 == 0 { min } else { max })
            .collect();
        check(word(5, size, 0, 1, 0, 0), 128, &s, 0, w, &want);
        let want: Vec<_> = (0..128 / u16::from(w))
            .map(|e| if e % 2 == 0 { min + 1 } else { max - 1 })
            .collect();
        check(word(5, size, 0, 1, 0, 1), 128, &s, 0, w, &want);
    }
}
#[test]
fn predicated_pair_difference_does_not_read_unused_source_lanes() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let mut s = State::new();
            s.missing = Some(1);
            s.p[0] = [0; 4];
            let want = reference(&s, 4, w, vl, 0, 1, 0, 0);
            check(word(4, size, 0, 1, 0, 0), vl, &s, 0, w, &want);
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1));
            for e in (0..vl / u16::from(w)).step_by(2) {
                let bit = e * u16::from(w) / 8;
                s.p[0][usize::from(bit / 64)] |= 1 << (bit % 64);
            }
            let want = reference(&s, 4, w, vl, 0, 1, 0, 0);
            check(word(4, size, 0, 1, 0, 0), vl, &s, 0, w, &want);
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1));
            let bit = u16::from(w) / 8;
            s.p[0][usize::from(bit / 64)] |= 1 << (bit % 64);
            let transition = evaluate(&build(word(4, size, 0, 1, 0, 0), vl), &s).unwrap();
            assert!(transition
                .registers
                .iter()
                .any(|out| out.value.defined != mask(64)));
            assert!(s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1));
        }
    }
}
#[test]
fn hand_computed_pair_order_crosses_segments_and_accumulates_both_halves() {
    let mut s = State::new();
    for e in 0..32 {
        s.put(1, e, 8, e as u64);
        s.put(2, e, 8, 100 + e as u64);
    }
    let want: Vec<_> = [
        1, 5, 9, 13, 17, 21, 25, 29, 201, 205, 209, 213, 217, 221, 225, 229, 33, 37, 41, 45, 49,
        53, 57, 61, 233, 237, 241, 245, 249, 253, 1, 5,
    ]
    .into();
    check(word(0, 0, 0, 1, 2, 0), 256, &s, 0, 8, &want);
    let want: Vec<_> = (0..32)
        .map(|e| if e % 2 == 0 { (2 * e + 1) as u64 } else { 255 })
        .collect();
    check(word(1, 0, 0, 1, 2, 0), 256, &s, 0, 8, &want);
    for e in 0..16 {
        s.put(0, e, 16, 65530);
        s.put(1, 2 * e, 8, 128);
        s.put(1, 2 * e + 1, 8, 127);
        s.put(2, 2 * e, 8, 127);
        s.put(2, 2 * e + 1, 8, 128);
    }
    check(word(2, 1, 0, 1, 2, 0), 256, &s, 0, 16, &[504; 16]);
    check(word(3, 1, 0, 1, 2, 0), 256, &s, 0, 16, &[65532; 16]);
}
#[test]
fn owned_reserved_sizes_and_invalid_lengths_fail_explicitly() {
    for base in BASES {
        for vl in [0, 64, 129, 192, 4096] {
            assert!(matches!(
                semantics::arm64_sve_pair_arithmetic::a64(base, 0x1000, vl)
                    .unwrap()
                    .support,
                Support::Unsupported(_)
            ));
        }
    }
    for base in [0x4400d400, 0x4400dc00] {
        assert!(matches!(
            semantics::arm64_sve_pair_arithmetic::a64(base, 0x1000, 128)
                .unwrap()
                .support,
            Support::Unsupported(_)
        ));
    }
}

#[test]
fn review_sqcadd_exhaustive_signed_byte_pairs_both_rotations_without_qc() {
    for rot in 0..2 {
        let r = build(word(5, 0, 0, 31, 0, rot), 128);
        for a in 0u16..256 {
            for first in (0u16..256).step_by(8) {
                let mut s = State::new();
                let mut packed = [0u64; 2];
                for e in 0..16u16 {
                    let b = first + e / 2;
                    s.put(0, e, 8, u64::from(a));
                    s.put(31, e, 8, u64::from(b));
                    let (x, y) = (a as u8 as i8 as i16, b as u8 as i8 as i16);
                    let sum = if (e % 2 == 0) == (rot == 0) {
                        x - y
                    } else {
                        x + y
                    };
                    let v = sum.clamp(-128, 127) as u8 as u64;
                    packed[usize::from(e / 8)] |= v << ((e % 8) * 8);
                }
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(
                    [t.registers[0].value, t.registers[1].value],
                    packed.map(|v| Value::known(64, v)),
                    "rot{rot} a{a} first{first}"
                );
                assert_eq!(t.registers.len(), 2); // Saturation writes no FPSR/QC/flags.
                assert!(s.reads.borrow().iter().all(|r| r.bank == "a64.vector64"));
            }
        }
    }
}
#[test]
fn review_pair_abal_exhaustive_byte_inputs_with_independent_second_half_and_wrap() {
    for unsigned in [false, true] {
        let r = build(word(if unsigned { 3 } else { 2 }, 1, 0, 1, 31, 0), 128);
        for a in 0u16..256 {
            for first in (0u16..256).step_by(8) {
                let mut s = State::new();
                let mut packed = [0u64; 2];
                for e in 0..8u16 {
                    let b = first + e;
                    let (other_a, other_b) = (a ^ 255, b ^ 127);
                    s.put(1, 2 * e, 8, u64::from(a));
                    s.put(31, 2 * e, 8, u64::from(b));
                    s.put(1, 2 * e + 1, 8, u64::from(other_a));
                    s.put(31, 2 * e + 1, 8, u64::from(other_b));
                    let old = 65520 + u64::from(e);
                    s.put(0, e, 16, old);
                    let cv = |x: u16| {
                        if unsigned {
                            x as i16
                        } else {
                            x as u8 as i8 as i16
                        }
                    };
                    let sum = (cv(a) - cv(b)).unsigned_abs() as u64
                        + (cv(other_a) - cv(other_b)).unsigned_abs() as u64;
                    packed[usize::from(e / 4)] |= ((old + sum) & 65535) << ((e % 4) * 16);
                }
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(
                    [t.registers[0].value, t.registers[1].value],
                    packed.map(|v| Value::known(64, v)),
                    "unsigned{unsigned} a{a} first{first}"
                );
            }
        }
    }
}
#[test]
fn review_subp_sparse_high_predicate_skips_unavailable_other_source_chunks() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for e in [1, vl / u16::from(w) - 1] {
                let mut s = State::new();
                s.p[7] = [0; 4];
                let bit = e * u16::from(w) / 8;
                s.p[7][usize::from(bit / 64)] |= 1 << (bit % 64);
                let needed = [(e - 1) * u16::from(w) / 64, e * u16::from(w) / 64];
                s.unavailable_chunks = (0..32)
                    .filter(|k| !needed.contains(k))
                    .map(|k| 31 * 32 + k)
                    .collect();
                let mut want = (0..vl / u16::from(w))
                    .map(|i| s.get(0, i, w))
                    .collect::<Vec<_>>();
                want[usize::from(e)] = s.get(31, e - 1, w).wrapping_sub(s.get(31, e, w)) & mask(w);
                check(word(4, size, 0, 31, 0, 0) | (7 << 10), vl, &s, 0, w, &want);
                assert!(s
                    .reads
                    .borrow()
                    .iter()
                    .filter(|r| r.bank == "a64.vector64" && r.index / 32 == 31)
                    .all(|r| needed.contains(&(r.index % 32))));
            }
        }
    }
}
#[test]
fn review_pair_abal_maximum_two_differences_wrap_at_every_widened_width() {
    for vl in VLS {
        for size in 1..4 {
            let w = 8 << size;
            let half = w / 2;
            for unsigned in [false, true] {
                let mut s = State::new();
                for e in 0..vl / u16::from(w) {
                    s.put(0, e, w, mask(w));
                }
                for e in 0..vl / u16::from(half) {
                    s.put(1, e, half, if unsigned { 0 } else { 1 << (half - 1) });
                    s.put(
                        31,
                        e,
                        half,
                        if unsigned { mask(half) } else { mask(half - 1) },
                    );
                }
                let expected = (1u64 << (half + 1)) - 3;
                check(
                    word(if unsigned { 3 } else { 2 }, size, 0, 1, 31, 0),
                    vl,
                    &s,
                    0,
                    w,
                    &vec![expected; usize::from(vl / u16::from(w))],
                );
            }
        }
    }
}

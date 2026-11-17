#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    predicate_undefined: [[u64; 4]; 16],
    missing: Option<u16>,
    missing_chunk: Option<u16>,
    sm: Value,
    fa: Value,
    p2: Value,
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
            predicate_undefined: [[0; 4]; 16],
            missing: None,
            missing_chunk: None,
            sm: Value::known(64, 0),
            fa: Value::known(1, 0),
            p2: Value::known(1, 0),
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
                    || self.missing_chunk == Some(r.index)
                    || self.unavailable_chunks.contains(&r.index) =>
            {
                Value::unknown(64)
            }
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.predicate64" => Value {
                width: 64,
                bits: self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
                defined: !self.predicate_undefined[usize::from(r.index / 4)]
                    [usize::from(r.index % 4)],
            },
            "a64.svcr" => self.sm,
            "a64.sme_fa64" => self.fa,
            "a64.sme2p2" => self.p2,
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
    semantics::arm64_sve_expand::a64(word, 0x1000, vl)
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x}"));
    assert_eq!(r.support, Support::Full, "{word:08x}");
    r.validate().unwrap();
    r
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

fn instruction(size: u32, d: u32, n: u32, g: u32) -> u32 {
    0x05318000 | (size << 22) | (g << 10) | (n << 5) | d
}
fn expected(s: &State, w: u8, vl: u16, n: u32, g: usize) -> Vec<u64> {
    let mut source = 0;
    (0..vl / u16::from(w))
        .map(|e| {
            if s.active(g, e, w) {
                let v = s.get(n, source, w);
                source += 1;
                v
            } else {
                0
            }
        })
        .collect()
}
#[test]
fn all_sizes_lengths_predicates_and_aliases_expand_the_whole_vector() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (d, n, g) in [(0, 1, 0), (1, 1, 7), (31, 31, 3)] {
                for mode in 0..5 {
                    let mut s = State::new();
                    s.p[g as usize] = [0; 4];
                    for e in 0..vl / u16::from(w) {
                        let bit = e * u16::from(w) / 8;
                        if match mode {
                            0 => false,
                            1 => true,
                            2 => e % 3 == 1,
                            3 => e % 7 < 3,
                            _ => e + 1 == vl / u16::from(w),
                        } {
                            s.p[g as usize][usize::from(bit / 64)] |= 1 << (bit % 64);
                        }
                        if w > 8 {
                            s.p[g as usize][usize::from(bit / 64)] |= 1 << ((bit + 1) % 64);
                        }
                        s.put(
                            n,
                            e,
                            w,
                            (u64::from(e) * 37 + u64::from(w)) ^ 0xa5a55a5a12345678,
                        );
                    }
                    let want = expected(&s, w, vl, n, g as usize);
                    check(instruction(size, d, n, g), vl, &s, d, w, &want);
                }
            }
        }
    }
}
#[test]
fn exhaustive_sixteen_bit_predicates_match_an_independent_iterator() {
    let r = build(instruction(0, 0, 1, 0), 128);
    let mut s = State::new();
    for e in 0..16 {
        s.put(1, e, 8, 0x80 + u64::from(e));
    }
    for pred in 0..=65535u64 {
        s.p[0] = [pred, 0, 0, 0];
        s.reads.borrow_mut().clear();
        let t = evaluate(&r, &s).unwrap();
        let want = expected(&s, 8, 128, 1, 0);
        for (k, out) in t.registers.iter().enumerate() {
            let bits = (0..8).fold(0, |acc, i| acc | (want[k * 8 + i] << (i * 8)));
            assert_eq!(out.value, Value::known(64, bits), "predicate {pred:04x}");
        }
    }
}
#[test]
fn empty_and_sparse_predicates_do_not_read_unused_vector_chunks_or_destination() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let mut s = State::new();
            s.p[0] = [0; 4];
            s.missing = Some(1);
            check(
                instruction(size, 0, 1, 0),
                vl,
                &s,
                0,
                w,
                &vec![0; usize::from(vl / u16::from(w))],
            );
            assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.vector64"));
            s.missing = Some(0);
            s.missing_chunk = Some(33);
            let bit = vl / 8 - u16::from(w) / 8;
            s.p[0][usize::from(bit / 64)] |= 1 << (bit % 64);
            let want = expected(&s, w, vl, 1, 0);
            check(instruction(size, 0, 1, 0), vl, &s, 0, w, &want);
            assert!(s
                .reads
                .borrow()
                .iter()
                .filter(|r| r.bank == "a64.vector64")
                .all(|r| r.index == 32));
        }
    }
}
#[test]
fn fixed_cross_chunk_golden_uses_sequential_sources_and_not_matching_lane_indices() {
    let mut s = State::new();
    s.p[0] = [0, 0, 0, 0];
    for e in 0..32 {
        s.put(1, e, 8, 100 + u64::from(e));
        if e % 2 != 0 {
            s.p[0][0] |= 1 << e;
        }
    }
    let want: Vec<_> = (0..32)
        .map(|e| if e % 2 == 0 { 0 } else { 100 + e / 2 })
        .collect();
    check(instruction(0, 0, 1, 0), 256, &s, 0, 8, &want);
}
#[test]
fn streaming_context_is_checked_before_predicates_or_sources() {
    let mut s = State::new();
    s.sm = Value::known(64, 1);
    let r = build(instruction(0, 0, 1, 0), 128);
    assert!(matches!(
        evaluate(&r, &s),
        Err(EvalError::UnsupportedContext)
    ));
    assert!(!s
        .reads
        .borrow()
        .iter()
        .any(|r| matches!(r.bank, "a64.vector64" | "a64.predicate64")));
    s.p2 = Value::known(1, 1);
    let want = expected(&s, 8, 128, 1, 0);
    check(instruction(0, 0, 1, 0), 128, &s, 0, 8, &want);
    s.p2 = Value::known(1, 0);
    s.fa = Value::known(1, 1);
    check(instruction(0, 0, 1, 0), 128, &s, 0, 8, &want);
    s.sm = Value::unknown(64);
    s.fa = Value::known(1, 0);
    assert!(matches!(evaluate(&r, &s), Err(EvalError::UnknownCondition)));
    s.sm = Value::known(64, 0);
    s.fa = Value::unknown(1);
    s.p2 = Value::unknown(1);
    check(instruction(0, 0, 1, 0), 128, &s, 0, 8, &want);
}
#[test]
fn invalid_lengths_have_explicit_unsupported_recipes() {
    for vl in [0, 64, 129, 192, 4096] {
        assert!(matches!(
            semantics::arm64_sve_expand::a64(0x05318000, 0x1000, vl)
                .unwrap()
                .support,
            Support::Unsupported(_)
        ));
    }
}

#[test]
fn review_sme2p2_context_needs_no_fa64_input() {
    let mut s = State::new();
    s.sm = Value::known(64, 1);
    s.p2 = Value::known(1, 1);
    s.fa = Value::unknown(1);
    let want = expected(&s, 8, 128, 1, 0);
    check(instruction(0, 0, 1, 0), 128, &s, 0, 8, &want);
    assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.sme_fa64"));
    s.reads.borrow_mut().clear();
    s.p2 = Value::known(1, 0);
    assert!(matches!(
        evaluate(&build(instruction(0, 0, 1, 0), 128), &s),
        Err(EvalError::UnknownCondition)
    ));
    assert!(!s
        .reads
        .borrow()
        .iter()
        .any(|r| matches!(r.bank, "a64.vector64" | "a64.predicate64")));
}
#[test]
fn review_every_tail_population_with_alias_and_unknown_unused_bits_and_chunks() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let elements = vl / u16::from(w);
            let per = 64 / u16::from(w);
            let stride = u16::from(w) / 8;
            let r = build(instruction(size, 31, 31, 7), vl);
            for count in 0..=elements {
                let mut s = State::new();
                s.p[7] = [0; 4];
                for bit in 0..256u16 {
                    if bit >= vl / 8 || bit % stride != 0 {
                        s.predicate_undefined[7][usize::from(bit / 64)] |= 1 << (bit % 64);
                    }
                }
                for e in elements - count..elements {
                    let bit = e * stride;
                    s.p[7][usize::from(bit / 64)] |= 1 << (bit % 64);
                }
                let used = count.div_ceil(per);
                s.unavailable_chunks = (used..32).map(|k| 31 * 32 + k).collect();
                let mut want = vec![0; usize::from(elements)];
                for i in 0..count {
                    want[usize::from(elements - count + i)] = s.get(31, i, w);
                }
                let t = evaluate(&r, &s).unwrap();
                for (k, v) in t.registers.iter().enumerate() {
                    let packed = (0..usize::from(per)).fold(0, |a, i| {
                        a | (want[k * usize::from(per) + i] << (i * usize::from(w)))
                    });
                    assert_eq!(
                        v.value,
                        Value::known(64, packed),
                        "VL{vl} w{w} population{count} chunk{k}"
                    );
                }
                assert!(s
                    .reads
                    .borrow()
                    .iter()
                    .filter(|r| r.bank == "a64.vector64")
                    .all(|r| r.index / 32 == 31 && r.index % 32 < used));
            }
        }
    }
}

#[test]
fn review_unknown_controlling_predicate_cannot_fabricate_known_indexed_data() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8u8 << size;
            let mut s = State::new();
            s.p[7] = [0; 4];
            // Whether lane0 consumes source0 is unknown. A known-active final
            // destination therefore cannot promise source0 versus source1.
            s.predicate_undefined[7][0] = 1;
            let last = vl / u16::from(w) - 1;
            let bit = last * u16::from(w) / 8;
            s.p[7][usize::from(bit / 64)] |= 1 << (bit % 64);
            let t = evaluate(&build(instruction(size, 0, 31, 7), vl), &s).unwrap();
            assert!(!t.registers[0].value.is_known());
            assert!(!t.registers.last().unwrap().value.is_known());
            assert!(s
                .reads
                .borrow()
                .iter()
                .filter(|r| r.bank == "a64.vector64")
                .all(|r| r.index / 32 == 31 && r.index % 32 < vl / 64));
        }
    }
}

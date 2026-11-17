#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::HashMap};
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
#[derive(Clone)]
struct State {
    values: HashMap<Register, Value>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
            reads: RefCell::new(vec![]),
        }
    }
    fn set(&mut self, bank: &'static str, n: u16, bits: u64) {
        self.values
            .insert(Register { bank, index: n }, Value::known(64, bits));
    }
    fn fill(&mut self) {
        for n in 0..32 {
            for k in 0..32 {
                self.set(
                    "a64.vector64",
                    n * 32 + k,
                    0x9e3779b97f4a7c15u64.wrapping_mul(u64::from(n * 41 + k + 1)),
                );
            }
        }
        for n in 0..16 {
            for k in 0..4 {
                self.set(
                    "a64.predicate64",
                    n * 4 + k,
                    0x6a09e667f3bcc909u64.rotate_left(u32::from(n + k * 9)),
                );
            }
        }
        for n in 0..31 {
            self.set("a64.gpr", n, u64::MAX - u64::from(n) * 13);
        }
    }
    fn bit(&self, bank: &'static str, reg: u16, stride: u16, bit: u16) -> bool {
        self.values[&Register {
            bank,
            index: reg * stride + bit / 64,
        }]
            .bits
            & (1u64 << (bit % 64))
            != 0
    }
    fn put(&mut self, bank: &'static str, reg: u16, stride: u16, bit: u16, value: bool) {
        let v = self
            .values
            .entry(Register {
                bank,
                index: reg * stride + bit / 64,
            })
            .or_insert(Value::known(64, 0));
        v.bits = (v.bits & !(1u64 << (bit % 64))) | (u64::from(value) << (bit % 64));
    }
    fn apply(&mut self, t: &Transition) {
        assert!(
            t.trap.is_none()
                && t.memory.is_empty()
                && t.wide_memory.is_empty()
                && t.atomics.is_empty()
        );
        for w in &t.registers {
            assert!(matches!(
                w.register.bank,
                "a64.vector64" | "a64.predicate64" | "a64.gpr"
            ));
            self.values.insert(w.register, w.value);
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        self.values.get(&r).copied().unwrap_or(Value::unknown(64))
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("predicate rearrangement touched memory")
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_predicate_rearrange::a64(word, 0x1000, vl)
}
fn full(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unowned {word:08x}"));
    assert_eq!(r.support, Support::Full, "{word:08x}");
    r.validate().unwrap();
    r
}
fn pmov(to_z: bool, w: u16, imm: u32, d: u16, n: u16) -> u32 {
    let base = match w {
        8 => 0x052a3800,
        16 => 0x052c3800,
        32 => 0x05683800,
        64 => 0x05a83800,
        _ => panic!(),
    };
    base | u32::from(to_z) << 16
        | ((imm & 3) << 17)
        | ((imm >> 2) << 22)
        | u32::from(n) << 5
        | u32::from(d)
}
fn psel(w: u16, imm: u32, v: u32, d: u32, n: u32, m: u32) -> u32 {
    let size = w.trailing_zeros() - 3;
    let combined = (imm << (size + 1)) | (1 << size);
    0x25204000
        | ((combined >> 4) << 23)
        | (((combined >> 3) & 1) << 22)
        | ((combined & 7) << 18)
        | ((v - 12) << 16)
        | (n << 10)
        | (m << 5)
        | d
}
#[test]
fn all_pmov_widths_immediates_and_register_edges_match_independent_bit_model() {
    for vl in VLS {
        for w in [8, 16, 32, 64] {
            for imm in 0..w / 8 {
                for to_z in [false, true] {
                    for (d, n) in if to_z {
                        vec![(0, 0), (31, 15), (7, 7)]
                    } else {
                        vec![(0, 0), (15, 31), (7, 7)]
                    } {
                        let mut state = State::new();
                        state.fill();
                        let original = state.clone();
                        let mut expected = state.clone();
                        let count = vl / w;
                        let offset = count * imm;
                        if to_z {
                            if imm == 0 {
                                for bit in 0..vl {
                                    expected.put("a64.vector64", d, 32, bit, false);
                                }
                            }
                            for e in 0..count {
                                expected.put(
                                    "a64.vector64",
                                    d,
                                    32,
                                    offset + e,
                                    original.bit("a64.predicate64", n, 4, e * (w / 8)),
                                );
                            }
                        } else {
                            for bit in 0..vl / 8 {
                                expected.put("a64.predicate64", d, 4, bit, false);
                            }
                            for e in 0..count {
                                expected.put(
                                    "a64.predicate64",
                                    d,
                                    4,
                                    e * (w / 8),
                                    original.bit("a64.vector64", n, 32, offset + e),
                                );
                            }
                        }
                        let r = full(pmov(to_z, w, imm.into(), d, n), vl);
                        let t = evaluate(&r, &state).unwrap();
                        assert_eq!(t.next_pc, Value::known(64, 0x1004));
                        state.apply(&t);
                        assert_eq!(
                            state.values, expected.values,
                            "PMOV {to_z} VL{vl} w{w} imm{imm} d{d} n{n}"
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn pmov_zero_and_narrow_preservation_do_not_require_old_destinations() {
    for vl in VLS {
        for w in [8, 16, 32, 64] {
            for imm in 0..w / 8 {
                let mut s = State::new();
                for k in 0..(vl / 8).div_ceil(64) {
                    s.set("a64.predicate64", 15 * 4 + k, u64::MAX);
                }
                let t = evaluate(&full(pmov(true, w, imm.into(), 31, 15), vl), &s).unwrap();
                if imm == 0 {
                    assert!(s.reads.borrow().iter().all(|r| r.bank != "a64.vector64"));
                }
                let count = vl / w;
                let offset = count * imm;
                for wr in &t.registers {
                    for bit in 0..64 {
                        let at = (wr.register.index % 32) * 64 + bit;
                        let known = wr.value.defined & (1u64 << bit) != 0;
                        assert_eq!(known, imm == 0 || at >= offset && at < offset + count);
                    }
                }
                // Every active predicate bit is true; invalid/spacing bits cannot leak.
                for wr in &t.registers {
                    for bit in 0..64 {
                        let at = (wr.register.index % 32) * 64 + bit;
                        if at >= offset && at < offset + count {
                            assert_ne!(wr.value.bits & (1u64 << bit), 0);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn psel_all_sizes_immediates_index_wraps_and_aliases_match_raw_predicate_copy() {
    for vl in VLS {
        for w in [8u16, 16, 32, 64] {
            for imm in 0..128 / u32::from(w) {
                for v in 12..16 {
                    for x in [0, 1, u32::MAX - 1, u32::MAX] {
                        for (d, n, m) in [(0, 1, 2), (15, 15, 15), (7, 7, 2), (2, 1, 2)] {
                            let mut s = State::new();
                            s.fill();
                            s.set("a64.gpr", v, x.into());
                            let original = s.clone();
                            let mut expected = s.clone();
                            let e = (u64::from(x) + u64::from(imm)) % u64::from(vl / w);
                            let active = original.bit("a64.predicate64", m, 4, e as u16 * (w / 8));
                            for bit in 0..vl / 8 {
                                expected.put(
                                    "a64.predicate64",
                                    d,
                                    4,
                                    bit,
                                    active && original.bit("a64.predicate64", n, 4, bit),
                                );
                            }
                            let t = evaluate(
                                &full(psel(w, imm, v.into(), d.into(), n.into(), m.into()), vl),
                                &s,
                            )
                            .unwrap();
                            s.apply(&t);
                            assert_eq!(
                                s.values, expected.values,
                                "PSEL VL{vl} w{w} imm{imm} W{v}={x:x}"
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn psel_false_suppresses_unavailable_source_and_ignores_high_w_register_bits() {
    for vl in VLS {
        for w in [8, 16, 32, 64] {
            let mut s = State::new();
            s.set("a64.gpr", 12, 0xffff_ffff_0000_0000);
            for k in 0..4 {
                s.set("a64.predicate64", 2 * 4 + k, 0);
            }
            let t = evaluate(&full(psel(w, 0, 12, 3, 1, 2), vl), &s).unwrap();
            assert!(t.registers.iter().all(|w| w.value.bits == 0));
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.predicate64" && r.index / 4 == 1));
        }
    }
}
#[test]
fn psel_reads_only_the_selected_bit_and_current_predicate_length() {
    for vl in VLS {
        for w in [8u16, 16, 32, 64] {
            let e = vl / w - 1;
            let bit = e * (w / 8);
            let mut s = State::new();
            s.values.insert(
                Register {
                    bank: "a64.gpr",
                    index: 15,
                },
                Value {
                    bits: u64::from(e),
                    defined: 0xffffffff,
                    width: 64,
                },
            );
            s.values.insert(
                Register {
                    bank: "a64.predicate64",
                    index: 2 * 4 + bit / 64,
                },
                Value {
                    bits: 1 << (bit % 64),
                    defined: 1 << (bit % 64),
                    width: 64,
                },
            );
            for k in 0..(vl / 8).div_ceil(64) {
                s.set("a64.predicate64", 4 + k, u64::MAX);
            }
            let t = evaluate(&full(psel(w, 0, 15, 3, 1, 2), vl), &s).unwrap();
            for wr in t.registers {
                assert_eq!(
                    wr.value.defined
                        & mask(((vl / 8 - (wr.register.index % 4) * 64).min(64)) as u8),
                    mask(((vl / 8 - (wr.register.index % 4) * 64).min(64)) as u8)
                );
            }
        }
    }
}
#[test]
fn first_last_intersections_empty_sparse_and_masked_spacing_have_exact_indices() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8u16 << size;
            for mode in 0..6 {
                for last in [false, true] {
                    for (g, n) in [(0, 1), (15, 15)] {
                        let mut s = State::new();
                        s.fill();
                        for k in 0..4 {
                            s.set("a64.predicate64", g * 4 + k, 0);
                            s.set("a64.predicate64", n * 4 + k, 0);
                        }
                        for bit in 0..vl / 8 {
                            let e = bit / (w / 8);
                            let group = bit % (w / 8) == 0;
                            s.put(
                                "a64.predicate64",
                                g,
                                4,
                                bit,
                                if group {
                                    match mode {
                                        0 => false,
                                        1 => true,
                                        2 => e % 3 == 1,
                                        _ => e == 0 || e + 1 == vl / w,
                                    }
                                } else {
                                    true
                                },
                            );
                            s.put(
                                "a64.predicate64",
                                n,
                                4,
                                bit,
                                if group {
                                    match mode {
                                        0 | 1 => false,
                                        2 => e % 7 == 1,
                                        3 => true,
                                        4 => e == 0,
                                        _ => e + 1 == vl / w,
                                    }
                                } else {
                                    true
                                },
                            );
                        }
                        let hits = (0..vl / w)
                            .filter(|e| {
                                s.bit("a64.predicate64", g, 4, e * (w / 8))
                                    && s.bit("a64.predicate64", n, 4, e * (w / 8))
                            })
                            .collect::<Vec<_>>();
                        let want = if last { hits.last() } else { hits.first() }
                            .copied()
                            .map_or(u64::MAX, u64::from);
                        let word = (if last { 0x25228000 } else { 0x25218000 })
                            | (size << 22)
                            | (u32::from(g) << 10)
                            | (u32::from(n) << 5)
                            | 30;
                        let t = evaluate(&full(word, vl), &s).unwrap();
                        assert_eq!(t.registers.len(), 1);
                        assert_eq!(
                            t.registers[0].register,
                            Register {
                                bank: "a64.gpr",
                                index: 30
                            }
                        );
                        assert_eq!(t.registers[0].value, Value::known(64, want));
                    }
                }
            }
        }
    }
}
#[test]
fn masked_sources_short_circuit_and_xzr_is_not_sp() {
    for vl in VLS {
        for last in [false, true] {
            let base = if last { 0x25228000 } else { 0x25218000 };
            let mut s = State::new();
            for k in 0..4 {
                s.set("a64.predicate64", k, 0);
            }
            let t = evaluate(&full(base | (1 << 5), vl), &s).unwrap();
            assert_eq!(t.registers[0].value, Value::known(64, u64::MAX));
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.predicate64" && r.index / 4 == 1));
            let s = State::new();
            let t = evaluate(&full(base | 31, vl), &s).unwrap();
            assert!(t.registers.is_empty());
            assert!(s.reads.borrow().is_empty());
        }
    }
}
#[test]
fn first_last_stop_after_the_selected_intersection_without_later_input_dependencies() {
    for vl in VLS {
        for size in 0..4 {
            for last in [false, true] {
                let width = 8u16 << size;
                let e = if last { vl / width - 1 } else { 0 };
                let bit = e * (width / 8);
                let mut s = State::new();
                for n in [0, 1] {
                    s.values.insert(
                        Register {
                            bank: "a64.predicate64",
                            index: n * 4 + bit / 64,
                        },
                        Value {
                            bits: 1 << (bit % 64),
                            defined: 1 << (bit % 64),
                            width: 64,
                        },
                    );
                }
                let word =
                    (if last { 0x25228000 } else { 0x25218000 }) | (size << 22) | (1 << 5) | 2;
                let t = evaluate(&full(word, vl), &s).unwrap();
                assert_eq!(t.registers[0].value, Value::known(64, e.into()));
            }
        }
    }
}

#[test]
fn exact_physical_ownership_and_invalid_vl() {
    for word in [
        0x052b3800,
        0x052a3800,
        0x25204000 | (1 << 18),
        0x25218000,
        0x25228000,
    ] {
        assert!(matches!(
            recipe(word, 384).unwrap().support,
            Support::Unsupported(_)
        ));
    }
    assert!(matches!(
        recipe(0x25204000, 128).unwrap().support,
        Support::Unsupported(_)
    ));
    for word in [
        0x052b3a00,
        0x052a3810,
        0x25204200,
        0x25218000 ^ (1 << 9),
        0x25228000 ^ (1 << 15),
        0xd503201f,
    ] {
        assert!(
            semantics::arm64_sve_predicate_rearrange::a64(word, 0, 128).is_none(),
            "neighbor {word:08x}"
        );
    }
}

#[test]
fn independently_derived_primary_masks_bound_every_single_bit_neighbor() {
    // Fixed-bit masks read independently from the June primary regdiagrams.
    let classes: [(u32, u32); 11] = [
        (0xff3fc200, 0x25218000), (0xff3fc200, 0x25228000),
        (0xfffffc10, 0x052a3800), (0xffb9fc10, 0x05a83800),
        (0xfffdfc10, 0x052c3800), (0xfff9fc10, 0x05683800),
        (0xfffffe00, 0x052b3800), (0xffb9fe00, 0x05a93800),
        (0xfffdfe00, 0x052d3800), (0xfff9fe00, 0x05693800),
        (0xff20c210, 0x25204000),
    ];
    for (fixed, base) in classes {
        for variables in [0, u32::MAX, 0xaaaaaaaa, 0x55555555] {
            let word = base | (variables & !fixed);
            for bit in 0..32 {
                let neighbor = word ^ (1 << bit);
                let expected = classes.iter().any(|(mask, value)| neighbor & mask == *value);
                assert_eq!(
                    semantics::arm64_sve_predicate_rearrange::a64(neighbor, 0, 128).is_some(),
                    expected, "ownership {neighbor:08x}"
                );
            }
        }
    }
}

#[test]
fn pmov_sparse_definedness_copies_only_selected_bits_and_preserves_every_other_bit() {
    for vl in VLS {
        for width in [8u16, 16, 32, 64] {
            for imm in 0..width / 8 {
                for to_z in [false, true] {
                    let (source, source_stride, destination, destination_stride) = if to_z {
                        ("a64.predicate64", 4, "a64.vector64", 32)
                    } else {
                        ("a64.vector64", 32, "a64.predicate64", 4)
                    };
                    let mut state = State::new();
                    for k in 0..source_stride {
                        state.values.insert(Register { bank: source, index: k },
                            Value { width: 64, bits: u64::MAX, defined: 0 });
                    }
                    for k in 0..destination_stride {
                        state.values.insert(Register { bank: destination, index: k },
                            Value { width: 64, bits: 0xa5a5a5a5a5a5a5a5, defined: 0x3333333333333333 });
                    }
                    let count = vl / width;
                    let offset = count * imm;
                    for e in 0..count {
                        let bit = if to_z { e * (width / 8) } else { offset + e };
                        let v = state.values.get_mut(&Register {bank: source, index: bit / 64}).unwrap();
                        let mask = 1u64 << (bit % 64);
                        // Only consumed source bits are available. Arithmetic
                        // nodes conservatively taint a complete scalar when a
                        // consumed bit is unknown; unrelated bits must never
                        // introduce that dependency.
                        v.defined |= mask;
                        if e % 2 == 0 { v.bits &= !mask; }
                    }
                    let mut expected = state.values.clone();
                    let limit = if to_z { vl } else { vl / 8 };
                    for bit in 0..limit {
                        let selected = if to_z {
                            (offset..offset + count).contains(&bit)
                        } else { bit % (width / 8) == 0 };
                        let (bits, defined) = if selected {
                            let e = if to_z { bit - offset } else { bit / (width / 8) };
                            let src = if to_z { e * (width / 8) } else { offset + e };
                            let v = state.values[&Register {bank: source, index: src / 64}];
                            (v.bits >> (src % 64) & 1, v.defined >> (src % 64) & 1)
                        } else if !to_z || imm == 0 { (0, 1) } else { continue };
                        let v = expected.get_mut(&Register {bank: destination, index: bit / 64}).unwrap();
                        let mask = 1u64 << (bit % 64);
                        v.bits = (v.bits & !mask) | (bits << (bit % 64));
                        v.defined = (v.defined & !mask) | (defined << (bit % 64));
                    }
                    let transition = evaluate(&full(pmov(to_z, width, imm.into(), 0, 0), vl), &state).unwrap();
                    state.apply(&transition);
                    for (register, want) in expected {
                        let got = state.values[&register];
                        assert_eq!(got.defined, want.defined, "defined {to_z} VL{vl} w{width} imm{imm} {register:?}");
                        assert_eq!((got.bits ^ want.bits) & want.defined, 0, "bits {to_z} VL{vl} w{width} imm{imm} {register:?}");
                    }
                }
            }
        }
    }
}

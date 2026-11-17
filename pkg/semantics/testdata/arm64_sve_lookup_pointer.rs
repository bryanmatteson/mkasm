#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    x: [u64; 31],
    flags: [Option<u64>; 4],
    fpcr: Option<u64>,
    controls: [Option<u64>; 5],
    absent: Vec<Register>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|i| 0x9e3779b97f4a7c15u64.wrapping_mul((n * 32 + i + 1) as u64))
            }),
            controls: [Some(0), Some(0), Some(0), Some(0), Some(0)],
            p: [[0; 4]; 16],
            x: [0; 31],
            flags: [Some(1), Some(0), Some(1), Some(1)],
            fpcr: Some(0),
            absent: vec![],
            reads: RefCell::new(vec![]),
        }
    }
    fn bits(&self, n: u32, bit: u16, width: u8) -> u64 {
        let mut x = 0;
        for i in 0..u16::from(width) {
            let at = bit + i;
            x |= ((self.z[n as usize][usize::from(at / 64)] >> (at % 64)) & 1) << i;
        }
        x
    }
    fn put(&mut self, n: u32, bit: u16, width: u8, v: u64) {
        for i in 0..u16::from(width) {
            let at = bit + i;
            let z = &mut self.z[n as usize][usize::from(at / 64)];
            *z = (*z & !(1 << (at % 64))) | (((v >> i) & 1) << (at % 64));
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        let w = if r.bank == "a64.vector64" || r.bank == "a64.svcr" {
            64
        } else {
            1
        };
        if self.absent.contains(&r) {
            return Value::unknown(w);
        };
        if r.bank == "a64.vector64" {
            return Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            );
        };
        match r.bank {
            "a64.predicate64" => {
                return Value::known(
                    64,
                    self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
                )
            }
            "a64.gpr" => return Value::known(64, self.x[usize::from(r.index)]),
            "a64.nzcv" => {
                return self.flags[usize::from(r.index)]
                    .map_or(Value::unknown(1), |v| Value::known(1, v))
            }
            "a64.fpcr" => {
                return self
                    .fpcr
                    .map_or(Value::unknown(32), |v| Value::known(32, v))
            }
            _ => {}
        }
        let index = match r.bank {
            "a64.svcr" => 0,
            "a64.sme_fa64" => 1,
            "a64.sme2" => 2,
            "a64.cpta" => 3,
            "a64.cptm" => 4,
            _ => panic!("input {r:?}"),
        };
        match self.controls[index] {
            Some(x) => Value::known(w, x),
            None => Value::unknown(w),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory")
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_lookup::a64(word, 0x1000, vl)
        .or_else(|| semantics::arm64_sve_misc::a64(word, 0x1000, vl))
        .or_else(|| semantics::arm64_sve_transfer::a64(word, 0x1000, vl))
}
fn run(word: u32, vl: u16, s: &State) -> (State, Transition) {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    let mut out = s.clone();
    for wr in &t.registers {
        assert!(wr.value.is_known());
        if wr.register.bank == "a64.nzcv" {
            out.flags[usize::from(wr.register.index)] = Some(wr.value.bits);
        } else {
            assert_eq!(wr.register.bank, "a64.vector64");
            out.z[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                wr.value.bits;
        }
    }
    assert!(t.memory.is_empty());
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    (out, t)
}
// base,width,index-width,part-count,part-shift,table-bits-per-source,sources,min-VL
const CLASSES: [(u32, u8, u8, u32, u8, u16, u32, u16); 7] = [
    (0x4520b000, 8, 2, 4, 22, 32, 1, 128),
    (0x4520a800, 16, 2, 8, 0, 64, 1, 128),
    (0x4560a400, 8, 4, 2, 23, 128, 1, 128),
    (0x4520b400, 16, 4, 4, 22, 128, 2, 128),
    (0x4520bc00, 16, 4, 4, 22, 256, 1, 256),
    (0x4560ac00, 16, 6, 2, 23, 512, 2, 512),
    (0x4520ac00, 8, 6, 1, 0, 256, 2, 256),
];
fn lookup_word(class: usize, part: u32, d: u32, n: u32, m: u32) -> u32 {
    let (base, _, _, _, shift, _, _, _) = CLASSES[class];
    base | (if class == 1 {
        ((part >> 1) << 22) | ((part & 1) << 12)
    } else {
        part << shift
    }) | (m << 16)
        | (n << 5)
        | d
}
#[test]
fn lookup_all_classes_parts_indices_lengths_wrapped_tables_and_aliases() {
    let mut cases = 0;
    for (class, &(_, width, iw, parts, _, tablebits, _, minimum)) in CLASSES.iter().enumerate() {
        for vl in [128, 256, 512, 1024, 2048] {
            if vl < minimum {
                continue;
            }
            for part in 0..parts {
                for (d, n, m) in [
                    (0, 1, 2),
                    (1, 1, 2),
                    (2, 1, 2),
                    (0, 31, 2),
                    (31, 31, 0),
                    (0, 0, 0),
                ] {
                    for start in 0..(1u64 << iw) {
                        let mut s = State::new();
                        let elements = vl / u16::from(width);
                        for e in 0..elements {
                            let at = (elements * part as u16 + e) * u16::from(iw);
                            s.put(m, at, iw, (start + u64::from(e)) & ((1 << iw) - 1));
                        }
                        let mut expected = s.clone();
                        for e in 0..elements {
                            let ix =
                                s.bits(m, (elements * part as u16 + e) * u16::from(iw), iw) as u16;
                            let source = (n + u32::from(ix * u16::from(width) / tablebits)) % 32;
                            let bit = ix * u16::from(width) % tablebits;
                            expected.put(
                                d,
                                e * u16::from(width),
                                width,
                                s.bits(source, bit, width),
                            );
                        }
                        let (out, _) = run(lookup_word(class, part, d, n, m), vl, &s);
                        assert_eq!(
                            out.z, expected.z,
                            "class{class} part{part} VL{vl} d{d} n{n} m{m} start{start}"
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    println!("{cases} lookup states");
}
#[test]
fn lookup_uses_global_table_and_global_packed_index_slice() {
    let mut s = State::new();
    for e in 0..64 {
        s.put(1, e * 8, 8, u64::from(e + 1));
    }
    for e in 0..512 {
        s.put(2, e * 4, 4, 15);
    }
    let (out, _) = run(lookup_word(2, 1, 0, 1, 2), 2048, &s);
    for e in 0..256 {
        assert_eq!(out.bits(0, e * 8, 8), 16);
    }
}
#[test]
fn lookup_context_branches_suppress_unneeded_controls_and_operands() {
    for class in 0..7 {
        let w = lookup_word(class, 0, 0, 1, 2);
        let mut s = State::new();
        s.controls = [Some(1), Some(0), Some(0), None, None];
        if class < 5 {
            let r = recipe(w, 2048).unwrap();
            assert!(evaluate(&r, &s).is_err());
            s.controls = [None, None, Some(1), None, None];
            s.reads.borrow_mut().clear();
            assert!(evaluate(&r, &s).is_ok());
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.svcr" || r.bank == "a64.sme_fa64"));
        } else if class == 5 {
            s.controls = [None, None, None, None, None];
            assert!(evaluate(&recipe(w, 2048).unwrap(), &s).is_ok());
        } else {
            assert!(evaluate(&recipe(w, 2048).unwrap(), &s).is_err());
            s.controls[1] = Some(1);
            assert!(evaluate(&recipe(w, 2048).unwrap(), &s).is_ok());
        }
    }
}
#[test]
fn lookup_minimum_lengths_and_fixed_bit_neighbors() {
    let masks = [
        0xff20fc00u32,
        0xff20ec00,
        0xff60fc00,
        0xff20fc00,
        0xff20fc00,
        0xff60fc00,
        0xffe0fc00,
    ];
    for (class, &(base, _, _, _, _, _, _, minimum)) in CLASSES.iter().enumerate() {
        for vl in [128, 256, 512, 1024, 2048] {
            let r = semantics::arm64_sve_lookup::a64(base, 0x1000, vl).unwrap();
            assert_eq!(r.support == Support::Full, vl >= minimum);
        }
        for vars in [0, u32::MAX, 0xaaaaaaaa, 0x55555555] {
            for bit in 0..32 {
                if masks[class] & (1 << bit) == 0 {
                    continue;
                }
                let word = (base | (vars & !masks[class])) ^ (1 << bit);
                let own = CLASSES.iter().zip(masks).any(|(c, m)| word & m == c.0);
                assert_eq!(
                    semantics::arm64_sve_lookup::a64(word, 0x1000, 2048).is_some(),
                    own,
                    "{word:08x}"
                );
            }
        }
    }
}
#[test]
fn lookup_does_not_read_unselected_table_chunks() {
    for class in 0..7 {
        let mut s = State::new();
        s.z[2] = [0; 32];
        for n in [1u16, 2] {
            for chunk in 1..32 {
                s.absent.push(Register {
                    bank: "a64.vector64",
                    index: n * 32 + chunk,
                });
            }
        } // all-zero indices at part0 need index chunks across VL, so only table chunks may be absent.
        s.absent.retain(|r| r.index / 32 == 1);
        let (out, _) = run(lookup_word(class, 0, 0, 1, 2), 2048, &s);
        let width = CLASSES[class].1;
        for e in 0..2048 / u16::from(width) {
            assert_eq!(
                out.bits(0, e * u16::from(width), width),
                s.bits(1, 0, width)
            );
        }
    }
}
#[test]
fn checked_pointer_products_all_controls_signed_overflows_and_aliases() {
    let values = [
        0,
        1,
        u64::MAX,
        2,
        1 << 63,
        (1 << 63) - 1,
        0x00ffffffffffffff,
        0x0040000000000000,
        0x0080000000000000,
        0xff80000000000000,
    ];
    let mut cases = 0;
    for vl in [128, 256, 512, 1024, 2048] {
        for mad in [false, true] {
            for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                for ca in [0, 1] {
                    for cm in [0, 1] {
                        for seed in 0..values.len() * values.len() {
                            let mut s = State::new();
                            s.controls[3] = Some(ca);
                            s.controls[4] = Some(cm);
                            for e in 0..vl / 64 {
                                for (reg, value) in [
                                    (d, values[(seed + usize::from(e)) % values.len()]),
                                    (
                                        n,
                                        values[(seed / values.len() + usize::from(e) * 3)
                                            % values.len()],
                                    ),
                                    (m, values[(seed / 3 + usize::from(e) * 7) % values.len()]),
                                ] {
                                    s.put(reg, e * 64, 64, value);
                                }
                            }
                            let mut expected = s.clone();
                            for e in 0..vl / 64 {
                                let a = s.bits(if mad { d } else { n }, e * 64, 64) as i64;
                                let b = s.bits(m, e * 64, 64) as i64;
                                let base = s.bits(if mad { n } else { d }, e * 64, 64);
                                let product = i128::from(a) * i128::from(b);
                                let value = base.wrapping_add(product as u64);
                                let addition = (base >> 55) & 1 != (base >> 54) & 1
                                    || value >> 56 != base >> 56;
                                let mul = product < i128::from(i64::MIN)
                                    || product > i128::from(i64::MAX);
                                let marked = if addition && ca != 0 || mul && cm != 0 {
                                    (base & 0xff80000000000000)
                                        | (((!(base >> 55)) & 1) << 54)
                                        | (value & ((1 << 54) - 1))
                                } else {
                                    value
                                };
                                expected.put(d, e * 64, 64, marked);
                            }
                            let word = (if mad { 0x44c0d800 } else { 0x44c0d000 })
                                | (m << 16)
                                | (n << 5)
                                | d;
                            let (out, _) = run(word, vl, &s);
                            assert_eq!(
                                out.z, expected.z,
                                "pointer VL{vl} mad{mad} d{d} n{n} m{m} ca{ca} cm{cm} seed{seed}"
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    println!("{cases} checked pointer states");
}
#[test]
fn checked_pointer_unused_controls_remain_lazy() {
    let mut s = State::new();
    s.z = [[0; 32]; 32];
    s.controls[3] = None;
    s.controls[4] = None;
    assert!(evaluate(&recipe(0x44c2d020, 2048).unwrap(), &s).is_ok());
    s.z[1] = [u64::MAX; 32];
    s.z[2] = [2; 32];
    s.controls[3] = Some(1);
    s.controls[4] = None;
    assert!(evaluate(&recipe(0x44c2d020, 2048).unwrap(), &s).is_ok());
}

#[test]
fn unpredicated_multiply_and_prefix_copies_all_sizes_lengths_and_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for size in 0..4 {
            let w = 8u8 << size;
            for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                let s = State::new();
                let mut expected = s.clone();
                for e in 0..vl / u16::from(w) {
                    let v =
                        s.bits(n, e * u16::from(w), w)
                            .wrapping_mul(s.bits(m, e * u16::from(w), w));
                    expected.put(d, e * u16::from(w), w, v);
                }
                let (out, _) = run(0x04206000 | (size << 22) | (m << 16) | (n << 5) | d, vl, &s);
                assert_eq!(out.z, expected.z);
                let (out, _) = run(0x0420bc00 | (n << 5) | d, vl, &s);
                let mut expected = s.clone();
                for chunk in 0..vl / 64 {
                    expected.z[d as usize][usize::from(chunk)] =
                        s.z[n as usize][usize::from(chunk)];
                }
                assert_eq!(out.z, expected.z);
                assert_eq!(out.flags, s.flags);
            }
        }
    }
}
#[test]
fn predicated_prefix_all_registers_sizes_policies_and_sparse_masks() {
    for vl in [128, 256, 512, 1024, 2048] {
        for size in 0..4 {
            let w = 8u8 << size;
            for merge in [false, true] {
                for g in 0..8 {
                    for kind in 0..4 {
                        for (d, n) in [(0, 1), (1, 1), (31, 0)] {
                            let mut s = State::new();
                            for e in 0..vl / u16::from(w) {
                                let active = kind == 1
                                    || (kind == 2 && e % 3 == 1)
                                    || (kind == 3 && e + 1 == vl / u16::from(w));
                                let bit = e * u16::from(w / 8);
                                if active {
                                    s.p[g][usize::from(bit / 64)] |= 1 << (bit % 64);
                                }
                                if w > 8 {
                                    s.p[g][usize::from(bit / 64)] |= 1 << ((bit + 1) % 64);
                                }
                            }
                            let mut expected = s.clone();
                            for e in 0..vl / u16::from(w) {
                                let bit = e * u16::from(w / 8);
                                let active = s.p[g][usize::from(bit / 64)] & (1 << (bit % 64)) != 0;
                                let v = if active {
                                    s.bits(n, e * u16::from(w), w)
                                } else if merge {
                                    s.bits(d, e * u16::from(w), w)
                                } else {
                                    0
                                };
                                expected.put(d, e * u16::from(w), w, v);
                            }
                            let (out, _) = run(
                                0x04102000
                                    | (size << 22)
                                    | (u32::from(merge) << 16)
                                    | ((g as u32) << 10)
                                    | (n << 5)
                                    | d,
                                vl,
                                &s,
                            );
                            assert_eq!(out.z, expected.z);
                            assert_eq!(out.flags, s.flags);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn conditional_termination_all_widths_conditions_zr_and_carry_availability() {
    for wide in [false, true] {
        for neq in [false, true] {
            for (a, b) in [
                (0, 0),
                (1, 0),
                (u64::MAX, u64::MAX),
                (1 << 32, 0),
                (1 << 63, 0),
            ] {
                for carry in [None, Some(0), Some(1)] {
                    for (n, m) in [(0, 1), (31, 1), (0, 31), (31, 31)] {
                        let mut s = State::new();
                        s.x[0] = a;
                        s.x[1] = b;
                        s.flags[2] = carry;
                        let left = if n == 31 {
                            0
                        } else if n == 0 {
                            a
                        } else {
                            b
                        };
                        let right = if m == 31 {
                            0
                        } else if m == 0 {
                            a
                        } else {
                            b
                        };
                        let mask = if wide { u64::MAX } else { u64::from(u32::MAX) };
                        let term = ((left & mask) == (right & mask)) ^ neq;
                        let w = 0x25a02000
                            | (u32::from(wide) << 22)
                            | (u32::from(neq) << 4)
                            | (m << 16)
                            | (n << 5);
                        let r = recipe(w, 128).unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert_eq!(t.registers.len(), 2);
                        let nwrite = t.registers.iter().find(|w| w.register.index == 0).unwrap();
                        assert_eq!(nwrite.value, Value::known(1, u64::from(term)));
                        let vwrite = t.registers.iter().find(|w| w.register.index == 3).unwrap();
                        assert_eq!(
                            vwrite.value,
                            if term {
                                Value::known(1, 0)
                            } else {
                                carry.map_or(Value::unknown(1), |v| Value::known(1, v ^ 1))
                            }
                        );
                        assert_eq!(s.flags[1], Some(0));
                        if term {
                            assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.nzcv"));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn trig_sign_selection_all_selectors_nan_classes_controls_and_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for size in 1..4 {
            let w = 8u8 << size;
            let sign = 1u64 << (w - 1);
            let (one, exp, fraction) = match w {
                16 => (0x3c00u64, 0x7c00u64, 0x3ffu64),
                32 => (0x3f800000, 0x7f800000, 0x7fffff),
                _ => (0x3ff0000000000000, 0x7ff0000000000000, 0xfffffffffffff),
            };
            let inputs = [
                0,
                sign,
                1,
                sign | 1,
                one,
                one | sign,
                exp,
                exp | sign,
                exp | 1,
                exp | (fraction >> 1),
                exp | sign | fraction,
            ];
            for ah in [0, 1] {
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                    for start in 0..inputs.len() {
                        let mut s = State::new();
                        s.fpcr = Some(ah << 1);
                        for e in 0..vl / u16::from(w) {
                            s.put(
                                n,
                                e * u16::from(w),
                                w,
                                inputs[(start + usize::from(e)) % inputs.len()],
                            );
                            s.put(m, e * u16::from(w), w, u64::from(e % 4) | 0x84);
                        }
                        let mut expected = s.clone();
                        for e in 0..vl / u16::from(w) {
                            let a = s.bits(n, e * u16::from(w), w);
                            let b = s.bits(m, e * u16::from(w), w);
                            let value = if b & 1 != 0 {
                                one | ((b & 2) << (w - 2))
                            } else if b & 2 != 0 {
                                if ah != 0 && a & exp == exp && a & fraction != 0 {
                                    a
                                } else {
                                    a ^ sign
                                }
                            } else {
                                a
                            };
                            expected.put(d, e * u16::from(w), w, value);
                        }
                        let (out, _) =
                            run(0x0420b000 | (size << 22) | (m << 16) | (n << 5) | d, vl, &s);
                        assert_eq!(out.z, expected.z);
                        assert_eq!(out.flags, s.flags);
                    }
                }
            }
        }
    }
}
#[test]
fn trig_one_suppresses_source_and_fp_context() {
    for size in 1..4 {
        let w = 8u8 << size;
        let mut s = State::new();
        s.fpcr = None;
        for e in 0..2048 / u16::from(w) {
            s.put(2, e * u16::from(w), w, 3);
        }
        for chunk in 0..32 {
            s.absent.push(Register {
                bank: "a64.vector64",
                index: 32 + chunk,
            });
        }
        assert!(evaluate(&recipe(0x0422b020 | (size << 22), 2048).unwrap(), &s).is_ok());
        assert!(!s
            .reads
            .borrow()
            .iter()
            .any(|r| r.bank == "a64.fpcr" || r.bank == "a64.vector64" && r.index / 32 == 1));
    }
}

// base,width,index-width,parts. Independent pseudocode oracle below uses
// element addresses, including the wrapped second 128-bit halfword table.
const FIXED_LOOKUP: [(u32, u8, u8, u32); 4] = [
    (0x4e801000, 8, 2, 4),
    (0x4ec00000, 16, 2, 8),
    (0x4e402000, 8, 4, 2),
    (0x4e401000, 16, 4, 4),
];
fn fixed_word(class: usize, part: u32, d: u32, n: u32, m: u32) -> u32 {
    let shift = [13, 12, 14, 13][class];
    FIXED_LOOKUP[class].0 | (part << shift) | (m << 16) | (n << 5) | d
}
#[test]
fn fixed_lookup_every_index_part_length_alias_and_wrapped_table() {
    let mut cases = 0;
    for (class, &(_, width, iw, parts)) in FIXED_LOOKUP.iter().enumerate() {
        for vl in [128, 256, 512, 1024, 2048] {
            for part in 0..parts {
                for (d, n, m) in [
                    (0, 1, 2),
                    (1, 1, 2),
                    (2, 1, 2),
                    (0, 31, 2),
                    (0, 31, 0),
                    (0, 0, 0),
                    (31, 31, 31),
                ] {
                    for start in 0..1u64 << iw {
                        let mut s = State::new();
                        // These forms must not consult scalable access controls,
                        // FPSR, predicates or vector chunks above the low128.
                        s.controls = [None; 5];
                        s.fpcr = None;
                        s.flags = [None; 4];
                        let elements = 128 / u16::from(width);
                        for e in 0..elements {
                            s.put(
                                m,
                                (elements * part as u16 + e) * u16::from(iw),
                                iw,
                                (start + u64::from(e)) & ((1 << iw) - 1),
                            );
                        }
                        let mut expected = s.clone();
                        for chunk in 2..vl / 64 {
                            expected.z[d as usize][chunk as usize] = 0;
                        }
                        for e in 0..elements {
                            let ix =
                                s.bits(m, (elements * part as u16 + e) * u16::from(iw), iw) as u16;
                            expected.put(
                                d,
                                e * u16::from(width),
                                width,
                                s.bits(
                                    (n + u32::from(ix / elements)) % 32,
                                    (ix % elements) * u16::from(width),
                                    width,
                                ),
                            );
                        }
                        let (out, t) = run(fixed_word(class, part, d, n, m), vl, &s);
                        assert_eq!(
                            out.z, expected.z,
                            "class{class} part{part} VL{vl} d{d} n{n} m{m} start{start}"
                        );
                        assert_eq!(t.registers.len(), usize::from(vl / 64));
                        assert!(s
                            .reads
                            .borrow()
                            .iter()
                            .all(|r| r.bank == "a64.vector64" && r.index % 32 < 2));
                        cases += 1;
                    }
                }
            }
        }
    }
    println!("{cases} fixed lookup states");
}
#[test]
fn fixed_lookup_rejects_reserved_encodings_and_lengths() {
    for word in [
        0x4e800000, 0x4e802000, 0x4e400000, 0x4e404000, 0x0e801000, 0x0e402000,
    ] {
        assert!(
            semantics::arm64_sve_lookup::a64(word, 0x1000, 128).is_none(),
            "{word:08x}"
        );
    }
    for vl in [0, 64, 129, 384, 4096] {
        assert!(matches!(
            recipe(0x4e801000, vl).unwrap().support,
            Support::Unsupported(_)
        ));
    }
}

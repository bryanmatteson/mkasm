#[allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::HashMap};
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl)
}
#[derive(Default)]
struct State {
    registers: HashMap<Register, u64>,
    forbidden: Option<u16>,
    memory: HashMap<u64, u8>,
    reads: RefCell<Vec<(u64, u8)>>,
}
impl State {
    fn set(&mut self, bank: &'static str, index: u16, value: u64) {
        self.registers.insert(Register { bank, index }, value);
    }
    fn lane(&mut self, n: u16, e: u16, w: u8, value: u64) {
        let bit = e * w as u16;
        let index = n * 32 + bit / 64;
        let old = *self
            .registers
            .get(&Register {
                bank: "a64.vector64",
                index,
            })
            .unwrap_or(&0);
        self.set(
            "a64.vector64",
            index,
            (old & !(mask(w) << (bit % 64))) | ((value & mask(w)) << (bit % 64)),
        );
    }
    fn predicate(&mut self, n: u16, e: u16, w: u8) {
        let bit = e * (w as u16 / 8);
        let index = n * 4 + bit / 64;
        let old = *self
            .registers
            .get(&Register {
                bank: "a64.predicate64",
                index,
            })
            .unwrap_or(&0);
        self.set("a64.predicate64", index, old | (1 << (bit % 64)));
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        if r.bank == "a64.vector64" {
            assert_ne!(self.forbidden, Some(r.index / 32), "inactive source read");
        }
        Value::known(
            if r.bank == "a64.fpsr" {
                32
            } else if r.bank == "a64.sme_fa64" {
                1
            } else {
                64
            },
            *self.registers.get(&r).unwrap_or(&0),
        )
    }
    fn read_memory(&self, a: u64, w: u8, endian: Endian) -> Result<Value, EvalError> {
        self.reads.borrow_mut().push((a, w));
        let mut value = 0;
        for i in 0..w / 8 {
            let byte = *self
                .memory
                .get(&(a + u64::from(i)))
                .ok_or(EvalError::Memory)?;
            let offset = if endian == Endian::Little {
                i
            } else {
                w / 8 - 1 - i
            };
            value |= u64::from(byte) << (8 * offset);
        }
        Ok(Value::known(w, value))
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
    let shift = 128 - w;
    ((i128::from(v & mask(w))) << shift) >> shift
}
fn run(word: u32, vl: u16, s: &State) -> Transition {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x} VL{vl}"));
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x} VL{vl}: {e:?}"));
    assert_eq!(t.next_pc.bits, 0x1004);
    t
}
fn reg(t: &Transition, bank: &str, index: u16) -> u64 {
    t.registers
        .iter()
        .find(|r| r.register.bank == bank && r.register.index == index)
        .unwrap_or_else(|| panic!("missing {bank}/{index}"))
        .value
        .bits
}
fn output(t: &Transition, n: u16, e: u16, w: u8) -> u64 {
    let bit = e * w as u16;
    reg(t, "a64.vector64", n * 32 + bit / 64) >> (bit % 64) & mask(w)
}
fn incoming(s: &State, n: u16, e: u16, w: u8) -> u64 {
    let bit = e * w as u16;
    *s.registers
        .get(&Register {
            bank: "a64.vector64",
            index: n * 32 + bit / 64,
        })
        .unwrap_or(&0)
        >> (bit % 64)
        & mask(w)
}
fn word(base: u32, w: u8, d: u32, n: u32, m: u32) -> u32 {
    base | ((w.trailing_zeros() - 3) << 22) | (n << 5) | (m << 16) | d
}
#[test]
fn divide_minmax_difference_high_multiply_all_widths_vl_alias_and_predication() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x04140000, 0x04150000, 0x04160000, 0x04170000, 0x04080000, 0x04090000, 0x040a0000,
                0x040b0000, 0x040c0000, 0x040d0000, 0x04120000, 0x04130000,
            ] {
                let divide = base & 0xfffc0000 == 0x04140000;
                if divide && w < 32 {
                    continue;
                }
                for alias in [false, true] {
                    let mut s = State::default();
                    let cases = [
                        0,
                        1,
                        mask(w),
                        1 << (w - 1),
                        (1 << (w - 1)) - 1,
                        3,
                        mask(w) - 2,
                    ];
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, cases[e as usize % cases.len()]);
                        s.lane(1, e, w, cases[(e as usize + 2) % cases.len()]);
                        if e % 3 != 1 {
                            s.predicate(0, e, w);
                        }
                    }
                    let source = if alias { 0 } else { 1 };
                    let t = run(word(base, w, 0, source, 0), vl, &s);
                    for e in 0..vl / w as u16 {
                        let a = incoming(&s, 0, e, w);
                        let b = incoming(&s, source as u16, e, w);
                        let unsigned = base & 0x10000 != 0;
                        let expected = if e % 3 == 1 {
                            a
                        } else if divide {
                            let (a, b) = if base & 0x20000 != 0 { (b, a) } else { (a, b) };
                            if b == 0 {
                                0
                            } else if unsigned {
                                a / b
                            } else {
                                (signed(a, w) / signed(b, w)) as u64 & mask(w)
                            }
                        } else if base & 0xfffc0000 == 0x04080000 {
                            let less = if unsigned {
                                a < b
                            } else {
                                signed(a, w) < signed(b, w)
                            };
                            if less == (base & 0x20000 != 0) {
                                a
                            } else {
                                b
                            }
                        } else if base & 0xfffe0000 == 0x040c0000 {
                            if unsigned {
                                a.abs_diff(b)
                            } else {
                                (signed(a, w) - signed(b, w)).unsigned_abs() as u64 & mask(w)
                            }
                        } else if unsigned {
                            ((u128::from(a) * u128::from(b)) >> w) as u64
                        } else {
                            ((signed(a, w) * signed(b, w)) >> w) as u64 & mask(w)
                        };
                        assert_eq!(output(&t, 0, e, w), expected, "{base:08x} w{w} lane{e}");
                    }
                }
            }
        }
    }
    let mut s = State::default();
    s.forbidden = Some(1);
    s.lane(0, 0, 64, 9);
    let t = run(word(0x04140000, 64, 0, 1, 0), 128, &s);
    assert_eq!(output(&t, 0, 0, 64), 9);
}
#[test]
fn saturating_register_predicate_immediate_preserve_fpsr_and_full_width_boundaries() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for unsigned in [false, true] {
                for subtract in [false, true] {
                    for predicated in [false, true] {
                        for reverse in [false, true] {
                            if reverse && (!predicated || !subtract) {
                                continue;
                            }
                            let base = if predicated {
                                0x44188000
                                    | (u32::from(unsigned) << 16)
                                    | (u32::from(subtract) << 17)
                                    | (u32::from(reverse) << 18)
                            } else {
                                0x04201000
                                    | (u32::from(unsigned) << 10)
                                    | (u32::from(subtract) << 11)
                            };
                            let mut s = State::default();
                            s.set("a64.fpsr", 0, 0x0800009f);
                            let cases =
                                [0, 1, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1, mask(w) - 1];
                            for e in 0..vl / w as u16 {
                                s.lane(0, e, w, cases[e as usize % 6]);
                                s.lane(1, e, w, cases[(e as usize + 1) % 6]);
                                s.lane(2, e, w, cases[(e as usize + 3) % 6]);
                                if e % 2 == 0 {
                                    s.predicate(0, e, w);
                                }
                            }
                            let instruction = if predicated {
                                word(base, w, 0, 1, 0)
                            } else {
                                word(base, w, 0, 1, 2)
                            };
                            let t = run(instruction, vl, &s);
                            assert!(!t.registers.iter().any(|v| v.register.bank == "a64.fpsr"));
                            for e in 0..vl / w as u16 {
                                let old = incoming(&s, 0, e, w);
                                let (a, b) = if predicated {
                                    (old, incoming(&s, 1, e, w))
                                } else {
                                    (incoming(&s, 1, e, w), incoming(&s, 2, e, w))
                                };
                                let (a, b) = if reverse { (b, a) } else { (a, b) };
                                let value = if unsigned {
                                    let x = if subtract {
                                        i128::from(a) - i128::from(b)
                                    } else {
                                        i128::from(a) + i128::from(b)
                                    };
                                    x.clamp(0, i128::from(mask(w))) as u64
                                } else {
                                    let x = if subtract {
                                        signed(a, w) - signed(b, w)
                                    } else {
                                        signed(a, w) + signed(b, w)
                                    };
                                    x.clamp(-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1) as u64
                                        & mask(w)
                                };
                                assert_eq!(
                                    output(&t, 0, e, w),
                                    if predicated && e % 2 != 0 { old } else { value },
                                    "{base:08x} w{w} lane{e}"
                                );
                            }
                        }
                    }
                }
            }
            for unsigned in [false, true] {
                for sub in [false, true] {
                    for sh in [false, true] {
                        if w == 8 && sh {
                            continue;
                        }
                        for imm in [0, 1, 127, 128, 255] {
                            let value = (imm as i128) << if sh { 8 } else { 0 };
                            let mut s = State::default();
                            for e in 0..vl / w as u16 {
                                s.lane(
                                    0,
                                    e,
                                    w,
                                    [0, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1][e as usize % 4],
                                );
                            }
                            let t = run(
                                word(
                                    0x2524c000
                                        | (u32::from(unsigned) << 16)
                                        | (u32::from(sub) << 17)
                                        | (u32::from(sh) << 13)
                                        | (imm << 5),
                                    w,
                                    0,
                                    0,
                                    0,
                                ),
                                vl,
                                &s,
                            );
                            for e in 0..vl / w as u16 {
                                let old = incoming(&s, 0, e, w);
                                let old = if unsigned {
                                    i128::from(old)
                                } else {
                                    signed(old, w)
                                };
                                let result = if sub { old - value } else { old + value };
                                let (low, high) = if unsigned {
                                    (0, i128::from(mask(w)))
                                } else {
                                    (-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1)
                                };
                                assert_eq!(
                                    output(&t, 0, e, w),
                                    result.clamp(low, high) as u64 & mask(w)
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
fn unary_counts_reverse_bits_subwords_merge_zero_and_source_suppression() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for (base, kind) in [
                (0x0406a000, 0),
                (0x0407a000, 1),
                (0x0408a000, 2),
                (0x0409a000, 3),
                (0x040aa000, 4),
                (0x040ea000, 5),
                (0x05278000, 6),
                (0x05248000, 7),
                (0x05258000, 8),
                (0x05268000, 9),
            ] {
                if kind >= 7 && w <= 8 << (kind - 7) {
                    continue;
                }
                for merge in [false, true] {
                    for alias in [false, true] {
                        let mut s = State::default();
                        let source = if alias { 0 } else { 1 };
                        let cases = [0, mask(w), 1, 1 << (w - 1), 0x123456789abcdef & mask(w)];
                        for e in 0..vl / w as u16 {
                            s.lane(0, e, w, mask(w));
                            s.lane(source, e, w, cases[e as usize % 5]);
                            if e % 2 == 0 {
                                s.predicate(0, e, w);
                            }
                        }
                        let instruction = word(
                            if kind < 6 {
                                base | if merge { 1 << 20 } else { 0 }
                            } else {
                                base | if merge { 0 } else { 1 << 13 }
                            },
                            w,
                            0,
                            source as u32,
                            0,
                        );
                        let t = run(instruction, vl, &s);
                        for e in 0..vl / w as u16 {
                            let a = incoming(&s, source, e, w);
                            let expected = if e % 2 != 0 {
                                if merge {
                                    incoming(&s, 0, e, w)
                                } else {
                                    0
                                }
                            } else {
                                match kind {
                                    0 => signed(a, w).abs() as u64 & mask(w),
                                    1 => a.wrapping_neg() & mask(w),
                                    2 => {
                                        let sign = a >> (w - 1);
                                        (0..w - 1).rev().take_while(|i| a >> i & 1 == sign).count()
                                            as u64
                                    }
                                    3 => u64::from(a.leading_zeros()) - u64::from(64 - w),
                                    4 => u64::from(a.count_ones()),
                                    5 => !a & mask(w),
                                    6 => a.reverse_bits() >> (64 - w),
                                    _ => {
                                        let sw = 8 << (kind - 7);
                                        (0..w / sw).fold(0, |v, i| {
                                            v | ((a >> (i * sw)) & mask(sw)) << (w - sw - i * sw)
                                        })
                                    }
                                }
                            };
                            assert_eq!(output(&t, 0, e, w), expected, "kind{kind} w{w} lane{e}");
                        }
                    }
                }
            }
        }
    }
    let mut s = State::default();
    s.forbidden = Some(1);
    let t = run(word(0x0409a000, 64, 0, 1, 0), 128, &s);
    assert_eq!(output(&t, 0, 0, 64), 0);
}
#[test]
fn integer_reductions_empty_identities_signed_sum_upper_clear_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x04002000, 0x04012000, 0x04082000, 0x04092000, 0x040a2000, 0x040b2000, 0x04182000,
                0x04192000, 0x041a2000,
            ] {
                if base == 0x04002000 && w == 64 {
                    continue;
                }
                for empty in [false, true] {
                    let mut s = State::default();
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, [mask(w), 2, 1 << (w - 1), 7][e as usize % 4]);
                        if !empty && e % 3 != 1 {
                            s.predicate(0, e, w);
                        }
                    }
                    let t = run(word(base, w, 0, 0, 0), vl, &s);
                    let values = (0..vl / w as u16)
                        .filter(|e| !empty && e % 3 != 1)
                        .map(|e| incoming(&s, 0, e, w))
                        .collect::<Vec<_>>();
                    let expected = match base {
                        0x04002000 => values.iter().map(|v| signed(*v, w)).sum::<i128>() as u64,
                        0x04012000 => values.iter().map(|v| u128::from(*v)).sum::<u128>() as u64,
                        0x04082000 => {
                            values
                                .iter()
                                .map(|v| signed(*v, w))
                                .max()
                                .unwrap_or(-(1i128 << (w - 1))) as u64
                                & mask(w)
                        }
                        0x040a2000 => {
                            values
                                .iter()
                                .map(|v| signed(*v, w))
                                .min()
                                .unwrap_or((1i128 << (w - 1)) - 1)
                                as u64
                                & mask(w)
                        }
                        0x04092000 => values.iter().copied().max().unwrap_or(0),
                        0x040b2000 => values.iter().copied().min().unwrap_or(mask(w)),
                        0x04182000 => values.iter().fold(0, |v, x| v | x),
                        0x04192000 => values.iter().fold(0, |v, x| v ^ x),
                        _ => values.iter().fold(mask(w), |v, x| v & x),
                    };
                    assert_eq!(output(&t, 0, 0, 64), expected, "{base:08x} w{w}");
                    for chunk in 1..vl / 64 {
                        assert_eq!(reg(&t, "a64.vector64", chunk), 0);
                    }
                    assert!(!t
                        .registers
                        .iter()
                        .any(|r| r.register.bank == "a64.fpsr" || r.register.bank == "a64.nzcv"));
                }
            }
        }
    }
}
#[test]
fn vector_and_predicate_permutations_move_complete_groups_with_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8u8, 16, 32, 64, 128] {
            if 2 * u16::from(w) > vl {
                continue;
            }
            for kind in 0..3 {
                for part in 0..2 {
                    for d in [0, 1, 2] {
                        let mut s = State::default();
                        for e in 0..vl / 64 {
                            s.lane(1, e, 64, 0x1020304050607080 + u64::from(e));
                            s.lane(2, e, 64, 0xfedcba9876543200 + u64::from(e));
                        }
                        let count = vl / u16::from(w);
                        let pairs = count / 2;
                        let base = if w == 128 {
                            [0x05a00000, 0x05a00800, 0x05a01800][kind]
                        } else {
                            [0x05206000, 0x05206800, 0x05207000][kind]
                        };
                        let instruction = if w == 128 {
                            base | (part << 10) | (2 << 16) | (1 << 5) | d
                        } else {
                            word(base | (part << 10), w, d, 1, 2)
                        };
                        let t = run(instruction, vl, &s);
                        for e in 0..count {
                            let (source, index) = match kind {
                                0 => (if e % 2 == 0 { 1 } else { 2 }, part as u16 * pairs + e / 2),
                                1 => (if e < pairs { 1 } else { 2 }, 2 * (e % pairs) + part as u16),
                                _ => (if e % 2 == 0 { 1 } else { 2 }, 2 * (e / 2) + part as u16),
                            };
                            for half in 0..if w == 128 { 2 } else { 1 } {
                                let width = if w == 128 { 64 } else { w };
                                assert_eq!(
                                    output(
                                        &t,
                                        d as u16,
                                        e * if w == 128 { 2 } else { 1 } + half,
                                        width
                                    ),
                                    incoming(
                                        &s,
                                        source,
                                        index * if w == 128 { 2 } else { 1 } + half,
                                        width
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
        for w in [8, 16, 32, 64] {
            for kind in 0..4 {
                for part in 0..if kind == 3 { 1 } else { 2 } {
                    let mut s = State::default();
                    for chunk in 0..4 {
                        s.set(
                            "a64.predicate64",
                            4 + chunk,
                            0x596ab3cc5079ef21u64.rotate_left(u32::from(chunk) * 13),
                        );
                        s.set(
                            "a64.predicate64",
                            8 + chunk,
                            0xe91237ab4c8f506du64.rotate_left(u32::from(chunk) * 7),
                        );
                    }
                    let base = if kind == 3 {
                        0x05344000
                    } else {
                        [0x05204000, 0x05204800, 0x05205000][kind]
                    };
                    let t = run(
                        word(base | (part << 10), w, 1, 1, if kind == 3 { 0 } else { 2 }),
                        vl,
                        &s,
                    );
                    let group = u16::from(w) / 8;
                    let count = vl / u16::from(w);
                    let pairs = count / 2;
                    for bit in 0..vl / 8 {
                        let e = bit / group;
                        let (source, index) = match kind {
                            0 => (if e % 2 == 0 { 1 } else { 2 }, part as u16 * pairs + e / 2),
                            1 => (if e < pairs { 1 } else { 2 }, 2 * (e % pairs) + part as u16),
                            2 => (if e % 2 == 0 { 1 } else { 2 }, 2 * (e / 2) + part as u16),
                            _ => (1, count - 1 - e),
                        };
                        let srcbit = index * group + bit % group;
                        let source = *s
                            .registers
                            .get(&Register {
                                bank: "a64.predicate64",
                                index: source * 4 + srcbit / 64,
                            })
                            .unwrap();
                        assert_eq!(
                            reg(&t, "a64.predicate64", 4 + bit / 64) >> (bit % 64) & 1,
                            source >> (srcbit % 64) & 1
                        );
                    }
                    for bit in vl / 8..256 {
                        assert_eq!(
                            reg(&t, "a64.predicate64", 4 + bit / 64) >> (bit % 64) & 1,
                            0
                        );
                    }
                }
            }
        }
    }
    let mut s = State::default();
    s.set("a64.svcr", 0, 1);
    let r = recipe(0x05a20020, 256).unwrap();
    assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
    s.set("a64.sme_fa64", 0, 1);
    assert!(evaluate(&r, &s).is_ok());
}
#[test]
fn table_lookup_extract_dup_reverse_wrap_indices_and_sp() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [0x05203000, 0x05202800, 0x05202c00] {
                for d in [0, 1, 2] {
                    let mut s = State::default();
                    let count = vl / w as u16;
                    for e in 0..count {
                        s.lane(0, e, w, 0x55);
                        s.lane(1, e, w, u64::from(e) + 11);
                        s.lane(
                            2,
                            e,
                            w,
                            [
                                0,
                                u64::from(count) - 1,
                                u64::from(count),
                                u64::from(count) * 2 - 1,
                                mask(w),
                            ][e as usize % 5],
                        );
                        s.lane(3, e, w, u64::from(e) + 91);
                        s.lane(4, e, w, u64::from(e) + 177);
                    }
                    let n = if base == 0x05202800 { 3 } else { 1 };
                    let t = run(word(base, w, d, n, 2), vl, &s);
                    for e in 0..count {
                        let index = incoming(&s, 2, e, w);
                        let expected = if index < u64::from(count) {
                            incoming(&s, n as u16, index as u16, w)
                        } else if base == 0x05202800 && index < u64::from(count) * 2 {
                            incoming(&s, (n as u16 + 1) % 32, index as u16 - count, w)
                        } else if base == 0x05202c00 {
                            incoming(&s, d as u16, e, w)
                        } else {
                            0
                        };
                        assert_eq!(output(&t, d as u16, e, w), expected);
                    }
                }
            }
            let mut s = State::default();
            for e in 0..vl / w as u16 {
                s.lane(1, e, w, u64::from(e) + 9);
            }
            let t = run(word(0x05383800, w, 1, 1, 0), vl, &s);
            for e in 0..vl / w as u16 {
                assert_eq!(
                    output(&t, 1, e, w),
                    (u64::from(vl / w as u16 - 1 - e) + 9) & mask(w)
                );
            }
            s.set("a64.sp", 0, 0xfedcba9876543210);
            let t = run(word(0x05203800, w, 0, 31, 0), vl, &s);
            for e in 0..vl / w as u16 {
                assert_eq!(output(&t, 0, e, w), 0xfedcba9876543210 & mask(w));
            }
        }
        for constructive in [false, true] {
            for offset in [0, 1, 15, 16, 31, 127, 255] {
                let mut s = State::default();
                for e in 0..vl / 8 {
                    s.lane(31, e, 8, u64::from(e));
                    s.lane(0, e, 8, u64::from(e) + 71);
                    s.lane(1, e, 8, u64::from(e) + 93);
                }
                let base = if constructive {
                    0x05600000 | (31 << 5) | 1
                } else {
                    0x05200000 | (0 << 5) | 31
                };
                let t = run(base | ((offset >> 3) << 16) | ((offset & 7) << 10), vl, &s);
                let count = vl / 8;
                let start = if offset >= u32::from(count) {
                    0
                } else {
                    offset as u16
                };
                for e in 0..count {
                    let pos = e + start;
                    assert_eq!(
                        output(&t, if constructive { 1 } else { 31 }, e, 8),
                        incoming(&s, if pos < count { 31 } else { 0 }, pos % count, 8)
                    );
                }
            }
        }
        for w in [8u8, 16, 32, 64, 128] {
            for index in [0, 1, 7, 63] {
                let mut s = State::default();
                for e in 0..vl / 64 {
                    s.lane(0, e, 64, u64::from(e) + 11);
                }
                let lsb = w.trailing_zeros() - 3;
                let imm = (index << (lsb + 1)) | (1 << lsb);
                if imm > 127 {
                    continue;
                }
                let instruction = 0x05202000 | ((imm & 31) << 16) | ((imm >> 5) << 22);
                let t = run(instruction, vl, &s);
                for e in 0..vl / 64 {
                    let expect = if index < u32::from(vl) / u32::from(w) {
                        if w == 128 {
                            incoming(&s, 0, (index as u16) * 2 + e % 2, 64)
                        } else {
                            let value = incoming(&s, 0, index as u16, w);
                            (0..64 / w).fold(0, |v, i| v | (value << (i * w)))
                        }
                    } else {
                        0
                    };
                    assert_eq!(reg(&t, "a64.vector64", e), expect);
                }
            }
        }
    }
}
#[test]
fn inactive_contiguous_memory_lanes_suppress_faults_and_active_faults_propagate() {
    for vl in [128, 256, 512, 1024, 2048] {
        let mut s = State::default();
        s.set("a64.gpr", 0, 0x1000);
        for i in 0..8 {
            s.memory.insert(0x1000 + i, (i + 1) as u8);
        }
        s.predicate(0, 0, 64);
        let t = run(0xa5e0a001, vl, &s);
        assert_eq!(output(&t, 1, 0, 64), 0x0807060504030201);
        assert_eq!(output(&t, 1, 1, 64), 0);
        assert_eq!(*s.reads.borrow(), [(0x1000, 64)]);
        s.predicate(0, 1, 64);
        assert_eq!(
            evaluate(&recipe(0xa5e0a001, vl).unwrap(), &s),
            Err(EvalError::Memory)
        );
    }
}

#[test]
fn immediate_minmax_modular_alu_dup_and_predicated_multiply_add_all_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x2528c000, 0x2529c000, 0x252ac000, 0x252bc000, 0x2530c000, 0x2520c000, 0x2521c000,
                0x2523c000, 0x2538c000,
            ] {
                for imm in [0, 1, 127, 128, 255] {
                    for sh in [false, true] {
                        let minmax = (base & 0xfffc0000) == 0x25280000;
                        let mul = base == 0x2530c000;
                        if sh && (w == 8 || minmax || mul) {
                            continue;
                        }
                        let mut s = State::default();
                        for e in 0..vl / w as u16 {
                            s.lane(
                                0,
                                e,
                                w,
                                [0, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1][e as usize % 4],
                            );
                        }
                        let instruction =
                            word(base | (imm << 5) | (u32::from(sh) << 13), w, 0, 0, 0);
                        let t = run(instruction, vl, &s);
                        let signed_imm = (imm as u8 as i8 as i128) << if sh { 8 } else { 0 };
                        let positive_imm = (imm as i128) << if sh { 8 } else { 0 };
                        for e in 0..vl / w as u16 {
                            let a = incoming(&s, 0, e, w);
                            let expected = if minmax {
                                let unsigned = base & 0x10000 != 0;
                                let a = if unsigned {
                                    i128::from(a)
                                } else {
                                    signed(a, w)
                                };
                                let imm = if unsigned { positive_imm } else { signed_imm };
                                if base & 0x20000 != 0 {
                                    a.min(imm)
                                } else {
                                    a.max(imm)
                                }
                            } else if mul {
                                i128::from(a) * signed_imm
                            } else if base == 0x2538c000 {
                                signed_imm
                            } else if base == 0x2520c000 {
                                i128::from(a) + positive_imm
                            } else if base == 0x2521c000 {
                                i128::from(a) - positive_imm
                            } else {
                                positive_imm - i128::from(a)
                            };
                            assert_eq!(
                                output(&t, 0, e, w),
                                expected as u64 & mask(w),
                                "{base:08x} imm{imm} w{w} sh{sh}"
                            );
                        }
                    }
                }
            }
            for base in [0x04004000, 0x04006000, 0x0400c000, 0x0400e000] {
                for d in [0, 1, 2] {
                    let mut s = State::default();
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, mask(w));
                        s.lane(1, e, w, 3 + u64::from(e));
                        s.lane(2, e, w, 7 + u64::from(e));
                        if e % 2 == 0 {
                            s.predicate(0, e, w);
                        }
                    }
                    let t = run(word(base, w, d, 1, 2), vl, &s);
                    for e in 0..vl / w as u16 {
                        let old = incoming(&s, d as u16, e, w);
                        let a = incoming(&s, 1, e, w);
                        let b = incoming(&s, 2, e, w);
                        let (addend, multiplicand) = if base & 0x8000 != 0 {
                            (a, old)
                        } else {
                            (old, a)
                        };
                        let product = multiplicand.wrapping_mul(b);
                        let expected = if e % 2 != 0 {
                            old
                        } else if base & 0x2000 != 0 {
                            addend.wrapping_sub(product)
                        } else {
                            addend.wrapping_add(product)
                        };
                        assert_eq!(output(&t, d as u16, e, w), expected & mask(w));
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_saturation_and_unary_saturation_extension_cover_signed_extremes() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [0x441c8000, 0x441d8000] {
                for a in [0, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1] {
                    for b in [0, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1] {
                        let mut s = State::default();
                        for e in 0..vl / w as u16 {
                            s.lane(0, e, w, a);
                            s.lane(1, e, w, b);
                            if e % 2 == 0 {
                                s.predicate(0, e, w);
                            }
                        }
                        let t = run(word(base, w, 0, 1, 0), vl, &s);
                        let expected = if base == 0x441c8000 {
                            (signed(a, w) + i128::from(b))
                                .clamp(-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1)
                                as u64
                                & mask(w)
                        } else {
                            (i128::from(a) + signed(b, w)).clamp(0, i128::from(mask(w))) as u64
                        };
                        for e in 0..vl / w as u16 {
                            assert_eq!(
                                output(&t, 0, e, w),
                                if e % 2 == 0 { expected } else { a },
                                "{base:08x} w{w} a{a:x} b{b:x}"
                            );
                        }
                        assert!(!t.registers.iter().any(|r| r.register.bank == "a64.fpsr"));
                    }
                }
            }
            for negate in [false, true] {
                for merge in [false, true] {
                    let mut s = State::default();
                    for e in 0..vl / w as u16 {
                        s.lane(
                            0,
                            e,
                            w,
                            [1 << (w - 1), mask(w), 0, 1, (1 << (w - 1)) - 1][e as usize % 5],
                        );
                        if e % 2 == 0 {
                            s.predicate(0, e, w);
                        }
                    }
                    let t = run(
                        word(
                            0x4408a000 | (u32::from(negate) << 16) | (u32::from(!merge) << 17),
                            w,
                            0,
                            0,
                            0,
                        ),
                        vl,
                        &s,
                    );
                    for e in 0..vl / w as u16 {
                        let a = incoming(&s, 0, e, w);
                        let expected = if e % 2 != 0 {
                            if merge {
                                a
                            } else {
                                0
                            }
                        } else {
                            let x = if negate {
                                -signed(a, w)
                            } else {
                                signed(a, w).abs()
                            };
                            x.min((1i128 << (w - 1)) - 1) as u64 & mask(w)
                        };
                        assert_eq!(output(&t, 0, e, w), expected);
                    }
                }
            }
            for sw in [8u8, 16, 32] {
                if sw >= w {
                    continue;
                }
                for unsigned in [false, true] {
                    for merge in [false, true] {
                        let mut s = State::default();
                        for e in 0..vl / w as u16 {
                            s.lane(0, e, w, 0x98765432123480ffu64.rotate_left(u32::from(e % 7)));
                            if e % 2 == 0 {
                                s.predicate(0, e, w);
                            }
                        }
                        let op = (sw.trailing_zeros() - 3) * 2 + u32::from(unsigned);
                        let t = run(
                            word(
                                0x0400a000 | (op << 16) | (u32::from(merge) << 20),
                                w,
                                0,
                                0,
                                0,
                            ),
                            vl,
                            &s,
                        );
                        for e in 0..vl / w as u16 {
                            let a = incoming(&s, 0, e, w);
                            let expected = if e % 2 != 0 {
                                if merge {
                                    a
                                } else {
                                    0
                                }
                            } else if unsigned {
                                a & mask(sw)
                            } else {
                                signed(a, sw) as u64 & mask(w)
                            };
                            assert_eq!(output(&t, 0, e, w), expected);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn division_and_saturation_corner_matrix_including_min_over_negative_one_at_every_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for a in [0, 1, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1] {
                for b in [0, 1, mask(w), 1 << (w - 1), (1 << (w - 1)) - 1] {
                    let mut s = State::default();
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, a);
                        s.lane(1, e, w, b);
                        s.predicate(0, e, w);
                    }
                    if w >= 32 {
                        for unsigned in [false, true] {
                            for reverse in [false, true] {
                                let t = run(
                                    word(
                                        0x04140000
                                            | (u32::from(unsigned) << 16)
                                            | (u32::from(reverse) << 17),
                                        w,
                                        0,
                                        1,
                                        0,
                                    ),
                                    vl,
                                    &s,
                                );
                                let (a, b) = if reverse { (b, a) } else { (a, b) };
                                let expected = if b == 0 {
                                    0
                                } else if unsigned {
                                    a / b
                                } else {
                                    (signed(a, w) / signed(b, w)) as u64 & mask(w)
                                };
                                for e in 0..vl / w as u16 {
                                    assert_eq!(output(&t, 0, e, w), expected);
                                }
                            }
                        }
                    }
                    for unsigned in [false, true] {
                        for sub in [false, true] {
                            let t = run(
                                word(
                                    0x44188000
                                        | (u32::from(unsigned) << 16)
                                        | (u32::from(sub) << 17),
                                    w,
                                    0,
                                    1,
                                    0,
                                ),
                                vl,
                                &s,
                            );
                            let (a, b) = if unsigned {
                                (i128::from(a), i128::from(b))
                            } else {
                                (signed(a, w), signed(b, w))
                            };
                            let sum = if sub { a - b } else { a + b };
                            let (lo, hi) = if unsigned {
                                (0, i128::from(mask(w)))
                            } else {
                                (-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1)
                            };
                            for e in 0..vl / w as u16 {
                                assert_eq!(output(&t, 0, e, w), sum.clamp(lo, hi) as u64 & mask(w));
                            }
                        }
                    }
                }
            }
        }
    }
}

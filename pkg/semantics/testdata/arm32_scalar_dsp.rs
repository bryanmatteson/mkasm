#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
#[derive(Clone, Default)]
struct State {
    g: [u32; 15],
    ge: u8,
    it: u8,
    reads: Cell<usize>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.set(self.reads.get() + 1);
        match r.bank {
            "a32.gpr" => Value::known(32, u64::from(self.g[r.index as usize])),
            "a32.ge" => Value::known(1, u64::from(self.ge >> r.index & 1)),
            "a32.itstate" => Value::known(8, u64::from(self.it)),
            "a32.nzcv" => Value::known(1, 0),
            _ => panic!("unexpected input {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("scalar DSP memory access")
    }
}
fn recipe(word: u32, thumb: bool) -> Option<Recipe> {
    let r = Recipe::new(0x1004, 32);
    if thumb {
        arm32_integer::thumb(word, 4, r)
    } else {
        arm32_integer::a32(word, r)
    }
}
fn run(word: u32, thumb: bool, state: &State) -> Transition {
    let graph = recipe(word, thumb).unwrap_or_else(|| panic!("missing {word:08x}"));
    assert_eq!(graph.support, Support::Full, "{word:08x}");
    graph.validate().unwrap();
    let transition = evaluate(&graph, state).unwrap();
    assert_eq!(transition.trap, None);
    assert!(transition.memory.is_empty());
    assert!(
        transition
            .registers
            .iter()
            .all(|w| matches!(w.register.bank, "a32.gpr" | "a32.ge" | "a32.itstate")),
        "NZCV/Q changed"
    );
    transition
}
fn out(t: &Transition, n: u16) -> u32 {
    t.registers
        .iter()
        .find(|w| w.register.bank == "a32.gpr" && w.register.index == n)
        .unwrap()
        .value
        .bits as u32
}
fn ge(t: &Transition) -> u8 {
    (0..4).fold(0, |v, bit| {
        v | ((t
            .registers
            .iter()
            .find(|w| w.register.bank == "a32.ge" && w.register.index == bit)
            .unwrap()
            .value
            .bits as u8)
            << bit)
    })
}
fn pair(a: u32, t: u32, d: u32, n: u32, m: u32, thumb: bool) -> u32 {
    if thumb {
        t | (d << 8) | (n << 16) | m
    } else {
        0xe0000000 | a | (d << 12) | (n << 16) | m
    }
}
fn signed(value: u32, w: u32) -> i64 {
    ((value as i32) << (32 - w) >> (32 - w)) as i64
}
const VALUES: &[u32] = &[
    0, 1, 0xffffffff, 0x7fff8000, 0x807f00ff, 0xff010080, 0x80000000, 0x12345678,
];
#[test]
fn every_parallel_ge_family_uses_untruncated_signed_results_and_unsigned_carry_or_no_borrow() {
    for thumb in [false, true] {
        for unsigned in [false, true] {
            for (op, tbase) in [
                (0, 0xfa90f000),
                (1, 0xfaa0f000),
                (2, 0xfae0f000),
                (3, 0xfad0f000),
                (4, 0xfa80f000),
                (7, 0xfac0f000),
            ] {
                let w = if op < 4 { 16 } else { 8 };
                let lane_mask = (1u32 << w) - 1;
                for &a in VALUES {
                    for &b in VALUES {
                        for d in [0, 1, 2, 13] {
                            let mut state = State::default();
                            state.g[1] = a;
                            state.g[2] = b;
                            state.ge = 0xa;
                            let mut expected = 0u32;
                            let mut flags = 0u8;
                            for i in 0..32 / w {
                                let j = if op == 1 || op == 2 { i ^ 1 } else { i };
                                let sub =
                                    op == 3 || op == 7 || op == 1 && i == 0 || op == 2 && i == 1;
                                let left = (a >> (i * w)) & lane_mask;
                                let right = (b >> (j * w)) & lane_mask;
                                let left = if unsigned {
                                    i64::from(left)
                                } else {
                                    signed(left, w)
                                };
                                let right = if unsigned {
                                    i64::from(right)
                                } else {
                                    signed(right, w)
                                };
                                let value = if sub { left - right } else { left + right };
                                expected |= (value as u32 & lane_mask) << (i * w);
                                let pass = if unsigned && !sub {
                                    value >= 1i64 << w
                                } else {
                                    value >= 0
                                };
                                if pass {
                                    flags |= ((1u8 << (w / 8)) - 1) << (i * w / 8);
                                }
                            }
                            let word = pair(
                                0x06100f10 | ((unsigned as u32) << 22) | (op << 5),
                                tbase | ((unsigned as u32) << 6),
                                d,
                                1,
                                2,
                                thumb,
                            );
                            let transition = run(word, thumb, &state);
                            assert_eq!(out(&transition, d as u16), expected, "{word:08x}");
                            assert_eq!(ge(&transition), flags, "{word:08x}");
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn selection_packing_and_extensions_preserve_aliases_and_rotate_all_bytes() {
    for thumb in [false, true] {
        for &a in VALUES {
            for &b in VALUES {
                for d in [0, 1, 2, 13] {
                    let mut state = State::default();
                    state.g[1] = a;
                    state.g[2] = b;
                    for flags in 0..16 {
                        state.ge = flags;
                        let transition =
                            run(pair(0x06800fb0, 0xfaa0f080, d, 1, 2, thumb), thumb, &state);
                        let mut expected = 0;
                        for i in 0..4 {
                            expected |= if flags >> i & 1 != 0 {
                                a & (255 << (i * 8))
                            } else {
                                b & (255 << (i * 8))
                            };
                        }
                        assert_eq!(out(&transition, d as u16), expected);
                        assert!(!transition
                            .registers
                            .iter()
                            .any(|w| w.register.bank == "a32.ge"));
                    }
                    for top in [false, true] {
                        for shift in [0, 1, 15, 16, 31] {
                            let word = if thumb {
                                0xeac00000
                                    | (1 << 16)
                                    | (d << 8)
                                    | ((shift >> 2) << 12)
                                    | ((shift & 3) << 6)
                                    | ((top as u32) << 5)
                                    | 2
                            } else {
                                0xe6800010
                                    | (1 << 16)
                                    | (d << 12)
                                    | (shift << 7)
                                    | ((top as u32) << 6)
                                    | 2
                            };
                            let shifted = if top {
                                ((b as i32) >> if shift == 0 { 31 } else { shift }) as u32
                            } else {
                                b << shift
                            };
                            let expected = if top {
                                a & 0xffff0000 | shifted & 0xffff
                            } else {
                                a & 0xffff | shifted & 0xffff0000
                            };
                            assert_eq!(out(&run(word, thumb, &state), d as u16), expected);
                        }
                    }
                    for unsigned in [false, true] {
                        for add in [false, true] {
                            for rotate in 0..4 {
                                let n = if add { 1 } else { 15 };
                                let word = pair(
                                    0x06800070 | ((unsigned as u32) << 22) | (rotate << 10),
                                    0xfa20f080 | ((unsigned as u32) << 20) | (rotate << 4),
                                    d,
                                    n,
                                    2,
                                    thumb,
                                );
                                let rotated = b.rotate_right(rotate * 8);
                                let mut expected = 0u32;
                                for i in 0..2 {
                                    let byte = (rotated >> (i * 16)) as u8;
                                    let extension = if unsigned {
                                        u16::from(byte)
                                    } else {
                                        byte as i8 as i16 as u16
                                    };
                                    let lane = if add {
                                        ((a >> (i * 16)) as u16).wrapping_add(extension)
                                    } else {
                                        extension
                                    };
                                    expected |= u32::from(lane) << (i * 16);
                                }
                                assert_eq!(
                                    out(&run(word, thumb, &state), d as u16),
                                    expected,
                                    "{word:08x}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
fn crc(mut acc: u32, data: u32, width: u32, castagnoli: bool) -> u32 {
    let polynomial = if castagnoli { 0x82f63b78 } else { 0xedb88320 };
    for byte in 0..width / 8 {
        acc ^= (data >> (byte * 8)) & 255;
        for _ in 0..8 {
            acc = if acc & 1 != 0 {
                (acc >> 1) ^ polynomial
            } else {
                acc >> 1
            };
        }
    }
    acc
}
#[test]
fn crc_both_polynomials_all_widths_aliases_and_standard_check_strings() {
    for thumb in [false, true] {
        for castagnoli in [false, true] {
            for size in 0..3 {
                for &a in VALUES {
                    for &b in VALUES {
                        for d in [0, 1, 2, 13] {
                            let mut state = State::default();
                            state.g[1] = a;
                            state.g[2] = b;
                            let word = pair(
                                0x01000040 | (size << 21) | ((castagnoli as u32) << 9),
                                0xfac0f080 | (size << 4) | ((castagnoli as u32) << 20),
                                d,
                                1,
                                2,
                                thumb,
                            );
                            assert_eq!(
                                out(&run(word, thumb, &state), d as u16),
                                crc(a, b, 8 << size, castagnoli),
                                "{word:08x}"
                            );
                        }
                    }
                }
            }
            let mut acc = 0xffffffff;
            for byte in b"123456789" {
                let mut state = State::default();
                state.g[1] = acc;
                state.g[2] = u32::from(*byte);
                let word = pair(
                    0x01000040 | ((castagnoli as u32) << 9),
                    0xfac0f080 | ((castagnoli as u32) << 20),
                    0,
                    1,
                    2,
                    thumb,
                );
                acc = out(&run(word, thumb, &state), 0);
            }
            assert_eq!(!acc, if castagnoli { 0xe3069283 } else { 0xcbf43926 });
        }
    }
}
#[test]
fn multiply_subtract_unsigned_accumulate_long_and_absolute_differences_capture_all_inputs() {
    for thumb in [false, true] {
        for &a in VALUES {
            for &b in VALUES {
                for (d, acc, n, m) in [
                    (0, 3, 1, 2),
                    (1, 3, 1, 2),
                    (2, 3, 1, 2),
                    (3, 0, 1, 2),
                    (1, 2, 1, 2),
                    (13, 3, 1, 2),
                ] {
                    let mut state = State::default();
                    for i in 0..15 {
                        state.g[i] = (i as u32).wrapping_mul(0x11111111);
                    }
                    state.g[n] = a;
                    state.g[m] = b;
                    let regs = if thumb {
                        ((n as u32) << 16) | ((acc as u32) << 12) | ((d as u32) << 8) | m as u32
                    } else {
                        ((d as u32) << 16) | ((acc as u32) << 12) | ((m as u32) << 8) | n as u32
                    };
                    let word = if thumb { 0xfb000010 } else { 0xe0600090 } | regs;
                    assert_eq!(
                        out(&run(word, thumb, &state), d as u16),
                        state.g[acc].wrapping_sub(a.wrapping_mul(b))
                    );
                    let word = if thumb { 0xfbe00060 } else { 0xe0400090 } | regs;
                    let expected = u64::from(a) * u64::from(b)
                        + u64::from(state.g[d])
                        + u64::from(state.g[acc]);
                    let transition = run(word, thumb, &state);
                    assert_eq!(out(&transition, d as u16), (expected >> 32) as u32);
                    assert_eq!(out(&transition, acc as u16), expected as u32);
                    for accumulate in [false, true] {
                        let acc = if accumulate { acc } else { 15 };
                        let regs = if thumb {
                            ((n as u32) << 16) | ((acc as u32) << 12) | ((d as u32) << 8) | m as u32
                        } else {
                            ((d as u32) << 16) | ((acc as u32) << 12) | ((m as u32) << 8) | n as u32
                        };
                        let word = if thumb { 0xfb700000 } else { 0xe7800010 } | regs;
                        let mut expected = if accumulate { state.g[acc] } else { 0 };
                        for i in 0..4 {
                            expected = expected.wrapping_add(
                                ((a >> (i * 8)) & 255).abs_diff((b >> (i * 8)) & 255),
                            );
                        }
                        assert_eq!(out(&run(word, thumb, &state), d as u16), expected);
                    }
                }
            }
        }
    }
}
#[test]
fn constrained_pc_overlap_crc_condition_and_it_cases_fail_before_architectural_outputs() {
    for word in [
        0xe611ff12, 0xe68f0fb2, 0xe6810fbf, 0xe100004f, 0xe1600042, 0xe0400091,
    ] {
        let graph = recipe(word, false);
        assert!(
            graph.is_none_or(|g| matches!(g.support, Support::Unsupported(_))),
            "{word:08x}"
        );
    }
    for cc in 0..14 {
        assert!(matches!(
            recipe((cc << 28) | 0x01000042, false).map(|g| g.support),
            None | Some(Support::Unsupported(_))
        ));
    }
    let mut state = State::default();
    state.it = 8;
    let graph = recipe(0xfac1f082, true).unwrap();
    assert!(matches!(
        evaluate(&graph, &state),
        Err(EvalError::UnsupportedContext)
    ));
}

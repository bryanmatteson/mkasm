#[allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::collections::HashMap;

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl)
}
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
fn mask(w: u8) -> u64 {
    u64::MAX >> (64 - w)
}
#[derive(Default)]
struct State {
    registers: HashMap<Register, u64>,
    forbidden_chunk: Option<u16>,
}
impl State {
    fn set(&mut self, bank: &'static str, index: u16, value: u64) {
        self.registers.insert(Register { bank, index }, value);
    }
    fn lane(&mut self, n: u16, e: u16, w: u8, value: u64) {
        let bit = e * u16::from(w);
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
    fn pred(&mut self, n: u16, e: u16, w: u8) {
        let bit = e * (u16::from(w) / 8);
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
            assert_ne!(
                self.forbidden_chunk,
                Some(r.index),
                "suppressed source read"
            );
        }
        Value::known(
            if matches!(r.bank, "a64.fpcr" | "a64.fpsr") {
                32
            } else {
                64
            },
            *self.registers.get(&r).unwrap_or(&0),
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("FP operation read memory")
    }
    fn evaluate_float(
        &self,
        _: &FloatExpression,
        _: &[Value],
        _: Value,
        _: Value,
    ) -> Result<Value, EvalError> {
        panic!("Scale/LogB must use exact bit expressions")
    }
}
fn run(word: u32, vl: u16, state: &State) -> Transition {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x} VL{vl}"));
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, state).unwrap_or_else(|e| panic!("{word:08x}: {e:?}"));
    assert_eq!(t.next_pc.bits, 0x1004);
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    assert!(t
        .registers
        .iter()
        .all(|r| matches!(r.register.bank, "a64.vector64" | "a64.fpsr")));
    t
}
fn register(t: &Transition, bank: &str, index: u16) -> u64 {
    t.registers
        .iter()
        .find(|w| w.register.bank == bank && w.register.index == index)
        .unwrap()
        .value
        .bits
}
fn output(t: &Transition, n: u16, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    (register(t, "a64.vector64", n * 32 + bit / 64) >> (bit % 64)) & mask(w)
}
fn scale(w: u8, d: u32, m: u32, pg: u32) -> u32 {
    0x65098000 | ((w.trailing_zeros() - 3) << 22) | (m << 5) | (pg << 10) | d
}
fn logb(w: u8, d: u32, n: u32, pg: u32, zero: bool) -> u32 {
    (if zero {
        0x641e8000 | ((w.trailing_zeros() - 3) << 13)
    } else {
        0x6518a000 | ((w.trailing_zeros() - 3) << 17)
    }) | (n << 5)
        | (pg << 10)
        | d
}
fn one(w: u8) -> u64 {
    match w {
        16 => 0x3c00,
        32 => 0x3f800000,
        _ => 0x3ff0000000000000,
    }
}

#[test]
fn scale_all_vl_widths_predicates_register_alias_and_signed_exponents() {
    for vl in VLS {
        for w in [16, 32, 64] {
            let f = match w {
                16 => 10,
                32 => 23,
                _ => 52,
            };
            let mut s = State::default();
            s.set("a64.fpsr", 0, 1 << 27);
            for e in 0..vl / u16::from(w) {
                s.lane(0, e, w, one(w));
                s.lane(1, e, w, if e % 4 == 0 { 2 } else { mask(w) });
                if e % 2 == 0 {
                    s.pred(7, e, w);
                }
            }
            let t = run(scale(w, 0, 1, 7), vl, &s);
            for e in 0..vl / u16::from(w) {
                let expected = if e % 4 == 0 {
                    one(w) + (2 << f)
                } else if e % 2 == 0 {
                    one(w) - (1 << f)
                } else {
                    one(w)
                };
                assert_eq!(output(&t, 0, e, w), expected, "VL{vl} w{w} lane{e}");
            }
            assert_eq!(register(&t, "a64.fpsr", 0), 1 << 27);
            // Zdn==Zm captures incoming bits for both float and integer operands.
            let mut s = State::default();
            for e in 0..vl / u16::from(w) {
                s.lane(31, e, w, one(w));
                s.pred(3, e, w);
            }
            let t = run(scale(w, 31, 31, 3), vl, &s);
            let infinity = match w {
                16 => 0x7c00,
                32 => 0x7f800000,
                _ => 0x7ff0000000000000,
            };
            for e in 0..vl / u16::from(w) {
                assert_eq!(output(&t, 31, e, w), infinity);
            }
            assert_eq!(register(&t, "a64.fpsr", 0), 20);
        }
    }
}

#[test]
fn logb_merge_zero_all_vl_widths_and_alias_preserve_integer_nzcv() {
    for vl in VLS {
        for w in [16, 32, 64] {
            for zero in [false, true] {
                for alias in [false, true] {
                    let mut s = State::default();
                    s.set("a64.nzcv", 0, 0xf);
                    let n = if alias { 17 } else { 29 };
                    let f = match w {
                        16 => 10,
                        32 => 23,
                        _ => 52,
                    };
                    for e in 0..vl / u16::from(w) {
                        s.lane(17, e, w, 0xdead);
                        s.lane(n, e, w, one(w) + (u64::from(e % 4) << f));
                        if e % 2 == 0 {
                            s.pred(6, e, w);
                        }
                    }
                    let t = run(logb(w, 17, u32::from(n), 6, zero), vl, &s);
                    for e in 0..vl / u16::from(w) {
                        let expected = if e % 2 == 0 {
                            u64::from(e % 4)
                        } else if zero {
                            0
                        } else if alias {
                            one(w) + (u64::from(e % 4) << f)
                        } else {
                            0xdead
                        };
                        assert_eq!(output(&t, 17, e, w), expected);
                    }
                    assert_eq!(register(&t, "a64.fpsr", 0), 0);
                }
            }
        }
    }
}

#[test]
fn inactive_lanes_skip_sources_exceptions_and_scale_context() {
    for w in [16, 32, 64] {
        for instruction in [
            scale(w, 0, 1, 0),
            logb(w, 0, 1, 0, false),
            logb(w, 0, 1, 0, true),
        ] {
            let mut s = State::default();
            s.forbidden_chunk = Some(32);
            s.set("a64.fpcr", 0, 2 | (1 << 8));
            s.set("a64.fpsr", 0, 0x0800009f);
            s.lane(0, 0, w, mask(w));
            let t = run(instruction, 128, &s);
            assert_eq!(register(&t, "a64.fpsr", 0), 0x0800009f);
            assert_eq!(t.trap, None);
            assert_eq!(
                output(&t, 0, 0, w),
                if instruction & 0xff000000 == 0x64000000 {
                    0
                } else {
                    mask(w)
                }
            );
        }
    }
    for w in [16, 32, 64] {
        let mut s = State::default();
        s.pred(0, 0, w);
        s.set("a64.fpcr", 0, 2 | (1 << 24));
        s.lane(0, 0, w, one(w));
        s.lane(1, 0, w, 1);
        let t = run(scale(w, 0, 1, 0), 128, &s);
        let f = match w {
            16 => 10,
            32 => 23,
            _ => 52,
        };
        assert_eq!(output(&t, 0, 0, w), one(w) + (1 << f));
        assert_eq!(register(&t, "a64.fpsr", 0), 0);
        assert_eq!(t.trap, None);
    }
}

#[test]
fn cumulative_flags_late_trap_commits_fpsr_before_stopping_all_destinations() {
    let mut s = State::default();
    s.set("a64.fpsr", 0, (1 << 27) | 1); // Existing IOC still traps on a new invalid.
    s.set("a64.fpcr", 0, (1 << 8) | 2);
    for e in 0..8 {
        s.pred(0, e, 32);
        s.lane(
            1,
            e,
            32,
            if e == 0 {
                1
            } else if e == 1 {
                0
            } else {
                0x3f800000
            },
        );
    }
    // AFP.AH keeps lane0 subnormal and reports IDC. A quiet NaN in lane1
    // raises InvalidOp too: the earlier IOC bit must not hide this new trap.
    s.lane(1, 0, 32, 1);
    s.lane(1, 1, 32, 0x7fc12345);
    s.forbidden_chunk = Some(33); // Lanes2 onward must not inspect input.
    let t = run(logb(32, 0, 1, 0, false), 256, &s);
    assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
    assert_eq!(register(&t, "a64.fpsr", 0), (1 << 27) | 129);
    assert!(t.registers.iter().all(|w| w.register.bank == "a64.fpsr"));
    let mut s = State::default();
    s.set("a64.fpcr", 0, 1 << 10);
    s.set("a64.fpsr", 0, 1 << 27);
    for e in 0..8 {
        s.pred(0, e, 32);
        s.lane(0, e, 32, if e == 7 { 0x7f7fffff } else { 0x3f800000 });
        s.lane(1, e, 32, 1);
    }
    let t = run(scale(32, 0, 1, 0), 256, &s);
    assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
    assert_eq!(register(&t, "a64.fpsr", 0), 1 << 27);
    assert!(t.registers.iter().all(|w| w.register.bank == "a64.fpsr"));
}

#[test]
fn scalar_bit_boundary_goldens_through_real_lane_dispatch() {
    for (w, value, exponent, control, expected, raised, trap) in [
        (16, 0x0400, u64::MAX, 0, 0x0200, 0, false),
        (16, 0x0400, u64::MAX, 1 << 11, 0x0200, 8, true),
        (16, 0x0400, u64::MAX, (1 << 19) | (1 << 11), 0, 8, false),
        (16, 1, u64::MAX, 1 << 22, 1, 24, false),
        (32, 0x7f7fffff, 1, 3 << 22, 0x7f7fffff, 20, false),
        (32, 0x7f800001, 1, 0, 0x7fc00001, 1, false),
        (32, 0xffc12345, 1, 1 << 25, 0x7fc00000, 0, false),
        (
            64,
            0x0010000000000000,
            u64::MAX,
            0,
            0x0008000000000000,
            0,
            false,
        ),
        (
            64,
            0xffefffffffffffff,
            1,
            1 << 22,
            0xffefffffffffffff,
            20,
            false,
        ),
    ] {
        let mut s = State::default();
        s.lane(0, 0, w, value);
        s.lane(1, 0, w, exponent);
        s.pred(0, 0, w);
        s.set("a64.fpcr", 0, control);
        let t = run(scale(w, 0, 1, 0), 128, &s);
        assert_eq!(register(&t, "a64.fpsr", 0), if trap { 0 } else { raised });
        assert_eq!(t.trap.is_some(), trap);
        if !trap {
            assert_eq!(output(&t, 0, 0, w), expected);
        }
    }
    for (w, value, control, expected, raised) in [
        (16, 1, 0, 0xffe8, 0),
        (32, 1, 0, 0xffffff6b, 0),
        (64, 1, 0, 0xfffffffffffffbce, 0),
        (32, 1, 1 << 24, 0x80000000, 129),
        (32, 1, 3, 0x80000000, 1),
        (32, 0xff800000, 0, 0x7fffffff, 0),
        (32, 0x7fc00000, 0, 0x80000000, 1),
        (32, 0x80000000, 0, 0x80000000, 1),
    ] {
        let mut s = State::default();
        s.lane(1, 0, w, value);
        s.pred(0, 0, w);
        s.set("a64.fpcr", 0, control);
        let t = run(logb(w, 0, 1, 0, true), 128, &s);
        assert_eq!(output(&t, 0, 0, w), expected);
        assert_eq!(register(&t, "a64.fpsr", 0), raised);
    }
}

#[test]
fn exact_width_dispatch_reserved_sizes_and_literal_architectural_words() {
    // Physical cases from June2026 FSCALE and FLOGB diagrams; size is not in
    // the same position in these three instruction classes.
    for (word, w) in [
        (0x65498020, 16),
        (0x65898020, 32),
        (0x65c98020, 64),
        (0x651aa020, 16),
        (0x651ca020, 32),
        (0x651ea020, 64),
        (0x641ea020, 16),
        (0x641ec020, 32),
        (0x641ee020, 64),
    ] {
        let mut s = State::default();
        s.pred(0, 0, w);
        s.lane(0, 0, w, one(w));
        s.lane(1, 0, w, 0);
        let t = run(word, 128, &s);
        assert_eq!(
            register(&t, "a64.fpsr", 0),
            if word & 0xff3fe000 == 0x65098000 {
                0
            } else {
                1
            }
        );
    }
    for word in [0x65098020, 0x6518a020, 0x641e8020] {
        assert!(
            recipe(word, 128).is_none(),
            "reserved byte format {word:08x}"
        );
    }
    for vl in [0, 64, 129, 384, 640, 1536, 2176] {
        assert!(recipe(scale(32, 0, 1, 0), vl).is_none());
    }
}

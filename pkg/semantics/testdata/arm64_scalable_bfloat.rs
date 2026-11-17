use semantics::*;
use std::{cell::Cell, collections::HashMap};
#[allow(dead_code)]
mod native_bfloat;
#[allow(dead_code)]
mod native_contract {
    pub use super::semantics::BFloatOperation as AArch64BFloatBinaryOperation;
    #[derive(Clone, Copy)]
    pub enum FloatRounding {
        NearestEven,
        NearestAway,
        Zero,
        Down,
        Up,
    }
    pub struct FloatExceptions;
    impl FloatExceptions {
        pub const INVALID: u8 = 1;
        pub const DENORMAL: u8 = 2;
        pub const DIVIDE_BY_ZERO: u8 = 4;
        pub const OVERFLOW: u8 = 8;
        pub const UNDERFLOW: u8 = 16;
        pub const INEXACT: u8 = 32;
    }
}
fn recipe(word: u32, vl: u16, sme: bool) -> Recipe {
    if sme {
        semantics::arm64_sme::a64(word, 0x1000, vl).unwrap()
    } else {
        semantics::arm64_sve_float_matrix::a64(word, 0x1000, vl)
            .or_else(|| semantics::arm64_sve::a64(word, 0x1000, Endian::Little, vl))
            .unwrap()
    }
}
#[derive(Default)]
struct State {
    regs: HashMap<Register, Value>,
    calls: Cell<usize>,
}
impl State {
    fn set(&mut self, bank: &'static str, index: u16, width: u8, bits: u64) {
        self.regs
            .insert(Register { bank, index }, Value::known(width, bits));
    }
    fn get(&self, bank: &'static str, index: u16) -> u64 {
        self.regs[&Register { bank, index }].bits
    }
    fn lane(&mut self, bank: &'static str, n: u16, e: u16, w: u8, value: u64) {
        let bit = e * u16::from(w);
        let index = n * 32 + bit / 64;
        let r = Register { bank, index };
        let old = self.regs.get(&r).map_or(0, |v| v.bits);
        let mask = (1u64 << w) - 1;
        self.set(
            bank,
            index,
            64,
            (old & !(mask << (bit % 64))) | ((value & mask) << (bit % 64)),
        );
    }
    fn element(&self, bank: &'static str, n: u16, e: u16, w: u8) -> u32 {
        let bit = e * u16::from(w);
        (self.get(bank, n * 32 + bit / 64) >> (bit % 64) & ((1u64 << w) - 1)) as u32
    }
    fn pred(&mut self, n: u16, e: u16, on: bool) {
        if on {
            let bit = e * 2;
            let index = n * 4 + bit / 64;
            let value = self.get("a64.predicate64", index) | (1 << (bit % 64));
            self.set("a64.predicate64", index, 64, value);
        }
    }
    fn base(vl: u16, control: u32, sme: bool) -> Self {
        let mut s = Self::default();
        s.set("a64.fpcr", 0, 32, control.into());
        s.set(
            "a64.svcr",
            0,
            if sme { 2 } else { 64 },
            if sme { 3 } else { 0 },
        );
        for n in 0..8 {
            for chunk in 0..4 {
                s.set("a64.predicate64", n * 4 + chunk, 64, 0);
            }
        }
        for row in 0..vl / 8 {
            for chunk in 0..vl / 64 {
                s.set("a64.za64", row * 32 + chunk, 64, 0);
            }
        }
        s
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        *self
            .regs
            .get(&r)
            .unwrap_or_else(|| panic!("unavailable input {r:?}"))
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("BF16 memory")
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        input: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        assert_eq!(f.operation, FloatOperation::BFloatDotAdd);
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.width, 32);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(status, Value::known(32, 0));
        assert_eq!(
            control,
            self.regs[&Register {
                bank: "a64.fpcr",
                index: 0
            }]
        );
        assert!(input.iter().all(|v| v.is_known()));
        self.calls.set(self.calls.get() + 1);
        Ok(Value::known(
            32,
            native_bfloat::aarch64_bfloat_dot_add_controlled(
                input[0].bits as u32,
                input[1].bits as u16,
                input[2].bits as u16,
                input[3].bits as u16,
                input[4].bits as u16,
                control.bits as u32,
            )
            .into(),
        ))
    }
}
fn run(word: u32, vl: u16, sme: bool, s: &State) -> HashMap<Register, u64> {
    let r = recipe(word, vl, sme);
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    assert_eq!(t.trap, None);
    assert!(t.events.is_empty());
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    let mut out = HashMap::new();
    for w in t.registers {
        assert_eq!(
            w.register.bank,
            if sme { "a64.za64" } else { "a64.vector64" }
        );
        assert!(w.value.is_known());
        out.insert(w.register, w.value.bits);
    }
    out
}
fn output(out: &HashMap<Register, u64>, bank: &'static str, n: u16, e: u16) -> u32 {
    (out[&Register {
        bank,
        index: n * 32 + e / 2,
    }] >> (e % 2 * 32)) as u32
}
fn fill(s: &mut State, vl: u16, acc: u32, args: [u16; 4]) {
    for e in 0..vl / 32 {
        s.lane("a64.vector64", 0, e, 32, acc.into());
        for k in 0..2 {
            s.lane("a64.vector64", 1, 2 * e + k, 16, args[k as usize].into());
            s.lane(
                "a64.vector64",
                2,
                2 * e + k,
                16,
                args[2 + k as usize].into(),
            );
        }
    }
}
#[test]
fn sve_bfloat_environments_vector_indexed_matrix_all_vls() {
    for vl in [128, 256, 512, 1024, 2048] {
        for &(control, acc, args, one, _, two) in CASES {
            for base in [
                0x64608000, 0x64604000, 0x64684000, 0x64704000, 0x64784000, 0x6460e400,
            ] {
                let mut s = State::base(vl, control, false);
                fill(&mut s, vl, acc, args);
                let word = base | (1 << 5) | (2 << 16);
                let out = run(word, vl, false, &s);
                assert_eq!(out.len(), (vl / 64) as usize);
                let matrix = base == 0x6460e400;
                for e in 0..vl / 32 {
                    assert_eq!(
                        output(&out, "a64.vector64", 0, e),
                        if matrix { two } else { one },
                        "{word:08x} VL{vl} FPCR={control:08x} e{e}"
                    );
                }
                assert_eq!(
                    s.calls.get(),
                    (vl / 32) as usize * if matrix { 2 } else { 1 }
                );
            }
        }
    }
}
#[test]
fn sve_segment_index_matrix_and_incoming_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for base in [
            0x64608000, 0x64604000, 0x64684000, 0x64704000, 0x64784000, 0x6460e400,
        ] {
            for (d, n, m) in [
                (0u16, 1u16, 2u16),
                (1, 1, 2),
                (2, 1, 2),
                (3, 3, 3),
                (31, 31, 2),
            ] {
                let mut s = State::base(vl, 1 << 13, false);
                for e in 0..vl / 32 {
                    s.lane("a64.vector64", d, e, 32, (e as f32 + 1.0).to_bits().into());
                }
                for reg in [n, m] {
                    for e in 0..vl / 16 {
                        s.lane(
                            "a64.vector64",
                            reg,
                            e,
                            16,
                            ((e % 13 + reg % 3 + 1) as f32).to_bits() as u64 >> 16,
                        );
                    }
                }
                let word = base | u32::from(d) | (u32::from(n) << 5) | (u32::from(m) << 16);
                let out = run(word, vl, false, &s);
                let matrix = base == 0x6460e400;
                let indexed = base != 0x64608000 && !matrix;
                for e in 0..vl / 32 {
                    let mut expected = f32::from_bits(s.element("a64.vector64", d, e, 32));
                    for k in 0..if matrix { 2 } else { 1 } {
                        let (a, z) = if matrix {
                            (
                                e / 4 * 8 + (e % 4 / 2) * 4 + 2 * k,
                                e / 4 * 8 + (e % 2) * 4 + 2 * k,
                            )
                        } else {
                            (
                                2 * e,
                                if indexed {
                                    2 * (e / 4 * 4 + ((word >> 19) & 3) as u16)
                                } else {
                                    2 * e
                                },
                            )
                        };
                        let f =
                            |reg, i| f32::from_bits(s.element("a64.vector64", reg, i, 16) << 16);
                        let dot = f(n, a) * f(m, z) + f(n, a + 1) * f(m, z + 1);
                        expected += dot;
                    }
                    assert_eq!(
                        output(&out, "a64.vector64", d, e),
                        expected.to_bits(),
                        "{word:08x} VL{vl} e{e}"
                    );
                }
            }
        }
    }
}
#[test]
fn sme_bfmopa_bfmops_effective_environments_all_vls() {
    for vl in [128, 256, 512, 1024, 2048] {
        for (i, &(control, acc, args, add, sub, _)) in CASES.iter().enumerate() {
            if vl > 128 && i % 8 != 0 && i < 40 {
                continue;
            }
            for subtract in [false, true] {
                let mut s = State::base(vl, control, true);
                fill(&mut s, vl, acc, args);
                for e in 0..vl / 16 {
                    s.pred(0, e, true);
                    s.pred(1, e, true);
                }
                for row in 0..vl / 32 {
                    for col in 0..vl / 32 {
                        s.lane("a64.za64", row * 4, col, 32, acc.into());
                    }
                }
                let word = 0x81800000 | (1 << 5) | (2 << 16) | (1 << 13) | ((subtract as u32) << 4);
                let out = run(word, vl, true, &s);
                for row in 0..vl / 32 {
                    for col in 0..vl / 32 {
                        assert_eq!(
                            output(&out, "a64.za64", row * 4, col),
                            if subtract { sub } else { add },
                            "{word:08x} VL{vl} FPCR={control:08x} row{row} col{col}"
                        );
                    }
                }
                assert_eq!(s.calls.get(), (vl / 32) as usize * (vl / 32) as usize);
            }
        }
    }
}
#[test]
fn sme_partial_products_and_fully_inactive_context_are_lazy() {
    for vl in [128, 256, 512, 1024, 2048] {
        for subtract in [false, true] {
            let mut s = State::base(vl, 1 << 13, true);
            fill(&mut s, vl, 5f32.to_bits(), [0x3f80, 0x4000, 0x4040, 0x4080]);
            for e in 0..vl / 16 {
                s.pred(0, e, (e / 2 + e % 2) % 3 != 0);
                s.pred(1, e, (e / 2 + e % 2) % 4 != 0);
            }
            for row in 0..vl / 32 {
                for col in 0..vl / 32 {
                    s.lane("a64.za64", row * 4, col, 32, 5f32.to_bits().into());
                }
            }
            let word = 0x81800000 | (1 << 5) | (2 << 16) | (1 << 13) | ((subtract as u32) << 4);
            let out = run(word, vl, true, &s);
            for row in 0..vl / 32 {
                for col in 0..vl / 32 {
                    let mut product = 0;
                    for k in 0..2 {
                        if (row + k) % 3 != 0 && (col + k) % 4 != 0 {
                            product += if k == 0 { 3 } else { 8 };
                        }
                    }
                    let expected = if subtract { 5 - product } else { 5 + product };
                    assert_eq!(
                        output(&out, "a64.za64", row * 4, col),
                        (expected as f32).to_bits()
                    );
                }
            }
            for chunk in 0..4 {
                s.set("a64.predicate64", chunk, 64, 0);
                s.set("a64.predicate64", 4 + chunk, 64, 0);
            }
            s.regs.remove(&Register {
                bank: "a64.fpcr",
                index: 0,
            });
            s.regs.retain(|r, _| r.bank != "a64.vector64");
            s.calls.set(0);
            let out = run(word, vl, true, &s);
            assert_eq!(s.calls.get(), 0);
            for row in 0..vl / 32 {
                for col in 0..vl / 32 {
                    assert_eq!(output(&out, "a64.za64", row * 4, col), 5f32.to_bits());
                }
            }
        }
    }
}
// Exact-rational June BFDotAdd reference vectors. The final columns are one
// add, one sign-inverted-input subtract, and two ordered dot-add stages.
const CASES: &[(u32, u32, [u16; 4], u32, u32, u32)] = &[
    (
        0xbf00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0x40bf00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0x80bf00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0xc0bf00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0x100bf00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0x100bf02,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0xbf01,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0xbf02,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x3f800000,
        0x3f800000,
        0x3f800000,
    ),
    (
        0xbf00,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0x40bf00,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800001,
        0xbf800000,
        0x40000001,
    ),
    (
        0x80bf00,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800001,
        0x40000000,
    ),
    (
        0xc0bf00,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0x100bf00,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0x100bf02,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0xbf01,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0xbf02,
        0x0,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x3f800000,
        0xbf800000,
        0x40000000,
    ),
    (
        0xbf00,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0x40bf00,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x34000000,
        0xc0000000,
        0x3f800002,
    ),
    (
        0x80bf00,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x80000000,
        0xc0000001,
        0x3f800000,
    ),
    (
        0xc0bf00,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0x100bf00,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0x100bf02,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0xbf01,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0xbf02,
        0xbf800000,
        [0x3f80, 0x3980, 0x3f80, 0x3980],
        0x0,
        0xc0000000,
        0x3f800000,
    ),
    (
        0xbf00,
        0x0,
        [0x1, 0x0, 0x3f80, 0x0],
        0x10000,
        0x80010000,
        0x20000,
    ),
    (
        0x40bf00,
        0x0,
        [0x1, 0x0, 0x3f80, 0x0],
        0x10000,
        0x80010000,
        0x20000,
    ),
    (
        0x80bf00,
        0x0,
        [0x1, 0x0, 0x3f80, 0x0],
        0x10000,
        0x80010000,
        0x20000,
    ),
    (
        0xc0bf00,
        0x0,
        [0x1, 0x0, 0x3f80, 0x0],
        0x10000,
        0x80010000,
        0x20000,
    ),
    (0x100bf00, 0x0, [0x1, 0x0, 0x3f80, 0x0], 0x0, 0x0, 0x0),
    (0x100bf02, 0x0, [0x1, 0x0, 0x3f80, 0x0], 0x0, 0x0, 0x0),
    (0xbf01, 0x0, [0x1, 0x0, 0x3f80, 0x0], 0x0, 0x0, 0x0),
    (
        0xbf02,
        0x0,
        [0x1, 0x0, 0x3f80, 0x0],
        0x10000,
        0x80010000,
        0x20000,
    ),
    (
        0xbf00,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x40bf00,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x80bf00,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0xc0bf00,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x100bf00,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x100bf02,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0xffc00000,
        0xffc00000,
        0xffc00000,
    ),
    (
        0xbf01,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0xbf02,
        0x7f800001,
        [0x3f80, 0x0, 0x3f80, 0x0],
        0xffc00000,
        0xffc00000,
        0xffc00000,
    ),
    (
        0x0,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x9f00,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x2,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0xffc00000,
        0xffc00000,
        0xffc00000,
    ),
    (
        0x400000,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
    (
        0x1000000,
        0x3f800000,
        [0x7f7f, 0x7f7f, 0x7f7f, 0xff7f],
        0x7fc00000,
        0x7fc00000,
        0x7fc00000,
    ),
];

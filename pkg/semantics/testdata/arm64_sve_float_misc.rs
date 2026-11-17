#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8)] = &[
    (0x650e8000, 0), //famax_z_p_zz_
    (0x650f8000, 1), //famin_z_p_zz_
    (0x64202400, 2), //fclamp_z_zz_
    (0x65000c00, 3), //ftsmul_z_zz_
    (0x0420b000, 4), //ftssel_z_zz_
];
fn mask(w: u8) -> u64 {
    u64::MAX >> (64 - w)
}
fn lane(z: &[[u64; 32]], n: u32, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    (z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
}
fn put(z: &mut [[u64; 32]], n: u32, e: u16, w: u8, v: u64) {
    let bit = e * u16::from(w);
    let out = &mut z[n as usize][usize::from(bit / 64)];
    *out = (*out & !(mask(w) << (bit % 64))) | ((v & mask(w)) << (bit % 64));
}
// Small integral values are exact in every supported format. This oracle
// derives half bits from the binary32 significand without using the recipe.
fn encode(v: f64, w: u8, bf: bool) -> u64 {
    if w == 64 {
        return v.to_bits();
    }
    if !v.is_finite() {
        return match w {
            16 => {
                if v.is_nan() {
                    0x7e00
                } else {
                    0x7c00 | if v.is_sign_negative() { 0x8000 } else { 0 }
                }
            }
            _ => u64::from((v as f32).to_bits()),
        };
    }
    let bits = (v as f32).to_bits();
    if w == 32 {
        return u64::from(bits);
    }
    if bf {
        return u64::from(bits >> 16);
    }
    let sign = (bits >> 16) & 0x8000;
    if bits & 0x7fffffff == 0 {
        return u64::from(sign);
    }
    u64::from(sign | ((((bits >> 23) & 255) - 112) << 10) | ((bits >> 13) & 1023))
}
fn decode(v: u64, w: u8) -> f64 {
    if w == 64 {
        return f64::from_bits(v);
    }
    if w == 32 {
        return f64::from(f32::from_bits(v as u32));
    }
    if v & 0x7c00 == 0x7c00 {
        return if v & 0x3ff != 0 {
            f64::NAN
        } else if v & 0x8000 != 0 {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    if v & 0x7fff == 0 {
        return if v & 0x8000 != 0 { -0.0 } else { 0.0 };
    }
    let bits = (((v as u32) & 0x8000) << 16)
        | (((((v as u32) >> 10) & 31) + 112) << 23)
        | (((v as u32) & 1023) << 13);
    f64::from(f32::from_bits(bits))
}

fn pattern(bit: u16, which: u32) -> bool {
    match which {
        0 => false,
        1 => bit % 5 != 0,
        2 => bit % 7 == 0,
        _ => true,
    }
}

fn args(kind: u8, alias: u32) -> (u32, u32, u32) {
    let d = 8;
    let n = if kind <= 1 || alias == 1 {
        d
    } else if alias == 3 {
        15
    } else {
        24
    };
    let m = if alias == 2 || kind <= 1 && alias == 1 {
        d
    } else {
        15
    };
    (d, n, m)
}
fn data(kind: u8, w: u8, n: u32, m: u32, alias: u32) -> [[u64; 32]; 32] {
    let mut z = [[0u64; 32]; 32];
    for reg in 0..32u32 {
        for e in 0..2048 / u16::from(w) {
            let num = f64::from((reg + u32::from(e)) % 6) - 2.0;
            put(&mut z, reg, e, w, encode(num, w, false));
        }
    }
    if kind >= 3 {
        for e in 0..2048 / u16::from(w) {
            put(
                &mut z,
                m,
                e,
                w,
                if n == m {
                    0
                } else {
                    u64::from((u32::from(e) + alias) % 4)
                },
            );
        }
    }
    z
}
fn expected(
    before: &[[u64; 32]; 32],
    kind: u8,
    d: u32,
    n: u32,
    m: u32,
    w: u8,
    vl: u16,
    which: u32,
) -> [[u64; 32]; 32] {
    let mut out = *before;
    for e in 0..vl / u16::from(w) {
        let a = lane(before, n, e, w);
        let b = lane(before, m, e, w);
        let old = lane(before, d, e, w);
        let result = if kind <= 1 && !pattern(e * u16::from(w / 8), which) {
            old
        } else if kind == 4 {
            if b & 1 != 0 {
                encode(if b & 2 != 0 { -1.0 } else { 1.0 }, w, false)
            } else {
                a ^ if b & 2 != 0 { 1u64 << (w - 1) } else { 0 }
            }
        } else {
            let num = decode(a, w);
            let rhs = decode(b, w);
            let value = match kind {
                0 => num.abs().max(rhs.abs()),
                1 => num.abs().min(rhs.abs()),
                2 => num.max(decode(old, w)).min(rhs),
                _ => {
                    let sq = num * num;
                    if b & 1 != 0 {
                        -sq.abs()
                    } else {
                        sq.abs()
                    }
                }
            };
            encode(value, w, false)
        };
        put(&mut out, d, e, w, result);
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sve_float_misc::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    p: [u64; 4],
    sm: bool,
    sme2: bool,
    fa64: bool,
    control: u32,
    status: u32,
    empty: bool,
    bit_only: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => {
                    if self.empty {
                        assert_eq!(r.index / 32, 8);
                    }
                    self.z[usize::from(r.index / 32)][usize::from(r.index % 32)]
                }
                "a64.predicate64" => {
                    assert_eq!(r.index / 4, 3);
                    self.p[usize::from(r.index % 4)]
                }
                "a64.svcr" => u64::from(self.sm),
                "a64.sme2" => u64::from(self.sme2),
                "a64.sme_fa64" => u64::from(self.fa64),
                "a64.fpcr" => {
                    assert!(!self.empty);
                    u64::from(self.control)
                }
                "a64.fpsr" => {
                    assert!(!self.empty && !self.bit_only);
                    u64::from(self.status)
                }
                _ => panic!("{r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        inputs: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        assert!(!self.empty && !self.bit_only);
        assert_eq!(
            control.bits,
            u64::from(
                self.control
                    & !(1 << 26)
                    & if self.sm && !self.fa64 {
                        !0x9f00
                    } else {
                        u32::MAX
                    }
            )
        );
        let a = decode(inputs[0].bits, f.width);
        let b = decode(inputs[1].bits, f.width);
        let value = match f.operation {
            FloatOperation::Multiply => a * b,
            FloatOperation::MinMax { minimum, .. } => {
                if minimum {
                    a.min(b)
                } else {
                    a.max(b)
                }
            }
            _ => panic!("{f:?}"),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, encode(value, f.width, false)),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
fn state() -> State {
    State {
        z: [[0; 32]; 32],
        p: [u64::MAX; 4],
        sm: false,
        sme2: false,
        fa64: false,
        control: 0x04089f00,
        status: 0x08000000,
        empty: false,
        bit_only: false,
    }
}
#[test]
fn all_sve_float_misc_widths_lengths_predicates_aliases_and_backing() {
    for &(base, kind) in FORMS {
        for size in 1..=3 {
            let w = 8u8 << size;
            for vl in [128, 256, 512, 1024, 2048] {
                for which in 0..4 {
                    for alias in 0..4 {
                        let (d, n, m) = args(kind, alias);
                        let word = base
                            | (size << 22)
                            | d
                            | if kind <= 1 {
                                m << 5 | (3 << 10)
                            } else {
                                n << 5 | m << 16
                            };
                        let mut s = state();
                        s.z = data(kind, w, n, m, alias);
                        s.p = [0; 4];
                        s.sm = alias == 1;
                        s.fa64 = alias == 1;
                        s.sme2 = alias == 1;
                        s.empty = which == 0 && kind <= 1;
                        s.bit_only = kind == 4;
                        for bit in 0..vl / 8 {
                            if pattern(bit, which) {
                                s.p[usize::from(bit / 64)] |= 1 << (bit % 64);
                            }
                        }
                        let want = expected(&s.z, kind, d, n, m, w, vl, which);
                        let r = recipe(word, vl).unwrap();
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert_eq!(t.trap, None);
                        let mut out = s.z;
                        for wr in t.registers {
                            if wr.register.bank == "a64.vector64" {
                                out[usize::from(wr.register.index / 32)]
                                    [usize::from(wr.register.index % 32)] = wr.value.bits;
                            } else {
                                assert_eq!(wr.register.bank, "a64.fpsr");
                                assert_eq!(wr.value.bits, 0x08000000);
                            }
                        }
                        for reg in 0..32 {
                            for k in 0..32 {
                                assert_eq!(
                                    out[reg][k], want[reg][k],
                                    "{word:08x} VL{vl} mask{which} alias{alias} Z{reg} chunk{k}"
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
fn absolute_minmax_disables_flushes_and_retains_original_nan_payload_priority() {
    for &(base, kind) in FORMS {
        if kind > 1 {
            continue;
        }
        for (size, sub, qnan, snan, quiet, default) in [
            (1, 0x8001, 0xfe55, 0x7c19, 0x0200, 0x7e00),
            (
                2, 0x80000001, 0xffc12345, 0x7f812345, 0x00400000, 0x7fc00000,
            ),
            (
                3,
                0x8000000000000001,
                0xfff8123456789abc,
                0x7ff0123456789abc,
                0x0008000000000000,
                0x7ff8000000000000,
            ),
        ] {
            let w = 8u8 << size;
            for (a, b, want, invalid) in [
                (sub, 0, if kind == 0 { 1 } else { 0 }, false),
                (qnan, snan, snan | quiet, true),
                (snan, qnan, snan | quiet, true),
                (qnan, qnan, qnan, false),
            ] {
                for dn in [false, true] {
                    let mut s = state();
                    s.control = 0x05080003 | if dn { 1 << 25 } else { 0 };
                    s.p = [1, 0, 0, 0];
                    put(&mut s.z, 8, 0, w, a);
                    put(&mut s.z, 15, 0, w, b);
                    let word = base | (size << 22) | 8 | (15 << 5) | (3 << 10);
                    let t = evaluate(&recipe(word, 128).unwrap(), &s).unwrap();
                    let expected = if dn && (a == qnan || a == snan) {
                        default
                    } else {
                        want
                    };
                    let result = t
                        .registers
                        .iter()
                        .find(|wr| wr.register.bank == "a64.vector64")
                        .unwrap()
                        .value
                        .bits
                        & mask(w);
                    assert_eq!(result, expected);
                    let fpsr = t
                        .registers
                        .iter()
                        .find(|wr| wr.register.bank == "a64.fpsr")
                        .unwrap()
                        .value
                        .bits;
                    assert_eq!(fpsr, 0x08000000 | u64::from(invalid));
                }
            }
        }
    }
}
#[test]
fn trig_select_raw_nan_signs_selectors_and_lazy_control_sources() {
    let base = FORMS.iter().find(|x| x.1 == 4).unwrap().0;
    for (size, nan, normal, one) in [
        (1, 0xfe55, 0xbc00, 0x3c00),
        (2, 0xffc12345, 0xbf800000, 0x3f800000),
        (
            3,
            0xfff8123456789abc,
            0xbff0000000000000,
            0x3ff0000000000000,
        ),
    ] {
        let w = 8u8 << size;
        for ah in [false, true] {
            for a in [nan, normal, 0] {
                for selector in 0..4u64 {
                    let mut s = state();
                    s.control = u32::from(ah) * 2;
                    s.bit_only = true;
                    put(&mut s.z, 24, 0, w, a);
                    put(&mut s.z, 15, 0, w, selector);
                    let word = base | (size << 22) | 8 | (24 << 5) | (15 << 16);
                    let t = evaluate(&recipe(word, 128).unwrap(), &s).unwrap();
                    assert!(t
                        .registers
                        .iter()
                        .all(|wr| wr.register.bank == "a64.vector64"));
                    let want = if selector & 1 != 0 {
                        one | if selector & 2 != 0 {
                            1u64 << (w - 1)
                        } else {
                            0
                        }
                    } else if selector & 2 != 0 && !(ah && a == nan) {
                        a ^ (1u64 << (w - 1))
                    } else {
                        a
                    };
                    assert_eq!(t.registers[0].value.bits & mask(w), want);
                }
            }
        }
    }
}
#[test]
fn misc_context_guards_and_reserved_forms() {
    for &(base, kind) in FORMS {
        let word = base | (1 << 22);
        let mut s = state();
        s.sm = true;
        s.empty = true;
        if kind != 2 {
            assert_eq!(
                evaluate(&recipe(word, 128).unwrap(), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
        // FCLAMP size 00 belongs to the separate, allocated BFCLAMP
        // class in the public decoder. Check ownership at this helper.
        assert!(matches!(
            semantics::arm64_sve_float_misc::a64(base, 0x1000, 128)
                .unwrap()
                .support,
            Support::Unsupported(_)
        ));
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(word, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

#[test]
fn trig_select_unchanged_and_signed_one_paths_need_no_fp_context() {
    struct Bits {
        selector: u64,
        source: u64,
    }
    impl Machine for Bits {
        fn read_register(&self, r: Register) -> Value {
            Value::known(
                64,
                match r.bank {
                    "a64.svcr" => 0,
                    "a64.vector64" => {
                        if r.index / 32 == 15 {
                            self.selector
                        } else {
                            assert_eq!(self.selector & 1, 0, "signed one must not read source");
                            self.source
                        }
                    }
                    _ => panic!("unneeded context {r:?}"),
                },
            )
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!()
        }
    }
    let base = FORMS.iter().find(|x| x.1 == 4).unwrap().0;
    for size in 1..=3 {
        let w = 8u8 << size;
        for selector in [0, 1, 3] {
            let pattern =
                (0..64 / u16::from(w)).fold(0, |out, i| out | (selector << (i * u16::from(w))));
            let s = Bits {
                selector: pattern,
                source: u64::MAX,
            };
            let word = base | (size << 22) | 8 | (24 << 5) | (15 << 16);
            let t = evaluate(&recipe(word, 128).unwrap(), &s).unwrap();
            assert!(t
                .registers
                .iter()
                .all(|v| v.register.bank == "a64.vector64"));
        }
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8)] = &[
    (0x6410a000, 0), // faddqv_z_p_z_
    (0x6414a000, 3), // fmaxnmqv_z_p_z_
    (0x6416a000, 1), // fmaxqv_z_p_z_
    (0x6415a000, 4), // fminnmqv_z_p_z_
    (0x6417a000, 2), // fminqv_z_p_z_
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

fn identity(kind: u8, w: u8, ah: bool) -> u64 {
    if kind >= 3 {
        (match w {
            16 => 0x7e00,
            32 => 0x7fc00000,
            _ => 0x7ff8000000000000,
        }) | if ah { 1u64 << (w - 1) } else { 0 }
    } else {
        encode(
            if kind == 1 {
                f64::NEG_INFINITY
            } else if kind == 2 {
                f64::INFINITY
            } else {
                0.0
            },
            w,
            false,
        )
    }
}
fn pattern(bit: u16, which: u32) -> bool {
    match which {
        0 => false,
        1 => bit % 5 != 0,
        2 => bit % 7 == 0,
        _ => true,
    }
}
fn data(w: u8) -> [[u64; 32]; 32] {
    let mut z = [[0u64; 32]; 32];
    for n in 0..32u32 {
        for e in 0..2048 / u16::from(w) {
            put(
                &mut z,
                n,
                e,
                w,
                encode(f64::from(1 + (n + u32::from(e)) % 15), w, false),
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
    w: u8,
    vl: u16,
    which: u32,
    ah: bool,
) -> [[u64; 32]; 32] {
    let mut out = *before;
    for k in 0..vl / 64 {
        out[d as usize][usize::from(k)] = 0;
    }
    let per = 128 / u16::from(w);
    for e in 0..per {
        let mut values = Vec::new();
        for segment in 0..vl / 128 {
            let el = segment * per + e;
            if pattern(el * u16::from(w / 8), which) {
                values.push(decode(lane(before, n, el, w), w));
            }
        }
        let result = if values.is_empty() {
            identity(kind, w, ah)
        } else if vl == 128 {
            lane(before, n, e, w)
        } else {
            let number = if kind == 0 {
                values.into_iter().sum()
            } else if kind == 1 || kind == 3 {
                values.into_iter().fold(f64::NEG_INFINITY, f64::max)
            } else {
                values.into_iter().fold(f64::INFINITY, f64::min)
            };
            encode(number, w, false)
        };
        put(&mut out, d, e, w, result);
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_float_quad_reduce::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    p: [u64; 4],
    sm: bool,
    ah: bool,
    single: bool,
    empty: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => {
                    assert!(!self.empty);
                    self.z[usize::from(r.index / 32)][usize::from(r.index % 32)]
                }
                "a64.predicate64" => {
                    assert_eq!(r.index / 4, 3);
                    self.p[usize::from(r.index % 4)]
                }
                "a64.svcr" => u64::from(self.sm),
                "a64.sme_fa64" => 0,
                "a64.fpcr" => 0x04089f00 | if self.ah { 2 } else { 0 },
                "a64.fpsr" => {
                    assert!(!self.single);
                    0x08000000
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
        assert!(!self.single);
        assert_eq!(
            control.bits,
            if self.sm { 0x80000 } else { 0x89f00 } | if self.ah { 2 } else { 0 }
        );
        let a = decode(inputs[0].bits, f.width);
        let b = decode(inputs[1].bits, f.width);
        let number = match f.operation {
            FloatOperation::Add => a + b,
            FloatOperation::MinMax { minimum, .. } => {
                if minimum {
                    a.min(b)
                } else {
                    a.max(b)
                }
            }
            _ => panic!(),
        };
        let value = if number.is_nan() {
            identity(3, f.width, self.ah)
        } else {
            encode(number, f.width, false)
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, value),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
#[test]
fn all_float_quad_reductions_widths_lengths_masks_aliases_and_backing() {
    for &(base, kind) in FORMS {
        for size in 1..=3 {
            let w = 8u8 << size;
            for vl in [128, 256, 512, 1024, 2048] {
                for which in 0..4 {
                    for alias in [false, true] {
                        let d = 8;
                        let n = if alias { 8 } else { 24 };
                        let word = base | (size << 22) | d | (n << 5) | (3 << 10);
                        let mut s = State {
                            z: data(w),
                            p: [0; 4],
                            sm: alias,
                            ah: alias,
                            single: vl == 128,
                            empty: which == 0,
                        };
                        for bit in 0..vl / 8 {
                            if pattern(bit, which) {
                                s.p[usize::from(bit / 64)] |= 1 << (bit % 64);
                            }
                        }
                        let want = expected(&s.z, kind, d, n, w, vl, which, alias);
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
                                    "{word:08x} VL{vl} mask{which} Z{reg} chunk{k}"
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
fn reduction_single_segment_is_raw_transport_and_invalid_context_rejects() {
    for &(base, kind) in FORMS {
        for size in 1..=3 {
            let w = 8u8 << size;
            let mut s = State {
                z: [[u64::MAX; 32]; 32],
                p: [u64::MAX; 4],
                sm: false,
                ah: false,
                single: true,
                empty: false,
            };
            let word = base | (size << 22) | 8 | (24 << 5) | (3 << 10);
            let t = evaluate(&recipe(word, 128).unwrap(), &s).unwrap();
            assert!(t
                .registers
                .iter()
                .all(|x| x.register.bank == "a64.vector64" && x.value.bits == u64::MAX));
            s.empty = true;
            s.p = [0; 4];
            let t = evaluate(&recipe(word, 128).unwrap(), &s).unwrap();
            let id = identity(kind, w, false);
            for wr in t.registers {
                let mut packed = 0;
                for part in 0..64 / u16::from(w) {
                    packed |= id << (part * w as u16);
                }
                assert_eq!(wr.value.bits, packed);
            }
        }
        assert!(matches!(
            recipe(base, 128).unwrap().support,
            Support::Unsupported(_)
        ));
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(base | (1 << 22), vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

#[test]
fn high_subtree_trap_suppresses_low_sources_and_every_destination() {
    struct Fault(std::cell::RefCell<Vec<u16>>);
    impl Machine for Fault {
        fn read_register(&self, r: Register) -> Value {
            Value::known(
                64,
                match r.bank {
                    "a64.svcr" | "a64.fpcr" | "a64.fpsr" => 0,
                    "a64.predicate64" => u64::MAX,
                    "a64.vector64" => {
                        self.0.borrow_mut().push(r.index);
                        0x3f803f803f803f80
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
            _: &[Value],
            _: Value,
            _: Value,
        ) -> Result<Value, EvalError> {
            Ok(match f.projection {
                FloatProjection::Value => Value::known(f.width, 0),
                FloatProjection::Status => Value::known(32, 1),
                FloatProjection::Trapped => Value::known(1, 1),
            })
        }
    }
    for &(base, _) in FORMS {
        for size in 1..=3 {
            let s = Fault(std::cell::RefCell::new(Vec::new()));
            let r = recipe(base | (size << 22) | 8 | (24 << 5) | (3 << 10), 512).unwrap();
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
            assert_eq!(t.registers.len(), 1);
            assert_eq!(t.registers[0].register.bank, "a64.fpsr");
            assert_eq!(t.registers[0].value.bits, 1);
            let reads = s.0.borrow();
            assert!(!reads.is_empty());
            assert!(
                reads
                    .iter()
                    .all(|index| *index == 24 * 32 + 4 || *index == 24 * 32 + 6),
                "high subtree first: {reads:?}"
            );
        }
    }
}

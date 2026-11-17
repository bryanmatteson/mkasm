#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u8, u16)] = &[
    (0xc160e020, 5, 2),  //bfcvtn_z_mz2_
    (0xc160e000, 4, 2),  //bfcvt_z_mz2_
    (0xc1a0e001, 1, 2),  //fcvtl_mz2_z_
    (0xc120e020, 3, 2),  //fcvtn_z_mz2_
    (0x650d3000, 8, 2),  //fcvtzsn_z_mz2_
    (0xc121e000, 6, 2),  //fcvtzs_mz_z_2
    (0xc131e000, 6, 4),  //fcvtzs_mz_z_4
    (0x650d3400, 9, 2),  //fcvtzun_z_mz2_
    (0xc121e020, 7, 2),  //fcvtzu_mz_z_2
    (0xc131e020, 7, 4),  //fcvtzu_mz_z_4
    (0xc1a0e000, 0, 2),  //fcvt_mz2_z_
    (0xc120e000, 2, 2),  //fcvt_z_mz2_
    (0xc122e000, 10, 2), //scvtf_mz_z_2
    (0xc132e000, 10, 4), //scvtf_mz_z_4
    (0xc122e020, 11, 2), //ucvtf_mz_z_2
    (0xc132e020, 11, 4), //ucvtf_mz_z_4
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
    if v & 0x7fff == 0 {
        return if v & 0x8000 != 0 { -0.0 } else { 0.0 };
    }
    let bits = (((v as u32) & 0x8000) << 16)
        | (((((v as u32) >> 10) & 31) + 112) << 23)
        | (((v as u32) & 1023) << 13);
    f64::from(f32::from_bits(bits))
}
fn widths(kind: u8, size: u32) -> (u8, u8) {
    if kind <= 1 {
        (16, 32)
    } else if kind <= 5 {
        (32, 16)
    } else if kind == 8 || kind == 9 {
        let w = 8u8 << size;
        (w, w / 2)
    } else {
        (32, 32)
    }
}
fn make_data(kind: u8, src: u8) -> [[u64; 32]; 32] {
    let mut z = [[0u64; 32]; 32];
    for n in 0..32u32 {
        for chunk in 0..32usize {
            z[n as usize][chunk] = 0xa5c35e7912340000 ^ ((n as u64) << 12) ^ chunk as u64;
        }
        for e in 0..2048 / u16::from(src) {
            let num = 1 + ((n + u32::from(e)) % 15);
            let value = if kind == 10 {
                (i64::from(num) - 8) as u64 & mask(src)
            } else if kind == 11 {
                u64::from(num)
            } else {
                encode(f64::from(num), src, false)
            };
            put(&mut z, n, e, src, value);
        }
    }
    z
}
fn expected(
    before: &[[u64; 32]; 32],
    kind: u8,
    nreg: u16,
    d: u32,
    n: u32,
    len: u16,
    src: u8,
    dst: u8,
) -> [[u64; 32]; 32] {
    let mut out = *before;
    let convert = |reg: u32, e: u16| {
        let bits = lane(before, reg, e, src);
        if kind >= 6 && kind <= 9 {
            decode(bits, src) as u64 & mask(dst)
        } else if kind == 10 {
            encode(((bits as u32) as i32) as f64, dst, false)
        } else if kind == 11 {
            encode(bits as f64, dst, false)
        } else {
            encode(decode(bits, src), dst, kind == 4 || kind == 5)
        }
    };
    if kind <= 1 {
        for member in 0..2u16 {
            for e in 0..len / 32 {
                let se = if kind == 0 {
                    member * (len / 32) + e
                } else {
                    e * 2 + member
                };
                put(&mut out, d + u32::from(member), e, dst, convert(n, se));
            }
        }
    } else if kind <= 5 || kind == 8 || kind == 9 {
        for e in 0..len / u16::from(dst) {
            let (member, se) = if kind == 2 || kind == 4 {
                (e / (len / 32), e % (len / 32))
            } else {
                (e % 2, e / 2)
            };
            put(&mut out, d, e, dst, convert(n + u32::from(member), se));
        }
    } else {
        for member in 0..nreg {
            for e in 0..len / 32 {
                put(
                    &mut out,
                    d + u32::from(member),
                    e,
                    dst,
                    convert(n + u32::from(member), e),
                );
            }
        }
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_group_convert::a64(word, 0x1000, vl, vl)
}
struct State {
    z: [[u64; 32]; 32],
    sm: bool,
    fa64: bool,
    control: u32,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => u64::from(self.sm),
                "a64.sme_fa64" => u64::from(self.fa64),
                "a64.fpcr" => u64::from(self.control),
                "a64.fpsr" => 0x08000000,
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
        assert_eq!(
            control.bits,
            (self.control
                & !(1 << 26)
                & if self.sm && !self.fa64 {
                    !0x9f00
                } else {
                    u32::MAX
                }) as u64
        );
        assert_eq!(status.bits, 0x08000000);
        let input = inputs[0].bits;
        let result = match f.operation {
            FloatOperation::Convert { source_width, .. } => {
                encode(decode(input, source_width), f.width, false)
            }
            FloatOperation::ToBFloat16 => encode(decode(input, 32), 16, true),
            FloatOperation::ToInteger { source_width, .. } => {
                decode(input, source_width) as u64 & mask(f.width)
            }
            FloatOperation::FromInteger { signed, .. } => encode(
                if signed {
                    ((input as u32) as i32) as f64
                } else {
                    input as f64
                },
                f.width,
                false,
            ),
            _ => panic!("{f:?}"),
        };
        Ok(match f.projection {
            FloatProjection::Value => Value::known(f.width, result),
            FloatProjection::Status => status,
            FloatProjection::Trapped => Value::known(1, 0),
        })
    }
}
#[test]
fn all_group_conversions_lengths_layouts_aliases_and_complete_backing() {
    for &(base, kind, nreg) in FORMS {
        for size in if kind == 8 || kind == 9 { 1..=3 } else { 0..=0 } {
            let (src, dst) = widths(kind, size);
            for vl in [128, 256, 512, 1024, 2048] {
                for alias in 0..4 {
                    let (d, n) = match alias {
                        0 => (8, 24),
                        1 => (8, 8),
                        2 => {
                            if kind <= 1 {
                                (30, 31)
                            } else if kind <= 5 || kind == 8 || kind == 9 {
                                (31, 30)
                            } else if nreg == 4 {
                                (28, 28)
                            } else {
                                (30, 30)
                            }
                        }
                        _ => (0, if kind <= 1 { 1 } else { 4 }),
                    };
                    let word = base | (size << 22) | d | (n << 5);
                    let state = State {
                        z: make_data(kind, src),
                        sm: true,
                        fa64: alias % 2 == 1,
                        control: 0x04089f00,
                    };
                    let r = recipe(word, vl).unwrap();
                    r.validate().unwrap();
                    let t = evaluate(&r, &state).unwrap();
                    assert_eq!(t.trap, None);
                    let want = expected(&state.z, kind, nreg, d, n, vl, src, dst);
                    let mut out = state.z;
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
                        for chunk in 0..32 {
                            assert_eq!(
                                out[reg][chunk], want[reg][chunk],
                                "{word:08x} VL{vl} Z{reg} chunk{chunk}"
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn group_conversion_context_and_reserved_sizes() {
    for &(base, kind, _) in FORMS {
        for length in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(base, length).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        let state = State {
            z: [[0; 32]; 32],
            sm: false,
            fa64: false,
            control: 0,
        };
        if kind != 8 && kind != 9 {
            assert_eq!(
                evaluate(&recipe(base, 128).unwrap(), &state),
                Err(EvalError::UnsupportedContext)
            );
        } else {
            assert!(matches!(
                recipe(base, 128).unwrap().support,
                Support::Unsupported(_)
            ));
            assert!(evaluate(&recipe(base | (1 << 22), 128).unwrap(), &state).is_ok());
        }
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_bfloat_widening::a64(
        word,
        0x1000,
        vl,
        if word >> 31 != 0 {
            vl
        } else if vl == 128 {
            2048
        } else {
            128
        },
    )
}
const FORMS: &[(u32, u8, u16, bool)] = &[
    (0x64e08000, 2, 1, false), // bfmlalb_z_zzz_
    (0x64e04000, 3, 1, false), // bfmlalb_z_zzzi_
    (0x64e08400, 2, 1, false), // bfmlalt_z_zzz_
    (0x64e04400, 3, 1, false), // bfmlalt_z_zzzi_
    (0x0fc0f000, 1, 1, false), // BFMLAL_asimdelem_F
    (0x2ec0fc00, 0, 1, false), // BFMLAL_asimdsame2_F_
    (0xc1801010, 4, 1, false), // bfmlal_za_zzi_1
    (0xc1901010, 4, 2, false), // bfmlal_za_zzi_2xi
    (0xc1909010, 4, 4, false), // bfmlal_za_zzi_4xi
    (0xc1200c10, 5, 1, false), // bfmlal_za_zzv_1
    (0xc1200810, 5, 2, false), // bfmlal_za_zzv_2x1
    (0xc1300810, 5, 4, false), // bfmlal_za_zzv_4x1
    (0xc1a00810, 6, 2, false), // bfmlal_za_zzw_2x2
    (0xc1a10810, 6, 4, false), // bfmlal_za_zzw_4x4
    (0x64e0a000, 2, 1, true),  // bfmlslb_z_zzz_
    (0x64e06000, 3, 1, true),  // bfmlslb_z_zzzi_
    (0x64e0a400, 2, 1, true),  // bfmlslt_z_zzz_
    (0x64e06400, 3, 1, true),  // bfmlslt_z_zzzi_
    (0xc1801018, 4, 1, true),  // bfmlsl_za_zzi_1
    (0xc1901018, 4, 2, true),  // bfmlsl_za_zzi_2xi
    (0xc1909018, 4, 4, true),  // bfmlsl_za_zzi_4xi
    (0xc1200c18, 5, 1, true),  // bfmlsl_za_zzv_1
    (0xc1200818, 5, 2, true),  // bfmlsl_za_zzv_2x1
    (0xc1300818, 5, 4, true),  // bfmlsl_za_zzv_4x1
    (0xc1a00818, 6, 2, true),  // bfmlsl_za_zzw_2x2
    (0xc1a10818, 6, 4, true),  // bfmlsl_za_zzw_4x4
];
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    fpcr: u64,
    sm: u64,
    w: u32,
    calls: Vec<([u64; 3], bool)>,
    at: Cell<usize>,
    trap: Option<usize>,
    fa64: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.za64" => Value::known(
                64,
                self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.fpcr" => Value::known(32, self.fpcr),
            "a64.fpsr" => {
                assert_eq!(self.sm & 2, 0, "ZA must have no FPSR dependency");
                Value::known(32, 1 << 27)
            }
            "a64.svcr" => Value::known(64, self.sm),
            "a64.sme_fa64" => Value::known(1, u64::from(self.fa64)),
            "a64.gpr" => Value::known(64, u64::from(self.w)),
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("BF16 memory")
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = self.at.get();
        let (inputs, za) = self.calls[i];
        assert_eq!(f.operation, FloatOperation::BFloatWideningFused { za });
        assert_eq!(f.width, 32);
        assert_eq!(
            v,
            [
                Value::known(32, inputs[0]),
                Value::known(16, inputs[1]),
                Value::known(16, inputs[2])
            ]
        );
        let masked = self.sm & 1 != 0 && !self.fa64 && !za;
        // Fixed SIMD operations do not use the streaming exception suppression;
        // such fixtures run with SM=0, while all ZA operations suppress in contract.
        assert_eq!(
            control,
            Value::known(
                32,
                (self.fpcr & !(1 << 26)) & if masked { !0x9f00u64 } else { u64::MAX }
            )
        );
        assert_eq!(status, Value::known(32, if za { 0 } else { 1 << 27 }));
        Ok(match f.projection {
            FloatProjection::Value => {
                if za {
                    self.at.set(i + 1);
                }
                Value::known(32, 0x12340000 + i as u64)
            }
            FloatProjection::Status => {
                Value::known(32, (1 << 27) | u64::from(self.trap == Some(i)))
            }
            FloatProjection::Trapped => {
                self.at.set(i + 1);
                Value::known(1, u64::from(self.trap == Some(i)))
            }
        })
    }
}
fn lane(z: &[[u64; 32]], n: usize, e: u16, w: u16) -> u64 {
    let bit = e * w;
    (z[n][usize::from(bit / 64)] >> (bit % 64)) & if w == 32 { 0xffff_ffff } else { 0xffff }
}
fn source_word(
    base: u32,
    kind: u8,
    nreg: u16,
    n: u32,
    m: u32,
    d: u32,
    index: u32,
    offset: u32,
    top: u32,
) -> u32 {
    let n = n & if kind >= 4 && kind != 5 {
        32 - u32::from(nreg)
    } else {
        31
    };
    let m = m & if kind == 6 {
        32 - u32::from(nreg)
    } else if kind == 1 || kind >= 4 {
        15
    } else if kind == 3 {
        7
    } else {
        31
    };
    let mut word = base
        | (n << 5)
        | (m << 16)
        | if kind < 4 {
            d
        } else {
            offset & if nreg == 1 { 7 } else { 3 }
        };
    if kind < 2 {
        word |= top << 30;
    }
    if kind == 1 {
        word |= ((index >> 2) << 11) | ((index & 3) << 20);
    }
    if kind == 3 {
        word |= ((index >> 1) << 19) | ((index & 1) << 11);
    }
    if kind == 4 {
        word |= if nreg == 1 {
            ((index >> 2) << 15) | ((index & 3) << 10)
        } else {
            ((index >> 1) << 10) | ((index & 1) << 2)
        };
    }
    word
}
#[test]
fn every_widening_layout_alias_index_length_and_za_row_matches_primary() {
    for &(base, kind, nreg, subtract) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for (raw_n, raw_m, d, alt) in [
                (0, 0, 0, false),
                (31, 15, 31, true),
                (28, 7, 28, false),
                (28, 28, 15, true),
            ] {
                for index in 0..if kind == 1 || kind == 3 || kind == 4 {
                    8
                } else {
                    1
                } {
                    for top in 0..if kind < 2 { 2 } else { 1 } {
                        let offset = index % 8;
                        let word =
                            source_word(base, kind, nreg, raw_n, raw_m, d, index, offset, top);
                        let za = kind >= 4;
                        let fixed = kind < 2;
                        let mut s = State {
                            z: std::array::from_fn(|n| {
                                std::array::from_fn(|k| {
                                    0x7fc17f812347abcd_u64.rotate_left((n * 7 + k * 11) as u32)
                                })
                            }),
                            za: (0..256)
                                .map(|n| {
                                    std::array::from_fn(|k| {
                                        0x89abcdef01234567u64.rotate_left((n + k) as u32)
                                    })
                                })
                                .collect(),
                            fpcr: 0x9f01 | (1 << 26) | if alt { 2 } else { 0 },
                            sm: if za {
                                3
                            } else if fixed {
                                0
                            } else {
                                1
                            },
                            w: u32::MAX - 3,
                            calls: vec![],
                            at: Cell::new(0),
                            trap: None,
                            fa64: false,
                        };
                        let n = raw_n
                            & if za && kind != 5 {
                                32 - u32::from(nreg)
                            } else {
                                31
                            };
                        let m = raw_m
                            & if kind == 6 {
                                32 - u32::from(nreg)
                            } else if kind == 1 || za {
                                15
                            } else if kind == 3 {
                                7
                            } else {
                                31
                            };
                        let mut expected_z = s.z;
                        let mut expected_za = s.za.clone();
                        let stride = vl / 8 / nreg;
                        let row = (((u64::from(s.w)
                            + u64::from(offset & if nreg == 1 { 7 } else { 3 }) * 2)
                            % u64::from(stride))
                            & !1) as u16;
                        for group in 0..nreg {
                            for pair in 0..if za { 2 } else { 1 } {
                                let dst = usize::from(row + group * stride + pair);
                                for e in 0..if fixed { 4 } else { vl / 32 } {
                                    let left_index = 2 * e
                                        + if za {
                                            pair
                                        } else if fixed {
                                            top as u16
                                        } else {
                                            ((base >> 10) & 1) as u16
                                        };
                                    let right_index = if kind == 1 {
                                        index as u16
                                    } else if kind == 3 || kind == 4 {
                                        e / 4 * 8 + index as u16
                                    } else {
                                        left_index
                                    };
                                    let mut left = lane(
                                        &s.z,
                                        ((n + u32::from(group)) % 32) as usize,
                                        left_index,
                                        16,
                                    );
                                    if subtract
                                        && !(alt && left & 0x7f80 == 0x7f80 && left & 127 != 0)
                                    {
                                        left ^= 0x8000;
                                    }
                                    let right = lane(
                                        &s.z,
                                        (m + if kind == 6 { u32::from(group) } else { 0 }) as usize,
                                        right_index,
                                        16,
                                    );
                                    let old = if za {
                                        lane(&s.za, dst, e, 32)
                                    } else {
                                        lane(&s.z, d as usize, e, 32)
                                    };
                                    let tag = 0x12340000 + s.calls.len() as u64;
                                    let chunk = usize::from(e / 2);
                                    let shift = (e % 2) * 32;
                                    let slot = if za {
                                        &mut expected_za[dst][chunk]
                                    } else {
                                        &mut expected_z[d as usize][chunk]
                                    };
                                    *slot = (*slot & !(0xffffffffu64 << shift)) | (tag << shift);
                                    s.calls.push(([old, left, right], za));
                                }
                            }
                        }
                        if fixed {
                            for c in 2..vl / 64 {
                                expected_z[d as usize][usize::from(c)] = 0;
                            }
                        }
                        let r = recipe(word, vl).unwrap();
                        assert_eq!(r.support, Support::Full, "{word:08x}");
                        r.validate().unwrap();
                        let t = evaluate(&r, &s).unwrap();
                        assert_eq!(t.trap, None);
                        assert_eq!(s.at.get(), s.calls.len());
                        let mut actual_z = s.z;
                        let mut actual_za = s.za.clone();
                        for w in t.registers {
                            match w.register.bank {
                                "a64.vector64" => {
                                    actual_z[usize::from(w.register.index / 32)]
                                        [usize::from(w.register.index % 32)] = w.value.bits
                                }
                                "a64.za64" => {
                                    actual_za[usize::from(w.register.index / 32)]
                                        [usize::from(w.register.index % 32)] = w.value.bits
                                }
                                "a64.fpsr" => assert_eq!(w.value, Value::known(32, 1 << 27)),
                                _ => panic!(),
                            }
                        }
                        assert_eq!(actual_z, expected_z, "{word:08x} VL{vl}");
                        assert_eq!(actual_za, expected_za, "{word:08x} VL{vl}");
                        if !za && vl == 128 && raw_n == 0 && index == 0 && top == 0 {
                            for at in 0..s.calls.len() {
                                s.at.set(0);
                                s.trap = Some(at);
                                let t = evaluate(&r, &s).unwrap();
                                assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
                                assert_eq!(s.at.get(), at + 1);
                                assert!(t.registers.iter().all(|w| w.register.bank == "a64.fpsr"));
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn za_admission_precedes_sources() {
    for &(word, kind, _, _) in FORMS {
        if kind < 4 {
            continue;
        }
        for sm in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                fpcr: 0,
                sm,
                w: 0,
                calls: vec![],
                at: Cell::new(0),
                trap: None,
                fa64: false,
            };
            assert_eq!(
                evaluate(&recipe(word, 128).unwrap(), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
    }
}

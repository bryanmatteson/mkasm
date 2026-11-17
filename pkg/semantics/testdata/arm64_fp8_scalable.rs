#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fp8::scalable(
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
struct State {
    z: [[u64; 32]; 32],
    fpmr: u64,
    fpcr: u64,
    calls: Vec<(FloatOperation, u8, u64)>,
    at: Cell<usize>,
    trap: Option<usize>,
    sm: bool,
    sme2: bool,
    fa64: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
            "a64.svcr" => Value::known(64, u64::from(self.sm)),
            "a64.sme2" => Value::known(1, u64::from(self.sme2)),
            "a64.sme_fa64" => Value::known(1, u64::from(self.fa64)),
            "a64.fpmr" => Value::known(64, self.fpmr),
            "a64.fpcr" => Value::known(32, self.fpcr),
            "a64.fpsr" => Value::known(32, 1 << 27),
            "a64.gpr" => Value::known(64, u64::MAX),
            _ => panic!("unexpected register {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("FP8 memory")
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        inputs: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        let i = self.at.get();
        let (op, width, bits) = self.calls[i];
        assert_eq!(f.operation, op);
        assert_eq!(f.width, width);
        assert_eq!(f.environment, FloatEnvironment::A64);
        let FloatOperation::Fp8Convert { source_width, .. } = op else {
            panic!()
        };
        assert_eq!(
            inputs,
            [
                Value::known(source_width, bits),
                Value::known(64, self.fpmr)
            ]
        );
        assert_eq!(
            control,
            Value::known(
                32,
                if self.sm && !self.fa64 {
                    self.fpcr & !0x9f00
                } else {
                    self.fpcr
                }
            )
        );
        assert_eq!(status, Value::known(32, 1 << 27));
        Ok(match f.projection {
            FloatProjection::Value => Value::known(width, 0x40 + i as u64),
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

fn forms() -> Vec<(u32, u8, bool, bool)> {
    let mut result = vec![];
    for bf in [false, true] {
        for src2 in [false, true] {
            for top in [false, true] {
                result.push((
                    0x65083000
                        | (u32::from(bf) << 11)
                        | (u32::from(src2) << 10)
                        | (u32::from(top) << 16),
                    u8::from(top),
                    bf,
                    src2,
                ));
                result.push((
                    0xc126e000 | (u32::from(bf) << 22) | (u32::from(src2) << 23) | u32::from(top),
                    if top { 3 } else { 2 },
                    bf,
                    src2,
                ));
            }
        }
    }
    for (word, kind) in [
        (0x650a3000, 4),
        (0x650a3400, 5),
        (0x650a3c00, 6),
        (0xc124e000, 7),
        (0xc134e000, 8),
        (0xc134e020, 9),
    ] {
        result.push((word, kind, false, false));
    }
    result.push((0xc164e000, 7, true, false));
    result.push((0x650a3800, 4, true, false));
    result
}
#[test]
fn scalable_all_primary_layouts_register_boundaries_aliases_lengths_and_traps() {
    for vl in [128, 256, 512, 1024, 2048] {
        for (base, kind, bf, src2) in forms() {
            for raw_n in 0..32u32 {
                for raw_d in [0, 1, 2, 28, 30, 31u32] {
                    let n = raw_n
                        & if kind >= 8 {
                            28
                        } else if kind >= 4 {
                            30
                        } else {
                            31
                        };
                    let d = raw_d & if kind == 2 || kind == 3 { 30 } else { 31 };
                    let instruction = base | (n << 5) | d;
                    let width = if kind < 4 { 16 } else { 8 };
                    let source_width = if kind < 4 {
                        8
                    } else if kind == 4 || kind == 7 {
                        16
                    } else {
                        32
                    };
                    let sources = if kind < 4 {
                        1
                    } else if kind >= 8 {
                        4
                    } else {
                        2
                    };
                    let streaming = matches!(kind, 2 | 3 | 7 | 8 | 9);
                    let mut state = State {
                        z: std::array::from_fn(|r| {
                            std::array::from_fn(|k| {
                                0x8123456789abcdefu64.rotate_left((r * 5 + k * 7) as u32)
                            })
                        }),
                        fpcr: 0x9f03,
                        fpmr: 0x3faf7fc1ff,
                        calls: vec![],
                        at: Cell::new(0),
                        trap: None,
                        sm: streaming,
                        sme2: true,
                        fa64: false,
                    };
                    let mut expected = state.z;
                    let destinations = if kind == 2 || kind == 3 { 2 } else { 1 };
                    for register in 0..destinations {
                        for chunk in 0..32 {
                            expected[d as usize + register][usize::from(chunk)] =
                                if kind == 6 && chunk < vl / 64 {
                                    state.z[d as usize][usize::from(chunk)] & 0x00ff00ff00ff00ff
                                } else {
                                    0
                                };
                        }
                    }
                    // A mapping from each primary's result element to its source and position,
                    // independent of the recipe's output chunk construction.
                    let count = vl / u16::from(if kind < 2 { 16 } else { source_width });
                    for e in 0..count {
                        for source in 0..sources {
                            let source_bit = if kind < 2 {
                                e * 16 + if kind == 1 { 8 } else { 0 }
                            } else {
                                e * u16::from(source_width)
                            };
                            let input = (state.z[(n + u32::from(source)) as usize]
                                [usize::from(source_bit / 64)]
                                >> (source_bit % 64))
                                & mask(source_width);
                            let (target, element) = match kind {
                                0 | 1 => (d, e),
                                2 => (d + u32::from(e / (vl / 16)), e % (vl / 16)),
                                3 => (d + u32::from(e % 2), e / 2),
                                4 => (d, e * 2 + source),
                                5 => (d, e * 4 + source * 2),
                                6 => (d, e * 4 + source * 2 + 1),
                                7 | 8 => (d, source * count + e),
                                9 => (d, e * 4 + source),
                                _ => unreachable!(),
                            };
                            let bit = element * u16::from(width);
                            let tag = (0x40 + state.calls.len() as u64) & mask(width);
                            expected[target as usize][usize::from(bit / 64)] |= tag << (bit % 64);
                            state.calls.push((
                                FloatOperation::Fp8Convert {
                                    source_width,
                                    bfloat: bf,
                                    source2: src2,
                                },
                                width,
                                input,
                            ));
                        }
                    }
                    let r = recipe(instruction, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &state).unwrap();
                    assert_eq!(t.trap, None);
                    assert_eq!(state.at.get(), state.calls.len());
                    let mut actual = state.z;
                    for w in t.registers {
                        match w.register.bank {
                            "a64.vector64" => {
                                actual[usize::from(w.register.index / 32)]
                                    [usize::from(w.register.index % 32)] = w.value.bits
                            }
                            "a64.fpsr" => assert_eq!(w.value, Value::known(32, 1 << 27)),
                            _ => panic!(),
                        }
                    }
                    assert_eq!(actual, expected, "{instruction:08x} kind{kind} VL{vl}");
                    if raw_n == 0 && raw_d == 0 && vl == 128 {
                        for at in 0..state.calls.len() {
                            state.at.set(0);
                            state.trap = Some(at);
                            let t = evaluate(&r, &state).unwrap();
                            assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
                            assert_eq!(state.at.get(), at + 1);
                            assert!(
                                t.registers
                                    .iter()
                                    .all(|w| w.register.bank != "a64.vector64")
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn scalable_streaming_admission_precedes_fp_inputs() {
    for (base, kind, _, _) in forms() {
        let streaming = matches!(kind, 2 | 3 | 7 | 8 | 9);
        let state = State {
            z: [[0; 32]; 32],
            fpcr: 0,
            fpmr: 0,
            calls: vec![],
            at: Cell::new(0),
            trap: None,
            sm: !streaming,
            sme2: false,
            fa64: false,
        };
        let r = recipe(base, 128).unwrap();
        assert!(evaluate(&r, &state).is_err());
        assert_eq!(state.at.get(), 0);
    }
}

#[test]
fn ordinary_fp8_streaming_accepts_fa64_without_sme2() {
    for (word, kind, bfloat, source2) in forms()
        .into_iter()
        .filter(|(_, kind, _, _)| !matches!(*kind, 2 | 3 | 7 | 8 | 9))
    {
        let source_width = if kind < 4 {
            8
        } else if kind == 4 {
            16
        } else {
            32
        };
        let width = if kind < 4 { 16 } else { 8 };
        let count = 128
            / if kind < 2 {
                16
            } else {
                u16::from(source_width)
            };
        let sources = if kind < 4 { 1 } else { 2 };
        let state = State {
            z: [[0; 32]; 32],
            fpcr: 0,
            fpmr: 0,
            calls: (0..count * sources)
                .map(|_| {
                    (
                        FloatOperation::Fp8Convert {
                            source_width,
                            bfloat,
                            source2,
                        },
                        width,
                        0,
                    )
                })
                .collect(),
            at: Cell::new(0),
            trap: None,
            sm: true,
            sme2: false,
            fa64: true,
        };
        evaluate(&recipe(word, 128).unwrap(), &state).unwrap();
        assert_eq!(state.at.get(), state.calls.len());
    }
}

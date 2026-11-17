#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_fp8::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    fpmr: u64,
    fpcr: u64,
    calls: Vec<(FloatOperation, u8, u64)>,
    at: Cell<usize>,
    trap: Option<usize>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.vector64" => Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            ),
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
        assert_eq!(control, Value::known(32, self.fpcr));
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
#[test]
fn all_fixed_classes_parts_registers_aliases_lengths_and_precise_traps() {
    for vl in [128, 256, 512, 1024, 2048] {
        for form in 0..6 {
            for q in 0..2u32 {
                for d in 0..32u32 {
                    for n in 0..32u32 {
                        let m = if d % 2 == 0 { d } else { (n + 1) % 32 };
                        let widen = form < 4;
                        let source_width = if widen {
                            8
                        } else if form == 4 {
                            16
                        } else {
                            32
                        };
                        let width = if widen { 16 } else { 8 };
                        let elements = if widen {
                            8
                        } else if form == 4 {
                            if q == 1 {
                                8
                            } else {
                                4
                            }
                        } else {
                            4
                        };
                        let base = if widen {
                            0x2e217800 | ((form as u32) << 22)
                        } else if form == 4 {
                            0x0e40f400
                        } else {
                            0x0e00f400
                        };
                        let word =
                            base | (q << 30) | (n << 5) | d | if widen { 0 } else { m << 16 };
                        let op = FloatOperation::Fp8Convert {
                            source_width,
                            bfloat: widen && form >= 2,
                            source2: widen && form % 2 == 1,
                        };
                        let mut state = State {
                            z: std::array::from_fn(|r| {
                                std::array::from_fn(|k| {
                                    0x0123456789abcdefu64.rotate_left((r + k) as u32)
                                })
                            }),
                            fpcr: 0x7c80003,
                            fpmr: 0x3fafffc1ff,
                            calls: vec![],
                            at: Cell::new(0),
                            trap: None,
                        };
                        let mut expected = state.z;
                        for k in 0..vl / 64 {
                            expected[d as usize][usize::from(k)] = 0;
                        }
                        if form == 5 && q == 1 {
                            expected[d as usize][0] = state.z[d as usize][0];
                        }
                        for e in 0..elements {
                            for source in 0..if widen { 1 } else { 2 } {
                                let input_bit = e * u16::from(source_width)
                                    + if widen && q == 1 { 64 } else { 0 };
                                let bits = (state.z[if source == 0 { n } else { m } as usize]
                                    [usize::from(input_bit / 64)]
                                    >> (input_bit % 64))
                                    & mask(source_width);
                                let output_bit = if widen {
                                    e * 16
                                } else {
                                    (source * elements + e) * 8
                                        + if form == 5 && q == 1 { 64 } else { 0 }
                                };
                                expected[d as usize][usize::from(output_bit / 64)] |=
                                    (0x40 + state.calls.len() as u64) << (output_bit % 64);
                                state.calls.push((op, width, bits));
                            }
                        }
                        let r = recipe(word, vl).unwrap();
                        assert_eq!(r.support, Support::Full, "{word:08x}");
                        r.validate().unwrap();
                        let transition = evaluate(&r, &state).unwrap();
                        assert_eq!(transition.trap, None);
                        assert_eq!(state.at.get(), state.calls.len());
                        let mut actual = state.z;
                        for write in transition.registers {
                            match write.register.bank {
                                "a64.vector64" => {
                                    actual[usize::from(write.register.index / 32)]
                                        [usize::from(write.register.index % 32)] = write.value.bits
                                }
                                "a64.fpsr" => assert_eq!(write.value, Value::known(32, 1 << 27)),
                                _ => panic!(),
                            }
                        }
                        assert_eq!(actual, expected, "{word:08x} VL{vl}");
                        if d == n && d < 2 {
                            for at in 0..state.calls.len() {
                                state.at.set(0);
                                state.trap = Some(at);
                                let t = evaluate(&r, &state).unwrap();
                                assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
                                assert_eq!(state.at.get(), at + 1);
                                assert!(t
                                    .registers
                                    .iter()
                                    .all(|w| w.register.bank != "a64.vector64"));
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn fpmr_system_moves_res0_and_zero_register() {
    let s = State {
        z: [[0; 32]; 32],
        fpmr: 0x3f12abcdff,
        fpcr: 0,
        calls: vec![],
        at: Cell::new(0),
        trap: None,
    };
    for rt in [0, 17, 31] {
        for read in [false, true] {
            let r = recipe((if read { 0xd53b4440 } else { 0xd51b4440 }) | rt, 128).unwrap();
            r.validate().unwrap();
            let t = evaluate(&r, &s).unwrap();
            if read && rt == 31 {
                assert!(t.registers.is_empty());
            } else {
                assert_eq!(t.registers.len(), 1);
                assert_eq!(
                    t.registers[0].value,
                    Value::known(
                        64,
                        if read {
                            s.fpmr
                        } else if rt == 31 {
                            0
                        } else {
                            (63 << 32) | (255 << 24) | (127 << 16) | (3 << 14) | 511
                        }
                    )
                );
            }
        }
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_lsfe::a64(word, 0x1000, endian)
}
const CASES: &[(u32, u8, bool, AtomicFloatRmwOp, bool)] = &[
    (0x3c200000, 16, true, AtomicFloatRmwOp::Add, false), //LDBFADD_16
    (0x3ca00000, 16, true, AtomicFloatRmwOp::Add, false), //LDBFADDA_16
    (0x3ce00000, 16, true, AtomicFloatRmwOp::Add, false), //LDBFADDAL_16
    (0x3c600000, 16, true, AtomicFloatRmwOp::Add, false), //LDBFADDL_16
    (0x3c204000, 16, true, AtomicFloatRmwOp::Maximum, false), //LDBFMAX_16
    (0x3ca04000, 16, true, AtomicFloatRmwOp::Maximum, false), //LDBFMAXA_16
    (0x3ce04000, 16, true, AtomicFloatRmwOp::Maximum, false), //LDBFMAXAL_16
    (0x3c604000, 16, true, AtomicFloatRmwOp::Maximum, false), //LDBFMAXL_16
    (0x3c206000, 16, true, AtomicFloatRmwOp::MaximumNumber, false), //LDBFMAXNM_16
    (0x3ca06000, 16, true, AtomicFloatRmwOp::MaximumNumber, false), //LDBFMAXNMA_16
    (0x3ce06000, 16, true, AtomicFloatRmwOp::MaximumNumber, false), //LDBFMAXNMAL_16
    (0x3c606000, 16, true, AtomicFloatRmwOp::MaximumNumber, false), //LDBFMAXNML_16
    (0x3c205000, 16, true, AtomicFloatRmwOp::Minimum, false), //LDBFMIN_16
    (0x3ca05000, 16, true, AtomicFloatRmwOp::Minimum, false), //LDBFMINA_16
    (0x3ce05000, 16, true, AtomicFloatRmwOp::Minimum, false), //LDBFMINAL_16
    (0x3c605000, 16, true, AtomicFloatRmwOp::Minimum, false), //LDBFMINL_16
    (0x3c207000, 16, true, AtomicFloatRmwOp::MinimumNumber, false), //LDBFMINNM_16
    (0x3ca07000, 16, true, AtomicFloatRmwOp::MinimumNumber, false), //LDBFMINNMA_16
    (0x3ce07000, 16, true, AtomicFloatRmwOp::MinimumNumber, false), //LDBFMINNMAL_16
    (0x3c607000, 16, true, AtomicFloatRmwOp::MinimumNumber, false), //LDBFMINNML_16
    (0x7c200000, 16, false, AtomicFloatRmwOp::Add, false), //LDFADD_16
    (0x7ca00000, 16, false, AtomicFloatRmwOp::Add, false), //LDFADDA_16
    (0x7ce00000, 16, false, AtomicFloatRmwOp::Add, false), //LDFADDAL_16
    (0x7c600000, 16, false, AtomicFloatRmwOp::Add, false), //LDFADDL_16
    (0xbc200000, 32, false, AtomicFloatRmwOp::Add, false), //LDFADD_32
    (0xbca00000, 32, false, AtomicFloatRmwOp::Add, false), //LDFADDA_32
    (0xbce00000, 32, false, AtomicFloatRmwOp::Add, false), //LDFADDAL_32
    (0xbc600000, 32, false, AtomicFloatRmwOp::Add, false), //LDFADDL_32
    (0xfc200000, 64, false, AtomicFloatRmwOp::Add, false), //LDFADD_64
    (0xfca00000, 64, false, AtomicFloatRmwOp::Add, false), //LDFADDA_64
    (0xfce00000, 64, false, AtomicFloatRmwOp::Add, false), //LDFADDAL_64
    (0xfc600000, 64, false, AtomicFloatRmwOp::Add, false), //LDFADDL_64
    (0x7c204000, 16, false, AtomicFloatRmwOp::Maximum, false), //LDFMAX_16
    (0x7ca04000, 16, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXA_16
    (0x7ce04000, 16, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXAL_16
    (0x7c604000, 16, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXL_16
    (0xbc204000, 32, false, AtomicFloatRmwOp::Maximum, false), //LDFMAX_32
    (0xbca04000, 32, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXA_32
    (0xbce04000, 32, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXAL_32
    (0xbc604000, 32, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXL_32
    (0xfc204000, 64, false, AtomicFloatRmwOp::Maximum, false), //LDFMAX_64
    (0xfca04000, 64, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXA_64
    (0xfce04000, 64, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXAL_64
    (0xfc604000, 64, false, AtomicFloatRmwOp::Maximum, false), //LDFMAXL_64
    (
        0x7c206000,
        16,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNM_16
    (
        0x7ca06000,
        16,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMA_16
    (
        0x7ce06000,
        16,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMAL_16
    (
        0x7c606000,
        16,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNML_16
    (
        0xbc206000,
        32,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNM_32
    (
        0xbca06000,
        32,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMA_32
    (
        0xbce06000,
        32,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMAL_32
    (
        0xbc606000,
        32,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNML_32
    (
        0xfc206000,
        64,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNM_64
    (
        0xfca06000,
        64,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMA_64
    (
        0xfce06000,
        64,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNMAL_64
    (
        0xfc606000,
        64,
        false,
        AtomicFloatRmwOp::MaximumNumber,
        false,
    ), //LDFMAXNML_64
    (0x7c205000, 16, false, AtomicFloatRmwOp::Minimum, false), //LDFMIN_16
    (0x7ca05000, 16, false, AtomicFloatRmwOp::Minimum, false), //LDFMINA_16
    (0x7ce05000, 16, false, AtomicFloatRmwOp::Minimum, false), //LDFMINAL_16
    (0x7c605000, 16, false, AtomicFloatRmwOp::Minimum, false), //LDFMINL_16
    (0xbc205000, 32, false, AtomicFloatRmwOp::Minimum, false), //LDFMIN_32
    (0xbca05000, 32, false, AtomicFloatRmwOp::Minimum, false), //LDFMINA_32
    (0xbce05000, 32, false, AtomicFloatRmwOp::Minimum, false), //LDFMINAL_32
    (0xbc605000, 32, false, AtomicFloatRmwOp::Minimum, false), //LDFMINL_32
    (0xfc205000, 64, false, AtomicFloatRmwOp::Minimum, false), //LDFMIN_64
    (0xfca05000, 64, false, AtomicFloatRmwOp::Minimum, false), //LDFMINA_64
    (0xfce05000, 64, false, AtomicFloatRmwOp::Minimum, false), //LDFMINAL_64
    (0xfc605000, 64, false, AtomicFloatRmwOp::Minimum, false), //LDFMINL_64
    (
        0x7c207000,
        16,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNM_16
    (
        0x7ca07000,
        16,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMA_16
    (
        0x7ce07000,
        16,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMAL_16
    (
        0x7c607000,
        16,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNML_16
    (
        0xbc207000,
        32,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNM_32
    (
        0xbca07000,
        32,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMA_32
    (
        0xbce07000,
        32,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMAL_32
    (
        0xbc607000,
        32,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNML_32
    (
        0xfc207000,
        64,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNM_64
    (
        0xfca07000,
        64,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMA_64
    (
        0xfce07000,
        64,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNMAL_64
    (
        0xfc607000,
        64,
        false,
        AtomicFloatRmwOp::MinimumNumber,
        false,
    ), //LDFMINNML_64
    (0x3c20801f, 16, true, AtomicFloatRmwOp::Add, true),  //STBFADD_16
    (0x3c60801f, 16, true, AtomicFloatRmwOp::Add, true),  //STBFADDL_16
    (0x3c20c01f, 16, true, AtomicFloatRmwOp::Maximum, true), //STBFMAX_16
    (0x3c60c01f, 16, true, AtomicFloatRmwOp::Maximum, true), //STBFMAXL_16
    (0x3c20e01f, 16, true, AtomicFloatRmwOp::MaximumNumber, true), //STBFMAXNM_16
    (0x3c60e01f, 16, true, AtomicFloatRmwOp::MaximumNumber, true), //STBFMAXNML_16
    (0x3c20d01f, 16, true, AtomicFloatRmwOp::Minimum, true), //STBFMIN_16
    (0x3c60d01f, 16, true, AtomicFloatRmwOp::Minimum, true), //STBFMINL_16
    (0x3c20f01f, 16, true, AtomicFloatRmwOp::MinimumNumber, true), //STBFMINNM_16
    (0x3c60f01f, 16, true, AtomicFloatRmwOp::MinimumNumber, true), //STBFMINNML_16
    (0x7c20801f, 16, false, AtomicFloatRmwOp::Add, true), //STFADD_16
    (0x7c60801f, 16, false, AtomicFloatRmwOp::Add, true), //STFADDL_16
    (0xbc20801f, 32, false, AtomicFloatRmwOp::Add, true), //STFADD_32
    (0xbc60801f, 32, false, AtomicFloatRmwOp::Add, true), //STFADDL_32
    (0xfc20801f, 64, false, AtomicFloatRmwOp::Add, true), //STFADD_64
    (0xfc60801f, 64, false, AtomicFloatRmwOp::Add, true), //STFADDL_64
    (0x7c20c01f, 16, false, AtomicFloatRmwOp::Maximum, true), //STFMAX_16
    (0x7c60c01f, 16, false, AtomicFloatRmwOp::Maximum, true), //STFMAXL_16
    (0xbc20c01f, 32, false, AtomicFloatRmwOp::Maximum, true), //STFMAX_32
    (0xbc60c01f, 32, false, AtomicFloatRmwOp::Maximum, true), //STFMAXL_32
    (0xfc20c01f, 64, false, AtomicFloatRmwOp::Maximum, true), //STFMAX_64
    (0xfc60c01f, 64, false, AtomicFloatRmwOp::Maximum, true), //STFMAXL_64
    (0x7c20e01f, 16, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNM_16
    (0x7c60e01f, 16, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNML_16
    (0xbc20e01f, 32, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNM_32
    (0xbc60e01f, 32, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNML_32
    (0xfc20e01f, 64, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNM_64
    (0xfc60e01f, 64, false, AtomicFloatRmwOp::MaximumNumber, true), //STFMAXNML_64
    (0x7c20d01f, 16, false, AtomicFloatRmwOp::Minimum, true), //STFMIN_16
    (0x7c60d01f, 16, false, AtomicFloatRmwOp::Minimum, true), //STFMINL_16
    (0xbc20d01f, 32, false, AtomicFloatRmwOp::Minimum, true), //STFMIN_32
    (0xbc60d01f, 32, false, AtomicFloatRmwOp::Minimum, true), //STFMINL_32
    (0xfc20d01f, 64, false, AtomicFloatRmwOp::Minimum, true), //STFMIN_64
    (0xfc60d01f, 64, false, AtomicFloatRmwOp::Minimum, true), //STFMINL_64
    (0x7c20f01f, 16, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNM_16
    (0x7c60f01f, 16, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNML_16
    (0xbc20f01f, 32, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNM_32
    (0xbc60f01f, 32, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNML_32
    (0xfc20f01f, 64, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNM_64
    (0xfc60f01f, 64, false, AtomicFloatRmwOp::MinimumNumber, true), //STFMINNML_64
];

struct State {
    source: u64,
    old: u64,
    width: u8,
    fpcr: Option<u32>,
    sp: u64,
    alignment: Option<bool>,
    calls: Cell<usize>,
    floats: Cell<usize>,
    fault: bool,
    invalid_old: bool,
}
fn state(width: u8) -> State {
    State {
        source: 0x5a6b7c8d9eaf0123,
        old: 0x789abcdef0123456 & mask(width),
        width,
        fpcr: Some(0x07c09f03),
        sp: 0x2000,
        alignment: None,
        calls: Cell::new(0),
        floats: Cell::new(0),
        fault: false,
        invalid_old: false,
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => {
                assert_eq!(r.index, 2);
                Value::known(64, 0x2000)
            }
            "a64.sp" => Value::known(64, self.sp),
            "a64.sp_alignment_enforced" => self
                .alignment
                .map_or(Value::unknown(1), |p| Value::known(1, u64::from(p))),
            "a64.vector64" => {
                assert_eq!(r.index % 32, 0);
                Value::known(64, self.source)
            }
            "a64.fpcr" => self
                .fpcr
                .map_or(Value::unknown(32), |p| Value::known(32, u64::from(p))),
            other => panic!("unexpected {other}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("non-atomic load fallback")
    }
    fn evaluate_atomic(
        &self,
        r: &AtomicRequest,
        prior: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        self.calls.set(self.calls.get() + 1);
        assert!(prior.is_empty());
        assert_eq!(r.width, self.width);
        assert_eq!(r.scope, MemoryScope::System);
        assert!(matches!(
            r.kind,
            AtomicRequestKind::FloatingPointReadModifyWrite { .. }
        ));
        if self.fault {
            return Err(EvalError::Memory);
        }
        Ok(AtomicObservation {
            old: Some(if self.invalid_old {
                Value::unknown(r.width)
            } else {
                Value::known(r.width, self.old)
            }),
            store_succeeded: None,
            reservation_token: None,
            witness: 43,
        })
    }
    fn evaluate_float(
        &self,
        f: &FloatExpression,
        v: &[Value],
        control: Value,
        status: Value,
    ) -> Result<Value, EvalError> {
        self.floats.set(self.floats.get() + 1);
        assert_eq!(
            v,
            [
                Value::known(self.width, self.old),
                Value::known(self.width, self.source)
            ]
        );
        assert_eq!(f.environment, FloatEnvironment::A64);
        assert_eq!(f.projection, FloatProjection::Value);
        assert_eq!(status, Value::known(32, 0));
        let raw = self.fpcr.unwrap();
        let expected = (raw & !((1 << 26) | (1 << 25) | (1 << 24) | 3 | (0x1f << 8) | (1 << 15)))
            | (1 << 25)
            | if raw & ((1 << 24) | 1) != 0 {
                1 << 24
            } else {
                0
            };
        assert_eq!(control, Value::known(32, u64::from(expected)));
        Ok(Value::known(self.width, 0x123456789abcdef0))
    }
}
#[test]
fn every_encoding_order_format_endian_vector31_and_source_alias() {
    let mut count = 0;
    for &(base, width, bfloat, op, store) in CASES {
        for endian in [Endian::Little, Endian::Big] {
            for s in [0u32, 3, 31] {
                for t in if store { vec![31] } else { vec![0, 3, 31] } {
                    for n in [2u32, 31] {
                        let word = base | (s << 16) | (n << 5) | t;
                        let r = recipe(word, 128, endian).unwrap();
                        assert_eq!(r.support, Support::Full, "{word:08x}");
                        r.validate().unwrap();
                        assert_eq!(r.atomics.len(), 1);
                        assert!(r.wide_loads.is_empty());
                        let machine = state(width);
                        let transition = evaluate(&r, &machine).unwrap();
                        assert_eq!(machine.calls.get(), 1);
                        assert_eq!(machine.floats.get(), 1);
                        assert_eq!(transition.events, [OrderedEvent::Atomic(0)]);
                        assert!(transition.memory.is_empty());
                        assert_eq!(transition.trap, None);
                        assert_eq!(transition.next_pc, Value::known(64, 0x1004));
                        let atom = &transition.atomics[0];
                        let req = atom.request.as_ref().unwrap();
                        assert_eq!(req.address, 0x2000);
                        assert_eq!(req.endian, endian);
                        assert_eq!(
                            req.ordering,
                            match ((word >> 23) & 1, (word >> 22) & 1) {
                                (0, 0) => MemoryOrdering::Monotonic,
                                (1, 0) => MemoryOrdering::Acquire,
                                (0, 1) => MemoryOrdering::Release,
                                _ => MemoryOrdering::AcquireRelease,
                            }
                        );
                        assert_eq!(
                            req.kind,
                            AtomicRequestKind::FloatingPointReadModifyWrite {
                                operation: op,
                                bfloat,
                                value: Value::known(width, machine.source),
                                control: Value::known(32, u64::from(machine.fpcr.unwrap()))
                            }
                        );
                        assert_eq!(atom.stored, Some(Value::known(width, 0x123456789abcdef0)));
                        assert_eq!(atom.monitor, ExclusiveMonitorEffect::Preserved);
                        assert_eq!(transition.registers.len(), if store { 0 } else { 32 });
                        for w in &transition.registers {
                            assert_eq!(w.register.bank, "a64.vector64");
                            assert_eq!(w.register.index / 32, t as u16);
                            assert_eq!(
                                w.value,
                                Value::known(
                                    64,
                                    if w.register.index % 32 == 0 {
                                        machine.old
                                    } else {
                                        0
                                    }
                                )
                            );
                        }
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 3360);
}
#[test]
fn preflight_alignment_unknown_controls_and_memory_failure_have_no_partial_effect() {
    for &(base, width, _, _, _) in CASES {
        let r = recipe(base | (3 << 16) | (31 << 5), 128, Endian::Little).unwrap();
        let mut s = state(width);
        s.sp = 0x2001;
        s.alignment = Some(true);
        s.fpcr = None;
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::Protection));
        assert!(t.events.is_empty() && t.registers.is_empty() && t.atomics.is_empty());
        assert_eq!(s.calls.get(), 0);
        s.alignment = None;
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnknownCondition));
        assert_eq!(s.calls.get(), 0);
        s.alignment = Some(false);
        assert_eq!(evaluate(&r, &s), Err(EvalError::UnknownAtomicValue));
        assert_eq!(s.calls.get(), 0);
        s.fpcr = Some(0);
        s.fault = true;
        assert_eq!(evaluate(&r, &s), Err(EvalError::Memory));
        assert_eq!(s.calls.get(), 1);
        assert_eq!(s.floats.get(), 0);
        s.fault = false;
        s.invalid_old = true;
        assert_eq!(evaluate(&r, &s), Err(EvalError::InvalidAtomicOutcome));
        assert_eq!(s.floats.get(), 0);
    }
}
#[test]
fn every_fpcr_bit_is_explicit_and_only_mematomicfp_overrides_apply() {
    for &(base, width, _, _, _) in CASES {
        let r = recipe(base | (3 << 16) | (2 << 5), 128, Endian::Little).unwrap();
        for raw in std::iter::once(0)
            .chain((0..32).map(|b| 1 << b))
            .chain(std::iter::once(u32::MAX))
        {
            let mut s = state(width);
            s.fpcr = Some(raw);
            evaluate(&r, &s).unwrap();
        }
    }
}

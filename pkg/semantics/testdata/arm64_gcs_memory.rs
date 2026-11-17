#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_gcs_memory::a64(word, 0x1000, endian)
}
struct State {
    x: [u64; 31],
    sp: u64,
    present: bool,
    permitted: bool,
    el: u64,
    unpriv_priv: bool,
    sp_align: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => Value::known(64, self.x[r.index as usize]),
            "a64.sp" => Value::known(64, self.sp),
            "a64.gcs_present" => Value::known(1, self.present as u64),
            "a64.gcs_store_permitted" => Value::known(1, self.permitted as u64),
            "a64.current_el" => Value::known(2, self.el),
            "a64.unprivileged_is_privileged" => Value::known(1, self.unpriv_priv as u64),
            "a64.sp_alignment_enforced" => Value::known(1, self.sp_align as u64),
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("GCS store cannot read ordinary memory")
    }
}
fn state() -> State {
    State {
        x: std::array::from_fn(|n| 0x1000 + n as u64 * 16),
        sp: 0x2000,
        present: true,
        permitted: true,
        el: 0,
        unpriv_priv: false,
        sp_align: true,
    }
}
#[test]
fn every_store_source_base_alias_and_endian_preserves_gcs_identity() {
    for endian in [Endian::Little, Endian::Big] {
        for unpriv in [false, true] {
            for n in 0..32 {
                for t in 0..32 {
                    let word = 0xd91f0c00 | ((unpriv as u32) << 12) | n << 5 | t;
                    let s = state();
                    let r = recipe(word, 128, endian).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let out = evaluate(&r, &s).unwrap();
                    assert_eq!(out.trap, None);
                    assert!(out.registers.is_empty());
                    assert_eq!(out.events, [OrderedEvent::Store(0)]);
                    assert_eq!(out.memory.len(), 1);
                    let w = &out.memory[0];
                    assert!(w.guarded_control_stack);
                    assert_eq!(w.address, if n == 31 { s.sp } else { s.x[n as usize] });
                    assert_eq!(
                        w.value,
                        Value::known(64, if t == 31 { 0 } else { s.x[t as usize] })
                    );
                    assert_eq!(w.endian, endian);
                    assert_eq!(
                        w.privilege,
                        if unpriv {
                            MemoryPrivilege::AArch64Unprivileged
                        } else {
                            MemoryPrivilege::Current
                        }
                    );
                }
            }
        }
    }
}
#[test]
fn feature_store_permission_and_sp_checks_have_architectural_priority() {
    for present in [false, true] {
        for permitted in [false, true] {
            for el in 0..4 {
                for unpriv_priv in [false, true] {
                    for unpriv in [false, true] {
                        let mut s = state();
                        s.present = present;
                        s.permitted = permitted;
                        s.el = el;
                        s.unpriv_priv = unpriv_priv;
                        s.sp = 0x2001;
                        let r = recipe(
                            0xd91f0c00 | ((unpriv as u32) << 12) | 31 << 5,
                            128,
                            Endian::Little,
                        )
                        .unwrap();
                        let out = evaluate(&r, &s).unwrap();
                        let checked = !unpriv || el == 0 || unpriv_priv;
                        assert_eq!(
                            out.trap,
                            Some(if !present {
                                TrapKind::InvalidInstruction
                            } else if checked && !permitted {
                                TrapKind::AArch64GcsStore
                            } else {
                                TrapKind::Protection
                            })
                        );
                        assert!(out.memory.is_empty());
                        assert!(out.events.is_empty());
                    }
                }
            }
        }
    }
    let mut s = state();
    s.sp = 0x2008;
    s.sp_align = false;
    assert_eq!(
        evaluate(
            &recipe(0xd91f0c00 | 31 << 5, 128, Endian::Little).unwrap(),
            &s
        )
        .unwrap()
        .trap,
        None
    );
}
#[test]
fn gcs_synchronization_is_a_distinct_feature_gated_event() {
    for present in [false, true] {
        let mut s = state();
        s.present = present;
        let out = evaluate(&recipe(0xd503227f, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(
            out.events,
            if present {
                vec![OrderedEvent::Barrier(Barrier {
                    kind: BarrierKind::GuardedControlStackSynchronization,
                    scope: BarrierScope::System,
                    access: BarrierAccess::All,
                })]
            } else {
                vec![]
            }
        );
        assert!(out.memory.is_empty());
    }
    for word in [0xd91f0800, 0xd91f1800, 0xd91f2c00, 0xd91e0c00] {
        assert!(arm64_gcs_memory::a64(word, 0x1000, Endian::Little).is_none());
    }
}

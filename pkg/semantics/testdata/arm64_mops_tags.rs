#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::collections::BTreeMap;
include!("arm64_mops_tags_cases.rs");
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    arm64_mops::a64(word, 0x1000, endian).or_else(|| arm64_tags::a64(word, 0x1000, endian))
}
struct State {
    regs: [u64; 32],
    flags: [u64; 4],
    bytes: Vec<u8>,
    tags: BTreeMap<u64, u8>,
    el: u64,
    bs: u64,
    enabled: bool,
    missing: bool,
}
impl State {
    fn new() -> Self {
        Self {
            regs: [0; 32],
            flags: [0; 4],
            bytes: (0..256).map(|x| x as u8).collect(),
            tags: BTreeMap::new(),
            el: 1,
            bs: 6,
            enabled: true,
            missing: false,
        }
    }
    fn commit(&mut self, t: &Transition) {
        assert_eq!(t.trap, None);
        for ev in &t.events {
            match *ev {
                OrderedEvent::Store(i) => {
                    let w = &t.memory[i];
                    let a = (w.address & 0x00ff_ffff_ffff_ffff) as usize;
                    for j in 0..usize::from(w.value.width / 8) {
                        self.bytes[a + j] = (w.value.bits >> (j * 8)) as u8;
                    }
                }
                OrderedEvent::WideStore(i) => {
                    let w = &t.wide_memory[i];
                    let a = (w.address & 0x00ff_ffff_ffff_ffff) as usize;
                    let mut bytes = vec![];
                    for v in &w.chunks {
                        bytes.extend_from_slice(&v.bits.to_le_bytes()[..usize::from(v.width / 8)]);
                    }
                    if w.endian == Endian::Big {
                        bytes.reverse();
                    }
                    self.bytes[a..a + bytes.len()].copy_from_slice(&bytes);
                }
                OrderedEvent::AllocationTagStore(i) => {
                    let w = &t.allocation_tags[i];
                    self.tags
                        .insert(w.address & 0x00ff_ffff_ffff_ffff, w.tag.bits as u8);
                }
                _ => panic!("unexpected {ev:?}"),
            }
        }
        for w in &t.registers {
            match w.register.bank {
                "a64.gpr" => self.regs[w.register.index as usize] = w.value.bits,
                "a64.sp" => self.regs[31] = w.value.bits,
                "a64.nzcv" => self.flags[w.register.index as usize] = w.value.bits,
                _ => panic!("{w:?}"),
            }
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.gpr" => Value::known(64, self.regs[r.index as usize]),
            "a64.sp" => Value::known(64, self.regs[31]),
            "a64.nzcv" => Value::known(1, self.flags[r.index as usize]),
            "a64.mops_enabled" => {
                if self.missing {
                    Value::unknown(1)
                } else {
                    Value::known(1, self.enabled as u64)
                }
            }
            "a64.sp_alignment_enforced" => Value::known(1, 1),
            "a64.current_el" => Value::known(2, self.el),
            "a64.gmid_bs" | "a64.dczid_bs" if self.missing => Value::unknown(4),
            "a64.gmid_bs" => Value::known(4, self.bs),
            "a64.dczid_bs" => Value::known(4, 4),
            _ => panic!("unexpected {r:?}"),
        }
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        let a = (a & 0x00ff_ffff_ffff_ffff) as usize;
        let bytes = self
            .bytes
            .get(a..a + usize::from(w / 8))
            .ok_or(EvalError::MemoryFault(MemoryFaultKind::Translation))?;
        let mut value = 0;
        for (i, v) in bytes.iter().enumerate() {
            value |= u64::from(*v)
                << (8 * if e == Endian::Little {
                    i
                } else {
                    bytes.len() - 1 - i
                });
        }
        Ok(Value::known(w, value))
    }
    fn read_memory_for_access(
        &self,
        a: u64,
        w: u8,
        e: Endian,
        _p: MemoryPrivilege,
    ) -> Result<Value, EvalError> {
        self.read_memory(a, w, e)
    }
    fn read_allocation_tag(&self, a: u64, _p: MemoryPrivilege) -> Result<Value, EvalError> {
        Ok(Value::known(
            4,
            u64::from(*self.tags.get(&(a & 0x00ff_ffff_ffff_ffff)).unwrap_or(&0)),
        ))
    }
}
fn word(base: u32) -> u32 {
    base | (2 << 16) | (1 << 5)
}
#[test]
fn all_120_mops_forms_finish_copy_fill_overlap_and_tag_sequences() {
    assert_eq!(MOPS_GROUPS.len() * 3, 120);
    for &(group, set, tags, forward_only) in MOPS_GROUPS {
        for endian in [Endian::Little, Endian::Big] {
            for count in [0, 16, 32] {
                for overlap in [false, true] {
                    let mut s = State::new();
                    let dst = if overlap { 48 } else { 128 };
                    let src = 32;
                    s.regs[0] = (if tags { 0xau64 << 56 } else { 0 }) | dst;
                    s.regs[1] = count;
                    s.regs[2] = if set { 0xab } else { src };
                    let mut expected = s.bytes.clone();
                    if set {
                        expected[dst as usize..(dst + count) as usize].fill(0xab);
                    } else if forward_only {
                        for i in 0..count {
                            expected[(dst + i) as usize] = expected[(src + i) as usize];
                        }
                    } else {
                        expected.copy_within(src as usize..(src + count) as usize, dst as usize);
                    }
                    let p = recipe(word(group[0]), 128, endian).unwrap();
                    assert_eq!(p.support, Support::Full);
                    p.validate().unwrap();
                    let t = evaluate(&p, &s).unwrap();
                    assert!(t.events.is_empty());
                    s.commit(&t);
                    let mut iterations = 0;
                    loop {
                        let main = recipe(word(group[1]), 128, endian).unwrap();
                        let t = evaluate(&main, &s).unwrap();
                        s.commit(&t);
                        iterations += 1;
                        if t.next_pc.bits != 0x1000 {
                            break;
                        }
                        assert!(iterations < 34);
                    }
                    let e = recipe(word(group[2]), 128, endian).unwrap();
                    let t = evaluate(&e, &s).unwrap();
                    assert!(t.events.is_empty());
                    s.commit(&t);
                    assert_eq!(s.regs[1], 0, "{:08x}", group[0]);
                    assert_eq!(s.bytes, expected, "{:08x}", group[0]);
                    if tags {
                        for offset in (0..count).step_by(16) {
                            assert_eq!(s.tags.get(&(dst + offset)), Some(&10));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn mops_traps_clamping_empty_stages_and_privilege_are_explicit() {
    for &(group, set, tags, _) in MOPS_GROUPS {
        let mut s = State::new();
        s.regs[0] = 32;
        s.regs[1] = 16;
        s.regs[2] = 64;
        s.enabled = false;
        assert_eq!(
            evaluate(&recipe(word(group[0]), 128, Endian::Little).unwrap(), &s)
                .unwrap()
                .trap,
            Some(TrapKind::InvalidInstruction)
        );
        s.enabled = true;
        s.missing = true;
        assert!(matches!(
            evaluate(&recipe(word(group[0]), 128, Endian::Little).unwrap(), &s),
            Err(EvalError::UnknownCondition)
        ));
        s.missing = false;
        s.flags[2] = 0;
        let t = evaluate(&recipe(word(group[1]), 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::AArch64MopsWrongOption));
        let t = evaluate(&recipe(word(group[2]), 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::AArch64MopsParameters));
        s.regs[1] = 0;
        let t = evaluate(&recipe(word(group[1]), 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, None);
        assert!(t.events.is_empty());
        s.regs[1] = u64::MAX;
        let t = evaluate(&recipe(word(group[0]), 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, None);
        let n = t
            .registers
            .iter()
            .find(|w| w.register.bank == "a64.gpr" && w.register.index == 1)
            .unwrap()
            .value
            .bits;
        assert_eq!(
            n,
            if tags {
                0x7fff_ffff_ffff_fff0
            } else if set || group[0] & (1 << 26) == 0 {
                0x7fff_ffff_ffff_ffff
            } else {
                0x007f_ffff_ffff_ffff
            }
        );
        let bad = group[0] | (1 << 16) | (1 << 5);
        assert_eq!(
            evaluate(&recipe(bad, 128, Endian::Little).unwrap(), &s)
                .unwrap()
                .trap,
            Some(TrapKind::InvalidInstruction)
        );
    }
}
#[test]
fn all_tag_forms_store_only_metadata_preserve_pointer_bits_and_honor_bulk_indices() {
    assert_eq!(TAG_CASES.len(), 19);
    for &(base, id) in TAG_CASES {
        for endian in [Endian::Little, Endian::Big] {
            let mut s = State::new();
            s.regs[0] = 0xb123_4567_89ab_cdef;
            s.regs[1] = 0x0a00_0000_0000_0080;
            s.regs[2] = 0x1122_3344_5566_7788;
            s.regs[31] = 0x0c00_0000_0000_0080;
            for a in (0..256).step_by(16) {
                s.tags.insert(a, ((a / 16 + 3) % 16) as u8);
            }
            let w = base | (1 << 5) | if id.starts_with("STGP") { 2 << 10 } else { 0 };
            let r = recipe(w, 128, endian).unwrap();
            r.validate().unwrap();
            assert_eq!(r.support, Support::Full, "{id}");
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.trap, None, "{id}");
            if id.starts_with("LDG_") {
                let value = t
                    .registers
                    .iter()
                    .find(|w| w.register.index == 0)
                    .unwrap()
                    .value
                    .bits;
                assert_eq!(value, (s.regs[0] & !(15 << 56)) | (11 << 56));
                assert!(t.events.is_empty());
            } else if id.starts_with("LDGM") {
                assert_eq!(t.registers[0].value.bits, 0x210f_edcb_a987_6543);
            } else {
                assert!(!t.allocation_tags.is_empty(), "{id}");
                if id.starts_with("STG_") || id.starts_with("ST2G") {
                    assert!(t.memory.is_empty() && t.wide_memory.is_empty());
                }
                if id.starts_with("STGP") {
                    assert_eq!(t.allocation_tags[0].tag.bits, 10);
                }
            }
            if id.contains("bulk") {
                s.el = 0;
                s.missing = true; // EL0 traps before consuming privileged block controls.
                assert_eq!(
                    evaluate(&r, &s).unwrap().trap,
                    Some(TrapKind::InvalidInstruction)
                );
            }
        }
    }
}
#[test]
fn tag_callbacks_are_required_and_malformed_values_rejected() {
    struct None;
    impl Machine for None {
        fn read_register(&self, _: Register) -> Value {
            Value::known(64, 0)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("ordinary byte fallback")
        }
    }
    let mut r = Recipe::new(4, 64);
    r.write(
        register("a64.gpr", 0, 4, 64),
        WritePolicy::ZeroUpper,
        Expr::load_allocation_tag(Expr::constant(64, 0), MemoryPrivilege::Current),
    );
    assert_eq!(evaluate(&r, &None), Err(EvalError::Unsupported));
    struct Bad;
    impl Machine for Bad {
        fn read_register(&self, _: Register) -> Value {
            Value::known(64, 0)
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!()
        }
        fn read_allocation_tag(&self, _: u64, _: MemoryPrivilege) -> Result<Value, EvalError> {
            Ok(Value::known(8, 7))
        }
    }
    assert_eq!(evaluate(&r, &Bad), Err(EvalError::InvalidExpression));
}

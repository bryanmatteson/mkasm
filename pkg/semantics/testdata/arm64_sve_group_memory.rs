#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    counter: u16,
    sve: Option<u64>,
    sm: Option<u64>,
    base: Option<u64>,
    offset: Option<u64>,
    inputs: RefCell<Vec<Register>>,
    accesses: RefCell<Vec<(u64, u16, Endian)>>,
    fault: Option<u64>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|c| 0x9e3779b97f4a7c15u64.wrapping_mul((n * 32 + c + 1) as u64))
            }),
            counter: 0x8001,
            sve: Some(1),
            sm: Some(1),
            base: Some(0x4000),
            offset: Some(3),
            inputs: RefCell::new(vec![]),
            accesses: RefCell::new(vec![]),
            fault: None,
        }
    }
    fn memory(a: u64, w: u16, e: Endian) -> u64 {
        let mut v = 0;
        for i in 0..w / 8 {
            let at = a.wrapping_add(u64::from(i));
            let byte = (at.wrapping_mul(37) ^ (at >> 7) ^ 0xa5) & 255;
            let pos = if e == Endian::Little {
                i
            } else {
                w / 8 - 1 - i
            };
            v |= byte << (pos * 8);
        }
        v
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.inputs.borrow_mut().push(r);
        let (width, value) = match r.bank {
            "a64.sve2p1" => (1, self.sve),
            "a64.svcr" => (64, self.sm),
            "a64.sp" => (64, self.base),
            "a64.gpr" => (64, if r.index == 3 { self.offset } else { self.base }),
            "a64.predicate64" => {
                assert_eq!(r.index % 4, 0);
                (64, Some(u64::from(self.counter)))
            }
            "a64.vector64" => (
                64,
                Some(self.z[usize::from(r.index / 32)][usize::from(r.index % 32)]),
            ),
            _ => panic!("unexpected input {r:?}"),
        };
        value.map_or(Value::unknown(width), |v| Value::known(width, v))
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        self.accesses.borrow_mut().push((a, u16::from(w), e));
        if self
            .fault
            .is_some_and(|f| (0..w / 8).any(|i| a.wrapping_add(u64::from(i)) == f))
        {
            return Err(EvalError::Memory);
        }
        Ok(Value::known(w, Self::memory(a, u16::from(w), e)))
    }
    fn read_wide_memory(&self, a: u64, w: u16, e: Endian) -> Result<Vec<Value>, EvalError> {
        assert!(w <= 64);
        Ok(vec![self.read_memory(a, w as u8, e)?])
    }
}
fn recipe(word: u32, vl: u16, endian: Endian) -> Recipe {
    semantics::arm64_sme::a64_group_memory(word, 0x1000, vl, endian).unwrap()
}
fn checked(word: u32, vl: u16, endian: Endian, s: &State) -> Result<Transition, EvalError> {
    let r = recipe(word, vl, endian);
    if matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        assert_eq!(r.support, Support::Full);
        r.validate().unwrap();
    }
    evaluate(&r, s)
}
fn active(encoded: u16, byte: u16, vl: u16) -> bool {
    if encoded & 15 == 0 {
        return false;
    }
    let size = encoded.trailing_zeros().min(3);
    let step = 1 << size;
    if byte % step != 0 {
        return false;
    }
    let maxbit = (vl / 8 * 4).ilog2();
    let count = (encoded >> (size + 1)) & ((1 << (maxbit - size)) - 1);
    (byte / step < count) ^ (encoded & 0x8000 != 0)
}
// Independent primary diagram metadata is appended by the Go test, rather
// than derived from the runtime's encoding masks or dispatch.
#[test]
fn all_primary_group_classes_execute_full_state_offsets_order_and_endian() {
    let mut cases = 0;
    for &(base, name, width, count, strided, immediate, store) in GROUP_CLASSES {
        for vl in [128u16, 256, 512, 1024, 2048] {
            for endian in [Endian::Little, Endian::Big] {
                for high in [false, true] {
                    for invert in [false, true] {
                        let mut s = State::new();
                        // Select a prefix crossing the register boundary and ignore encoded
                        // count bits above maxbit, independently of requested memory width.
                        let k = (width / 8).trailing_zeros();
                        let elements = vl / width;
                        s.counter = ((elements + 1) << (k + 1))
                            | (1 << k)
                            | (u16::from(invert) << 15)
                            | 0x4000;
                        if strided {
                            s.sve = None;
                        } else {
                            s.sm = None;
                        }
                        let (low, first, stride) = if strided {
                            if high {
                                (
                                    if count == 2 { 23 } else { 19 },
                                    if count == 2 { 23 } else { 19 },
                                    16 / count,
                                )
                            } else {
                                (0, 0, 16 / count)
                            }
                        } else {
                            (
                                if high { 32 - count } else { 0 },
                                if high { 32 - count } else { 0 },
                                1,
                            )
                        };
                        let pn: u32 = if high { 7 } else { 0 };
                        let selector: u32 = if immediate {
                            if high {
                                8
                            } else {
                                7
                            }
                        } else {
                            3
                        };
                        let word = base
                            | (u32::from(selector) << 16)
                            | (u32::from(pn) << 10)
                            | (2 << 5)
                            | u32::from(low);
                        let start = if immediate {
                            0x4000u64.wrapping_add(
                                (if high { -8i64 } else { 7 })
                                    .wrapping_mul(i64::from(count * vl / 8))
                                    as u64,
                            )
                        } else {
                            0x4000 + 3 * u64::from(width / 8)
                        };
                        let t = checked(word, vl, endian, &s)
                            .unwrap_or_else(|e| panic!("{name} {word:08x} VL{vl}: {e:?}"));
                        assert_eq!(t.next_pc, Value::known(64, 0x1004));
                        assert!(t.trap.is_none());
                        assert!(t.atomics.is_empty());
                        let mut expected = s.z;
                        let mut accesses = vec![];
                        let mut stores = vec![];
                        for member in 0..count {
                            let vector = first + member * stride;
                            if !store {
                                expected[usize::from(vector)] = [0; 32];
                            }
                            for lane in 0..elements {
                                let index = member * elements + lane;
                                let a = start.wrapping_add(u64::from(index * width / 8));
                                let selected = active(s.counter, index * width / 8, vl);
                                let bit = lane * width;
                                let chunk = usize::from(bit / 64);
                                let offset = bit % 64;
                                if selected {
                                    if store {
                                        let v = s.z[usize::from(vector)][chunk] >> offset;
                                        stores.push((
                                            a,
                                            width,
                                            endian,
                                            Value::known(width as u8, v),
                                        ));
                                    } else {
                                        accesses.push((a, width, endian));
                                        expected[usize::from(vector)][chunk] |=
                                            State::memory(a, width, endian) << offset;
                                    }
                                }
                            }
                        }
                        let mut actual = s.z;
                        for wr in &t.registers {
                            assert_eq!(wr.register.bank, "a64.vector64");
                            assert!(wr.value.is_known());
                            actual[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits;
                        }
                        assert_eq!(actual, expected, "{name} {word:08x} VL{vl}");
                        assert_eq!(*s.accesses.borrow(), accesses);
                        assert!(t.wide_memory.is_empty());
                        let written = t
                            .events
                            .iter()
                            .filter_map(|event| {
                                if let OrderedEvent::Store(i) = *event {
                                    let w = &t.memory[i];
                                    Some((w.address, u16::from(w.value.width), w.endian, w.value))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(written, stores, "{name}");
                        assert!(s
                            .inputs
                            .borrow()
                            .iter()
                            .all(|r| r.bank != "a64.gpr" || r.index == 2 || r.index == 3));
                        cases += 1;
                    }
                }
            }
        }
    }
    eprintln!("{cases} primary grouped memory states");
}
#[test]
fn all_counter_tags_counts_inversion_and_reserved_encodings_expand_independently() {
    for vl in [128u16, 256, 512, 1024, 2048] {
        for width in [8u16, 16, 32, 64] {
            for tag in [0u16, 1, 2, 4, 8] {
                for invert in [false, true] {
                    for count in [0u16, 1, 3, 31, 127, 1023] {
                        let mut s = State::new();
                        let k = if tag == 0 { 0 } else { tag.trailing_zeros() };
                        s.counter = if tag == 0 {
                            0
                        } else {
                            (count << (k + 1)) | tag
                        };
                        s.counter |= u16::from(invert) << 15;
                        let word = 0xa0408000 | ((width / 8).trailing_zeros() << 13) | (2 << 5);
                        checked(word, vl, Endian::Little, &s).unwrap();
                        let expected = (0..4 * vl / width)
                            .filter(|i| active(s.counter, i * width / 8, vl))
                            .map(|i| (0x4000 + u64::from(i * width / 8), width, Endian::Little))
                            .collect::<Vec<_>>();
                        assert_eq!(
                            *s.accesses.borrow(),
                            expected,
                            "VL{vl} W{width} {:04x}",
                            s.counter
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn empty_masks_suppress_unavailable_sp_offsets_and_store_values() {
    for &(base, name, _, _, strided, immediate, _) in GROUP_CLASSES {
        let mut s = State::new();
        s.counter = 0;
        s.base = None;
        s.offset = None;
        if strided {
            s.sve = None;
        } else {
            s.sm = None;
        }
        let word = base | (31 << 5) | if immediate { 15 << 16 } else { 3 << 16 };
        let t = checked(word, 128, Endian::Big, &s).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(s.accesses.borrow().is_empty());
        assert!(t.memory.is_empty());
        assert!(s
            .inputs
            .borrow()
            .iter()
            .all(|r| !matches!(r.bank, "a64.gpr" | "a64.sp" | "a64.vector64")));
    }
}
#[test]
fn admission_alignment_faults_and_invalid_lengths_precede_publication() {
    for &(base, name, width, _, strided, immediate, store) in GROUP_CLASSES {
        let word = base | (31 << 5) | if immediate { 0 } else { 31 << 16 };
        let mut s = State::new();
        s.base = Some(0x4001);
        assert_eq!(
            checked(word, 128, Endian::Little, &s),
            Err(EvalError::UnsupportedContext),
            "{name}"
        );
        assert!(s.accesses.borrow().is_empty());
        s.base = Some(u64::MAX - 15);
        s.counter = 0x8001;
        if !store {
            s.fault = Some(u64::MAX - 15 + u64::from(width / 8));
            assert_eq!(
                checked(word, 128, Endian::Little, &s),
                Err(EvalError::Memory)
            );
            assert_eq!(s.accesses.borrow().len(), 2);
            s.accesses.borrow_mut().clear();
        }
        s.sve = Some(0);
        s.sm = Some(0);
        assert_eq!(
            checked(word, 128, Endian::Little, &s),
            Err(EvalError::UnsupportedContext)
        );
        assert!(s.accesses.borrow().is_empty());
        assert!(!s.inputs.borrow().is_empty());
        if !strided {
            s.sve = Some(1);
            s.sm = None;
            s.base = Some(0x4000);
            s.fault = None;
            checked(word, 128, Endian::Little, &s).unwrap();
        }
    }
    for vl in [0, 64, 384, 4096] {
        let s = State::new();
        assert!(matches!(checked(0xa0400000, vl, Endian::Little, &s), Err(EvalError::UnsupportedContext | EvalError::Unsupported)));
        assert!(s.inputs.borrow().is_empty());
    }
}

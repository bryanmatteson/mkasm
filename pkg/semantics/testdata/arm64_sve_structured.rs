#[allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::HashMap};
// Base words and decoded parameters come independently from primary diagrams.
include!("arm64_sve_structured_cases.rs");
fn recipe(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_structured::a64(word, address, endian, vl)
}
fn byte(address: u64) -> u8 {
    let x = address.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(17);
    (x ^ (x >> 11) ^ (x >> 37)) as u8
}
fn vector(n: u16, chunk: u16) -> u64 {
    (u64::from(n) + 1).wrapping_mul(0x0193b54769abcdef)
        ^ u64::from(chunk).wrapping_mul(0x8123456701234567)
}
fn lane(n: u16, e: u16, w: u8) -> u64 {
    let bit = e * u16::from(w);
    let m = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
    vector(n, bit / 64) >> (bit % 64) & m
}
fn active(e: u16, mode: u8) -> bool {
    match mode {
        0 => e % 3 != 1,
        1 => true,
        _ => false,
    }
}
struct State {
    vl: u16,
    width: u16,
    base: u64,
    offset: u64,
    base_index: u16,
    offset_index: u16,
    mask: u8,
    forbid_addresses: bool,
    forbid_vectors: bool,
    reads: RefCell<Vec<(u64, u16, Endian)>>,
    registers: RefCell<Vec<Register>>,
    fault: Option<usize>,
}
impl State {
    fn new(vl: u16, width: u16) -> Self {
        Self {
            vl,
            width,
            base: 0x1000,
            offset: 3,
            base_index: 1,
            offset_index: 2,
            mask: 0,
            forbid_addresses: false,
            forbid_vectors: false,
            reads: RefCell::new(vec![]),
            registers: RefCell::new(vec![]),
            fault: None,
        }
    }
    fn x(&self, n: u16) -> u64 {
        if n == self.base_index {
            self.base
        } else if n == self.offset_index {
            self.offset
        } else {
            panic!("unexpected GPR{n}")
        }
    }
    fn observe(&self, address: u64, width: u16, endian: Endian) -> Result<Vec<Value>, EvalError> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((address, width, endian));
        if self.fault == Some(index) {
            return Err(EvalError::Memory);
        }
        let mut chunks = vec![0u64; width as usize / 64 + usize::from(width % 64 != 0)];
        for i in 0..width / 8 {
            let position = if endian == Endian::Little {
                i
            } else {
                width / 8 - 1 - i
            };
            chunks[(position / 8) as usize] |=
                u64::from(byte(address.wrapping_add(u64::from(i)))) << (position % 8 * 8);
        }
        Ok(chunks
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                Value::known(
                    (width - usize::min(i * 64, width as usize) as u16).min(64) as u8,
                    v,
                )
            })
            .collect())
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.registers.borrow_mut().push(r);
        Value::known(
            64,
            match r.bank {
                "a64.gpr" => {
                    assert!(!self.forbid_addresses, "inactive GPR address read");
                    self.x(r.index)
                }
                "a64.sp" => {
                    assert!(!self.forbid_addresses, "inactive SP address read");
                    self.base
                }
                "a64.vector64" => {
                    assert!(!self.forbid_vectors, "inactive vector source read");
                    vector(r.index / 32, r.index % 32)
                }
                "a64.predicate64" => {
                    assert!(r.index / 4 <= 7);
                    let mut v = 0;
                    for bit in 0..64 {
                        let global = (r.index % 4) * 64 + bit;
                        if global < self.vl / 8 {
                            let lane = global / (self.width / 8);
                            if (global % (self.width / 8) == 0 && active(lane, self.mask))
                                || (self.mask == 3 && global % (self.width / 8) != 0)
                            {
                                v |= 1 << bit;
                            }
                        }
                    }
                    v
                }
                _ => panic!("ordinary structured SVE must not read context/flags: {r:?}"),
            },
        )
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        Ok(self.observe(a, u16::from(w), e)?[0])
    }
    fn read_wide_memory(&self, a: u64, w: u16, e: Endian) -> Result<Vec<Value>, EvalError> {
        assert_eq!(w, 128, "Q transfer was widened or split");
        self.observe(a, w, e)
    }
}
fn start(s: &State, count: u16, immediate: bool, imm: i8) -> u64 {
    let offset = if immediate {
        (i64::from(imm) * i64::from(count) * i64::from(s.vl / 8)) as u64
    } else {
        s.x(s.offset_index).wrapping_mul(u64::from(s.width / 8))
    };
    s.base.wrapping_add(offset)
}
fn numerical(
    baseword: u32,
    width: u16,
    count: u16,
    store: bool,
    immediate: bool,
    vl: u16,
    endian: Endian,
    first: u16,
    imm: i8,
    base: u64,
    offset: u64,
) {
    let mut s = State::new(vl, width);
    s.base = base;
    s.offset = offset;
    let word = baseword
        | (u32::from(first))
        | (1 << 5)
        | if immediate {
            ((imm as u32) & 15) << 16
        } else {
            2 << 16
        };
    let r = recipe(word, u64::MAX - 3, endian, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, &s).unwrap();
    assert_eq!(t.next_pc.bits, 0);
    assert_eq!(t.trap, None);
    assert!(t.atomics.is_empty());
    let addr = start(&s, count, immediate, imm);
    let mut expected_accesses = vec![];
    for e in 0..vl / width {
        if active(e, s.mask) {
            for member in 0..count {
                expected_accesses.push((
                    addr.wrapping_add(u64::from((e * count + member) * (width / 8))),
                    width,
                    endian,
                ));
            }
        }
    }
    if store {
        assert!(s.reads.borrow().is_empty());
        assert!(t.registers.is_empty());
        assert_eq!(t.events.len(), expected_accesses.len());
        let mut committed = HashMap::new();
        for (i, event) in t.events.iter().enumerate() {
            let (address, w, chunks, order) = match event {
                OrderedEvent::Store(j) => {
                    let m = &t.memory[*j];
                    (m.address, u16::from(m.value.width), vec![m.value], m.endian)
                }
                OrderedEvent::WideStore(j) => {
                    let m = &t.wide_memory[*j];
                    (m.address, m.width, m.chunks.clone(), m.endian)
                }
                other => panic!("unexpected event {other:?}"),
            };
            assert_eq!((address, w, order), expected_accesses[i]);
            for byte_index in 0..w / 8 {
                let numeric = if order == Endian::Little {
                    byte_index
                } else {
                    w / 8 - 1 - byte_index
                };
                let value = (chunks[(numeric / 8) as usize].bits >> (numeric % 8 * 8)) as u8;
                committed.insert(address.wrapping_add(u64::from(byte_index)), value);
            }
        }
        for e in 0..vl / width {
            if active(e, s.mask) {
                for member in 0..count {
                    let n = (first + member) % 32;
                    let address = addr.wrapping_add(u64::from((e * count + member) * (width / 8)));
                    for i in 0..width / 8 {
                        let numeric = if endian == Endian::Little {
                            i
                        } else {
                            width / 8 - 1 - i
                        };
                        let value = if width == 128 {
                            vector(n, e * 2 + numeric / 8) >> (numeric % 8 * 8)
                        } else {
                            lane(n, e, width as u8) >> (numeric * 8)
                        };
                        assert_eq!(
                            committed[&address.wrapping_add(u64::from(i))],
                            value as u8,
                            "{word:08x} VL{vl} member{member} e{e}"
                        );
                    }
                }
            }
        }
    } else {
        assert_eq!(*s.reads.borrow(), expected_accesses, "{word:08x} VL{vl}");
        assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.events.is_empty());
        assert_eq!(t.registers.len(), usize::from(count * vl / 64));
        for member in 0..count {
            let n = (first + member) % 32;
            for chunk in 0..vl / 64 {
                let actual = t
                    .registers
                    .iter()
                    .find(|w| {
                        w.register
                            == Register {
                                bank: "a64.vector64",
                                index: n * 32 + chunk,
                            }
                    })
                    .unwrap();
                let mut wanted = 0;
                for i in 0..8u16 {
                    let bit = chunk * 64 + i * 8;
                    let e = bit / width;
                    let within = (bit % width) / 8;
                    let expected =
                        if active(e, s.mask) {
                            let numeric = if endian == Endian::Little {
                                within
                            } else {
                                width / 8 - 1 - within
                            };
                            byte(addr.wrapping_add(u64::from(
                                (e * count + member) * (width / 8) + numeric,
                            )))
                        } else {
                            0
                        };
                    wanted |= u64::from(expected) << (i * 8);
                }
                assert_eq!(
                    actual.value,
                    Value::known(64, wanted),
                    "{word:08x} VL{vl} Z{n} chunk{chunk}"
                );
            }
        }
    }
    assert!(s.registers.borrow().iter().all(|r| !matches!(
        r.bank,
        "a64.nzcv" | "a64.fpsr" | "a64.svcr" | "a64.sme_fa64"
    )));
}
#[test]
fn all_primary_forms_interleave_wrap_endian_predicate_and_address_wrap() {
    for &(word, width, count, store, immediate) in CASES {
        for vl in [128, 256, 512, 1024, 2048] {
            for endian in [Endian::Little, Endian::Big] {
                for first in [0, 29, 30, 31] {
                    numerical(
                        word, width, count, store, immediate, vl, endian, first, -3, 0x1000, 3,
                    );
                }
            }
        }
    }
    for &(word, width, count, store, immediate) in CASES {
        for endian in [Endian::Little, Endian::Big] {
            for imm in [-8, -1, 0, 7] {
                numerical(
                    word,
                    width,
                    count,
                    store,
                    immediate,
                    128,
                    endian,
                    31,
                    imm,
                    u64::MAX - 15,
                    u64::MAX - 1,
                );
            }
        }
    }
}
#[test]
fn every_signed_immediate_scaled_by_entire_group_at_all_lengths() {
    for &(word, width, count, store, immediate) in CASES {
        if !immediate {
            continue;
        }
        for vl in [128, 256, 512, 1024, 2048] {
            for imm in -8..8 {
                numerical(
                    word,
                    width,
                    count,
                    store,
                    true,
                    vl,
                    Endian::Little,
                    31,
                    imm,
                    0x1000,
                    3,
                );
            }
        }
    }
}
#[test]
fn inactive_lanes_suppress_addresses_sources_and_q_backend_padding_bits_do_not_activate() {
    for &(word, width, _, store, immediate) in CASES {
        for vl in [128, 256, 512, 1024, 2048] {
            for mask in [2, 3] {
                let mut s = State::new(vl, width);
                s.mask = mask;
                s.forbid_addresses = true;
                s.forbid_vectors = true;
                let word = word | (31 << 5) | 31 | if immediate { 0 } else { 2 << 16 };
                let r = recipe(word, 0, Endian::Big, vl).unwrap();
                let t = evaluate(&r, &s).unwrap();
                assert!(s.reads.borrow().is_empty());
                assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.events.is_empty());
                if !store {
                    assert!(t.registers.iter().all(|r| r.value == Value::known(64, 0)));
                }
            }
        }
    }
}
#[test]
fn sp_alignment_qualification_precedes_any_memory_and_sources() {
    for &(word, width, _, _, immediate) in CASES {
        let mut s = State::new(128, width);
        s.base = 0x1004;
        s.mask = 1;
        s.forbid_vectors = true;
        let r = recipe(
            word | (31 << 5) | if immediate { 0 } else { 2 << 16 },
            0,
            Endian::Little,
            128,
        )
        .unwrap();
        assert!(matches!(
            evaluate(&r, &s),
            Err(EvalError::UnsupportedContext)
        ));
        assert!(s.reads.borrow().is_empty());
        assert!(s
            .registers
            .borrow()
            .iter()
            .all(|r| matches!(r.bank, "a64.predicate64" | "a64.sp")));
        s.base = 0x1000;
        s.forbid_vectors = false;
        assert!(evaluate(&r, &s).is_ok());
    }
}
#[test]
fn load_faults_stop_the_ordered_access_stream_and_produce_no_transition() {
    for &(word, width, count, store, immediate) in CASES {
        if store {
            continue;
        }
        for endian in [Endian::Little, Endian::Big] {
            let mut s = State::new(128, width);
            s.mask = 1;
            s.fault = Some(count as usize - 1);
            let word = word | (1 << 5) | 31 | if immediate { 0 } else { 2 << 16 };
            let r = recipe(word, 0, endian, 128).unwrap();
            assert!(matches!(evaluate(&r, &s), Err(EvalError::Memory)));
            assert_eq!(s.reads.borrow().len(), count as usize);
            assert!(!s
                .registers
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64"));
        }
    }
}
#[test]
fn register_offset_aliases_base_without_writeback_and_invalid_contexts_reject() {
    for &(baseword, width, count, store, immediate) in CASES {
        if immediate {
            continue;
        }
        let mut s = State::new(128, width);
        s.offset_index = 1;
        s.mask = 1;
        let r = recipe(baseword | (1 << 5) | (1 << 16), 0, Endian::Little, 128).unwrap();
        let t = evaluate(&r, &s).unwrap();
        assert!(!t
            .registers
            .iter()
            .any(|r| matches!(r.register.bank, "a64.gpr" | "a64.sp")));
        let first = s
            .base
            .wrapping_add(s.base.wrapping_mul(u64::from(width / 8)));
        if !store {
            assert_eq!(s.reads.borrow()[0].0, first);
        } else {
            let addr = if width == 128 {
                t.wide_memory[0].address
            } else {
                t.memory[0].address
            };
            assert_eq!(addr, first);
        }
        let _ = count;
        assert!(recipe(baseword | (31 << 16), 0, Endian::Little, 128)
            .map_or(true, |r| r.support != Support::Full));
        for vl in [0, 64, 192, 4096] {
            assert!(recipe(baseword | (2 << 16), 0, Endian::Little, vl)
                .map_or(true, |r| r.support != Support::Full));
        }
    }
}
#[test]
fn selected_q_load_requires_backend_capability_and_stays_one_access() {
    struct NoWide(State);
    impl Machine for NoWide {
        fn read_register(&self, r: Register) -> Value {
            self.0.read_register(r)
        }
        fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
            self.0.read_memory(a, w, e)
        }
    }
    for &(word, width, _, store, immediate) in CASES {
        if width != 128 || store {
            continue;
        }
        let mut s = State::new(128, width);
        s.mask = 1;
        let word = word | (1 << 5) | if immediate { 0 } else { 2 << 16 };
        let r = recipe(word, 0, Endian::Little, 128).unwrap();
        assert!(matches!(
            evaluate(&r, &NoWide(s)),
            Err(EvalError::Unsupported)
        ));
    }
}

#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
include!("arm64_sve_replicate_cases.rs");
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    semantics::arm64_sve_replicate::a64(word, 0x1000, endian, vl)
}
fn byte(a: u64) -> u8 {
    let x = a.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(17);
    (x ^ (x >> 11) ^ (x >> 37)) as u8
}
fn vector(n: usize, chunk: usize) -> u64 {
    (n as u64 + 1).wrapping_mul(0x0193b54769abcdef)
        ^ (chunk as u64).wrapping_mul(0x8123456701234567)
}
struct State {
    z: [[u64; 32]; 32],
    p: [u64; 4],
    base: u64,
    offset: u64,
    n: u16,
    m: u16,
    controls: [Option<u64>; 2],
    forbid_addresses: bool,
    reads: RefCell<Vec<(u64, u8, Endian)>>,
    registers: RefCell<Vec<Register>>,
    fault: Option<usize>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| std::array::from_fn(|c| vector(n, c))),
            p: [0; 4],
            base: 0x2000,
            offset: 3,
            n: 1,
            m: 2,
            controls: [Some(0), None],
            forbid_addresses: false,
            reads: RefCell::new(vec![]),
            registers: RefCell::new(vec![]),
            fault: None,
        }
    }
    fn mask(&mut self, vl: u16, w: u8, block: u16, mode: u8) {
        let elements = vl / u16::from(w);
        let block_elements = if block == 0 {
            elements
        } else {
            block / u16::from(w)
        };
        for e in 0..elements {
            let active = match mode {
                0 => false,
                1 => true,
                2 => e % 3 != 1,
                3 => e == elements - 1,
                4 => e >= block_elements,
                _ => false,
            };
            let at = e * u16::from(w) / 8;
            if active {
                self.p[usize::from(at / 64)] |= 1 << (at % 64);
            }
        }
        if mode == 5 {
            for at in 0..vl / 8 {
                if at % (u16::from(w) / 8) != 0 {
                    self.p[usize::from(at / 64)] |= 1 << (at % 64);
                }
            }
        }
    }
    fn active(&self, e: u16, w: u8) -> bool {
        let at = e * u16::from(w) / 8;
        self.p[usize::from(at / 64)] & (1 << (at % 64)) != 0
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.registers.borrow_mut().push(r);
        match r.bank {
            "a64.vector64" => panic!("replicate does not read vector source state"),
            "a64.predicate64" => Value::known(64, self.p[usize::from(r.index % 4)]),
            "a64.svcr" => self.controls[0].map_or(Value::unknown(64), |v| Value::known(64, v)),
            "a64.sme_fa64" => self.controls[1].map_or(Value::unknown(1), |v| Value::known(1, v)),
            "a64.gpr" | "a64.sp" => {
                assert!(!self.forbid_addresses, "masked address read");
                Value::known(
                    64,
                    if r.bank == "a64.sp" || r.index == self.n {
                        self.base
                    } else {
                        assert_eq!(r.index, self.m);
                        self.offset
                    },
                )
            }
            _ => panic!("unexpected input {r:?}"),
        }
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((a, w, e));
        if self.fault == Some(index) {
            return Err(EvalError::Memory);
        }
        let mut value = 0;
        for i in 0..w / 8 {
            let at = if e == Endian::Little {
                i
            } else {
                w / 8 - 1 - i
            };
            value |= u64::from(byte(a.wrapping_add(u64::from(i)))) << (at * 8);
        }
        Ok(Value::known(w, value))
    }
}
fn instruction(base: u32, block: u16, immediate: bool, d: u32, n: u32, m: u32, imm: u32) -> u32 {
    base | d
        | (n << 5)
        | (7 << 10)
        | if immediate {
            (imm & (if block == 0 { 63 } else { 15 })) << 16
        } else {
            m << 16
        }
}
fn numerical(
    class: usize,
    vl: u16,
    endian: Endian,
    mode: u8,
    d: u32,
    n: u32,
    m: u32,
    imm: u32,
    base: u64,
    offset: u64,
) {
    let (word, w, mw, block, signed, immediate, _) = CASES[class];
    let mut s = State::new();
    s.n = n as u16;
    s.m = m as u16;
    s.base = base;
    s.offset = offset;
    s.mask(vl, w, block, mode);
    let word = instruction(word, block, immediate, d, n, m, imm);
    let count = if block == 0 { vl } else { block } / u16::from(w);
    let any = (0..count).any(|e| s.active(e, w));
    s.forbid_addresses = !any;
    let delta = if !immediate {
        (if n == m { base } else { offset }).wrapping_mul(u64::from(mw / 8))
    } else if block == 0 {
        u64::from(imm & 63) * u64::from(mw / 8)
    } else {
        let ix = (imm & 15) as i64;
        ((if ix & 8 != 0 { ix - 16 } else { ix }) * i64::from(block / 8)) as u64
    };
    let start = base.wrapping_add(delta);
    let mut access = vec![];
    let mut lanes = vec![0; usize::from(count)];
    let load = |a: u64| {
        let mut v = 0;
        for i in 0..mw / 8 {
            let at = if endian == Endian::Little {
                i
            } else {
                mw / 8 - 1 - i
            };
            v |= u64::from(byte(a.wrapping_add(u64::from(i)))) << (at * 8);
        }
        if signed && v & (1 << (mw - 1)) != 0 && mw < 64 {
            v |= u64::MAX << mw;
        }
        v & if w == 64 { u64::MAX } else { (1 << w) - 1 }
    };
    if block == 0 && any {
        access.push((start, mw, endian));
    }
    for e in 0..count {
        if s.active(e, w) {
            let address = if block == 0 {
                start
            } else {
                start.wrapping_add(u64::from(e) * u64::from(mw / 8))
            };
            if block != 0 {
                access.push((address, mw, endian));
            }
            lanes[usize::from(e)] = load(address);
        }
    }
    let r = recipe(word, vl, endian).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, &s).unwrap();
    let mut actual = s.z;
    let mut expected = s.z;
    for output in 0..vl / 64 {
        let mut value = 0;
        for lane in 0..64 / u16::from(w) {
            let e = output * (64 / u16::from(w)) + lane;
            value |= lanes[usize::from(e) % lanes.len()] << (lane * u16::from(w));
        }
        expected[d as usize][usize::from(output)] = value;
    }
    for wr in &t.registers {
        assert_eq!(wr.register.bank, "a64.vector64");
        assert_eq!(wr.register.index / 32, d as u16);
        assert!(wr.value.is_known());
        actual[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
            wr.value.bits;
    }
    assert_eq!(
        actual, expected,
        "class{class} VL{vl} {endian:?} mode{mode} imm{imm}"
    );
    assert_eq!(*s.reads.borrow(), access, "class{class} access stream");
    assert_eq!(t.registers.len(), usize::from(vl / 64));
    assert!(t.memory.is_empty());
    assert!(t.atomics.is_empty());
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
}
#[test]
fn all_replicate_classes_lengths_endians_masks_addresses_and_destinations() {
    let mut cases = 0;
    for (class, &(_, _, _, block, _, immediate, _)) in CASES.iter().enumerate() {
        for vl in [128, 256, 512, 1024, 2048] {
            if block > vl {
                continue;
            }
            for endian in [Endian::Little, Endian::Big] {
                for mode in 0..6 {
                    for d in [0, 31] {
                        for imm in if immediate {
                            vec![0, 1, 7, 8, 15, 31, 63]
                        } else {
                            vec![0]
                        } {
                            for (n, m, base, offset) in [
                                (1, 2, 0x2000, 3),
                                (1, 1, 0x2000, 3),
                                (31, 2, 0x2000, u64::MAX),
                            ] {
                                numerical(class, vl, endian, mode, d, n, m, imm, base, offset);
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("{cases} SVE replicate states");
}
#[test]
fn replicate_all_immediate_values_and_wrapping_addresses() {
    for (class, &(_, _, _, block, _, immediate, _)) in CASES.iter().enumerate() {
        if !immediate {
            continue;
        }
        for imm in 0..if block == 0 { 64 } else { 16 } {
            for endian in [Endian::Little, Endian::Big] {
                numerical(class, 512, endian, 1, 31, 1, 2, imm, u64::MAX - 7, 3);
            }
        }
    }
}
#[test]
fn replicate_faults_never_publish_a_partial_transition() {
    for &(word, w, _, block, _, immediate, _) in CASES {
        let vl = 512;
        let mut s = State::new();
        s.mask(vl, w, block, 1);
        let accesses = if block == 0 {
            1
        } else {
            usize::from(block / u16::from(w))
        };
        for fault in [0, accesses - 1] {
            for endian in [Endian::Little, Endian::Big] {
                s.reads.borrow_mut().clear();
                s.fault = Some(fault);
                let r =
                    recipe(instruction(word, block, immediate, 31, 1, 2, 0), vl, endian).unwrap();
                assert_eq!(evaluate(&r, &s), Err(EvalError::Memory));
                assert_eq!(s.reads.borrow().len(), fault + 1);
            }
        }
    }
}
#[test]
fn replicate_context_alignment_reserved_offsets_and_lengths() {
    for &(word, w, _, block, _, immediate, _) in CASES {
        for vl in [0, 64, 129, 384, 4096] {
            assert!(matches!(
                recipe(word, vl, Endian::Little).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if block == 256 {
            assert!(matches!(
                recipe(word, 128, Endian::Little).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if !immediate {
            assert!(recipe(word | (31 << 16), 512, Endian::Little)
                .is_none_or(|r| matches!(r.support, Support::Unsupported(_))));
        }
        for active in [false, true] {
            let mut s = State::new();
            s.n = 31;
            s.base = 0x2001;
            s.mask(512, w, block, u8::from(active));
            s.forbid_addresses = !active;
            let r = recipe(
                instruction(word, block, immediate, 0, 31, 2, 0),
                512,
                Endian::Little,
            )
            .unwrap();
            assert_eq!(evaluate(&r, &s).is_err(), active);
            assert!(s.reads.borrow().is_empty());
        }
        if block == 256 {
            for (sm, fa, ok) in [
                (Some(0), None, true),
                (Some(1), Some(1), true),
                (Some(1), Some(0), false),
                (None, Some(1), false),
                (Some(1), None, false),
            ] {
                let mut s = State::new();
                s.controls = [sm, fa];
                s.mask(512, w, block, 1);
                let r = recipe(
                    instruction(word, block, immediate, 0, 1, 2, 0),
                    512,
                    Endian::Little,
                )
                .unwrap();
                assert_eq!(evaluate(&r, &s).is_ok(), ok);
                if !ok {
                    assert!(s.reads.borrow().is_empty());
                    assert!(s
                        .registers
                        .borrow()
                        .iter()
                        .all(|r| matches!(r.bank, "a64.svcr" | "a64.sme_fa64")));
                }
            }
        }
    }
}

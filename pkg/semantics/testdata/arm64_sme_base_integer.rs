#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
#[derive(Clone)]
struct State {
    za: Vec<u64>,
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    x: [u64; 31],
    sp: u64,
    svcr: Option<u64>,
    forbid_data: bool,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            za: (0..8192)
                .map(|i| 0xa3897165fedcba09u64.wrapping_mul(i + 1))
                .collect(),
            z: std::array::from_fn(|n| {
                std::array::from_fn(|i| 0xfedcba9876543211u64.wrapping_mul((n * 32 + i + 1) as u64))
            }),
            p: [[0; 4]; 16],
            x: std::array::from_fn(|n| u64::MAX.wrapping_sub(n as u64 * 7)),
            sp: u64::MAX - 15,
            svcr: Some(3),
            forbid_data: false,
            reads: RefCell::new(vec![]),
        }
    }
    fn predicate(&self, n: usize, e: u16, w: u8) -> bool {
        let b = e * u16::from(w) / 8;
        self.p[n][usize::from(b / 64)] & (1 << (b % 64)) != 0
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        if r.bank == "a64.svcr" {
            return self.svcr.map_or(Value::unknown(2), |v| Value::known(2, v));
        }
        assert!(!self.forbid_data, "data read before context guard: {r:?}");
        Value::known(
            64,
            match r.bank {
                "a64.za64" => self.za[usize::from(r.index)],
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.predicate64" => self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
                "a64.gpr" => self.x[usize::from(r.index)],
                "a64.sp" => self.sp,
                _ => panic!("{r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory")
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sme::a64(word, 0x1000, vl)
}
fn run(word: u32, vl: u16, s: &State) -> (State, Transition) {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    let mut out = s.clone();
    for wr in &t.registers {
        assert!(wr.value.is_known());
        match wr.register.bank {
            "a64.za64" => out.za[usize::from(wr.register.index)] = wr.value.bits,
            "a64.gpr" => out.x[usize::from(wr.register.index)] = wr.value.bits,
            "a64.sp" => out.sp = wr.value.bits,
            _ => panic!("unexpected write {wr:?}"),
        }
    }
    assert!(t.memory.is_empty());
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    (out, t)
}
#[test]
fn tile_additions_all_tiles_lengths_predicate_dimensions_and_wraps() {
    let mut states = 0;
    for vl in [128, 256, 512, 1024, 2048] {
        for width in [32u8, 64] {
            for vertical in [false, true] {
                for tile in 0..width / 8 {
                    for (pn, pm, n) in [(0u32, 7u32, 0u32), (7, 0, 31), (7, 7, 17)] {
                        for mode in 0..6 {
                            let mut s = State::new();
                            let dim = vl / u16::from(width);
                            for p in [pn, pm] {
                                for e in 0..vl / 8 {
                                    let active = match mode {
                                        0 => false,
                                        1 => true,
                                        2 => e % 3 != p as u16 % 3,
                                        3 => e == 0,
                                        4 => e == vl / 8 - u16::from(width) / 8,
                                        _ => e % u16::from(width / 8) != 0,
                                    };
                                    if active {
                                        s.p[p as usize][usize::from(e / 64)] |= 1 << (e % 64);
                                    }
                                }
                            }
                            // Maximal positive bit patterns ensure unsigned wrapping in both widths.
                            s.za[usize::from(tile) * 32] = u64::MAX;
                            s.z[n as usize][0] = u64::MAX;
                            let mut expected = s.za.clone();
                            for row in 0..dim {
                                for col in 0..dim {
                                    if s.predicate(pn as usize, row, width)
                                        && s.predicate(pm as usize, col, width)
                                    {
                                        let src = if vertical { row } else { col };
                                        let bit = src * u16::from(width);
                                        let value =
                                            s.z[n as usize][usize::from(bit / 64)] >> (bit % 64);
                                        let dbit = col * u16::from(width);
                                        let i = usize::from(
                                            row * u16::from(width) / 8 + u16::from(tile),
                                        ) * 32
                                            + usize::from(dbit / 64);
                                        let shift = dbit % 64;
                                        let mask = u64::MAX >> (64 - width);
                                        let old = (s.za[i] >> shift) & mask;
                                        expected[i] = (expected[i] & !(mask << shift))
                                            | ((old.wrapping_add(value) & mask) << shift);
                                    }
                                }
                            }
                            let word = 0xc0900000
                                | if width == 64 { 1 << 22 } else { 0 }
                                | if vertical { 1 << 16 } else { 0 }
                                | (pm << 13)
                                | (pn << 10)
                                | (n << 5)
                                | u32::from(tile);
                            let (out, t) = run(word, vl, &s);
                            assert_eq!(out.za, expected, "{word:08x} SVL{vl} mode{mode}");
                            assert_eq!(out.z, s.z);
                            assert_eq!(out.p, s.p);
                            assert_eq!(out.x, s.x);
                            assert_eq!(out.sp, s.sp);
                            assert_eq!(t.registers.len(), usize::from(dim * (vl / 64)));
                            states += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(states, 2160);
    println!("{states} complete ZA states, including inactive backing");
}
#[test]
fn scalar_all_immediates_lengths_register_aliases_sp_and_zr() {
    let mut states = 0;
    for vl in [128, 256, 512, 1024, 2048] {
        for form in 0..3 {
            for imm in 0..64u32 {
                for (n, d) in [(0u32, 0u32), (0, 30), (30, 0), (31, 0), (0, 31), (31, 31)] {
                    let mut s = State::new();
                    s.svcr = None;
                    let delta = ((i64::from(imm) << 58) >> 58)
                        .wrapping_mul(i64::from(if form == 0 { vl / 64 } else { vl / 8 }))
                        as u64;
                    let mut x = s.x;
                    let mut sp = s.sp;
                    let word = if form == 2 {
                        0x04bf5800
                    } else {
                        (if form == 0 { 0x04605800 } else { 0x04205800 }) | (n << 16)
                    } | (imm << 5)
                        | d;
                    let value = if form == 2 {
                        delta
                    } else {
                        (if n == 31 { s.sp } else { s.x[n as usize] }).wrapping_add(delta)
                    };
                    if d == 31 {
                        if form != 2 {
                            sp = value
                        }
                    } else {
                        x[d as usize] = value
                    }
                    let (out, t) = run(word, vl, &s);
                    assert_eq!(out.x, x, "{word:08x} SVL{vl}");
                    assert_eq!(out.sp, sp);
                    assert_eq!(out.za, s.za);
                    assert_eq!(out.z, s.z);
                    assert_eq!(out.p, s.p);
                    assert_eq!(s.reads.borrow().len(), usize::from(form != 2));
                    assert_eq!(t.registers.len(), usize::from(form != 2 || d != 31));
                    states += 1;
                }
            }
        }
    }
    assert_eq!(states, 5760);
    println!("{states} scalar states, every signed immediate");
}
#[test]
fn tile_guards_precede_all_state_reads() {
    for word in [0xc0900000, 0xc0910003, 0xc0d00007, 0xc0d10007] {
        for control in [None, Some(0), Some(1), Some(2)] {
            let mut s = State::new();
            s.svcr = control;
            s.forbid_data = true;
            assert_eq!(
                evaluate(&recipe(word, 2048).unwrap(), &s),
                Err(if control.is_none() {
                    EvalError::UnknownCondition
                } else {
                    EvalError::UnsupportedContext
                })
            );
            assert!(s.reads.borrow().iter().all(|r| r.bank == "a64.svcr"));
        }
    }
}
#[test]
fn lengths_reserved_bits_and_unrelated_words_are_explicit() {
    for word in [
        0xc0900000, 0xc0910000, 0xc0d00000, 0xc0d10000, 0x04605800, 0x04205800, 0x04bf5800,
    ] {
        for vl in [0, 64, 192, 384, 4096] {
            let r = recipe(word, vl).unwrap();
            assert!(matches!(
                evaluate(&r, &State::new()),
                Err(EvalError::UnsupportedContext | EvalError::Unsupported)
            ));
        }
    }
    for word in [
        0xc0900004,
        0xc0d00008,
        0x04605000,
        0x04be5800,
        0,
        0xffff_ffff,
    ] {
        assert!(semantics::arm64_sme::a64(word, 0x1000, 128).is_none(), "{word:08x}");
    }
}

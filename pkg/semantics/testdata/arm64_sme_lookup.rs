#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    zt: [u64; 8],
    p: [[u64; 4]; 16],
    x: [u64; 31],
    flags: [Option<u64>; 4],
    fpcr: Option<u64>,
    controls: [Option<u64>; 5],
    absent: Vec<Register>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|i| 0x9e3779b97f4a7c15u64.wrapping_mul((n * 32 + i + 1) as u64))
            }),
            zt: std::array::from_fn(|i| 0xa391fd8250bc476eu64.wrapping_mul(i as u64 + 1)),
            controls: [Some(3), None, None, None, None],
            p: [[0; 4]; 16],
            x: [0; 31],
            flags: [Some(1), Some(0), Some(1), Some(1)],
            fpcr: Some(0),
            absent: vec![],
            reads: RefCell::new(vec![]),
        }
    }
    fn bits(&self, n: u32, bit: u16, width: u8) -> u64 {
        let mut x = 0;
        for i in 0..u16::from(width) {
            let at = bit + i;
            x |= ((self.z[n as usize][usize::from(at / 64)] >> (at % 64)) & 1) << i;
        }
        x
    }
    fn put(&mut self, n: u32, bit: u16, width: u8, v: u64) {
        for i in 0..u16::from(width) {
            let at = bit + i;
            let z = &mut self.z[n as usize][usize::from(at / 64)];
            *z = (*z & !(1 << (at % 64))) | (((v >> i) & 1) << (at % 64));
        }
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        let w = if r.bank == "a64.vector64" || r.bank == "a64.svcr" {
            64
        } else {
            1
        };
        if self.absent.contains(&r) {
            return Value::unknown(w);
        };
        if r.bank == "a64.vector64" {
            return Value::known(
                64,
                self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
            );
        };
        match r.bank {
            "a64.zt064" => return Value::known(64, self.zt[r.index as usize]),
            "a64.predicate64" => {
                return Value::known(
                    64,
                    self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
                )
            }
            "a64.gpr" => return Value::known(64, self.x[usize::from(r.index)]),
            "a64.nzcv" => {
                return self.flags[usize::from(r.index)]
                    .map_or(Value::unknown(1), |v| Value::known(1, v))
            }
            "a64.fpcr" => {
                return self
                    .fpcr
                    .map_or(Value::unknown(32), |v| Value::known(32, v))
            }
            _ => {}
        }
        let index = match r.bank {
            "a64.svcr" => 0,
            "a64.sme_fa64" => 1,
            "a64.sme2" => 2,
            "a64.cpta" => 3,
            "a64.cptm" => 4,
            _ => panic!("input {r:?}"),
        };
        match self.controls[index] {
            Some(x) => Value::known(w, x),
            None => Value::unknown(w),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("memory")
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_lookup::sme(word, 0x1000, vl)
}
fn run(word: u32, vl: u16, s: &State) -> (State, Transition) {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap();
    let mut out = s.clone();
    for wr in &t.registers {
        assert!(wr.value.is_known());
        if wr.register.bank == "a64.nzcv" {
            out.flags[usize::from(wr.register.index)] = Some(wr.value.bits);
        } else {
            assert_eq!(wr.register.bank, "a64.vector64");
            out.z[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                wr.value.bits;
        }
    }
    assert!(t.memory.is_empty());
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    (out, t)
}
// base, index bits, outputs, stride, kind, immediate shift/bits, legal size mask.
const FORMS: [(u32, u8, u16, bool, u8, u8, u8, u8); 17] = [
    (0xc08c4000, 2, 2, false, 0, 15, 3, 7),
    (0xc09c4000, 2, 2, true, 0, 15, 3, 3),
    (0xc08c8000, 2, 4, false, 0, 16, 2, 7),
    (0xc09c8000, 2, 4, true, 0, 16, 2, 3),
    (0xc0cc0000, 2, 1, false, 0, 14, 4, 7),
    (0xc08a4000, 4, 2, false, 0, 15, 2, 7),
    (0xc09a4000, 4, 2, true, 0, 15, 2, 3),
    (0xc08b0000, 4, 4, false, 1, 0, 0, 1),
    (0xc09b0000, 4, 4, true, 1, 0, 0, 1),
    (0xc08a8000, 4, 4, false, 0, 16, 1, 6),
    (0xc09a8000, 4, 4, true, 0, 16, 1, 2),
    (0xc0ca0000, 4, 1, false, 0, 14, 3, 7),
    (0xc120f400, 6, 4, false, 4, 22, 1, 1),
    (0xc120fc00, 6, 4, true, 4, 22, 1, 1),
    (0xc08a0000, 6, 4, false, 3, 0, 0, 1),
    (0xc09a0000, 6, 4, true, 3, 0, 0, 1),
    (0xc0c84000, 6, 1, false, 2, 0, 0, 1),
];
fn physical(
    class: usize,
    size: u32,
    imm: u32,
    last: bool,
    alias: u32,
) -> (u32, u32, u32, u32, u16, u8, u8) {
    let (base, iw, count, strided, kind, shift, _, _) = FORMS[class];
    let d = if last {
        if strided {
            16 + 16 / u32::from(count) - 1
        } else {
            32 - u32::from(count)
        }
    } else {
        0
    };
    let stride = if strided { 16 / count } else { 1 };
    let mut n = match alias {
        0 => {
            if kind == 3 {
                7
            } else if kind == 1 {
                30
            } else {
                31
            }
        }
        1 => d,
        _ => d + u32::from((count - 1) * stride),
    };
    if kind == 1 {
        n &= 30;
    }
    if kind == 3 {
        n &= 7;
    }
    let source = if kind == 4 {
        if alias == 0 {
            31
        } else {
            d
        }
    } else {
        n
    };
    let width = if kind >= 2 {
        if kind == 4 {
            16
        } else {
            8
        }
    } else {
        8 << size
    };
    let word = base
        | (if kind < 2 { size << 12 } else { 0 })
        | (imm << shift)
        | d
        | (if kind == 3 { n << 7 } else { n << 5 })
        | (if kind == 4 { source << 16 } else { 0 });
    (word, d, n, source, stride, width, iw)
}
fn index(s: &State, n: u32, bit: u16, iw: u8, vl: u16) -> u64 {
    (0..u16::from(iw))
        .map(|i| {
            let at = bit + i;
            ((s.bits((n + u32::from(at / vl)) % 32, at % vl, 1)) & 1) << i
        })
        .fold(0, |a, b| a | b)
}
#[test]
fn sme_lookup_all_classes_sizes_immediates_lengths_aliases_and_tables() {
    let mut cases = 0;
    for (class, &(_, _, count, _, kind, _, immbits, sizes)) in FORMS.iter().enumerate() {
        for size in 0..4 {
            if sizes & (1 << size) == 0 {
                continue;
            }
            for vl in [128, 256, 512, 1024, 2048] {
                if kind == 4 && vl < 512 {
                    continue;
                }
                for imm in 0..1 << immbits {
                    for last in [false, true] {
                        for alias in 0..3 {
                            for seed in [0u64, 0xffffffffffffffff, 0x72b04ad13e65fc98] {
                                let (word, d, n, source, stride, width, iw) =
                                    physical(class, size, imm, last, alias);
                                let mut s = State::new();
                                for reg in 0..32 {
                                    for chunk in 0..32 {
                                        s.z[reg][chunk] ^= seed.rotate_left((reg + chunk) as u32);
                                    }
                                }
                                for chunk in 0..8 {
                                    s.zt[chunk] ^= seed.rotate_left(chunk as u32);
                                }
                                let mut expected = s.clone();
                                let elements = vl / u16::from(width);
                                let segment = if kind == 0 {
                                    imm % (u32::from(width) / (u32::from(iw) * u32::from(count)))
                                } else {
                                    0
                                };
                                for member in 0..count {
                                    for element in 0..elements {
                                        let bit = if kind == 4 {
                                            imm as u16 * (vl / 2)
                                                + (member * elements + element) * u16::from(iw)
                                        } else {
                                            ((segment as u16 * count + member) * elements + element)
                                                * u16::from(iw)
                                        };
                                        let ix = index(&s, source, bit, iw, vl) as u16;
                                        let value = if kind == 4 {
                                            s.bits(
                                                (n + u32::from(ix / 32)) % 32,
                                                (ix % 32) * 16,
                                                16,
                                            )
                                        } else {
                                            let at = ix * (if kind <= 1 { 32 } else { 8 });
                                            (s.zt[usize::from(at / 64)] >> (at % 64))
                                                & ((1u64 << width) - 1)
                                        };
                                        expected.put(
                                            d + u32::from(member * stride),
                                            element * u16::from(width),
                                            width,
                                            value,
                                        );
                                    }
                                }
                                let (out, t) = run(word, vl, &s);
                                assert_eq!(out.z,expected.z,"class{class} size{size} imm{imm} VL{vl} last{last} alias{alias} seed{seed}");
                                assert_eq!(out.zt, s.zt);
                                assert_eq!(out.p, s.p);
                                assert_eq!(out.x, s.x);
                                assert_eq!(out.flags, s.flags);
                                assert_eq!(t.registers.len(), usize::from(count * vl / 64));
                                assert!(s.reads.borrow().iter().all(|r| match r.bank {
                                    "a64.vector64" => r.index % 32 < vl / 64,
                                    "a64.zt064" => kind != 4,
                                    "a64.svcr" => true,
                                    _ => false,
                                }));
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("{cases} SME lookup states");
}
#[test]
fn sme_lookup_rejects_reserved_sizes_lengths_and_disabled_context_without_operand_reads() {
    for (class, &(_, _, _, _, kind, _, _, sizes)) in FORMS.iter().enumerate() {
        for size in 0..4 {
            if sizes & (1 << size) != 0 {
                continue;
            }
            if kind >= 2 {
                continue;
            }
            let (word, ..) = physical(class, size, 0, false, 0);
            assert!(
                recipe(word, 512).is_none_or(|r| matches!(r.support, Support::Unsupported(_))),
                "class{class} size{size}"
            );
        }
        let (word, ..) = physical(class, sizes.trailing_zeros(), 0, false, 0);
        for vl in [0, 64, 129, 384, 4096] {
            assert!(matches!(
                recipe(word, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        if kind == 4 {
            for vl in [128, 256] {
                assert!(matches!(
                    recipe(word, vl).unwrap().support,
                    Support::Unsupported(_)
                ));
            }
        }
        for control in [Some(0), Some(2), None] {
            let mut s = State::new();
            s.controls[0] = control;
            assert!(evaluate(&recipe(word, 512).unwrap(), &s).is_err());
            assert!(s.reads.borrow().iter().all(|r| r.bank == "a64.svcr"));
        }
        let mut s = State::new();
        s.controls[0] = Some(1);
        assert_eq!(evaluate(&recipe(word, 512).unwrap(), &s).is_ok(), kind == 4);
    }
}
#[test]
fn sme_lookup_every_index_value_and_cross_register_boundary() {
    for (class, &(_, iw, count, _, kind, _, _, sizes)) in FORMS.iter().enumerate() {
        let size = sizes.trailing_zeros();
        let vl = 512;
        let (word, d, n, source, stride, width, _) = physical(class, size, 0, true, 0);
        let elements = vl / u16::from(width);
        for ix in 0..1u64 << iw {
            let mut s = State::new();
            for at in 0..count * elements {
                for i in 0..u16::from(iw) {
                    let bit = at * u16::from(iw) + i;
                    s.put(
                        (source + u32::from(bit / vl)) % 32,
                        bit % vl,
                        1,
                        (ix >> i) & 1,
                    );
                }
            }
            // Inputs may overlap the vector tables; the oracle reads the
            // resulting incoming state after all index initialization.
            let value = if kind == 4 {
                s.bits((n + (ix / 32) as u32) % 32, (ix as u16 % 32) * 16, 16)
            } else {
                let at = ix as u16 * if kind <= 1 { 32 } else { 8 };
                (s.zt[usize::from(at / 64)] >> (at % 64)) & ((1 << width) - 1)
            };
            let (out, _) = run(word, vl, &s);
            for member in 0..count {
                for lane in 0..elements {
                    assert_eq!(
                        out.bits(
                            d + u32::from(member * stride),
                            lane * u16::from(width),
                            width
                        ),
                        value,
                        "class{class} index{ix} member{member} lane{lane}"
                    );
                }
            }
        }
    }
}

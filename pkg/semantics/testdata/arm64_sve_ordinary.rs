#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const CASES: &[(u32, bool, u16, u8, u8, bool, bool)] = &[
    (0xa400a000, true, 8, 8, 0, true, false),    //ld1b_z_p_bi_u8
    (0xa420a000, true, 16, 8, 0, true, false),   //ld1b_z_p_bi_u16
    (0xa440a000, true, 32, 8, 0, true, false),   //ld1b_z_p_bi_u32
    (0xa460a000, true, 64, 8, 0, true, false),   //ld1b_z_p_bi_u64
    (0xa4004000, true, 8, 8, 0, false, false),   //ld1b_z_p_br_u8
    (0xa4204000, true, 16, 8, 0, false, false),  //ld1b_z_p_br_u16
    (0xa4404000, true, 32, 8, 0, false, false),  //ld1b_z_p_br_u32
    (0xa4604000, true, 64, 8, 0, false, false),  //ld1b_z_p_br_u64
    (0xa5e0a000, true, 64, 64, 0, true, false),  //ld1d_z_p_bi_u64
    (0xa5902000, true, 128, 64, 0, true, false), //ld1d_z_p_bi_u128
    (0xa5e04000, true, 64, 64, 0, false, false), //ld1d_z_p_br_u64
    (0xa5808000, true, 128, 64, 0, false, false), //ld1d_z_p_br_u128
    (0xa4a0a000, true, 16, 16, 0, true, false),  //ld1h_z_p_bi_u16
    (0xa4c0a000, true, 32, 16, 0, true, false),  //ld1h_z_p_bi_u32
    (0xa4e0a000, true, 64, 16, 0, true, false),  //ld1h_z_p_bi_u64
    (0xa4a04000, true, 16, 16, 0, false, false), //ld1h_z_p_br_u16
    (0xa4c04000, true, 32, 16, 0, false, false), //ld1h_z_p_br_u32
    (0xa4e04000, true, 64, 16, 0, false, false), //ld1h_z_p_br_u64
    (0xc400a000, true, 128, 128, 3, false, false), //ld1q_z_p_ar_d_64_unscaled
    (0xa5c0a000, true, 16, 8, 0, true, true),    //ld1sb_z_p_bi_s16
    (0xa5a0a000, true, 32, 8, 0, true, true),    //ld1sb_z_p_bi_s32
    (0xa580a000, true, 64, 8, 0, true, true),    //ld1sb_z_p_bi_s64
    (0xa5c04000, true, 16, 8, 0, false, true),   //ld1sb_z_p_br_s16
    (0xa5a04000, true, 32, 8, 0, false, true),   //ld1sb_z_p_br_s32
    (0xa5804000, true, 64, 8, 0, false, true),   //ld1sb_z_p_br_s64
    (0xa520a000, true, 32, 16, 0, true, true),   //ld1sh_z_p_bi_s32
    (0xa500a000, true, 64, 16, 0, true, true),   //ld1sh_z_p_bi_s64
    (0xa5204000, true, 32, 16, 0, false, true),  //ld1sh_z_p_br_s32
    (0xa5004000, true, 64, 16, 0, false, true),  //ld1sh_z_p_br_s64
    (0xa480a000, true, 64, 32, 0, true, true),   //ld1sw_z_p_bi_s64
    (0xa4804000, true, 64, 32, 0, false, true),  //ld1sw_z_p_br_s64
    (0xa540a000, true, 32, 32, 0, true, false),  //ld1w_z_p_bi_u32
    (0xa560a000, true, 64, 32, 0, true, false),  //ld1w_z_p_bi_u64
    (0xa5102000, true, 128, 32, 0, true, false), //ld1w_z_p_bi_u128
    (0xa5404000, true, 32, 32, 0, false, false), //ld1w_z_p_br_u32
    (0xa5604000, true, 64, 32, 0, false, false), //ld1w_z_p_br_u64
    (0xa5008000, true, 128, 32, 0, false, false), //ld1w_z_p_br_u128
    (0x85800000, true, 8, 8, 1, true, false),    //ldr_p_bi_
    (0x85804000, true, 8, 8, 2, true, false),    //ldr_z_bi_
    (0xe400e000, false, 8, 8, 0, true, false),   //st1b_z_p_bi_
    (0xe420e000, false, 16, 8, 0, true, false),  //st1b_z_p_bi_
    (0xe440e000, false, 32, 8, 0, true, false),  //st1b_z_p_bi_
    (0xe460e000, false, 64, 8, 0, true, false),  //st1b_z_p_bi_
    (0xe4004000, false, 8, 8, 0, false, false),  //st1b_z_p_br_
    (0xe4204000, false, 16, 8, 0, false, false), //st1b_z_p_br_
    (0xe4404000, false, 32, 8, 0, false, false), //st1b_z_p_br_
    (0xe4604000, false, 64, 8, 0, false, false), //st1b_z_p_br_
    (0xe5e0e000, false, 64, 64, 0, true, false), //st1d_z_p_bi_
    (0xe5c0e000, false, 128, 64, 0, true, false), //st1d_z_p_bi_u128
    (0xe5e04000, false, 64, 64, 0, false, false), //st1d_z_p_br_
    (0xe5c04000, false, 128, 64, 0, false, false), //st1d_z_p_br_u128
    (0xe4a0e000, false, 16, 16, 0, true, false), //st1h_z_p_bi_
    (0xe4c0e000, false, 32, 16, 0, true, false), //st1h_z_p_bi_
    (0xe4e0e000, false, 64, 16, 0, true, false), //st1h_z_p_bi_
    (0xe4a04000, false, 16, 16, 0, false, false), //st1h_z_p_br_
    (0xe4c04000, false, 32, 16, 0, false, false), //st1h_z_p_br_
    (0xe4e04000, false, 64, 16, 0, false, false), //st1h_z_p_br_
    (0xe4202000, false, 128, 128, 3, false, false), //st1q_z_p_ar_d_64_unscaled
    (0xe540e000, false, 32, 32, 0, true, false), //st1w_z_p_bi_
    (0xe560e000, false, 64, 32, 0, true, false), //st1w_z_p_bi_
    (0xe500e000, false, 128, 32, 0, true, false), //st1w_z_p_bi_u128
    (0xe5404000, false, 32, 32, 0, false, false), //st1w_z_p_br_
    (0xe5604000, false, 64, 32, 0, false, false), //st1w_z_p_br_
    (0xe5004000, false, 128, 32, 0, false, false), //st1w_z_p_br_u128
    (0xe5800000, false, 8, 8, 1, true, false),   //str_p_bi_
    (0xe5804000, false, 8, 8, 2, true, false),   //str_z_bi_
];

fn vectors() -> [[u64; 32]; 32] {
    std::array::from_fn(|n| {
        std::array::from_fn(|c| 0x1927356bdcfa8231u64.wrapping_mul((n * 32 + c + 1) as u64))
    })
}
fn predicates() -> [[u64; 4]; 16] {
    std::array::from_fn(|n| {
        std::array::from_fn(|c| 0x91b37ca813954a76u64.wrapping_mul((n * 4 + c + 1) as u64))
    })
}
fn byte(a: u64) -> u8 {
    let x = a.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(17);
    (x ^ (x >> 11) ^ (x >> 37)) as u8
}
fn instruction(base: u32, kind: u8, im: bool, case: u32) -> u32 {
    let n = if kind != 3 && case == 4 {
        31
    } else if kind == 3 && case & 1 != 0 {
        0
    } else {
        1
    };
    base | (n << 5)
        | if kind == 1 || kind == 2 {
            let imm = [0u32, 1, 255, 256, 511][case as usize % 5];
            ((imm >> 3) << 16) | ((imm & 7) << 10)
        } else {
            (7 << 10)
                | if im {
                    ([0u32, 7, 8, 15, 1][case as usize % 5]) << 16
                } else {
                    2 << 16
                }
        }
}
#[derive(Clone)]
struct Inputs {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    base: u64,
    offset: u64,
}
fn inputs(vl: u16, ew: u16, kind: u8, case: u32) -> Inputs {
    let mut s = Inputs {
        z: vectors(),
        p: predicates(),
        base: 0x2800,
        offset: 3,
    };
    if kind == 3 {
        for chunk in (0..vl / 64).step_by(2) {
            s.z[1][usize::from(chunk)] = 0x2200 + u64::from(chunk) * 8;
            s.z[0][usize::from(chunk)] = 0x2200 + u64::from(chunk) * 8;
        }
    }
    if kind == 0 || kind == 3 {
        s.p[7] = [0; 4];
        for bit in 0..vl / 8 {
            let e = bit / (ew / 8);
            let active = match case {
                0 => false,
                1 => true,
                2 => e % 3 != 1,
                3 => e == vl / ew - 1,
                4 => true,
                _ => false,
            };
            if bit % (ew / 8) == 0 && active || case == 0 && bit % (ew / 8) != 0 {
                s.p[7][usize::from(bit / 64)] |= 1 << (bit % 64);
            }
        }
    }
    s
}
fn active(s: &Inputs, e: u16, ew: u16) -> bool {
    let bit = e * (ew / 8);
    s.p[7][usize::from(bit / 64)] & (1 << (bit % 64)) != 0
}
fn source(s: &Inputs, n: u32, bit: u16, w: u8, kind: u8) -> u64 {
    let data = if kind == 1 {
        s.p[n as usize][usize::from(bit / 64)]
    } else {
        s.z[n as usize][usize::from(bit / 64)]
    };
    (data >> (bit % 64)) & if w == 64 { u64::MAX } else { (1u64 << w) - 1 }
}
fn access_plan(
    s: &Inputs,
    word: u32,
    vl: u16,
    ew: u16,
    mw: u8,
    kind: u8,
    im: bool,
) -> Vec<(u64, u16, u16)> {
    let mut out = vec![];
    if kind == 1 || kind == 2 {
        let count = if kind == 1 { vl / 64 } else { vl / 8 };
        let raw = (((word >> 16) & 63) << 3) | ((word >> 10) & 7);
        let imm = if raw & 256 != 0 {
            i64::from(raw) - 512
        } else {
            i64::from(raw)
        };
        let start = s.base.wrapping_add((imm * i64::from(count)) as u64);
        for e in 0..count {
            out.push((start.wrapping_add(u64::from(e)), e * 8, 8));
        }
    } else {
        let count = vl / ew;
        let imm = ((word >> 16) & 15) as i64;
        let delta = if im {
            ((if imm & 8 != 0 { imm - 16 } else { imm }) * i64::from(count) * i64::from(mw / 8))
                as u64
        } else {
            s.offset
                .wrapping_mul(if kind == 3 { 1 } else { u64::from(mw / 8) })
        };
        for e in 0..count {
            if active(s, e, ew) {
                let a = if kind == 3 {
                    s.z[((word >> 5) & 31) as usize][usize::from(e * 2)].wrapping_add(delta)
                } else {
                    s.base
                        .wrapping_add(delta)
                        .wrapping_add(u64::from(e) * u64::from(mw / 8))
                };
                out.push((a, e * ew, u16::from(mw)));
            }
        }
    }
    out
}
fn memory_value(a: u64, w: u16, endian: bool) -> Vec<u64> {
    let mut chunks = vec![0; usize::from(w.div_ceil(64))];
    for i in 0..w / 8 {
        let bit = if endian { i * 8 } else { w - 8 - i * 8 };
        chunks[usize::from(bit / 64)] |=
            u64::from(byte(a.wrapping_add(u64::from(i)))) << (bit % 64);
    }
    chunks
}
fn expected(
    s: &Inputs,
    plan: &[(u64, u16, u16)],
    kind: u8,
    ew: u16,
    signed: bool,
    endian: bool,
) -> ([[u64; 32]; 32], [[u64; 4]; 16]) {
    let mut z = s.z;
    let mut p = s.p;
    if kind == 1 {
        p[0] = [0; 4];
    } else {
        z[0] = [0; 32];
    }
    for &(a, bit, mw) in plan {
        let mut values = memory_value(a, mw, endian);
        if signed && mw < 64 && values[0] & (1 << (mw - 1)) != 0 {
            values[0] |= u64::MAX << mw;
        }
        for (part, mut v) in values.drain(..).enumerate() {
            let pos = bit + part as u16 * 64;
            if kind != 1 && ew < 64 {
                v &= (1u64 << ew) - 1;
            }
            if kind == 1 {
                p[0][usize::from(pos / 64)] |= v << (pos % 64);
            } else {
                z[0][usize::from(pos / 64)] |= v << (pos % 64);
            }
        }
    }
    (z, p)
}

fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    arm64_sve_ordinary::a64(word, 0x1000, endian, vl)
}
struct State {
    data: Inputs,
    sm: u64,
    fa64: bool,
    policy: Option<bool>,
    sp_policy: Option<bool>,
    reads: RefCell<Vec<(u64, u16, Endian)>>,
    fault: Option<usize>,
    forbid: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.vector64" => {
                assert!(!self.forbid);
                Value::known(
                    64,
                    self.data.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                )
            }
            "a64.predicate64" => Value::known(
                64,
                self.data.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
            ),
            "a64.svcr" => Value::known(64, self.sm),
            "a64.sme_fa64" => Value::known(1, u64::from(self.fa64)),
            "a64.alignment_enforced" => self
                .policy
                .map_or(Value::unknown(1), |p| Value::known(1, u64::from(p))),
            "a64.sp_alignment_enforced" => self
                .sp_policy
                .map_or(Value::unknown(1), |p| Value::known(1, u64::from(p))),
            "a64.gpr" | "a64.sp" => {
                assert!(!self.forbid);
                Value::known(
                    64,
                    if r.bank == "a64.sp" || r.index == 1 {
                        self.data.base
                    } else {
                        assert_eq!(r.index, 2);
                        self.data.offset
                    },
                )
            }
            _ => panic!("unexpected {r:?}"),
        }
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((a, u16::from(w), e));
        if self.fault == Some(index) {
            return Err(EvalError::Memory);
        }
        Ok(Value::known(
            w,
            memory_value(a, u16::from(w), e == Endian::Little)[0],
        ))
    }
    fn read_wide_memory(&self, a: u64, w: u16, e: Endian) -> Result<Vec<Value>, EvalError> {
        let index = self.reads.borrow().len();
        self.reads.borrow_mut().push((a, w, e));
        if self.fault == Some(index) {
            return Err(EvalError::Memory);
        }
        Ok(memory_value(a, w, e == Endian::Little)
            .into_iter()
            .map(|v| Value::known(64, v))
            .collect())
    }
}
fn state(data: Inputs) -> State {
    State {
        data,
        sm: 0,
        fa64: false,
        policy: None,
        sp_policy: None,
        reads: RefCell::new(vec![]),
        fault: None,
        forbid: false,
    }
}
#[test]
fn ordinary_memory_complete_forms_lengths_endians_predicates_offsets_aliases_and_storage() {
    for &(base, load, ew, mw, kind, im, signed) in CASES {
        for vl in [128, 256, 512, 1024, 2048] {
            for endian in [Endian::Little, Endian::Big] {
                for case in 0..5 {
                    let word = instruction(base, kind, im, case);
                    let data = inputs(vl, ew, kind, case);
                    let plan = access_plan(&data, word, vl, ew, mw, kind, im);
                    let mut s = state(data);
                    s.forbid = plan.is_empty();
                    let r = recipe(word, vl, endian).unwrap();
                    assert_eq!(r.support, Support::Full, "{word:08x}");
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    assert_eq!(t.trap, None);
                    if load {
                        assert_eq!(
                            *s.reads.borrow(),
                            plan.iter()
                                .map(|&(a, _, w)| (a, w, endian))
                                .collect::<Vec<_>>(),
                            "{word:08x} VL{vl}"
                        );
                        let want =
                            expected(&s.data, &plan, kind, ew, signed, endian == Endian::Little);
                        let (mut z, mut p) = (s.data.z, s.data.p);
                        for wr in t.registers {
                            assert!(wr.value.is_known());
                            match wr.register.bank {
                                "a64.vector64" => {
                                    z[usize::from(wr.register.index / 32)]
                                        [usize::from(wr.register.index % 32)] = wr.value.bits
                                }
                                "a64.predicate64" => {
                                    p[usize::from(wr.register.index / 4)]
                                        [usize::from(wr.register.index % 4)] = wr.value.bits
                                }
                                _ => panic!(),
                            }
                        }
                        assert_eq!((z, p), want, "{word:08x} VL{vl} case{case}");
                        assert!(t.memory.is_empty() && t.wide_memory.is_empty());
                    } else {
                        assert!(s.reads.borrow().is_empty());
                        let mut writes = vec![];
                        for w in t.memory {
                            writes.push((w.address, u16::from(w.value.width), vec![w.value.bits]));
                        }
                        for w in t.wide_memory {
                            writes.push((
                                w.address,
                                w.width,
                                w.chunks
                                    .iter()
                                    .map(|v| {
                                        assert!(v.is_known());
                                        v.bits
                                    })
                                    .collect(),
                            ));
                        }
                        let want = plan
                            .iter()
                            .map(|&(a, bit, w)| {
                                (
                                    a,
                                    w,
                                    (0..w.div_ceil(64))
                                        .map(|part| {
                                            source(
                                                &s.data,
                                                0,
                                                bit + part * 64,
                                                (w - part * 64).min(64) as u8,
                                                kind,
                                            )
                                        })
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(writes, want, "{word:08x} VL{vl}");
                    }
                }
            }
        }
    }
}
#[test]
fn ordinary_memory_alignment_context_and_faults_precede_all_accesses() {
    for word in [0x85800020, 0xe5800020, 0x85804020, 0xe5804020] {
        for enforced in [false, true] {
            let mut s = state(inputs(128, 8, 2, 0));
            s.data.base = 0x2801;
            s.policy = Some(enforced);
            let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).unwrap();
            assert_eq!(
                t.trap,
                if enforced {
                    Some(TrapKind::Protection)
                } else {
                    None
                }
            );
            if enforced {
                assert!(
                    s.reads.borrow().is_empty() && t.memory.is_empty() && t.registers.is_empty()
                );
            }
        }
        let mut s = state(inputs(128, 8, 2, 0));
        s.data.base = 0x2801;
        assert_eq!(
            evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s),
            Err(EvalError::UnknownCondition)
        );
    }
    for &(base, load, ew, mw, kind, im, _) in CASES {
        if kind == 3 {
            continue;
        }
        let word = instruction(base, kind, im, 4);
        let mut s = state(inputs(128, ew, kind, 4));
        s.data.base = 0x2801;
        s.policy = Some(false);
        s.sp_policy = Some(true);
        let t = evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).unwrap();
        assert_eq!(t.trap, Some(TrapKind::Protection), "{word:08x}");
        assert!(s.reads.borrow().is_empty() && t.memory.is_empty() && t.registers.is_empty());
        if load {
            let word = instruction(base, kind, im, 1);
            let mut s = state(inputs(2048, ew, kind, 1));
            let plan = access_plan(&s.data, word, 2048, ew, mw, kind, im);
            s.fault = Some(plan.len() - 1);
            assert_eq!(
                evaluate(&recipe(word, 2048, Endian::Little).unwrap(), &s),
                Err(EvalError::Memory)
            );
            assert_eq!(s.reads.borrow().len(), plan.len());
        }
    }
}
#[test]
fn quadword_streaming_requires_effective_fa64() {
    for &(base, _, ew, _, kind, _, _) in CASES {
        if ew != 128 {
            continue;
        }
        let word = instruction(base, kind, false, 1);
        let mut s = state(inputs(128, ew, kind, 1));
        s.sm = 1;
        assert_eq!(
            evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        );
        assert!(s.reads.borrow().is_empty());
        s.fa64 = true;
        assert!(evaluate(&recipe(word, 128, Endian::Little).unwrap(), &s).is_ok());
    }
}

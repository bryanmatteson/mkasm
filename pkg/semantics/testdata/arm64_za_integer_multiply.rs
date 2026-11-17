#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u32, u8, u16, u8, u8, u8)] = &[
    (0xfff0001c, 0xc1000014, 32, 1, 3, 1, 2), //sumlall_za_zzi_s
    (0xfff09038, 0xc1100030, 32, 2, 3, 1, 2), //sumlall_za_zzi_s2xi
    (0xfff09078, 0xc1108030, 32, 4, 3, 1, 2), //sumlall_za_zzi_s4xi
    (0xfff09c1e, 0xc1200014, 32, 2, 3, 0, 2), //sumlall_za_zzv_s2x1
    (0xfff09c1e, 0xc1300014, 32, 4, 3, 0, 2), //sumlall_za_zzv_s4x1
    (0xfff09078, 0xc1508038, 32, 4, 4, 1, 2), //suvdot_za_zzi_s4xi
    (0xfff09038, 0xc1500020, 32, 2, 4, 1, 0), //svdot_za32_zzi_2xi
    (0xfff09078, 0xc1508020, 32, 4, 4, 1, 0), //svdot_za_zzi_s4xi
    (0xfff09878, 0xc1d08808, 64, 4, 4, 1, 0), //svdot_za_zzi_d4xi
    (0xfff0001c, 0xc1000004, 32, 1, 3, 1, 1), //usmlall_za_zzi_s
    (0xfff09038, 0xc1100020, 32, 2, 3, 1, 1), //usmlall_za_zzi_s2xi
    (0xfff09078, 0xc1108020, 32, 4, 3, 1, 1), //usmlall_za_zzi_s4xi
    (0xfff09c1c, 0xc1200404, 32, 1, 3, 0, 1), //usmlall_za_zzv_s
    (0xfff09c1e, 0xc1200004, 32, 2, 3, 0, 1), //usmlall_za_zzv_s2x1
    (0xfff09c1e, 0xc1300004, 32, 4, 3, 0, 1), //usmlall_za_zzv_s4x1
    (0xffe19c3e, 0xc1a00004, 32, 2, 3, 2, 1), //usmlall_za_zzw_s2x2
    (0xffe39c7e, 0xc1a10004, 32, 4, 3, 2, 1), //usmlall_za_zzw_s4x4
    (0xfff09078, 0xc1508028, 32, 4, 4, 1, 1), //usvdot_za_zzi_s4xi
    (0xfff09038, 0xc1500030, 32, 2, 4, 1, 3), //uvdot_za32_zzi_2xi
    (0xfff09078, 0xc1508030, 32, 4, 4, 1, 3), //uvdot_za_zzi_s4xi
    (0xfff09878, 0xc1d08818, 64, 4, 4, 1, 3), //uvdot_za_zzi_d4xi
];
fn vectors() -> [[u64; 32]; 32] {
    std::array::from_fn(|n| {
        std::array::from_fn(|c| 0x9127356bdcfa8231u64.wrapping_mul((n * 32 + c + 1) as u64))
    })
}
fn matrix() -> Vec<[u64; 32]> {
    (0..256)
        .map(|r| {
            std::array::from_fn(|c| 0x8f2e731a6954bcd1u64.wrapping_mul((r * 32 + c + 1) as u64))
        })
        .collect()
}
fn instruction(mask: u32, base: u32, w: u8, group: u16, shape: u8, mode: u8, case: u32) -> u32 {
    let n = [0, 31, 29, 30][(case % 4) as usize];
    let m = [0, 15, 31, 14][((case / 4) % 4) as usize];
    let index = if shape == 4 {
        (case % (128 / u32::from(w))) << 10
    } else if mode == 1 {
        if group == 1 {
            ((case & 8) << 12) | ((case & 7) << 10)
        } else {
            ((case & 12) << 8) | ((case & 3) << 1)
        }
    } else {
        0
    };
    base | (((n << 5) | (m << 16) | ((case % 4) << 13) | ((case / 2) % 8) | index) & !mask)
}
fn selector(case: u32, vl: u16, group: u16) -> u64 {
    0xdeadbeef00000000
        | match case % 4 {
            0 => 0,
            1 => u64::from(vl / 8 / group - 1),
            2 => u64::from(u32::MAX),
            _ => 0x80000001,
        }
}
fn lane(z: &[[u64; 32]; 32], n: usize, e: usize, w: u8) -> i128 {
    let bit = e * usize::from(w);
    i128::from((z[n][bit / 64] >> (bit % 64)) & ((1u64 << w) - 1))
}
fn number(v: i128, w: u8, unsigned: bool) -> i128 {
    if !unsigned && v & (1i128 << (w - 1)) != 0 {
        v - (1i128 << w)
    } else {
        v
    }
}
fn expected(
    before: &[[u64; 32]],
    z: &[[u64; 32]; 32],
    word: u32,
    w: u8,
    group: u16,
    shape: u8,
    mode: u8,
    flags: u8,
    select: u64,
    vl: u16,
) -> Vec<[u64; 32]> {
    let n = ((word >> 5) & if mode == 0 { 31 } else { 32 - u32::from(group) }) as usize;
    let m = ((word >> 16) & if mode == 2 { 32 - u32::from(group) } else { 15 }) as usize;
    let vertical = shape == 4;
    let offset = if vertical {
        word & 7
    } else {
        (word & if group == 1 { 3 } else { 1 }) * 4
    };
    let index = if vertical {
        (word >> 10) & if w == 64 { 1 } else { 3 }
    } else if mode != 1 {
        0
    } else if group == 1 {
        ((word >> 15) & 1) * 8 + ((word >> 10) & 7)
    } else {
        ((word >> 10) & 3) * 4 + ((word >> 1) & 3)
    };
    let stride = usize::from(vl / 8 / group);
    let first = ((u64::from(select as u32) + u64::from(offset)) % stride as u64) as usize;
    let first = if vertical { first } else { first / 4 * 4 };
    let mut out = before.to_vec();
    let count = if vertical { group as usize } else { 4 };
    let input = w / count as u8;
    for member in 0..usize::from(group) {
        for row in 0..if vertical { 1 } else { 4 } {
            let dest = first + member * stride + row;
            for e in 0..usize::from(vl) / usize::from(w) {
                let mut sum = 0i128;
                let segment = e / (128 / usize::from(w)) * (128 / usize::from(w));
                for p in 0..if vertical { count } else { 1 } {
                    let left = if vertical {
                        count * e + member
                    } else {
                        4 * e + row
                    };
                    let right = if mode == 1 {
                        if vertical {
                            count * (segment + index as usize) + p
                        } else {
                            4 * segment + index as usize
                        }
                    } else {
                        left
                    };
                    let a = number(
                        lane(z, (n + if vertical { p } else { member }) % 32, left, input),
                        input,
                        flags & 1 != 0,
                    );
                    let b = number(
                        lane(z, m + if mode == 2 { member } else { 0 }, right, input),
                        input,
                        flags & 2 != 0,
                    );
                    sum += a * b;
                }
                let bit = e * usize::from(w);
                let mask = if w == 64 { u64::MAX } else { 0xffffffff };
                let old = (before[dest][bit / 64] >> (bit % 64)) & mask;
                let value = (i128::from(old) + sum) as u64 & mask;
                out[dest][bit / 64] =
                    (out[dest][bit / 64] & !(mask << (bit % 64))) | (value << (bit % 64));
            }
        }
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sme::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    svcr: u64,
    select: u64,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.za64" => self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => self.svcr,
                "a64.gpr" => self.select,
                _ => panic!("integer operation read context {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
}
#[test]
fn za_integer_multiply_all_classes_lengths_indices_selectors_and_complete_storage() {
    for &(mask, base, w, group, shape, mode, flags) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for case in 0..16 {
                let word = instruction(mask, base, w, group, shape, mode, case);
                let s = State {
                    z: vectors(),
                    za: matrix(),
                    svcr: 3,
                    select: selector(case, vl, group),
                };
                let want = expected(
                    &s.za, &s.z, word, w, group, shape, mode, flags, s.select, vl,
                );
                let r = recipe(word, vl).unwrap();
                assert_eq!(r.support, Support::Full);
                r.validate().unwrap();
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(t.trap, None);
                let mut out = s.za;
                for wr in t.registers {
                    assert_eq!(wr.register.bank, "a64.za64");
                    out[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                        wr.value.bits;
                }
                assert_eq!(out, want, "{word:08x} SVL{vl} case{case}");
            }
        }
    }
}
#[test]
fn za_integer_multiply_context_precedes_unavailable_sources() {
    for &(_, word, _, _, _, _, _) in FORMS {
        for svcr in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                svcr,
                select: 0,
            };
            assert_eq!(
                evaluate(&recipe(word, 128).unwrap(), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
    }
}

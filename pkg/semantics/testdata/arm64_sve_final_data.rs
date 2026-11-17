#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u32, u8, bool)] = &[
    (0xffe0fc01, 0x4520fc00, 1, false), //pmlal_mz_zzzw_1x2
    (0xffe0e010, 0x8400e000, 0, true),  //prfb_i_p_ai_s
    (0xffe0e010, 0xc400e000, 0, true),  //prfb_i_p_ai_d
    (0xffc0e010, 0x85c00000, 0, false), //prfb_i_p_bi_s
    (0xffe0e010, 0x8400c000, 0, false), //prfb_i_p_br_s
    (0xffa0e010, 0x84200000, 0, true),  //prfb_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4200000, 0, true),  //prfb_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc4608000, 0, true),  //prfb_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8580e000, 0, true),  //prfd_i_p_ai_s
    (0xffe0e010, 0xc580e000, 0, true),  //prfd_i_p_ai_d
    (0xffc0e010, 0x85c06000, 0, false), //prfd_i_p_bi_s
    (0xffe0e010, 0x8580c000, 0, false), //prfd_i_p_br_s
    (0xffa0e010, 0x84206000, 0, true),  //prfd_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4206000, 0, true),  //prfd_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460e000, 0, true),  //prfd_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8480e000, 0, true),  //prfh_i_p_ai_s
    (0xffe0e010, 0xc480e000, 0, true),  //prfh_i_p_ai_d
    (0xffc0e010, 0x85c02000, 0, false), //prfh_i_p_bi_s
    (0xffe0e010, 0x8480c000, 0, false), //prfh_i_p_br_s
    (0xffa0e010, 0x84202000, 0, true),  //prfh_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4202000, 0, true),  //prfh_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460a000, 0, true),  //prfh_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8500e000, 0, true),  //prfw_i_p_ai_s
    (0xffe0e010, 0xc500e000, 0, true),  //prfw_i_p_ai_d
    (0xffc0e010, 0x85c04000, 0, false), //prfw_i_p_bi_s
    (0xffe0e010, 0x8500c000, 0, false), //prfw_i_p_br_s
    (0xffa0e010, 0x84204000, 0, true),  //prfw_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4204000, 0, true),  //prfw_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460c000, 0, true),  //prfw_i_p_bz_d_64_scaled
    (0xff20c210, 0x25204000, 2, false), //psel_p_ppi_
];

fn prefetch_word(mask: u32, base: u32, case: u32) -> u32 {
    let mut word = base | ((case * 0x189423) & !mask);
    if matches!(base, 0x8400c000 | 0x8480c000 | 0x8500c000 | 0x8580c000) && (word >> 16) & 31 == 31
    {
        word &= !(1 << 16);
    }
    word
}
fn vectors(case: u32) -> [[u64; 32]; 32] {
    std::array::from_fn(|n| {
        std::array::from_fn(|c| match case % 5 {
            0 => 0,
            1 => u64::MAX,
            2 => 1u64 << ((n + c) % 64),
            3 => 0x5555555555555555u64.rotate_left((n + c) as u32),
            _ => 0x193b75d2a4768e39u64.wrapping_mul((n * 32 + c + 1) as u64),
        })
    })
}
fn predicates(case: u32) -> [[u64; 4]; 16] {
    std::array::from_fn(|n| {
        std::array::from_fn(|c| match case % 4 {
            0 => 0,
            1 => u64::MAX,
            2 => 1u64 << ((n * 4 + c) % 64),
            _ => 0x193b75d2a4768e39u64.wrapping_mul((n * 4 + c + 1) as u64),
        })
    })
}
fn gpr(case: u32) -> [u64; 31] {
    std::array::from_fn(|n| {
        0xdeadbeef00000000 | u64::from([0, 1, u32::MAX, 0x80000001][(case as usize + n) % 4])
    })
}
fn carryless(a: u64, b: u64) -> u128 {
    let mut value = 0;
    for bit in 0..64 {
        if a >> bit & 1 != 0 {
            value ^= u128::from(b) << bit;
        }
    }
    value
}
fn polynomial_expected(input: &[[u64; 32]; 32], word: u32, vl: u16) -> [[u64; 32]; 32] {
    let mut out = *input;
    let d = (word & 30) as usize;
    let n = ((word >> 5) & 31) as usize;
    let m = ((word >> 16) & 31) as usize;
    out[d] = [0; 32];
    out[d + 1] = [0; 32];
    for segment in 0..usize::from(vl / 128) {
        for half in 0..2 {
            let value = carryless(input[n][segment * 2 + half], input[m][segment * 2 + half]);
            out[d + half][segment * 2] = input[d + half][segment * 2] ^ value as u64;
            out[d + half][segment * 2 + 1] =
                input[d + half][segment * 2 + 1] ^ (value >> 64) as u64;
        }
    }
    out
}
fn select_expected(input: &[[u64; 4]; 16], regs: &[u64; 31], word: u32, vl: u16) -> [[u64; 4]; 16] {
    let d = (word & 15) as usize;
    let n = ((word >> 10) & 15) as usize;
    let m = ((word >> 5) & 15) as usize;
    let selector = 12 + ((word >> 16) & 3) as usize;
    let tsz = ((word >> 19) & 8) | ((word >> 18) & 7);
    let size = tsz.trailing_zeros();
    let width = 8u16 << size;
    let imm = (((word >> 23) & 1) << 4 | tsz) >> (size + 1);
    let e = (u64::from(regs[selector] as u32) + u64::from(imm)) % u64::from(vl / width);
    let bit = e * u64::from(width / 8);
    let selected = input[m][(bit / 64) as usize] >> (bit % 64) & 1 != 0;
    let mut out = *input;
    out[d] = [0; 4];
    if selected {
        for chunk in 0..usize::from((vl / 8).div_ceil(64)) {
            let bits = (usize::from(vl / 8) - chunk * 64).min(64);
            out[d][chunk] = input[n][chunk]
                & if bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                };
        }
    }
    out
}
fn polynomial_word(base: u32, case: u32) -> u32 {
    let d = (case % 16) * 2;
    let n = if case % 3 == 0 {
        d
    } else if case % 3 == 1 {
        d + 1
    } else {
        31
    };
    let m = if case % 4 == 0 {
        d + 1
    } else if case % 4 == 1 {
        d
    } else {
        n
    };
    base | d | (n << 5) | (m << 16)
}
fn select_word(base: u32, tsz: u32, upper: u32, case: u32) -> u32 {
    base | ((tsz & 8) << 19)
        | ((tsz & 7) << 18)
        | (upper << 23)
        | ((case % 4) << 16)
        | ((case % 16) << 10)
        | ((if case % 3 == 0 {
            case % 16
        } else {
            15 - case % 16
        }) << 5)
        | (if case % 3 == 1 {
            15 - case % 16
        } else {
            case % 16
        })
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sve_final_data::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    x: [u64; 31],
    sm: bool,
    fa64: bool,
    ssve: bool,
    forbid: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.svcr" => Value::known(64, u64::from(self.sm)),
            "a64.sme_fa64" => Value::known(1, u64::from(self.fa64)),
            "a64.ssve_aes" => Value::known(1, u64::from(self.ssve)),
            bank => {
                assert!(!self.forbid, "NOP prefetch consumed operand {r:?}");
                Value::known(
                    64,
                    match bank {
                        "a64.vector64" => {
                            self.z[usize::from(r.index / 32)][usize::from(r.index % 32)]
                        }
                        "a64.predicate64" => {
                            self.p[usize::from(r.index / 4)][usize::from(r.index % 4)]
                        }
                        "a64.gpr" => self.x[r.index as usize],
                        _ => panic!("unexpected {r:?}"),
                    },
                )
            }
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("non-memory recipe touched memory")
    }
}
fn state(case: u32) -> State {
    State {
        z: vectors(case),
        p: predicates(case),
        x: gpr(case),
        sm: false,
        fa64: false,
        ssve: false,
        forbid: false,
    }
}
#[test]
fn prefetch_all_classes_hints_selectors_lengths_and_access_modes_are_legal_nops() {
    for &(mask, base, kind, restricted) in FORMS {
        if kind != 0 {
            continue;
        }
        for vl in [128, 256, 512, 1024, 2048] {
            for case in 0..16 {
                let word = prefetch_word(mask, base, case);
                for (sm, fa64) in [(false, false), (true, false), (true, true)] {
                    let mut s = state(case);
                    s.sm = sm;
                    s.fa64 = fa64;
                    s.forbid = true;
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let result = evaluate(&r, &s);
                    if restricted && sm && !fa64 {
                        assert_eq!(result, Err(EvalError::UnsupportedContext));
                    } else {
                        let t = result.unwrap();
                        assert_eq!(t.next_pc, Value::known(64, 0x1004));
                        assert!(
                            t.registers.is_empty()
                                && t.memory.is_empty()
                                && t.wide_memory.is_empty()
                                && t.events.is_empty()
                        );
                        assert_eq!(t.trap, None);
                    }
                }
            }
        }
    }
}
#[test]
fn paired_polynomial_accumulate_all_lengths_aliases_and_entire_backing() {
    let base = FORMS.iter().find(|f| f.2 == 1).unwrap().1;
    for vl in [128, 256, 512, 1024, 2048] {
        for case in 0..40 {
            let word = polynomial_word(base, case);
            let s = state(case);
            let want = polynomial_expected(&s.z, word, vl);
            let r = recipe(word, vl).unwrap();
            r.validate().unwrap();
            let t = evaluate(&r, &s).unwrap();
            let mut got = s.z;
            for wr in t.registers {
                assert_eq!(wr.register.bank, "a64.vector64");
                assert!(wr.value.is_known());
                got[usize::from(wr.register.index / 32)][usize::from(wr.register.index % 32)] =
                    wr.value.bits;
            }
            assert_eq!(got, want, "{word:08x} VL{vl} case{case}");
        }
    }
}
#[test]
fn paired_polynomial_access_admission_observes_effective_fa64_and_ssve_aes() {
    let base = FORMS.iter().find(|f| f.2 == 1).unwrap().1;
    for sm in [false, true] {
        for fa64 in [false, true] {
            for ssve in [false, true] {
                let mut s = state(4);
                s.sm = sm;
                s.fa64 = fa64;
                s.ssve = ssve;
                let result = evaluate(&recipe(base, 128).unwrap(), &s);
                assert_eq!(result.is_ok(), !sm || fa64 || ssve);
            }
        }
    }
}
#[test]
fn psel_all_sizes_immediates_selectors_lengths_aliases_and_predicate_backing() {
    let base = FORMS.iter().find(|f| f.2 == 2).unwrap().1;
    for vl in [128, 256, 512, 1024, 2048] {
        for tsz in 1..16 {
            for upper in 0..2 {
                for case in 0..16 {
                    let word = select_word(base, tsz, upper, case);
                    let s = state(case);
                    let want = select_expected(&s.p, &s.x, word, vl);
                    let r = recipe(word, vl).unwrap();
                    assert_eq!(r.support, Support::Full);
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    let mut got = s.p;
                    for wr in t.registers {
                        assert_eq!(wr.register.bank, "a64.predicate64");
                        got[usize::from(wr.register.index / 4)]
                            [usize::from(wr.register.index % 4)] = wr.value.bits;
                    }
                    assert_eq!(got, want, "{word:08x} VL{vl} case{case}");
                }
            }
        }
    }
    assert!(matches!(
        recipe(base, 128).unwrap().support,
        Support::Unsupported(_)
    ));
}

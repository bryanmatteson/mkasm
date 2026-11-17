#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u32, u8, u16, u16, u16)] = &[
    (0xffff1f01, 0xc0060200, 0, 8, 2, 1),   //movaz_mz2_za_b1
    (0xffff1f01, 0xc0460200, 0, 16, 2, 1),  //movaz_mz2_za_h1
    (0xffff1f01, 0xc0860200, 0, 32, 2, 1),  //movaz_mz2_za_w1
    (0xffff1f01, 0xc0c60200, 0, 64, 2, 1),  //movaz_mz2_za_d1
    (0xffff1f83, 0xc0060600, 0, 8, 4, 1),   //movaz_mz4_za_b1
    (0xffff1f83, 0xc0460600, 0, 16, 4, 1),  //movaz_mz4_za_h1
    (0xffff1f83, 0xc0860600, 0, 32, 4, 1),  //movaz_mz4_za_w1
    (0xffff1f03, 0xc0c60600, 0, 64, 4, 1),  //movaz_mz4_za_d1
    (0xffff9f01, 0xc0060a00, 1, 8, 2, 1),   //movaz_mz_za2_1
    (0xffff9f03, 0xc0060e00, 1, 8, 4, 1),   //movaz_mz_za4_1
    (0xffff1e00, 0xc0020200, 0, 8, 1, 1),   //movaz_z_rza_b
    (0xffff1e00, 0xc0420200, 0, 16, 1, 1),  //movaz_z_rza_h
    (0xffff1e00, 0xc0820200, 0, 32, 1, 1),  //movaz_z_rza_w
    (0xffff1e00, 0xc0c20200, 0, 64, 1, 1),  //movaz_z_rza_d
    (0xffff1e00, 0xc0c30200, 0, 128, 1, 1), //movaz_z_rza_q
    (0xffff8fe0, 0xc04c03e0, 5, 8, 1, 1),   //movt_r_zt_
    (0xffff8fe0, 0xc04e03e0, 4, 8, 1, 1),   //movt_zt_r_
    (0xffffcfe0, 0xc04f03e0, 6, 8, 1, 1),   //movt_zt_z_
    (0xffff9ff8, 0xc00c0000, 2, 8, 2, 1),   //zero_za1_ri_2
    (0xffff9ff8, 0xc00e0000, 2, 8, 4, 1),   //zero_za1_ri_4
    (0xffff9ff8, 0xc00c8000, 2, 8, 1, 2),   //zero_za2_ri_1
    (0xffff9ffc, 0xc00d0000, 2, 8, 2, 2),   //zero_za2_ri_2
    (0xffff9ffc, 0xc00d8000, 2, 8, 4, 2),   //zero_za2_ri_4
    (0xffff9ffc, 0xc00e8000, 2, 8, 1, 4),   //zero_za4_ri_1
    (0xffff9ffe, 0xc00f0000, 2, 8, 2, 4),   //zero_za4_ri_2
    (0xffff9ffe, 0xc00f8000, 2, 8, 4, 4),   //zero_za4_ri_4
    (0xffffffff, 0xc0480001, 3, 8, 1, 1),   //zero_zt_i_
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
fn instruction(mask: u32, base: u32, case: u32) -> u32 {
    let seed = ((case % 4) << 13)
        | ((case % 8) << 12)
        | ((case % 4) << 5)
        | if case & 1 != 0 { 0xffff81ff } else { 0 };
    base | (seed & !mask)
}
fn selector(case: u32) -> u64 {
    0xdeadbeef00000000 | [0, 1, u64::from(u32::MAX), 0x80000001][(case % 4) as usize]
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Storage {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    table: [u64; 8],
    gpr: [u64; 31],
}
fn storage(case: u32) -> Storage {
    Storage {
        z: vectors(),
        za: matrix(),
        table: std::array::from_fn(|i| 0xdaf87e6210839bc5u64.wrapping_mul(i as u64 + 1)),
        gpr: [selector(case); 31],
    }
}
fn expected(
    before: &Storage,
    word: u32,
    kind: u8,
    width: u16,
    group: u16,
    rows: u16,
    vl: u16,
) -> Storage {
    let mut out = before.clone();
    let d = (word & 31) as usize;
    if kind >= 3 {
        let offset = ((word >> 12) & 7) as usize;
        match kind {
            3 => out.table = [0; 8],
            4 => out.table[offset] = if d == 31 { 0 } else { before.gpr[d] },
            5 => {
                if d != 31 {
                    out.gpr[d] = before.table[offset]
                }
            }
            6 => {
                let imm = ((word >> 12) & 3) as usize;
                let count = usize::from(vl.min(512) / 64);
                let offset = (imm % (8 / count)) * count;
                if imm == 0 {
                    out.table = [0; 8];
                }
                out.table[offset..offset + count].copy_from_slice(&before.z[d][..count]);
            }
            _ => panic!(),
        }
        return out;
    }
    let reg = usize::from(if kind == 0 { 12u16 } else { 8u16 }) + ((word >> 13) & 3) as usize;
    let select = u64::from(before.gpr[reg] as u32);
    if kind == 1 || kind == 2 {
        let off = if kind == 1 {
            (word >> 5) & 7
        } else {
            (word
                & if rows == 1 || rows == 2 && group == 1 {
                    7
                } else if rows == 4 && group != 1 {
                    1
                } else {
                    3
                })
                * u32::from(rows)
        };
        let stride = usize::from(vl / 8 / group);
        let base = ((select + u64::from(off)) % stride as u64) as usize / usize::from(rows)
            * usize::from(rows);
        for member in 0..usize::from(group) {
            for row in 0..usize::from(rows) {
                let physical = base + member * stride + row;
                if kind == 1 {
                    out.z[d + member] = [0; 32];
                    out.z[d + member][..usize::from(vl / 64)]
                        .copy_from_slice(&before.za[physical][..usize::from(vl / 64)]);
                }
                out.za[physical][..usize::from(vl / 64)].fill(0);
            }
        }
        return out;
    }
    let elements = usize::from(vl / width);
    let bytes = usize::from(width / 8);
    let offbits = (4 - bytes.trailing_zeros()).saturating_sub(group.trailing_zeros());
    let low = ((word >> 5) & 15) as usize;
    let tile = low >> offbits;
    let off = (low & ((1 << offbits) - 1)) * usize::from(group);
    let first =
        ((select / u64::from(group) * u64::from(group) + off as u64) % elements as u64) as usize;
    for member in 0..usize::from(group) {
        out.z[d + member] = [0; 32];
        for e in 0..elements {
            for bit in 0..usize::from(width) {
                let (row, col) = if word & (1 << 15) != 0 {
                    (e, first + member)
                } else {
                    (first + member, e)
                };
                let physical = row * bytes + tile;
                let src = col * usize::from(width) + bit;
                let dst = e * usize::from(width) + bit;
                let value = (before.za[physical][src / 64] >> (src % 64)) & 1;
                out.z[d + member][dst / 64] |= value << (dst % 64);
                out.za[physical][src / 64] &= !(1u64 << (src % 64));
            }
        }
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_sme_state::a64(word, 0x1000, vl)
}
struct State {
    storage: Storage,
    svcr: u64,
    halted: bool,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => {
                    self.storage.z[usize::from(r.index / 32)][usize::from(r.index % 32)]
                }
                "a64.za64" => self.storage.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => self.svcr,
                "a64.debug_halted" => u64::from(self.halted),
                "a64.gpr" => self.storage.gpr[r.index as usize],
                "a64.zt064" => self.storage.table[r.index as usize],
                _ => panic!("state instruction read FP context {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
}
#[test]
fn sme_state_every_class_length_tile_orientation_offset_selector_and_full_storage() {
    for &(mask, base, kind, w, group, rows) in FORMS {
        for vl in [128, 256, 512, 1024, 2048] {
            for case in 0..16 {
                let word = instruction(mask, base, case);
                let s = State {
                    storage: storage(case),
                    svcr: if kind >= 3 && kind <= 5 && case & 1 == 0 {
                        2
                    } else {
                        3
                    },
                    halted: true,
                };
                let r = recipe(word, vl).unwrap();
                if kind == 0 && group == 4 && w == 64 && vl == 128 {
                    assert!(matches!(r.support, Support::Unsupported(_)));
                    continue;
                }
                assert_eq!(r.support, Support::Full);
                r.validate().unwrap();
                let want = expected(&s.storage, word, kind, w, group, rows, vl);
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(t.trap, None);
                let mut out = s.storage;
                for wr in t.registers {
                    match wr.register.bank {
                        "a64.vector64" => {
                            out.z[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits
                        }
                        "a64.za64" => {
                            out.za[usize::from(wr.register.index / 32)]
                                [usize::from(wr.register.index % 32)] = wr.value.bits
                        }
                        "a64.zt064" => out.table[wr.register.index as usize] = wr.value.bits,
                        "a64.gpr" => out.gpr[wr.register.index as usize] = wr.value.bits,
                        _ => panic!(),
                    }
                }
                assert_eq!(out, want, "{word:08x} SVL{vl} case{case}");
            }
        }
    }
}
#[test]
fn sme_state_context_and_halted_decode_qualification() {
    for &(_, word, kind, _, _, _) in FORMS {
        for svcr in 0..4 {
            let s = State {
                storage: storage(0),
                svcr,
                halted: false,
            };
            let admitted = if (3..=5).contains(&kind) {
                svcr & 2 != 0 && kind == 3
            } else {
                svcr == 3
            };
            let result = evaluate(&recipe(word, 256).unwrap(), &s);
            if admitted {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(EvalError::UnsupportedContext));
            }
        }
    }
}

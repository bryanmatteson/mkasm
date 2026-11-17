#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xffbf9c38, 0xc1a01c10, 0, 2, false), //add_za_zw_2x2
    (0xffbf9c78, 0xc1a11c10, 0, 4, false), //add_za_zw_4x4
    (0xffb09c18, 0xc1201810, 1, 2, false), //add_za_zzv_2x1
    (0xffb09c18, 0xc1301810, 1, 4, false), //add_za_zzv_4x1
    (0xffa19c38, 0xc1a01810, 2, 2, false), //add_za_zzw_2x2
    (0xffa39c78, 0xc1a11810, 2, 4, false), //add_za_zzw_4x4
    (0xffbf9c38, 0xc1a01c18, 0, 2, true),  //sub_za_zw_2x2
    (0xffbf9c78, 0xc1a11c18, 0, 4, true),  //sub_za_zw_4x4
    (0xffb09c18, 0xc1201818, 1, 2, true),  //sub_za_zzv_2x1
    (0xffb09c18, 0xc1301818, 1, 4, true),  //sub_za_zzv_4x1
    (0xffa19c38, 0xc1a01818, 2, 2, true),  //sub_za_zzw_2x2
    (0xffa39c78, 0xc1a11818, 2, 4, true),  //sub_za_zzw_4x4
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
fn parameters(layout: u8, group: u16, case: u32, vl: u16) -> (u32, u32, u32, u32, u64) {
    let n = if layout == 1 {
        [0, 29, 30, 31][(case % 4) as usize]
    } else {
        if case & 1 == 0 {
            0
        } else {
            32 - u32::from(group)
        }
    };
    let m = if layout == 1 {
        [0, 8, 14, 15][(case % 4) as usize]
    } else {
        if case & 2 == 0 {
            0
        } else {
            32 - u32::from(group)
        }
    };
    let selector = case % 4;
    let off = case;
    let low = match case % 4 {
        0 => 0,
        1 => u32::from(vl / 8 / group) - 1,
        2 => u32::MAX,
        _ => 0x80000001,
    };
    (n, m, selector, off, 0xdeadbeef00000000 | u64::from(low))
}
fn instruction(
    mask: u32,
    base: u32,
    layout: u8,
    w: u8,
    n: u32,
    m: u32,
    selector: u32,
    off: u32,
) -> u32 {
    base | (((if layout == 0 { m } else { n } << 5)
        | if layout == 0 { 0 } else { m << 16 }
        | (selector << 13)
        | off
        | if w == 64 { 1 << 22 } else { 0 })
        & !mask)
}
fn expected(
    before: &[[u64; 32]],
    z: &[[u64; 32]; 32],
    layout: u8,
    group: u16,
    subtract: bool,
    w: u8,
    n: u32,
    m: u32,
    off: u32,
    selector: u64,
    vl: u16,
) -> Vec<[u64; 32]> {
    let stride = vl / 8 / group;
    let first = (u64::from(selector as u32) + u64::from(off)) % u64::from(stride);
    let mut out = before.to_vec();
    let mask = if w == 64 { u64::MAX } else { 0xffffffff };
    for member in 0..group {
        let row = first as usize + usize::from(member * stride);
        for chunk in 0..vl / 64 {
            let a = if layout == 0 {
                before[row][chunk as usize]
            } else {
                z[((n + u32::from(member)) % 32) as usize][chunk as usize]
            };
            let rhs =
                z[(m + if layout == 1 { 0 } else { u32::from(member) }) as usize][chunk as usize];
            let mut result = 0;
            for part in 0..64 / u16::from(w) {
                let shift = part * u16::from(w);
                let x = (a >> shift) & mask;
                let y = (rhs >> shift) & mask;
                let value = if subtract {
                    x.wrapping_sub(y)
                } else {
                    x.wrapping_add(y)
                } & mask;
                result |= value << shift;
            }
            out[row][chunk as usize] = result;
        }
    }
    out
}

fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    arm64_za_integer::a64(word, 0x1000, vl)
}
struct State {
    z: [[u64; 32]; 32],
    za: Vec<[u64; 32]>,
    svcr: u64,
    selector: u64,
    register: u16,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        Value::known(
            64,
            match r.bank {
                "a64.vector64" => self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.za64" => self.za[usize::from(r.index / 32)][usize::from(r.index % 32)],
                "a64.svcr" => self.svcr,
                "a64.gpr" => {
                    assert_eq!(r.index, self.register);
                    self.selector
                }
                _ => panic!("integer operation read FP context {r:?}"),
            },
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
}
#[test]
fn za_integer_all_classes_widths_selectors_offsets_wrap_and_complete_backing() {
    for &(mask, base, layout, group, subtract) in FORMS {
        for w in [32, 64] {
            for vl in [128, 256, 512, 1024, 2048] {
                for case in 0..8 {
                    let (n, m, select, off, value) = parameters(layout, group, case, vl);
                    let word = instruction(mask, base, layout, w, n, m, select, off);
                    let s = State {
                        z: vectors(),
                        za: matrix(),
                        svcr: 3,
                        selector: value,
                        register: 8 + select as u16,
                    };
                    let want = expected(
                        &s.za, &s.z, layout, group, subtract, w, n, m, off, value, vl,
                    );
                    let r = recipe(word, vl).unwrap();
                    r.validate().unwrap();
                    let t = evaluate(&r, &s).unwrap();
                    assert_eq!(t.trap, None);
                    let mut out = s.za;
                    for wr in t.registers {
                        assert_eq!(wr.register.bank, "a64.za64");
                        out[usize::from(wr.register.index / 32)]
                            [usize::from(wr.register.index % 32)] = wr.value.bits;
                    }
                    assert_eq!(out, want, "{word:08x} VL{vl} W{select}");
                }
            }
        }
    }
}
#[test]
fn za_integer_context_precedes_unavailable_operands() {
    for &(_, word, _, _, _) in FORMS {
        for svcr in [0, 1, 2] {
            let s = State {
                z: [[0; 32]; 32],
                za: vec![],
                svcr,
                selector: 0,
                register: 8,
            };
            assert_eq!(
                evaluate(&recipe(word, 128).unwrap(), &s),
                Err(EvalError::UnsupportedContext)
            );
        }
        for vl in [0, 64, 384, 4096] {
            assert!(matches!(
                recipe(word, vl).unwrap().support,
                Support::Unsupported(_)
            ));
        }
    }
}

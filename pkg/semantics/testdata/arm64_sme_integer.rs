#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::{cell::RefCell, collections::HashMap};
const SVLS: [u16; 5] = [128, 256, 512, 1024, 2048];
#[derive(Clone, Copy, Debug)]
enum Case {
    Multiply {
        word: u32,
        width: u8,
        nreg: u16,
        n: u16,
        m: u16,
        group: bool,
    },
    Shift {
        word: u32,
        width: u8,
        nreg: u16,
        n: u16,
        m: u16,
        group: bool,
        unsigned: bool,
    },
    Narrow {
        word: u32,
        width: u8,
        nreg: u16,
        n: u16,
        d: u16,
        shift: u8,
        rounded: bool,
        unsigned: bool,
        to_unsigned: bool,
        interleaved: bool,
        streaming: bool,
    },
    Matrix {
        word: u32,
        width: u8,
        nreg: u16,
        n: u16,
        m: u16,
        v: u16,
        offset: u16,
        index: i16,
        parts: u16,
        rows: u16,
        group: bool,
        left_unsigned: bool,
        right_unsigned: bool,
        subtract: bool,
    },
}
include!("arm64_sme_integer_cases.rs");
fn reg(bank: &'static str, index: u16) -> Register {
    Register { bank, index }
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}
fn signed(v: u64, w: u8) -> i128 {
    ((v as i128) << (128 - w)) >> (128 - w)
}
fn number(v: u64, w: u8, unsigned: bool) -> i128 {
    if unsigned {
        v as i128
    } else {
        signed(v, w)
    }
}
fn sample(w: u8, e: u16, n: u16, phase: u16) -> u64 {
    let values = [
        0,
        1,
        mask(w),
        1u64 << (w - 1),
        (1u64 << (w - 1)) - 1,
        2,
        mask(w) - 1,
        0x814203fe7f010080 & mask(w),
    ];
    values[usize::from((e + n * 3 + phase) % 8)]
}
struct State {
    input: u8,
    output: u8,
    phase: u16,
    index: u64,
    svcr: u64,
    reads: RefCell<Vec<Register>>,
    shifts: Option<(u16, u16, i128)>,
}
impl State {
    fn new(c: Case, phase: u16, index: u64) -> Self {
        let (input, output) = match c {
            Case::Multiply { width, .. } | Case::Shift { width, .. } => (width, width),
            Case::Narrow { width, nreg, .. } => (width * nreg as u8, width),
            Case::Matrix {
                width, parts, rows, ..
            } => (width / (parts * rows) as u8, width),
        };
        Self {
            input,
            output,
            phase,
            index,
            svcr: 3,
            reads: RefCell::new(Vec::new()),
            shifts: None,
        }
    }
    fn value(&self, r: Register) -> u64 {
        match r.bank {
            "a64.vector64" | "a64.za64" => {
                let w = if r.bank == "a64.za64" {
                    self.output
                } else {
                    self.input
                };
                let n = r.index / 32;
                if r.bank == "a64.vector64" {
                    if let Some((first, len, count)) = self.shifts {
                        if (first..first + len).contains(&n) {
                            return (0..64 / u16::from(w)).fold(0, |v, e| {
                                v | ((count as u64 & mask(w)) << (e * u16::from(w)))
                            });
                        }
                    }
                }

                let chunk = r.index % 32;
                (0..64 / u16::from(w)).fold(0, |v, e| {
                    v | (sample(w, chunk * 64 / u16::from(w) + e, n, self.phase)
                        << u32::from(e * u16::from(w)))
                })
            }
            "a64.gpr" => self.index | 0xabcd_0000_0000_0000,
            "a64.svcr" => self.svcr,
            "a64.fpsr" => 0xf800009f,
            _ => panic!("unexpected input {r:?}"),
        }
    }
    fn lane(&self, bank: &'static str, n: u16, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        (self.value(reg(bank, n * 32 + bit / 64)) >> (bit % 64)) & mask(w)
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        Value::known(
            if r.bank == "a64.svcr" {
                2
            } else if r.bank == "a64.fpsr" {
                32
            } else {
                64
            },
            self.value(r),
        )
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("integer matrix recipe accessed memory")
    }
}
fn word(c: Case) -> u32 {
    match c {
        Case::Multiply { word, .. }
        | Case::Shift { word, .. }
        | Case::Narrow { word, .. }
        | Case::Matrix { word, .. } => word,
    }
}
fn recipe(word: u32, svl: u16) -> Option<Recipe> {
    semantics::arm64_sme::a64(word, 0x1000, svl)
}
fn set_lane(
    out: &mut HashMap<Register, u64>,
    state: &State,
    bank: &'static str,
    n: u16,
    e: u16,
    w: u8,
    value: u64,
) {
    let bit = e * u16::from(w);
    let r = reg(bank, n * 32 + bit / 64);
    let old = out.get(&r).copied().unwrap_or_else(|| state.value(r));
    let m = mask(w) << (bit % 64);
    out.insert(r, (old & !m) | ((value & mask(w)) << (bit % 64)));
}
fn expected(c: Case, state: &State, svl: u16) -> HashMap<Register, u64> {
    let mut out = HashMap::new();
    match c {
        Case::Multiply {
            width,
            nreg,
            n,
            m,
            group,
            ..
        } => {
            for member in 0..nreg {
                for e in 0..svl / u16::from(width) {
                    let a = signed(state.lane("a64.vector64", n + member, e, width), width);
                    let b = signed(
                        state.lane("a64.vector64", m + if group { member } else { 0 }, e, width),
                        width,
                    );
                    // Divide the full product by 2^(w-1), avoiding overflowing even the
                    // independent i128 oracle for the 64-bit MIN*MIN exceptional product.
                    let result = (a * b) >> (width - 1);
                    let max = (1i128 << (width - 1)) - 1;
                    set_lane(
                        &mut out,
                        state,
                        "a64.vector64",
                        n + member,
                        e,
                        width,
                        result.min(max) as u64,
                    );
                }
                for chunk in svl / 64..32 {
                    out.insert(reg("a64.vector64", (n + member) * 32 + chunk), 0);
                }
            }
        }
        Case::Shift {
            width,
            nreg,
            n,
            m,
            group,
            unsigned,
            ..
        } => {
            for member in 0..nreg {
                for e in 0..svl / u16::from(width) {
                    let a = number(
                        state.lane("a64.vector64", n + member, e, width),
                        width,
                        unsigned,
                    );
                    let shift = signed(
                        state.lane("a64.vector64", m + if group { member } else { 0 }, e, width),
                        width,
                    )
                    .clamp(-i128::from(width) - 1, i128::from(width) + 1);
                    let result = if shift >= 0 {
                        if shift >= i128::from(width) {
                            0
                        } else {
                            (a as u64).wrapping_shl(shift as u32) & mask(width)
                        }
                    } else {
                        ((a + (1i128 << (-shift - 1))) >> (-shift)) as u64 & mask(width)
                    };
                    set_lane(
                        &mut out,
                        state,
                        "a64.vector64",
                        n + member,
                        e,
                        width,
                        result,
                    );
                }
                for chunk in svl / 64..32 {
                    out.insert(reg("a64.vector64", (n + member) * 32 + chunk), 0);
                }
            }
        }
        Case::Narrow {
            width,
            nreg,
            n,
            d,
            shift,
            rounded,
            unsigned,
            to_unsigned,
            interleaved,
            ..
        } => {
            let input = width * nreg as u8;
            let elements = svl / u16::from(input);
            for member in 0..nreg {
                for e in 0..elements {
                    let a = number(
                        state.lane("a64.vector64", n + member, e, input),
                        input,
                        unsigned,
                    );
                    let shifted = (a + if rounded { 1i128 << (shift - 1) } else { 0 }) >> shift;
                    let (min, max) = if to_unsigned {
                        (0, (1i128 << width) - 1)
                    } else {
                        (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1)
                    };
                    let output = if interleaved {
                        e * nreg + member
                    } else {
                        member * elements + e
                    };
                    set_lane(
                        &mut out,
                        state,
                        "a64.vector64",
                        d,
                        output,
                        width,
                        shifted.clamp(min, max) as u64,
                    );
                }
            }
            for chunk in svl / 64..32 {
                out.insert(reg("a64.vector64", d * 32 + chunk), 0);
            }
        }
        Case::Matrix {
            width,
            nreg,
            n,
            m,
            offset,
            index,
            parts,
            rows,
            group,
            left_unsigned,
            right_unsigned,
            subtract,
            ..
        } => {
            let stride = svl / 8 / nreg;
            let base = ((state.index as u32 as u64 + u64::from(offset)) % u64::from(stride)) as u16;
            let base = base - base % rows;
            let input = width / (parts * rows) as u8;
            for member in 0..nreg {
                for row in 0..rows {
                    let physical = base + member * stride + row;
                    for e in 0..svl / u16::from(width) {
                        let mut delta = 0i128;
                        for p in 0..parts {
                            let left = e * rows * parts + row + p;
                            let right = if index >= 0 {
                                let segment =
                                    e / (128 / u16::from(width)) * (128 / u16::from(width));
                                if parts > 1 {
                                    (segment + index as u16) * parts + p
                                } else {
                                    segment * rows + index as u16
                                }
                            } else {
                                left
                            };
                            let a = number(
                                state.lane("a64.vector64", (n + member) % 32, left, input),
                                input,
                                left_unsigned,
                            );
                            let b = number(
                                state.lane(
                                    "a64.vector64",
                                    m + if group { member } else { 0 },
                                    right,
                                    input,
                                ),
                                input,
                                right_unsigned,
                            );
                            delta += a * b;
                        }
                        let old = state.lane("a64.za64", physical, e, width) as i128;
                        set_lane(
                            &mut out,
                            state,
                            "a64.za64",
                            physical,
                            e,
                            width,
                            (old + if subtract { -delta } else { delta }) as u64,
                        );
                    }
                }
            }
        }
    }
    out
}
fn check(c: Case, svl: u16, phase: u16, index: u64) {
    let state = State::new(c, phase, index);
    check_state(c, svl, state);
}
fn check_state(c: Case, svl: u16, state: State) {
    let phase = state.phase;
    let index = state.index;
    let r = recipe(word(c), svl).unwrap_or_else(|| panic!("unhandled {c:?}"));
    assert_eq!(r.support, Support::Full, "{c:?}");
    r.validate().unwrap();
    let t = evaluate(&r, &state).unwrap_or_else(|e| panic!("{c:?} SVL{svl}: {e:?}"));
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert_eq!(t.trap, None);
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    let wanted = expected(c, &state, svl);
    let mut actual = HashMap::new();
    for w in &t.registers {
        assert!(w.value.is_known());
        assert_eq!(w.value.width, 64);
        assert!(
            !matches!(
                w.register.bank,
                "a64.fpsr" | "a64.nzcv" | "a64.gpr" | "a64.svcr"
            ),
            "QC/flags/context must be preserved"
        );
        assert!(
            actual.insert(w.register, w.value.bits).is_none(),
            "duplicate write {c:?} {w:?}"
        );
        assert_eq!(
            w.value.bits,
            wanted
                .get(&w.register)
                .copied()
                .unwrap_or_else(|| state.value(w.register)),
            "{c:?} SVL{svl} phase{phase} index{index} {:?}",
            w.register
        );
    }
    for (register, value) in wanted {
        assert_eq!(
            actual
                .get(&register)
                .copied()
                .unwrap_or_else(|| state.value(register)),
            value,
            "omitted {c:?} SVL{svl} {register:?}"
        );
    }
}
#[test]
fn all_primary_classes_widths_aliases_and_lengths_match_integer_reference() {
    for &c in CASES {
        for svl in SVLS {
            check(c, svl, svl / 128, 0xffff_ffff);
        }
    }
}
#[test]
fn saturation_rounding_extremes_and_row_selector_add_alignment_order() {
    for &c in CASES {
        for phase in [0, 3, 7] {
            check(
                c,
                128,
                phase,
                if phase == 0 {
                    0
                } else if phase == 3 {
                    1
                } else {
                    u32::MAX as u64
                },
            );
        }
    }
}
#[test]
fn sme_context_guards_precede_source_reads_and_reject_invalid_lengths() {
    for &c in CASES {
        let streaming = match c {
            Case::Narrow { streaming, .. } => streaming,
            _ => true,
        };
        if !streaming {
            continue;
        }
        let mut state = State::new(c, 0, 0);
        state.svcr = 0;
        let r = recipe(word(c), 128).unwrap();
        assert!(matches!(
            evaluate(&r, &state),
            Err(EvalError::UnsupportedContext)
        ));
        assert!(state.reads.borrow().iter().all(|r| r.bank == "a64.svcr"));
    }
    for svl in [0, 64, 192, 384, 768, 1536, 4096] {
        let state = State::new(CASES[0], 0, 0);
        if let Some(r) = recipe(word(CASES[0]), svl) {
            assert!(matches!(
                evaluate(&r, &state),
                Err(EvalError::UnsupportedContext)
            ));
        }
        assert!(state.reads.borrow().is_empty());
    }
}
#[test]
fn reserved_group_alignment_and_shift_size_fields_are_not_admitted() {
    for word in [
        0xc120aa22, 0xc122ba20, 0xc120a401, 0xc120ac02, 0xc121b400, 0xc122bc00, 0xc120d800,
        0xc120dc40, 0x45a00000, 0x45a01000, 0x45a02000,
    ] {
        assert!(recipe(word, 128).is_none(), "overadmitted {word:08x}");
    }
}
#[test]
fn every_narrowing_shift_at_every_length_and_nonstreaming_sve_forms() {
    let mut seen = std::collections::HashSet::new();
    for &c in CASES {
        if let Case::Narrow {
            word,
            width,
            nreg,
            n,
            d,
            rounded,
            unsigned,
            to_unsigned,
            interleaved,
            streaming,
            ..
        } = c
        {
            if matches!(c, Case::Narrow { shift: 0, .. }) {
                continue;
            }
            if !seen.insert((
                width,
                nreg,
                rounded,
                unsigned,
                to_unsigned,
                interleaved,
                streaming,
            )) {
                continue;
            }
            let limit = if nreg == 4 { width * 4 } else { width };
            for shift in 1..=limit {
                let word = if nreg == 4 {
                    let encoded = u32::from(width) * 8 - u32::from(shift);
                    (word & !0x00df0000) | ((encoded & 31) << 16) | ((encoded >> 5) << 22)
                } else if rounded {
                    let bits = if width == 8 { 7 } else { 15 };
                    (word & !(bits << 16)) | (u32::from(width - shift) << 16)
                } else {
                    let encoded = u32::from(width) * 2 - u32::from(shift);
                    (word & !0x001f0000) | (encoded << 16)
                };
                let c = Case::Narrow {
                    word,
                    width,
                    nreg,
                    n,
                    d,
                    shift,
                    rounded,
                    unsigned,
                    to_unsigned,
                    interleaved,
                    streaming,
                };
                for svl in SVLS {
                    check(c, svl, u16::from(shift) % 8, 0);
                }
                if !streaming {
                    let mut s = State::new(c, 0, 0);
                    s.svcr = 0;
                    let r = recipe(word, 128).unwrap();
                    assert!(evaluate(&r, &s).is_ok());
                    assert!(s.reads.borrow().iter().all(|r| r.bank != "a64.svcr"));
                }
            }
        }
    }
}
#[test]
fn every_indexed_za_lane_selector_at_every_length() {
    let mut seen = std::collections::HashSet::new();
    for &c in CASES {
        if let Case::Matrix {
            word,
            width,
            nreg,
            n,
            m,
            v,
            offset,
            index,
            parts,
            rows,
            group,
            left_unsigned,
            right_unsigned,
            subtract,
        } = c
        {
            if index < 0 || !seen.insert((width, nreg, parts, rows)) {
                continue;
            }
            let count = if parts > 1 {
                128 / u16::from(width)
            } else {
                128 / (u16::from(width) / rows)
            };
            for index in 0..count {
                let i = u32::from(index);
                let (clear, bits) = if parts > 1 {
                    let mask = if width == 32 { 3 } else { 1 };
                    (mask << 10, i << 10)
                } else if rows == 2 {
                    if nreg == 1 {
                        ((1 << 15) | (3 << 10), ((i >> 2) << 15) | ((i & 3) << 10))
                    } else {
                        ((3 << 10) | (1 << 2), ((i >> 1) << 10) | ((i & 1) << 2))
                    }
                } else if nreg == 1 {
                    let low_mask = if width == 32 { 7 } else { 3 };
                    let low_bits = if width == 32 { 3 } else { 2 };
                    (
                        (1 << 15) | (low_mask << 10),
                        ((i >> low_bits) << 15) | ((i & low_mask) << 10),
                    )
                } else {
                    let high_mask = if width == 32 { 3 } else { 1 };
                    (
                        (high_mask << 10) | (3 << 1),
                        ((i >> 2) << 10) | ((i & 3) << 1),
                    )
                };
                let word = (word & !clear) | bits;
                let c = Case::Matrix {
                    word,
                    width,
                    nreg,
                    n,
                    m,
                    v,
                    offset,
                    index: index as i16,
                    parts,
                    rows,
                    group,
                    left_unsigned,
                    right_unsigned,
                    subtract,
                };
                for svl in SVLS {
                    check(c, svl, index % 8, u64::from(u32::MAX));
                }
            }
        }
    }
}
#[test]
fn za_disabled_with_streaming_enabled_fails_before_matrix_or_vector_inputs() {
    for &c in CASES {
        if !matches!(c, Case::Matrix { .. }) {
            continue;
        }
        let mut s = State::new(c, 0, 0);
        s.svcr = 1;
        assert!(matches!(
            evaluate(&recipe(word(c), 128).unwrap(), &s),
            Err(EvalError::UnsupportedContext)
        ));
        assert!(s.reads.borrow().iter().all(|r| r.bank == "a64.svcr"));
    }
}

#[test]
fn multivector_round_shifts_full_signed_counts_and_clamped_boundaries() {
    let mut seen = std::collections::HashSet::new();
    for &c in CASES {
        if let Case::Shift {
            width,
            nreg,
            m,
            group,
            unsigned,
            ..
        } = c
        {
            if !seen.insert((width, nreg, group, unsigned)) {
                continue;
            }
            for count in [
                -129i128, -128, -65, -64, -63, -33, -32, -31, -17, -16, -15, -9, -8, -7, -1, 0, 1,
                7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
            ] {
                if count < -(1i128 << (width - 1)) || count > (1i128 << (width - 1)) - 1 {
                    continue;
                }
                for svl in SVLS {
                    let mut state = State::new(c, (count.unsigned_abs() % 8) as u16, 0);
                    state.shifts = Some((m, if group { nreg } else { 1 }, count));
                    check_state(c, svl, state);
                }
            }
        }
    }
}

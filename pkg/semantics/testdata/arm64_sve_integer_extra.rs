#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 16],
    x: [u64; 31],
    sp: u64,
    sm: u64,
    fa: u64,
    missing: Option<u16>,
    reads: RefCell<Vec<Register>>,
}
impl State {
    fn new() -> Self {
        Self {
            z: std::array::from_fn(|n| {
                std::array::from_fn(|i| {
                    0x9e3779b97f4a7c15u64
                        .wrapping_mul((n * 37 + i + 1) as u64)
                        .rotate_left((i % 63) as u32)
                })
            }),
            p: [[u64::MAX; 4]; 16],
            x: std::array::from_fn(|n| u64::MAX - (n as u64) * 17),
            sp: 0xffff_ffff_ffff_ffe0,
            sm: 0,
            fa: 0,
            missing: None,
            reads: RefCell::new(vec![]),
        }
    }
    fn get(&self, n: u32, e: u16, w: u8) -> u64 {
        let bit = e * u16::from(w);
        (self.z[n as usize][usize::from(bit / 64)] >> (bit % 64)) & mask(w)
    }
    fn put(&mut self, n: u32, e: u16, w: u8, v: u64) {
        let bit = e * u16::from(w);
        let out = &mut self.z[n as usize][usize::from(bit / 64)];
        *out = (*out & !(mask(w) << (bit % 64))) | ((v & mask(w)) << (bit % 64));
    }
    fn predicate(&mut self, g: usize, w: u8, mode: u8, vl: u16) {
        self.p[g] = [0; 4];
        for e in 0..vl / u16::from(w) {
            let bit = e * u16::from(w) / 8;
            let active = match mode {
                0 => false,
                1 => true,
                2 => e % 3 == 1,
                _ => e == 0 || e + 1 == vl / u16::from(w),
            };
            if active {
                self.p[g][usize::from(bit / 64)] |= 1 << (bit % 64);
            }
            if w > 8 {
                let junk = bit + 1;
                if junk < vl / 8 {
                    self.p[g][usize::from(junk / 64)] |= 1 << (junk % 64);
                }
            }
        }
    }
    fn active(&self, g: usize, e: u16, w: u8) -> bool {
        let bit = e * u16::from(w) / 8;
        self.p[g][usize::from(bit / 64)] & (1 << (bit % 64)) != 0
    }
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        match r.bank {
            "a64.vector64" => {
                if self.missing == Some(r.index / 32) {
                    return Value::unknown(64);
                }
                Value::known(
                    64,
                    self.z[usize::from(r.index / 32)][usize::from(r.index % 32)],
                )
            }
            "a64.predicate64" => Value::known(
                64,
                self.p[usize::from(r.index / 4)][usize::from(r.index % 4)],
            ),
            "a64.gpr" => Value::known(64, self.x[usize::from(r.index)]),
            "a64.sp" => Value::known(64, self.sp),
            "a64.svcr" => Value::known(64, self.sm),
            "a64.sme_fa64" => Value::known(1, self.fa),
            _ => panic!("unexpected integer input {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("integer family accessed memory")
    }
}
fn mask(w: u8) -> u64 {
    if w == 64 {
        u64::MAX
    } else {
        (1 << w) - 1
    }
}
fn signed(v: u64, w: u8) -> i128 {
    let v = (v & mask(w)) as i128;
    if v & (1i128 << (w - 1)) != 0 {
        v - (1i128 << w)
    } else {
        v
    }
}
fn reference_shift(v: u64, count: u64, op: u32, w: u8) -> u64 {
    let n = count.min(u64::from(w)) as u32;
    match op {
        0 => (signed(v, w) >> n) as u64 & mask(w),
        1 => {
            if n >= u32::from(w) {
                0
            } else {
                v >> n
            }
        }
        _ => {
            if n >= u32::from(w) {
                0
            } else {
                (v << n) & mask(w)
            }
        }
    }
}
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_integer_extra::a64(word, 0x1000, vl)
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x}"));
    assert_eq!(r.support, Support::Full, "{word:08x}");
    r.validate().unwrap();
    r
}
fn vector(word: u32, vl: u16, s: &State, d: u32, w: u8, want: Vec<u64>) {
    let r = build(word, vl);
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x} VL{vl}: {e:?}"));
    assert_eq!(t.trap, None);
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
    assert_eq!(t.registers.len(), usize::from(vl / 64));
    for (chunk, out) in t.registers.iter().enumerate() {
        assert_eq!(
            out.register,
            Register {
                bank: "a64.vector64",
                index: d as u16 * 32 + chunk as u16
            }
        );
        let per = 64 / usize::from(w);
        let expected = (0..per).fold(0, |a, k| {
            a | ((want[chunk * per + k] & mask(w)) << (k * usize::from(w)))
        });
        assert_eq!(
            out.value,
            Value::known(64, expected),
            "{word:08x} VL{vl} chunk{chunk} w{w}"
        );
    }
}
fn immediate(base: u32, w: u8, amount: u8, left: bool, asrd: bool) -> u32 {
    let encoded = if left {
        u32::from(w + amount)
    } else {
        u32::from(2 * w - amount)
    };
    let tsize = encoded >> 3;
    let imm = encoded & 7;
    if asrd {
        base | ((tsize >> 2) << 22) | ((tsize & 3) << 8) | (imm << 5)
    } else {
        base | ((tsize >> 2) << 22) | ((tsize & 3) << 19) | (imm << 16)
    }
}
#[test]
fn scalar_vl_lengths_signed_immediates_sp_zr_alias_and_wrap() {
    for vl in VLS {
        for base in [0x04205000, 0x04605000, 0x04bf5000] {
            for imm in -32i64..32 {
                for n in [0u32, 7, 31] {
                    for d in [0u32, n, 31] {
                        let s = State::new();
                        let word = base
                            | (((imm as u32) & 63) << 5)
                            | d
                            | if base == 0x04bf5000 { 0 } else { n << 16 };
                        let r = build(word, vl);
                        let t = evaluate(&r, &s).unwrap();
                        let scale = if base == 0x04605000 { vl / 64 } else { vl / 8 };
                        let offset = imm * i64::from(scale);
                        let expected = if base == 0x04bf5000 {
                            offset as u64
                        } else {
                            (if n == 31 { s.sp } else { s.x[n as usize] })
                                .wrapping_add(offset as u64)
                        };
                        if base == 0x04bf5000 && d == 31 {
                            assert!(t.registers.is_empty());
                        } else {
                            assert_eq!(t.registers.len(), 1);
                            assert_eq!(
                                t.registers[0].register,
                                Register {
                                    bank: if d == 31 { "a64.sp" } else { "a64.gpr" },
                                    index: if d == 31 { 0 } else { d as u16 }
                                }
                            );
                            assert_eq!(t.registers[0].value, Value::known(64, expected));
                        }
                        assert!(s
                            .reads
                            .borrow()
                            .iter()
                            .all(|r| r.bank == "a64.gpr" || r.bank == "a64.sp"));
                    }
                }
            }
        }
    }
    let r = semantics::arm64_sve_integer_extra::a64(0x04bf5020, u64::MAX - 3, 128).unwrap();
    assert_eq!(
        evaluate(&r, &State::new()).unwrap().next_pc,
        Value::known(64, 0)
    );
}
#[test]
fn adr_all_offset_forms_scaling_wrap_and_alias() {
    for vl in VLS {
        for (base, w, source, signed_offset) in [
            (0x04a0a000, 32u8, 32u8, false),
            (0x04e0a000, 64, 64, false),
            (0x0420a000, 64, 32, true),
            (0x0460a000, 64, 32, false),
        ] {
            for scale in 0..4 {
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                    let s = State::new();
                    let expected = (0..vl / u16::from(w))
                        .map(|e| {
                            let off = s.get(m, e, w) & mask(source);
                            let off = if signed_offset {
                                signed(off, source) as u64
                            } else {
                                off
                            };
                            s.get(n, e, w).wrapping_add(off.wrapping_shl(scale)) & mask(w)
                        })
                        .collect();
                    vector(
                        base | (m << 16) | (n << 5) | d | (scale << 10),
                        vl,
                        &s,
                        d,
                        w,
                        expected,
                    );
                }
            }
        }
    }
    let mut s = State::new();
    s.sm = 1;
    s.missing = Some(1);
    let r = build(0x04a2a020, 128);
    assert!(evaluate(&r, &s).is_err());
    assert!(s
        .reads
        .borrow()
        .iter()
        .all(|r| r.bank == "a64.svcr" || r.bank == "a64.sme_fa64"));
    s.fa = 1;
    s.missing = None;
    assert!(evaluate(&r, &s).is_ok());
}
#[test]
fn asrd_all_widths_shifts_predicates_and_negative_rounding() {
    for vl in VLS {
        for w in [8u8, 16, 32, 64] {
            for amount in 1..=w {
                for mode in 0..4 {
                    let mut s = State::new();
                    s.predicate(3, w, mode, vl);
                    for e in 0..vl / u16::from(w) {
                        let v = match e % 8 {
                            0 => 0,
                            1 => 1,
                            2 => mask(w),
                            3 => 1 << (w - 1),
                            4 => (1 << (w - 1)) + 1,
                            5 => mask(w) - 1,
                            _ => s.get(1, e, w),
                        };
                        s.put(1, e, w, v);
                    }
                    let want = (0..vl / u16::from(w))
                        .map(|e| {
                            let x = s.get(1, e, w);
                            if s.active(3, e, w) {
                                (signed(x, w) / (1i128 << amount)) as u64 & mask(w)
                            } else {
                                x
                            }
                        })
                        .collect();
                    vector(
                        immediate(0x04048000, w, amount, false, true) | (3 << 10) | 1,
                        vl,
                        &s,
                        1,
                        w,
                        want,
                    );
                }
            }
        }
    }
}
#[test]
fn high_products_all_widths_unsigned_signed_aliases_and_extremes() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8u8 << size;
            for unsigned in [false, true] {
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                    for phase in 0..4 {
                        let mut s = State::new();
                        for e in 0..vl / u16::from(w) {
                            for (reg, k) in [(n, phase), (m, phase + 3)] {
                                let v = match (e + k) % 8 {
                                    0 => 0,
                                    1 => 1,
                                    2 => mask(w),
                                    3 => 1 << (w - 1),
                                    4 => (1 << (w - 1)) - 1,
                                    _ => s.get(reg, e, w),
                                };
                                s.put(reg, e, w, v);
                            }
                        }
                        let want = (0..vl / u16::from(w))
                            .map(|e| {
                                let (a, b) = (s.get(n, e, w), s.get(m, e, w));
                                if unsigned {
                                    ((u128::from(a) * u128::from(b)) >> w) as u64 & mask(w)
                                } else {
                                    ((signed(a, w) * signed(b, w)) >> w) as u64 & mask(w)
                                }
                            })
                            .collect();
                        vector(
                            0x04206800
                                | if unsigned { 1 << 10 } else { 0 }
                                | (size << 22)
                                | (m << 16)
                                | (n << 5)
                                | d,
                            vl,
                            &s,
                            d,
                            w,
                            want,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn wide_count_shifts_full_u64_counts_aliases_and_predicate_laziness() {
    for vl in VLS {
        for size in 0..3 {
            let w = 8u8 << size;
            let counts = [
                0,
                u64::from(w - 1),
                u64::from(w),
                u64::from(w + 1),
                63,
                64,
                255,
                u64::MAX,
            ];
            for op in [0u32, 1, 3] {
                for pred in [false, true] {
                    for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                        for phase in 0..8 {
                            let mut s = State::new();
                            for chunk in 0..vl / 64 {
                                s.z[m as usize][usize::from(chunk)] =
                                    counts[(usize::from(chunk) + phase) % counts.len()];
                            }
                            s.predicate(2, w, (phase % 4) as u8, vl);
                            let source = if pred { d } else { n };
                            let want = (0..vl / u16::from(w))
                                .map(|e| {
                                    let old = s.get(d, e, w);
                                    if pred && !s.active(2, e, w) {
                                        old
                                    } else {
                                        reference_shift(
                                            s.get(source, e, w),
                                            s.z[m as usize][usize::from(e * u16::from(w) / 64)],
                                            op,
                                            w,
                                        )
                                    }
                                })
                                .collect();
                            let word = if pred {
                                0x04188000 | (op << 16) | (2 << 10) | (m << 5) | d
                            } else {
                                0x04208000 | (op << 10) | (m << 16) | (n << 5) | d
                            };
                            vector(word | (size << 22), vl, &s, d, w, want);
                        }
                    }
                }
            }
        }
    }
    for base in [0x04188000, 0x04198000, 0x041b8000] {
        let mut s = State::new();
        s.p[0] = [0; 4];
        s.missing = Some(2);
        vector(
            base | (2 << 5) | 1,
            2048,
            &s,
            1,
            8,
            (0..256).map(|e| s.get(1, e, 8)).collect(),
        );
        assert!(!s
            .reads
            .borrow()
            .iter()
            .any(|r| r.bank == "a64.vector64" && r.index / 32 == 2));
    }
}
#[test]
fn reversed_shifts_full_element_counts_and_inactive_sources() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8u8 << size;
            for op in [0u32, 1, 3] {
                for (d, m) in [(0, 1), (1, 1), (31, 31)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        s.predicate(1, w, mode, vl);
                        for e in 0..vl / u16::from(w) {
                            s.put(
                                d,
                                e,
                                w,
                                match e % 5 {
                                    0 => 0,
                                    1 => u64::from(w - 1),
                                    2 => u64::from(w),
                                    3 => u64::from(w + 1),
                                    _ => mask(w),
                                },
                            );
                        }
                        let want = (0..vl / u16::from(w))
                            .map(|e| {
                                let old = s.get(d, e, w);
                                if s.active(1, e, w) {
                                    reference_shift(s.get(m, e, w), old, op, w)
                                } else {
                                    old
                                }
                            })
                            .collect();
                        vector(
                            0x04148000 | (op << 16) | (size << 22) | (1 << 10) | (m << 5) | d,
                            vl,
                            &s,
                            d,
                            w,
                            want,
                        );
                    }
                }
            }
        }
    }
    for base in [0x04148000, 0x04158000, 0x04178000] {
        let mut s = State::new();
        s.p[0] = [0; 4];
        s.missing = Some(2);
        vector(
            base | (2 << 5) | 1,
            2048,
            &s,
            1,
            8,
            (0..256).map(|e| s.get(1, e, 8)).collect(),
        );
        assert!(!s
            .reads
            .borrow()
            .iter()
            .any(|r| r.bank == "a64.vector64" && r.index / 32 == 2));
    }
}
#[test]
fn widening_all_sources_top_bottom_signedness_immediates_and_aliases() {
    for vl in VLS {
        for source in [8u8, 16, 32] {
            for amount in 0..source {
                let encoded = u32::from(source + amount);
                let tsize = encoded >> 3;
                for unsigned in [false, true] {
                    for top in [false, true] {
                        for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                            let s = State::new();
                            let want = (0..vl / u16::from(2 * source))
                                .map(|e| {
                                    let v = s.get(n, 2 * e + u16::from(top), source);
                                    let v = if unsigned {
                                        v as i128
                                    } else {
                                        signed(v, source)
                                    };
                                    ((v << amount) as u64) & mask(2 * source)
                                })
                                .collect();
                            let word = 0x4500a000
                                | ((tsize >> 2) << 22)
                                | ((tsize & 3) << 19)
                                | ((encoded & 7) << 16)
                                | if unsigned { 1 << 11 } else { 0 }
                                | if top { 1 << 10 } else { 0 }
                                | (n << 5)
                                | d;
                            vector(word, vl, &s, d, source * 2, want);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn shift_accumulate_insert_all_immediates_modular_edges_and_aliases() {
    for vl in VLS {
        for w in [8u8, 16, 32, 64] {
            for base in [0x4500e000u32, 0x4500e400, 0x4500f000, 0x4500f400] {
                let left = base == 0x4500f400;
                for amount in if left { 0..w } else { 1..w + 1 } {
                    for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                        let s = State::new();
                        let want = (0..vl / u16::from(w))
                            .map(|e| {
                                let old = s.get(d, e, w);
                                let v = s.get(n, e, w);
                                match base {
                                    0x4500e000 => {
                                        old.wrapping_add((signed(v, w) >> amount) as u64) & mask(w)
                                    }
                                    0x4500e400 => {
                                        old.wrapping_add(if amount == w { 0 } else { v >> amount })
                                            & mask(w)
                                    }
                                    0x4500f000 => {
                                        let insert = if amount == w { 0 } else { v >> amount };
                                        let keep = if amount == w {
                                            mask(w)
                                        } else {
                                            mask(w) ^ (mask(w) >> amount)
                                        };
                                        (old & keep) | insert
                                    }
                                    _ => {
                                        let keep =
                                            if amount == 0 { 0 } else { (1u64 << amount) - 1 };
                                        ((old & keep) | (v << amount)) & mask(w)
                                    }
                                }
                            })
                            .collect();
                        vector(
                            immediate(base, w, amount, left, false) | (n << 5) | d,
                            vl,
                            &s,
                            d,
                            w,
                            want,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn reserved_invalid_context_and_nearby_classes_are_not_full() {
    for word in [
        0x04048000, 0x4500a000, 0x4500a400, 0x4500a800, 0x4500ac00, 0x4500e000, 0x4500e400,
        0x4500f000, 0x4500f400, 0x04d88000, 0x04d98000, 0x04db8000, 0x04e08000, 0x04e08400,
        0x04e08c00,
    ] {
        for vl in VLS {
            assert!(
                matches!(recipe(word, vl).unwrap().support, Support::Unsupported(_)),
                "{word:08x}"
            );
        }
    }
    for vl in [0, 1, 64, 129, 384, 768, 4096] {
        assert!(matches!(
            recipe(0x04205000, vl).unwrap().support,
            Support::Unsupported(_)
        ));
    }
    for word in [
        0x04008000, 0x04018000, 0x04038000, 0x04206000, 0x04206400, 0x4500e800, 0x4500ec00,
        0x04a09000, 0xd503201f, 0x65008000,
    ] {
        assert!(
            semantics::arm64_sve_integer_extra::a64(word, 0x1000, 128).is_none(),
            "unexpected helper ownership {word:08x}"
        );
    }
}

fn lowered_nodes(recipe: &Recipe) -> usize {
    #[derive(Clone, Copy)]
    struct Native {
        nodes: usize,
        width: u8,
        immutable: bool,
    }
    fn lower(e: &Expr, temps: &[Native]) -> Native {
        let width = e.ty.width;
        let nodes = match &e.kind {
            ExprKind::Constant(_) => {
                return Native {
                    nodes: 1,
                    width,
                    immutable: true,
                }
            }
            ExprKind::Temporary(i) => return temps[*i],
            ExprKind::Register(_) => 1,
            ExprKind::RequireContext { condition, .. } => 1 + lower(condition, temps).nodes,
            ExprKind::Unary { op: _, value } => 1 + lower(value, temps).nodes,
            ExprKind::Binary { left, right, .. } => {
                1 + lower(left, temps).nodes + lower(right, temps).nodes
            }
            ExprKind::Select { condition, yes, no } => {
                1 + lower(condition, temps).nodes + lower(yes, temps).nodes + lower(no, temps).nodes
            }
            ExprKind::Cast { value, .. } => {
                if width < value.ty.width && matches!(value.kind, ExprKind::Register(_)) {
                    1
                } else {
                    let v = lower(value, temps);
                    v.nodes + usize::from(v.width != width)
                }
            }
            ExprKind::Extract { value, .. } => {
                if matches!(value.kind, ExprKind::Register(_)) {
                    1
                } else {
                    let v = lower(value, temps);
                    v.nodes + 2 + usize::from(v.width != width)
                }
            }
            other => panic!("unmodeled bit permutation lowering {other:?}"),
        };
        Native {
            nodes,
            width,
            immutable: false,
        }
    }
    assert!(
        recipe.atomics.is_empty()
            && recipe.wide_loads.is_empty()
            && recipe.always_writes.is_empty()
    );
    assert_eq!(recipe.flow.kind, FlowKind::Next);
    let guard = usize::from(recipe.guard != Expr::constant(1, 1));
    let mut total = if guard == 1 {
        lower(&recipe.guard, &[]).nodes
    } else {
        0
    };
    let mut temps = vec![];
    for expr in &recipe.temporaries {
        let v = lower(expr, &temps);
        if !v.immutable {
            total += v.nodes + guard;
        }
        temps.push(Native {
            nodes: 1,
            width: v.width,
            immutable: true,
        });
    }
    for effect in &recipe.effects {
        let Effect::WriteRegister {
            destination,
            value,
            policy,
        } = effect
        else {
            panic!("unmodeled bit permutation effect")
        };
        let v = lower(value, &temps);
        if !v.immutable {
            total += v.nodes + guard;
        }
        total += 1 + guard;
        if *policy == WritePolicy::ZeroUpper && destination.parent_width != value.ty.width {
            total += 1;
        }
    }
    total
}

#[test]
fn native_graph_budget_at_maximum_length() {
    let mut maximum = 0;
    for w in [8u8, 16, 32, 64] {
        let size = u32::from(w.ilog2() - 3);
        for base in [
            0x04206800u32,
            0x04206c00,
            0x04148000,
            0x04158000,
            0x04178000,
        ] {
            let r = build(base | (size << 22) | (2 << 5), 2048);
            maximum = maximum.max(lowered_nodes(&r));
        }
        for amount in [1, w] {
            let r = build(immediate(0x04048000, w, amount, false, true), 2048);
            maximum = maximum.max(lowered_nodes(&r));
        }
        if w != 64 {
            for base in [
                0x04188000u32,
                0x04198000,
                0x041b8000,
                0x04208000,
                0x04208400,
                0x04208c00,
            ] {
                let r = build(base | (size << 22) | (2 << 5), 2048);
                maximum = maximum.max(lowered_nodes(&r));
            }
        }
        for base in [0x4500e000u32, 0x4500e400, 0x4500f000, 0x4500f400] {
            let left = base == 0x4500f400;
            let r = build(
                immediate(base, w, if left { w - 1 } else { w }, left, false),
                2048,
            );
            maximum = maximum.max(lowered_nodes(&r));
        }
    }
    for word in [
        0x04a0a000u32,
        0x04e0a000,
        0x0420a000,
        0x0460a000,
        0x4540a000,
        0x4540a400,
        0x4540a800,
        0x4540ac00,
    ] {
        maximum = maximum.max(lowered_nodes(&build(word, 2048)));
    }
    println!("maximum modeled native nodes: {maximum}");
    assert!(
        maximum <= 32768,
        "native admission graph budget exceeded: {maximum}"
    );
}

#[test]
fn review_asrd_exhaustive_signed_bytes_all_lengths_and_immediates() {
    // June ASL adds 2^shift-1 to negative mathematical integers before ASR.
    // Signed division is an independent reference, including negative values
    // whose discarded low bits are zero and the maximal shift of eight.
    for vl in VLS {
        let elements = vl / 8;
        for start in (0..256u16).step_by(usize::from(elements)) {
            for amount in 1..=8 {
                let mut s = State::new();
                let expected = (0..elements)
                    .map(|e| {
                        let bits = ((start + e) % 256) as u8;
                        s.put(1, e, 8, u64::from(bits));
                        ((i16::from(bits as i8) / (1i16 << amount)) as u8) as u64
                    })
                    .collect();
                vector(
                    immediate(0x04048000, 8, amount, false, true) | 1,
                    vl,
                    &s,
                    1,
                    8,
                    expected,
                );
            }
        }
    }
}

#[test]
fn review_adr_explicit_low_word_sign_extension_and_modular_goldens() {
    for vl in VLS {
        for (base, width, addr, offset, expected) in [
            // SXTW uses low32 of each64-bit offset and scales after extension.
            (
                0x0420a000,
                64,
                0x8000_0000_0000_0000,
                0xaaaa_bbbb_8000_0001,
                0x7fff_fffc_0000_0008,
            ),
            // UXTW discards upper offset bits but does not sign-extend bit31.
            (
                0x0460a000,
                64,
                0x8000_0000_0000_0000,
                0xaaaa_bbbb_8000_0001,
                0x8000_0004_0000_0008,
            ),
            // Packed .S arithmetic wraps independently in each32-bit lane.
            (0x04a0a000, 32, 0xffff_fffc, 0x8000_0001, 4),
            // Packed .D retains the entire64-bit offset and wraps at64 bits.
            (
                0x04e0a000,
                64,
                0x8000_0000_0000_0000,
                0x8000_0001_8000_0001,
                0x8000_000c_0000_0008,
            ),
        ] {
            let mut s = State::new();
            for e in 0..vl / u16::from(width) {
                s.put(1, e, width, addr);
                s.put(2, e, width, offset);
            }
            for d in [0, 1, 2] {
                vector(
                    base | (2 << 16) | (3 << 10) | (1 << 5) | d,
                    vl,
                    &s,
                    d,
                    width,
                    vec![expected; usize::from(vl / u16::from(width))],
                );
            }
        }
    }
}

#[test]
fn absolute_differences_cross_long_clamps_and_complex_add_follow_integer_math() {
    let bases = [
        0x4500f800u32,
        0x4500fc00,
        0x4500c000,
        0x4500c400,
        0x4500c800,
        0x4500cc00,
        0x45003000,
        0x45003400,
        0x45003800,
        0x45003c00,
        0x45008000,
        0x45008800,
        0x45008c00,
        0x4400c000,
        0x4400c400,
        0x4500d800,
    ];
    for vl in VLS {
        for (op, base) in bases.into_iter().enumerate() {
            for size in 0..4 {
                let w = 8u8 << size;
                let long = (2..=12).contains(&op);
                if long && size == 0 {
                    continue;
                }
                for d in [0u32, 1, 2] {
                    for rotation in 0..if op == 15 { 2 } else { 1 } {
                        let mut s = State::new();
                        let source = if long { w / 2 } else { w };
                        let bounds = [
                            0,
                            1,
                            mask(source),
                            1 << (source - 1),
                            mask(source) >> 1,
                            mask(source) - 1,
                        ];
                        for n in [0u32, 1, 2] {
                            for e in 0..vl / u16::from(source) {
                                s.put(
                                    n,
                                    e,
                                    source,
                                    bounds[(usize::from(e) + n as usize) % bounds.len()],
                                );
                            }
                        }
                        let want = (0..vl / u16::from(w))
                            .map(|e| {
                                let acc = s.get(d, e, w);
                                let value = match op {
                                    0 | 1 => {
                                        let a = s.get(1, e, w);
                                        let b = s.get(2, e, w);
                                        let delta = if op == 0 {
                                            (signed(a, w) - signed(b, w)).unsigned_abs()
                                        } else {
                                            u128::from(a.abs_diff(b))
                                        };
                                        u128::from(acc).wrapping_add(delta) as u64
                                    }
                                    2..=9 => {
                                        let top = ((op - 2) % 2) as u16;
                                        let a = s.get(1, 2 * e + top, source);
                                        let b = s.get(2, 2 * e + top, source);
                                        let unsigned = matches!(op, 4 | 5 | 8 | 9);
                                        let delta = if unsigned {
                                            u128::from(a.abs_diff(b))
                                        } else {
                                            (signed(a, source) - signed(b, source)).unsigned_abs()
                                        };
                                        (if op <= 5 {
                                            u128::from(acc) + delta
                                        } else {
                                            delta
                                        }) as u64
                                    }
                                    10..=12 => {
                                        let top = u16::from(op == 12);
                                        let a = signed(s.get(1, 2 * e + top, source), source);
                                        let b = signed(s.get(2, 2 * e + (top ^ 1), source), source);
                                        (if op == 10 { a + b } else { a - b }) as u64
                                    }
                                    13 | 14 => {
                                        let to_int = |x| {
                                            if op == 13 {
                                                signed(x, w)
                                            } else {
                                                i128::from(x)
                                            }
                                        };
                                        to_int(s.get(1, e, w))
                                            .max(to_int(acc))
                                            .min(to_int(s.get(2, e, w)))
                                            as u64
                                    }
                                    _ => {
                                        let a = signed(acc, w);
                                        let b = signed(s.get(1, e ^ 1, w), w);
                                        (if (e % 2 == 0) == (rotation == 0) {
                                            a - b
                                        } else {
                                            a + b
                                        }) as u64
                                    }
                                };
                                value & mask(w)
                            })
                            .collect();
                        let word = base
                            | (size << 22)
                            | (1 << 5)
                            | d
                            | if op == 15 { rotation << 10 } else { 2 << 16 };
                        vector(word, vl, &s, d, w, want);
                    }
                }
            }
        }
    }
    for base in &bases[2..13] {
        assert!(matches!(
            recipe(*base, 128).unwrap().support,
            Support::Unsupported(_)
        ));
    }
}

#[test]
fn review_absolute_difference_exhaustive_byte_pairs_normal_and_long() {
    for (base, long, unsigned, accumulate, top) in [
        (0x4500f800, false, false, true, 0),
        (0x4500fc00, false, true, true, 0),
        (0x4500c000, true, false, true, 0),
        (0x4500c400, true, false, true, 1),
        (0x4500c800, true, true, true, 0),
        (0x4500cc00, true, true, true, 1),
        (0x45003000, true, false, false, 0),
        (0x45003400, true, false, false, 1),
        (0x45003800, true, true, false, 0),
        (0x45003c00, true, true, false, 1),
    ] {
        let w = if long { 16 } else { 8 };
        let lanes = 128 / usize::from(w);
        let r = build(
            base | if long { 1 << 22 } else { 0 } | (2 << 16) | (1 << 5),
            128,
        );
        for a in 0u16..256 {
            for first in (0u16..256).step_by(lanes) {
                let mut s = State::new();
                let mut packed = [0u64; 2];
                for e in 0..lanes {
                    let b = first + e as u16;
                    let index = if long { 2 * e + top } else { e };
                    s.put(1, index as u16, 8, u64::from(a));
                    s.put(2, index as u16, 8, u64::from(b));
                    let old = (0xfff0 + e as u64) & mask(w);
                    s.put(0, e as u16, w, old);
                    let cv = |x: u16| {
                        if unsigned {
                            x as i16
                        } else {
                            x as u8 as i8 as i16
                        }
                    };
                    let difference = (cv(a) - cv(b)).unsigned_abs() as u64;
                    let expected = (if accumulate {
                        old + difference
                    } else {
                        difference
                    }) & mask(w);
                    let bit = e * usize::from(w);
                    packed[bit / 64] |= expected << (bit % 64);
                }
                let t = evaluate(&r, &s).unwrap();
                assert_eq!(
                    [t.registers[0].value, t.registers[1].value],
                    packed.map(|v| Value::known(64, v)),
                    "{base:08x} a{a} b{first}"
                );
            }
        }
    }
}
#[test]
fn review_signed64_wrap_reversed_clamps_and_complex_rotation_goldens() {
    for vl in VLS {
        // |MIN-MAX|=2^64-1: adding1 wraps to0 in both operand orders.
        let mut s = State::new();
        for e in 0..vl / 64 {
            s.put(0, e, 64, 1);
            s.put(1, e, 64, if e % 2 == 0 { 1 << 63 } else { (1 << 63) - 1 });
            s.put(2, e, 64, if e % 2 == 0 { (1 << 63) - 1 } else { 1 << 63 });
        }
        vector(
            0x45c0f800 | (2 << 16) | (1 << 5),
            vl,
            &s,
            0,
            64,
            vec![0; usize::from(vl / 64)],
        );
        for size in 0..4 {
            let w = 8 << size;
            let min = 1u64 << (w - 1);
            let max = min - 1;
            for (base, lower, upper, expected) in [
                (0x4400c000, max, min, min), // signed bounds reversed
                (0x4400c400, mask(w), 1, 1), // unsigned bounds reversed
                (0x4400c000, min, max, 0),
                (0x4400c400, 1, mask(w), 1),
            ] {
                let mut s = State::new();
                for e in 0..vl / u16::from(w) {
                    s.put(0, e, w, 0);
                    s.put(1, e, w, lower);
                    s.put(2, e, w, upper);
                }
                vector(
                    base | (size << 22) | (2 << 16) | (1 << 5),
                    vl,
                    &s,
                    0,
                    w,
                    vec![expected; usize::from(vl / u16::from(w))],
                );
            }
            for alias in [false, true] {
                for rotation in 0..2 {
                    let mut s = State::new();
                    for e in 0..vl / u16::from(w) {
                        s.put(0, e, w, if e % 2 == 0 { 2 } else { mask(w) - 2 });
                        s.put(31, e, w, if e % 2 == 0 { 11 } else { mask(w) - 6 });
                    }
                    let expected = match (alias, rotation) {
                        (false, 0) => [9, 8],
                        (false, _) => [mask(w) - 4, mask(w) - 13],
                        (true, 0) => [18, 4],
                        (true, _) => [4, mask(w) - 17],
                    };
                    let want = (0..vl / u16::from(w))
                        .map(|e| expected[usize::from(e % 2)])
                        .collect();
                    vector(
                        0x4500d800
                            | (size << 22)
                            | (rotation << 10)
                            | (31 << 5)
                            | if alias { 31 } else { 0 },
                        vl,
                        &s,
                        if alias { 31 } else { 0 },
                        w,
                        want,
                    );
                }
            }
        }
    }
}

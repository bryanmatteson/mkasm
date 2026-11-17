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
    absent: Option<Register>,
    x: [u64; 31],
    sp: u64,
    sm: u64,
    fa: u64,
    missing: Option<u16>,
    reads: RefCell<Vec<Register>>,
    unavailable_chunks: Vec<u16>,
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
            absent: None,
            unavailable_chunks: vec![],
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
        if self.absent == Some(r) {
            return Value::unknown(64);
        }
        match r.bank {
            "a64.vector64" => {
                if self.missing == Some(r.index / 32) || self.unavailable_chunks.contains(&r.index)
                {
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
const OPS: [u32; 10] = [
    0x25205010, 0x25205011, 0x25205811, 0x25205810, 0x25205411, 0x25205c10, 0x25205c11, 0x25205410,
    0x25203010, 0x25203000,
];
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_while_extra::a64(word, 0x1000, vl)
}
fn build(word: u32, vl: u16) -> Recipe {
    let r = recipe(word, vl).unwrap();
    assert_eq!(r.support, Support::Full, "{word:08x}");
    r.validate().unwrap();
    r
}
fn input(s: &State, n: u32) -> u64 {
    if n == 31 {
        0
    } else {
        s.x[n as usize]
    }
}
fn reference(a: u64, z: u64, op: usize, w: u8, vl: u16) -> Vec<bool> {
    let count = usize::from(vl / u16::from(w)) * if op < 8 { 2 } else { 1 };
    let mut out = vec![false; count];
    if op < 8 {
        let unsigned = matches!(op, 2 | 3 | 5 | 6);
        let ascending = op >= 4;
        let inclusive = matches!(op, 0 | 3 | 4 | 6);
        let mut sticky = true;
        for step in 0..count {
            let cur = if ascending {
                a.wrapping_add(step as u64)
            } else {
                a.wrapping_sub(step as u64)
            };
            let lhs = if unsigned {
                cur as i128
            } else {
                cur as i64 as i128
            };
            let rhs = if unsigned {
                z as i128
            } else {
                z as i64 as i128
            };
            let condition = match (ascending, inclusive) {
                (true, true) => lhs <= rhs,
                (true, false) => lhs < rhs,
                (false, true) => lhs >= rhs,
                (false, false) => lhs > rhs,
            };
            sticky &= condition;
            out[if ascending { step } else { count - 1 - step }] = sticky;
        }
    } else {
        let raw = z as i128 - a as i128;
        let distance = if op == 8 { raw.abs() } else { raw };
        let diff = distance.div_euclid(i128::from(w / 8));
        for (e, v) in out.iter_mut().enumerate() {
            *v = diff <= 0 || (e as i128) < diff;
        }
    }
    out
}
fn check(word: u32, vl: u16, s: &State, w: u8, pair: bool, want: &[bool]) {
    let r = build(word, vl);
    let t = evaluate(&r, s).unwrap();
    assert_eq!(t.next_pc, Value::known(64, 0x1004));
    assert!(
        t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty() && t.trap.is_none()
    );
    let nregs = if pair { 2 } else { 1 };
    let d = if pair { word & 14 } else { word & 15 };
    let pl = vl / 8;
    let per = usize::from(vl / u16::from(w));
    assert_eq!(t.registers.len(), 4 + usize::from(pl.div_ceil(64)) * nregs);
    for i in 0..nregs {
        let mut expected = s.p[d as usize + i];
        for bit in 0..pl {
            expected[usize::from(bit / 64)] &= !(1 << (bit % 64));
        }
        for e in 0..per {
            if want[i * per + e] {
                let bit = e * u16::from(w / 8) as usize;
                expected[bit / 64] |= 1 << (bit % 64);
            }
        }
        let mut actual = s.p[d as usize + i];
        for out in &t.registers {
            if out.register.bank == "a64.predicate64"
                && out.register.index / 4 == d as u16 + i as u16
            {
                assert!(out.value.is_known());
                actual[usize::from(out.register.index % 4)] = out.value.bits;
            }
        }
        assert_eq!(
            actual,
            expected,
            "word{word:08x} VL{vl} d{}",
            d as usize + i
        );
    }
    let flags = [
        want[0],
        !want.iter().any(|v| *v),
        !want[want.len() - 1],
        false,
    ];
    for (i, v) in flags.into_iter().enumerate() {
        assert_eq!(
            t.registers
                .iter()
                .find(|x| x.register.bank == "a64.nzcv" && x.register.index == i as u16)
                .unwrap()
                .value,
            Value::known(1, u64::from(v)),
            "word{word:08x} VL{vl} flag{i}"
        );
    }
    assert!(!s.reads.borrow().iter().any(|x| x.bank == "a64.sp"
        || x.bank == "a64.vector64"
        || x.bank.starts_with("a64.fp")
        || x.bank == "a64.nzcv"
        || x.bank == "a64.svcr"));
}
#[test]
fn all_relations_widths_lengths_boundary_matrix() {
    let inputs = [
        0,
        1,
        2,
        7,
        8,
        9,
        63,
        64,
        127,
        128,
        u32::MAX as u64,
        0x7ffffffffffffffe,
        0x7fffffffffffffff,
        0x8000000000000000,
        0x8000000000000001,
        u64::MAX - 1,
        u64::MAX,
    ];
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                for a in inputs {
                    for z in inputs {
                        let mut s = State::new();
                        s.x[0] = a;
                        s.x[1] = z;
                        let want = reference(a, z, op, w, vl);
                        check(
                            base | (size << 22) | (1 << 16) | 14,
                            vl,
                            &s,
                            w,
                            op < 8,
                            &want,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn aliases_xzr_and_every_predicate_destination_pair() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                for (n, m) in [(0, 0), (0, 1), (31, 0), (0, 31), (31, 31)] {
                    let s = State::new();
                    let want = reference(input(&s, n), input(&s, m), op, w, vl);
                    for dest in 0..if op < 8 { 8 } else { 16 } {
                        let d = if op < 8 { dest * 2 } else { dest };
                        check(
                            base | (size << 22) | (m << 16) | (n << 5) | d,
                            vl,
                            &s,
                            w,
                            op < 8,
                            &want,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn sticky_wrap_goldens_and_reverse_iteration_flags() {
    let cases = [
        (0, 5, 3, vec![false, true, true, true]),
        (1, 5, 3, vec![false, false, true, true]),
        (7, 3, 5, vec![true, true, false, false]),
        (4, 3, 5, vec![true, true, true, false]),
        (5, u64::MAX - 1, u64::MAX, vec![true, false, false, false]),
        (6, u64::MAX, u64::MAX, vec![true, true, true, true]),
        (3, 0, 1, vec![false, false, false, false]),
        (3, 0, 0, vec![true, true, true, true]),
        (
            0,
            0x8000000000000000,
            0x8000000000000000,
            vec![true, true, true, true],
        ),
        (
            4,
            0x7fffffffffffffff,
            0x7fffffffffffffff,
            vec![true, true, true, true],
        ),
    ];
    for (op, a, z, want) in cases {
        let mut s = State::new();
        s.x[0] = a;
        s.x[1] = z;
        assert_eq!(reference(a, z, op, 64, 128), want);
        check(
            OPS[op] | (3 << 22) | (1 << 16) | 14,
            128,
            &s,
            64,
            true,
            &want,
        );
    }
}
// Independent first-failure derivation: translate signed X values to their
// ordered unsigned rank, then measure the interval before the first failing
// comparison. Unlike the primary loop and the builder, this never increments
// or decrements an architectural operand. Inclusive extreme bounds have no
// failing value in the 64-bit domain, including after wrap.
fn interval_reference(a: u64, z: u64, op: usize, count: usize) -> Vec<bool> {
    assert!(op < 8);
    let bias = if matches!(op, 2 | 3 | 5 | 6) {
        0
    } else {
        1 << 63
    };
    let a = u128::from(a ^ bias);
    let z = u128::from(z ^ bias);
    let ascending = op >= 4;
    let inclusive = matches!(op, 0 | 3 | 4 | 6);
    let span = if inclusive && z == if ascending { u128::from(u64::MAX) } else { 0 } {
        count as u128
    } else if ascending && a <= z {
        z - a + u128::from(inclusive)
    } else if !ascending && a >= z {
        a - z + u128::from(inclusive)
    } else {
        0
    };
    let active = span.min(count as u128) as usize;
    (0..count)
        .map(|e| {
            if ascending {
                e < active
            } else {
                e >= count - active
            }
        })
        .collect()
}
#[test]
fn independent_interval_goldens_wrap_and_complete_pair_frontiers() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let elements = u64::from(vl / u16::from(w));
            let count = 2 * elements as usize;
            let cases = [
                (0, 0),
                (u64::MAX, u64::MAX),
                (1 << 63, 1 << 63),
                ((1 << 63) - 1, (1 << 63) - 1),
                (0, u64::MAX),
                (u64::MAX, 0),
                ((1 << 63) - 1, 1 << 63),
                (1 << 63, (1 << 63) - 1),
                // Values above 32 bits independently detect a guessed W form.
                ((1 << 32) + 7, (1 << 32) + 10),
                ((1 << 32) - 1, (1 << 32) + 1),
                // The first failing position immediately before/at/after the
                // split between even and odd predicates exercises pair NZC.
                (4096, 4096 + elements - 1),
                (4096, 4096 + elements),
                (4096, 4096 + elements + 1),
                (4096 + elements - 1, 4096),
                (4096 + elements, 4096),
                (4096 + elements + 1, 4096),
                (u64::MAX - elements, u64::MAX),
                (elements, 0),
            ];
            for op in 0..8 {
                for (a, z) in cases {
                    let want = interval_reference(a, z, op, count);
                    assert_eq!(
                        reference(a, z, op, w, vl),
                        want,
                        "independent interval op{op} Xn{a:016x} Xm{z:016x} VL{vl} esize{w}"
                    );
                    let mut s = State::new();
                    s.x[0] = a;
                    s.x[1] = z;
                    check(
                        OPS[op] | (size << 22) | (1 << 16) | 14,
                        vl,
                        &s,
                        w,
                        true,
                        &want,
                    );
                }
            }
        }
    }
}
#[test]
fn both_consumed_sources_unknown_and_unconsumed_inputs_not_read() {
    for vl in VLS {
        for size in 0..4 {
            for base in OPS {
                let word = base | (size << 22) | (1 << 16) | 14;
                for index in [0, 1] {
                    let mut s = State::new();
                    let missing = Register {
                        bank: "a64.gpr",
                        index,
                    };
                    s.absent = Some(missing);
                    let t = evaluate(&build(word, vl), &s).unwrap();
                    assert!(s.reads.borrow().contains(&missing));
                    for out in &t.registers {
                        if out.register.bank == "a64.nzcv" {
                            if out.register.index == 3 {
                                assert_eq!(out.value, Value::known(1, 0));
                            } else {
                                assert!(!out.value.is_known(), "word{word:08x} VL{vl} {out:?}");
                            }
                        }
                    }
                    assert!(
                        t.registers
                            .iter()
                            .any(|out| out.register.bank == "a64.predicate64"
                                && !out.value.is_known())
                    );
                }
                for missing in [
                    Register {
                        bank: "a64.gpr",
                        index: 2,
                    },
                    Register {
                        bank: "a64.sp",
                        index: 0,
                    },
                    Register {
                        bank: "a64.svcr",
                        index: 0,
                    },
                    Register {
                        bank: "a64.sme_fa64",
                        index: 0,
                    },
                    Register {
                        bank: "a64.nzcv",
                        index: 0,
                    },
                    Register {
                        bank: "a64.vector64",
                        index: 0,
                    },
                    Register {
                        bank: "a64.predicate64",
                        index: 0,
                    },
                ] {
                    let mut s = State::new();
                    s.absent = Some(missing);
                    // Streaming is permitted by standard CheckSVEEnabled;
                    // the operation never reads SVCR or an invented FA64 flag.
                    s.sm = 1;
                    s.fa = 0;
                    let t = evaluate(&build(word, vl), &s).unwrap();
                    assert!(t.registers.iter().all(|out| out.value.is_known()));
                    assert!(
                        !s.reads.borrow().contains(&missing),
                        "word{word:08x} VL{vl} {missing:?}"
                    );
                }
            }
        }
    }
}
#[test]
fn rw_wr_mathematical_differences_division_and_flag_endpoints() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let bytes = u64::from(w / 8);
            let elements = vl / u16::from(w);
            for op in [8, 9] {
                for a in [0, 0x7fffffffffffffff, u64::MAX - 257] {
                    for delta in [
                        0,
                        1,
                        bytes - 1,
                        bytes,
                        bytes + 1,
                        bytes * u64::from(elements - 1),
                        bytes * u64::from(elements),
                        bytes * u64::from(elements + 1),
                    ] {
                        for reverse in [false, true] {
                            let z = a.wrapping_add(delta);
                            let (a, z) = if reverse { (z, a) } else { (a, z) };
                            let mut s = State::new();
                            s.x[0] = a;
                            s.x[1] = z;
                            let want = reference(a, z, op, w, vl);
                            check(
                                OPS[op] | (size << 22) | (1 << 16) | 15,
                                vl,
                                &s,
                                w,
                                false,
                                &want,
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn no_old_predicate_dependency_except_preserved_backing() {
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            let mut s = State::new();
            s.absent = Some(Register {
                bank: "a64.predicate64",
                index: 0,
            });
            let t = evaluate(&build(base, vl), &s).unwrap();
            let out = t
                .registers
                .iter()
                .find(|x| x.register.bank == "a64.predicate64" && x.register.index == 0)
                .unwrap();
            let width = (vl / 8).min(64) as u8;
            assert_eq!(out.value.defined & mask(width), mask(width));
            if vl >= 512 {
                assert!(out.value.is_known());
                assert!(!s.reads.borrow().contains(&s.absent.unwrap()));
            } else {
                assert_eq!(out.value.defined & !mask(width), 0);
            }
            assert!(!t
                .registers
                .iter()
                .any(|x| x.register.bank == "a64.predicate64"
                    && x.register.index / 4 > if op < 8 { 1 } else { 0 }));
        }
    }
}
#[test]
fn unknown_required_inputs_propagate_and_xzr_has_no_register_or_sp_input() {
    for vl in VLS {
        for base in OPS {
            let mut s = State::new();
            s.absent = Some(Register {
                bank: "a64.gpr",
                index: 0,
            });
            let t = evaluate(&build(base | (1 << 16), vl), &s).unwrap();
            assert!(t
                .registers
                .iter()
                .any(|x| x.register.bank == "a64.nzcv" && !x.value.is_known()));
            let mut s = State::new();
            s.absent = Some(Register {
                bank: "a64.sp",
                index: 0,
            });
            let t = evaluate(&build(base | (31 << 16) | (31 << 5), vl), &s).unwrap();
            assert!(t.registers.iter().all(|x| x.value.is_known()));
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|x| x.bank == "a64.gpr" || x.bank == "a64.sp"));
        }
    }
}
const MASKS: [(u32, u32); 10] = [
    (0xff20fc11, 0x25205010),
    (0xff20fc11, 0x25205011),
    (0xff20fc11, 0x25205811),
    (0xff20fc11, 0x25205810),
    (0xff20fc11, 0x25205411),
    (0xff20fc11, 0x25205c10),
    (0xff20fc11, 0x25205c11),
    (0xff20fc11, 0x25205410),
    (0xff20fc10, 0x25203010),
    (0xff20fc10, 0x25203000),
];
#[test]
fn exact_physical_ownership_invalid_vl_no_guessed_32bit_form() {
    for (mask, base) in MASKS {
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let word = base ^ (1 << bit);
            assert_eq!(
                semantics::arm64_sve_while_extra::a64(word, 0x1000, 128).is_some(),
                MASKS.iter().any(|(m, b)| word & m == *b),
                "{word:08x}"
            );
        }
        assert!(semantics::arm64_sve_while_extra::a64(base ^ (1 << 12), 0x1000, 128).is_none());
        for vl in [0, 64, 384, 768, 4096] {
            assert!(matches!(
                semantics::arm64_sve_while_extra::a64(base, 0x1000, vl)
                    .unwrap()
                    .support,
                Support::Unsupported(_)
            ));
        }
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
fn native_graph_bound_all_forms_lengths() {
    let mut maximum = 0;
    for vl in VLS {
        for base in OPS {
            for size in 0..4 {
                let word = base | (size << 22) | (30 << 16) | (29 << 5) | 14;
                let r = semantics::arm64_sve_while_extra::a64(word, 0x1000, vl).unwrap();
                let nodes = lowered_nodes(&r);
                assert!(nodes <= 32768, "{word:08x} VL{vl} nodes{nodes}");
                maximum = maximum.max(nodes);
            }
        }
    }
    println!("maximum modeled native nodes {maximum}");
}

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
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    semantics::arm64_sve_integer_estimate::a64(word, 0x1000, vl)
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
const OPS: [u32; 4] = [0x4480a000, 0x4482a000, 0x4481a000, 0x4483a000];
// Literal primary RecipEstimate / RecipSqrtEstimate incrementing reference,
// independent of recipe binary search. Products use u64 to avoid host overflow.
fn expected(x: u32, sqrt: bool) -> u64 {
    if !sqrt {
        if x < 0x80000000 {
            return u64::from(u32::MAX);
        }
        let a = u64::from(x >> 23);
        let b = (1u64 << 19) / (2 * a + 1);
        ((b + 1) / 2) << 23
    } else {
        if x < 0x40000000 {
            return u64::from(u32::MAX);
        }
        let a = u64::from(x >> 23);
        let a = if a < 256 {
            2 * a + 1
        } else {
            2 * ((a / 2) * 2 + 1)
        };
        let mut b = 512u64;
        while a * (b + 1) * (b + 1) < (1u64 << 28) {
            b += 1;
        }
        ((b + 1) / 2) << 23
    }
}
#[test]
fn every_estimate_bucket_and_low_bit_endpoints_all_vls_aliases_policies() {
    let mut inputs = vec![
        0,
        1,
        0x3ffffffe,
        0x3fffffff,
        0x40000000,
        0x40000001,
        0x7ffffffe,
        0x7fffffff,
        0x80000000,
        0x80000001,
        u32::MAX,
    ];
    for bucket in 0u32..512 {
        inputs.extend([
            bucket << 23,
            (bucket << 23) | 0x3fffff,
            (bucket << 23) | 0x7fffff,
        ]);
    }
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                for batch in inputs.chunks(usize::from(vl / 32)) {
                    let mut s = State::new();
                    for e in 0..vl / 32 {
                        s.put(n, e, 32, u64::from(batch[usize::from(e) % batch.len()]));
                    }
                    let want = (0..vl / 32)
                        .map(|e| expected(s.get(n, e, 32) as u32, op >= 2))
                        .collect();
                    vector(base | (n << 5) | d, vl, &s, d, 32, want);
                }
            }
        }
    }
}
#[test]
fn predication_empty_sparse_full_and_noncontrolling_bits() {
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            for g in 0..8 {
                for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        s.predicate(g, 32, mode, vl);
                        let want = (0..vl / 32)
                            .map(|e| {
                                if s.active(g, e, 32) {
                                    expected(s.get(n, e, 32) as u32, op >= 2)
                                } else if op % 2 == 1 {
                                    0
                                } else {
                                    s.get(d, e, 32)
                                }
                            })
                            .collect();
                        vector(
                            base | ((g as u32) << 10) | (n << 5) | d,
                            vl,
                            &s,
                            d,
                            32,
                            want,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn inactive_source_and_zero_destination_unavailable_and_active_merge_skips_old_d() {
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            let mut s = State::new();
            s.predicate(7, 32, 0, vl);
            let want = (0..vl / 32)
                .map(|e| if op % 2 == 1 { 0 } else { s.get(0, e, 32) })
                .collect();
            s.missing = Some(1);
            if op % 2 == 1 {
                s.unavailable_chunks = (0..32).collect();
            }
            vector(base | (7 << 10) | (1 << 5), vl, &s, 0, 32, want);
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && (r.index / 32 == 1 || op % 2 == 1)));
            let mut s = State::new();
            let want = (0..vl / 32)
                .map(|e| expected(s.get(1, e, 32) as u32, op >= 2))
                .collect();
            s.missing = Some(0);
            vector(base | (1 << 5), vl, &s, 0, 32, want);
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
        }
    }
}
#[test]
fn sparse_active_lanes_do_not_require_inactive_source_chunks() {
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            let mut s = State::new();
            s.p[7] = [0; 4];
            s.p[7][0] = 1;
            for k in 1..32 {
                s.unavailable_chunks.push(32 + k);
            }
            let want = (0..vl / 32)
                .map(|e| {
                    if e == 0 {
                        expected(s.get(1, e, 32) as u32, op >= 2)
                    } else if op % 2 == 1 {
                        0
                    } else {
                        s.get(0, e, 32)
                    }
                })
                .collect();
            vector(base | (7 << 10) | (1 << 5), vl, &s, 0, 32, want);
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1 && r.index % 32 != 0));
        }
    }
}
#[test]
fn architectural_estimate_goldens() {
    for (x, recip, rsqrt) in [
        (0, 0xffffffff, 0xffffffff),
        (0x3fffffff, 0xffffffff, 0xffffffff),
        (0x40000000, 0xffffffff, 0xff800000),
        (0x7fffffff, 0xffffffff, 0xb5000000),
        (0x80000000, 0xff800000, 0xb4800000),
        (0xffffffff, 0x80000000, 0x80000000),
    ] {
        assert_eq!(expected(x, false), recip, "recip{x:08x}");
        assert_eq!(expected(x, true), rsqrt, "rsqrt{x:08x}");
        let mut s = State::new();
        for e in 0..4 {
            s.put(1, e, 32, u64::from(x));
        }
        for (op, base) in OPS.into_iter().enumerate() {
            vector(
                base | (1 << 5),
                128,
                &s,
                0,
                32,
                vec![if op >= 2 { rsqrt } else { recip }; 4],
            );
        }
    }
}
#[test]
fn max_backing_and_no_fp_flags_memory_or_control_side_effects() {
    for vl in VLS {
        for base in OPS {
            let s = State::new();
            let r = build(base | (1 << 5), vl);
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.registers.len(), usize::from(vl / 64));
            assert!(t
                .registers
                .iter()
                .all(|x| x.register.bank == "a64.vector64" && x.register.index < vl / 64));
            let mut backing = s.z[0];
            for out in &t.registers {
                backing[usize::from(out.register.index)] = out.value.bits;
            }
            assert_eq!(
                &backing[usize::from(vl / 64)..],
                &s.z[0][usize::from(vl / 64)..]
            );
            assert_eq!(t.next_pc, Value::known(64, 0x1004));
            assert!(
                t.trap.is_none()
                    && t.memory.is_empty()
                    && t.wide_memory.is_empty()
                    && t.atomics.is_empty()
            );
            assert!(s
                .reads
                .borrow()
                .iter()
                .all(|r| r.bank == "a64.vector64" || r.bank == "a64.predicate64"));
        }
    }
}
const PHYSICAL: [(u32, u32); 4] = [
    (0xff3fe000, 0x4400a000),
    (0xff3fe000, 0x4402a000),
    (0xff3fe000, 0x4401a000),
    (0xff3fe000, 0x4403a000),
];
#[test]
fn physical_selectors_reserved_sizes_and_vls() {
    for (mask, base) in PHYSICAL {
        for size in 0..4 {
            let r = semantics::arm64_sve_integer_estimate::a64(base | (size << 22), 0x1000, 128)
                .unwrap();
            assert_eq!(r.support == Support::Full, size == 2);
        }
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let word = base ^ (1 << bit);
            assert_eq!(
                semantics::arm64_sve_integer_estimate::a64(word, 0x1000, 128).is_some(),
                PHYSICAL.iter().any(|(m, b)| word & m == *b),
                "{word:08x}"
            );
        }
        for vl in [0, 64, 384, 768, 4096] {
            assert!(matches!(
                semantics::arm64_sve_integer_estimate::a64(base | (2 << 22), 0x1000, vl)
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
fn native_graph_budget_all_forms_vls() {
    let mut maximum = 0;
    for vl in VLS {
        for base in OPS {
            let r = semantics::arm64_sve_integer_estimate::a64(
                base | (7 << 10) | (31 << 5) | 31,
                0x1000,
                vl,
            )
            .unwrap();
            let nodes = lowered_nodes(&r);
            assert!(nodes <= 32768, "{base:08x} VL{vl} nodes{nodes}");
            maximum = maximum.max(nodes);
        }
    }
    println!("maximum modeled native nodes {maximum}");
}
#[test]
fn unknown_inactive_half_of_a_shared_source_chunk_does_not_poison_active_lane() {
    struct Partial<'a>(&'a State);
    impl Machine for Partial<'_> {
        fn read_register(&self, r: Register) -> Value {
            let mut v = self.0.read_register(r);
            if r.bank == "a64.vector64" && r.index / 32 == 1 {
                v.defined = 0xffff_ffff;
            }
            v
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("estimate accessed memory")
        }
    }
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            let mut s = State::new();
            s.p[7] = [0; 4];
            for e in (0..vl / 32).step_by(2) {
                let bit = e * 4;
                s.p[7][usize::from(bit / 64)] |= 1 << (bit % 64);
            }
            let t = evaluate(&build(base | (7 << 10) | (1 << 5), vl), &Partial(&s)).unwrap();
            for (k, out) in t.registers.iter().enumerate() {
                let low = expected(s.z[1][k] as u32, op >= 2);
                let high = if op % 2 == 1 {
                    0
                } else {
                    s.z[0][k] & 0xffff_ffff_0000_0000
                };
                assert_eq!(out.value, Value::known(64, low | high));
            }
        }
    }
}

// Independent characterization of the rounded estimate: assert the interval
// containing the exact rational reciprocal or reciprocal square root, rather
// than computing an expected estimate with either search used above.
#[test]
fn every_bucket_satisfies_exact_rounding_intervals() {
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            let sqrt = op >= 2;
            let first = if sqrt { 128u32 } else { 256 };
            let count = u32::from(vl / 32);
            for start in (first..512).step_by(count as usize) {
                let mut s = State::new();
                for e in 0..vl / 32 {
                    let bucket = (start + u32::from(e)).min(511);
                    // Exercise both ends of the discarded low 23 bits. Every
                    // output must lie in the same rounding interval.
                    let low = if e % 2 == 0 { 0 } else { 0x7fffff };
                    s.put(31, e, 32, u64::from((bucket << 23) | low));
                }
                let t = evaluate(&build(base | (31 << 5) | 31, vl), &s).unwrap();
                for e in 0..vl / 32 {
                    let out = t.registers[usize::from(e / 2)].value;
                    assert_eq!(out.defined, u64::MAX);
                    let y = (out.bits >> ((e % 2) * 32)) & 0xffffffff;
                    assert_eq!(y & 0x7fffff, 0);
                    let estimate = y >> 23;
                    assert!((256..512).contains(&estimate));
                    let input = s.get(31, e, 32) >> 23;
                    let lower = 2 * estimate - 1;
                    let upper = 2 * estimate + 1;
                    if sqrt {
                        let a = if input < 256 {
                            2 * input + 1
                        } else {
                            2 * ((input & !1) + 1)
                        };
                        assert!(
                            a * lower * lower < 1 << 28,
                            "rsqrt input{input} estimate{estimate}"
                        );
                        assert!(
                            1 << 28 <= a * upper * upper,
                            "rsqrt input{input} estimate{estimate}"
                        );
                    } else {
                        let denominator = 2 * input + 1;
                        assert!(
                            lower * denominator <= 1 << 19,
                            "recip input{input} estimate{estimate}"
                        );
                        assert!(
                            1 << 19 < upper * denominator,
                            "recip input{input} estimate{estimate}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn only_controlling_predicate_bits_need_be_defined() {
    struct PartialPredicate<'a>(&'a State);
    impl Machine for PartialPredicate<'_> {
        fn read_register(&self, r: Register) -> Value {
            let mut v = self.0.read_register(r);
            if r.bank == "a64.predicate64" {
                // Bits 4e are the only predicate inputs for 32-bit elements;
                // neither the other element-size views nor high backing count.
                v.defined = 0x1111111111111111;
            }
            v
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("integer estimate accessed memory")
        }
    }
    for vl in VLS {
        for (op, base) in OPS.into_iter().enumerate() {
            for (d, n) in [(0, 31), (31, 31)] {
                let mut s = State::new();
                s.predicate(7, 32, 3, vl);
                let t = evaluate(
                    &build(base | (7 << 10) | (n << 5) | d, vl),
                    &PartialPredicate(&s),
                )
                .unwrap();
                for e in 0..vl / 32 {
                    let got = t.registers[usize::from(e / 2)].value;
                    let want = if s.active(7, e, 32) {
                        expected(s.get(n, e, 32) as u32, op >= 2)
                    } else if op % 2 == 1 {
                        0
                    } else {
                        s.get(d, e, 32)
                    };
                    assert_eq!(got.defined, u64::MAX);
                    assert_eq!((got.bits >> ((e % 2) * 32)) & 0xffffffff, want);
                }
            }
        }
    }
}

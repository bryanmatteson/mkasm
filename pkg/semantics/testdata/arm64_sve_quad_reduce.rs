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
    semantics::arm64_sve_quad_reduce::a64(word, 0x1000, vl)
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
const OPS: [u32; 8] = [
    0x04052000, 0x040c2000, 0x040e2000, 0x040d2000, 0x040f2000, 0x041e2000, 0x041d2000, 0x041c2000,
];
fn reference(s: &State, n: u32, g: usize, w: u8, vl: u16, op: usize) -> Vec<u64> {
    let identity = match op {
        1 => 1u64 << (w - 1),
        2 => (1u64 << (w - 1)) - 1,
        4 | 5 => mask(w),
        _ => 0,
    };
    let per = 128 / u16::from(w);
    let mut out = vec![0; usize::from(vl / u16::from(w))];
    for e in 0..per {
        let mut a = identity;
        for k in 0..vl / 128 {
            let index = k * per + e;
            if !s.active(g, index, w) {
                continue;
            }
            let v = s.get(n, index, w);
            a = match op {
                0 => a.wrapping_add(v) & mask(w),
                1 => {
                    if signed(v, w) > signed(a, w) {
                        v
                    } else {
                        a
                    }
                }
                2 => {
                    if signed(v, w) < signed(a, w) {
                        v
                    } else {
                        a
                    }
                }
                3 => a.max(v),
                4 => a.min(v),
                5 => a & v,
                6 => a ^ v,
                7 => a | v,
                _ => unreachable!(),
            };
        }
        out[usize::from(e)] = a;
    }
    out
}
#[test]
fn all_reductions_sizes_lengths_sparse_empty_full_aliases_and_boundaries() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                for (d, n) in [(0, 1), (1, 1), (31, 31), (31, 0)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        s.predicate(7, w, mode, vl);
                        for e in 0..vl / u16::from(w) {
                            s.put(
                                n,
                                e,
                                w,
                                match e % 9 {
                                    0 => 0,
                                    1 => mask(w),
                                    2 => 1u64 << (w - 1),
                                    3 => (1u64 << (w - 1)) - 1,
                                    4 => 1,
                                    5 => mask(w) - 1,
                                    _ => s.get(n, e, w),
                                },
                            );
                        }
                        let want = reference(&s, n, 7, w, vl, op);
                        vector(
                            base | (size << 22) | (7 << 10) | (n << 5) | d,
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
fn segment_position_is_not_adjacent_horizontal_reduction() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let per = 128 / u16::from(w);
            let mut s = State::new();
            s.p[0] = [u64::MAX; 4];
            for e in 0..vl / u16::from(w) {
                s.put(1, e, w, u64::from(e / per) * 19 + u64::from(e % per) + 1);
            }
            let want = reference(&s, 1, 0, w, vl, 0);
            for e in 0..per {
                let segments = u64::from(vl / 128);
                let independent =
                    (19 * segments * (segments - 1) / 2 + segments * (u64::from(e) + 1)) & mask(w);
                assert_eq!(want[usize::from(e)], independent);
            }
            vector(OPS[0] | (size << 22) | (1 << 5), vl, &s, 0, w, want);
        }
    }
}
#[test]
fn inactive_sources_unavailable_and_noncontrolling_predicate_bits_do_not_activate() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                let mut s = State::new();
                s.predicate(7, w, 0, vl);
                s.missing = Some(31);
                let want = reference(&s, 31, 7, w, vl, op);
                vector(
                    base | (size << 22) | (7 << 10) | (31 << 5),
                    vl,
                    &s,
                    0,
                    w,
                    want,
                );
                assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.vector64"));
            }
        }
    }
}
#[test]
fn active_lanes_do_not_require_inactive_source_chunks() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                let mut s = State::new();
                s.p[7] = [0; 4];
                s.p[7][0] = 1;
                for k in 1..32 {
                    s.unavailable_chunks.push(32 + k);
                }
                let want = reference(&s, 1, 7, w, vl, op);
                vector(
                    base | (size << 22) | (7 << 10) | (1 << 5),
                    vl,
                    &s,
                    0,
                    w,
                    want,
                );
                assert!(!s
                    .reads
                    .borrow()
                    .iter()
                    .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1 && r.index % 32 != 0));
            }
        }
    }
}
#[test]
fn v128_write_clears_active_upper_z_preserves_max_backing_and_no_old_dest_reads() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for (op, base) in OPS.into_iter().enumerate() {
                let mut s = State::new();
                s.missing = Some(0);
                let t = evaluate(&build(base | (size << 22) | (1 << 5), vl), &s).unwrap();
                assert_eq!(t.registers.len(), usize::from(vl / 64));
                for k in 2..vl / 64 {
                    assert_eq!(t.registers[usize::from(k)].value, Value::known(64, 0));
                }
                assert!(!t
                    .registers
                    .iter()
                    .any(|r| r.register.bank != "a64.vector64" || r.register.index >= vl / 64));
                assert!(!s
                    .reads
                    .borrow()
                    .iter()
                    .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
                let mut backing = s.z[0];
                for out in &t.registers {
                    backing[usize::from(out.register.index)] = out.value.bits;
                }
                assert_eq!(
                    &backing[usize::from(vl / 64)..],
                    &s.z[0][usize::from(vl / 64)..]
                );
                let want = reference(&s, 1, 0, w, vl, op);
                vector(base | (size << 22) | (1 << 5), vl, &s, 0, w, want);
            }
        }
    }
}
#[test]
fn reserved_neighbors_and_vl_are_not_admitted() {
    for base in OPS {
        for vl in [0, 64, 384, 768, 4096] {
            assert!(matches!(
                semantics::arm64_sve_quad_reduce::a64(base, 0x1000, vl)
                    .unwrap()
                    .support,
                Support::Unsupported(_)
            ));
        }
    }
    // Every fixed-bit single mutation must leave the owned physical set unless
    // it exactly reaches another audited reduction family.
    for base in OPS {
        for bit in 0..32 {
            if 0xff3fe000u32 & (1 << bit) == 0 {
                continue;
            }
            let word = base ^ (1 << bit);
            assert_eq!(
                semantics::arm64_sve_quad_reduce::a64(word, 0x1000, 128).is_some(),
                OPS.contains(&(word & 0xff3fe000)),
                "{word:08x}"
            );
        }
    }
    for word in [
        0,
        0x04042000,
        0x041f2000,
        0x04052000 ^ 0x80000000,
        0xd503201f,
    ] {
        assert!(
            semantics::arm64_sve_quad_reduce::a64(word, 0x1000, 128).is_none(),
            "{word:08x}"
        );
    }
}
#[test]
fn wrapping_pc_and_no_control_memory_flag_effects() {
    for vl in VLS {
        for base in OPS {
            let r = semantics::arm64_sve_quad_reduce::a64(base, u64::MAX - 1, vl).unwrap();
            assert_eq!(
                evaluate(&r, &State::new()).unwrap().next_pc,
                Value::known(64, 2)
            );
            assert_eq!(r.flow.kind, FlowKind::Next);
            assert!(r.atomics.is_empty() && r.wide_loads.is_empty() && r.choices.is_empty());
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
fn native_graph_budget_all_ops_sizes_vls() {
    let mut max = 0;
    for vl in VLS {
        for base in OPS {
            for size in 0..4 {
                let word = base | (size << 22) | (7 << 10) | (31 << 5) | 31;
                let r = build(word, vl);
                let nodes = lowered_nodes(&r);
                assert!(nodes <= 32768, "{word:08x} VL{vl} nodes{nodes}");
                max = max.max(nodes);
            }
        }
    }
    println!("maximum modeled native nodes {max}");
}

// With exactly one active source, every reduction must project that element
// to the same position within V128. All other positions are the empty
// identity. No reduction loop is used by this oracle.
#[test]
fn every_single_active_position_projects_exactly_with_alias_and_unknown_chunks() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let per = 128 / u16::from(w);
            for (op, base) in OPS.into_iter().enumerate() {
                let identity = match op {
                    1 => 1u64 << (w - 1),
                    2 => (1u64 << (w - 1)) - 1,
                    4 | 5 => mask(w),
                    _ => 0,
                };
                let r = build(base | (size << 22) | (7 << 10) | (31 << 5) | 31, vl);
                for e in 0..vl / u16::from(w) {
                    let mut s = State::new();
                    s.p[7] = [0; 4];
                    let bit = e * u16::from(w / 8);
                    s.p[7][usize::from(bit / 64)] = 1 << (bit % 64);
                    let input_chunk = e * u16::from(w) / 64;
                    s.unavailable_chunks = (0..32)
                        .filter(|k| *k != input_chunk)
                        .map(|k| 31 * 32 + k)
                        .collect();
                    let value = s.get(31, e, w);
                    let t = evaluate(&r, &s).unwrap();
                    assert!(t.registers.iter().all(|v| v.value.is_known()));
                    let mut result = vec![identity; usize::from(per)];
                    result[usize::from(e % per)] = value;
                    for k in 0..2 {
                        let packed = result[k * usize::from(64 / w)..(k + 1) * usize::from(64 / w)]
                            .iter()
                            .enumerate()
                            .fold(0, |a, (j, v)| a | (*v << (j * usize::from(w))));
                        assert_eq!(
                            t.registers[k].value,
                            Value::known(64, packed),
                            "VL{vl} w{w} op{op} source{e}"
                        );
                    }
                    assert!(t.registers[2..]
                        .iter()
                        .all(|v| v.value == Value::known(64, 0)));
                    assert!(s
                        .reads
                        .borrow()
                        .iter()
                        .filter(|r| r.bank == "a64.vector64")
                        .all(|r| r.index == 31 * 32 + input_chunk));
                }
            }
        }
    }
}
#[test]
fn independent_two_segment_64_bit_goldens_and_cleared_upper_aliases() {
    // Segment0=[-2,MIN], segment1=[3,-1]. These fixed results distinguish
    // signed/unsigned comparisons, the two segment positions and wraparound.
    let golden = [
        [1, 0x7fff_ffff_ffff_ffff],
        [3, u64::MAX],
        [u64::MAX - 1, 0x8000_0000_0000_0000],
        [u64::MAX - 1, u64::MAX],
        [3, 0x8000_0000_0000_0000],
        [2, 0x8000_0000_0000_0000],
        [0xffff_ffff_ffff_fffd, 0x7fff_ffff_ffff_ffff],
        [u64::MAX, u64::MAX],
    ];
    for vl in [256, 512, 1024, 2048] {
        for (op, base) in OPS.into_iter().enumerate() {
            let mut s = State::new();
            s.p[7] = [0; 4];
            s.p[7][0] = (1 << 0) | (1 << 8) | (1 << 16) | (1 << 24);
            s.z[31][0..4].copy_from_slice(&[u64::MAX - 1, 0x8000_0000_0000_0000, 3, u64::MAX]);
            s.unavailable_chunks = (4..32).map(|k| 31 * 32 + k).collect();
            let t = evaluate(
                &build(base | (3 << 22) | (7 << 10) | (31 << 5) | 31, vl),
                &s,
            )
            .unwrap();
            assert_eq!(t.registers[0].value, Value::known(64, golden[op][0]));
            assert_eq!(t.registers[1].value, Value::known(64, golden[op][1]));
            assert!(t.registers[2..]
                .iter()
                .all(|v| v.value == Value::known(64, 0)));
            assert!(s
                .reads
                .borrow()
                .iter()
                .filter(|r| r.bank == "a64.vector64")
                .all(|r| r.index < 31 * 32 + 4));
        }
    }
}

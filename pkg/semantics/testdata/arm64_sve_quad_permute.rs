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
    semantics::arm64_sve_quad_permute::a64(word, 0x1000, vl)
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
const PERM: [u32; 4] = [0x4400e000, 0x4400e400, 0x4400e800, 0x4400ec00];
fn tref(s: &State, d: u32, n: u32, m: u32, w: u8, vl: u16, tbx: bool) -> Vec<u64> {
    let per = 128 / u16::from(w);
    (0..vl / u16::from(w))
        .map(|e| {
            let idx = s.get(m, e, w);
            if idx < u64::from(per) {
                s.get(n, e / per * per + idx as u16, w)
            } else if tbx {
                s.get(d, e, w)
            } else {
                0
            }
        })
        .collect()
}
#[test]
fn table_segment_local_lookup_all_sizes_lengths_and_aliases() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let per = 128 / u16::from(w);
            for base in [0x4400f800, 0x05203400] {
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (1, 1, 1), (31, 31, 31)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        for e in 0..vl / u16::from(w) {
                            s.put(
                                n,
                                e,
                                w,
                                u64::from(e / per) * 31 + u64::from(e % per) * 3 + 1,
                            );
                        }
                        for e in 0..vl / u16::from(w) {
                            s.put(
                                m,
                                e,
                                w,
                                match mode {
                                    0 => u64::from(e % per),
                                    1 => mask(w),
                                    2 => [
                                        0,
                                        u64::from(per / 2 - 1),
                                        u64::from(per / 2),
                                        u64::from(per - 1),
                                        u64::from(per),
                                        mask(w),
                                    ][usize::from(e) % 6],
                                    _ => u64::from(e % per * 2),
                                },
                            );
                        }
                        let want = tref(&s, d, n, m, w, vl, base == 0x05203400);
                        vector(
                            base | (size << 22) | (m << 16) | (n << 5) | d,
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
fn table_exhaustive_byte_indices_and_large_unsigned_indices() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let mut indices: Vec<u64> = (0..=255).collect();
            if w > 8 {
                indices.extend([256, 1u64 << (w - 1), mask(w)]);
            }
            for index in indices {
                for base in [0x4400f800, 0x05203400] {
                    let mut s = State::new();
                    for e in 0..vl / u16::from(w) {
                        s.put(2, e, w, index);
                    }
                    let want = tref(&s, 0, 1, 2, w, vl, base == 0x05203400);
                    vector(
                        base | (size << 22) | (2 << 16) | (1 << 5),
                        vl,
                        &s,
                        0,
                        w,
                        want,
                    );
                }
            }
        }
    }
}
#[test]
fn table_range_suppresses_unavailable_table_and_tbx_old_destination_is_lazy() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for base in [0x4400f800, 0x05203400] {
                let mut s = State::new();
                for e in 0..vl / u16::from(w) {
                    s.put(2, e, w, mask(w));
                }
                let want = tref(&s, 0, 1, 2, w, vl, base == 0x05203400);
                s.missing = Some(1);
                vector(
                    base | (size << 22) | (2 << 16) | (1 << 5),
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
                    .any(|r| r.bank == "a64.vector64" && r.index / 32 == 1));
            }
            let mut s = State::new();
            for e in 0..vl / u16::from(w) {
                s.put(2, e, w, 0);
            }
            let want = tref(&s, 0, 1, 2, w, vl, true);
            s.missing = Some(0);
            vector(
                0x05203400 | (size << 22) | (2 << 16) | (1 << 5),
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
                .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
        }
    }
}
#[test]
fn table_only_selected_sixty_four_bit_chunk_is_needed() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let half = 64 / u16::from(w);
            for selected in 0..2 {
                let mut s = State::new();
                for k in 0..vl / 128 {
                    s.unavailable_chunks.push(32 + k * 2 + 1 - selected);
                }
                for e in 0..vl / u16::from(w) {
                    s.put(2, e, w, u64::from(selected * half));
                }
                for base in [0x4400f800, 0x05203400] {
                    let want = tref(&s, 0, 1, 2, w, vl, base == 0x05203400);
                    vector(
                        base | (size << 22) | (2 << 16) | (1 << 5),
                        vl,
                        &s,
                        0,
                        w,
                        want,
                    );
                }
                assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.vector64"
                    && r.index / 32 == 1
                    && (r.index % 2) != (selected as u16)));
            }
        }
    }
}
#[test]
fn dupq_all_legal_tsz_and_indices_all_vls_aliases() {
    for vl in VLS {
        for imm in 0u32..32 {
            let tsz = imm & 15;
            if tsz == 0 {
                continue;
            }
            let size = tsz.trailing_zeros();
            let w = 8 << size;
            let per = 128 / u16::from(w);
            let index = (imm >> (size + 1)) as u16;
            for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                let s = State::new();
                let want = (0..vl / u16::from(w))
                    .map(|e| s.get(n, e / per * per + index, w))
                    .collect();
                vector(0x05202400 | (imm << 16) | (n << 5) | d, vl, &s, d, w, want);
            }
        }
    }
}
#[test]
fn extq_every_byte_offset_vl_and_alias() {
    for vl in VLS {
        for imm in 0..16 {
            for (d, m) in [(0, 1), (1, 1), (31, 31), (31, 0)] {
                let s = State::new();
                let want = (0..vl / 8)
                    .map(|e| {
                        let segment = e / 16;
                        let index = e % 16 + imm;
                        let n = if index < 16 { d } else { m };
                        s.get(n, segment * 16 + index % 16, 8)
                    })
                    .collect();
                vector(
                    0x05602400 | (u32::from(imm) << 16) | (m << 5) | d,
                    vl,
                    &s,
                    d,
                    8,
                    want,
                );
            }
        }
    }
}
#[test]
fn zipq_uzpq_all_sizes_vls_parts_and_aliases() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let per = 128 / u16::from(w);
            for (op, base) in PERM.into_iter().enumerate() {
                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (1, 1, 1), (31, 31, 31)] {
                    let s = State::new();
                    let part = op as u16 % 2;
                    let want = (0..vl / u16::from(w))
                        .map(|e| {
                            let seg = e / per;
                            let within = e % per;
                            let (src, index) = if op < 2 {
                                (
                                    if within % 2 == 0 { n } else { m },
                                    part * (per / 2) + within / 2,
                                )
                            } else {
                                (
                                    if within < per / 2 { n } else { m },
                                    2 * (within % (per / 2)) + part,
                                )
                            };
                            s.get(src, seg * per + index, w)
                        })
                        .collect();
                    vector(
                        base | (size << 22) | (m << 16) | (n << 5) | d,
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
#[test]
fn revd_merge_zero_quad_predicate_and_aliases() {
    for vl in VLS {
        for base in [0x052e8000, 0x052ea000] {
            for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                for mode in 0..4 {
                    let mut s = State::new();
                    s.predicate(7, 128, mode, vl);
                    let want = (0..vl / 64)
                        .map(|e| {
                            if s.active(7, e / 2, 128) {
                                s.get(n, e ^ 1, 64)
                            } else if base == 0x052e8000 {
                                s.get(d, e, 64)
                            } else {
                                0
                            }
                        })
                        .collect();
                    if mode == 0 && d != n {
                        s.missing = Some(n as u16);
                    }
                    vector(base | (7 << 10) | (n << 5) | d, vl, &s, d, 64, want);
                    if mode == 0 && d != n {
                        assert!(!s
                            .reads
                            .borrow()
                            .iter()
                            .any(|r| r.bank == "a64.vector64" && r.index / 32 == n as u16));
                    }
                }
            }
        }
    }
}
#[test]
fn revd_inactive_and_active_laziness() {
    for vl in VLS {
        let mut s = State::new();
        s.predicate(7, 128, 0, vl);
        s.missing = Some(0);
        s.unavailable_chunks = (32..64).collect();
        vector(
            0x052ea000 | (7 << 10) | (1 << 5),
            vl,
            &s,
            0,
            64,
            vec![0; usize::from(vl / 64)],
        );
        assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.vector64"));
        let mut s = State::new();
        s.predicate(7, 128, 1, vl);
        let want = (0..vl / 64).map(|e| s.get(1, e ^ 1, 64)).collect();
        s.missing = Some(0);
        vector(0x052e8000 | (7 << 10) | (1 << 5), vl, &s, 0, 64, want);
        assert!(!s
            .reads
            .borrow()
            .iter()
            .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
    }
}
const PHYSICAL: [(u32, u32); 10] = [
    (0xff20fc00, 0x4400f800),
    (0xff20fc00, 0x05203400),
    (0xffe0fc00, 0x05202400),
    (0xfff0fc00, 0x05602400),
    (0xffffe000, 0x052e8000),
    (0xffffe000, 0x052ea000),
    (0xff20fc00, 0x4400e000),
    (0xff20fc00, 0x4400e400),
    (0xff20fc00, 0x4400e800),
    (0xff20fc00, 0x4400ec00),
];
#[test]
fn exact_owned_masks_reserved_tsz_and_invalid_vl() {
    for (mask, base) in PHYSICAL {
        let legal = if base == 0x05202400 {
            base | (1 << 16)
        } else {
            base
        };
        for vl in [0, 64, 384, 768, 4096] {
            assert!(matches!(
                semantics::arm64_sve_quad_permute::a64(legal, 0x1000, vl)
                    .unwrap()
                    .support,
                Support::Unsupported(_)
            ));
        }
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let word = base ^ (1 << bit);
            assert_eq!(
                semantics::arm64_sve_quad_permute::a64(word, 0x1000, 128).is_some(),
                PHYSICAL.iter().any(|(m, b)| word & m == *b),
                "{word:08x}"
            );
        }
    }
    for imm in [0, 16] {
        assert!(matches!(
            semantics::arm64_sve_quad_permute::a64(0x05202400 | (imm << 16), 0x1000, 128)
                .unwrap()
                .support,
            Support::Unsupported(_)
        ));
    }
    assert!(semantics::arm64_sve_quad_permute::a64(0x052c8000, 0x1000, 128).is_none());
}
#[test]
fn preserve_max_backing_and_no_flags_fp_memory_control_effects() {
    for vl in VLS {
        for (_, base) in PHYSICAL {
            let word = base | if base == 0x05202400 { 1 << 16 } else { 0 };
            let r = build(word, vl);
            let s = State::new();
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(t.registers.len(), usize::from(vl / 64));
            for out in &t.registers {
                assert_eq!(out.register.bank, "a64.vector64");
                assert!(out.register.index < vl / 64);
            }
            assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.atomics.is_empty());
            let mut backing = s.z[0];
            for out in &t.registers {
                backing[usize::from(out.register.index)] = out.value.bits;
            }
            assert_eq!(
                &backing[usize::from(vl / 64)..],
                &s.z[0][usize::from(vl / 64)..]
            );
            assert_eq!(t.next_pc, Value::known(64, 0x1004));
            assert!(!s
                .reads
                .borrow()
                .iter()
                .any(|r| r.bank.starts_with("a64.fp") || r.bank == "a64.nzcv"));
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
        for (_, base) in PHYSICAL {
            for control in 0..32 {
                let word =
                    base | if base == 0x05202400 {
                        control << 16
                    } else if base == 0x05602400 {
                        (control & 15) << 16
                    } else if base == 0x052e8000 || base == 0x052ea000 {
                        0
                    } else {
                        (control & 3) << 22
                    } | (31 << 5)
                        | 31;
                let r = semantics::arm64_sve_quad_permute::a64(word, 0x1000, vl).unwrap();
                if r.support != Support::Full {
                    continue;
                }
                let nodes = lowered_nodes(&r);
                assert!(nodes <= 32768, "{word:08x} VL{vl} nodes{nodes}");
                maximum = maximum.max(nodes);
            }
        }
    }
    println!("maximum modeled native nodes {maximum}");
}

#[test]
fn literal_byte_goldens_fix_segment_order_concat_direction_and_quad_reverse() {
    let cases: [(u32, [u8; 16]); 8] = [
        (0x4400e000 | (2 << 16) | (1 << 5), [0,128,1,129,2,130,3,131,4,132,5,133,6,134,7,135]),
        (0x4400e400 | (2 << 16) | (1 << 5), [8,136,9,137,10,138,11,139,12,140,13,141,14,142,15,143]),
        (0x4400e800 | (2 << 16) | (1 << 5), [0,2,4,6,8,10,12,14,128,130,132,134,136,138,140,142]),
        (0x4400ec00 | (2 << 16) | (1 << 5), [1,3,5,7,9,11,13,15,129,131,133,135,137,139,141,143]),
        (0x05202400 | (31 << 16) | (1 << 5), [15;16]),
        (0x05602400 | (9 << 16) | (2 << 5), [9,10,11,12,13,14,15,128,129,130,131,132,133,134,135,136]),
        (0x052e8000 | (7 << 10) | (1 << 5), [8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7]),
        (0x052ea000 | (7 << 10) | (1 << 5), [8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7]),
    ];
    for vl in VLS {
        for (word, golden) in cases {
            let mut s = State::new();
            for byte in 0..vl / 8 {
                let tag = (byte / 16 * 16) as u8;
                let element = (byte % 16) as u8;
                for n in [0, 1] { s.put(n, byte, 8, u64::from(element ^ tag)); }
                s.put(2, byte, 8, u64::from(element ^ tag ^ 128));
            }
            let expected = (0..vl / 8).map(|byte|
                u64::from(golden[usize::from(byte % 16)] ^ (byte / 16 * 16) as u8)
            ).collect();
            vector(word, vl, &s, 0, 8, expected);
        }
    }
}

#[test]
fn mixed_tbx_fallback_needs_neither_unselected_table_nor_replaced_destination_chunk() {
    for vl in VLS {
        for size in 0..4 {
            let width = 8 << size;
            let per = 128 / u16::from(width);
            let half = per / 2;
            let mut s = State::new();
            for e in 0..vl / u16::from(width) {
                s.put(2, e, width, if e % per < half {u64::from(e % half)} else {u64::from(per)});
            }
            let want = (0..vl / u16::from(width)).map(|e|
                if e % per < half { s.get(1, e, width) } else { s.get(0, e, width) }
            ).collect();
            for segment in 0..vl / 128 {
                s.unavailable_chunks.extend([segment * 2, 32 + segment * 2 + 1]);
            }
            vector(0x05203400 | (size << 22) | (2 << 16) | (1 << 5), vl, &s, 0, width, want);
            assert!(!s.reads.borrow().iter().any(|r|
                r.bank == "a64.vector64" && s.unavailable_chunks.contains(&r.index)));
        }
    }
}

#[test]
fn extq_zero_and_half_offsets_and_dupq_ignore_unconsumed_chunks() {
    for vl in VLS {
        for offset in [0u16, 8] {
            let mut s = State::new();
            let want = (0..vl / 8).map(|e| {
                let at = e % 16 + offset;
                s.get(if at < 16 {0} else {1}, e / 16 * 16 + at % 16, 8)
            }).collect();
            for segment in 0..vl / 128 {
                if offset == 0 {s.unavailable_chunks.extend([32 + segment * 2, 32 + segment * 2 + 1]);}
                else {s.unavailable_chunks.extend([segment * 2, 32 + segment * 2 + 1]);}
            }
            vector(0x05602400 | (u32::from(offset) << 16) | (1 << 5), vl, &s, 0, 8, want);
            assert!(!s.reads.borrow().iter().any(|r|
                r.bank == "a64.vector64" && s.unavailable_chunks.contains(&r.index)));
        }
        for imm in 1u32..32 {
            if imm & 15 == 0 {continue;}
            let size = (imm & 15).trailing_zeros();
            let width = 8 << size;
            let index = (imm >> (size + 1)) as u16;
            let per = 128 / u16::from(width);
            let selected_chunk = index * u16::from(width) / 64;
            let mut s = State::new();
            let want = (0..vl / u16::from(width)).map(|e| s.get(1, e / per * per + index, width)).collect();
            for segment in 0..vl / 128 {s.unavailable_chunks.push(32 + segment * 2 + 1 - selected_chunk);}
            vector(0x05202400 | (imm << 16) | (1 << 5), vl, &s, 0, width, want);
            assert!(!s.reads.borrow().iter().any(|r|
                r.bank == "a64.vector64" && s.unavailable_chunks.contains(&r.index)));
        }
    }
}

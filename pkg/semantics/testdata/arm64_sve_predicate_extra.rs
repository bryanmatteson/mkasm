#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::RefCell;
const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
#[derive(Clone)]
struct State {
    z: [[u64; 32]; 32],
    p: [[u64; 4]; 17],
    x: [u64; 31],
    sp: u64,
    sm: u64,
    fa: u64,
    missing: Option<u16>,
    reads: RefCell<Vec<Register>>,
    choices: RefCell<Vec<(usize, u8)>>,
    absent: Option<Register>,
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
            p: [[u64::MAX; 4]; 17],
            x: std::array::from_fn(|n| u64::MAX - (n as u64) * 17),
            sp: 0xffff_ffff_ffff_ffe0,
            sm: 0,
            fa: 0,
            missing: None,
            reads: RefCell::new(vec![]),
            choices: RefCell::new(vec![]),
            absent: None,
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
            return Value::unknown(if r.bank == "a64.sme_fa64" { 1 } else { 64 });
        }
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
    fn choose(&self, i: usize, w: u8) -> Result<Value, EvalError> {
        self.choices.borrow_mut().push((i, w));
        Ok(Value::known(w, 0xa5a5a5a5a5a5a5a5 & mask(w)))
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
    semantics::arm64_sve_predicate_extra::a64(word, 0x1000, vl)
}
fn owned_recipe(word: u32, vl: u16) -> Option<Recipe> {
    let helper = semantics::arm64_sve_predicate_extra::a64;
    helper(word, 0x1000, vl)
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
    assert!(!s
        .reads
        .borrow()
        .iter()
        .any(|r| r.bank == "a64.vector64" && r.index % 32 >= vl / 64));
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
fn pout(t: &Transition, s: &State, n: usize, k: usize) -> u64 {
    t.registers
        .iter()
        .find(|x| x.register.bank == "a64.predicate64" && x.register.index == (n * 4 + k) as u16)
        .map(|x| {
            assert!(x.value.is_known());
            x.value.bits
        })
        .unwrap_or(s.p[n][k])
}
fn plmask(vl: u16, k: usize) -> u64 {
    if k * 64 >= usize::from(vl / 8) {
        0
    } else {
        mask((usize::from(vl / 8) - k * 64).min(64) as u8)
    }
}
#[test]
fn ffr_read_three_forms_alias_flags_and_max_backing() {
    for vl in VLS {
        for base in [0x2519f000, 0x2518f000, 0x2558f000] {
            for d in [0, 1, 15] {
                for mode in 0..4 {
                    let mut s = State::new();
                    s.predicate(d, 8, mode, vl);
                    s.p[16] = [
                        0x8421123589abcdef,
                        0x551109876543210f,
                        0xfedcba9876543210,
                        0x8123456789abcdef,
                    ];
                    let word = base
                        | d as u32
                        | if base == 0x2519f000 {
                            0
                        } else {
                            (d as u32) << 5
                        };
                    let t = evaluate(&build(word, vl), &s).unwrap();
                    for k in 0..4 {
                        let m = plmask(vl, k);
                        let v = s.p[16][k]
                            & if base == 0x2519f000 {
                                u64::MAX
                            } else {
                                s.p[d][k]
                            };
                        assert_eq!(pout(&t, &s, d, k), (s.p[d][k] & !m) | (v & m));
                    }
                    if base == 0x2558f000 {
                        let active: Vec<_> = (0..vl / 8)
                            .filter(|b| s.p[d][usize::from(b / 64)] & (1 << (b % 64)) != 0)
                            .collect();
                        let set = |b: u16| s.p[16][usize::from(b / 64)] >> (b % 64) & 1;
                        let nzcv = [
                            active.first().map(|&x| set(x)).unwrap_or(0),
                            u64::from(!active.iter().any(|&x| set(x) != 0)),
                            active.last().map(|&x| set(x) ^ 1).unwrap_or(1),
                            0,
                        ];
                        for (i, v) in nzcv.into_iter().enumerate() {
                            assert_eq!(
                                t.registers
                                    .iter()
                                    .find(|x| x.register.bank == "a64.nzcv"
                                        && x.register.index == i as u16)
                                    .unwrap()
                                    .value,
                                Value::known(1, v)
                            );
                        }
                    } else {
                        assert!(!t.registers.iter().any(|x| x.register.bank == "a64.nzcv"));
                    }
                    assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.predicate64"
                        && usize::from(r.index % 4) * 64 >= usize::from(vl / 8)));
                }
            }
        }
    }
}
#[test]
fn ffr_set_no_sources_and_write_monotonic_or_replayable_arbitrary() {
    for vl in VLS {
        let s = State::new();
        let t = evaluate(&build(0x252c9000, vl), &s).unwrap();
        for k in 0..4 {
            assert_eq!(pout(&t, &s, 16, k), s.p[16][k] | plmask(vl, k));
        }
        assert!(!s
            .reads
            .borrow()
            .iter()
            .any(|r| r.bank == "a64.predicate64" && r.index / 4 != 16));
        for n in [0, 15] {
            for count in 0..=vl / 8 {
                let mut s = State::new();
                s.p[n] = [0; 4];
                for bit in 0..count {
                    s.p[n][usize::from(bit / 64)] |= 1 << (bit % 64);
                }
                let t = evaluate(&build(0x25289000 | (n as u32) << 5, vl), &s).unwrap();
                assert!(s.choices.borrow().is_empty());
                for k in 0..4 {
                    let m = plmask(vl, k);
                    assert_eq!(pout(&t, &s, 16, k), (s.p[16][k] & !m) | (s.p[n][k] & m));
                }
            }
            let mut s = State::new();
            s.p[n] = [0; 4];
            s.p[n][0] = 2;
            let t = evaluate(&build(0x25289000 | (n as u32) << 5, vl), &s).unwrap();
            assert_eq!(s.choices.borrow().len(), usize::from((vl / 8).div_ceil(64)));
            for k in 0..4 {
                let m = plmask(vl, k);
                assert_eq!(
                    pout(&t, &s, 16, k),
                    (s.p[16][k] & !m) | (0xa5a5a5a5a5a5a5a5 & m)
                );
            }
        }
    }
}
#[test]
fn ffr_context_rejects_before_sources_and_fa64_allows_streaming() {
    for vl in VLS {
        for word in [0x2519f000, 0x2518f000, 0x2558f000, 0x25289000, 0x252c9000] {
            let mut s = State::new();
            s.sm = 1;
            assert!(evaluate(&build(word, vl), &s).is_err());
            assert!(!s.reads.borrow().iter().any(|x| x.bank == "a64.predicate64"));
            s.fa = 1;
            evaluate(&build(word, vl), &s).unwrap();
            let mut s = State::new();
            s.absent = Some(Register {
                bank: "a64.sme_fa64",
                index: 0,
            });
            evaluate(&build(word, vl), &s).unwrap();
            assert!(!s.reads.borrow().contains(&s.absent.unwrap()));
        }
    }
}
#[test]
fn cnot_all_widths_merge_zero_aliases_and_inactive_inputs() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for base in [0x041ba000, 0x040ba000] {
                for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        s.predicate(2, w, mode, vl);
                        for e in 0..vl / u16::from(w) {
                            s.put(n, e, w, if e % 3 == 1 { 0 } else { mask(w) });
                        }
                        let expected = (0..vl / u16::from(w))
                            .map(|e| {
                                if s.active(2, e, w) {
                                    u64::from(s.get(n, e, w) == 0)
                                } else if base == 0x041ba000 {
                                    s.get(d, e, w)
                                } else {
                                    0
                                }
                            })
                            .collect();
                        if mode == 0 && d != n {
                            s.missing = Some(n as u16);
                        }
                        vector(
                            base | (size << 22) | (2 << 10) | (n << 5) | d,
                            vl,
                            &s,
                            d,
                            w,
                            expected,
                        );
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
}
#[test]
fn cpy_immediate_signed_shift_merge_zero_all_immediates() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for sh in 0..=1 {
                if w == 8 && sh != 0 {
                    continue;
                }
                for imm in 0..=255 {
                    for base in [0x05100000, 0x05104000] {
                        let mut s = State::new();
                        s.predicate(15, w, 2, vl);
                        let value = ((imm as u8 as i8 as i128) << (sh * 8)) as u64 & mask(w);
                        let expected = (0..vl / u16::from(w))
                            .map(|e| {
                                if s.active(15, e, w) {
                                    value
                                } else if base == 0x05104000 {
                                    s.get(31, e, w)
                                } else {
                                    0
                                }
                            })
                            .collect();
                        if base == 0x05100000 {
                            s.missing = Some(31);
                        }
                        vector(
                            base | (size << 22) | (15 << 16) | (sh << 13) | (imm << 5) | 31,
                            vl,
                            &s,
                            31,
                            w,
                            expected,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn cpy_gpr_sp_and_scalar_v_alias_snapshots_lazy_sources() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            for base in [0x0528a000, 0x05208000] {
                for (d, n) in [(0, 1), (1, 1), (31, 31)] {
                    for mode in 0..4 {
                        let mut s = State::new();
                        s.predicate(7, w, mode, vl);
                        let v = if base == 0x05208000 {
                            s.get(n, 0, w)
                        } else if n == 31 {
                            s.sp & mask(w)
                        } else {
                            s.x[n as usize] & mask(w)
                        };
                        let expected = (0..vl / u16::from(w))
                            .map(|e| if s.active(7, e, w) { v } else { s.get(d, e, w) })
                            .collect();
                        if mode == 0 && d != n {
                            s.absent = Some(Register {
                                bank: if base == 0x05208000 {
                                    "a64.vector64"
                                } else {
                                    "a64.gpr"
                                },
                                index: if base == 0x05208000 {
                                    n as u16 * 32
                                } else {
                                    n as u16
                                },
                            });
                        }
                        vector(
                            base | (size << 22) | (7 << 10) | (n << 5) | d,
                            vl,
                            &s,
                            d,
                            w,
                            expected,
                        );
                        if let Some(absent) = s.absent {
                            assert!(!s.reads.borrow().contains(&absent));
                        }
                    }
                }
            }
        }
    }
}
// Independent numerical oracle for VFPExpandImm: magnitude=(16+frac)/16 * 2^exp.
fn fp_reference(i: u32, w: u8) -> u64 {
    let power = if i & 64 != 0 {
        ((i >> 4) & 3) as i32 - 3
    } else {
        ((i >> 4) & 3) as i32 + 1
    };
    let value = (if i & 128 != 0 { -1.0 } else { 1.0 })
        * (1.0 + f64::from(i & 15) / 16.0)
        * 2f64.powi(power);
    match w {
        64 => value.to_bits(),
        32 => (value as f32).to_bits().into(),
        16 => {
            let f = (value as f32).to_bits();
            u64::from(((f >> 16) & 0x8000) | ((((f >> 23) & 255) - 112) << 10) | ((f >> 13) & 1023))
        }
        _ => unreachable!(),
    }
}
#[test]
fn fcpy_fdup_all_constants_no_fp_environment_reads() {
    for vl in VLS {
        for size in 1..4 {
            let w = 8 << size;
            for i in 0..=255 {
                for base in [0x0510c000, 0x2539c000] {
                    let mut s = State::new();
                    s.predicate(15, w, 2, vl);
                    let value = fp_reference(i, w);
                    let expected = (0..vl / u16::from(w))
                        .map(|e| {
                            if base == 0x2539c000 || s.active(15, e, w) {
                                value
                            } else {
                                s.get(31, e, w)
                            }
                        })
                        .collect();
                    vector(
                        base | (size << 22)
                            | (i << 5)
                            | 31
                            | if base == 0x0510c000 { 15 << 16 } else { 0 },
                        vl,
                        &s,
                        31,
                        w,
                        expected,
                    );
                    assert!(!s
                        .reads
                        .borrow()
                        .iter()
                        .any(|r| r.bank.starts_with("a64.fp")));
                }
            }
        }
    }
}
#[test]
fn exact_owned_reserved_fields_and_context() {
    for word in [0x05102000, 0x05106000, 0x0510c000, 0x2539c000] {
        assert!(matches!(
            owned_recipe(word, 128).unwrap().support,
            Support::Unsupported(_)
        ));
    }
    for vl in [0, 64, 384, 768, 4096] {
        assert!(matches!(
            owned_recipe(0x252c9000, vl).unwrap().support,
            Support::Unsupported(_)
        ));
    }
    for word in [0, 0x04180000, 0x0420bc00, 0x25a02000, 0xd503201f] {
        assert!(owned_recipe(word, 128).is_none(), "{word:08x}");
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
            ExprKind::Register(_) | ExprKind::ChoiceResult { .. } => 1,
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
    for choice in &recipe.choices {
        total += 1 + choice
            .condition
            .as_ref()
            .map(|c| lower(c, &[]).nodes + 1)
            .unwrap_or(0);
    }
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
            policy: _,
        } = effect
        else {
            panic!("unmodeled bit permutation effect")
        };
        let v = lower(value, &temps);
        if !v.immutable {
            total += v.nodes + guard;
        }
        total += 1 + guard;
        if destination.parent_width != value.ty.width {
            total += 1;
        }
    }
    total
}

#[test]
fn native_graph_budget_all_forms_widths_and_vls() {
    let mut maximum = 0;
    for vl in VLS {
        for base in [
            0x2519f000, 0x2518f000, 0x2558f000, 0x25289000, 0x252c9000, 0x041ba000, 0x040ba000,
            0x05100000, 0x05104000, 0x0528a000, 0x05208000, 0x0510c000, 0x2539c000,
        ] {
            for size in 0..4 {
                let word = if base & 0xff000000 == 0x25000000 && base != 0x2539c000 {
                    base
                } else {
                    base | (size << 22)
                };
                let r = recipe(word, vl).unwrap();
                if r.support != Support::Full {
                    continue;
                }
                let n = lowered_nodes(&r);
                assert!(n <= 32768, "{word:08x} VL{vl} {n}");
                maximum = maximum.max(n);
            }
        }
    }
    println!("maximum modeled native nodes {maximum}");
}
#[test]
fn zeroing_cnot_all_inactive_needs_neither_source_nor_destination() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let mut s = State::new();
            s.p[7] = [0; 4];
            s.missing = Some(31);
            s.absent = Some(Register {
                bank: "a64.vector64",
                index: 0,
            });
            vector(
                0x040ba000 | (size << 22) | (7 << 10) | (31 << 5),
                vl,
                &s,
                0,
                w,
                vec![0; usize::from(vl / u16::from(w))],
            );
            assert!(!s.reads.borrow().iter().any(|r| r.bank == "a64.vector64"));
        }
    }
}
#[test]
fn inactive_sp_source_and_fully_active_merge_skip_unavailable_inputs() {
    for vl in VLS {
        for size in 0..4 {
            let w = 8 << size;
            let mut s = State::new();
            s.p[7] = [0; 4];
            s.absent = Some(Register {
                bank: "a64.sp",
                index: 0,
            });
            let expected = (0..vl / u16::from(w)).map(|e| s.get(0, e, w)).collect();
            vector(
                0x0528a000 | (size << 22) | (7 << 10) | (31 << 5),
                vl,
                &s,
                0,
                w,
                expected,
            );
            assert!(!s.reads.borrow().contains(&s.absent.unwrap()));
            for base in [0x041ba000, 0x0528a000, 0x05208000, 0x05104000] {
                let mut s = State::new();
                let immediate = base == 0x05104000;
                let g = if immediate { 15 } else { 7 };
                s.predicate(g, w, 1, vl);
                s.missing = Some(0);
                let value = if immediate {
                    1
                } else if base == 0x05208000 {
                    s.get(1, 0, w)
                } else {
                    s.x[1] & mask(w)
                };
                let expected = (0..vl / u16::from(w))
                    .map(|e| {
                        if base == 0x041ba000 {
                            u64::from(s.get(1, e, w) == 0)
                        } else {
                            value
                        }
                    })
                    .collect();
                vector(
                    base | (size << 22)
                        | if immediate {
                            (15 << 16) | (1 << 5)
                        } else {
                            (7 << 10) | (1 << 5)
                        },
                    vl,
                    &s,
                    0,
                    w,
                    expected,
                );
                assert!(!s
                    .reads
                    .borrow()
                    .iter()
                    .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
            }
        }
    }
}

// Primary WRFFR uses HighestSetBit and tests every lower bit. Enumerating all
// 16-bit predicates supplies an independent oracle, including internal holes.
#[test]
fn wrffr_all_16_bit_inputs_and_cross_chunk_holes() {
    let r = build(0x25289000, 128);
    for bits in 0u32..=65535 {
        let mut s = State::new();
        s.p[0] = [u64::from(bits) | 0xa55a_ffff_0000_0000, u64::MAX, 2, 4];
        s.p[16] = [0x1234_5678_abcd_0000, 0x1234, 0x5678, 0x9abc];
        let monotonic = bits == 0 || bits.count_ones() == 32 - bits.leading_zeros();
        let t = evaluate(&r, &s).unwrap();
        assert_eq!(
            s.choices.borrow().len(),
            usize::from(!monotonic),
            "{bits:04x}"
        );
        let low = if monotonic { u64::from(bits) } else { 0xa5a5 };
        assert_eq!(pout(&t, &s, 16, 0), 0x1234_5678_abcd_0000 | low);
        for k in 1..4 {
            assert_eq!(pout(&t, &s, 16, k), s.p[16][k]);
        }
    }
    for vl in [1024, 2048] {
        for k in 1..usize::from(vl / 512) {
            let mut s = State::new();
            s.p[0] = [u64::MAX; 4];
            // A zero below the highest set bit invalidates monotonicity even
            // when it occurs immediately before a 64-bit chunk boundary.
            s.p[0][k - 1] &= !(1 << 63);
            let t = evaluate(&build(0x25289000, vl), &s).unwrap();
            assert_eq!(s.choices.borrow().len(), usize::from(vl / 512));
            for j in 0..usize::from(vl / 512) {
                assert_eq!(pout(&t, &s, 16, j), 0xa5a5a5a5a5a5a5a5);
            }
        }
    }
}
#[test]
fn rdffrs_nonalias_mask_uses_first_last_active_ffr_and_preserves_backing() {
    for vl in VLS {
        for mask_bits in [0, 1, 2, 0x8001, 0xffff] {
            for ffr_bits in [0, 1, 2, 0x8000, 0x8001, 0xffff] {
                let mut s = State::new();
                s.p[2] = [mask_bits, 0, 0, 0];
                s.p[16] = [ffr_bits, 0, 0, 0];
                s.p[15] = [
                    0x9876_5432_abcd_eeff,
                    0x1122334455667788,
                    0x8877665544332211,
                    0xdeadbeef,
                ];
                let t = evaluate(&build(0x2558f000 | (2 << 5) | 15, vl), &s).unwrap();
                let result = mask_bits & ffr_bits;
                let n = mask_bits != 0 && result & (1 << mask_bits.trailing_zeros()) != 0;
                let c = mask_bits == 0 || result & (1 << (63 - mask_bits.leading_zeros())) == 0;
                let expected = [u64::from(n), u64::from(result == 0), u64::from(c), 0];
                for (i, v) in expected.into_iter().enumerate() {
                    assert_eq!(
                        t.registers
                            .iter()
                            .find(|w| w.register
                                == Register {
                                    bank: "a64.nzcv",
                                    index: i as u16
                                })
                            .unwrap()
                            .value,
                        Value::known(1, v)
                    );
                }
                for k in 0..4 {
                    let m = plmask(vl, k);
                    let low = if k == 0 { result } else { 0 };
                    assert_eq!(pout(&t, &s, 15, k), (s.p[15][k] & !m) | (low & m));
                }
            }
        }
    }
}

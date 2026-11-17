#[allow(dead_code)]
mod runtime;
use runtime::*;
fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    runtime::arm64_sve_crypto_group::a64(word, address, vl)
        .or_else(|| runtime::arm64_sve_crypto::a64(word, address, vl))
}
use std::{cell::RefCell, collections::BTreeMap};
#[derive(Clone, Default)]
struct State {
    regs: BTreeMap<(&'static str, u16), Value>,
    reads: RefCell<Vec<Register>>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.borrow_mut().push(r);
        self.regs
            .get(&(r.bank, r.index))
            .copied()
            .unwrap_or(Value::unknown(64))
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("crypto accessed memory")
    }
}
impl State {
    fn new() -> Self {
        let mut s = Self::default();
        for bank in [
            "a64.svcr",
            "a64.sme_fa64",
            "a64.ssve_aes",
            "a64.ssve_bitperm",
            "a64.sme2p1",
        ] {
            s.set(bank, 0, if bank == "a64.svcr" { 64 } else { 1 }, 0);
        }
        s
    }
    fn set(&mut self, b: &'static str, n: u16, w: u8, v: u64) {
        self.regs.insert((b, n), Value::known(w, v));
    }
    fn vector(&mut self, n: u16, bytes: &[u8]) {
        for (ch, v) in bytes.chunks(8).enumerate() {
            let mut b = [0; 8];
            b[..v.len()].copy_from_slice(v);
            self.set(
                "a64.vector64",
                n * 32 + ch as u16,
                64,
                u64::from_le_bytes(b),
            );
        }
    }
    fn bytes(&self, n: u16, vl: u16) -> Vec<u8> {
        (0..vl / 64)
            .flat_map(|ch| self.regs[&("a64.vector64", n * 32 + ch)].bits.to_le_bytes())
            .collect()
    }
    fn run(&mut self, word: u32, vl: u16) {
        let r = a64(word, 0x1000, vl).unwrap();
        assert_eq!(r.support, Support::Full);
        r.validate().unwrap();
        let before = self.regs.clone();
        let t = evaluate(&r, self).unwrap();
        assert!(
            t.memory.is_empty()
                && t.wide_memory.is_empty()
                && t.atomics.is_empty()
                && t.trap.is_none()
                && t.events.is_empty()
        );
        assert_eq!(t.next_pc, Value::known(64, 0x1004));
        assert_eq!(self.regs, before);
        for w in t.registers {
            assert_eq!(w.register.bank, "a64.vector64");
            assert!(w.value.is_known());
            self.regs
                .insert((w.register.bank, w.register.index), w.value);
        }
    }
}
fn pattern(seed: u8, vl: u16) -> Vec<u8> {
    (0..vl / 8)
        .map(|i| {
            seed.wrapping_add((i as u8).wrapping_mul(29))
                .rotate_left((i % 7) as u32)
        })
        .collect()
}
fn gf(mut a: u8, mut b: u8) -> u8 {
    let mut v = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            v ^= a;
        }
        a = if a & 0x80 != 0 {
            (a << 1) ^ 0x1b
        } else {
            a << 1
        };
        b >>= 1;
    }
    v
}
fn inverse_gf(a: u8) -> u8 {
    let mut v = 1;
    let mut base = a;
    let mut exponent = 254;
    while exponent != 0 {
        if exponent & 1 != 0 {
            v = gf(v, base);
        }
        base = gf(base, base);
        exponent >>= 1;
    }
    v
}
fn aes_sbox(a: u8) -> u8 {
    let p = inverse_gf(a);
    p ^ p.rotate_left(1) ^ p.rotate_left(2) ^ p.rotate_left(3) ^ p.rotate_left(4) ^ 0x63
}
fn aes_inverse(a: u8) -> u8 {
    inverse_gf(a.rotate_left(1) ^ a.rotate_left(3) ^ a.rotate_left(6) ^ 0x05)
}
fn aes_round(x: &[u8], key: &[u8], inverse: bool) -> Vec<u8> {
    let mut out = vec![0; x.len()];
    for segment in 0..x.len() / 16 {
        for i in 0..16 {
            let row = i % 4;
            let col = i / 4;
            let source = segment * 16 + 4 * ((col + if inverse { 4 - row } else { row }) % 4) + row;
            out[segment * 16 + i] = if inverse {
                aes_inverse(x[source] ^ key[source])
            } else {
                aes_sbox(x[source] ^ key[source])
            };
        }
    }
    out
}
fn aes_mix(x: &[u8], inverse: bool) -> Vec<u8> {
    let coeff = if inverse {
        [14, 11, 13, 9]
    } else {
        [2, 3, 1, 1]
    };
    let mut out = vec![0; x.len()];
    for col in 0..x.len() / 4 {
        for row in 0..4 {
            out[col * 4 + row] =
                (0..4).fold(0, |a, i| a ^ gf(x[col * 4 + (row + i) % 4], coeff[i]));
        }
    }
    out
}
const SM4_SBOX: [u64; 32] = [
    0xb73de1ccfee990d6,
    0x052cfb28c214b616,
    0xc304be2a769a672b,
    0x99068649261344aa,
    0x7a98ef91f450429c,
    0x62accfed430b5433,
    0x95e808c9a91cb3e4,
    0xa63f8f75fa94df80,
    0xba1773f3fca70747,
    0xa84f85e6193c5983,
    0x8bda6471b2816b68,
    0x359d56704b0febf8,
    0xa2d158635e0e241e,
    0x877821013b7c2225,
    0x5227d39f574600d4,
    0x9ec8c4a0e702364c,
    0xb538c740d28abfea,
    0xa11561f9cef2f7a3,
    0x551a349ba45daee0,
    0xe3b18cf5303293ad,
    0x60ca66822ee2f61d,
    0x6f4e530dab2329c0,
    0x2f8efdde4537dbd5,
    0x515b6c6d726aff03,
    0x7fbcddbb92af1b8d,
    0xd85a101f415cd911,
    0xbd7bcda58831c10a,
    0xb0b4e5b812d0742d,
    0x7e77960c4a976989,
    0x84c66ec509f1b965,
    0x204ddc3aec7df018,
    0x4839cbd73e5fee79,
];
fn sm4(mut x: [u32; 4], key: [u32; 4], schedule: bool) -> [u32; 4] {
    for k in key {
        let b = x[1] ^ x[2] ^ x[3] ^ k;
        let mut t = 0;
        for i in 0..4 {
            let v = ((b >> (i * 8)) & 255) as usize;
            t |= (((SM4_SBOX[v / 8] >> ((v % 8) * 8)) & 255) as u32) << (i * 8);
        }
        let v = if schedule {
            t ^ t.rotate_left(13) ^ t.rotate_left(23)
        } else {
            t ^ t.rotate_left(2) ^ t.rotate_left(10) ^ t.rotate_left(18) ^ t.rotate_left(24)
        };
        x = [x[1], x[2], x[3], x[0] ^ v];
    }
    x
}
fn words(x: &[u8]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(x[i * 4..i * 4 + 4].try_into().unwrap()))
}
fn wordbytes(x: [u32; 4]) -> Vec<u8> {
    x.into_iter().flat_map(u32::to_le_bytes).collect()
}
#[cfg(test)]
mod sve_crypto {
    use super::*;
    const VLS: [u16; 5] = [128, 256, 512, 1024, 2048];
    // Count the scalar native lowering shape, including extraction shifts,
    // width conversions, SSA snapshots and each statement predicate. This is
    // deliberately independent of schema node count: Extract(register) becomes
    // one native register reference, but Extract(temporary) adds shift/truncate.
    // Actual consumer Semantics::try_complete remains the integration check.
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
                ExprKind::Unary {
                    op: UnaryOp::Not | UnaryOp::Neg,
                    value,
                } => 1 + lower(value, temps).nodes,
                ExprKind::Binary { left, right, .. } => {
                    1 + lower(left, temps).nodes + lower(right, temps).nodes
                }
                ExprKind::Select { condition, yes, no } => {
                    1 + lower(condition, temps).nodes
                        + lower(yes, temps).nodes
                        + lower(no, temps).nodes
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
                other => panic!("unmodeled crypto lowering {other:?}"),
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
                panic!("unmodeled crypto effect")
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
    fn native_graph_budget_at_maximum_vector_length() {
        for word in [
            0x4522e020, 0x4522e420, 0x4520e000, 0x4520e400, 0x4523e020, 0x4521f000,
        ] {
            let recipe = a64(word, 0x1000, 2048).unwrap();
            let nodes = lowered_nodes(&recipe);
            println!("native scalar lowering model {word:08x}: {nodes} nodes");
            assert!(
                nodes < 32700,
                "{word:08x}: {nodes} exceeds native aggregate expression budget"
            );
        }
    }

    #[test]
    fn aes_every_segment_all_substitution_bytes_mix_and_key_aliases() {
        for vl in VLS {
            for inverse in [false, true] {
                for alias in [false, true] {
                    for seed in [0u8, 1, 0x63, 0x80, 0xff] {
                        let mut s = State::new();
                        let d = 31;
                        let key = if alias { 31 } else { 30 };
                        let x = pattern(seed, vl);
                        let k = pattern(seed ^ 0xac, vl);
                        s.vector(d, &x);
                        if !alias {
                            s.vector(key, &k);
                        }
                        let expected = aes_round(&x, if alias { &x } else { &k }, inverse);
                        s.run(
                            if inverse { 0x4522e400 } else { 0x4522e000 }
                                | (u32::from(key) << 5)
                                | u32::from(d),
                            vl,
                        );
                        assert_eq!(s.bytes(d, vl), expected);
                        let expected_mix = aes_mix(&expected, inverse);
                        s.run(
                            if inverse { 0x4520e400 } else { 0x4520e000 } | u32::from(d),
                            vl,
                        );
                        assert_eq!(s.bytes(d, vl), expected_mix);
                    }
                }
            }
        }
        // Exhaust the S-box domain, rather than relying on pseudo-random vectors.
        for inverse in [false, true] {
            let mut s = State::new();
            let input = (0..=255u8).collect::<Vec<_>>();
            s.vector(0, &input);
            s.vector(1, &[0; 256]);
            s.run(
                if inverse { 0x4522e400 } else { 0x4522e000 } | (1 << 5),
                2048,
            );
            assert_eq!(s.bytes(0, 2048), aes_round(&input, &[0; 256], inverse));
        }
    }
    #[test]
    fn aes_fips_known_round_and_mix() {
        let mut s = State::new();
        let x = [
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0,
            0xe0, 0xf0,
        ];
        s.vector(0, &x);
        s.vector(1, &[0; 16]);
        s.run(0x4522e020, 128);
        assert_eq!(
            s.bytes(0, 128),
            [
                0x63, 0x53, 0xe0, 0x8c, 0x09, 0x60, 0xe1, 0x04, 0xcd, 0x70, 0xb7, 0x51, 0xba, 0xca,
                0xd0, 0xe7
            ]
        );
        s.run(0x4520e000, 128);
        assert_eq!(
            s.bytes(0, 128),
            [
                0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92, 0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9,
                0xf9, 0x1a
            ]
        );
    }
    #[test]
    fn sm4_rounds_and_key_updates_keep_128_bit_segments_and_alias_snapshots() {
        for vl in VLS {
            for schedule in [false, true] {
                for alias in [0, 1, 2] {
                    let mut s = State::new();
                    let d = 31;
                    let n = if schedule {
                        if alias == 1 {
                            d
                        } else {
                            29
                        }
                    } else {
                        d
                    };
                    let m = if alias == 2 { d } else { 30 };
                    for index in [d, n, m] {
                        s.vector(index, &pattern(index as u8, vl));
                    }
                    let x = s.bytes(n, vl);
                    let k = s.bytes(m, vl);
                    let expected = x
                        .chunks(16)
                        .zip(k.chunks(16))
                        .flat_map(|(x, k)| wordbytes(sm4(words(x), words(k), schedule)))
                        .collect::<Vec<_>>();
                    let word = if schedule {
                        0x4520f000 | (u32::from(m) << 16) | (u32::from(n) << 5) | u32::from(d)
                    } else {
                        0x4523e000 | (u32::from(m) << 5) | u32::from(d)
                    };
                    s.run(word, vl);
                    assert_eq!(s.bytes(d, vl), expected, "{word:08x} VL={vl}");
                }
            }
        }
    }
    #[test]
    fn sm4_byte_lookups_do_not_rotate_by_neighboring_low_bits() {
        for schedule in [false, true] {
            for byte in 1..4 {
                for bit in 0..8 {
                    let input = [
                        0x01234567,
                        0xa5a5a5a5 ^ (0x99 << (byte * 8)),
                        1 << ((byte - 1) * 8 + bit),
                        0xefcdab89,
                    ];
                    let key = [0x89abcdef, 0x76543210, 0xfedcba98, 0x01234567];
                    let mut state = State::new();
                    state.vector(0, &wordbytes(input));
                    state.vector(1, &wordbytes(key));
                    state.run(if schedule { 0x4521f000 } else { 0x4523e020 }, 128);
                    assert_eq!(
                        words(&state.bytes(0, 128)),
                        sm4(input, key, schedule),
                        "schedule={schedule} byte={byte} neighbor_bit={bit}"
                    );
                }
            }
        }
    }
    #[test]
    fn sm4_all_substitution_bytes_and_fresh_destination_at_every_length() {
        for vl in VLS {
            let segments = usize::from(vl / 128);
            for batch in 0..256 / segments {
                for schedule in [false, true] {
                    let mut state = State::new();
                    let inputs = vec![0; usize::from(vl / 8)];
                    let mut keys = vec![];
                    let mut expected = vec![];
                    for segment in 0..segments {
                        let byte = (batch * segments + segment) as u32;
                        let key = [byte * 0x01010101, 0x89abcdef, 0x76543210, 0xfedcba98];
                        keys.extend(wordbytes(key));
                        expected.extend(wordbytes(sm4([0; 4], key, schedule)));
                    }
                    // SM4EKEY writes a distinct, entirely unavailable Zd. Its
                    // low-word initialization must not consume old upper bits.
                    state.vector(if schedule { 1 } else { 0 }, &inputs);
                    state.vector(2, &keys);
                    state.run(if schedule { 0x4522f020 } else { 0x4523e040 }, vl);
                    assert_eq!(
                        state.bytes(0, vl),
                        expected,
                        "VL={vl} batch={batch} schedule={schedule}"
                    );
                    if schedule {
                        assert!(!state
                            .reads
                            .borrow()
                            .iter()
                            .any(|r| r.bank == "a64.vector64" && r.index / 32 == 0));
                    }
                }
            }
        }
    }
    #[test]
    fn sm4_published_32_round_cipher_and_key_schedule() {
        for vl in VLS {
            let mut s = State::new();
            let key = [0x01234567u32, 0x89abcdef, 0xfedcba98, 0x76543210];
            let fk = [0xa3b1bac6u32, 0x56aa3350, 0x677d9197, 0xb27022dc];
            let initial = wordbytes(core::array::from_fn(|i| key[i] ^ fk[i]));
            s.vector(0, &initial.repeat(usize::from(vl / 128)));
            let mut keys = vec![];
            for group in 0..8 {
                let ck = core::array::from_fn(|i| {
                    let r = group * 4 + i;
                    (0..4).fold(0, |a, j| {
                        a | (((((r * 4 + j) * 7) & 255) as u32) << ((3 - j) * 8))
                    })
                });
                s.vector(1, &wordbytes(ck).repeat(usize::from(vl / 128)));
                s.run(0x4521f000, vl);
                keys.extend(words(&s.bytes(0, vl)[..16]));
            }
            assert_eq!(
                &keys[..4],
                &[0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077]
            );
            assert_eq!(
                &keys[28..],
                &[0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012]
            );
            s.vector(0, &wordbytes(key).repeat(usize::from(vl / 128)));
            for group in 0..8 {
                s.vector(
                    1,
                    &wordbytes(keys[group * 4..group * 4 + 4].try_into().unwrap())
                        .repeat(usize::from(vl / 128)),
                );
                s.run(0x4523e020, vl);
            }
            for segment in s.bytes(0, vl).chunks(16) {
                assert_eq!(
                    words(segment),
                    [0x536e4246, 0x86b3e94f, 0xd206965e, 0x681edf34]
                );
            }
        }
    }
    fn pack_lanes(bytes: &[u8], w: u8) -> Vec<u64> {
        bytes
            .chunks(usize::from(w / 8))
            .map(|v| {
                v.iter()
                    .enumerate()
                    .fold(0, |a, (i, b)| a | (u64::from(*b) << (i * 8)))
            })
            .collect()
    }
    fn lane_bytes(lanes: Vec<u64>, w: u8) -> Vec<u8> {
        lanes
            .into_iter()
            .flat_map(|v| v.to_le_bytes()[..usize::from(w / 8)].to_vec())
            .collect()
    }
    fn widthmask(w: u8) -> u64 {
        if w == 64 {
            u64::MAX
        } else {
            (1u64 << w) - 1
        }
    }
    fn rotate(v: u64, n: u8, w: u8) -> u64 {
        let n = n % w;
        if n == 0 {
            v & widthmask(w)
        } else {
            ((v >> n) | (v << (w - n))) & widthmask(w)
        }
    }
    #[test]
    fn sha3_logical_rax1_xar_all_element_sizes_rotations_and_aliases() {
        for vl in VLS {
            for base in [0x04203800u32, 0x04603800, 0x4520f400] {
                for alias in 0..4 {
                    let d = 31;
                    let n = if alias & 1 != 0 { d } else { 29 };
                    let m = if alias & 2 != 0 { d } else { 30 };
                    let mut s = State::new();
                    for v in [d, n, m] {
                        s.vector(v, &pattern(v as u8, vl));
                    }
                    let x = pack_lanes(&s.bytes(if base == 0x4520f400 { n } else { d }, vl), 64);
                    let y = pack_lanes(&s.bytes(m, vl), 64);
                    let z = pack_lanes(&s.bytes(n, vl), 64);
                    let expected = x
                        .iter()
                        .enumerate()
                        .map(|(e, x)| match base {
                            0x04203800 => x ^ y[e] ^ z[e],
                            0x04603800 => x ^ (y[e] & !z[e]),
                            _ => x ^ y[e].rotate_left(1),
                        })
                        .collect();
                    s.run(
                        base | (u32::from(m) << 16) | (u32::from(n) << 5) | u32::from(d),
                        vl,
                    );
                    assert_eq!(s.bytes(d, vl), lane_bytes(expected, 64));
                }
            }
            for w in [8u8, 16, 32, 64] {
                for rot in 1..=w {
                    for alias in [false, true] {
                        let d = 31;
                        let m = if alias { 31 } else { 30 };
                        let mut s = State::new();
                        s.vector(d, &pattern(0x35, vl));
                        if !alias {
                            s.vector(m, &pattern(0xf1, vl));
                        }
                        let x = pack_lanes(&s.bytes(d, vl), w);
                        let y = pack_lanes(&s.bytes(m, vl), w);
                        let expected = x
                            .into_iter()
                            .zip(y)
                            .map(|(a, b)| rotate(a ^ b, rot, w))
                            .collect();
                        let field = u32::from(2 * w - rot);
                        let word = 0x04203400
                            | ((field >> 5) & 3) << 22
                            | ((field >> 3) & 3) << 19
                            | (field & 7) << 16
                            | (u32::from(m) << 5)
                            | u32::from(d);
                        s.run(word, vl);
                        assert_eq!(s.bytes(d, vl), lane_bytes(expected, w), "XAR w={w} r={rot}");
                    }
                }
            }
        }
    }
    fn bitperm(data: u64, mask: u64, w: u8, mode: u8) -> u64 {
        let mut yes = 0;
        let mut no = 0;
        let mut selected = 0;
        let mut other = 0;
        for bit in 0..w {
            if mask & (1 << bit) != 0 {
                if mode == 1 {
                    selected |= ((data >> yes) & 1) << bit
                } else {
                    selected |= ((data >> bit) & 1) << yes
                }
                yes += 1;
            } else {
                other |= ((data >> bit) & 1) << no;
                no += 1;
            }
        }
        if mode == 2 && yes < 64 {
            selected | (other << yes)
        } else {
            selected
        }
    }
    #[test]
    fn bitperm_full_width_masks_zero_counts_and_destructive_aliases() {
        for vl in VLS {
            for w in [8u8, 16, 32, 64] {
                for (mode, base) in [0x4500b000u32, 0x4500b400, 0x4500b800]
                    .into_iter()
                    .enumerate()
                {
                    for alias in 0..4 {
                        let d = 31;
                        let n = if alias & 1 != 0 { 31 } else { 29 };
                        let m = if alias & 2 != 0 { 31 } else { 30 };
                        let mut s = State::new();
                        for v in [d, n, m] {
                            s.vector(v, &pattern(v as u8, vl));
                        }
                        let masks = (0..vl / u16::from(w))
                            .map(|e| {
                                [
                                    0,
                                    widthmask(w),
                                    1u64 << (w - 1),
                                    0xaaaaaaaaaaaaaaaa & widthmask(w),
                                ][usize::from(e) % 4]
                            })
                            .collect::<Vec<_>>();
                        s.vector(m, &lane_bytes(masks, w));
                        let x = pack_lanes(&s.bytes(n, vl), w);
                        let masks = pack_lanes(&s.bytes(m, vl), w);
                        let expected = x
                            .into_iter()
                            .zip(masks)
                            .map(|(x, m)| bitperm(x, m, w, mode as u8))
                            .collect();
                        let word = base
                            | ((w.trailing_zeros() - 3) << 22)
                            | (u32::from(m) << 16)
                            | (u32::from(n) << 5)
                            | u32::from(d);
                        s.run(word, vl);
                        assert_eq!(
                            s.bytes(d, vl),
                            lane_bytes(expected, w),
                            "{word:08x} VL={vl}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn polynomial_bytes_exhaust_every_input_pair_and_keep_long_forms_with_existing_owner() {
        for vl in VLS {
            let mut s = State::new();
            for seed in 0..=255u8 {
                let x = vec![seed; usize::from(vl / 8)];
                let y = (0..vl / 8).map(|i| i as u8).collect::<Vec<_>>();
                s.vector(31, &x);
                s.vector(30, &y);
                s.run(0x04206400 | (30 << 16) | (31 << 5) | 31, vl);
                let expected = x
                    .iter()
                    .zip(y)
                    .map(|(a, b)| {
                        (0..8).fold(0, |v, bit| {
                            if b & (1 << bit) != 0 {
                                v ^ (a << bit)
                            } else {
                                v
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(s.bytes(31, vl), expected);
            }
        }
        for word in [0x45006800u32, 0x45006c00, 0x45406800, 0x45c06c00] {
            assert!(a64(word, 0, 128).is_none());
            assert!(runtime::arm64_sve::a64(word, 0, Endian::Little, 128).is_some());
        }
    }
    #[test]
    fn crypto_streaming_qualification_precedes_operand_reads() {
        for (word, extension) in [
            (0x4522e000, Some("a64.ssve_aes")),
            (0x4522e400, Some("a64.ssve_aes")),
            (0x4520e000, Some("a64.ssve_aes")),
            (0x4520e400, Some("a64.ssve_aes")),
            (0x4523e000, None),
            (0x4520f000, None),
            (0x4520f400, Some("a64.sme2p1")),
            (0x4500b000, Some("a64.ssve_bitperm")),
            (0x4500b400, Some("a64.ssve_bitperm")),
            (0x4500b800, Some("a64.ssve_bitperm")),
        ] {
            for vl in VLS {
                let mut s = State::new();
                s.set("a64.svcr", 0, 64, 1);
                let r = a64(word, 0, vl).unwrap();
                assert_eq!(
                    evaluate(&r, &s),
                    Err(EvalError::UnsupportedContext),
                    "{word:08x}"
                );
                assert!(s.reads.borrow().iter().all(|r| r.bank != "a64.vector64"));
                for fa in [false, true] {
                    for extra in [false, true] {
                        let mut s = State::new();
                        s.set("a64.svcr", 0, 64, 1);
                        s.set("a64.sme_fa64", 0, 1, u64::from(fa));
                        if let Some(bank) = extension {
                            s.set(bank, 0, 1, u64::from(extra));
                        }
                        for n in 0..32 {
                            s.vector(n, &vec![0; usize::from(vl / 8)]);
                        }
                        let result = evaluate(&r, &s);
                        if fa || extension.is_some() && extra {
                            assert!(result.is_ok(), "{word:08x}");
                        } else {
                            assert_eq!(result, Err(EvalError::UnsupportedContext));
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn independent_streaming_extensions_never_read_unavailable_fa64() {
        for (word, bank) in [
            (0x4522e000, "a64.ssve_aes"),
            (0x4522e400, "a64.ssve_aes"),
            (0x4520e000, "a64.ssve_aes"),
            (0x4520e400, "a64.ssve_aes"),
            (0x4520f400, "a64.sme2p1"),
            (0x4500b000, "a64.ssve_bitperm"),
        ] {
            for vl in VLS {
                let mut s = State::new();
                s.set("a64.svcr", 0, 64, 1);
                s.set(bank, 0, 1, 1);
                s.regs.remove(&("a64.sme_fa64", 0));
                for n in 0..32 {
                    s.vector(n, &pattern(n as u8, vl));
                }
                let r = a64(word, 0, vl).unwrap();
                evaluate(&r, &s).unwrap();
                assert!(
                    !s.reads.borrow().iter().any(|r| r.bank == "a64.sme_fa64"),
                    "{word:08x}"
                );
            }
        }
    }

    #[test]
    fn grouped_aes_every_round_group_key_index_length_and_alias() {
        let mut cases = 0;
        for vl in VLS {
            for count in [2u16, 4] {
                for inverse in [false, true] {
                    for mix in [false, true] {
                        for index in 0..4u32 {
                            for (d, m) in [(0, 7), (0, 0), (28, 31), (28, 29)] {
                                let mut state = State::new();
                                for n in 0..32 {
                                    state.vector(n, &pattern(n as u8, 2048));
                                }
                                let mut expected = state.regs.clone();
                                let key = state.bytes(m, vl);
                                let selected = index as usize % (usize::from(vl / 128).min(4));
                                for n in d..d + count {
                                    let source = state.bytes(n, vl);
                                    let mut result = vec![];
                                    for segment in 0..usize::from(vl / 128) {
                                        let keysegment = segment / 4 * 4 + selected;
                                        let value = aes_round(
                                            &source[segment * 16..segment * 16 + 16],
                                            &key[keysegment * 16..keysegment * 16 + 16],
                                            inverse,
                                        );
                                        result.extend(if mix {
                                            aes_mix(&value, inverse)
                                        } else {
                                            value
                                        });
                                    }
                                    for (chunk, bytes) in result.chunks_exact(8).enumerate() {
                                        expected.insert(
                                            ("a64.vector64", n * 32 + chunk as u16),
                                            Value::known(
                                                64,
                                                u64::from_le_bytes(bytes.try_into().unwrap()),
                                            ),
                                        );
                                    }
                                }
                                let word = (if count == 2 { 0x4522e800 } else { 0x4526e800 })
                                    | (u32::from(inverse) << 10)
                                    | (u32::from(mix) << 16)
                                    | (index << 19)
                                    | (u32::from(m) << 5)
                                    | u32::from(d);
                                state.run(word, vl);
                                assert_eq!(state.regs, expected, "{word:08x} VL{vl}");
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 640);
    }
    #[test]
    fn paired_polynomial_products_use_both_halves_and_capture_all_aliases() {
        for vl in VLS {
            for (d, n, m) in [
                (0u16, 1u16, 2u16),
                (0, 0, 1),
                (0, 1, 0),
                (0, 0, 0),
                (30, 31, 30),
                (30, 30, 31),
            ] {
                let mut state = State::new();
                for reg in 0..32 {
                    state.vector(reg, &pattern(reg as u8, 2048));
                }
                let mut expected = state.regs.clone();
                for segment in 0..vl / 128 {
                    for half in 0..2 {
                        let a = state.regs[&("a64.vector64", n * 32 + segment * 2 + half)].bits;
                        let b = state.regs[&("a64.vector64", m * 32 + segment * 2 + half)].bits;
                        let mut product = 0u128;
                        for bit in 0..64 {
                            if a >> bit & 1 != 0 {
                                product ^= u128::from(b) << bit;
                            }
                        }
                        expected.insert(
                            ("a64.vector64", (d + half) * 32 + segment * 2),
                            Value::known(64, product as u64),
                        );
                        expected.insert(
                            ("a64.vector64", (d + half) * 32 + segment * 2 + 1),
                            Value::known(64, (product >> 64) as u64),
                        );
                    }
                }
                state.run(
                    0x4520f800 | (u32::from(m) << 16) | (u32::from(n) << 5) | u32::from(d),
                    vl,
                );
                assert_eq!(state.regs, expected, "d{d} n{n} m{m} VL{vl}");
            }
        }
    }
    #[test]
    fn grouped_crypto_streaming_checks_are_lazy_and_precede_data() {
        for word in [
            0x4522e800, 0x4522ec00, 0x4523e800, 0x4523ec00, 0x4526e800, 0x4526ec00, 0x4527e800,
            0x4527ec00, 0x4520f800,
        ] {
            let r = a64(word, 0, 128).unwrap();
            for (sm, ssve, fa, allowed) in [
                (0, 0, 0, true),
                (1, 0, 0, false),
                (1, 0, 1, true),
                (1, 1, 0, true),
            ] {
                let mut state = State::new();
                state.set("a64.svcr", 0, 64, sm);
                state.set("a64.ssve_aes", 0, 1, ssve);
                state.set("a64.sme_fa64", 0, 1, fa);
                if ssve != 0 {
                    state.regs.remove(&("a64.svcr", 0));
                    state.regs.remove(&("a64.sme_fa64", 0));
                }
                if allowed {
                    for n in 0..32 {
                        state.vector(n, &pattern(n as u8, 128));
                    }
                }
                let result = evaluate(&r, &state);
                if allowed {
                    result.unwrap();
                } else {
                    assert_eq!(result, Err(EvalError::UnsupportedContext));
                    assert!(state
                        .reads
                        .borrow()
                        .iter()
                        .all(|r| r.bank != "a64.vector64"));
                }
                if ssve != 0 {
                    assert!(state
                        .reads
                        .borrow()
                        .iter()
                        .all(|r| r.bank != "a64.svcr" && r.bank != "a64.sme_fa64"));
                }
            }
        }
    }
    #[test]
    fn primary_corpus_covers_every_owned_single_vector_page() {
        assert_eq!(PRIMARY.len(), 92);
        for &(word, name) in PRIMARY {
            for vl in VLS {
                let mut s = State::new();
                for n in 0..32 {
                    s.vector(n, &pattern(n as u8, vl));
                }
                let r = a64(word, 0, vl).unwrap_or_else(|| panic!("{name} {word:08x}"));
                assert_eq!(r.support, Support::Full);
                r.validate().unwrap();
                evaluate(&r, &s).unwrap();
            }
        }
    }
    #[test]
    fn ordinary_sve2_crypto_does_not_require_fa64_or_nonstreaming_context() {
        for word in [0x04203800, 0x04603800, 0x04283400, 0x04206400] {
            for vl in VLS {
                let mut state = State::default();
                for n in 0..32 {
                    state.vector(n, &pattern(n as u8, vl));
                }
                state.run(word, vl);
                assert!(state
                    .reads
                    .borrow()
                    .iter()
                    .all(|r| r.bank == "a64.vector64"));
            }
        }
    }

    #[test]
    fn reserved_contexts_encodings_and_unrelated_words_are_explicit() {
        for word in [0x04203400u32, 0xd503201f, 0x4e284800] {
            assert!(a64(word, 0, 128).is_none());
        }
        for vl in [0, 64, 192, 384, 4096] {
            let r = a64(0x4522e000, 0, vl).unwrap();
            assert!(matches!(r.support, Support::Unsupported(_)));
            assert!(r.effects.is_empty());
        }
    }
}

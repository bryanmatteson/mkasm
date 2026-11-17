#[allow(dead_code)]
mod semantics;
mod simd_integer_extra {
    use super::semantics::arm64_simd_integer_extra::a64;
    use super::semantics::*;
    use std::cell::Cell;
    #[derive(Clone)]
    struct State {
        v: [u128; 32],
        available: u64,
        reads: Cell<u64>,
    }
    impl Default for State {
        fn default() -> Self {
            Self {
                v: [0; 32],
                available: 0,
                reads: Cell::new(0),
            }
        }
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            assert_eq!(r.bank, "a64.vector64", "unexpected state dependency: {r:?}");
            assert!(r.index % 32 < 2);
            let n = usize::from(r.index / 32);
            let chunk = r.index % 32;
            let bit = 1u64 << (n * 2 + chunk as usize);
            self.reads.set(self.reads.get() | bit);
            if self.available & bit == 0 {
                Value::unknown(64)
            } else {
                Value::known(64, (self.v[n] >> (chunk * 64)) as u64)
            }
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("pure SIMD read memory")
        }
    }
    fn run(recipe: &Recipe, s: &State, d: usize) -> u128 {
        assert_eq!(recipe.support, Support::Full);
        let t = evaluate(recipe, s).unwrap();
        assert_eq!(t.next_pc, Value::known(64, 0x1004));
        assert!(
            t.memory.is_empty()
                && t.wide_memory.is_empty()
                && t.atomics.is_empty()
                && t.events.is_empty()
                && t.trap.is_none()
        );
        assert_eq!(t.registers.len(), 2);
        let mut result = 0;
        for write in t.registers {
            assert_eq!(write.register.bank, "a64.vector64");
            assert_eq!(usize::from(write.register.index / 32), d);
            assert!(write.value.is_known(), "unknown destination {write:?}");
            result |= u128::from(write.value.bits) << (64 * (write.register.index % 32));
        }
        result
    }
    fn mask(w: u8) -> u64 {
        if w == 64 {
            u64::MAX
        } else {
            (1u64 << w) - 1
        }
    }
    fn signed(x: u64, w: u8) -> i128 {
        let x = i128::from(x & mask(w));
        if x & (1i128 << (w - 1)) != 0 {
            x - (1i128 << w)
        } else {
            x
        }
    }
    fn elem(v: u128, i: usize, w: u8) -> u64 {
        ((v >> (i * usize::from(w))) as u64) & mask(w)
    }
    fn set(s: &mut State, n: usize, value: u128, bits: usize) {
        s.v[n] = value;
        s.available |= (if bits == 128 { 3 } else { 1 }) << (n * 2);
    }
    fn recipe(word: u32) -> Recipe {
        a64(word, 0x1000).unwrap_or_else(|| panic!("unhandled {word:08x}"))
    }
    // Host signed/unsigned comparisons are independent of the Expr predicate
    // construction; every lane includes rotating zero/sign/maximum boundaries.
    #[test]
    fn all_comparisons_sizes_scalar_vector_and_source_destination_aliases() {
        let cases = [
            (0x0e209800, 0x5ee09800, 0, true),  // CMEQ zero
            (0x2e208800, 0x7ee08800, 1, true),  // CMGE zero
            (0x0e208800, 0x5ee08800, 2, true),  // CMGT zero
            (0x2e209800, 0x7ee09800, 5, true),  // CMLE zero
            (0x0e20a800, 0x5ee0a800, 6, true),  // CMLT zero
            (0x2e208c00, 0x7ee08c00, 0, false), // CMEQ
            (0x0e203c00, 0x5ee03c00, 1, false), // CMGE
            (0x0e203400, 0x5ee03400, 2, false), // CMGT
            (0x2e203400, 0x7ee03400, 3, false), // CMHI
            (0x2e203c00, 0x7ee03c00, 4, false), // CMHS
            (0x0e208c00, 0x5ee08c00, 7, false), // CMTST
        ];
        let mut executions = 0;
        for (vector, scalar, op, zero) in cases {
            for scalar_mode in [false, true] {
                for size in 0..4 {
                    for q in [false, true] {
                        if scalar_mode && (size != 3 || !q) || !scalar_mode && size == 3 && !q {
                            continue;
                        }
                        let w = 8u8 << size;
                        let bits = if scalar_mode || !q { 64 } else { 128 };
                        let lanes = bits / usize::from(w);
                        let vals = [
                            0,
                            1,
                            2,
                            mask(w),
                            mask(w) - 1,
                            1u64 << (w - 1),
                            (1u64 << (w - 1)) - 1,
                            0x55 & mask(w),
                        ];
                        for xseed in 0..vals.len() {
                            for yseed in 0..vals.len() {
                                for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                                    let mut s = State::default();
                                    let x = (0..lanes).fold(0, |v, i| {
                                        v | u128::from(vals[(xseed + i) % vals.len()])
                                            << (i * usize::from(w))
                                    });
                                    let y = (0..lanes).fold(0, |v, i| {
                                        v | u128::from(vals[(yseed + 3 * i) % vals.len()])
                                            << (i * usize::from(w))
                                    });
                                    set(&mut s, n, x, bits);
                                    if !zero && n != m {
                                        set(&mut s, m, y, bits)
                                    }
                                    let mut expected = 0;
                                    for i in 0..lanes {
                                        let x = elem(s.v[n], i, w);
                                        let y = if zero { 0 } else { elem(s.v[m], i, w) };
                                        let yes = match op {
                                            0 => x == y,
                                            1 => signed(x, w) >= signed(y, w),
                                            2 => signed(x, w) > signed(y, w),
                                            3 => x > y,
                                            4 => x >= y,
                                            5 => signed(x, w) <= signed(y, w),
                                            6 => signed(x, w) < signed(y, w),
                                            7 => x & y != 0,
                                            _ => unreachable!(),
                                        };
                                        if yes {
                                            expected |= u128::from(mask(w)) << (i * usize::from(w));
                                        }
                                    }
                                    let word = if scalar_mode {
                                        scalar
                                    } else {
                                        vector | (size << 22) | ((q as u32) << 30)
                                    } | ((n as u32) << 5)
                                        | d as u32
                                        | if zero { 0 } else { (m as u32) << 16 };
                                    assert_eq!(
                                        run(&recipe(word), &s, d),
                                        expected,
                                        "{word:08x} x={x:032x} y={y:032x}"
                                    );
                                    let chunks = if bits == 128 { 3 } else { 1 };
                                    assert_eq!(
                                        s.reads.get(),
                                        (chunks << (n * 2))
                                            | if zero { 0 } else { chunks << (m * 2) },
                                        "extra source {word:08x}"
                                    );
                                    executions += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("independent compare boundary/alias executions: {executions}");
    }
    fn imm_word(cmode: u32, op: bool, q: bool, imm: u8, d: u32) -> u32 {
        0x0f000400
            | ((q as u32) << 30)
            | ((op as u32) << 29)
            | ((u32::from(imm) >> 5) << 16)
            | (cmode << 12)
            | ((u32::from(imm) & 31) << 5)
            | d
    }
    // Byte-oriented expansion oracle; does not share the implementation's
    // shift/replicate path. All 256 immediates and all integer cmode/op/Q forms.
    fn expanded_bytes(cmode: u32, op: bool, imm: u8) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        if cmode == 14 {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = if op {
                    if imm & (1 << i) != 0 {
                        255
                    } else {
                        0
                    }
                } else {
                    imm
                };
            }
        } else if cmode >= 12 {
            let shift = if cmode == 12 { 1 } else { 2 };
            for i in 0..8 {
                if i % 4 < shift {
                    bytes[i] = 255
                } else if i % 4 == shift {
                    bytes[i] = imm
                }
            }
        } else {
            let period = if cmode < 8 { 4 } else { 2 };
            let position = if cmode < 8 {
                cmode as usize / 2
            } else {
                (cmode as usize - 8) / 2
            };
            for i in 0..8 {
                if i % period == position {
                    bytes[i] = imm
                }
            }
        }
        bytes
    }
    #[test]
    fn all_modified_immediates_complete_byte_domains_and_fresh_destinations() {
        let old = 0x9182736455aa00ff_fedcba9876543210u128;
        let mut count = 0;
        for cmode in 0..15 {
            for op in [false, true] {
                for q in [false, true] {
                    for imm in 0..=255u8 {
                        for d in [0, 31] {
                            let mut s = State::default();
                            let modify = cmode < 12 && cmode & 1 != 0;
                            let expanded = expanded_bytes(cmode, op, imm);
                            let bits = if q { 128 } else { 64 };
                            let mut expected = [0u8; 16];
                            let oldbytes = old.to_le_bytes();
                            for i in 0..bits / 8 {
                                let v = expanded[i % 8];
                                expected[i] = if modify {
                                    if op {
                                        oldbytes[i] & !v
                                    } else {
                                        oldbytes[i] | v
                                    }
                                } else if op && cmode != 14 {
                                    !v
                                } else {
                                    v
                                };
                            }
                            // MOVI/MVNI must work with a wholly unavailable old destination;
                            // ORR/BIC may read only the active 64/128-bit portion.
                            if modify {
                                set(&mut s, d as usize, old, bits);
                            }
                            let word = imm_word(cmode, op, q, imm, d);
                            assert_eq!(
                                run(&recipe(word), &s, d as usize),
                                u128::from_le_bytes(expected),
                                "{word:08x}"
                            );
                            assert_eq!(
                                s.reads.get(),
                                if modify {
                                    (if q { 3 } else { 1 }) << (d * 2)
                                } else {
                                    0
                                },
                                "{word:08x}"
                            );
                            count += 1;
                        }
                    }
                }
            }
        }
        println!("complete integer immediate selector/domain executions: {count}");
    }
    fn urecpe(x: u32) -> u32 {
        if x < 0x80000000 {
            return u32::MAX;
        }
        let a = u64::from(x >> 23) * 2 + 1;
        ((((1u64 << 19) / a + 1) / 2) as u32) << 23
    }
    fn ursqrte(x: u32) -> u32 {
        if x < 0x40000000 {
            return u32::MAX;
        }
        let mut a = u64::from(x >> 23);
        if a < 256 {
            a = a * 2 + 1
        } else {
            a = ((a >> 1) * 2 + 1) * 2
        }
        let mut b = 512u64;
        while a * (b + 1) * (b + 1) < 1u64 << 28 {
            b += 1
        }
        (((b + 1) / 2) as u32) << 23
    }
    #[test]
    fn unsigned_estimates_every_input_bin_threshold_low_bits_and_alias() {
        let mut count = 0;
        for sqrt in [false, true] {
            for q in [false, true] {
                for d in [0, 31] {
                    let word = if sqrt { 0x2ea1c800 } else { 0x0ea1c800 }
                        | ((q as u32) << 30)
                        | (31 << 5)
                        | d;
                    let r = recipe(word);
                    let bits = if q { 128 } else { 64 };
                    for bin in 0..512u32 {
                        for low in [0, 1, 0x007fffff] {
                            let mut s = State::default();
                            let mut src = 0u128;
                            let mut expected = 0u128;
                            for i in 0..bits / 32 {
                                let x = (((bin + i as u32 * 127) & 511) << 23) | low;
                                src |= u128::from(x) << (i * 32);
                                expected |= u128::from(if sqrt { ursqrte(x) } else { urecpe(x) })
                                    << (i * 32);
                            }
                            set(&mut s, 31, src, bits);
                            assert_eq!(
                                run(&r, &s, d as usize),
                                expected,
                                "{word:08x} source={src:032x}"
                            );
                            assert_eq!(s.reads.get(), (if q { 3 } else { 1 }) << 62);
                            count += 1;
                        }
                    }
                }
            }
        }
        println!("independent unsigned estimate bin/low-bit/alias executions: {count}");
    }
    #[test]
    fn unknown_values_stay_unknown_and_inactive_upper_chunks_are_not_read() {
        for word in [0x0e209820, 0x0e228c20, 0x0ea1c820, 0x2ea1c820, 0x0f009400] {
            let t = evaluate(&recipe(word), &State::default()).unwrap();
            assert!(
                !t.registers[0].value.is_known(),
                "fabricated result {word:08x}"
            );
            assert_eq!(t.registers[1].value, Value::known(64, 0));
        }
    }
    #[test]
    fn reserved_and_adjacent_fp_integer_scalable_encodings_are_not_claimed_full() {
        for base in [
            0x0e209800, 0x2e208800, 0x0e208800, 0x2e209800, 0x0e20a800, 0x2e208c00, 0x0e203c00,
            0x0e203400, 0x2e203400, 0x2e203c00, 0x0e208c00,
        ] {
            assert!(matches!(
                recipe(base | (3 << 22)).support,
                Support::Unsupported(_)
            ));
        }
        for base in [0x0ea1c800, 0x2ea1c800] {
            for q in [0, 1 << 30] {
                assert!(matches!(
                    recipe(base | q | (1 << 22)).support,
                    Support::Unsupported(_)
                ))
            }
        }
        for word in [
            0x1e222820, 0x4e20d800, 0x0f00f400, 0x2f00f400, 0x4f00f400, 0x6f00f400, 0x0f000c00,
            0x4e205800, 0x0e212800, 0x2e213800, 0x4522e020,
        ] {
            assert!(
                a64(word, 0x1000).is_none(),
                "overclaimed adjacent word {word:08x}"
            );
        }
    }
    #[test]
    fn june_primary_diagrams_all_legal_selector_and_alias_cases() {
        assert!(super::PRIMARY.is_empty() || super::PRIMARY.len() > 400);
        for &(word, legal, name) in super::PRIMARY {
            let r = recipe(word);
            assert_eq!(
                r.support == Support::Full,
                legal,
                "primary {name} {word:08x}: {:?}",
                r.support
            );
            if legal {
                let mut s = State::default();
                s.available = u64::MAX;
                s.v = [0x80000000_ffffffff_00000000_01234567; 32];
                run(&r, &s, (word & 31) as usize);
            }
        }
    }
    // Conservative native expansion bound: temporary uses are scalar SSA
    // references; allow five native nodes for every other scalar node to cover
    // extract/shift/cast/boolean expansion, and include statement/flow overhead.
    // Actual Semantics::try_complete is a separate caller integration check.
    fn nodes(x: &Expr) -> usize {
        1 + match &x.kind {
            ExprKind::Constant(_) | ExprKind::Register(_) | ExprKind::Temporary(_) => 0,
            ExprKind::Binary { left, right, .. } => nodes(left) + nodes(right),
            ExprKind::Unary { value, .. }
            | ExprKind::Cast { value, .. }
            | ExprKind::Extract { value, .. } => nodes(value),
            ExprKind::Select { condition, yes, no } => nodes(condition) + nodes(yes) + nodes(no),
            other => panic!("unexpected expression {other:?}"),
        }
    }
    #[test]
    fn all_primary_graphs_bound_native_expansion_without_shared_subtree_explosion() {
        let mut maximum = 0;
        let mut worst = 0;
        for &(word, legal, _) in super::PRIMARY {
            if !legal {
                continue;
            }
            let r = recipe(word);
            let mut n = r.temporaries.iter().map(nodes).sum::<usize>();
            for effect in &r.effects {
                match effect {
                    Effect::WriteRegister { value, .. } => n += nodes(value) + 2,
                    other => panic!("unexpected effect {other:?}"),
                }
            }
            let bound = 5 * n + 32;
            if bound > maximum {
                maximum = bound;
                worst = word
            }
            assert!(bound < 4096, "{word:08x}: bound={bound}");
        }
        println!("conservative native expansion maximum={maximum} nodes, word={worst:08x}, native limit32768");
    }
}

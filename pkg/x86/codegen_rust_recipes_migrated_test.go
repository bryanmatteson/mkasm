package x86

// Keep admission over the complete source corpus and arithmetic independent of
// the generated recipe implementation. Splice separately tests its IR adapter.
const x86MigratedRecipeTests = `
const MIGRATED_NAMES: &[&str] = &[
    "SHLD", "SHRD", "RCL", "RCR", "AESENC", "AESENCLAST", "AESDEC", "AESDECLAST",
    "AESIMC", "AESKEYGENASSIST", "PCLMULQDQ", "GF2P8MULB", "GF2P8AFFINEQB",
    "GF2P8AFFINEINVQB",
];

#[test]
fn migrated_scalar_crypto_admits_every_supported_corpus_form() {
    for mode in [Mode::Mode16, Mode::Mode32, Mode::Mode64] {
        let mut covered = std::collections::HashSet::new();
        let mut count = 0;
        for index in 0..encoding_count() {
            let e = encoding(index).unwrap();
            let name = e.mnemonic.strip_prefix('V').unwrap_or(e.mnemonic);
            if !MIGRATED_NAMES.contains(&name) || !SSE_AVX_FORMS.contains(&e.form_id) || !encoding_supports_mode(index, mode) {
                continue;
            }
            let mut bytes = [0; 15];
            let len = encode_representative(index, mode, &mut bytes)
                .unwrap_or_else(|error| panic!("{mode:?} {}: {error:?}", e.form_id));
            let decoded = decode(&bytes[..len], mode).unwrap();
            let recipe = decoded.semantic_recipe(0x1000);
            assert_eq!(recipe.support, Support::Full, "{mode:?} {}", e.form_id);
            recipe.validate().unwrap();
            covered.insert(name);
            count += 1;
        }
        assert_eq!(covered, MIGRATED_NAMES.iter().copied().collect());
        println!("migrated scalar/crypto {mode:?}: {count} public corpus witnesses");
    }
}

#[test]
fn migrated_scalar_counts_follow_independent_bit_rings_in_all_modes() {
    for mode in [Mode::Mode16, Mode::Mode32, Mode::Mode64] {
        for width in [8, 16, 32, 64] {
            if mode != Mode::Mode64 && width == 64 { continue; }
            for left in [false, true] {
                for double in [false, true] {
                    if double && width == 8 { continue; }
                    for immediate in [false, true] {
                        for raw in 0..=255u8 {
                            let mut bytes = Vec::new();
                            if (width == 16 && mode != Mode::Mode16)
                                || (width == 32 && mode == Mode::Mode16) { bytes.push(0x66); }
                            if width == 64 { bytes.push(0x48); }
                            if double {
                                bytes.extend([0x0f, if left { 0xa4 } else { 0xac } + u8::from(!immediate), 0xd0]);
                            } else {
                                bytes.extend([if immediate { if width == 8 { 0xc0 } else { 0xc1 } }
                                    else if width == 8 { 0xd2 } else { 0xd3 }, if left { 0xd0 } else { 0xd8 }]);
                            }
                            if immediate { bytes.push(raw); }
                            let mask = u64::MAX >> (64 - width);
                            let input = 0xfedcba9876543210u64 & mask;
                            let source = 0x8123456789abcdefu64 & mask;
                            let n = u32::from(raw & if width == 64 { 63 } else { 31 });
                            for incoming_carry in [0, 1] {
                                let mut state = State::default();
                                state.x(0, input);
                                state.x(1, u64::from(raw));
                                state.x(2, source);
                                for flag in 0..6 { state.reg("x86.flags", flag, incoming_carry); }
                                let t = mode_run(&bytes, mode, 0x1000, &state);
                                assert_eq!(t.next_pc.bits, 0x1000 + bytes.len() as u64);
                                if double && n > width { assert_eq!(reg(&t, "x86.gpr", 0).defined & mask, 0); continue; }
                                let mut result = input;
                                let mut carry = incoming_carry;
                                for bit in 0..n {
                                    let outgoing = if left { result >> (width - 1) } else { result & 1 };
                                    let incoming = if double {
                                        if left { source >> (width - 1 - bit) & 1 } else { source >> bit & 1 }
                                    } else { carry };
                                    result = if left { result.wrapping_shl(1) | incoming }
                                        else { result >> 1 | incoming << (width - 1) } & mask;
                                    carry = outgoing;
                                }
                                assert_eq!(x(&t, 0) & mask, result, "{mode:?} {bytes:02x?}");
                                assert_eq!(flag(&t, 0), Value::known(1, carry));
                                if n == 0 { assert_eq!(flag(&t, 5), Value::known(1, incoming_carry)); }
                                else if n == 1 {
                                    let of = if double { (input ^ result) >> (width - 1) }
                                        else if left { result >> (width - 1) ^ carry }
                                        else { result >> (width - 1) ^ result >> (width - 2) } & 1;
                                    assert_eq!(flag(&t, 5), Value::known(1, of));
                                } else { assert_eq!(flag(&t, 5).defined, 0); }
                                if !double {
                                    assert!(t.registers.iter().all(|r| r.register.bank != "x86.flags"
                                        || r.register.index == 0 || r.register.index == 5));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
`

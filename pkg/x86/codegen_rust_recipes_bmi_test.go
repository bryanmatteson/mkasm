package x86

// Execute the migrated BMI family using freshly generated code and independent
// integer arithmetic. Native Splice tests separately require its generated adapter.
const x86BMIRecipeTests = `
const BMI_NAMES: &[&str] = &[
    "ANDN", "BEXTR", "BLSI", "BLSMSK", "BLSR", "BZHI", "MULX", "PDEP", "PEXT", "RORX", "SARX",
    "SHLX", "SHRX",
];

#[test]
fn generated_bmi_admits_every_encodable_corpus_form_without_a_fallback() {
    for mode in [Mode::Mode16, Mode::Mode32, Mode::Mode64] {
        let mut covered = std::collections::HashSet::new();
        let mut forms = 0;
        for index in 0..encoding_count() {
            let encoding = encoding(index).unwrap();
            if !BMI_NAMES.contains(&encoding.mnemonic) || !encoding_supports_mode(index, mode) {
                continue;
            }
            let mut bytes = [0; 15];
            let len = encode_representative(index, mode, &mut bytes)
                .unwrap_or_else(|error| panic!("BMI corpus form has no witness: {mode:?} {} {error:?}", encoding.form_id));
            let decoded = decode(&bytes[..len], mode).unwrap();
            let recipe = decoded.semantic_recipe(0x1000);
            assert_eq!(
                recipe.support,
                Support::Full,
                "{mode:?} {} {:02x?}",
                encoding.form_id,
                &bytes[..len]
            );
            recipe.validate().unwrap();
            covered.insert(encoding.mnemonic);
            forms += 1;
        }
        if mode != Mode::Mode16 {
            assert_eq!(covered, BMI_NAMES.iter().copied().collect());
        }
        println!("generated BMI {mode:?}: {forms} encodable corpus forms");
    }
}

#[test]
fn generated_mulx_full_product_aliases_and_implicit_source_preserve_flags() {
    let values = [
        0,
        1,
        7,
        0x80000000,
        0xffffffff,
        0x8000000000000000,
        u64::MAX,
        0x123456789abcdef,
    ];
    for width in [32, 64] {
        let mask = u64::MAX >> (64 - width);
        for memory in [false, true] {
            // Include identical destinations, each destination aliasing RDX,
            // each destination aliasing the explicit source, and RDX squared.
            for (high, low, source) in [
                (0, 3, 1),
                (0, 0, 1),
                (2, 0, 1),
                (0, 2, 2),
                (1, 0, 1),
                (0, 1, 1),
            ] {
                for a in values {
                    for b in values {
                        let mut state = State::default();
                        for n in 0..8 {
                            state.x(n, 0xfeedfacecafebeef);
                        }
                        state.x(2, a);
                        if memory {
                            state.x(6, 0x2000);
                            state.mem.insert(0x2000, b);
                        } else if source != 2 {
                            state.x(source, b);
                        }
                        for f in 0..7 {
                            state.reg("x86.flags", f, 1);
                        }
                        let third =
                            if width == 64 { 0x80 } else { 0 } | ((!low as u8 & 15) << 3) | 3;
                        let bytes = [
                            0xc4,
                            0xe2,
                            third,
                            0xf6,
                            (if memory { 0 } else { 0xc0 })
                                | (high as u8) << 3
                                | if memory { 6 } else { source as u8 },
                        ];
                        let product = u128::from(a & mask)
                            * u128::from(if !memory && source == 2 { a } else { b } & mask);
                        let mut expected = std::collections::HashMap::new();
                        expected.insert(low, product as u64 & mask);
                        expected.insert(high, (product >> width) as u64);
                        let transition = run(&bytes, &state);
                        for (register, value) in expected {
                            assert_eq!(x(&transition, register), value, "{bytes:02x?} {a:x} {b:x}");
                        }
                        assert!(transition
                            .registers
                            .iter()
                            .all(|r| r.register.bank != "x86.flags"));
                        assert!(transition.memory.is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn generated_tbm_bextr_uses_immediate_low_bytes_for_all_bit_boundaries() {
    for mode in [Mode::Mode32, Mode::Mode64] {
        for width in [32, 64] {
            if mode == Mode::Mode32 && width == 64 {
                continue;
            }
            let mask = u64::MAX >> (64 - width);
            for memory in [false, true] {
                for control in [
                    0u32, 0x100, 0x802, 0x201f, 0x4020, 0xffff, 0x80ffff00, 0x11040,
                ] {
                    for value in [0, 1, u64::MAX, 0x123456789abcdef, 0x8000000000000000] {
                        let mut state = State::default();
                        state.x(0, u64::MAX);
                        state.x(1, value);
                        state.x(3, 0x2000);
                        state.mem.insert(0x2000, value);
                        let mut bytes = vec![
                            0x8f,
                            0xea,
                            if width == 64 { 0xf8 } else { 0x78 },
                            0x10,
                            if memory { 3 } else { 0xc1 },
                        ];
                        bytes.extend(control.to_le_bytes());
                        let start = control & 255;
                        let len = control >> 8 & 255;
                        let source = value & mask;
                        let expected = (0..width)
                            .filter(|&bit| bit >= start && bit < start + len)
                            .fold(0, |result, bit| {
                                result | ((source >> bit & 1) << (bit - start))
                            });
                        let transition = mode_run(&bytes, mode, 0x1000, &state);
                        let stored = if mode == Mode::Mode32 { expected | !mask } else { expected };
                        assert_eq!(
                            x(&transition, 0),
                            stored,
                            "{mode:?} {bytes:02x?} {value:x}"
                        );
                        assert_eq!(flag(&transition, 0), Value::known(1, 0));
                        assert_eq!(flag(&transition, 5), Value::known(1, 0));
                        assert_eq!(
                            flag(&transition, 3),
                            Value::known(1, u64::from(expected == 0))
                        );
                        for f in [1, 2, 4] {
                            assert_eq!(flag(&transition, f).defined, 0);
                        }
                        assert_eq!(transition.next_pc.bits, 0x1000 + bytes.len() as u64);
                    }
                }
            }
        }
    }
}

#[test]
fn generated_bmi_new_memory_forms_issue_one_read_and_propagate_faults() {
    struct Memory<'a> {
        state: &'a State,
        reads: std::cell::Cell<usize>,
        fail: bool,
    }
    impl Machine for Memory<'_> {
        fn read_register(&self, r: s::Register) -> Value {
            self.state.read_register(r)
        }
        fn read_memory(
            &self,
            address: u64,
            width: u8,
            endian: s::Endian,
        ) -> Result<Value, EvalError> {
            self.reads.set(self.reads.get() + 1);
            assert_eq!((address, width), (0x2000, 64));
            if self.fail {
                Err(EvalError::Memory)
            } else {
                self.state.read_memory(address, width, endian)
            }
        }
    }
    let mut state = State::default();
    state.x(2, 7);
    state.x(3, 0x2000);
    state.mem.insert(0x2000, 9);
    for bytes in [
        &[0xc4, 0xe2, 0xe3, 0xf6, 0x03][..],
        &[0x8f, 0xea, 0xf8, 0x10, 0x03, 2, 8, 0, 0],
    ] {
        let recipe = decode(bytes, Mode::Mode64).unwrap().semantic_recipe(0x1000);
        assert_eq!(recipe.support, Support::Full);
        for fail in [false, true] {
            let memory = Memory {
                state: &state,
                reads: std::cell::Cell::new(0),
                fail,
            };
            let result = s::evaluate(&recipe, &memory);
            assert_eq!(memory.reads.get(), 1);
            if fail {
                assert!(matches!(result, Err(EvalError::Memory)));
            } else {
                assert!(result.is_ok());
            }
        }
    }
}
`

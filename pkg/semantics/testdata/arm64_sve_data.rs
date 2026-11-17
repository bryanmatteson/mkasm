include!("sve_integer_base.rs");
struct DataState(State);
impl Machine for DataState {
    fn read_register(&self, r: Register) -> Value {
        if r.bank == "a64.sme2p2" {
            Value::known(1, *self.0.registers.get(&r).unwrap_or(&0))
        } else {
            self.0.read_register(r)
        }
    }
    fn read_memory(&self, a: u64, w: u8, endian: Endian) -> Result<Value, EvalError> {
        self.0.read_memory(a, w, endian)
    }
}
fn data_run(word: u32, vl: u16, s: &DataState) -> Transition {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x} VL{vl}"));
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    evaluate(&r, s).unwrap()
}
#[test]
fn compact_stable_all_widths_vls_alias_empty_and_streaming_context() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for alias in [false, true] {
                for empty in [false, true] {
                    let n = if alias { 0 } else { 1 };
                    let mut s = State::default();
                    let mut expected = Vec::new();
                    for e in 0..vl / w as u16 {
                        s.lane(n, e, w, u64::from(e) + 7);
                        if !empty && (e % 5 == 1 || e % 5 == 4) {
                            s.predicate(0, e, w);
                            expected.push((u64::from(e) + 7) & mask(w));
                        }
                    }
                    let word = (if w < 32 { 0x05218000 } else { 0x05a18000 })
                        | (((w.trailing_zeros() - 3) % 2) << 22)
                        | (u32::from(n) << 5);
                    let mut s = DataState(s);
                    if empty && !alias {
                        s.0.forbidden = Some(n);
                    }
                    let t = data_run(word, vl, &s);
                    for e in 0..vl / w as u16 {
                        assert_eq!(
                            output(&t, 0, e, w),
                            expected.get(e as usize).copied().unwrap_or(0)
                        );
                    }
                }
            }
        }
    }
    let mut s = DataState(State::default());
    s.0.set("a64.svcr", 0, 1);
    let r = recipe(0x05a18020, 128).unwrap();
    assert!(matches!(
        evaluate(&r, &s),
        Err(EvalError::UnsupportedContext)
    ));
    for bank in ["a64.sme_fa64", "a64.sme2p2"] {
        s.0.set(bank, 0, 1);
        assert!(evaluate(&r, &s).is_ok());
        s.0.set(bank, 0, 0);
    }
}

#[test]
fn compact_sme2p2_streaming_does_not_consume_fa64() {
    struct WithoutFa64(DataState);
    impl Machine for WithoutFa64 {
        fn read_register(&self, r: Register) -> Value {
            assert_ne!(
                r.bank, "a64.sme_fa64",
                "SME2p2 selects CheckSVEEnabled without FA64"
            );
            self.0.read_register(r)
        }
        fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
            self.0.read_memory(a, w, e)
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for size in 0..4 {
            let mut s = WithoutFa64(DataState(State::default()));
            s.0 .0.set("a64.svcr", 0, 1);
            s.0 .0.set("a64.sme2p2", 0, 1);
            let r = recipe(0x05218020 | (size << 22), vl).unwrap();
            assert_eq!(r.support, Support::Full);
            r.validate().unwrap();
            let t = evaluate(&r, &s).unwrap();
            assert!(t
                .registers
                .iter()
                .all(|out| out.value.bits == 0 && out.value.is_known()));
        }
    }
}
#[test]
fn splice_copies_span_not_only_active_lanes_and_wraps_constructive_sources() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for constructive in [false, true] {
                for pattern in [0, 1, 2, 3] {
                    let (s1, s2) = if constructive { (31, 0) } else { (0, 1) };
                    let mut s = State::default();
                    let len = vl / w as u16;
                    for e in 0..len {
                        s.lane(s1, e, w, 20 + u64::from(e));
                        s.lane(s2, e, w, 90 + u64::from(e));
                    }
                    let active: Vec<_> = (0..len)
                        .filter(|e| match pattern {
                            0 => false,
                            1 => e % 3 == 1,
                            2 => *e == len - 1,
                            _ => true,
                        })
                        .collect();
                    for &e in &active {
                        s.predicate(0, e, w);
                    }
                    let (first, count) = if active.is_empty() {
                        (0, 0)
                    } else {
                        (active[0], active[active.len() - 1] - active[0] + 1)
                    };
                    if active.is_empty() && s1 != s2 {
                        s.forbidden = Some(s1);
                    }
                    let inst = word(
                        if constructive { 0x052d8000 } else { 0x052c8000 },
                        w,
                        0,
                        if constructive { 31 } else { 1 },
                        0,
                    );
                    let t = run(inst, vl, &s);
                    for e in 0..len {
                        let expected = if e < count {
                            incoming(&s, s1, e + first, w)
                        } else {
                            incoming(&s, s2, e - count, w)
                        };
                        assert_eq!(output(&t, 0, e, w), expected, "{inst:08x} e{e}");
                    }
                }
            }
        }
    }
}
#[test]
fn last_and_conditional_last_scalar_vector_gpr_destinations_preserve_contracts() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for before in [false, true] {
                for conditional in [false, true] {
                    for kind in 0..3 {
                        if kind == 2 && !conditional {
                            continue;
                        }
                        for active in [None, Some(0), Some(vl / w as u16 - 1)] {
                            let mut s = State::default();
                            let len = vl / w as u16;
                            for e in 0..len {
                                s.lane(0, e, w, 37 + u64::from(e));
                            }
                            s.set("a64.gpr", 0, u64::MAX);
                            s.set("a64.sp", 0, 0xaabbccdd);
                            if let Some(e) = active {
                                s.predicate(0, e, w);
                            }
                            let base = match (kind, conditional) {
                                (0, false) => 0x0520a000,
                                (0, true) => 0x0530a000,
                                (1, false) => 0x05228000,
                                (1, true) => 0x052a8000,
                                _ => 0x05288000,
                            };
                            let inst = word(base | ((before as u32) << 16), w, 0, 0, 0);
                            let t = run(inst, vl, &s);
                            let index = active
                                .map(|e| if before { e } else { (e + 1) % len })
                                .unwrap_or(if before { len - 1 } else { 0 });
                            let selected = incoming(&s, 0, index, w);
                            if kind == 0 {
                                assert_eq!(
                                    reg(&t, "a64.gpr", 0),
                                    if conditional && active.is_none() {
                                        mask(w)
                                    } else {
                                        selected
                                    }
                                );
                            } else {
                                for e in 0..len {
                                    let expected = if kind == 1 && e > 0 {
                                        0
                                    } else if conditional && active.is_none() {
                                        incoming(&s, 0, e, w)
                                    } else {
                                        selected
                                    };
                                    assert_eq!(output(&t, 0, e, w), expected, "{inst:08x} e{e}");
                                }
                            }
                            let zr = run(inst | 31, vl, &s);
                            if kind == 0 {
                                assert!(zr.registers.is_empty());
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn insert_and_unpack_all_widths_signs_halves_aliases_and_zero_register() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for vector in [false, true] {
                let mut s = State::default();
                for e in 0..vl / w as u16 {
                    s.lane(0, e, w, 5 + u64::from(e));
                }
                s.set("a64.gpr", 0, 0x9876543212345678);
                let inst = word(if vector { 0x05343800 } else { 0x05243800 }, w, 0, 0, 0);
                let t = run(inst, vl, &s);
                for e in 0..vl / w as u16 {
                    let expected = if e > 0 {
                        incoming(&s, 0, e - 1, w)
                    } else if vector {
                        incoming(&s, 0, 0, w)
                    } else {
                        0x9876543212345678 & mask(w)
                    };
                    assert_eq!(output(&t, 0, e, w), expected);
                }
                if !vector {
                    s.set("a64.sp", 0, u64::MAX);
                    let t = run(inst | (31 << 5), vl, &s);
                    assert_eq!(output(&t, 0, 0, w), 0);
                }
            }
            if w > 8 {
                for unsigned in [false, true] {
                    for high in [false, true] {
                        let mut s = State::default();
                        for e in 0..vl / (w / 2) as u16 {
                            s.lane(
                                0,
                                e,
                                w / 2,
                                if e % 2 == 0 {
                                    mask(w / 2) - u64::from(e) % 7
                                } else {
                                    u64::from(e)
                                },
                            );
                        }
                        let inst = word(
                            0x05303800 | ((unsigned as u32) << 17) | ((high as u32) << 16),
                            w,
                            0,
                            0,
                            0,
                        );
                        let t = run(inst, vl, &s);
                        let len = vl / w as u16;
                        for e in 0..len {
                            let a = incoming(&s, 0, e + if high { len } else { 0 }, w / 2);
                            let expected = if unsigned {
                                a
                            } else {
                                signed(a, w / 2) as u64 & mask(w)
                            };
                            assert_eq!(output(&t, 0, e, w), expected);
                        }
                    }
                }
            }
        }
    }
    assert!(recipe(0x05303800, 128).is_none());
}
#[test]
fn logical_masks_exhaustive_encoding_domain_and_all_ternary_aliases() {
    let mut masks = HashMap::new();
    for size in [2u32, 4, 8, 16, 32, 64] {
        for ones in 1..size {
            for rotation in 0..64u32 {
                let mut pattern = 0u64;
                for bit in 0..64 {
                    if (bit + rotation) % size < ones {
                        pattern |= 1 << bit;
                    }
                }
                let imms = (((!(size - 1)) << 1) | (ones - 1)) & 63;
                let encoded = ((size == 64) as u32) << 12 | rotation << 6 | imms;
                masks.insert(encoded, pattern);
            }
        }
    }
    for encoded in 0..8192 {
        for base in [0x05000000, 0x05400000, 0x05800000, 0x05c00000] {
            let inst = base | encoded << 5;
            let r = recipe(inst, 128);
            if let Some(&pattern) = masks.get(&encoded) {
                let mut s = State::default();
                s.set("a64.vector64", 0, 0x90ab1234dcba4321);
                s.set("a64.vector64", 1, u64::MAX);
                let t = run(inst, 128, &s);
                for chunk in 0..2 {
                    let old = *s
                        .registers
                        .get(&Register {
                            bank: "a64.vector64",
                            index: chunk,
                        })
                        .unwrap();
                    let expected = match base {
                        0x05000000 => old | pattern,
                        0x05400000 => old ^ pattern,
                        0x05800000 => old & pattern,
                        _ => pattern,
                    };
                    assert_eq!(reg(&t, "a64.vector64", chunk), expected, "{inst:08x}");
                }
            } else {
                assert!(r.is_none(), "reserved mask {inst:08x}");
            }
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for base in [
            0x04203800, 0x04603800, 0x04203c00, 0x04603c00, 0x04a03c00, 0x04e03c00,
        ] {
            for n in 0..3 {
                for m in 0..3 {
                    let mut s = State::default();
                    for chunk in 0..vl / 64 {
                        for source in 0..3 {
                            s.set(
                                "a64.vector64",
                                source * 32 + chunk,
                                0x123456789abcdef0u64
                                    .wrapping_mul(u64::from(source + 1))
                                    .rotate_left(chunk as u32),
                            );
                        }
                    }
                    let t = run(base | (n << 5) | (m << 16), vl, &s);
                    for chunk in 0..vl / 64 {
                        let a = incoming(&s, 0, chunk, 64);
                        let k = incoming(&s, n as u16, chunk, 64);
                        let b = incoming(&s, m as u16, chunk, 64);
                        let expected = match base {
                            0x04203800 => a ^ b ^ k,
                            0x04603800 => a ^ (b & !k),
                            0x04203c00 => (a & k) | (b & !k),
                            0x04603c00 => (!a & k) | (b & !k),
                            0x04a03c00 => (a & k) | (!b & !k),
                            _ => !((a & k) | (b & !k)),
                        };
                        assert_eq!(output(&t, 0, chunk, 64), expected);
                    }
                }
            }
        }
    }
}
#[test]
fn xar_every_immediate_width_and_vl() {
    for vl in [128, 256, 512, 1024, 2048] {
        for tsize in 1..16u32 {
            let w = 8u8 << (31 - tsize.leading_zeros());
            for imm in 0..8 {
                let rotation = 2 * w as u32 - (tsize * 8 + imm);
                let mut s = State::default();
                for e in 0..vl / w as u16 {
                    s.lane(0, e, w, 0x87654321fedcba98u64.rotate_left(e as u32));
                    s.lane(1, e, w, 0xabcd0000ee55aa11);
                }
                let inst = 0x04203400
                    | ((tsize >> 2) << 22)
                    | ((tsize & 3) << 19)
                    | (imm << 16)
                    | (1 << 5);
                let t = run(inst, vl, &s);
                for e in 0..vl / w as u16 {
                    let a = incoming(&s, 0, e, w) ^ incoming(&s, 1, e, w);
                    let r = rotation % w as u32;
                    let expected = if r == 0 {
                        a
                    } else {
                        ((a >> r) | (a << (w as u32 - r))) & mask(w)
                    };
                    assert_eq!(output(&t, 0, e, w), expected);
                }
            }
        }
    }
    assert!(recipe(0x04203400, 128).is_none());
}
fn rounded(a: i128, shift: i128) -> i128 {
    if shift > 0 {
        (a + (1i128 << (shift - 1))) >> shift
    } else {
        a
    }
}
#[test]
fn halving_pairwise_and_widening_pair_accumulate_all_vls_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x44108000, 0x44118000, 0x44128000, 0x44138000, 0x44148000, 0x44158000, 0x44168000,
                0x44178000, 0x4411a000, 0x4414a000, 0x4415a000, 0x4416a000, 0x4417a000, 0x4404a000,
                0x4405a000,
            ] {
                if w == 8 && base & 0xff3ee000 == 0x4404a000 {
                    continue;
                }
                for alias in [false, true] {
                    let n = if alias { 0 } else { 1 };
                    let mut s = State::default();
                    let edge = [0, 1, mask(w), 1u64 << (w - 1), (1u64 << (w - 1)) - 1];
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, edge[e as usize % 5]);
                        s.lane(n, e, w, edge[(e as usize + 2) % 5]);
                        if e % 3 != 1 {
                            s.predicate(0, e, w);
                        }
                    }
                    s.set("a64.fpsr", 0, 0x08000011);
                    let t = run(word(base, w, 0, n as u32, 0), vl, &s);
                    let unsigned = base & (1 << 16) != 0;
                    let val = |src, e, width| {
                        let a = incoming(&s, src, e, width);
                        if unsigned {
                            i128::from(a)
                        } else {
                            signed(a, width)
                        }
                    };
                    for e in 0..vl / w as u16 {
                        let old = incoming(&s, 0, e, w);
                        let expected = if e % 3 == 1 {
                            old
                        } else if base & 0xff3ee000 == 0x4404a000 {
                            old.wrapping_add(
                                (val(n, e * 2, w / 2) + val(n, e * 2 + 1, w / 2)) as u64,
                            ) & mask(w)
                        } else if base & 0xe000 == 0xa000 {
                            let src = if e % 2 == 0 { 0 } else { n };
                            let a = val(src, e & !1, w);
                            let b = val(src, (e & !1) + 1, w);
                            (match base {
                                0x4411a000 => a + b,
                                0x4414a000 | 0x4415a000 => a.max(b),
                                _ => a.min(b),
                            }) as u64
                                & mask(w)
                        } else {
                            let a = val(0, e, w);
                            let b = val(n, e, w);
                            let value = if base & (1 << 17) != 0 {
                                if base & (1 << 18) != 0 {
                                    b - a
                                } else {
                                    a - b
                                }
                            } else {
                                a + b
                            };
                            (if base & (1 << 18) != 0 && base & (1 << 17) == 0 {
                                rounded(value, 1)
                            } else {
                                value >> 1
                            }) as u64
                                & mask(w)
                        };
                        assert_eq!(output(&t, 0, e, w), expected, "{base:08x} w{w} e{e}");
                    }
                    assert!(t.registers.iter().all(|r| r.register.bank != "a64.fpsr"));
                }
            }
        }
    }
}
#[test]
fn rounded_saturating_variable_shifts_full_signed_counts_and_boundaries() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x44028000, 0x44038000, 0x44068000, 0x44078000, 0x44088000, 0x44098000, 0x440a8000,
                0x440b8000, 0x440c8000, 0x440d8000, 0x440e8000, 0x440f8000,
            ] {
                for alias in [false, true] {
                    let n = if alias { 0 } else { 1 };
                    let reversed = base & (1 << 18) != 0;
                    let mut s = State::default();
                    let counts = [
                        0,
                        1,
                        -1,
                        w as i128,
                        -(w as i128),
                        w as i128 + 1,
                        -(w as i128) - 1,
                        i128::from(mask(w)),
                        signed(1u64 << (w - 1), w),
                    ];
                    let vals = [0, 1, mask(w), 1u64 << (w - 1), (1u64 << (w - 1)) - 1];
                    for start in 0..counts.len() {
                        for e in 0..vl / w as u16 {
                            s.lane(
                                if reversed { n } else { 0 },
                                e,
                                w,
                                vals[e as usize % vals.len()],
                            );
                            s.lane(
                                if reversed { 0 } else { n },
                                e,
                                w,
                                counts[(start + e as usize) % counts.len()] as u64,
                            );
                            if e % 3 != 1 {
                                s.predicate(0, e, w);
                            }
                        }
                        let t = run(word(base, w, 0, n as u32, 0), vl, &s);
                        let unsigned = base & (1 << 16) != 0;
                        let saturation = base & (1 << 19) != 0;
                        let rounding = base & (1 << 17) != 0;
                        for e in 0..vl / w as u16 {
                            let old = incoming(&s, 0, e, w);
                            let input = incoming(&s, if reversed { n } else { 0 }, e, w);
                            let value = if unsigned {
                                i128::from(input)
                            } else {
                                signed(input, w)
                            };
                            let shift = signed(incoming(&s, if reversed { 0 } else { n }, e, w), w)
                                .clamp(-(w as i128 + 1), w as i128 + 1);
                            let res = if shift < 0 {
                                if rounding {
                                    rounded(value, -shift)
                                } else {
                                    value >> (-shift)
                                }
                            } else if shift >= w as i128 {
                                if !saturation || value == 0 {
                                    0
                                } else if value < 0 {
                                    i128::MIN
                                } else {
                                    i128::MAX
                                }
                            } else {
                                value.checked_shl(shift as u32).unwrap_or(0)
                            };
                            let expected = if e % 3 == 1 {
                                old
                            } else if saturation {
                                res.clamp(
                                    if unsigned { 0 } else { -(1i128 << (w - 1)) },
                                    if unsigned {
                                        i128::from(mask(w))
                                    } else {
                                        (1i128 << (w - 1)) - 1
                                    },
                                ) as u64
                                    & mask(w)
                            } else {
                                res as u64 & mask(w)
                            };
                            assert_eq!(
                                output(&t, 0, e, w),
                                expected,
                                "{base:08x} w{w} e{e} old{old:x} shift{shift}"
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn immediate_round_saturating_and_accumulating_shifts_every_legal_count() {
    for vl in [128, 256, 512, 1024, 2048] {
        for tsize in 1..16u32 {
            let w = 8u8 << (31 - tsize.leading_zeros());
            for imm in 0..8u32 {
                for base in [
                    0x04068000, 0x04078000, 0x040f8000, 0x040c8000, 0x040d8000, 0x4500e800,
                    0x4500ec00,
                ] {
                    let accumulate = base >> 24 == 0x45;
                    let left = base == 0x04068000 || base == 0x04078000 || base == 0x040f8000;
                    let shift = if left {
                        tsize * 8 + imm - w as u32
                    } else {
                        2 * w as u32 - (tsize * 8 + imm)
                    };
                    let unsigned = base == 0x04078000 || base == 0x040d8000 || base == 0x4500ec00;
                    let mut s = State::default();
                    let edge = [0, 1, mask(w), 1u64 << (w - 1), (1u64 << (w - 1)) - 1];
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, edge[e as usize % 5]);
                        s.lane(1, e, w, edge[(e as usize + 2) % 5]);
                        if e % 3 != 1 {
                            s.predicate(0, e, w);
                        }
                    }
                    let inst = base
                        | ((tsize >> 2) << 22)
                        | if accumulate {
                            ((tsize & 3) << 19) | (imm << 16) | (1 << 5)
                        } else {
                            ((tsize & 3) << 8) | (imm << 5)
                        };
                    let t = run(inst, vl, &s);
                    for e in 0..vl / w as u16 {
                        let old = incoming(&s, 0, e, w);
                        let a = incoming(&s, if accumulate { 1 } else { 0 }, e, w);
                        let a = if unsigned {
                            i128::from(a)
                        } else {
                            signed(a, w)
                        };
                        let value = if left {
                            (a << shift).clamp(
                                if unsigned || base == 0x040f8000 {
                                    0
                                } else {
                                    -(1i128 << (w - 1))
                                },
                                if unsigned || base == 0x040f8000 {
                                    i128::from(mask(w))
                                } else {
                                    (1i128 << (w - 1)) - 1
                                },
                            )
                        } else {
                            rounded(a, shift as i128)
                        };
                        let expected = if accumulate {
                            old.wrapping_add(value as u64) & mask(w)
                        } else if e % 3 == 1 {
                            old
                        } else {
                            value as u64 & mask(w)
                        };
                        assert_eq!(
                            output(&t, 0, e, w),
                            expected,
                            "{inst:08x} w{w} shift{shift} e{e}"
                        );
                    }
                }
            }
        }
    }
    for base in [
        0x04068000, 0x04078000, 0x040f8000, 0x040c8000, 0x040d8000, 0x4500e800, 0x4500ec00,
    ] {
        assert!(recipe(base, 128).is_none());
    }
}
#[test]
fn widening_and_narrowing_complete_shapes_preserved_top_lanes_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            for base in [
                0x45000000, 0x45000400, 0x45000800, 0x45000c00, 0x45001000, 0x45001400, 0x45001800,
                0x45001c00, 0x45004000, 0x45004400, 0x45004800, 0x45004c00, 0x45005000, 0x45005400,
                0x45005800, 0x45005c00, 0x45206000, 0x45206400, 0x45206800, 0x45206c00, 0x45207000,
                0x45207400, 0x45207800, 0x45207c00,
            ] {
                for alias in 0..3 {
                    let n = if alias == 1 { 0 } else { 1 };
                    let m = if alias == 2 { 0 } else { 2 };
                    let mut s = State::default();
                    for source in 0..3 {
                        for e in 0..vl / (w / 2) as u16 {
                            s.lane(
                                source,
                                e,
                                w / 2,
                                if e % 3 == 0 {
                                    mask(w / 2) - u64::from(e % 5)
                                } else {
                                    u64::from(e + source + 1)
                                },
                            );
                        }
                    }
                    let t = run(word(base, w, 0, n, m), vl, &s);
                    let top = base & (1 << 10) != 0;
                    let unsigned = base & (1 << 11) != 0;
                    let subtract = base & (1 << 12) != 0;
                    let narrow = base & (1 << 21) != 0;
                    let wide = base & (1 << 14) != 0;
                    for e in 0..vl / w as u16 {
                        if narrow {
                            let a = i128::from(incoming(&s, n as u16, e, w));
                            let b = i128::from(incoming(&s, m as u16, e, w));
                            let res = ((if subtract { a - b } else { a + b })
                                + if unsigned { 1i128 << (w / 2 - 1) } else { 0 })
                                >> (w / 2);
                            assert_eq!(
                                output(&t, 0, e * 2 + top as u16, w / 2),
                                res as u64 & mask(w / 2)
                            );
                            assert_eq!(
                                output(&t, 0, e * 2 + (!top) as u16, w / 2),
                                if top {
                                    incoming(&s, 0, e * 2, w / 2)
                                } else {
                                    0
                                }
                            );
                        } else {
                            let a = incoming(
                                &s,
                                n as u16,
                                if wide { e } else { e * 2 + top as u16 },
                                if wide { w } else { w / 2 },
                            );
                            let b = incoming(&s, m as u16, e * 2 + top as u16, w / 2);
                            let a = if unsigned {
                                i128::from(a)
                            } else {
                                signed(a, if wide { w } else { w / 2 })
                            };
                            let b = if unsigned {
                                i128::from(b)
                            } else {
                                signed(b, w / 2)
                            };
                            assert_eq!(
                                output(&t, 0, e, w),
                                (if subtract { a - b } else { a + b }) as u64 & mask(w)
                            );
                        }
                    }
                }
            }
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            for base in [
                0x45204000, 0x45204400, 0x45204800, 0x45204c00, 0x45205000, 0x45205400,
            ] {
                for alias in [false, true] {
                    let n = if alias { 0 } else { 1 };
                    let mut s = State::default();
                    let h = w / 2;
                    let edge = [
                        0,
                        mask(w),
                        1u64 << (w - 1),
                        mask(h),
                        1u64 << (h - 1),
                        (1u64 << (h - 1)) - 1,
                        1u64 << h,
                    ];
                    for e in 0..vl / w as u16 {
                        s.lane(0, e, w, 0x123456789abcdef0);
                        s.lane(n, e, w, edge[e as usize % edge.len()]);
                    }
                    let tsize = 1u32 << (w.trailing_zeros() - 4);
                    let inst =
                        base | ((tsize >> 2) << 22) | ((tsize & 3) << 19) | ((n as u32) << 5);
                    let t = run(inst, vl, &s);
                    let unsigned = base & (1 << 11) != 0;
                    let to_unsigned = base & (1 << 12) != 0;
                    let top = base & (1 << 10) != 0;
                    for e in 0..vl / w as u16 {
                        let a = incoming(&s, n, e, w);
                        let a = if unsigned {
                            i128::from(a)
                        } else {
                            signed(a, w)
                        };
                        let value = a.clamp(
                            if unsigned || to_unsigned {
                                0
                            } else {
                                -(1i128 << (h - 1))
                            },
                            if unsigned || to_unsigned {
                                i128::from(mask(h))
                            } else {
                                (1i128 << (h - 1)) - 1
                            },
                        );
                        assert_eq!(output(&t, 0, e * 2 + top as u16, h), value as u64 & mask(h));
                        assert_eq!(
                            output(&t, 0, e * 2 + (!top) as u16, h),
                            if top { incoming(&s, 0, e * 2, h) } else { 0 }
                        );
                    }
                }
            }
        }
    }
    for tsize in [0u32, 3, 5, 6, 7] {
        for base in [
            0x45204000, 0x45204400, 0x45204800, 0x45204c00, 0x45205000, 0x45205400,
        ] {
            assert!(recipe(base | ((tsize >> 2) << 22) | ((tsize & 3) << 19), 128).is_none());
        }
    }
}
fn pred_output(t: &Transition, e: u16, w: u8) -> bool {
    let bit = e * (w as u16 / 8);
    reg(t, "a64.predicate64", bit / 64) >> (bit % 64) & 1 != 0
}
#[test]
fn comparisons_immediate_and_wide_signed_unsigned_full_predicate_flags_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x25008000, 0x25008010, 0x25000000, 0x25000010, 0x25002000, 0x25002010, 0x24200000,
                0x24200010, 0x24202000, 0x24202010, 0x24002000, 0x24002010, 0x24004000, 0x24004010,
                0x24006000, 0x24006010, 0x2400c000, 0x2400c010, 0x2400e000, 0x2400e010,
            ] {
                let wide = base >> 24 == 0x24 && base & 0x00200000 == 0;
                if wide && w == 64 {
                    continue;
                }
                for imm in [0u32, 1, 15, 16, 31, 63, 127] {
                    let unsigned = base & 0x00200000 != 0 || (wide && base & (1 << 15) != 0);
                    let code = if wide {
                        match base & 0x6010 {
                            0x2000 => 0,
                            0x2010 => 1,
                            0x4000 => 2,
                            0x4010 => 3,
                            0x6000 => 4,
                            _ => 5,
                        }
                    } else {
                        match base {
                            0x25008000 => 0,
                            0x25008010 => 1,
                            0x25000000 | 0x24200000 => 2,
                            0x25000010 | 0x24200010 => 3,
                            0x25002000 | 0x24202000 => 4,
                            _ => 5,
                        }
                    };
                    let mut s = State::default();
                    let len = vl / w as u16;
                    let edge = [0, 1, mask(w), 1u64 << (w - 1), 127];
                    for e in 0..len {
                        s.lane(1, e, w, edge[e as usize % 5]);
                        if e % 4 != 1 {
                            s.predicate(0, e, w);
                        }
                    }
                    for i in 0..vl / 64 {
                        s.set(
                            "a64.vector64",
                            2 * 32 + i,
                            if i % 2 == 0 { u64::MAX } else { 17 },
                        );
                    }
                    let mut inst = word(
                        base,
                        w,
                        0,
                        1,
                        if wide {
                            2
                        } else if unsigned {
                            0
                        } else {
                            imm & 31
                        },
                    );
                    if unsigned && !wide {
                        inst |= imm << 14;
                    }
                    let t = run(inst, vl, &s);
                    let mut expected = Vec::new();
                    for e in 0..len {
                        let a = incoming(&s, 1, e, w);
                        let a = if unsigned {
                            i128::from(a)
                        } else {
                            signed(a, w)
                        };
                        let b = if wide {
                            let b = incoming(&s, 2, e * w as u16 / 64, 64);
                            if unsigned {
                                i128::from(b)
                            } else {
                                signed(b, 64)
                            }
                        } else if unsigned {
                            i128::from(imm)
                        } else {
                            signed(u64::from(imm & 31), 5)
                        };
                        let value = e % 4 != 1
                            && match code {
                                0 => a == b,
                                1 => a != b,
                                2 => a >= b,
                                3 => a > b,
                                4 => a < b,
                                _ => a <= b,
                            };
                        expected.push(value);
                        assert_eq!(pred_output(&t, e, w), value, "{inst:08x} e{e}");
                    }
                    let active: Vec<_> = (0..len).filter(|e| e % 4 != 1).collect();
                    assert_eq!(reg(&t, "a64.nzcv", 0), expected[active[0] as usize] as u64);
                    assert_eq!(
                        reg(&t, "a64.nzcv", 1),
                        (!expected.iter().any(|v| *v)) as u64
                    );
                    assert_eq!(
                        reg(&t, "a64.nzcv", 2),
                        (!expected[*active.last().unwrap() as usize]) as u64
                    );
                    assert_eq!(reg(&t, "a64.nzcv", 3), 0);
                }
            }
        }
    }
    // Every inactive input lane remains unread, including with predicate destination=governing.
    let mut s = State::default();
    s.forbidden = Some(1);
    for base in [0x25008000, 0x24202010, 0x24004000] {
        run(word(base, 16, 0, 1, 2), 128, &s);
    }
    for base in [0x24002000, 0x24004000, 0x2400c010] {
        assert!(recipe(word(base, 64, 0, 1, 2), 128).is_none());
    }
}
fn independent_count(pattern: u32, elements: u16) -> u16 {
    match pattern {
        0 => {
            let mut n = 1;
            while n * 2 <= elements {
                n *= 2;
            }
            n
        }
        1..=8 => {
            if elements >= pattern as u16 {
                pattern as u16
            } else {
                0
            }
        }
        9..=13 => {
            let n = 16 << (pattern - 9);
            if elements >= n {
                n
            } else {
                0
            }
        }
        29 => elements - elements % 4,
        30 => elements - elements % 3,
        31 => elements,
        _ => 0,
    }
}
#[test]
fn count_updates_all_patterns_predicate_widths_saturation_and_sign_extension() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for base in [
                0x252c8800, 0x252d8800, 0x252c8000, 0x252d8000, 0x25288800, 0x25288c00, 0x25298800,
                0x25298c00, 0x252a8800, 0x252a8c00, 0x252b8800, 0x252b8c00, 0x25288000, 0x25298000,
                0x252a8000, 0x252b8000,
            ] {
                let scalar = base & (1 << 11) != 0;
                if !scalar && w == 8 {
                    continue;
                }
                let sat = base & 0x00040000 == 0;
                let unsigned = sat && base & (1 << 16) != 0;
                let width = if scalar {
                    if sat && base & (1 << 10) == 0 {
                        32
                    } else {
                        64
                    }
                } else {
                    w
                };
                let subtract = if sat {
                    base & (1 << 17) != 0
                } else {
                    base & (1 << 16) != 0
                };
                for initial in [
                    0,
                    1,
                    mask(width),
                    1u64 << (width - 1),
                    (1u64 << (width - 1)) - 1,
                ] {
                    let mut s = State::default();
                    let mut count = 0;
                    for e in 0..vl / w as u16 {
                        if e % 3 != 1 {
                            s.predicate(1, e, w);
                            count += 1;
                        }
                        s.lane(0, e, w, initial);
                    }
                    s.set("a64.gpr", 0, initial);
                    let t = run(word(base, w, 0, 1, 0), vl, &s);
                    let a = if sat && !unsigned {
                        signed(initial, width)
                    } else {
                        i128::from(initial)
                    };
                    let res = a + if subtract { -count } else { count };
                    let value = if sat {
                        res.clamp(
                            if unsigned { 0 } else { -(1i128 << (width - 1)) },
                            if unsigned {
                                i128::from(mask(width))
                            } else {
                                (1i128 << (width - 1)) - 1
                            },
                        )
                    } else {
                        res
                    };
                    if scalar {
                        assert_eq!(
                            reg(&t, "a64.gpr", 0),
                            if sat && !unsigned {
                                value as u64
                            } else {
                                value as u64 & mask(width)
                            },
                            "{base:08x} w{w}"
                        );
                    } else {
                        for e in 0..vl / w as u16 {
                            assert_eq!(output(&t, 0, e, w), value as u64 & mask(w));
                        }
                    }
                    assert!(t.registers.iter().all(|r| r.register.bank != "a64.fpsr"));
                    let zr = run(word(base, w, 31, 1, 0), vl, &s);
                    if scalar {
                        assert!(zr.registers.is_empty());
                    }
                }
            }
            for scalar in [false, true] {
                if !scalar && w == 8 {
                    continue;
                }
                for subtract in [false, true] {
                    for pattern in 0..32 {
                        for multiplier in [1, 16] {
                            let mut s = State::default();
                            s.set("a64.gpr", 0, u64::MAX - 100);
                            for e in 0..vl / w as u16 {
                                s.lane(0, e, w, mask(w) - 10);
                            }
                            let inst = word(
                                if scalar { 0x0430e000 } else { 0x0430c000 },
                                w,
                                0,
                                pattern,
                                0,
                            ) | ((multiplier - 1) << 16)
                                | ((subtract as u32) << 10);
                            let t = run(inst, vl, &s);
                            let delta = u64::from(independent_count(pattern, vl / w as u16))
                                * u64::from(multiplier);
                            if scalar {
                                let old = u64::MAX - 100;
                                assert_eq!(
                                    reg(&t, "a64.gpr", 0),
                                    if subtract {
                                        old.wrapping_sub(delta)
                                    } else {
                                        old.wrapping_add(delta)
                                    }
                                );
                            } else {
                                for e in 0..vl / w as u16 {
                                    let old = mask(w) - 10;
                                    assert_eq!(
                                        output(&t, 0, e, w),
                                        (if subtract {
                                            old.wrapping_sub(delta)
                                        } else {
                                            old.wrapping_add(delta)
                                        }) & mask(w)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
fn predicate_in(s: &State, n: u16, bit: u16) -> bool {
    *s.registers
        .get(&Register {
            bank: "a64.predicate64",
            index: n * 4 + bit / 64,
        })
        .unwrap_or(&0)
        >> (bit % 64)
        & 1
        != 0
}
fn flags_reference(t: &Transition, governing: &[bool], values: &[bool]) {
    let active: Vec<_> = governing
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.then_some(i))
        .collect();
    let first = active.first().map(|i| values[*i]).unwrap_or(false);
    let last = active.last().map(|i| values[*i]).unwrap_or(false);
    let any = active.iter().any(|i| values[*i]);
    for (i, value) in [first, !any, !last, false].iter().enumerate() {
        assert_eq!(reg(t, "a64.nzcv", i as u16), *value as u64);
    }
}
#[test]
fn predicate_break_before_after_previous_next_complete_alias_matrix() {
    for vl in [128, 256, 512, 1024, 2048] {
        for base in [
            0x25104000, 0x25904000, 0x25504000, 0x25d04000, 0x2500c000, 0x2500c010, 0x2540c000,
            0x2540c010, 0x25184000, 0x25584000,
        ] {
            for merge in [false, true] {
                let flags = base & (1 << 22) != 0;
                let previous = base & 0x00100000 == 0;
                let next = base & 0x00080000 != 0;
                if merge && (flags || previous || next) {
                    continue;
                }
                for d in 0..3u32 {
                    for n in 0..3u32 {
                        for m in 0..3u32 {
                            for empty in [false, true] {
                                let mut s = State::default();
                                for e in 0..vl / 8 {
                                    for source in 0..3 {
                                        if !empty && (e + source) % 5 == source + 1 {
                                            s.predicate(source, e, 8);
                                        }
                                    }
                                }
                                let governing: Vec<_> =
                                    (0..vl / 8).map(|e| predicate_in(&s, 0, e)).collect();
                                let input: Vec<_> =
                                    (0..vl / 8).map(|e| predicate_in(&s, n as u16, e)).collect();
                                let old: Vec<_> =
                                    (0..vl / 8).map(|e| predicate_in(&s, d as u16, e)).collect();
                                let mut continuing = if previous || next {
                                    governing
                                        .iter()
                                        .enumerate()
                                        .rev()
                                        .find(|(_, v)| **v)
                                        .map(|(e, _)| input[e])
                                        .unwrap_or(false)
                                } else {
                                    true
                                };
                                let mut expected = Vec::new();
                                for e in 0..(vl / 8) as usize {
                                    let active = governing[e];
                                    let bit = if next {
                                        old[e] && continuing
                                    } else {
                                        let after = continuing
                                            && !(active
                                                && if previous {
                                                    predicate_in(&s, m as u16, e as u16)
                                                } else {
                                                    input[e]
                                                });
                                        let value = if active {
                                            if (previous && base & 16 != 0)
                                                || (!previous && base & (1 << 23) != 0)
                                            {
                                                after
                                            } else {
                                                continuing
                                            }
                                        } else {
                                            merge && old[e]
                                        };
                                        continuing = after;
                                        value
                                    };
                                    expected.push(bit);
                                }
                                let inst = base
                                    | d
                                    | (n << 5)
                                    | if previous { m << 16 } else { 0 }
                                    | if merge { 16 } else { 0 };
                                let t = run(inst, vl, &s);
                                for (e, value) in expected.iter().enumerate() {
                                    assert_eq!(
                                        (reg(&t, "a64.predicate64", d as u16 * 4 + e as u16 / 64)
                                            >> (e % 64)
                                            & 1)
                                            != 0,
                                        *value,
                                        "{inst:08x} e{e}"
                                    );
                                }
                                if flags {
                                    let all = vec![true; vl as usize / 8];
                                    flags_reference(
                                        &t,
                                        if next { &all } else { &governing },
                                        &expected,
                                    );
                                } else {
                                    assert!(t
                                        .registers
                                        .iter()
                                        .all(|r| r.register.bank != "a64.nzcv"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn predicate_first_next_and_unpack_cover_empty_final_interiors_and_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for pattern in 0..4 {
                for alias in [false, true] {
                    let n = if alias { 0 } else { 1 };
                    let mut s = State::default();
                    for e in 0..vl / 8 {
                        if e % 5 == 2 {
                            s.predicate(n, e, 8);
                        }
                        let active = match pattern {
                            0 => false,
                            1 => e == 0,
                            2 => e == vl / 8 - w as u16 / 8,
                            _ => e % 3 == 0,
                        };
                        if active {
                            s.predicate(0, e, 8);
                        }
                    }
                    let len = vl / w as u16;
                    let last = (0..len)
                        .rev()
                        .find(|e| predicate_in(&s, 0, *e * (w as u16 / 8)));
                    let next = (last.map(|e| e + 1).unwrap_or(0)..len)
                        .find(|e| predicate_in(&s, n, *e * (w as u16 / 8)));
                    let t = run(word(0x2519c400, w, 0, n as u32, 0), vl, &s);
                    let mask: Vec<_> = (0..len)
                        .map(|e| predicate_in(&s, n, e * (w as u16 / 8)))
                        .collect();
                    let expected: Vec<_> = (0..len).map(|e| Some(e) == next).collect();
                    for (e, value) in expected.iter().enumerate() {
                        assert_eq!(pred_output(&t, e as u16, w), *value);
                    }
                    flags_reference(&t, &mask, &expected);
                    if w == 8 {
                        let first = (0..len).find(|e| predicate_in(&s, n, *e));
                        let expected: Vec<_> = (0..len)
                            .map(|e| predicate_in(&s, 0, e) || Some(e) == first)
                            .collect();
                        let t = run(0x2558c000 | ((n as u32) << 5), vl, &s);
                        for (e, value) in expected.iter().enumerate() {
                            assert_eq!(pred_output(&t, e as u16, 8), *value);
                        }
                        flags_reference(&t, &mask, &expected);
                    }
                }
            }
        }
        for high in [false, true] {
            for alias in [false, true] {
                let n = if alias { 0 } else { 1 };
                let mut s = State::default();
                for e in 0..vl / 8 {
                    if e % 3 == 1 {
                        s.predicate(n, e, 8);
                    }
                }
                let t = run(
                    0x05304000 | ((high as u32) << 16) | ((n as u32) << 5),
                    vl,
                    &s,
                );
                for e in 0..vl / 16 {
                    assert_eq!(
                        pred_output(&t, e, 16),
                        predicate_in(&s, n, e + if high { vl / 16 } else { 0 })
                    );
                    assert!(!pred_output(&t, e * 2 + 1, 8));
                }
            }
        }
    }
}
#[test]
fn saturating_pattern_updates_all_shapes_patterns_and_multipliers() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for scalar_width in [0, 32, 64] {
                if scalar_width == 0 && w == 8 {
                    continue;
                }
                for unsigned in [false, true] {
                    for subtract in [false, true] {
                        for pattern in 0..32u32 {
                            for multiplier in [1, 16u32] {
                                let width = if scalar_width == 0 { w } else { scalar_width };
                                let base = if scalar_width == 0 {
                                    0x0420c000
                                } else {
                                    0x0420f000 | if scalar_width == 64 { 1 << 20 } else { 0 }
                                };
                                let inst = word(base, w, 0, pattern, 0)
                                    | ((multiplier - 1) << 16)
                                    | ((unsigned as u32) << 10)
                                    | ((subtract as u32) << 11);
                                let amount = i128::from(independent_count(pattern, vl / w as u16))
                                    * i128::from(multiplier);
                                for initial in [
                                    0,
                                    1,
                                    mask(width),
                                    1u64 << (width - 1),
                                    (1u64 << (width - 1)) - 1,
                                ] {
                                    let mut s = State::default();
                                    s.set("a64.gpr", 0, initial);
                                    for e in 0..vl / w as u16 {
                                        s.lane(0, e, w, initial);
                                    }
                                    let a = if unsigned {
                                        i128::from(initial)
                                    } else {
                                        signed(initial, width)
                                    };
                                    let expected = (a + if subtract { -amount } else { amount })
                                        .clamp(
                                            if unsigned { 0 } else { -(1i128 << (width - 1)) },
                                            if unsigned {
                                                i128::from(mask(width))
                                            } else {
                                                (1i128 << (width - 1)) - 1
                                            },
                                        );
                                    let t = run(inst, vl, &s);
                                    if scalar_width != 0 {
                                        assert_eq!(
                                            reg(&t, "a64.gpr", 0),
                                            if unsigned {
                                                expected as u64 & mask(width)
                                            } else {
                                                expected as u64
                                            }
                                        );
                                    } else {
                                        for e in 0..vl / w as u16 {
                                            assert_eq!(
                                                output(&t, 0, e, w),
                                                expected as u64 & mask(w)
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

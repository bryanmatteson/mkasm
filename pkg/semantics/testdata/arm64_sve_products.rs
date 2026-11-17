include!("sve_integer_base.rs");
struct ProductState(State);
impl Machine for ProductState {
    fn read_register(&self, r: Register) -> Value {
        if matches!(r.bank, "a64.ssve_bitperm" | "a64.ssve_aes") {
            Value::known(1, *self.0.registers.get(&r).unwrap_or(&0))
        } else {
            self.0.read_register(r)
        }
    }
    fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
        self.0.read_memory(a, w, e)
    }
}
fn product_run(word: u32, vl: u16, s: &ProductState) -> Transition {
    let r = recipe(word, vl).unwrap_or_else(|| panic!("unhandled {word:08x} VL{vl}"));
    assert_eq!(r.support, Support::Full);
    r.validate().unwrap();
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x}: {e:?}"));
    assert!(t
        .registers
        .iter()
        .all(|r| r.register.bank != "a64.fpsr" && r.register.bank != "a64.nzcv"));
    t
}
// All seven edge phases at the minimum VL, then every encoding/index/alias at
// each larger VL. Larger vectors cycle the same edge values across segments.
fn product_starts(vl: u16) -> usize {
    if vl == 128 {
        7
    } else {
        1
    }
}
fn clamp_signed(a: i128, w: u8) -> i128 {
    a.clamp(-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1)
}
fn fill_product(s: &mut State, vl: u16, w: u8, start: usize) {
    let edge = [
        0,
        1,
        mask(w),
        1u64 << (w - 1),
        (1u64 << (w - 1)) - 1,
        2,
        mask(w) - 1,
    ];
    for n in 0..3 {
        for e in 0..vl / w as u16 {
            s.lane(
                n,
                e,
                w,
                edge[(e as usize + start + n as usize * 2) % edge.len()],
            );
        }
    }
    s.set("a64.fpsr", 0, 0x08000013);
}
#[test]
fn narrowing_right_shifts_every_encoding_width_count_top_bottom_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for tsize in 1..8u32 {
            let h = 8u8 << (31 - tsize.leading_zeros());
            let w = h * 2;
            for imm in 0..8u32 {
                let shift = 2 * h as u32 - (tsize * 8 + imm);
                for kind in 0..4u32 {
                    for rounded in [false, true] {
                        for top in [false, true] {
                            for n in 0..3u16 {
                                for start in 0..product_starts(vl) {
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w, start);
                                    let inst = 0x45200000
                                        | ((tsize >> 2) << 22)
                                        | ((tsize & 3) << 19)
                                        | (imm << 16)
                                        | (kind << 12)
                                        | ((rounded as u32) << 11)
                                        | ((top as u32) << 10)
                                        | ((n as u32) << 5);
                                    let t = product_run(inst, vl, &ProductState(s));
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w, start);
                                    for e in 0..vl / w as u16 {
                                        let a = incoming(&s, n, e, w);
                                        let unsigned = kind == 1 || kind == 3;
                                        let a = if unsigned {
                                            i128::from(a)
                                        } else {
                                            signed(a, w)
                                        };
                                        let res =
                                            (a + if rounded { 1i128 << (shift - 1) } else { 0 })
                                                >> shift;
                                        let expected = match kind {
                                            0 => res.clamp(0, i128::from(mask(h))),
                                            1 => res,
                                            2 => clamp_signed(res, h),
                                            _ => res.clamp(0, i128::from(mask(h))),
                                        };
                                        assert_eq!(
                                            output(&t, 0, e * 2 + top as u16, h),
                                            expected as u64 & mask(h),
                                            "{inst:08x} e{e}"
                                        );
                                        assert_eq!(
                                            output(&t, 0, e * 2 + (!top) as u16, h),
                                            if top { incoming(&s, 0, e * 2, h) } else { 0 }
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
    for opcode in (0..16u32).map(|i| i << 10) {
        assert!(recipe(0x45200000 | opcode, 128).is_none());
    }
}
#[test]
fn widening_multiply_accumulate_doubling_all_plain_and_indexed_forms() {
    let plain = [
        (0x45007000, false, false, false),
        (0x45007800, true, false, false),
        (0x44004000, false, true, false),
        (0x44004800, true, true, false),
        (0x44005000, false, true, true),
        (0x44005800, true, true, true),
        (0x45006000, false, false, false),
        (0x44006000, false, true, false),
        (0x44006800, false, true, true),
    ];
    let indexed = [
        (0x8000, false, true, false),
        (0x9000, true, true, false),
        (0xa000, false, true, true),
        (0xb000, true, true, true),
        (0xc000, false, false, false),
        (0xd000, true, false, false),
        (0x2000, false, true, false),
        (0x3000, false, true, true),
        (0xe000, false, false, false),
    ];
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            let h = w / 2;
            for index_form in [false, true] {
                if index_form && w == 16 {
                    continue;
                }
                for top in [false, true] {
                    for n in 0..3u16 {
                        for m in 0..3u16 {
                            for form in 0..9 {
                                let (base, unsigned, accumulate, subtract) = if index_form {
                                    indexed[form]
                                } else {
                                    plain[form]
                                };
                                let doubling = form >= 6;
                                for index in 0..if index_form { 128 / h as u32 } else { 1 } {
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, h, index as usize);
                                    let inst = if index_form {
                                        let prefix = if w == 32 { 0x44a00000 } else { 0x44e00000 };
                                        prefix
                                            | base
                                            | ((top as u32) << 10)
                                            | ((n as u32) << 5)
                                            | ((m as u32) << 16)
                                            | if w == 32 {
                                                ((index >> 1) << 19) | ((index & 1) << 11)
                                            } else {
                                                ((index >> 1) << 20) | ((index & 1) << 11)
                                            }
                                    } else {
                                        word(base | ((top as u32) << 10), w, 0, n as u32, m as u32)
                                    };
                                    let t = product_run(inst, vl, &ProductState(s));
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, h, index as usize);
                                    for e in 0..vl / w as u16 {
                                        let src = if index_form {
                                            e / (128 / w as u16) * (128 / h as u16) + index as u16
                                        } else {
                                            e * 2 + top as u16
                                        };
                                        let a = incoming(&s, n, e * 2 + top as u16, h);
                                        let b = incoming(&s, m, src, h);
                                        let a = if unsigned {
                                            i128::from(a)
                                        } else {
                                            signed(a, h)
                                        };
                                        let b = if unsigned {
                                            i128::from(b)
                                        } else {
                                            signed(b, h)
                                        };
                                        let product = if doubling {
                                            clamp_signed(2 * a * b, w)
                                        } else {
                                            a * b
                                        };
                                        let old = incoming(&s, 0, e, w);
                                        let old = if unsigned {
                                            i128::from(old)
                                        } else {
                                            signed(old, w)
                                        };
                                        let result = if accumulate {
                                            old + if subtract { -product } else { product }
                                        } else {
                                            product
                                        };
                                        let expected = if doubling {
                                            clamp_signed(result, w)
                                        } else {
                                            result
                                        };
                                        assert_eq!(
                                            output(&t, 0, e, w),
                                            expected as u64 & mask(w),
                                            "{inst:08x} w{w} e{e}"
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
    for base in [
        0x45007000, 0x45007800, 0x44004000, 0x44004800, 0x44005000, 0x44005800, 0x45006000,
        0x44006000, 0x44006800,
    ] {
        assert!(recipe(base, 128).is_none());
    }
}
#[test]
fn doubling_high_and_rounding_accumulate_full_widths_indices_ties_overflow_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for indexed in [false, true] {
                if indexed && w == 8 {
                    continue;
                }
                for operation in 0..4 {
                    let (accumulate, subtract, rounding) =
                        (operation >= 2, operation == 3, operation != 0);
                    for n in 0..3u16 {
                        for m in 0..3u16 {
                            for index in 0..if indexed { 128 / w as u32 } else { 1 } {
                                for start in 0..product_starts(vl) {
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w, start);
                                    let inst = if indexed {
                                        let base = match (w, accumulate) {
                                            (16, false) => 0x4420f000,
                                            (16, true) => 0x44201000,
                                            (32, false) => 0x44a0f000,
                                            (32, true) => 0x44a01000,
                                            (64, false) => 0x44e0f000,
                                            _ => 0x44e01000,
                                        };
                                        base | ((if accumulate { subtract } else { rounding })
                                            as u32)
                                            << 10
                                            | ((n as u32) << 5)
                                            | ((m as u32) << 16)
                                            | match w {
                                                16 => ((index >> 2) << 22) | ((index & 3) << 19),
                                                32 => index << 19,
                                                _ => index << 20,
                                            }
                                    } else {
                                        word(
                                            if accumulate { 0x44007000 } else { 0x04207000 }
                                                | (((if accumulate { subtract } else { rounding })
                                                    as u32)
                                                    << 10),
                                            w,
                                            0,
                                            n as u32,
                                            m as u32,
                                        )
                                    };
                                    let t = product_run(inst, vl, &ProductState(s));
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w, start);
                                    for e in 0..vl / w as u16 {
                                        let src = if indexed {
                                            e / (128 / w as u16) * (128 / w as u16) + index as u16
                                        } else {
                                            e
                                        };
                                        let a = signed(incoming(&s, n, e, w), w);
                                        let b = signed(incoming(&s, m, src, w), w);
                                        let product = a * b * if subtract { -1 } else { 1 };
                                        let q = (product
                                            + if rounding { 1i128 << (w - 2) } else { 0 })
                                        .div_euclid(1i128 << (w - 1));
                                        let result = if accumulate {
                                            signed(incoming(&s, 0, e, w), w) + q
                                        } else {
                                            q
                                        };
                                        let expected = clamp_signed(result, w) as u64 & mask(w);
                                        assert_eq!(
                                            output(&t, 0, e, w),
                                            expected,
                                            "{inst:08x} w{w} e{e} a{a} b{b}"
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
    // Exact minimum times minimum needs a positive extra bit before final saturation.
    for w in [8, 16, 32, 64] {
        let mut s = State::default();
        for e in 0..128 / w as u16 {
            s.lane(0, e, w, mask(w));
            s.lane(1, e, w, 1u64 << (w - 1));
            s.lane(2, e, w, 1u64 << (w - 1));
        }
        let t = product_run(word(0x44007000, w, 0, 1, 2), 128, &ProductState(s));
        assert_eq!(output(&t, 0, 0, w), mask(w - 1));
    }
}
#[test]
fn integer_dot_and_matrix_segment_layout_signedness_accumulate_and_context() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32, 64] {
            for kind in 0..4 {
                if w == 64 && kind >= 2 {
                    continue;
                }
                for indexed in [false, true] {
                    if !indexed && kind == 3 {
                        continue;
                    }
                    for n in 0..3u16 {
                        for m in 0..3u16 {
                            for index in 0..if indexed { 128 / w as u32 } else { 1 } {
                                let mut s = State::default();
                                fill_product(&mut s, vl, w / 4, index as usize);
                                let (u1, u2) = match kind {
                                    0 => (false, false),
                                    1 => (true, true),
                                    2 => (true, false),
                                    _ => (false, true),
                                };
                                let inst = if indexed {
                                    let base = match kind {
                                        0 => {
                                            if w == 32 {
                                                0x44a00000
                                            } else {
                                                0x44e00000
                                            }
                                        }
                                        1 => {
                                            if w == 32 {
                                                0x44a00400
                                            } else {
                                                0x44e00400
                                            }
                                        }
                                        2 => 0x44a01800,
                                        _ => 0x44a01c00,
                                    };
                                    base | ((n as u32) << 5)
                                        | ((m as u32) << 16)
                                        | if w == 32 { index << 19 } else { index << 20 }
                                } else {
                                    word(
                                        match kind {
                                            0 => 0x44800000,
                                            1 => 0x44800400,
                                            _ => 0x44807800,
                                        },
                                        w,
                                        0,
                                        n as u32,
                                        m as u32,
                                    )
                                };
                                let t = product_run(inst, vl, &ProductState(s));
                                let mut s = State::default();
                                fill_product(&mut s, vl, w / 4, index as usize);
                                for e in 0..vl / w as u16 {
                                    let src = if indexed {
                                        e / (128 / w as u16) * (128 / w as u16) + index as u16
                                    } else {
                                        e
                                    };
                                    let mut sum = i128::from(incoming(&s, 0, e, w));
                                    for i in 0..4 {
                                        let a = incoming(&s, n, e * 4 + i, w / 4);
                                        let b = incoming(&s, m, src * 4 + i, w / 4);
                                        sum += if u1 { i128::from(a) } else { signed(a, w / 4) }
                                            * if u2 { i128::from(b) } else { signed(b, w / 4) };
                                    }
                                    assert_eq!(
                                        output(&t, 0, e, w),
                                        sum as u64 & mask(w),
                                        "{inst:08x} e{e}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for base in [0x45009800, 0x45c09800, 0x45809800] {
            for n in 0..3u16 {
                for m in 0..3u16 {
                    let mut s = State::default();
                    for source in 0..3 {
                        for e in 0..vl / 8 {
                            s.lane(source, e, 8, ((e * 13 + source * 31) % 256) as u64);
                        }
                    }
                    let inst = base | ((n as u32) << 5) | ((m as u32) << 16);
                    let t = product_run(inst, vl, &ProductState(s));
                    let mut s = State::default();
                    for source in 0..3 {
                        for e in 0..vl / 8 {
                            s.lane(source, e, 8, ((e * 13 + source * 31) % 256) as u64);
                        }
                    }
                    for segment in 0..vl / 128 {
                        for i in 0..2 {
                            for j in 0..2 {
                                let lane = segment * 4 + i * 2 + j;
                                let mut expected = i128::from(incoming(&s, 0, lane, 32));
                                for k in 0..8 {
                                    let a = incoming(&s, n, segment * 16 + i * 8 + k, 8);
                                    let b = incoming(&s, m, segment * 16 + j * 8 + k, 8);
                                    expected += if base != 0x45009800 {
                                        i128::from(a)
                                    } else {
                                        signed(a, 8)
                                    } * if base == 0x45c09800 {
                                        i128::from(b)
                                    } else {
                                        signed(b, 8)
                                    };
                                }
                                assert_eq!(output(&t, 0, lane, 32), expected as u64 & mask(32));
                            }
                        }
                    }
                }
            }
        }
    }
    let r = recipe(0x45009800, 128).unwrap();
    let mut s = ProductState(State::default());
    s.0.set("a64.svcr", 0, 1);
    assert!(matches!(
        evaluate(&r, &s),
        Err(EvalError::UnsupportedContext)
    ));
    s.0.set("a64.sme_fa64", 0, 1);
    assert!(evaluate(&r, &s).is_ok());
}
#[test]
fn carry_borrow_long_bottom_top_pairs_and_eor_cross_preserve_other_lanes() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [32, 64] {
            for base in [0x4500d000, 0x4500d400, 0x4580d000, 0x4580d400] {
                for n in 0..3u16 {
                    for m in 0..3u16 {
                        for start in 0..product_starts(vl) {
                            let mut s = State::default();
                            fill_product(&mut s, vl, w, start);
                            let inst = base
                                | (((w == 64) as u32) << 22)
                                | ((n as u32) << 5)
                                | ((m as u32) << 16);
                            let t = product_run(inst, vl, &ProductState(s));
                            let mut s = State::default();
                            fill_product(&mut s, vl, w, start);
                            for e in 0..vl / (w as u16 * 2) {
                                let a = incoming(&s, 0, e * 2, w);
                                let b = incoming(&s, n, e * 2 + ((base >> 10) & 1) as u16, w);
                                let b = if base & (1 << 23) != 0 {
                                    !b & mask(w)
                                } else {
                                    b
                                };
                                let c = incoming(&s, m, e * 2 + 1, w) & 1;
                                let sum = u128::from(a) + u128::from(b) + u128::from(c);
                                assert_eq!(output(&t, 0, e * 2, w), sum as u64 & mask(w));
                                assert_eq!(output(&t, 0, e * 2 + 1, w), (sum >> w) as u64);
                            }
                        }
                    }
                }
            }
        }
        for w in [8, 16, 32, 64] {
            for top in [false, true] {
                for n in 0..3u16 {
                    for m in 0..3u16 {
                        let mut s = State::default();
                        fill_product(&mut s, vl, w, 0);
                        let inst =
                            word(0x45009000 | ((top as u32) << 10), w, 0, n as u32, m as u32);
                        let t = product_run(inst, vl, &ProductState(s));
                        let mut s = State::default();
                        fill_product(&mut s, vl, w, 0);
                        for e in 0..vl / w as u16 {
                            assert_eq!(
                                output(&t, 0, e, w),
                                if e % 2 == top as u16 {
                                    incoming(&s, n, e, w) ^ incoming(&s, m, e ^ 1, w)
                                } else {
                                    incoming(&s, 0, e, w)
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}
fn bit_reference(data: u64, mask: u64, w: u8, kind: u8) -> u64 {
    let mut yes = Vec::new();
    let mut no = Vec::new();
    for bit in 0..w {
        if mask >> bit & 1 != 0 {
            yes.push(bit)
        } else {
            no.push(bit)
        }
    }
    let mut result = 0;
    match kind {
        0 => {
            for (i, bit) in yes.iter().enumerate() {
                result |= (data >> bit & 1) << i
            }
        }
        1 => {
            for (i, bit) in yes.iter().enumerate() {
                result |= (data >> i & 1) << bit
            }
        }
        _ => {
            for (i, bit) in yes.iter().chain(no.iter()).enumerate() {
                result |= (data >> bit & 1) << i
            }
        }
    }
    result
}
#[test]
fn bit_extract_deposit_group_all_widths_vls_aliases_masks_and_streaming_permission() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            for kind in 0..3 {
                for n in 0..3u16 {
                    for m in 0..3u16 {
                        for start in 0..product_starts(vl) {
                            let mut s = State::default();
                            fill_product(&mut s, vl, w, start);
                            let inst =
                                word(0x4500b000 | ((kind as u32) << 10), w, 0, n as u32, m as u32);
                            let t = product_run(inst, vl, &ProductState(s));
                            let mut s = State::default();
                            fill_product(&mut s, vl, w, start);
                            for e in 0..vl / w as u16 {
                                assert_eq!(
                                    output(&t, 0, e, w),
                                    bit_reference(
                                        incoming(&s, n, e, w),
                                        incoming(&s, m, e, w),
                                        w,
                                        kind
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    for kind in 0..3u32 {
        let r = recipe(0x4500b000 | (kind << 10), 128).unwrap();
        let mut s = ProductState(State::default());
        s.0.set("a64.svcr", 0, 1);
        assert!(matches!(
            evaluate(&r, &s),
            Err(EvalError::UnsupportedContext)
        ));
        for bank in ["a64.sme_fa64", "a64.ssve_bitperm"] {
            s.0.set(bank, 0, 1);
            assert!(evaluate(&r, &s).is_ok());
            s.0.set(bank, 0, 0);
        }
    }
}
#[test]
fn bit_permutation_exhaustive_byte_inputs_and_masks() {
    for kind in 0..3 {
        for data in 0..256u64 {
            for start in (0..256u64).step_by(16) {
                let mut s = State::default();
                for e in 0..16 {
                    s.lane(1, e, 8, data);
                    s.lane(2, e, 8, start + e as u64);
                }
                let t = product_run(
                    word(0x4500b000 | ((kind as u32) << 10), 8, 0, 1, 2),
                    128,
                    &ProductState(s),
                );
                for e in 0..16 {
                    assert_eq!(
                        output(&t, 0, e, 8),
                        bit_reference(data, start + e as u64, 8, kind)
                    );
                }
            }
        }
    }
}
#[test]
fn cross_doubling_and_polynomial_widening_all_sizes_alias_and_streaming() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32, 64] {
            for subtract in [false, true] {
                for n in 0..3u16 {
                    for m in 0..3u16 {
                        for start in 0..product_starts(vl) {
                            let mut s = State::default();
                            fill_product(&mut s, vl, w / 2, start);
                            let inst = word(
                                0x44000800 | ((subtract as u32) << 10),
                                w,
                                0,
                                n as u32,
                                m as u32,
                            );
                            let t = product_run(inst, vl, &ProductState(s));
                            let mut s = State::default();
                            fill_product(&mut s, vl, w / 2, start);
                            for e in 0..vl / w as u16 {
                                let a = signed(incoming(&s, n, e * 2, w / 2), w / 2);
                                let b = signed(incoming(&s, m, e * 2 + 1, w / 2), w / 2);
                                let product = clamp_signed(2 * a * b, w);
                                let expected = clamp_signed(
                                    signed(incoming(&s, 0, e, w), w)
                                        + if subtract { -product } else { product },
                                    w,
                                );
                                assert_eq!(output(&t, 0, e, w), expected as u64 & mask(w));
                            }
                        }
                    }
                }
            }
        }
        for width in [16u16, 64, 128] {
            let h = (width / 2) as u8;
            for top in [false, true] {
                for n in 0..3u16 {
                    for m in 0..3u16 {
                        for start in 0..product_starts(vl) {
                            let mut s = State::default();
                            fill_product(&mut s, vl, h, start);
                            let inst = 0x45006800
                                | ((match width {
                                    16 => 1,
                                    64 => 3,
                                    _ => 0,
                                }) << 22)
                                | ((top as u32) << 10)
                                | ((n as u32) << 5)
                                | ((m as u32) << 16);
                            let t = product_run(inst, vl, &ProductState(s));
                            let mut s = State::default();
                            fill_product(&mut s, vl, h, start);
                            for e in 0..vl / width {
                                let a = incoming(&s, n, e * 2 + top as u16, h);
                                let b = incoming(&s, m, e * 2 + top as u16, h);
                                let mut expected = 0u128;
                                for bit in 0..h {
                                    if b >> bit & 1 != 0 {
                                        expected ^= u128::from(a) << bit;
                                    }
                                }
                                if width == 128 {
                                    assert_eq!(output(&t, 0, e * 2, 64), expected as u64);
                                    assert_eq!(
                                        output(&t, 0, e * 2 + 1, 64),
                                        (expected >> 64) as u64
                                    );
                                } else {
                                    assert_eq!(output(&t, 0, e, width as u8), expected as u64);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(recipe(0x45806800, 128).is_none());
    assert!(recipe(0x44000800, 128).is_none());
    let mut s = ProductState(State::default());
    s.0.set("a64.svcr", 0, 1);
    let r = recipe(0x45006800, 128).unwrap();
    assert!(matches!(
        evaluate(&r, &s),
        Err(EvalError::UnsupportedContext)
    ));
    for bank in ["a64.ssve_aes", "a64.sme_fa64"] {
        s.0.set(bank, 0, 1);
        assert!(evaluate(&r, &s).is_ok());
        s.0.set(bank, 0, 0);
    }
}
#[test]
fn complex_integer_multiply_doubling_and_dot_all_rotations_segments_and_alias() {
    for vl in [128, 256, 512, 1024, 2048] {
        for kind in 0..3 {
            for indexed in [false, true] {
                for w in [8, 16, 32, 64] {
                    if kind == 0 && w < 32 || indexed && kind != 0 && (w == 8 || w == 64) {
                        continue;
                    }
                    for rotation in 0..4u32 {
                        for n in 0..3u16 {
                            for m in 0..3u16 {
                                for index in 0..if indexed {
                                    if kind == 0 {
                                        128 / w as u32
                                    } else {
                                        64 / w as u32
                                    }
                                } else {
                                    1
                                } {
                                    for start in 0..product_starts(vl) {
                                        let h = if kind == 0 { w / 4 } else { w };
                                        let mut s = State::default();
                                        fill_product(&mut s, vl, h, start);
                                        let inst = if indexed {
                                            let prefix = if (kind == 0 && w == 32)
                                                || (kind != 0 && w == 16)
                                            {
                                                0x44a00000
                                            } else {
                                                0x44e00000
                                            };
                                            prefix
                                                | (match kind {
                                                    0 => 0x4000,
                                                    1 => 0x6000,
                                                    _ => 0x7000,
                                                })
                                                | (rotation << 10)
                                                | ((n as u32) << 5)
                                                | ((m as u32) << 16)
                                                | if prefix == 0x44a00000 {
                                                    index << 19
                                                } else {
                                                    index << 20
                                                }
                                        } else {
                                            word(
                                                0x44000000 | ((kind + 1) << 12) | (rotation << 10),
                                                w,
                                                0,
                                                n as u32,
                                                m as u32,
                                            )
                                        };
                                        let t = product_run(inst, vl, &ProductState(s));
                                        let mut s = State::default();
                                        fill_product(&mut s, vl, h, start);
                                        let a = (rotation & 1) as u16;
                                        let b = a ^ 1;
                                        if kind == 0 {
                                            for e in 0..vl / w as u16 {
                                                let src = if indexed {
                                                    e / (128 / w as u16) * (128 / w as u16)
                                                        + index as u16
                                                } else {
                                                    e
                                                };
                                                let mut expected =
                                                    i128::from(incoming(&s, 0, e, w));
                                                for i in 0..2 {
                                                    let real = signed(
                                                        incoming(&s, n, e * 4 + i * 2, h),
                                                        h,
                                                    ) * signed(
                                                        incoming(&s, m, src * 4 + i * 2 + a, h),
                                                        h,
                                                    );
                                                    let imaginary = signed(
                                                        incoming(&s, n, e * 4 + i * 2 + 1, h),
                                                        h,
                                                    ) * signed(
                                                        incoming(&s, m, src * 4 + i * 2 + b, h),
                                                        h,
                                                    );
                                                    expected += real
                                                        + if (rotation & 1) == (rotation >> 1) {
                                                            -imaginary
                                                        } else {
                                                            imaginary
                                                        };
                                                }
                                                assert_eq!(
                                                    output(&t, 0, e, w),
                                                    expected as u64 & mask(w)
                                                );
                                            }
                                        } else {
                                            for e in 0..vl / (2 * w as u16) {
                                                let per = 128 / (2 * w as u16);
                                                let src = if indexed {
                                                    e / per * per + index as u16
                                                } else {
                                                    e
                                                };
                                                let input =
                                                    signed(incoming(&s, n, e * 2 + a, w), w);
                                                for (part, select, subtract) in [
                                                    (0, a, (rotation & 1) != (rotation >> 1)),
                                                    (1, b, rotation & 2 != 0),
                                                ] {
                                                    let product = input
                                                        * signed(
                                                            incoming(&s, m, src * 2 + select, w),
                                                            w,
                                                        );
                                                    let old = incoming(&s, 0, e * 2 + part, w);
                                                    let expected = if kind == 2 {
                                                        let q = (product
                                                            * if subtract { -1 } else { 1 }
                                                            + (1i128 << (w - 2)))
                                                            .div_euclid(1i128 << (w - 1));
                                                        clamp_signed(signed(old, w) + q, w) as u64
                                                            & mask(w)
                                                    } else {
                                                        let product = (product as u64) & mask(w);
                                                        (if subtract {
                                                            old.wrapping_sub(product)
                                                        } else {
                                                            old.wrapping_add(product)
                                                        }) & mask(w)
                                                    };
                                                    assert_eq!(
                                                        output(&t, 0, e * 2 + part, w),
                                                        expected,
                                                        "{inst:08x} w{w} e{e}"
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
    }
    for w in [8, 16] {
        assert!(recipe(word(0x44001000, w, 0, 1, 2), 128).is_none());
    }
}
#[test]
fn doubling_accumulate_rounding_ties_and_product_saturation_are_distinct() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [8, 16, 32, 64] {
            let mut s = State::default();
            for e in 0..vl / w as u16 {
                s.lane(0, e, w, 0);
                s.lane(1, e, w, 1);
                s.lane(2, e, w, 1u64 << (w - 2));
            }
            let s = ProductState(s);
            let add = product_run(word(0x44007000, w, 0, 1, 2), vl, &s);
            let sub = product_run(word(0x44007400, w, 0, 1, 2), vl, &s);
            for e in 0..vl / w as u16 {
                assert_eq!(output(&add, 0, e, w), 1);
                assert_eq!(output(&sub, 0, e, w), 0);
            }
        }
        for w in [16, 32, 64] {
            let mut s = State::default();
            for e in 0..vl / w as u16 {
                s.lane(0, e, w, mask(w));
                s.lane(1, e * 2, w / 2, 1u64 << (w / 2 - 1));
                s.lane(2, e * 2 + 1, w / 2, 1u64 << (w / 2 - 1));
            }
            let t = product_run(word(0x44000800, w, 0, 1, 2), vl, &ProductState(s));
            for e in 0..vl / w as u16 {
                assert_eq!(output(&t, 0, e, w), mask(w - 1) - 1);
            }
        }
    }
}
#[test]
fn two_element_dot_all_widths_indices_signedness_and_aliases() {
    for vl in [128, 256, 512, 1024, 2048] {
        for w in [16, 32] {
            for unsigned in [false, true] {
                for indexed in [false, true] {
                    for n in 0..3u16 {
                        for m in 0..3u16 {
                            for index in 0..if indexed { 128 / w as u32 } else { 1 } {
                                for start in 0..product_starts(vl) {
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w / 2, start);
                                    let inst = (match (w, indexed) {
                                        (16, false) => 0x44400000,
                                        (16, true) => 0x44200000,
                                        (32, false) => 0x4400c800,
                                        _ => 0x4480c800,
                                    }) | ((unsigned as u32) << 10)
                                        | ((n as u32) << 5)
                                        | ((m as u32) << 16)
                                        | if indexed {
                                            if w == 16 {
                                                ((index >> 2) << 22) | ((index & 3) << 19)
                                            } else {
                                                index << 19
                                            }
                                        } else {
                                            0
                                        };
                                    let t = product_run(inst, vl, &ProductState(s));
                                    let mut s = State::default();
                                    fill_product(&mut s, vl, w / 2, start);
                                    for e in 0..vl / w as u16 {
                                        let src = if indexed {
                                            e / (128 / w as u16) * (128 / w as u16) + index as u16
                                        } else {
                                            e
                                        };
                                        let mut expected = i128::from(incoming(&s, 0, e, w));
                                        for i in 0..2 {
                                            let a = incoming(&s, n, e * 2 + i, w / 2);
                                            let b = incoming(&s, m, src * 2 + i, w / 2);
                                            let a = if unsigned {
                                                i128::from(a)
                                            } else {
                                                signed(a, w / 2)
                                            };
                                            let b = if unsigned {
                                                i128::from(b)
                                            } else {
                                                signed(b, w / 2)
                                            };
                                            expected += a * b;
                                        }
                                        assert_eq!(output(&t, 0, e, w), expected as u64 & mask(w));
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

#[test]
fn streaming_feature_capabilities_do_not_read_unavailable_privileged_fa64() {
    struct NoFa64(ProductState);
    impl Machine for NoFa64 {
        fn read_register(&self, r: Register) -> Value {
            assert_ne!(
                r.bank, "a64.sme_fa64",
                "feature capability already authorizes streaming"
            );
            self.0.read_register(r)
        }
        fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
            self.0.read_memory(a, w, e)
        }
    }
    for vl in [128, 256, 512, 1024, 2048] {
        for (word, bank) in [
            (0x4500b400, "a64.ssve_bitperm"),
            (0x45006800, "a64.ssve_aes"),
        ] {
            let mut state = ProductState(State::default());
            state.0.set("a64.svcr", 0, 1);
            state.0.set(bank, 0, 1);
            assert!(evaluate(&recipe(word, vl).unwrap(), &NoFa64(state)).is_ok());
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
fn bit_permutation_native_graph_budget_at_maximum_length() {
    let mut maximum=0;
    for opcode in [0x4500b000u32, 0x4500b400, 0x4500b800] {
        for size in 0..4 {
            let word = opcode | size << 22 | 2 << 16 | 1 << 5;
            let r = recipe(word, 2048).unwrap();
            let nodes = lowered_nodes(&r);
            println!("bit permutation {word:08x}: {nodes} nodes");
            maximum=maximum.max(nodes);
        }
    }
    assert!(maximum<32768,"maximum {maximum} native nodes exceeds budget");
}

// Concrete transition writes are sparse: absent rows retain incoming bits.
fn za_output(s: &State, out: &HashMap<Register, u64>, row: u16, e: u16) -> u32 {
    let register = Register {
        bank: "a64.za64",
        index: row * 32 + e / 2,
    };
    (out.get(&register)
        .copied()
        .unwrap_or_else(|| s.regs[&register].bits)
        >> (e % 2 * 32)) as u32
}
// Six primary classes: vector, indexed and grouped second source, each VGx2/4.
fn encoding(nreg: u16, layout: u8, n: u16, m: u16, selector: u16, offset: u16, index: u16) -> u32 {
    let base = match (nreg, layout) {
        (2, 0) => 0xc1201010,
        (4, 0) => 0xc1301010,
        (2, 1) => 0xc1501018,
        (4, 1) => 0xc1509018,
        (2, 2) => 0xc1a01010,
        (4, 2) => 0xc1a11010,
        _ => unreachable!(),
    };
    base | (u32::from(n) << 5)
        | (u32::from(m) << 16)
        | (u32::from(selector - 8) << 13)
        | u32::from(offset)
        | if layout == 1 {
            u32::from(index) << 10
        } else {
            0
        }
}
fn za_fill(s: &mut State, vl: u16, value: u32) {
    for row in 0..vl / 8 {
        for e in 0..vl / 32 {
            s.lane("a64.za64", row, e, 32, u64::from(value));
        }
    }
}
fn sources(s: &mut State, vl: u16, n: u16, nreg: u16, m: u16, layout: u8, args: [u16; 4]) {
    for member in 0..nreg {
        for e in 0..vl / 32 {
            for k in 0..2 {
                s.lane(
                    "a64.vector64",
                    (n + member) % 32,
                    2 * e + k,
                    16,
                    u64::from(args[k as usize]),
                );
                s.lane(
                    "a64.vector64",
                    m + if layout == 2 { member } else { 0 },
                    2 * e + k,
                    16,
                    u64::from(args[2 + k as usize]),
                );
            }
        }
    }
}
#[test]
fn sme2_bfdot_numerical_environments_all_classes_and_lengths() {
    for vl in [128, 256, 512, 1024, 2048] {
        for &(control, acc, args, expected, _, _) in CASES {
            if vl > 128 && control != 0 && control != 0xbf00 {
                continue;
            }
            for nreg in [2, 4] {
                for layout in 0..3 {
                    let (n, m) = (4, 16);
                    let m = if layout == 2 { m } else { 8 };
                    let mut s = State::base(vl, control, true);
                    s.set("a64.gpr", 11, 64, 0xffff_ffff);
                    za_fill(&mut s, vl, acc);
                    sources(&mut s, vl, n, nreg, m, layout, args);
                    let word = encoding(nreg, layout, n, m, 11, 7, 3);
                    let out = run(word, vl, true, &s);
                    let stride = vl / 8 / nreg;
                    let first = ((u64::from(u32::MAX) + 7) % u64::from(stride)) as u16;
                    for row in 0..vl / 8 {
                        for e in 0..vl / 32 {
                            assert_eq!(
                                za_output(&s, &out, row, e),
                                if row % stride == first { expected } else { acc },
                                "{word:08x} SVL{vl} FPCR{control:08x} row{row} e{e}"
                            );
                        }
                    }
                    assert_eq!(s.calls.get(), usize::from(nreg) * usize::from(vl / 32));
                    assert_eq!(out.len(), usize::from(nreg) * usize::from(vl / 64));
                }
            }
        }
    }
}
#[test]
fn sme2_bfdot_selector_stride_groups_segment_indices_aliases_and_wrapping() {
    for vl in [128, 256, 512, 1024, 2048] {
        for nreg in [2, 4] {
            for layout in 0..3 {
                for index in 0..if layout == 1 { 4 } else { 1 } {
                    for (selector, w, offset, alias) in [
                        (8, 5u64, 6, false),
                        (11, 0xabcd_1234_ffff_ffff, 7, true),
                        (9, 0, 0, true),
                    ] {
                        let (n, m) = if layout == 0 {
                            (31, if alias { 0 } else { 15 })
                        } else if layout == 1 {
                            (16 - nreg, if alias { 15 } else { 1 })
                        } else {
                            (32 - nreg, if alias { 32 - nreg } else { 0 })
                        };
                        let mut s = State::base(vl, 1 << 13, true);
                        s.set("a64.gpr", selector, 64, w);
                        for reg in 0..32 {
                            for e in 0..vl / 16 {
                                s.lane(
                                    "a64.vector64",
                                    reg,
                                    e,
                                    16,
                                    u64::from(((reg + e % 11 + 1) as f32).to_bits() >> 16),
                                );
                            }
                        }
                        for row in 0..vl / 8 {
                            for e in 0..vl / 32 {
                                s.lane(
                                    "a64.za64",
                                    row,
                                    e,
                                    32,
                                    u64::from(
                                        ((u32::from(row) * 3 + u32::from(e) + 1) as f32).to_bits(),
                                    ),
                                );
                            }
                        }
                        let word = encoding(nreg, layout, n, m, selector, offset, index);
                        let out = run(word, vl, true, &s);
                        let stride = vl / 8 / nreg;
                        let first =
                            ((u64::from(w as u32) + u64::from(offset)) % u64::from(stride)) as u16;
                        for row in 0..vl / 8 {
                            for e in 0..vl / 32 {
                                let old = s.element("a64.za64", row, e, 32);
                                let expected = if row % stride == first {
                                    let member = row / stride;
                                    let left = (n + member) % 32;
                                    let right = m + if layout == 2 { member } else { 0 };
                                    let z = if layout == 1 {
                                        2 * (e / 4 * 4 + index)
                                    } else {
                                        2 * e
                                    };
                                    let integer = |reg, at| {
                                        f32::from_bits(s.element("a64.vector64", reg, at, 16) << 16)
                                            as u32
                                    };
                                    let product = integer(left, 2 * e) * integer(right, z)
                                        + integer(left, 2 * e + 1) * integer(right, z + 1);
                                    ((f32::from_bits(old) as u32 + product) as f32).to_bits()
                                } else {
                                    old
                                };
                                assert_eq!(
                                    za_output(&s, &out, row, e),
                                    expected,
                                    "{word:08x} SVL{vl} row{row} e{e}"
                                );
                            }
                        }
                        assert_eq!(s.calls.get(), usize::from(nreg) * usize::from(vl / 32));
                    }
                }
            }
        }
    }
}
#[test]
fn sme2_bfdot_context_and_length_fail_before_data_access() {
    for nreg in [2, 4] {
        for layout in 0..3 {
            let word = encoding(nreg, layout, 4, 8, 8, 0, 0);
            for svcr in 0..3 {
                let mut s = State::default();
                s.set("a64.svcr", 0, 2, svcr);
                assert_eq!(
                    evaluate(&recipe(word, 128, true), &s),
                    Err(EvalError::UnsupportedContext)
                );
            }
            let mut s = State::default();
            s.regs.insert(
                Register {
                    bank: "a64.svcr",
                    index: 0,
                },
                Value::unknown(2),
            );
            assert_eq!(
                evaluate(&recipe(word, 128, true), &s),
                Err(EvalError::UnknownCondition)
            );
            for vl in [0, 64, 192, 384, 4096] {
                assert_eq!(
                    evaluate(&recipe(word, vl, true), &s),
                    Err(EvalError::Unsupported)
                );
            }
        }
    }
}
// Count the actual typed source graph, including selector trees. The native
// consumer independently validates its lowered graph against its fixed cap.
fn source_nodes(e: &Expr) -> usize {
    use ExprKind as E;
    1 + match &e.kind {
        E::Constant(_) | E::Register(_) | E::Temporary(_) => 0,
        E::IndexedRegister(r) => source_nodes(&r.index),
        E::Binary { left, right, .. } => source_nodes(left) + source_nodes(right),
        E::Cast { value, .. } | E::Extract { value, .. } => source_nodes(value),
        E::RequireContext { condition, .. } => source_nodes(condition),
        E::Float(f) => {
            f.inputs.iter().map(source_nodes).sum::<usize>()
                + source_nodes(&f.control)
                + source_nodes(&f.status)
        }
        other => panic!("unexpected BFDOT graph {other:?}"),
    }
}
#[test]
fn sme2_bfdot_only_selected_rows_are_inputs_or_outputs_and_graph_is_linear() {
    for vl in [128, 256, 512, 1024, 2048] {
        for nreg in [2, 4] {
            for layout in 0..3 {
                let mut s = State::base(vl, 1 << 13, true);
                s.set("a64.gpr", 11, 64, u64::from(u32::MAX));
                za_fill(&mut s, vl, 1.0f32.to_bits());
                let stride = vl / 8 / nreg;
                let first = ((u64::from(u32::MAX) + 7) % u64::from(stride)) as u16;
                // Missing unselected ZA rows deliberately panic if read.
                s.regs
                    .retain(|reg, _| reg.bank != "a64.za64" || reg.index / 32 % stride == first);
                let m = if layout == 2 { 16 } else { 8 };
                sources(&mut s, vl, 4, nreg, m, layout, [0x3f80; 4]);
                let word = encoding(nreg, layout, 4, m, 11, 7, 3);
                let r = recipe(word, vl, true);
                let nodes = source_nodes(&r.guard)
                    + r.temporaries.iter().map(source_nodes).sum::<usize>()
                    + r.effects
                        .iter()
                        .map(|effect| match effect {
                            Effect::WriteIndexedRegister {
                                destination, value, ..
                            } => {
                                assert_eq!(destination.bank, "a64.za64");
                                assert_eq!(destination.count, vl / 8);
                                assert_eq!(destination.stride, 32);
                                source_nodes(&destination.index) + source_nodes(value)
                            }
                            other => panic!("BFDOT expanded a selected-row output: {other:?}"),
                        })
                        .sum::<usize>();
                println!("BFDOT source SVL{vl} VGx{nreg} layout{layout}: temporaries={} outputs={} nodes={nodes}",r.temporaries.len(),r.effects.len());
                assert!(nodes < 32768);
                assert_eq!(r.effects.len(), usize::from(nreg * (vl / 64)));
                let out = run(word, vl, true, &s);
                assert_eq!(out.len(), usize::from(nreg * (vl / 64)));
                assert_eq!(s.calls.get(), usize::from(nreg * (vl / 32)));
                for (reg, value) in out {
                    assert_eq!(reg.index / 32 % stride, first);
                    assert_eq!(value, 0x4040_0000_4040_0000);
                }
            }
        }
    }
}

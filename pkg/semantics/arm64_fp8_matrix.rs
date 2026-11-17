//! Complete FP8 matrix multiply, predicated/MOP4 and selective outer products.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u8)] = &[
    (0xffe0fc00, 0x6e00ec00, 16, 0), // FMMLA_asimd_FP8FP16
    (0xffe0fc00, 0x6e80ec00, 32, 0), // FMMLA_asimd_FP8FP32
    (0xffe0fc00, 0x6460e000, 16, 1), // fmmla_z16_zz8z8_
    (0xffe0fc00, 0x6420e000, 32, 1), // fmmla_z32_zz8z8_
    (0xfff1fe3e, 0x80300008, 16, 3), // fmop4a_za16_z8z8_b1x2
    (0xfff1fe3e, 0x80200008, 16, 3), // fmop4a_za16_z8z8_b1x1
    (0xfff1fe3e, 0x80200208, 16, 3), // fmop4a_za16_z8z8_b2x1
    (0xfff1fe3e, 0x80300208, 16, 3), // fmop4a_za16_z8z8_b2x2
    (0xfff1fe3c, 0x80300000, 32, 3), // fmop4a_za32_z8z8_b1x2
    (0xfff1fe3c, 0x80200000, 32, 3), // fmop4a_za32_z8z8_b1x1
    (0xfff1fe3c, 0x80200200, 32, 3), // fmop4a_za32_z8z8_b2x1
    (0xfff1fe3c, 0x80300200, 32, 3), // fmop4a_za32_z8z8_b2x2
    (0xffe0001e, 0x80a00008, 16, 2), // fmopa_za16_pp_z8z8_8
    (0xffe0001c, 0x80a00000, 32, 2), // fmopa_za32_pp_z8z8_8
    (0xffe0e00e, 0x80600008, 16, 4), // ftmopa_za16_z8z8zi_b2x1
    (0xffe0e00c, 0x80600000, 32, 4), // ftmopa_za32_z8z8zi_b2x1
];
fn part(bank: &'static str, index: u16, bit: u16, width: u8) -> Expr {
    let mut reg = register(bank, index + bit / 64, width, 64);
    reg.offset = (bit % 64) as u8;
    Expr::register(reg)
}
fn z(n: u32, e: u16, w: u8) -> Expr {
    part("a64.vector64", n as u16 * 32, e * u16::from(w), w)
}
fn pred(n: u32, byte: u16) -> Expr {
    part("a64.predicate64", n as u16 * 4, byte, 1)
}
fn combine(out: Expr, v: Expr, at: u16, w: u8, target: u8) -> Expr {
    b(
        B::Or,
        out,
        b(
            B::Shl,
            Expr::cast(v, target, false),
            c(target, u64::from(at) * u64::from(w)),
        ),
    )
}
fn dot(
    r: &mut Recipe,
    acc: Expr,
    a: Expr,
    b_: Expr,
    width: u8,
    ways: u8,
    fpcr: &Expr,
    fpmr: &Expr,
) -> Expr {
    r.bind(Expr::float(FloatExpression {
        operation: FloatOperation::Fp8Dot { ways },
        environment: FloatEnvironment::A64,
        width,
        inputs: vec![acc, a, b_, fpmr.clone()],
        control: Box::new(fpcr.clone()),
        status: Box::new(c(32, 0)),
        projection: FloatProjection::Value,
    }))
}
pub fn a64(word: u32, address: u64, current_vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, width, kind) = FORMS
        .iter()
        .find(|(mask, value, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(current_vl, 128 | 256 | 512 | 1024 | 2048)
        || !matches!(svl, 128 | 256 | 512 | 1024 | 2048)
    {
        return Some(Recipe::unsupported(
            "invalid FP8 matrix CurrentVL/SVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::register(register("a64.svcr", 0, 64, 64));
    r.guard = Expr::require_context(
        if kind >= 2 {
            b(B::Eq, b(B::And, sm, c(64, 3)), c(64, 3))
        } else if kind == 1 {
            b(B::Eq, Expr::extract(sm, 0, 1), c(1, 0))
        } else {
            b(
                B::Or,
                b(B::Eq, Expr::extract(sm, 0, 1), c(1, 0)),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            )
        },
        "FP8 matrix streaming/ZA admission",
    );
    // Predicated outer products consume controls only when a corresponding
    // pair is active. Fixed, unpredicated and selective products always run.
    let fpcr = Expr::register(register("a64.fpcr", 0, 32, 32));
    let fpmr = Expr::register(register("a64.fpmr", 0, 64, 64));
    let fpcr = if kind == 2 { fpcr } else { r.bind(fpcr) };
    let fpmr = if kind == 2 { fpmr } else { r.bind(fpmr) };
    let vl = if kind >= 2 {
        svl
    } else if kind == 0 {
        128
    } else {
        current_vl
    };
    if kind <= 1 {
        let n = (word >> 5) & 31;
        let m = (word >> 16) & 31;
        let d = word & 31;
        let source_width = width * 2;
        for chunk in 0..vl / 64 {
            let old = r.bind(z(d, chunk, 64));
            let mut out = c(64, 0);
            for sub in 0..64 / u16::from(width) {
                let e = chunk * (64 / u16::from(width)) + sub;
                let segment = e / 4;
                let row = (e % 4) / 2;
                let col = e % 2;
                let a = r.bind(z(n, segment * 2 + row, source_width));
                let b_ = r.bind(z(m, segment * 2 + col, source_width));
                let acc = Expr::extract(old.clone(), (sub * u16::from(width)) as u8, width);
                let result = dot(&mut r, acc, a, b_, width, source_width / 8, &fpcr, &fpmr);
                out = combine(out, result, sub, width, 64);
            }
            r.write(
                register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                out,
            );
        }
        if kind == 0 {
            for chunk in 2..current_vl / 64 {
                r.write(
                    register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
                    WritePolicy::ZeroUpper,
                    c(64, 0),
                );
            }
        }
        return Some(r);
    }
    let dim = vl / u16::from(width);
    let bytes = u16::from(width) / 8;
    let tile = (word & u32::from(width / 8 - 1)) as u16;
    let n = (word >> 5)
        & if kind == 3 {
            14
        } else if kind == 4 {
            30
        } else {
            31
        };
    let m = if kind == 3 {
        16 + ((word >> 16) & 14)
    } else {
        (word >> 16) & 31
    };
    let pn = (word >> 10) & 7;
    let pm = (word >> 13) & 7;
    let control_reg = 16 + ((word >> 12) & 1) * 8 + 4 + ((word >> 10) & 3);
    let control_start = ((word >> 4) & 3) as u16 * (vl / 4);
    // Capture each predicated source vector once. Every output cell uses the
    // same masked row/column operand; rebuilding it per cell makes the native
    // transition quadratic in both cells and byte-selection expression size.
    // Pair activity controls the captures so empty predicates still require no
    // source or FP environment state, including disjoint byte predicates.
    let mut left_pred = Vec::new();
    let mut right_pred = Vec::new();
    let mut left = Vec::new();
    let mut right = Vec::new();
    let (fpcr, fpmr) = if kind == 2 {
        for e in 0..dim {
            left_pred.push(
                (0..bytes)
                    .map(|i| r.bind(pred(pn, e * bytes + i)))
                    .collect::<Vec<_>>(),
            );
            right_pred.push(
                (0..bytes)
                    .map(|i| r.bind(pred(pm, e * bytes + i)))
                    .collect::<Vec<_>>(),
            );
        }
        let any_left = (0..bytes)
            .map(|i| {
                r.bind((0..dim).fold(c(1, 0), |out, e| {
                    b(B::Or, out, left_pred[e as usize][i as usize].clone())
                }))
            })
            .collect::<Vec<_>>();
        let any_right = (0..bytes)
            .map(|i| {
                r.bind((0..dim).fold(c(1, 0), |out, e| {
                    b(B::Or, out, right_pred[e as usize][i as usize].clone())
                }))
            })
            .collect::<Vec<_>>();
        let active = r.bind((0..bytes).fold(c(1, 0), |out, i| {
            b(
                B::Or,
                out,
                b(
                    B::And,
                    any_left[i as usize].clone(),
                    any_right[i as usize].clone(),
                ),
            )
        }));
        for e in 0..dim {
            let active_left = r.bind((0..bytes).fold(c(1, 0), |out, i| {
                b(
                    B::Or,
                    out,
                    b(
                        B::And,
                        left_pred[e as usize][i as usize].clone(),
                        any_right[i as usize].clone(),
                    ),
                )
            }));
            let active_right = r.bind((0..bytes).fold(c(1, 0), |out, i| {
                b(
                    B::Or,
                    out,
                    b(
                        B::And,
                        right_pred[e as usize][i as usize].clone(),
                        any_left[i as usize].clone(),
                    ),
                )
            }));
            let a = (0..bytes).fold(c(width, 0), |out, i| {
                combine(
                    out,
                    Expr::select(
                        left_pred[e as usize][i as usize].clone(),
                        z(n, e * bytes + i, 8),
                        c(8, 0),
                    ),
                    i,
                    8,
                    width,
                )
            });
            let b_ = (0..bytes).fold(c(width, 0), |out, i| {
                combine(
                    out,
                    Expr::select(
                        right_pred[e as usize][i as usize].clone(),
                        z(m, e * bytes + i, 8),
                        c(8, 0),
                    ),
                    i,
                    8,
                    width,
                )
            });
            left.push(r.bind(Expr::select(active_left, a, c(width, 0))));
            right.push(r.bind(Expr::select(active_right, b_, c(width, 0))));
        }
        (
            r.bind(Expr::select(active.clone(), fpcr, c(32, 0))),
            r.bind(Expr::select(active, fpmr, c(64, 0))),
        )
    } else {
        (fpcr, fpmr)
    };
    // FTMOPA selection depends on the column, not on the matrix row.
    // Cache placements and demanded source bytes before constructing cells.
    let mut placements = Vec::new();
    let mut selected_sources = Vec::new();
    let mut selective_right = Vec::new();
    if kind == 4 {
        let mut uses = vec![c(1, 0); usize::from(bytes) * 2];
        for col in 0..dim {
            let mut slots = vec![vec![c(1, 0); usize::from(bytes) * 2]; usize::from(bytes)];
            let mut count = c(8, 0);
            for member in 0..2u16 {
                if width == 32 {
                    count = c(8, 0);
                }
                for e in 0..bytes {
                    let selected = part(
                        "a64.vector64",
                        control_reg as u16 * 32,
                        control_start + col * bytes * 2 + member * bytes + e,
                        1,
                    );
                    let take = r.bind(Expr::select(
                        b(B::Ult, count.clone(), c(8, 2)),
                        selected,
                        c(1, 0),
                    ));
                    let source = usize::from(member * bytes + e);
                    uses[source] = b(B::Or, uses[source].clone(), take.clone());
                    for slot in 0..2u16 {
                        let at = usize::from(if width == 32 { member * 2 + slot } else { slot });
                        slots[at][source] = r.bind(b(
                            B::And,
                            take.clone(),
                            b(B::Eq, count.clone(), c(8, u64::from(slot))),
                        ));
                    }
                    count = r.bind(b(B::Add, count, Expr::cast(take, 8, false)));
                }
            }
            placements.push(slots);
            selective_right.push(r.bind(z(m, col, width)));
        }
        let uses = uses.into_iter().map(|v| r.bind(v)).collect::<Vec<_>>();
        for row in 0..dim {
            let mut sources = Vec::new();
            for member in 0..2u16 {
                for e in 0..bytes {
                    sources.push(r.bind(Expr::select(
                        uses[usize::from(member * bytes + e)].clone(),
                        z(n + u32::from(member), row * bytes + e, 8),
                        c(8, 0),
                    )));
                }
            }
            selected_sources.push(sources);
        }
    }
    // FMOP4A operands vary only by one quadrant bit. Capture each demanded
    // row/column once, rather than reconstructing its byte pack for every cell.
    // This retains the complete maximum-length matrix under the fixed native
    // expression budget without raising that budget or reading unused members.
    let mut quadrant_left = Vec::new();
    let mut quadrant_right = Vec::new();
    if kind == 3 {
        for member in 0..=u32::from((word >> 9) & 1 != 0) {
            quadrant_left.push(
                (0..dim)
                    .map(|row| r.bind(z(n + member, row, width)))
                    .collect::<Vec<_>>(),
            );
        }
        for member in 0..=u32::from((word >> 20) & 1 != 0) {
            quadrant_right.push(
                (0..dim)
                    .map(|col| r.bind(z(m + member, col, width)))
                    .collect::<Vec<_>>(),
            );
        }
    }
    for row in 0..dim {
        for chunk in 0..vl / 64 {
            let physical = row * bytes + tile;
            let old = r.bind(part("a64.za64", physical * 32, chunk * 64, 64));
            let mut out = c(64, 0);
            for sub in 0..64 / u16::from(width) {
                let col = chunk * (64 / u16::from(width)) + sub;
                let acc = Expr::extract(old.clone(), (sub * u16::from(width)) as u8, width);
                let mut a = c(width, 0);
                let b_;
                let mut active = c(1, 0);
                if kind == 4 {
                    for slot in 0..bytes {
                        let mut value = c(8, 0);
                        for source in 0..usize::from(bytes) * 2 {
                            value = Expr::select(
                                placements[col as usize][slot as usize][source].clone(),
                                selected_sources[row as usize][source].clone(),
                                value,
                            );
                        }
                        a = combine(a, value, slot, 8, width);
                    }
                    a = r.bind(a);
                    b_ = selective_right[col as usize].clone();
                    active = c(1, 1);
                } else if kind == 2 {
                    a = left[row as usize].clone();
                    b_ = right[col as usize].clone();
                    for i in 0..bytes {
                        active = b(
                            B::Or,
                            active,
                            b(
                                B::And,
                                left_pred[row as usize][i as usize].clone(),
                                right_pred[col as usize][i as usize].clone(),
                            ),
                        );
                    }
                } else {
                    let left_member = ((word >> 9) & 1) as usize * usize::from(col / (dim / 2));
                    let right_member = ((word >> 20) & 1) as usize * usize::from(row / (dim / 2));
                    a = quadrant_left[left_member][row as usize].clone();
                    b_ = quadrant_right[right_member][col as usize].clone();
                    active = c(1, 1);
                }
                // Keep the FP intrinsic conditional: a wholly inactive product does
                // not read source bytes, evaluate NaNs or depend on FPMR formats.
                let result = Expr::float(FloatExpression {
                    operation: FloatOperation::Fp8Dot { ways: width / 8 },
                    environment: FloatEnvironment::A64,
                    width,
                    inputs: vec![acc.clone(), a, b_, fpmr.clone()],
                    control: Box::new(fpcr.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                });
                let value = r.bind(Expr::select(active, result, acc));
                out = combine(out, value, sub, width, 64);
            }
            r.write(
                register("a64.za64", physical * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                out,
            );
        }
    }
    Some(r)
}

//! All SVE/SME FP8 widening fused multiply/accumulate layouts (June 2026).
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
// Physical diagram: mask, value, result width, operand layout, group size, lane selector.
const FORMS: &[(u32, u32, u8, u8, u16, u16)] = &[
    (0xffe0fc00, 0x64a08800, 16, 0, 1, 0), // fmlalb_z_z8z8z8_
    (0xffe0f000, 0x64205000, 16, 1, 1, 0), // fmlalb_z_z8z8z8i_
    (0xffe0fc00, 0x64208800, 32, 0, 1, 0), // fmlallbb_z32_z8z8z8_
    (0xffe0f000, 0x6420c000, 32, 1, 1, 0), // fmlallbb_z32_z8z8z8i_
    (0xffe0fc00, 0x64209800, 32, 0, 1, 1), // fmlallbt_z32_z8z8z8_
    (0xffe0f000, 0x6460c000, 32, 1, 1, 1), // fmlallbt_z32_z8z8z8i_
    (0xffe0fc00, 0x6420a800, 32, 0, 1, 2), // fmlalltb_z32_z8z8z8_
    (0xffe0f000, 0x64a0c000, 32, 1, 1, 2), // fmlalltb_z32_z8z8z8i_
    (0xffe0fc00, 0x6420b800, 32, 0, 1, 3), // fmlalltt_z32_z8z8z8_
    (0xffe0f000, 0x64e0c000, 32, 1, 1, 3), // fmlalltt_z32_z8z8z8i_
    (0xfff0001c, 0xc1400000, 32, 2, 1, 0), // fmlall_za32_z8z8i_1
    (0xfff09038, 0xc1900020, 32, 2, 2, 0), // fmlall_za32_z8z8i_2xi
    (0xfff09078, 0xc1108040, 32, 2, 4, 0), // fmlall_za32_z8z8i_4xi
    (0xfff09c1c, 0xc1300400, 32, 3, 1, 0), // fmlall_za32_z8z8v_1
    (0xfff09c1e, 0xc1200002, 32, 3, 2, 0), // fmlall_za32_z8z8v_2x1
    (0xfff09c1e, 0xc1300002, 32, 3, 4, 0), // fmlall_za32_z8z8v_4x1
    (0xffe19c3e, 0xc1a00020, 32, 4, 2, 0), // fmlall_za32_z8z8w_2x2
    (0xffe39c7e, 0xc1a10020, 32, 4, 4, 0), // fmlall_za32_z8z8w_4x4
    (0xffe0fc00, 0x64a09800, 16, 0, 1, 1), // fmlalt_z_z8z8z8_
    (0xffe0f000, 0x64a05000, 16, 1, 1, 1), // fmlalt_z_z8z8z8i_
    (0xfff01010, 0xc1c00000, 16, 2, 1, 0), // fmlal_za_z8z8i_1
    (0xfff09030, 0xc1901030, 16, 2, 2, 0), // fmlal_za_z8z8i_2xi
    (0xfff09070, 0xc1909020, 16, 2, 4, 0), // fmlal_za_z8z8i_4xi
    (0xfff09c18, 0xc1300c00, 16, 3, 1, 0), // fmlal_za_z8z8v_1
    (0xfff09c1c, 0xc1200804, 16, 3, 2, 0), // fmlal_za_z8z8v_2x1
    (0xfff09c1c, 0xc1300804, 16, 3, 4, 0), // fmlal_za_z8z8v_4x1
    (0xffe19c3c, 0xc1a00820, 16, 4, 2, 0), // fmlal_za_z8z8w_2x2
    (0xffe39c7c, 0xc1a10820, 16, 4, 4, 0), // fmlal_za_z8z8w_4x4
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut reg = register("a64.vector64", n as u16 * 32 + bit / 64, w, 64);
    reg.offset = (bit % 64) as u8;
    Expr::register(reg)
}
pub fn a64(word: u32, address: u64, current_vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, width, kind, nreg, sel) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let za = kind >= 2;
    let vl = if za { svl } else { current_vl };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid FP8 widening CurrentVL/SVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    let svcr = Expr::register(register("a64.svcr", 0, 64, 64));
    r.guard = Expr::require_context(
        if za {
            b(B::Eq, b(B::And, svcr, c(64, 3)), c(64, 3))
        } else {
            Expr::select(
                Expr::extract(svcr, 0, 1),
                Expr::register(register("a64.ssve_fp8_fma", 0, 1, 1)),
                Expr::register(register("a64.fp8_fma", 0, 1, 1)),
            )
        },
        "FP8 widening streaming/feature admission",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let fpmr = r.bind(Expr::register(register("a64.fpmr", 0, 64, 64)));
    let n = (word >> 5)
        & if za && kind != 3 {
            32 - u32::from(nreg)
        } else {
            31
        };
    let m = (word >> 16)
        & if kind == 4 {
            32 - u32::from(nreg)
        } else if za {
            15
        } else if kind == 1 {
            7
        } else {
            31
        };
    let d = word & 31;
    let index = if !za {
        ((word >> 19) & 3) * 4 + ((word >> 10) & 3)
    } else if nreg == 1 && width == 16 {
        ((word >> 15) & 1) * 8 + ((word >> 10) & 3) * 2 + ((word >> 3) & 1)
    } else if nreg == 1 {
        ((word >> 15) & 1) * 8 + ((word >> 10) & 7)
    } else {
        ((word >> 10) & 3) * 4 + ((word >> if width == 16 { 2 } else { 1 }) & 3)
    } as u16;
    let rows = u16::from(width) / 8;
    let base = if za {
        let offset = (word
            & if nreg == 1 {
                if width == 16 {
                    7
                } else {
                    3
                }
            } else if width == 16 {
                3
            } else {
                1
            })
            * u32::from(rows);
        let sum = b(
            B::Add,
            Expr::cast(
                Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                64,
                false,
            ),
            c(64, u64::from(offset)),
        );
        let v = r.bind(b(B::Urem, sum, c(64, u64::from(vl / 8 / nreg))));
        r.bind(b(B::And, v, c(64, !(u64::from(rows) - 1))))
    } else {
        c(64, 0)
    };
    for member in 0..nreg {
        for part in 0..if za { rows } else { 1 } {
            let row = b(
                B::Add,
                base.clone(),
                c(64, u64::from(member * (vl / 8 / nreg) + part)),
            );
            for chunk in 0..vl / 64 {
                let dst = IndexedRegister {
                    bank: "a64.za64",
                    base: chunk,
                    stride: 32,
                    count: vl / 8,
                    index: Box::new(row.clone()),
                    offset: 0,
                    width: 64,
                    parent_width: 64,
                };
                let old = r.bind(if za {
                    Expr::indexed_register(dst.clone())
                } else {
                    lane(d, chunk, 64)
                });
                let mut packed = c(64, 0);
                for sub in 0..64 / u16::from(width) {
                    let e = chunk * (64 / u16::from(width)) + sub;
                    let a_index = e * rows + if za { part } else { sel };
                    let b_index = if kind == 1 || kind == 2 {
                        e / (128 / u16::from(width)) * 16 + index
                    } else {
                        a_index
                    };
                    let a = r.bind(lane((n + u32::from(member)) % 32, a_index, 8));
                    let b_ = r.bind(lane(
                        m + if kind == 4 { u32::from(member) } else { 0 },
                        b_index,
                        8,
                    ));
                    let value = r.bind(Expr::float(FloatExpression {
                        operation: FloatOperation::Fp8WideningFused,
                        environment: FloatEnvironment::A64,
                        width,
                        inputs: vec![
                            Expr::extract(old.clone(), (sub * u16::from(width)) as u8, width),
                            a,
                            b_,
                            fpmr.clone(),
                        ],
                        control: Box::new(control.clone()),
                        status: Box::new(c(32, 0)),
                        projection: FloatProjection::Value,
                    }));
                    packed = b(
                        B::Or,
                        packed,
                        b(
                            B::Shl,
                            Expr::cast(value, 64, false),
                            c(64, u64::from(sub * u16::from(width))),
                        ),
                    );
                }
                if za {
                    r.write_indexed(dst, WritePolicy::ZeroUpper, packed);
                } else {
                    r.write(
                        register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
                        WritePolicy::ZeroUpper,
                        packed,
                    );
                }
            }
        }
    }
    Some(r)
}

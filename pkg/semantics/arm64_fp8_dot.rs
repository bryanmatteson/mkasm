//! All SVE FDOT and SME FDOT/FVDOT FP8 layouts.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u8, u16, u16)] = &[
    (0xffe0fc00, 0x64608400, 32, 0, 1, 0), // fdot_z32_zz8z8_
    (0xffe0fc00, 0x64604400, 32, 1, 1, 0), // fdot_z32_zz8z8i_
    (0xfff09038, 0xc1500038, 32, 2, 2, 0), // fdot_za32_z8z8i_2xi
    (0xfff09078, 0xc1508008, 32, 2, 4, 0), // fdot_za32_z8z8i_4xi
    (0xfff09c18, 0xc1201018, 32, 3, 2, 0), // fdot_za32_z8z8v_2x1
    (0xfff09c18, 0xc1301018, 32, 3, 4, 0), // fdot_za32_z8z8v_4x1
    (0xffe19c38, 0xc1a01030, 32, 4, 2, 0), // fdot_za32_z8z8w_2x2
    (0xffe39c78, 0xc1a11030, 32, 4, 4, 0), // fdot_za32_z8z8w_4x4
    (0xfff09030, 0xc1d00020, 16, 2, 2, 0), // fdot_za_z8z8i_2xi
    (0xfff09070, 0xc1109040, 16, 2, 4, 0), // fdot_za_z8z8i_4xi
    (0xfff09c18, 0xc1201008, 16, 3, 2, 0), // fdot_za_z8z8v_2x1
    (0xfff09c18, 0xc1301008, 16, 3, 4, 0), // fdot_za_z8z8v_4x1
    (0xffe19c38, 0xc1a01020, 16, 4, 2, 0), // fdot_za_z8z8w_2x2
    (0xffe39c78, 0xc1a11020, 16, 4, 4, 0), // fdot_za_z8z8w_4x4
    (0xffe0fc00, 0x64208400, 16, 0, 1, 0), // fdot_z_zz8z8_
    (0xffe0f400, 0x64204400, 16, 1, 1, 0), // fdot_z_zz8z8i_
    (0xfff09830, 0xc1d00800, 32, 5, 4, 0), // fvdotb_za32_z8z8i_2xi
    (0xfff09830, 0xc1d00810, 32, 5, 4, 1), // fvdott_za32_z8z8i_2xi
    (0xfff09030, 0xc1d01020, 16, 5, 2, 0), // fvdot_za_z8z8i_2xi
];
fn lane(n: u32, e: u16, width: u8) -> Expr {
    let bit = e * u16::from(width);
    let mut reg = register("a64.vector64", n as u16 * 32 + bit / 64, width, 64);
    reg.offset = (bit % 64) as u8;
    Expr::register(reg)
}
pub fn a64(word: u32, address: u64, current_vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, width, kind, nreg, top) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let za = kind >= 2;
    let vl = if za { svl } else { current_vl };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid FP8 dot CurrentVL/SVL",
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
                Expr::register(register(
                    if width == 16 {
                        "a64.ssve_fp8_dot2"
                    } else {
                        "a64.ssve_fp8_dot4"
                    },
                    0,
                    1,
                    1,
                )),
                Expr::register(register(
                    if width == 16 {
                        "a64.fp8_dot2"
                    } else {
                        "a64.fp8_dot4"
                    },
                    0,
                    1,
                    1,
                )),
            )
        },
        "FP8 dot streaming/feature admission",
    );
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let fpmr = r.bind(Expr::register(register("a64.fpmr", 0, 64, 64)));
    let n = (word >> 5)
        & if kind == 2 || kind == 4 {
            32 - u32::from(nreg)
        } else if kind == 5 {
            30
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
    let index = if za {
        if width == 16 {
            ((word >> 10) & 3) * 2 + ((word >> 3) & 1)
        } else if kind == 5 {
            ((word >> 10) & 1) * 2 + ((word >> 3) & 1)
        } else {
            (word >> 10) & 3
        }
    } else if width == 16 {
        ((word >> 19) & 3) * 2 + ((word >> 11) & 1)
    } else {
        (word >> 19) & 3
    } as u16;
    let base = if za {
        let sum = b(
            B::Add,
            Expr::cast(
                Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                64,
                false,
            ),
            c(64, u64::from(word & 7)),
        );
        r.bind(b(B::Urem, sum, c(64, u64::from(vl / 8 / nreg))))
    } else {
        c(64, 0)
    };
    for member in 0..nreg {
        let row = b(
            B::Add,
            base.clone(),
            c(64, u64::from(member * (vl / 8 / nreg))),
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
                lane(word & 31, chunk, 64)
            });
            let mut packed = c(64, 0);
            for sub in 0..64 / u16::from(width) {
                let e = chunk * (64 / u16::from(width)) + sub;
                let source_width = if kind == 5 { 16 } else { width };
                let (a, bi) = if kind == 5 {
                    let ai = e * (u16::from(width) / 8) + member;
                    let a = b(
                        B::Or,
                        Expr::cast(lane(n, ai, 8), 16, false),
                        b(B::Shl, Expr::cast(lane(n + 1, ai, 8), 16, false), c(16, 8)),
                    );
                    let si = e / (128 / u16::from(width)) * (128 / u16::from(width)) + index;
                    (a, if width == 32 { si * 2 + top } else { si })
                } else {
                    (
                        lane((n + u32::from(member)) % 32, e, width),
                        if kind == 1 || kind == 2 {
                            e / (128 / u16::from(width)) * (128 / u16::from(width)) + index
                        } else {
                            e
                        },
                    )
                };
                let a = r.bind(a);
                let rhs = r.bind(lane(
                    m + if kind == 4 { u32::from(member) } else { 0 },
                    bi,
                    source_width,
                ));
                let value = r.bind(Expr::float(FloatExpression {
                    operation: FloatOperation::Fp8Dot {
                        ways: source_width / 8,
                    },
                    environment: FloatEnvironment::A64,
                    width,
                    inputs: vec![
                        Expr::extract(old.clone(), (sub * u16::from(width)) as u8, width),
                        a,
                        rhs,
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
                    register("a64.vector64", (word & 31) as u16 * 32 + chunk, 64, 64),
                    WritePolicy::ZeroUpper,
                    packed,
                );
            }
        }
    }
    Some(r)
}

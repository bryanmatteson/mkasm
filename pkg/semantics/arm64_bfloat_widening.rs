//! All AdvSIMD, SVE and SME2 BFMLAL/BFMLSL physical classes (June 2026).
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
// mask, value, layout, group size, subtract. Fixed primary diagram bits only.
const FORMS: &[(u32, u32, u8, u16, bool)] = &[
    (0xffe0fc00, 0x64e08000, 2, 1, false), // bfmlalb_z_zzz_
    (0xffe0f400, 0x64e04000, 3, 1, false), // bfmlalb_z_zzzi_
    (0xffe0fc00, 0x64e08400, 2, 1, false), // bfmlalt_z_zzz_
    (0xffe0f400, 0x64e04400, 3, 1, false), // bfmlalt_z_zzzi_
    (0xbfc0f400, 0x0fc0f000, 1, 1, false), // BFMLAL_asimdelem_F
    (0xbfe0fc00, 0x2ec0fc00, 0, 1, false), // BFMLAL_asimdsame2_F_
    (0xfff01018, 0xc1801010, 4, 1, false), // bfmlal_za_zzi_1
    (0xfff09038, 0xc1901010, 4, 2, false), // bfmlal_za_zzi_2xi
    (0xfff09078, 0xc1909010, 4, 4, false), // bfmlal_za_zzi_4xi
    (0xfff09c18, 0xc1200c10, 5, 1, false), // bfmlal_za_zzv_1
    (0xfff09c1c, 0xc1200810, 5, 2, false), // bfmlal_za_zzv_2x1
    (0xfff09c1c, 0xc1300810, 5, 4, false), // bfmlal_za_zzv_4x1
    (0xffe19c3c, 0xc1a00810, 6, 2, false), // bfmlal_za_zzw_2x2
    (0xffe39c7c, 0xc1a10810, 6, 4, false), // bfmlal_za_zzw_4x4
    (0xffe0fc00, 0x64e0a000, 2, 1, true),  // bfmlslb_z_zzz_
    (0xffe0f400, 0x64e06000, 3, 1, true),  // bfmlslb_z_zzzi_
    (0xffe0fc00, 0x64e0a400, 2, 1, true),  // bfmlslt_z_zzz_
    (0xffe0f400, 0x64e06400, 3, 1, true),  // bfmlslt_z_zzzi_
    (0xfff01018, 0xc1801018, 4, 1, true),  // bfmlsl_za_zzi_1
    (0xfff09038, 0xc1901018, 4, 2, true),  // bfmlsl_za_zzi_2xi
    (0xfff09078, 0xc1909018, 4, 4, true),  // bfmlsl_za_zzi_4xi
    (0xfff09c18, 0xc1200c18, 5, 1, true),  // bfmlsl_za_zzv_1
    (0xfff09c1c, 0xc1200818, 5, 2, true),  // bfmlsl_za_zzv_2x1
    (0xfff09c1c, 0xc1300818, 5, 4, true),  // bfmlsl_za_zzv_4x1
    (0xffe19c3c, 0xc1a00818, 6, 2, true),  // bfmlsl_za_zzw_2x2
    (0xffe39c7c, 0xc1a10818, 6, 4, true),  // bfmlsl_za_zzw_4x4
];
fn source(reg: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    let mut r = register("a64.vector64", reg as u16 * 32 + bit / 64, w, 64);
    r.offset = (bit % 64) as u8;
    Expr::register(r)
}
fn neg(value: Expr, control: Expr) -> Expr {
    // BFNeg leaves either NaN sign unchanged under AFP.AH.
    let nan = b(
        B::And,
        b(
            B::Eq,
            b(B::And, value.clone(), c(16, 0x7f80)),
            c(16, 0x7f80),
        ),
        b(B::Ult, c(16, 0), b(B::And, value.clone(), c(16, 127))),
    );
    let keep = b(B::And, Expr::extract(control, 1, 1), nan);
    Expr::select(keep, value.clone(), b(B::Xor, value, c(16, 0x8000)))
}
/// CurrentVL for SVE; saved SVL for SME-only ZA operations. Fixed V writes
/// clear active upper Z, while scalable writes retain backing beyond active VL.
pub fn a64(word: u32, address: u64, current_vl: u16, svl: u16) -> Option<Recipe> {
    let &(_, _, kind, nreg, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _)| word & mask == *value)?;
    let za = kind >= 4;
    let fixed = kind < 2;
    let vl = if za { svl } else { current_vl };
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid BF16 widening CurrentVL/SVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    if za {
        r.guard = Expr::require_context(
            b(
                B::Eq,
                b(
                    B::And,
                    Expr::register(register("a64.svcr", 0, 2, 2)),
                    c(2, 3),
                ),
                c(2, 3),
            ),
            "BF16 ZA widening requires streaming and ZA enabled",
        );
    }
    let original_control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    // ZA forms cannot accrue or trap exceptions and have no FPSR dependency.
    let mut fp = if za {
        None
    } else {
        Some(FloatState::new(&mut r))
    };
    if let Some(fp) = fp.as_mut() {
        fp.control = original_control.clone();
        if !fixed {
            let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
            let full = Expr::register(register("a64.sme_fa64", 0, 1, 1));
            fp.control = Expr::select(
                b(B::And, sm, b(B::Eq, full, c(1, 0))),
                b(B::And, original_control.clone(), c(32, !0x9f00u64)),
                original_control.clone(),
            );
        }
    }
    let indexed = kind == 1 || kind == 3 || kind == 4;
    let grouped_m = kind == 6;
    let n = (word >> 5)
        & if za && kind != 5 {
            32 - u32::from(nreg)
        } else {
            31
        };
    let m = (word >> 16)
        & if grouped_m {
            32 - u32::from(nreg)
        } else if kind == 1 || za {
            15
        } else if indexed {
            7
        } else {
            31
        };
    let index = if kind == 1 {
        ((word >> 11) & 1) * 4 + ((word >> 20) & 3)
    } else if kind == 3 {
        ((word >> 19) & 3) * 2 + ((word >> 11) & 1)
    } else if kind == 4 && nreg == 1 {
        ((word >> 15) & 1) * 4 + ((word >> 10) & 3)
    } else {
        ((word >> 10) & 3) * 2 + ((word >> 2) & 1)
    } as u16;
    let d = word & 31;
    let sel = if fixed {
        ((word >> 30) & 1) as u16
    } else {
        ((word >> 10) & 1) as u16
    };
    let width = if fixed { 128 } else { vl };
    // Bind selected inputs only. All temporaries evaluate against incoming
    // state before any effect, including overlapping source/accumulator views.
    let base = if za {
        let off = (word & if nreg == 1 { 7 } else { 3 }) * 2;
        let sum = b(
            B::Add,
            Expr::cast(
                Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                64,
                false,
            ),
            c(64, u64::from(off)),
        );
        let v = r.bind(b(B::Urem, sum, c(64, u64::from(vl / 8 / nreg))));
        r.bind(b(B::And, v, c(64, !1u64)))
    } else {
        c(64, 0)
    };
    for member in 0..nreg {
        for pair in 0..if za { 2 } else { 1 } {
            let row = b(
                B::Add,
                base.clone(),
                c(64, u64::from(member * (vl / 8 / nreg) + pair)),
            );
            let mut outputs = Vec::new();
            for chunk in 0..width / 64 {
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
                    source(d, chunk, 64)
                });
                let mut packed = c(64, 0);
                for part in 0..2 {
                    let e = chunk * 2 + part;
                    let lane = 2 * e + if za { pair } else { sel };
                    let right = if indexed {
                        if fixed {
                            index
                        } else {
                            2 * (e / 4 * 4) + index
                        }
                    } else {
                        lane
                    };
                    let x = r.bind(source((n + u32::from(member)) % 32, lane, 16));
                    let x = if subtract {
                        neg(x, original_control.clone())
                    } else {
                        x
                    };
                    let y = r.bind(source(
                        m + if grouped_m { u32::from(member) } else { 0 },
                        right,
                        16,
                    ));
                    let inputs = vec![Expr::extract(old.clone(), (part * 32) as u8, 32), x, y];
                    let operation = FloatOperation::BFloatWideningFused { za };
                    let value = if let Some(fp) = fp.as_mut() {
                        fp.step(&mut r, operation, 32, inputs, c(1, 1), c(32, 0), true)
                    } else {
                        r.bind(Expr::float(FloatExpression {
                            operation,
                            environment: FloatEnvironment::A64,
                            width: 32,
                            inputs,
                            control: Box::new(b(
                                B::And,
                                original_control.clone(),
                                c(32, !(1u64 << 26)),
                            )),
                            status: Box::new(c(32, 0)),
                            projection: FloatProjection::Value,
                        }))
                    };
                    packed = b(
                        B::Or,
                        packed,
                        b(
                            B::Shl,
                            Expr::cast(value, 64, false),
                            c(64, u64::from(part * 32)),
                        ),
                    );
                }
                outputs.push((dst, packed));
            }
            // FloatState records precise exceptions before the register effects commit.
            for (chunk, (dst, value)) in outputs.into_iter().enumerate() {
                if za {
                    r.write_indexed(dst, WritePolicy::ZeroUpper, value);
                } else {
                    r.write(
                        register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
                        WritePolicy::ZeroUpper,
                        value,
                    );
                }
            }
        }
    }
    if let Some(fp) = fp {
        let writes = std::mem::take(&mut r.effects);
        fp.finish(&mut r);
        r.effects.extend(writes);
    }
    if fixed {
        for chunk in 2..vl / 64 {
            r.write(
                register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                c(64, 0),
            );
        }
    }
    Some(r)
}

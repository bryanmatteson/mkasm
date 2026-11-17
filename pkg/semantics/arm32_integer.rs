//! Audited A32/Thumb DSP and integer Advanced SIMD recipes. Physical masks and
//! lane rules follow the Arm A-profile 2026-06 instruction corpus. The caller
//! supplies feature legality, the architectural predicate and IT pipeline writes.
//! D/Q operands share a32.vector64 D0..D31 storage; saturation uses the existing
//! a32.q (DSP) or a32.fpscr.QC[27] (SIMD), never a shadow aggregate flag bank.
use super::*;
use BinaryOp as B;

fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn sel(p: Expr, a: Expr, z: Expr) -> Expr {
    Expr::select(p, a, z)
}
fn eq(a: Expr, z: Expr) -> Expr {
    b(B::Eq, a, z)
}
fn ext(a: Expr, offset: u8, width: u8) -> Expr {
    Expr::extract(a, offset, width)
}
fn cast(a: Expr, width: u8, signed: bool) -> Expr {
    Expr::cast(a, width, signed)
}
fn g(n: u32) -> Expr {
    Expr::register(register("a32.gpr", n as u16, 32, 32))
}
fn d(n: u32) -> Expr {
    Expr::register(register("a32.vector64", n as u16, 64, 64))
}
fn wg(r: &mut Recipe, n: u32, value: Expr) {
    r.write(
        register("a32.gpr", n as u16, 32, 32),
        WritePolicy::ZeroUpper,
        value,
    );
}
fn wd(r: &mut Recipe, n: u32, value: Expr) {
    r.write(
        register("a32.vector64", n as u16, 64, 64),
        WritePolicy::ZeroUpper,
        value,
    );
}
fn unsupported(mut r: Recipe, reason: &'static str) -> Recipe {
    r.support = Support::Unsupported(reason);
    r
}
fn sticky(r: &mut Recipe, saturated: Expr, simd: bool) {
    let mut flag = if simd {
        register("a32.fpscr", 0, 1, 32)
    } else {
        register("a32.q", 0, 1, 1)
    };
    if simd {
        flag.offset = 27;
    }
    // A known saturation sets the bit even when its incoming value is unknown.
    r.write(
        flag,
        WritePolicy::Preserve,
        sel(saturated, c(1, 1), Expr::register(flag)),
    );
}
fn pack(mut into: Expr, value: Expr, offset: u8) -> Expr {
    let width = into.ty.width;
    into = b(
        B::Or,
        into,
        b(
            B::Shl,
            cast(value, width, false),
            c(width, u64::from(offset)),
        ),
    );
    into
}
fn lane(n: u32, index: u8, width: u8) -> Expr {
    let bit = u16::from(index) * u16::from(width);
    ext(d(n + u32::from(bit / 64)), (bit % 64) as u8, width)
}

// Clamp a represented integer to a narrower signed/unsigned range. A zero-bit
// unsigned saturation range is {0}; retain a valid one-bit expression type.
fn clamp(value: Expr, signed_in: bool, bits: u8, signed_out: bool) -> (Expr, Expr) {
    let w = value.ty.width;
    let low = if signed_out {
        (!mask(bits - 1)) & mask(w)
    } else {
        0
    };
    let high = if signed_out {
        mask(bits - 1)
    } else {
        mask(bits)
    };
    let below = if signed_in {
        b(B::Slt, value.clone(), c(w, low))
    } else {
        c(1, 0)
    };
    let above = if signed_in && !signed_out && bits >= w {
        c(1, 0)
    } else {
        b(
            if signed_in { B::Slt } else { B::Ult },
            c(w, high),
            value.clone(),
        )
    };
    let sat = b(B::Or, below.clone(), above.clone());
    (
        cast(
            sel(below, c(w, low), sel(above, c(w, high), value)),
            bits.max(1),
            false,
        ),
        sat,
    )
}
fn sat_binary(a: Expr, z: Expr, signed: bool, sub: bool) -> (Expr, Expr) {
    let w = a.ty.width;
    let value = b(if sub { B::Sub } else { B::Add }, a.clone(), z.clone());
    let sat = if signed {
        Expr::overflow(sub, a.clone(), z, value.clone())
    } else if sub {
        Expr::sub_borrow(a.clone(), z, c(1, 0))
    } else {
        Expr::add_carry(a.clone(), z, c(1, 0))
    };
    let bound = if signed {
        sel(ext(a, w - 1, 1), c(w, 1u64 << (w - 1)), c(w, mask(w - 1)))
    } else {
        c(w, if sub { 0 } else { mask(w) })
    };
    (sel(sat.clone(), bound, value), sat)
}

// Convert only audited T32 DSP classes to their A32 field layout. This is an
// encoding transform, not mnemonic-based dispatch; the supplied guard is kept.
fn thumb_dsp(word: u32) -> Option<u32> {
    let n = (word >> 16) & 15;
    let m = word & 15;
    let rd = (word >> 8) & 15;
    let ra = (word >> 12) & 15;
    if word & 0xfff0f0c0 == 0xfa80f080 {
        let op = ((word >> 5) & 1) | (((word >> 4) & 1) << 1);
        return Some(0x01000050 | (op << 21) | (n << 16) | (rd << 12) | m);
    }
    if word & 0xfff0f0f0 == 0xfaa0f080 {
        return Some(0x06800fb0 | (n << 16) | (rd << 12) | m);
    }
    if word & 0xfff08010 == 0xeac00000 {
        let shift = (((word >> 12) & 7) << 2) | ((word >> 6) & 3);
        return Some(0x06800010 | (n << 16) | (rd << 12) | (shift << 7) | ((word & 0x20) << 1) | m);
    }
    if matches!(word & 0xfff0f0c0, 0xfa20f080 | 0xfa30f080) {
        return Some(
            0x06800070
                | ((word & 0x00100000) << 2)
                | (n << 16)
                | (rd << 12)
                | (((word >> 4) & 3) << 10)
                | m,
        );
    }
    if word & 0xffe0f0c0 == 0xfac0f080 {
        return Some(
            0x01000040
                | (((word >> 4) & 3) << 21)
                | (((word >> 20) & 1) << 9)
                | (n << 16)
                | (rd << 12)
                | m,
        );
    }
    if word & 0xfff000f0 == 0xfb000010 {
        return Some(0x00600090 | (rd << 16) | (ra << 12) | (m << 8) | n);
    }
    if word & 0xfff000f0 == 0xfbe00060 {
        return Some(0x00400090 | (rd << 16) | (ra << 12) | (m << 8) | n);
    }
    if word & 0xfff000f0 == 0xfb700000 {
        return Some(0x07800010 | (rd << 16) | (ra << 12) | (m << 8) | n);
    }
    let parallel = match word & 0xfff0f080 {
        0xfa90f000 => Some(0),
        0xfaa0f000 => Some(1),
        0xfae0f000 => Some(2),
        0xfad0f000 => Some(3),
        0xfa80f000 => Some(4),
        0xfac0f000 => Some(7),
        _ => None,
    };
    if let Some(op) = parallel {
        let kind = match (word >> 4) & 7 {
            0 => 1,
            4 => 5,
            1 => 2,
            2 => 3,
            5 => 6,
            6 => 7,
            _ => return None,
        };
        return Some(0x06000f10 | (kind << 20) | (op << 5) | (n << 16) | (rd << 12) | m);
    }
    let sat16 = word & 0xfff0f0f0;
    if matches!(sat16, 0xf3200000 | 0xf3a00000) {
        return Some(
            (if sat16 == 0xf3200000 {
                0x06a00f30
            } else {
                0x06e00f30
            }) | ((word & 15) << 16)
                | (rd << 12)
                | n,
        );
    }
    let sat = word & 0xffd08020;
    if matches!(sat, 0xf3000000 | 0xf3800000) {
        let shift = (((word >> 12) & 7) << 2) | ((word >> 6) & 3);
        return Some(
            (if sat == 0xf3000000 {
                0x06a00010
            } else {
                0x06e00010
            }) | ((word & 31) << 16)
                | (rd << 12)
                | (shift << 7)
                | (((word >> 21) & 1) << 6)
                | n,
        );
    }
    let regs = (rd << 16) | (ra << 12) | (m << 8) | n;
    let half = word & 0xfff000c0;
    if half == 0xfb100000 {
        let base = if ra == 15 {
            0x01600080 | (regs & !0xf000)
        } else {
            0x01000080 | regs
        };
        return Some(base | (((word >> 4) & 1) << 6) | (word & 0x20));
    }
    let longregs = (rd << 16) | (ra << 12) | (m << 8) | n;
    if half == 0xfbc00080 {
        return Some(0x01400080 | longregs | (((word >> 4) & 1) << 6) | (word & 0x20));
    }
    let class = word & 0xfff000e0;
    let flag = ((word >> 4) & 1) << 5;
    Some(match class {
        0xfb300000 => {
            (if ra == 15 {
                0x012000a0 | (regs & !0xf000)
            } else {
                0x01200080 | regs
            }) | (((word >> 4) & 1) << 6)
        }
        0xfb200000 => 0x07000010 | regs | flag,
        0xfb400000 => 0x07000050 | regs | flag,
        0xfb500000 => 0x07500010 | regs | flag,
        0xfb600000 => 0x075000d0 | regs | flag,
        0xfbc000c0 => 0x07400010 | longregs | flag,
        0xfbd000c0 => 0x07400050 | longregs | flag,
        _ => return None,
    })
}

fn dsp(word: u32, mut r: Recipe) -> Option<Recipe> {
    let rd = (word >> 12) & 15;
    let rn = (word >> 16) & 15;
    let rm = word & 15;
    if let Some(extra) = scalar_dsp(word, r.clone()) {
        return Some(extra);
    }
    let qop = word & 0x0f900ff0 == 0x01000050;
    if qop {
        if [rd, rn, rm].contains(&15) {
            return Some(unsupported(
                r,
                "DSP PC operand is constrained unpredictable",
            ));
        }
        let op = (word >> 21) & 3;
        let (right, sat1) = if op & 2 != 0 {
            sat_binary(g(rn), g(rn), true, false)
        } else {
            (g(rn), c(1, 0))
        };
        let (value, sat2) = sat_binary(g(rm), right, true, op & 1 != 0);
        wg(&mut r, rd, value);
        sticky(&mut r, b(B::Or, sat1, sat2), false);
        return Some(r);
    }
    let p = word & 0x0f800f10 == 0x06000f10;
    let kind = (word >> 20) & 7;
    let op = (word >> 5) & 7;
    if p && [1, 2, 3, 5, 6, 7].contains(&kind) && [0, 1, 2, 3, 4, 7].contains(&op) {
        if [rd, rn, rm].contains(&15) {
            return Some(unsupported(
                r,
                "parallel DSP PC operand is constrained unpredictable",
            ));
        }
        let width = if op >= 4 { 8 } else { 16 };
        let signed = kind & 4 == 0;
        let ge_flags = kind == 1 || kind == 5;
        let halving = kind == 3 || kind == 7;
        let mut result = c(32, 0);
        let mut ge = c(4, 0);
        for i in 0..32 / width {
            let other = if op == 1 || op == 2 { i ^ 1 } else { i };
            let sub = match op {
                1 => i == 0,
                2 => i == 1,
                3 | 7 => true,
                _ => false,
            };
            let a = ext(g(rn), i * width, width);
            let z = ext(g(rm), other * width, width);
            let value = if ge_flags {
                let wide = r.bind(b(
                    if sub { B::Sub } else { B::Add },
                    cast(a, 64, signed),
                    cast(z, 64, signed),
                ));
                let pass = if signed || sub {
                    not(b(B::Slt, wide.clone(), c(64, 0)))
                } else {
                    not(b(B::Ult, wide.clone(), c(64, 1u64 << width)))
                };
                let bits = if width == 16 {
                    sel(pass, c(4, 3), c(4, 0))
                } else {
                    cast(pass, 4, false)
                };
                ge = pack(ge, bits, i * width / 8);
                cast(wide, width, false)
            } else if halving {
                let wide = b(
                    if sub { B::Sub } else { B::Add },
                    cast(a, 64, signed),
                    cast(z, 64, signed),
                );
                cast(b(B::Asr, wide, c(64, 1)), width, false)
            } else {
                sat_binary(a, z, signed, sub).0
            };
            result = pack(result, value, i * width);
        }
        wg(&mut r, rd, result);
        if ge_flags {
            for bit in 0..4 {
                r.write(
                    register("a32.ge", bit, 1, 1),
                    WritePolicy::ZeroUpper,
                    ext(ge.clone(), bit as u8, 1),
                );
            }
        }
        return Some(r); // Saturating/halving forms preserve Q and GE.
    }
    let sat16 = matches!(word & 0x0ff00ff0, 0x06a00f30 | 0x06e00f30);
    let sat32 = matches!(word & 0x0fe00030, 0x06a00010 | 0x06e00010);
    if sat16 || sat32 {
        if rd == 15 || rm == 15 {
            return Some(unsupported(
                r,
                "saturation PC operand is constrained unpredictable",
            ));
        }
        let signed = word & 0x00400000 == 0;
        let bits = if sat16 {
            ((word >> 16) & 15) as u8
        } else {
            ((word >> 16) & 31) as u8
        } + u8::from(signed);
        let width = if sat16 { 16 } else { 32 };
        let amount = ((word >> 7) & 31) as u8;
        let asr = word & 0x40 != 0;
        let source = if sat16 {
            g(rm)
        } else {
            b(
                if asr { B::Asr } else { B::Shl },
                g(rm),
                c(32, u64::from(if asr && amount == 0 { 32 } else { amount })),
            )
        };
        let mut result = c(32, 0);
        let mut saturated = c(1, 0);
        for i in 0..32 / width {
            let (value, sat) = clamp(ext(source.clone(), i * width, width), true, bits, signed);
            result = pack(result, cast(value, width, signed), i * width);
            saturated = b(B::Or, saturated, sat);
        }
        wg(&mut r, rd, result);
        sticky(&mut r, saturated, false);
        return Some(r);
    }
    dsp_multiply(word, r)
}

// Packing, byte selection/extension, polynomial CRC and word multiply groups.
// Canonical fields are shared by the A32 and explicit T32 transforms above.
fn scalar_dsp(word: u32, mut r: Recipe) -> Option<Recipe> {
    let rd = (word >> 12) & 15;
    let rn = (word >> 16) & 15;
    let rm = word & 15;
    let crc = word & 0x0f900df0 == 0x01000040;
    if crc {
        let size = (word >> 21) & 3;
        if size == 3 || [rd, rn, rm].contains(&15) {
            return Some(unsupported(r, "reserved CRC width or PC operand"));
        }
        let width = 8u8 << size;
        let mut acc = r.bind(g(rn));
        let value = r.bind(ext(g(rm), 0, width));
        let polynomial = if word & 0x200 == 0 {
            0xedb88320
        } else {
            0x82f63b78
        };
        for bit in 0..width {
            let feedback = b(B::Xor, ext(acc.clone(), 0, 1), ext(value.clone(), bit, 1));
            acc = r.bind(b(
                B::Xor,
                b(B::Lsr, acc, c(32, 1)),
                sel(feedback, c(32, polynomial), c(32, 0)),
            ));
        }
        wg(&mut r, rd, acc);
        return Some(r);
    }
    let pkh = word & 0x0ff00030 == 0x06800010;
    let select = word & 0x0ff00ff0 == 0x06800fb0;
    let extend = matches!(word & 0x0ff003f0, 0x06800070 | 0x06c00070);
    if pkh || select || extend {
        if rd == 15 || rm == 15 || (!extend && rn == 15) {
            return Some(unsupported(r, "packing/selection PC operand"));
        }
        let result = if pkh {
            let top = word & 0x40 != 0;
            let amount = (word >> 7) & 31;
            let shifted = b(
                if top { B::Asr } else { B::Shl },
                g(rm),
                c(32, u64::from(if top && amount == 0 { 32 } else { amount })),
            );
            b(
                B::Or,
                b(B::And, g(rn), c(32, if top { 0xffff0000 } else { 0xffff })),
                b(
                    B::And,
                    shifted,
                    c(32, if top { 0xffff } else { 0xffff0000 }),
                ),
            )
        } else if select {
            let mut value = c(32, 0);
            for i in 0..4 {
                value = pack(
                    value,
                    sel(
                        Expr::register(register("a32.ge", u16::from(i), 1, 1)),
                        ext(g(rn), i * 8, 8),
                        ext(g(rm), i * 8, 8),
                    ),
                    i * 8,
                );
            }
            value
        } else {
            let rotate = ((word >> 10) & 3) * 8;
            let source = g(rm);
            let rotated = if rotate == 0 {
                source
            } else {
                b(
                    B::Or,
                    b(B::Lsr, source.clone(), c(32, u64::from(rotate))),
                    b(B::Shl, source, c(32, u64::from(32 - rotate))),
                )
            };
            let mut value = c(32, 0);
            for i in 0..2 {
                let lane = cast(ext(rotated.clone(), i * 16, 8), 16, word & 0x00400000 == 0);
                let lane = if rn == 15 {
                    lane
                } else {
                    b(B::Add, ext(g(rn), i * 16, 16), lane)
                };
                value = pack(value, lane, i * 16);
            }
            value
        };
        wg(&mut r, rd, result);
        return Some(r);
    }
    let mls = word & 0x0ff000f0 == 0x00600090;
    let umaal = word & 0x0ff000f0 == 0x00400090;
    let usad = word & 0x0ff000f0 == 0x07800010;
    if !mls && !umaal && !usad {
        return None;
    }
    let d = (word >> 16) & 15;
    let a = (word >> 12) & 15;
    let m = (word >> 8) & 15;
    let n = word & 15;
    if [d, n, m].contains(&15) || ((mls || umaal) && a == 15) || (umaal && d == a) {
        return Some(unsupported(r, "DSP multiply PC or overlapping outputs"));
    }
    let value = if usad {
        let mut sum = if a == 15 { c(32, 0) } else { g(a) };
        for lane in 0..4 {
            let left = cast(ext(g(n), lane * 8, 8), 32, false);
            let right = cast(ext(g(m), lane * 8, 8), 32, false);
            let difference = sel(
                b(B::Ult, left.clone(), right.clone()),
                b(B::Sub, right.clone(), left.clone()),
                b(B::Sub, left, right),
            );
            sum = b(B::Add, sum, difference);
        }
        sum
    } else if umaal {
        b(
            B::Add,
            b(
                B::Add,
                b(B::Mul, cast(g(n), 64, false), cast(g(m), 64, false)),
                cast(g(d), 64, false),
            ),
            cast(g(a), 64, false),
        )
    } else {
        b(B::Sub, g(a), b(B::Mul, g(n), g(m)))
    };
    let value = r.bind(value);
    if umaal {
        wg(&mut r, a, ext(value.clone(), 0, 32));
        wg(&mut r, d, ext(value, 32, 32));
    } else {
        wg(&mut r, d, value);
    }
    Some(r)
}

fn dsp_multiply(word: u32, mut r: Recipe) -> Option<Recipe> {
    let rd = (word >> 16) & 15;
    let ra = (word >> 12) & 15;
    let rm = (word >> 8) & 15;
    let rn = word & 15;
    let half = word & 0x0ff00090;
    let wordhalf = word & 0x0ff000b0;
    let dual = word & 0x0ff000d0;
    let (mode, accumulate, long, sub, flag) = if half == 0x01000080 {
        (0, true, false, false, true)
    } else if word & 0x0ff0f090 == 0x01600080 {
        (0, false, false, false, false)
    } else if half == 0x01400080 {
        (0, true, true, false, false)
    } else if wordhalf == 0x01200080 {
        (1, true, false, false, true)
    } else if word & 0x0ff0f0b0 == 0x012000a0 {
        (1, false, false, false, false)
    } else if matches!(dual, 0x07000010 | 0x07000050) {
        (
            2,
            ra != 15,
            false,
            dual == 0x07000050,
            dual == 0x07000010 || ra != 15,
        )
    } else if matches!(dual, 0x07400010 | 0x07400050) {
        (2, true, true, dual == 0x07400050, false)
    } else if matches!(dual, 0x07500010 | 0x075000d0) {
        (3, ra != 15, false, dual == 0x075000d0, false)
    } else {
        return None;
    };
    if [rd, rn, rm].contains(&15)
        || (long && (ra == 15 || ra == rd))
        || (mode == 3 && sub && ra == 15)
        || ((mode == 0 || mode == 1) && accumulate && ra == 15)
    {
        return Some(unsupported(
            r,
            "DSP multiply operand is constrained unpredictable",
        ));
    }
    let mut value = match mode {
        0 => b(
            B::Mul,
            cast(ext(g(rn), ((word >> 5) & 1) as u8 * 16, 16), 64, true),
            cast(ext(g(rm), ((word >> 6) & 1) as u8 * 16, 16), 64, true),
        ),
        1 => {
            let product = b(
                B::Mul,
                cast(g(rn), 64, true),
                cast(ext(g(rm), ((word >> 6) & 1) as u8 * 16, 16), 64, true),
            );
            b(B::Asr, product, c(64, 16))
        }
        2 => {
            let swap = ((word >> 5) & 1) as u8;
            let first = b(
                B::Mul,
                cast(ext(g(rn), 0, 16), 64, true),
                cast(ext(g(rm), swap * 16, 16), 64, true),
            );
            let second = b(
                B::Mul,
                cast(ext(g(rn), 16, 16), 64, true),
                cast(ext(g(rm), (swap ^ 1) * 16, 16), 64, true),
            );
            b(if sub { B::Sub } else { B::Add }, first, second)
        }
        _ => b(B::Mul, cast(g(rn), 64, true), cast(g(rm), 64, true)),
    };
    if accumulate {
        let accumulator = if long {
            pack(cast(g(ra), 64, false), g(rd), 32)
        } else if mode == 3 {
            b(B::Shl, cast(g(ra), 64, false), c(64, 32))
        } else {
            cast(g(ra), 64, true)
        };
        value = if mode == 3 && sub {
            b(B::Sub, accumulator, value)
        } else {
            b(B::Add, value, accumulator)
        };
    }
    if mode == 3 {
        if word & 0x20 != 0 {
            value = b(B::Add, value, c(64, 0x80000000));
        }
        value = b(B::Asr, value, c(64, 32));
    }
    let value = r.bind(value);
    if long {
        wg(&mut r, ra, ext(value.clone(), 0, 32));
        wg(&mut r, rd, ext(value, 32, 32));
    } else {
        let low = ext(value.clone(), 0, 32);
        wg(&mut r, rd, low.clone());
        if flag {
            sticky(&mut r, not(eq(value, cast(low, 64, true))), false);
        }
    }
    Some(r)
}

/// Extend an already predicated A32 recipe. Unrecognized encodings return None;
/// recognized constrained/undefined encodings return an explicit Unsupported.
pub fn a32(word: u32, base: Recipe) -> Option<Recipe> {
    if word & 0xfe000000 == 0xf2000000 {
        return neon(word, base);
    }
    if word >> 28 == 15 {
        return None;
    }
    if word & 0x0f900df0 == 0x01000040 && word >> 28 != 14 {
        return Some(unsupported(base, "A32 CRC condition must be AL"));
    }
    dsp(word, base)
}

/// Extend an already predicated Thumb recipe; wide words place the first
/// halfword at 31:16. Every accepted family preserves guard and always_writes.
pub fn thumb(word: u32, length: u8, base: Recipe) -> Option<Recipe> {
    if length != 4 {
        return None;
    }
    let saturation = word & 0xffd08020;
    if matches!(saturation, 0xf3000000 | 0xf3800000)
        && word & (1 << 21) != 0
        && word & 0x000070c0 == 0
        && word & 0x10 != 0
    {
        // ASR #0 selects SSAT16/USAT16. Their immediate has only four bits;
        // do not reinterpret its reserved high bit as scalar ASR #32.
        return Some(unsupported(
            base,
            "reserved Thumb halfword saturation encoding",
        ));
    }
    if word & 0xef000000 == 0xef000000 {
        let canonical = 0xf2000000 | (word & 0x00ffffff) | ((word >> 4) & 0x01000000);
        return neon(canonical, base);
    }
    let canonical = thumb_dsp(word)?;
    let mut base = base;
    if canonical & 0x0f900df0 == 0x01000040 {
        base.guard = Expr::select(
            Expr::require_context(
                eq(
                    b(
                        B::And,
                        Expr::register(register("a32.itstate", 0, 8, 8)),
                        c(8, 15),
                    ),
                    c(8, 0),
                ),
                "Thumb CRC instruction in IT block",
            ),
            base.guard,
            c(1, 0),
        );
    }
    dsp(canonical, base)
}

fn neon(word: u32, mut r: Recipe) -> Option<Recipe> {
    let dd = ((word >> 12) & 15) | ((word >> 18) & 16);
    let dn = ((word >> 16) & 15) | ((word >> 3) & 16);
    let dm = (word & 15) | ((word >> 1) & 16);
    let q = word & 0x40 != 0;
    let chunks = if q { 2 } else { 1 };
    let unsigned = word & 0x01000000 != 0;
    let bits = 8u8 << ((word >> 20) & 3);
    let satop = word & 0xfe800f10;
    if matches!(satop, 0xf2000010 | 0xf2000210) {
        if q && (dd | dn | dm) & 1 != 0 {
            return Some(unsupported(r, "odd D register in a SIMD Q operand"));
        }
        let mut saturated = c(1, 0);
        for chunk in 0..chunks {
            let mut result = c(64, 0);
            for i in 0..64 / bits {
                let (value, sat) = sat_binary(
                    lane(dn + chunk, i, bits),
                    lane(dm + chunk, i, bits),
                    !unsigned,
                    satop == 0xf2000210,
                );
                result = pack(result, value, i * bits);
                saturated = b(B::Or, saturated, sat);
            }
            wd(&mut r, dd + chunk, result);
        }
        sticky(&mut r, saturated, true);
        return Some(r);
    }
    // Integer multiply-accumulate and signed saturating doubling multiply high.
    let mulop = word & 0xfe800f10;
    if matches!(mulop, 0xf2000900 | 0xf2000b00) {
        let doubling = mulop == 0xf2000b00;
        if bits == 64 || (doubling && bits == 8) || (q && (dd | dn | dm) & 1 != 0) {
            return Some(unsupported(
                r,
                "invalid SIMD integer multiply size or Q operand",
            ));
        }
        let mut saturated = c(1, 0);
        for chunk in 0..chunks {
            let mut result = c(64, 0);
            for i in 0..64 / bits {
                let a = lane(dn + chunk, i, bits);
                let z = lane(dm + chunk, i, bits);
                let value = if doubling {
                    // (2*a*b + round) >> bits == (a*b + round/2) >> (bits-1).
                    // This avoids a 65-bit temporary for signed 32-bit lanes.
                    let mut product = b(B::Mul, cast(a, 64, true), cast(z, 64, true));
                    if unsigned {
                        product = b(B::Add, product, c(64, 1u64 << (bits - 2)));
                    }
                    let shifted = b(B::Asr, product, c(64, u64::from(bits - 1)));
                    let (value, sat) = clamp(shifted, true, bits, true);
                    saturated = b(B::Or, saturated, sat);
                    value
                } else {
                    let product = b(B::Mul, a, z);
                    let old = lane(dd + chunk, i, bits);
                    b(if unsigned { B::Sub } else { B::Add }, old, product)
                };
                result = pack(result, value, i * bits);
            }
            wd(&mut r, dd + chunk, result);
        }
        if doubling {
            sticky(&mut r, saturated, true);
        }
        return Some(r);
    }
    // Long add/sub, wide add/sub, multiply long and multiply accumulate long.
    let longop = word & 0xfe800f50;
    if bits != 64
        && matches!(
            longop,
            0xf2800000
                | 0xf2800100
                | 0xf2800200
                | 0xf2800300
                | 0xf2800800
                | 0xf2800a00
                | 0xf2800c00
        )
    {
        let wide = matches!(longop, 0xf2800100 | 0xf2800300);
        if dd & 1 != 0 || (wide && dn & 1 != 0) {
            return Some(unsupported(r, "invalid widening SIMD size or Q operand"));
        }
        let sub = matches!(longop, 0xf2800200 | 0xf2800300 | 0xf2800a00);
        let multiply = matches!(longop, 0xf2800800 | 0xf2800a00 | 0xf2800c00);
        let accumulate = matches!(longop, 0xf2800800 | 0xf2800a00);
        for chunk in 0..2 {
            let mut result = c(64, 0);
            for i in 0..64 / (bits * 2) {
                let index = i + (chunk as u8) * (64 / (bits * 2));
                let a = if wide {
                    lane(dn, index, bits * 2)
                } else {
                    cast(lane(dn, index, bits), bits * 2, !unsigned)
                };
                let z = cast(lane(dm, index, bits), bits * 2, !unsigned);
                let mut value = b(
                    if multiply {
                        B::Mul
                    } else if sub {
                        B::Sub
                    } else {
                        B::Add
                    },
                    a,
                    z,
                );
                if accumulate {
                    value = b(
                        if sub { B::Sub } else { B::Add },
                        lane(dd, index, bits * 2),
                        value,
                    );
                }
                result = pack(result, value, i * bits * 2);
            }
            wd(&mut r, dd + chunk, result);
        }
        return Some(r);
    }
    // VMOVN and the three signed/unsigned saturating narrowing variants.
    if word & 0xffb30f10 == 0xf3b20200 {
        let width = 8u8 << ((word >> 18) & 3);
        let op = (word >> 6) & 3;
        if width == 64 || dm & 1 != 0 {
            return Some(unsupported(r, "invalid narrowing SIMD size or Q source"));
        }
        let mut result = c(64, 0);
        let mut saturated = c(1, 0);
        for i in 0..64 / width {
            let source = lane(dm, i, width * 2);
            let value = if op == 0 {
                ext(source, 0, width)
            } else {
                let (v, sat) = clamp(source, op != 3, width, op & 1 == 0);
                saturated = b(B::Or, saturated, sat);
                v
            };
            result = pack(result, value, i * width);
        }
        wd(&mut r, dd, result);
        if op != 0 {
            sticky(&mut r, saturated, true);
        }
        return Some(r);
    }
    // VSHLL's maximum shift has a separate two-register miscellaneous encoding.
    if word & 0xffb30fd0 == 0xf3b20300 {
        let width = 8u8 << ((word >> 18) & 3);
        if width == 64 || dd & 1 != 0 {
            return Some(unsupported(
                r,
                "invalid maximum widening shift size or Q destination",
            ));
        }
        for chunk in 0..2 {
            let mut value = c(64, 0);
            for i in 0..64 / (width * 2) {
                let source = lane(dm, i + (chunk as u8) * (64 / (width * 2)), width);
                value = pack(
                    value,
                    b(
                        B::Shl,
                        cast(source, width * 2, false),
                        c(width * 2, u64::from(width)),
                    ),
                    i * width * 2,
                );
            }
            wd(&mut r, dd + chunk, value);
        }
        return Some(r);
    }
    if let Some(permutation) = neon_permute(word, r.clone(), dd, dm, q) {
        return Some(permutation);
    }
    neon_shift(word, r, dd, dn, dm, q)
}

fn neon_permute(word: u32, mut r: Recipe, dd: u32, dm: u32, q: bool) -> Option<Recipe> {
    let op = word & 0xffb30f90;
    if !matches!(
        op,
        0xf3b00000 | 0xf3b00080 | 0xf3b00100 | 0xf3b20080 | 0xf3b20100 | 0xf3b20180
    ) {
        return None;
    }
    let width = 8u8 << ((word >> 18) & 3);
    let chunks = if q { 2 } else { 1 };
    let reverse = matches!(op, 0xf3b00000 | 0xf3b00080 | 0xf3b00100);
    let container = match op {
        0xf3b00080 => 32,
        0xf3b00100 => 16,
        _ => 64,
    };
    if width == 64
        || (q && (dd | dm) & 1 != 0)
        || (reverse && width >= container)
        || (!reverse && op != 0xf3b20080 && !q && width == 32)
    {
        return Some(unsupported(r, "invalid SIMD permutation size or Q operand"));
    }
    if !reverse && dd == dm {
        for chunk in 0..chunks {
            wd(
                &mut r,
                dd + chunk,
                Expr::undefined(
                    64,
                    "SIMD permutation with identical operands is architecturally UNKNOWN",
                ),
            );
        }
        return Some(r);
    }
    let elements = (64 / width) * (chunks as u8);
    for output in 0..if reverse { 1 } else { 2 } {
        for chunk in 0..chunks {
            let mut result = c(64, 0);
            for i in 0..64 / width {
                let e = (chunk as u8) * (64 / width) + i;
                let value = if reverse {
                    let group = container / width;
                    let source = (e / group) * group + (group - 1 - e % group);
                    lane(dm, source, width)
                } else if op == 0xf3b20080 {
                    lane(
                        if e & 1 == 0 { dd } else { dm },
                        (e / 2) * 2 + output,
                        width,
                    )
                } else if op == 0xf3b20180 {
                    let zipped = e + output * elements;
                    lane(if zipped & 1 == 0 { dd } else { dm }, zipped / 2, width)
                } else {
                    let source = e * 2 + output;
                    lane(
                        if source < elements { dd } else { dm },
                        source % elements,
                        width,
                    )
                };
                result = pack(result, value, i * width);
            }
            wd(
                &mut r,
                if output == 0 { dd + chunk } else { dm + chunk },
                result,
            );
        }
    }
    Some(r)
}

// A rounded right shift is quotient plus the highest discarded bit. Unlike
// adding a rounding constant before shifting, this never loses a carry at 64b.
fn right_shift(value: Expr, amount: Expr, signed: bool, round: bool) -> Expr {
    let w = value.ty.width;
    let amount = cast(amount, w, false);
    let shifted = b(
        if signed { B::Asr } else { B::Lsr },
        value.clone(),
        amount.clone(),
    );
    if !round {
        return shifted;
    }
    let bit = ext(b(B::Lsr, value, b(B::Sub, amount.clone(), c(w, 1))), 0, 1);
    let valid = b(
        B::And,
        not(eq(amount.clone(), c(w, 0))),
        not(b(B::Ult, c(w, u64::from(w)), amount.clone())),
    );
    let result = b(B::Add, shifted, cast(sel(valid, bit, c(1, 0)), w, false));
    sel(
        b(B::Ult, c(w, u64::from(w)), cast(amount, w, false)),
        c(w, 0),
        result,
    )
}
fn left_shift_sat(value: Expr, amount: Expr, signed_in: bool, unsigned_out: bool) -> (Expr, Expr) {
    let w = value.ty.width;
    let amount = cast(amount, w, false);
    let shifted = b(B::Shl, value.clone(), amount.clone());
    let reversed = b(
        if signed_in && !unsigned_out {
            B::Asr
        } else {
            B::Lsr
        },
        shifted.clone(),
        amount.clone(),
    );
    let too_far = not(b(B::Ult, amount.clone(), c(w, u64::from(w))));
    let negative = if signed_in {
        ext(value.clone(), w - 1, 1)
    } else {
        c(1, 0)
    };
    let nonzero = not(eq(value.clone(), c(w, 0)));
    let lost = sel(too_far, nonzero, not(eq(value, reversed)));
    let saturated = if unsigned_out && signed_in {
        b(B::Or, lost, negative.clone())
    } else {
        lost
    };
    let bound = if unsigned_out {
        sel(negative, c(w, 0), c(w, mask(w)))
    } else {
        sel(negative, c(w, 1u64 << (w - 1)), c(w, mask(w - 1)))
    };
    (sel(saturated.clone(), bound, shifted), saturated)
}
fn neon_shift(word: u32, mut r: Recipe, dd: u32, dn: u32, dm: u32, q: bool) -> Option<Recipe> {
    let unsigned = word & 0x01000000 != 0;
    let register_op = word & 0xfe800f10;
    let register_shift = matches!(
        register_op,
        0xf2000400 | 0xf2000410 | 0xf2000500 | 0xf2000510
    );
    let immediate_op = word & 0xfe800f10;
    let immediate_shift = matches!(
        immediate_op,
        0xf2800010 | 0xf2800210 | 0xf2800510 | 0xf2800610 | 0xf2800710
    ) || (immediate_op == 0xf2800410 && unsigned);
    let insert = !register_shift && unsigned && matches!(immediate_op, 0xf2800410 | 0xf2800510);
    let narrow = word & 0xfe800e90 == 0xf2800810;
    let movl = word & 0xfe800fd0 == 0xf2800a10;
    if !register_shift && !immediate_shift && !narrow && !movl {
        return None;
    }
    let imm = ((word >> 16) & 63) | ((word >> 1) & 64);
    let size_imm = if narrow || movl {
        (word >> 16) & 63
    } else {
        imm
    };
    if !register_shift && size_imm < 8 {
        return None;
    } // Different encoding class.
    let bits = if register_shift {
        8u8 << ((word >> 20) & 3)
    } else {
        1u8 << (31 - size_imm.leading_zeros())
    };
    let chunks = if q { 2 } else { 1 };
    if (narrow && dm & 1 != 0)
        || (movl && (dd & 1 != 0 || bits == 64))
        || (!narrow && !movl && q && ((dd | dm) & 1 != 0 || (register_shift && dn & 1 != 0)))
    {
        return Some(unsupported(
            r,
            "invalid SIMD shift Q operand or element size",
        ));
    }
    if movl {
        // VSHLL with an immediate, including VMOVL's shift-zero aliases.
        let shift = size_imm - u32::from(bits);
        for chunk in 0..2 {
            let mut result = c(64, 0);
            for i in 0..64 / (bits * 2) {
                let e = i + (chunk as u8) * (64 / (bits * 2));
                let value = b(
                    B::Shl,
                    cast(lane(dm, e, bits), bits * 2, !unsigned),
                    c(bits * 2, u64::from(shift)),
                );
                result = pack(result, value, i * bits * 2);
            }
            wd(&mut r, dd + chunk, result);
        }
        return Some(r);
    }
    if narrow {
        let op = (word >> 8) & 1;
        let rounding = word & 0x40 != 0;
        let saturating = unsigned || op != 0;
        let signed_in = !(unsigned && op != 0);
        let signed_out = !unsigned;
        let amount = u32::from(bits) * 2 - size_imm;
        let mut result = c(64, 0);
        let mut saturated = c(1, 0);
        for i in 0..64 / bits {
            let source = lane(dm, i, bits * 2);
            let shifted = right_shift(
                source,
                c(8, u64::from(amount)),
                saturating && signed_in,
                rounding,
            );
            let value = if saturating {
                let (v, s) = clamp(shifted, signed_in, bits, signed_out);
                saturated = b(B::Or, saturated, s);
                v
            } else {
                ext(shifted, 0, bits)
            };
            result = pack(result, value, i * bits);
        }
        wd(&mut r, dd, result);
        if saturating {
            sticky(&mut r, saturated, true);
        }
        return Some(r);
    }
    let saturating = if register_shift {
        register_op & 0x10 != 0
    } else {
        matches!(immediate_op, 0xf2800610 | 0xf2800710)
    };
    let rounding = if register_shift {
        register_op & 0x100 != 0
    } else {
        immediate_op == 0xf2800210
    };
    let signed_in = if !register_shift && immediate_op == 0xf2800610 {
        true
    } else {
        !unsigned
    };
    if !register_shift && immediate_op == 0xf2800610 && !unsigned {
        return Some(unsupported(
            r,
            "reserved signed-to-signed immediate SIMD shift encoding",
        ));
    }
    let left = !register_shift && !matches!(immediate_op, 0xf2800010 | 0xf2800210 | 0xf2800410);
    let mut saturated = c(1, 0);
    for chunk in 0..chunks {
        let mut result = c(64, 0);
        for i in 0..64 / bits {
            let source = lane(dm + chunk, i, bits);
            let (value, sat) = if register_shift {
                let shift = cast(ext(lane(dn + chunk, i, bits), 0, 8), 16, true);
                let negative = b(B::Slt, shift.clone(), c(16, 0));
                let right = right_shift(
                    source.clone(),
                    b(B::Sub, c(16, 0), shift.clone()),
                    signed_in,
                    rounding,
                );
                let (left, sat) = if saturating {
                    left_shift_sat(source, shift, signed_in, unsigned)
                } else {
                    (b(B::Shl, source, cast(shift, bits, false)), c(1, 0))
                };
                (
                    sel(negative.clone(), right, left),
                    sel(negative, c(1, 0), sat),
                )
            } else {
                let amount = if left {
                    size_imm - u32::from(bits)
                } else {
                    2 * u32::from(bits) - size_imm
                };
                if insert {
                    let copied = if left {
                        mask(bits).checked_shl(amount).unwrap_or(0) & mask(bits)
                    } else {
                        mask(bits).checked_shr(amount).unwrap_or(0)
                    };
                    let value = b(
                        B::Or,
                        b(B::And, lane(dd + chunk, i, bits), c(bits, !copied)),
                        b(
                            if left { B::Shl } else { B::Lsr },
                            source,
                            c(bits, u64::from(amount)),
                        ),
                    );
                    (value, c(1, 0))
                } else if left && saturating {
                    left_shift_sat(source, c(8, u64::from(amount)), signed_in, unsigned)
                } else if left {
                    (b(B::Shl, source, c(bits, u64::from(amount))), c(1, 0))
                } else {
                    (
                        right_shift(source, c(8, u64::from(amount)), signed_in, rounding),
                        c(1, 0),
                    )
                }
            };
            result = pack(result, value, i * bits);
            saturated = b(B::Or, saturated, sat);
        }
        wd(&mut r, dd + chunk, result);
    }
    if saturating {
        sticky(&mut r, saturated, true);
    }
    Some(r)
}

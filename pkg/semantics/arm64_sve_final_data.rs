//! Complete SVE prefetch hints, paired polynomial accumulation and PSEL.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn p(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.predicate64", n as u16 * 4 + chunk, 64, 64))
}
fn nonstreaming() -> Expr {
    Expr::select(
        Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
        Expr::register(register("a64.sme_fa64", 0, 1, 1)),
        c(1, 1),
    )
}
const FORMS: &[(u32, u32, u8, bool)] = &[
    (0xffe0fc01, 0x4520fc00, 1, false), //pmlal_mz_zzzw_1x2
    (0xffe0e010, 0x8400e000, 0, true),  //prfb_i_p_ai_s
    (0xffe0e010, 0xc400e000, 0, true),  //prfb_i_p_ai_d
    (0xffc0e010, 0x85c00000, 0, false), //prfb_i_p_bi_s
    (0xffe0e010, 0x8400c000, 0, false), //prfb_i_p_br_s
    (0xffa0e010, 0x84200000, 0, true),  //prfb_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4200000, 0, true),  //prfb_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc4608000, 0, true),  //prfb_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8580e000, 0, true),  //prfd_i_p_ai_s
    (0xffe0e010, 0xc580e000, 0, true),  //prfd_i_p_ai_d
    (0xffc0e010, 0x85c06000, 0, false), //prfd_i_p_bi_s
    (0xffe0e010, 0x8580c000, 0, false), //prfd_i_p_br_s
    (0xffa0e010, 0x84206000, 0, true),  //prfd_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4206000, 0, true),  //prfd_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460e000, 0, true),  //prfd_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8480e000, 0, true),  //prfh_i_p_ai_s
    (0xffe0e010, 0xc480e000, 0, true),  //prfh_i_p_ai_d
    (0xffc0e010, 0x85c02000, 0, false), //prfh_i_p_bi_s
    (0xffe0e010, 0x8480c000, 0, false), //prfh_i_p_br_s
    (0xffa0e010, 0x84202000, 0, true),  //prfh_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4202000, 0, true),  //prfh_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460a000, 0, true),  //prfh_i_p_bz_d_64_scaled
    (0xffe0e010, 0x8500e000, 0, true),  //prfw_i_p_ai_s
    (0xffe0e010, 0xc500e000, 0, true),  //prfw_i_p_ai_d
    (0xffc0e010, 0x85c04000, 0, false), //prfw_i_p_bi_s
    (0xffe0e010, 0x8500c000, 0, false), //prfw_i_p_br_s
    (0xffa0e010, 0x84204000, 0, true),  //prfw_i_p_bz_s_x32_scaled
    (0xffa0e010, 0xc4204000, 0, true),  //prfw_i_p_bz_d_x32_scaled
    (0xffe0e010, 0xc460c000, 0, true),  //prfw_i_p_bz_d_64_scaled
    (0xff20c210, 0x25204000, 2, false), //psel_p_ppi_
];
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind, restricted) = FORMS
        .iter()
        .find(|(mask, value, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    let mut r = Recipe::new(next, 64);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    if kind == 0
        && matches!(
            word & 0xffe0e010,
            0x8400c000 | 0x8480c000 | 0x8500c000 | 0x8580c000
        )
        && (word >> 16) & 31 == 31
    {
        return Some(Recipe::unsupported("reserved SVE prefetch Rm=31", next, 64));
    }
    if kind == 0 {
        // Hint_Prefetch explicitly permits every hint to be treated as NOP and
        // forbids synchronous alignment/translation aborts or Device accesses.
        // Select that architectural behavior, retaining mandatory access admission.
        if restricted {
            r.guard = Expr::require_context(
                nonstreaming(),
                "SVE vector prefetch needs non-streaming mode or effective FA64",
            );
        }
        return Some(r);
    }
    if kind == 1 {
        r.guard = Expr::require_context(
            Expr::select(
                Expr::register(register("a64.ssve_aes", 0, 1, 1)),
                c(1, 1),
                nonstreaming(),
            ),
            "SVE polynomial accumulation needs SSVE_AES or non-streaming access",
        );
        let (d, n, m) = (word & 30, (word >> 5) & 31, (word >> 16) & 31);
        let mut outputs = vec![];
        for segment in 0..vl / 128 {
            for half in 0..2 {
                let (low, high) = arm64_crypto::polynomial(
                    &mut r,
                    z(n, segment * 2 + half),
                    z(m, segment * 2 + half),
                    64,
                );
                outputs.push((
                    d + u32::from(half),
                    segment * 2,
                    b(B::Xor, z(d + u32::from(half), segment * 2), low),
                ));
                outputs.push((
                    d + u32::from(half),
                    segment * 2 + 1,
                    b(B::Xor, z(d + u32::from(half), segment * 2 + 1), high?),
                ));
            }
        }
        for (n, chunk, value) in outputs {
            let value = r.bind(value);
            r.write(
                register("a64.vector64", n as u16 * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                value,
            );
        }
        for n in [d, d + 1] {
            for chunk in vl / 64..32 {
                r.write(
                    register("a64.vector64", n as u16 * 32 + chunk, 64, 64),
                    WritePolicy::ZeroUpper,
                    c(64, 0),
                );
            }
        }
        return Some(r);
    }
    let tsz = ((word >> 19) & 8) | ((word >> 18) & 7);
    if tsz == 0 {
        return Some(Recipe::unsupported(
            "reserved PSEL zero size selector",
            next,
            64,
        ));
    }
    let size = tsz.trailing_zeros();
    let width = 8u16 << size;
    let imm = (((word >> 23) & 1) << 4 | tsz) >> (size + 1);
    let (d, n, m) = (word & 15, (word >> 10) & 15, (word >> 5) & 15);
    let idx = Expr::cast(
        Expr::register(register("a64.gpr", 12 + ((word >> 16) & 3) as u16, 32, 64)),
        64,
        false,
    );
    let bit = r.bind(b(
        B::Mul,
        b(
            B::Urem,
            b(B::Add, idx, c(64, u64::from(imm))),
            c(64, u64::from(vl / width)),
        ),
        c(64, u64::from(width / 8)),
    ));
    let chunk = r.bind(b(B::Lsr, bit.clone(), c(64, 6)));
    let mut source = c(64, 0);
    for i in (0..(vl / 8).div_ceil(64)).rev() {
        source = Expr::select(
            b(B::Eq, chunk.clone(), c(64, u64::from(i))),
            p(m, i),
            source,
        );
    }
    let selected = r.bind(Expr::extract(
        b(B::Lsr, source, b(B::And, bit, c(64, 63))),
        0,
        1,
    ));
    for chunk in 0..4 {
        let value = if chunk * 64 < vl / 8 {
            let bits = (vl / 8 - chunk * 64).min(64) as u8;
            Expr::select(
                selected.clone(),
                b(B::And, p(n, chunk), c(64, mask(bits))),
                c(64, 0),
            )
        } else {
            c(64, 0)
        };
        let value = r.bind(value);
        r.write(
            register("a64.predicate64", d as u16 * 4 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(r)
}

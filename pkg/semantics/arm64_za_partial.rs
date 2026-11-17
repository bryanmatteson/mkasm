//! Complete non-FP8 MOP4 and TMOP outer-product category (June 2026).
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
// Physical diagram, accumulator/source width, product count, number kind,
// selective layout, source signedness, subtraction. No mnemonic inference.
const FORMS: &[(u32, u32, u8, u8, u8, u8, bool, bool, bool, bool)] = &[
    (
        0xfff1fe3c, 0x81100000, 32, 16, 2, 2, false, false, false, false,
    ), // bfmop4a_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81000000, 32, 16, 2, 2, false, false, false, false,
    ), // bfmop4a_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81000200, 32, 16, 2, 2, false, false, false, false,
    ), // bfmop4a_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81100200, 32, 16, 2, 2, false, false, false, false,
    ), // bfmop4a_za32_zz_h2x2
    (
        0xfff1fe3e, 0x81300008, 16, 16, 1, 2, false, false, false, false,
    ), // bfmop4a_za_zz_h1x2
    (
        0xfff1fe3e, 0x81200008, 16, 16, 1, 2, false, false, false, false,
    ), // bfmop4a_za_zz_h1x1
    (
        0xfff1fe3e, 0x81200208, 16, 16, 1, 2, false, false, false, false,
    ), // bfmop4a_za_zz_h2x1
    (
        0xfff1fe3e, 0x81300208, 16, 16, 1, 2, false, false, false, false,
    ), // bfmop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x81100010, 32, 16, 2, 2, false, false, false, true,
    ), // bfmop4s_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81000010, 32, 16, 2, 2, false, false, false, true,
    ), // bfmop4s_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81000210, 32, 16, 2, 2, false, false, false, true,
    ), // bfmop4s_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81100210, 32, 16, 2, 2, false, false, false, true,
    ), // bfmop4s_za32_zz_h2x2
    (
        0xfff1fe3e, 0x81300018, 16, 16, 1, 2, false, false, false, true,
    ), // bfmop4s_za_zz_h1x2
    (
        0xfff1fe3e, 0x81200018, 16, 16, 1, 2, false, false, false, true,
    ), // bfmop4s_za_zz_h1x1
    (
        0xfff1fe3e, 0x81200218, 16, 16, 1, 2, false, false, false, true,
    ), // bfmop4s_za_zz_h2x1
    (
        0xfff1fe3e, 0x81300218, 16, 16, 1, 2, false, false, false, true,
    ), // bfmop4s_za_zz_h2x2
    (
        0xffe0e00c, 0x81400000, 32, 16, 2, 2, true, false, false, false,
    ), // bftmopa_za32_zzzi_h2x1
    (
        0xffe0e00e, 0x81600008, 16, 16, 1, 2, true, false, false, false,
    ), // bftmopa_za_zzzi_h2x1
    (
        0xfff1fe3c, 0x81300000, 32, 16, 2, 1, false, false, false, false,
    ), // fmop4a_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81200000, 32, 16, 2, 1, false, false, false, false,
    ), // fmop4a_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81200200, 32, 16, 2, 1, false, false, false, false,
    ), // fmop4a_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81300200, 32, 16, 2, 1, false, false, false, false,
    ), // fmop4a_za32_zz_h2x2
    (
        0xfff1fe3e, 0x81100008, 16, 16, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_h1x2
    (
        0xfff1fe3e, 0x81000008, 16, 16, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_h1x1
    (
        0xfff1fe3e, 0x81000208, 16, 16, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_h2x1
    (
        0xfff1fe3e, 0x81100208, 16, 16, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x80100000, 32, 32, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_s1x2
    (
        0xfff1fe3c, 0x80000000, 32, 32, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_s1x1
    (
        0xfff1fe3c, 0x80000200, 32, 32, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_s2x1
    (
        0xfff1fe3c, 0x80100200, 32, 32, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_s2x2
    (
        0xfff1fe38, 0x80d00008, 64, 64, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_d1x2
    (
        0xfff1fe38, 0x80c00008, 64, 64, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_d1x1
    (
        0xfff1fe38, 0x80c00208, 64, 64, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_d2x1
    (
        0xfff1fe38, 0x80d00208, 64, 64, 1, 1, false, false, false, false,
    ), // fmop4a_za_zz_d2x2
    (
        0xfff1fe3c, 0x81300010, 32, 16, 2, 1, false, false, false, true,
    ), // fmop4s_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81200010, 32, 16, 2, 1, false, false, false, true,
    ), // fmop4s_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81200210, 32, 16, 2, 1, false, false, false, true,
    ), // fmop4s_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81300210, 32, 16, 2, 1, false, false, false, true,
    ), // fmop4s_za32_zz_h2x2
    (
        0xfff1fe3e, 0x81100018, 16, 16, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_h1x2
    (
        0xfff1fe3e, 0x81000018, 16, 16, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_h1x1
    (
        0xfff1fe3e, 0x81000218, 16, 16, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_h2x1
    (
        0xfff1fe3e, 0x81100218, 16, 16, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_h2x2
    (
        0xfff1fe3c, 0x80100010, 32, 32, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_s1x2
    (
        0xfff1fe3c, 0x80000010, 32, 32, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_s1x1
    (
        0xfff1fe3c, 0x80000210, 32, 32, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_s2x1
    (
        0xfff1fe3c, 0x80100210, 32, 32, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_s2x2
    (
        0xfff1fe38, 0x80d00018, 64, 64, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_d1x2
    (
        0xfff1fe38, 0x80c00018, 64, 64, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_d1x1
    (
        0xfff1fe38, 0x80c00218, 64, 64, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_d2x1
    (
        0xfff1fe38, 0x80d00218, 64, 64, 1, 1, false, false, false, true,
    ), // fmop4s_za_zz_d2x2
    (
        0xffe0e00c, 0x81600000, 32, 16, 2, 1, true, false, false, false,
    ), // ftmopa_za32_zzzi_h2x1
    (
        0xffe0e00e, 0x81400008, 16, 16, 1, 1, true, false, false, false,
    ), // ftmopa_za_zzzi_h2x1
    (
        0xffe0e00c, 0x80400000, 32, 32, 1, 1, true, false, false, false,
    ), // ftmopa_za_zzzi_s2x1
    (
        0xfff1fe3c, 0x80108008, 32, 16, 2, 0, false, false, false, false,
    ), // smop4a_za32_zz_h1x2
    (
        0xfff1fe3c, 0x80008008, 32, 16, 2, 0, false, false, false, false,
    ), // smop4a_za32_zz_h1x1
    (
        0xfff1fe3c, 0x80008208, 32, 16, 2, 0, false, false, false, false,
    ), // smop4a_za32_zz_h2x1
    (
        0xfff1fe3c, 0x80108208, 32, 16, 2, 0, false, false, false, false,
    ), // smop4a_za32_zz_h2x2
    (
        0xfff1fe3c, 0x80108000, 32, 8, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_b1x2
    (
        0xfff1fe3c, 0x80008000, 32, 8, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_b1x1
    (
        0xfff1fe3c, 0x80008200, 32, 8, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_b2x1
    (
        0xfff1fe3c, 0x80108200, 32, 8, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_b2x2
    (
        0xfff1fe38, 0xa0d00008, 64, 16, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_h1x2
    (
        0xfff1fe38, 0xa0c00008, 64, 16, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_h1x1
    (
        0xfff1fe38, 0xa0c00208, 64, 16, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_h2x1
    (
        0xfff1fe38, 0xa0d00208, 64, 16, 4, 0, false, false, false, false,
    ), // smop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x80108018, 32, 16, 2, 0, false, false, false, true,
    ), // smop4s_za32_zz_h1x2
    (
        0xfff1fe3c, 0x80008018, 32, 16, 2, 0, false, false, false, true,
    ), // smop4s_za32_zz_h1x1
    (
        0xfff1fe3c, 0x80008218, 32, 16, 2, 0, false, false, false, true,
    ), // smop4s_za32_zz_h2x1
    (
        0xfff1fe3c, 0x80108218, 32, 16, 2, 0, false, false, false, true,
    ), // smop4s_za32_zz_h2x2
    (
        0xfff1fe3c, 0x80108010, 32, 8, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_b1x2
    (
        0xfff1fe3c, 0x80008010, 32, 8, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_b1x1
    (
        0xfff1fe3c, 0x80008210, 32, 8, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_b2x1
    (
        0xfff1fe3c, 0x80108210, 32, 8, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_b2x2
    (
        0xfff1fe38, 0xa0d00018, 64, 16, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_h1x2
    (
        0xfff1fe38, 0xa0c00018, 64, 16, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_h1x1
    (
        0xfff1fe38, 0xa0c00218, 64, 16, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_h2x1
    (
        0xfff1fe38, 0xa0d00218, 64, 16, 4, 0, false, false, false, true,
    ), // smop4s_za_zz_h2x2
    (
        0xffe0e00c, 0x80408008, 32, 16, 2, 0, true, false, false, false,
    ), // stmopa_za32_zzzi_h2x1
    (
        0xffe0e00c, 0x80408000, 32, 8, 4, 0, true, false, false, false,
    ), // stmopa_za_zzzi_b2x1
    (
        0xfff1fe3c, 0x80308000, 32, 8, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_b1x2
    (
        0xfff1fe3c, 0x80208000, 32, 8, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_b1x1
    (
        0xfff1fe3c, 0x80208200, 32, 8, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_b2x1
    (
        0xfff1fe3c, 0x80308200, 32, 8, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_b2x2
    (
        0xfff1fe38, 0xa0f00008, 64, 16, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_h1x2
    (
        0xfff1fe38, 0xa0e00008, 64, 16, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_h1x1
    (
        0xfff1fe38, 0xa0e00208, 64, 16, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_h2x1
    (
        0xfff1fe38, 0xa0f00208, 64, 16, 4, 0, false, false, true, false,
    ), // sumop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x80308010, 32, 8, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_b1x2
    (
        0xfff1fe3c, 0x80208010, 32, 8, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_b1x1
    (
        0xfff1fe3c, 0x80208210, 32, 8, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_b2x1
    (
        0xfff1fe3c, 0x80308210, 32, 8, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_b2x2
    (
        0xfff1fe38, 0xa0f00018, 64, 16, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_h1x2
    (
        0xfff1fe38, 0xa0e00018, 64, 16, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_h1x1
    (
        0xfff1fe38, 0xa0e00218, 64, 16, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_h2x1
    (
        0xfff1fe38, 0xa0f00218, 64, 16, 4, 0, false, false, true, true,
    ), // sumop4s_za_zz_h2x2
    (
        0xffe0e00c, 0x80608000, 32, 8, 4, 0, true, false, true, false,
    ), // sutmopa_za_zzzi_b2x1
    (
        0xfff1fe3c, 0x81108008, 32, 16, 2, 0, false, true, true, false,
    ), // umop4a_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81008008, 32, 16, 2, 0, false, true, true, false,
    ), // umop4a_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81008208, 32, 16, 2, 0, false, true, true, false,
    ), // umop4a_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81108208, 32, 16, 2, 0, false, true, true, false,
    ), // umop4a_za32_zz_h2x2
    (
        0xfff1fe3c, 0x81308000, 32, 8, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_b1x2
    (
        0xfff1fe3c, 0x81208000, 32, 8, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_b1x1
    (
        0xfff1fe3c, 0x81208200, 32, 8, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_b2x1
    (
        0xfff1fe3c, 0x81308200, 32, 8, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_b2x2
    (
        0xfff1fe38, 0xa1f00008, 64, 16, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_h1x2
    (
        0xfff1fe38, 0xa1e00008, 64, 16, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_h1x1
    (
        0xfff1fe38, 0xa1e00208, 64, 16, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_h2x1
    (
        0xfff1fe38, 0xa1f00208, 64, 16, 4, 0, false, true, true, false,
    ), // umop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x81108018, 32, 16, 2, 0, false, true, true, true,
    ), // umop4s_za32_zz_h1x2
    (
        0xfff1fe3c, 0x81008018, 32, 16, 2, 0, false, true, true, true,
    ), // umop4s_za32_zz_h1x1
    (
        0xfff1fe3c, 0x81008218, 32, 16, 2, 0, false, true, true, true,
    ), // umop4s_za32_zz_h2x1
    (
        0xfff1fe3c, 0x81108218, 32, 16, 2, 0, false, true, true, true,
    ), // umop4s_za32_zz_h2x2
    (0xfff1fe3c, 0x81308010, 32, 8, 4, 0, false, true, true, true), // umop4s_za_zz_b1x2
    (0xfff1fe3c, 0x81208010, 32, 8, 4, 0, false, true, true, true), // umop4s_za_zz_b1x1
    (0xfff1fe3c, 0x81208210, 32, 8, 4, 0, false, true, true, true), // umop4s_za_zz_b2x1
    (0xfff1fe3c, 0x81308210, 32, 8, 4, 0, false, true, true, true), // umop4s_za_zz_b2x2
    (
        0xfff1fe38, 0xa1f00018, 64, 16, 4, 0, false, true, true, true,
    ), // umop4s_za_zz_h1x2
    (
        0xfff1fe38, 0xa1e00018, 64, 16, 4, 0, false, true, true, true,
    ), // umop4s_za_zz_h1x1
    (
        0xfff1fe38, 0xa1e00218, 64, 16, 4, 0, false, true, true, true,
    ), // umop4s_za_zz_h2x1
    (
        0xfff1fe38, 0xa1f00218, 64, 16, 4, 0, false, true, true, true,
    ), // umop4s_za_zz_h2x2
    (
        0xfff1fe3c, 0x81108000, 32, 8, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_b1x2
    (
        0xfff1fe3c, 0x81008000, 32, 8, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_b1x1
    (
        0xfff1fe3c, 0x81008200, 32, 8, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_b2x1
    (
        0xfff1fe3c, 0x81108200, 32, 8, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_b2x2
    (
        0xfff1fe38, 0xa1d00008, 64, 16, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_h1x2
    (
        0xfff1fe38, 0xa1c00008, 64, 16, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_h1x1
    (
        0xfff1fe38, 0xa1c00208, 64, 16, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_h2x1
    (
        0xfff1fe38, 0xa1d00208, 64, 16, 4, 0, false, true, false, false,
    ), // usmop4a_za_zz_h2x2
    (
        0xfff1fe3c, 0x81108010, 32, 8, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_b1x2
    (
        0xfff1fe3c, 0x81008010, 32, 8, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_b1x1
    (
        0xfff1fe3c, 0x81008210, 32, 8, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_b2x1
    (
        0xfff1fe3c, 0x81108210, 32, 8, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_b2x2
    (
        0xfff1fe38, 0xa1d00018, 64, 16, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_h1x2
    (
        0xfff1fe38, 0xa1c00018, 64, 16, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_h1x1
    (
        0xfff1fe38, 0xa1c00218, 64, 16, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_h2x1
    (
        0xfff1fe38, 0xa1d00218, 64, 16, 4, 0, false, true, false, true,
    ), // usmop4s_za_zz_h2x2
    (
        0xffe0e00c, 0x81408000, 32, 8, 4, 0, true, true, false, false,
    ), // ustmopa_za_zzzi_b2x1
    (
        0xffe0e00c, 0x81408008, 32, 16, 2, 0, true, true, true, false,
    ), // utmopa_za32_zzzi_h2x1
    (0xffe0e00c, 0x81608000, 32, 8, 4, 0, true, true, true, false), // utmopa_za_zzzi_b2x1
];
fn part(bank: &'static str, base: u16, bit: u16, width: u8) -> Expr {
    let mut v = register(bank, base + bit / 64, width, 64);
    v.offset = (bit % 64) as u8;
    Expr::register(v)
}
fn z(n: u32, e: u16, w: u8) -> Expr {
    part("a64.vector64", n as u16 * 32, e * u16::from(w), w)
}
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let &(_, _, w, sw, ways, kind, selective, u1, u2, subtract) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _, _, _, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid partial/selective outer-product SVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
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
        "partial/selective outer product requires streaming and ZA enabled",
    );
    let control = if kind != 0 {
        Some(r.bind(Expr::register(register("a64.fpcr", 0, 32, 32))))
    } else {
        None
    };
    let dim = svl / u16::from(w);
    let tile = (word & u32::from(w / 8 - 1)) as u16;
    let n = (word >> 5) & if selective { 30 } else { 14 };
    let m = if selective {
        (word >> 16) & 31
    } else {
        16 + ((word >> 16) & 14)
    };
    let nreg = 1 + ((word >> 9) & 1);
    let mreg = 1 + ((word >> 20) & 1);
    let k = 20 + ((word >> 12) & 1) * 8 + ((word >> 10) & 3);
    let csize = dim * u16::from(ways) * 2;
    let control_start = ((word >> 4) & 3) as u16 * csize;
    // Column control bits select the same source slots in every matrix row.
    // Capture that selection once, then capture each demanded source element
    // once per row. Unselected data remains lazy, and the native SSA program
    // grows with cells rather than cells times the selection algorithm.
    let mut placements = Vec::new();
    let mut selected_sources = Vec::new();
    if selective {
        let split = ways == 4;
        let limit = if split { 2 } else { ways };
        let mut uses = vec![c(1, 0); usize::from(ways) * 2];
        for col in 0..dim {
            let mut slots = vec![vec![c(1, 0); usize::from(ways) * 2]; usize::from(ways)];
            let mut count = c(8, 0);
            for member in 0..2u16 {
                if split {
                    count = c(8, 0);
                }
                for e in 0..u16::from(ways) {
                    let selected = part(
                        "a64.vector64",
                        k as u16 * 32,
                        control_start + col * u16::from(ways) * 2 + member * u16::from(ways) + e,
                        1,
                    );
                    let take = r.bind(Expr::select(
                        b(B::Ult, count.clone(), c(8, u64::from(limit))),
                        selected,
                        c(1, 0),
                    ));
                    let source = usize::from(member * u16::from(ways) + e);
                    uses[source] = b(B::Or, uses[source].clone(), take.clone());
                    for slot in 0..limit {
                        let at = usize::from(if split {
                            member * 2 + u16::from(slot)
                        } else {
                            u16::from(slot)
                        });
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
        }
        let uses = uses.into_iter().map(|v| r.bind(v)).collect::<Vec<_>>();
        for row in 0..dim {
            let mut sources = Vec::new();
            for member in 0..2u16 {
                for e in 0..u16::from(ways) {
                    sources.push(r.bind(Expr::select(
                        uses[usize::from(member * u16::from(ways) + e)].clone(),
                        z(n + u32::from(member), row * u16::from(ways) + e, sw),
                        c(sw, 0),
                    )));
                }
            }
            selected_sources.push(sources);
        }
    }
    for row in 0..dim {
        let physical = row * u16::from(w) / 8 + tile;
        for chunk in 0..svl / 64 {
            let old = r.bind(part("a64.za64", physical * 32, chunk * 64, 64));
            let mut out = c(64, 0);
            for sub in 0..64 / u16::from(w) {
                let col = chunk * (64 / u16::from(w)) + sub;
                let acc = Expr::extract(old.clone(), (sub * u16::from(w)) as u8, w);
                let nr = n + if selective {
                    0
                } else {
                    (nreg - 1) * u32::from(col / (dim / 2))
                };
                let mr = m + if selective {
                    0
                } else {
                    (mreg - 1) * u32::from(row / (dim / 2))
                };
                let mut left = vec![c(sw, 0); usize::from(ways)];
                if selective {
                    for slot in 0..usize::from(ways) {
                        let mut value = c(sw, 0);
                        for source in 0..usize::from(ways) * 2 {
                            value = Expr::select(
                                placements[col as usize][slot][source].clone(),
                                selected_sources[row as usize][source].clone(),
                                value,
                            );
                        }
                        left[slot] = r.bind(value);
                    }
                } else {
                    for i in 0..u16::from(ways) {
                        left[usize::from(i)] = z(nr, row * u16::from(ways) + i, sw);
                    }
                }
                let right = (0..u16::from(ways))
                    .map(|i| z(mr, col * u16::from(ways) + i, sw))
                    .collect::<Vec<_>>();
                let value = if kind == 0 {
                    let mut sum = acc;
                    for i in 0..usize::from(ways) {
                        let product = b(
                            B::Mul,
                            Expr::cast(left[i].clone(), w, !u1),
                            Expr::cast(right[i].clone(), w, !u2),
                        );
                        sum = b(if subtract { B::Sub } else { B::Add }, sum, product);
                    }
                    r.bind(sum)
                } else {
                    if subtract {
                        for source in &mut left {
                            *source = b(B::Xor, source.clone(), c(sw, 1u64 << (sw - 1)));
                        }
                    }
                    let mut inputs = vec![acc];
                    inputs.extend(left);
                    inputs.extend(right);
                    r.bind(Expr::float(FloatExpression {
                        operation: if ways == 2 {
                            if kind == 2 {
                                FloatOperation::BFloatDotAdd
                            } else {
                                FloatOperation::ZaHalfDot
                            }
                        } else {
                            FloatOperation::ZaFused { bfloat: kind == 2 }
                        },
                        environment: FloatEnvironment::A64,
                        width: w,
                        inputs,
                        control: Box::new(control.as_ref().unwrap().clone()),
                        status: Box::new(c(32, 0)),
                        projection: FloatProjection::Value,
                    }))
                };
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(value, 64, false),
                        c(64, u64::from(sub) * u64::from(w)),
                    ),
                );
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

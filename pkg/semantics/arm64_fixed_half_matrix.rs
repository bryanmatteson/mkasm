//! Fixed-width FP16 dot products and FP16/FP32 matrix multiply-add.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8)] = &[
    (0xbfc0f400, 0x0f409000, 0), //FDOT_asimdelem_FP16FP32
    (0xbfe0fc00, 0x0e80fc00, 1), //FDOT_asimdsame2_FP16FP32
    (0xffe0fc00, 0x4ec0ec00, 2), //FMMLA_asimd_FP16FP16
    (0xffe0fc00, 0x4e40ec00, 3), //FMMLA_asimd_FP16FP32
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn dot(r: &mut Recipe, fp: &mut FloatState, n: u32, m: u32, a: u16, b: u16) -> Expr {
    fp.step(
        r,
        FloatOperation::HalfDotProduct,
        32,
        vec![
            lane(n, a, 16),
            lane(n, a + 1, 16),
            lane(m, b, 16),
            lane(m, b + 1, 16),
        ],
        c(1, 1),
        c(32, 0),
        true,
    )
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind) = FORMS
        .iter()
        .find(|(mask, value, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "invalid fixed half matrix CurrentVL",
            next,
            64,
        ));
    }
    let mut r = Recipe::new(next, 64);
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    r.guard = Expr::require_context(
        Expr::select(
            sm,
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            c(1, 1),
        ),
        "AdvSIMD FP16 matrix streaming requires FA64",
    );
    let mut fp = FloatState::new(&mut r);
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let d = word & 31;
    let index = (((word >> 11) & 1) * 2 + ((word >> 21) & 1)) as u16;
    let w = if kind == 2 { 16 } else { 32 };
    let size = if kind <= 1 && word & (1 << 30) == 0 {
        64
    } else {
        128
    };
    let mut values = Vec::new();
    for e in 0..size / u16::from(w) {
        let old = lane(d, e, w);
        let product = if kind <= 1 {
            dot(
                &mut r,
                &mut fp,
                n,
                m,
                2 * e,
                if kind == 0 { 2 * index } else { 2 * e },
            )
        } else {
            let segment = if kind == 2 { e / 4 * 4 } else { 0 };
            let row = (e % 4) / 2;
            let col = e % 2;
            let stride = if kind == 2 { 2 } else { 4 };
            let a = segment + row * stride;
            let b = segment + col * stride;
            let (p0, p1) = if kind == 2 {
                let p0 = fp.step(
                    &mut r,
                    FloatOperation::Multiply,
                    16,
                    vec![lane(n, a, 16), lane(m, b, 16)],
                    c(1, 1),
                    c(16, 0),
                    true,
                );
                let p1 = fp.step(
                    &mut r,
                    FloatOperation::Multiply,
                    16,
                    vec![lane(n, a + 1, 16), lane(m, b + 1, 16)],
                    c(1, 1),
                    c(16, 0),
                    true,
                );
                (p0, p1)
            } else {
                let p0 = dot(&mut r, &mut fp, n, m, a, b);
                let p1 = dot(&mut r, &mut fp, n, m, a + 2, b + 2);
                (p0, p1)
            };
            fp.step(
                &mut r,
                FloatOperation::Add,
                w,
                vec![p0, p1],
                c(1, 1),
                c(w, 0),
                true,
            )
        };
        let result = fp.step(
            &mut r,
            FloatOperation::Add,
            w,
            vec![old, product],
            c(1, 1),
            c(w, 0),
            true,
        );
        values.push(result);
    }
    fp.finish(&mut r);
    for chunk in 0..vl / 64 {
        let mut out = c(64, 0);
        for part in 0..64 / u16::from(w) {
            let e = chunk * (64 / u16::from(w)) + part;
            if let Some(value) = values.get(usize::from(e)) {
                out = b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(value.clone(), 64, false),
                        c(64, u64::from(part * u16::from(w))),
                    ),
                );
            }
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
    Some(r)
}

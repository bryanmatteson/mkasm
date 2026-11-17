//! All non-FP8 SVE floating matrix multiply-add encodings.
use super::*;
use arm64_sve::FloatState;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
const FORMS: &[(u32, u32, u8, u8)] = &[
    (0xffe0fc00, 0x64e0e000, 0, 16), // bfmmla_z_zzz_h
    (0xffe0fc00, 0x6460e400, 1, 32), // bfmmla_z_zzz_
    (0xffe0fc00, 0x6420e400, 2, 32), // fmmla_z32_zzz_h
    (0xffe0fc00, 0x64a0e000, 3, 16), // fmmla_z_zzz_h
    (0xffe0fc00, 0x64a0e400, 3, 32), // fmmla_z_zzz_s
    (0xffe0fc00, 0x64e0e400, 3, 64), // fmmla_z_zzz_d
];
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn step(r: &mut Recipe, fp: &mut FloatState, op: FloatOperation, w: u8, inputs: Vec<Expr>) -> Expr {
    fp.step(r, op, w, inputs, c(1, 1), c(w, 0), true)
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let &(_, _, kind, w) = FORMS
        .iter()
        .find(|(mask, value, _, _)| word & mask == *value)?;
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) || vl < 4 * u16::from(w) {
        return Some(Recipe::unsupported(
            "invalid SVE matrix CurrentVL",
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
        "SVE matrix requires non-streaming mode or effective FA64",
    );
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    // BFMatMulAddH suppresses every exception and must not read/write FPSR.
    let mut fp = if kind == 1 {
        FloatState::without_status(&mut r)
    } else {
        FloatState::new(&mut r)
    };
    let mut values = Vec::new();
    for e in 0..vl / u16::from(w) {
        let row = e % 4 / 2;
        let col = e % 2;
        let segment = e / 4 * if kind == 1 || kind == 2 { 8 } else { 4 };
        let stride = if kind == 1 || kind == 2 { 4 } else { 2 };
        let a = segment + row * stride;
        let z = segment + col * stride;
        let old = lane(d, e, w);
        let value = if kind == 1 {
            let mut sum = old;
            for k in 0..2 {
                sum = r.bind(Expr::float(FloatExpression {
                    operation: FloatOperation::BFloatDotAdd,
                    environment: FloatEnvironment::A64,
                    width: 32,
                    inputs: vec![
                        sum,
                        lane(n, a + 2 * k, 16),
                        lane(n, a + 2 * k + 1, 16),
                        lane(m, z + 2 * k, 16),
                        lane(m, z + 2 * k + 1, 16),
                    ],
                    control: Box::new(fp.control.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                }));
            }
            sum
        } else {
            let mut products = Vec::new();
            for k in 0..2 {
                let (op, inputs) = if kind == 2 {
                    (
                        FloatOperation::HalfDotProduct,
                        vec![
                            lane(n, a + 2 * k, 16),
                            lane(n, a + 2 * k + 1, 16),
                            lane(m, z + 2 * k, 16),
                            lane(m, z + 2 * k + 1, 16),
                        ],
                    )
                } else {
                    (
                        if kind == 0 {
                            FloatOperation::BFloatBinary {
                                operation: BFloatOperation::Multiply,
                            }
                        } else {
                            FloatOperation::Multiply
                        },
                        vec![lane(n, a + k, w), lane(m, z + k, w)],
                    )
                };
                products.push(step(&mut r, &mut fp, op, w, inputs));
            }
            let add = if kind == 0 {
                FloatOperation::BFloatBinary {
                    operation: BFloatOperation::Add,
                }
            } else {
                FloatOperation::Add
            };
            let product = step(&mut r, &mut fp, add.clone(), w, products);
            step(&mut r, &mut fp, add, w, vec![old, product])
        };
        values.push(value);
    }
    if kind != 1 {
        fp.finish(&mut r);
    }
    for (chunk, lanes) in values.chunks(64 / usize::from(w)).enumerate() {
        let mut out = c(64, 0);
        for (part, value) in lanes.iter().enumerate() {
            out = b(
                B::Or,
                out,
                b(
                    B::Shl,
                    Expr::cast(value.clone(), 64, false),
                    c(64, (part * usize::from(w)) as u64),
                ),
            );
        }
        r.write(
            register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
            WritePolicy::ZeroUpper,
            out,
        );
    }
    Some(r)
}

//! SVE_AES2 grouped AES rounds and paired 64x64 polynomial products.
//! AES keys select one 128-bit segment within each 512-bit group. All outputs
//! refer to incoming state, including keys aliased with any destination.
use super::*;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(register("a64.vector64", n as u16 * 32 + chunk, 64, 64))
}
fn remap(mut value: Expr, inputs: &[[Expr; 2]; 2], base: usize) -> Option<Expr> {
    match &mut value.kind {
        ExprKind::Constant(_) => {}
        ExprKind::Register(s) => {
            if s.register.bank != "a64.vector64"
                || s.register.index / 32 > 1
                || s.register.index % 32 > 1
            {
                return None;
            }
            let input = inputs[usize::from(s.register.index / 32)]
                [usize::from(s.register.index % 32)]
            .clone();
            return Some(Expr::extract(input, s.offset, s.width));
        }
        ExprKind::Temporary(i) => *i += base,
        ExprKind::Unary { value, .. }
        | ExprKind::Cast { value, .. }
        | ExprKind::Extract { value, .. } => **value = remap((**value).clone(), inputs, base)?,
        ExprKind::Binary { left, right, .. } => {
            **left = remap((**left).clone(), inputs, base)?;
            **right = remap((**right).clone(), inputs, base)?;
        }
        ExprKind::Select { condition, yes, no } => {
            **condition = remap((**condition).clone(), inputs, base)?;
            **yes = remap((**yes).clone(), inputs, base)?;
            **no = remap((**no).clone(), inputs, base)?;
        }
        _ => return None,
    }
    Some(value)
}
fn round(r: &mut Recipe, word: u32, inputs: [[Expr; 2]; 2]) -> Option<[Expr; 2]> {
    let child = arm64_crypto::a64(word, 0)?;
    if child.support != Support::Full || child.effects.len() != 2 {
        return None;
    }
    let base = r.temporaries.len();
    for value in child.temporaries {
        r.temporaries.push(remap(value, &inputs, base)?);
    }
    let mut values = vec![];
    for effect in child.effects {
        let Effect::WriteRegister { value, .. } = effect else {
            return None;
        };
        values.push(r.bind(remap(value, &inputs, base)?));
    }
    values.try_into().ok()
}
pub fn a64(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let two = word & 0xffe6f801 == 0x4522e800;
    let four = word & 0xffe6f803 == 0x4526e800;
    let polynomial = word & 0xffe0fc01 == 0x4520f800;
    if !(two || four || polynomial) {
        return None;
    }
    let next = address.wrapping_add(4);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported("invalid SVE CurrentVL", next, 64));
    }
    let mut r = Recipe::new(next, 64);
    r.bind(Expr::require_context(
        Expr::select(
            Expr::register(register("a64.ssve_aes", 0, 1, 1)),
            c(1, 1),
            Expr::select(
                Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
        ),
        "SVE AES2 requires SSVE_AES or non-streaming SVE access",
    ));
    let mut outputs = vec![];
    if polynomial {
        let (d, n, m) = (word & 30, (word >> 5) & 31, (word >> 16) & 31);
        for segment in 0..vl / 128 {
            for half in 0..2 {
                let (low, high) = arm64_crypto::polynomial(
                    &mut r,
                    z(n, segment * 2 + half),
                    z(m, segment * 2 + half),
                    64,
                );
                outputs.push((d + u32::from(half), segment * 2, low));
                outputs.push((d + u32::from(half), segment * 2 + 1, high?));
            }
        }
    } else {
        let d = word & if two { 30 } else { 28 };
        let m = (word >> 5) & 31;
        let index = ((word >> 19) & 3) as u16 % (vl / 128).min(4);
        let inverse = word & (1 << 10) != 0;
        let mix = word & (1 << 16) != 0;
        for reg in 0..if two { 2 } else { 4 } {
            for segment in 0..vl / 128 {
                let key = (segment / 4 * 4 + index) * 2;
                let input = [z(d + reg, segment * 2), z(d + reg, segment * 2 + 1)];
                let key = [z(m, key), z(m, key + 1)];
                let value = round(
                    &mut r,
                    if inverse { 0x4e285820 } else { 0x4e284820 },
                    [input, key],
                )?;
                let value = if mix {
                    round(
                        &mut r,
                        if inverse { 0x4e287820 } else { 0x4e286820 },
                        [[c(64, 0), c(64, 0)], value],
                    )?
                } else {
                    value
                };
                for (chunk, value) in value.into_iter().enumerate() {
                    outputs.push((d + reg, segment * 2 + chunk as u16, value));
                }
            }
        }
    }
    for (n, chunk, value) in outputs {
        r.write(
            register("a64.vector64", n as u16 * 32 + chunk, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(r)
}

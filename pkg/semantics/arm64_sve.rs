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
fn slice(bank: &'static str, index: u16, width: u8) -> RegisterSlice {
    register(bank, index, width, 64)
}
fn z(n: u32, chunk: u16) -> Expr {
    Expr::register(slice("a64.vector64", n as u16 * 32 + chunk, 64))
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * w as u16;
    Expr::extract(z(n, bit / 64), (bit % 64) as u8, w)
}
fn p(n: u32, bit: u16) -> Expr {
    Expr::extract(
        Expr::register(slice("a64.predicate64", n as u16 * 4 + bit / 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
fn gp(n: u32, w: u8, sp: bool) -> Expr {
    if n == 31 && !sp {
        c(w, 0)
    } else {
        Expr::register(register(
            if n == 31 { "a64.sp" } else { "a64.gpr" },
            if n == 31 { 0 } else { n as u16 },
            w,
            64,
        ))
    }
}
fn write_z(r: &mut Recipe, n: u32, values: Vec<Expr>, w: u8) {
    let per = 64 / w as usize;
    for (chunk, lanes) in values.chunks(per).enumerate() {
        let mut value = c(64, 0);
        for (i, v) in lanes.iter().enumerate() {
            value = b(
                B::Or,
                value,
                b(
                    B::Shl,
                    Expr::cast(v.clone(), 64, false),
                    c(64, (i * w as usize) as u64),
                ),
            );
        }
        let value = r.bind(value);
        r.write(
            slice("a64.vector64", n as u16 * 32 + chunk as u16, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn write_p(r: &mut Recipe, n: u32, values: &[Expr], w: u8, vl: u16) {
    // Choose the permitted SVEZEROUPPER behavior: zero-extend to MAX_PL.
    // Only active predicate bits are read; no inactive input chunk is needed.
    for chunk in 0..4u16 {
        let mut value = c(64, 0);
        for (e, v) in values.iter().enumerate() {
            let bit = e as u16 * (w as u16 / 8);
            if bit < vl / 8 && bit / 64 == chunk {
                value = b(
                    B::Or,
                    value,
                    b(
                        B::Shl,
                        Expr::cast(v.clone(), 64, false),
                        c(64, (bit % 64) as u64),
                    ),
                );
            }
        }
        let value = r.bind(value);
        r.write(
            slice("a64.predicate64", n as u16 * 4 + chunk, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn pred_flags(r: &mut Recipe, mask: &[Expr], result: &[Expr]) {
    let (mut first, mut last, mut any) = (c(1, 0), c(1, 0), c(1, 0));
    for (m, v) in mask.iter().zip(result).rev() {
        first = r.bind(Expr::select(m.clone(), v.clone(), first));
    }
    for (m, v) in mask.iter().zip(result) {
        last = r.bind(Expr::select(m.clone(), v.clone(), last));
        any = r.bind(b(B::Or, any, b(B::And, m.clone(), v.clone())));
    }
    for (i, value) in [first, not(any), not(last), c(1, 0)]
        .into_iter()
        .enumerate()
    {
        let value = r.bind(value);
        r.write(
            register("a64.nzcv", i as u16, 1, 1),
            WritePolicy::ZeroUpper,
            value,
        );
    }
}
fn count(pattern: u32, elements: u16) -> u16 {
    match pattern {
        0 => 1u16 << (15 - elements.leading_zeros()),
        1..=8 => {
            if elements >= pattern as u16 {
                pattern as u16
            } else {
                0
            }
        }
        9..=13 => {
            let n = 16u16 << (pattern - 9);
            if elements >= n {
                n
            } else {
                0
            }
        }
        29 => elements / 4 * 4,
        30 => elements / 3 * 3,
        31 => elements,
        _ => 0,
    }
}
fn cmp(code: u32, a: Expr, z: Expr) -> Expr {
    match code {
        0 => b(B::Eq, a, z),
        1 => not(b(B::Eq, a, z)),
        2 => not(b(B::Slt, a, z)),
        3 => b(B::Slt, z, a),
        4 => not(b(B::Ult, a, z)),
        _ => b(B::Ult, z, a),
    }
}
// SVE evaluates FP operations in architectural lane order. Each operation
// captures its sources and all three projections before the next operation,
// preserving cumulative FPSR and stopping evaluation at the first trap. A
// Select guards the operation itself, not merely its final result.
pub(super) struct FloatState {
    pub(super) control: Expr,
    status: Expr,
    trapped: Expr,
}
impl FloatState {
    /// Instructions that suppress exceptions do not observe incoming FPSR.
    pub(super) fn without_status(r: &mut Recipe) -> Self {
        Self {
            control: r.bind(Expr::register(register("a64.fpcr", 0, 32, 32))),
            status: c(32, 0),
            trapped: c(1, 0),
        }
    }
    pub(super) fn new(r: &mut Recipe) -> Self {
        Self {
            control: Expr::register(register("a64.fpcr", 0, 32, 32)),
            status: r.bind(Expr::register(register("a64.fpsr", 0, 32, 32))),
            trapped: c(1, 0),
        }
    }
    pub(super) fn new_conditional(r: &mut Recipe, active: Expr) -> Self {
        Self {
            control: r.bind(Expr::select(
                active.clone(),
                Expr::register(register("a64.fpcr", 0, 32, 32)),
                c(32, 0),
            )),
            status: r.bind(Expr::select(
                active,
                Expr::register(register("a64.fpsr", 0, 32, 32)),
                c(32, 0),
            )),
            trapped: c(1, 0),
        }
    }
    pub(super) fn finish_conditional(self, r: &mut Recipe, active: Expr) {
        r.write_conditional(
            active,
            register("a64.fpsr", 0, 32, 32),
            WritePolicy::ZeroUpper,
            self.status,
        );
        r.effects.push(Effect::Trap {
            kind: TrapKind::FloatingPoint,
            condition: self.trapped,
        });
    }
    pub(super) fn step(
        &mut self,
        r: &mut Recipe,
        operation: FloatOperation,
        width: u8,
        inputs: Vec<Expr>,
        active: Expr,
        inactive: Expr,
        clear_ahp: bool,
    ) -> Expr {
        let guard = r.bind(b(B::And, active, not(self.trapped.clone())));
        let inputs = inputs
            .into_iter()
            .map(|v| {
                let width = v.ty.width;
                r.bind(Expr::select(guard.clone(), v, c(width, 0)))
            })
            .collect();
        // FPConvertSVE explicitly ignores the alternative-half-precision bit.
        let control = if clear_ahp {
            b(B::And, self.control.clone(), c(32, !(1u64 << 26)))
        } else {
            self.control.clone()
        };
        let expression = FloatExpression {
            operation,
            environment: FloatEnvironment::A64,
            width,
            inputs,
            control: Box::new(control),
            status: Box::new(self.status.clone()),
            projection: FloatProjection::Value,
        };
        let value = r.bind(Expr::select(
            guard.clone(),
            Expr::float(expression.clone()),
            inactive,
        ));
        let status = r.bind(Expr::select(
            guard.clone(),
            Expr::float(FloatExpression {
                projection: FloatProjection::Status,
                ..expression.clone()
            }),
            self.status.clone(),
        ));
        let trapped = r.bind(Expr::select(
            guard,
            Expr::float(FloatExpression {
                projection: FloatProjection::Trapped,
                ..expression
            }),
            c(1, 0),
        ));
        self.status = status;
        self.trapped = r.bind(b(B::Or, self.trapped.clone(), trapped));
        value
    }
    // Scale/LogB are exact integer expression algebras. Guard every projection
    // before binding it: inactive lanes must not inspect operands or demand an
    // FP context, and no later lane executes after an enabled exception.
    pub(super) fn scale_logb(
        &mut self,
        r: &mut Recipe,
        width: u8,
        value: Expr,
        exponent: Option<Expr>,
        active: Expr,
        inactive: Expr,
    ) -> Expr {
        let guard = r.bind(b(B::And, active, not(self.trapped.clone())));
        let value = r.bind(Expr::select(guard.clone(), value, c(width, 0)));
        let outcome = if let Some(exponent) = exponent {
            let exponent = r.bind(Expr::select(guard.clone(), exponent, c(width, 0)));
            arm64_float_extra::scale_bound(
                r,
                guard.clone(),
                width,
                value,
                exponent,
                self.control.clone(),
                self.status.clone(),
                false,
            )
        } else {
            arm64_float_extra::logb(width, value, self.control.clone(), self.status.clone())
        }
        .expect("decoded Scale/LogB dimensions");
        let value = r.bind(Expr::select(guard.clone(), outcome.value, inactive));
        self.status = r.bind(Expr::select(
            guard.clone(),
            outcome.status,
            self.status.clone(),
        ));
        let trapped = r.bind(Expr::select(guard, outcome.trapped, c(1, 0)));
        self.trapped = r.bind(b(B::Or, self.trapped.clone(), trapped));
        value
    }
    pub(super) fn bfloat_scale(
        &mut self,
        r: &mut Recipe,
        value: Expr,
        exponent: Expr,
        active: Expr,
        inactive: Expr,
    ) -> Expr {
        let guard = r.bind(b(B::And, active, not(self.trapped.clone())));
        let value = r.bind(Expr::select(guard.clone(), value, c(16, 0)));
        let exponent = r.bind(Expr::select(guard.clone(), exponent, c(16, 0)));
        let outcome = arm64_float_extra::scale_bound(
            r,
            guard.clone(),
            16,
            value,
            exponent,
            self.control.clone(),
            self.status.clone(),
            true,
        )
        .expect("BFScale dimensions");
        let value = r.bind(Expr::select(guard.clone(), outcome.value, inactive));
        self.status = r.bind(Expr::select(
            guard.clone(),
            outcome.status,
            self.status.clone(),
        ));
        let trapped = r.bind(Expr::select(guard, outcome.trapped, c(1, 0)));
        self.trapped = r.bind(b(B::Or, self.trapped.clone(), trapped));
        value
    }
    pub(super) fn absolute_minmax(
        &mut self,
        r: &mut Recipe,
        a: Expr,
        b_: Expr,
        minimum: bool,
        active: Expr,
        inactive: Expr,
    ) -> Expr {
        let w = a.ty.width;
        let guard = r.bind(b(B::And, active, not(self.trapped.clone())));
        let a = r.bind(Expr::select(guard.clone(), a, c(w, 0)));
        let b_ = r.bind(Expr::select(guard.clone(), b_, c(w, 0)));
        let (value, invalid) =
            arm64_float_misc::absolute_minmax(r, a, b_, self.control.clone(), minimum);
        let raised = r.bind(Expr::select(
            guard.clone(),
            Expr::cast(invalid, 32, false),
            c(32, 0),
        ));
        self.status = r.bind(b(B::Or, self.status.clone(), raised.clone()));
        self.trapped = r.bind(b(
            B::Or,
            self.trapped.clone(),
            not(b(
                B::Eq,
                b(B::And, b(B::Lsr, self.control.clone(), c(32, 8)), raised),
                c(32, 0),
            )),
        ));
        r.bind(Expr::select(guard, value, inactive))
    }
    pub(super) fn finish(self, r: &mut Recipe) {
        r.write(
            register("a64.fpsr", 0, 32, 32),
            WritePolicy::ZeroUpper,
            self.status,
        );
        r.effects.push(Effect::Trap {
            kind: TrapKind::FloatingPoint,
            condition: self.trapped,
        });
    }

    fn bounded_round(
        &mut self,
        r: &mut Recipe,
        value: Expr,
        intsize: u8,
        environment: bool,
        active: Expr,
        inactive: Expr,
    ) -> Expr {
        let guard = r.bind(b(B::And, active, not(self.trapped.clone())));
        let width = value.ty.width;
        let value = r.bind(Expr::select(guard.clone(), value, c(width, 0)));
        let control = r.bind(Expr::select(guard.clone(), self.control.clone(), c(32, 0)));
        let (value, raised) =
            arm64_float_misc::bounded_round(r, value, intsize, environment, control.clone());
        let raised = r.bind(Expr::select(guard.clone(), raised, c(32, 0)));
        self.status = r.bind(b(B::Or, self.status.clone(), raised.clone()));
        let enabled = b(B::And, b(B::Lsr, control, c(32, 8)), raised);
        self.trapped = r.bind(b(
            B::Or,
            self.trapped.clone(),
            not(b(B::Eq, enabled, c(32, 0))),
        ));
        r.bind(Expr::select(guard, value, inactive))
    }
}
fn fp_scalar_write(r: &mut Recipe, d: u32, value: Expr, vl: u16) {
    let value = r.bind(Expr::cast(value, 64, false));
    for chunk in 0..vl / 64 {
        r.write(
            slice("a64.vector64", d as u16 * 32 + chunk, 64),
            WritePolicy::ZeroUpper,
            if chunk == 0 { value.clone() } else { c(64, 0) },
        );
    }
}
fn fp_relation(code: u32, nzcv: Expr) -> Expr {
    let z = Expr::extract(nzcv.clone(), 2, 1);
    let carry = Expr::extract(nzcv.clone(), 1, 1);
    let unordered = Expr::extract(nzcv, 0, 1);
    match code {
        0 => z,
        1 => not(z),
        2 => b(B::And, carry, not(unordered)),
        3 => b(B::And, b(B::And, carry, not(z)), not(unordered)),
        _ => unordered,
    }
}
fn fp_reduce(
    r: &mut Recipe,
    fp: &mut FloatState,
    op: FloatOperation,
    values: &[Expr],
    w: u8,
) -> Expr {
    if values.len() == 1 {
        return values[0].clone();
    }
    // Arm FPReduce visits the high subtree before the low subtree, but the
    // primitive receives (low, high). This order matters for traps and NaNs.
    let half = values.len() / 2;
    let high = fp_reduce(r, fp, op, &values[half..], w);
    let low = fp_reduce(r, fp, op, &values[..half], w);
    fp.step(r, op, w, vec![low, high], c(1, 1), c(w, 0), false)
}
// Literal coefficients from Arm shared pseudocode (June2026), not host math.
const EXP16: &[u64] = &[
    0x0, 0x16, 0x2d, 0x45, 0x5d, 0x75, 0x8e, 0xa8, 0xc2, 0xdc, 0xf8, 0x114, 0x130, 0x14d, 0x16b,
    0x189, 0x1a8, 0x1c8, 0x1e8, 0x209, 0x22b, 0x24e, 0x271, 0x295, 0x2ba, 0x2e0, 0x306, 0x32e,
    0x356, 0x37f, 0x3a9, 0x3d4,
];
const EXP32: &[u64] = &[
    0x0, 0x164d2, 0x2cd87, 0x43a29, 0x5aac3, 0x71f62, 0x8980f, 0xa14d5, 0xb95c2, 0xd1adf, 0xea43a,
    0x1031dc, 0x11c3d3, 0x135a2b, 0x14f4f0, 0x16942d, 0x1837f0, 0x19e046, 0x1b8d3a, 0x1d3eda,
    0x1ef532, 0x20b051, 0x227043, 0x243516, 0x25fed7, 0x27cd94, 0x29a15b, 0x2b7a3a, 0x2d583f,
    0x2f3b79, 0x3123f6, 0x3311c4, 0x3504f3, 0x36fd92, 0x38fbaf, 0x3aff5b, 0x3d08a4, 0x3f179a,
    0x412c4d, 0x4346cd, 0x45672a, 0x478d75, 0x49b9be, 0x4bec15, 0x4e248c, 0x506334, 0x52a81e,
    0x54f35b, 0x5744fd, 0x599d16, 0x5bfbb8, 0x5e60f5, 0x60ccdf, 0x633f89, 0x65b907, 0x68396a,
    0x6ac0c7, 0x6d4f30, 0x6fe4ba, 0x728177, 0x75257d, 0x77d0df, 0x7a83b3, 0x7d3e0c,
];
const EXP64: &[u64] = &[
    0x0,
    0x2c9a3e778061,
    0x59b0d3158574,
    0x874518759bc8,
    0xb5586cf9890f,
    0xe3ec32d3d1a2,
    0x11301d0125b51,
    0x1429aaea92de0,
    0x172b83c7d517b,
    0x1a35beb6fcb75,
    0x1d4873168b9aa,
    0x2063b88628cd6,
    0x2387a6e756238,
    0x26b4565e27cdd,
    0x29e9df51fdee1,
    0x2d285a6e4030b,
    0x306fe0a31b715,
    0x33c08b26416ff,
    0x371a7373aa9cb,
    0x3a7db34e59ff7,
    0x3dea64c123422,
    0x4160a21f72e2a,
    0x44e086061892d,
    0x486a2b5c13cd0,
    0x4bfdad5362a27,
    0x4f9b2769d2ca7,
    0x5342b569d4f82,
    0x56f4736b527da,
    0x5ab07dd485429,
    0x5e76f15ad2148,
    0x6247eb03a5585,
    0x6623882552225,
    0x6a09e667f3bcd,
    0x6dfb23c651a2f,
    0x71f75e8ec5f74,
    0x75feb564267c9,
    0x7a11473eb0187,
    0x7e2f336cf4e62,
    0x82589994cce13,
    0x868d99b4492ed,
    0x8ace5422aa0db,
    0x8f1ae99157736,
    0x93737b0cdc5e5,
    0x97d829fde4e50,
    0x9c49182a3f090,
    0xa0c667b5de565,
    0xa5503b23e255d,
    0xa9e6b5579fdbf,
    0xae89f995ad3ad,
    0xb33a2b84f15fb,
    0xb7f76f2fb5e47,
    0xbcc1e904bc1d2,
    0xc199bdd85529c,
    0xc67f12e57d14b,
    0xcb720dcef9069,
    0xd072d4a07897c,
    0xd5818dcfba487,
    0xda9e603db3285,
    0xdfc97337b9b5f,
    0xe502ee78b3ff6,
    0xea4afa2a490da,
    0xefa1bee615a27,
    0xf50765b6e4540,
    0xfa7c1819e90d8,
];
const TRIG16: &[u64] = &[
    0x3c00, 0xb155, 0x2030, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3c00, 0xb800, 0x293a, 0x0, 0x0, 0x0, 0x0,
    0x0,
];
const TRIG32: &[u64] = &[
    0x3f800000, 0xbe2aaaab, 0x3c088886, 0xb95008b9, 0x36369d6d, 0x0, 0x0, 0x0, 0x3f800000,
    0xbf000000, 0x3d2aaaa6, 0xbab60705, 0x37cd37cc, 0x0, 0x0, 0x0,
];
const TRIG64: &[u64] = &[
    0x3ff0000000000000,
    0xbfc5555555555543,
    0x3f8111111110f30c,
    0xbf2a01a019b92fc6,
    0x3ec71de351f3d22b,
    0xbe5ae5e2b60f7b91,
    0x3de5d8408868552f,
    0x0,
    0x3ff0000000000000,
    0xbfe0000000000000,
    0x3fa5555555555536,
    0xbf56c16c16c13a0b,
    0x3efa01a019b1e8d8,
    0xbe927e4f7282f468,
    0x3e21ee96d2641b13,
    0xbda8f76380fbb401,
];
fn coefficient(index: Expr, values: &[u64], w: u8) -> Expr {
    if values.len() == 1 {
        return c(w, values[0]);
    }
    let half = values.len() / 2;
    let bit = half.trailing_zeros() as u8;
    Expr::select(
        Expr::extract(index.clone(), bit, 1),
        coefficient(index.clone(), &values[half..], w),
        coefficient(index, &values[..half], w),
    )
}
fn non_streaming(r: &mut Recipe, ssve_fexpa: bool) {
    let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
    let fa64 = Expr::register(register("a64.sme_fa64", 0, 1, 1));
    let enabled = if ssve_fexpa {
        Expr::select(
            Expr::register(register("a64.ssve_fexpa", 0, 1, 1)),
            c(1, 1),
            fa64,
        )
    } else {
        fa64
    };
    // Effective FullA64 includes every applicable SMCR_ELx.FA64 control.
    r.bind(Expr::require_context(
        Expr::select(sm, enabled, c(1, 1)),
        "SVE instruction requires non-streaming mode or effective streaming capability",
    ));
}
pub(super) fn fp_abs(value: Expr, w: u8, control: Expr) -> Expr {
    let exponent = match w {
        16 => 0x7c00,
        32 => 0x7f800000,
        _ => 0x7ff0000000000000,
    };
    let fraction = match w {
        16 => 0x3ff,
        32 => 0x7fffff,
        _ => 0xfffffffffffff,
    };
    let nan = b(
        B::And,
        b(
            B::Eq,
            b(B::And, value.clone(), c(w, exponent)),
            c(w, exponent),
        ),
        not(b(B::Eq, b(B::And, value.clone(), c(w, fraction)), c(w, 0))),
    );
    Expr::select(
        b(B::And, Expr::extract(control, 1, 1), nan),
        value.clone(),
        b(B::And, value, c(w, !(1u64 << (w - 1)))),
    )
}
// FPNeg changes the sign of numbers, but AFP.AH preserves NaN bits.
// In complex operations this is an operand transform before FPAdd/FPMulAdd,
// rather than a negate-product modifier with different NaN selection rules.
pub(super) fn fp_neg(value: Expr, control: Expr) -> Expr {
    let w = value.ty.width;
    let fraction = match w {
        16 => 10,
        32 => 23,
        _ => 52,
    };
    let exponent = mask(w - 1) & !mask(fraction);
    let nan = b(
        B::And,
        b(
            B::Eq,
            b(B::And, value.clone(), c(w, exponent)),
            c(w, exponent),
        ),
        not(b(
            B::Eq,
            b(B::And, value.clone(), c(w, mask(fraction))),
            c(w, 0),
        )),
    );
    Expr::select(
        b(B::And, Expr::extract(control, 1, 1), nan),
        value.clone(),
        b(B::Xor, value, c(w, 1u64 << (w - 1))),
    )
}
fn floating_complex_long(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    use FloatOperation as F;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let fcadd = word & 0xff3ee000 == 0x64008000;
    let fcmla = word & 0xff208000 == 0x64000000;
    let indexed = match word & 0xffe0f000 {
        0x64a01000 => Some((16u8, (word >> 19) & 3, m & 7)),
        0x64e01000 => Some((32u8, (word >> 20) & 1, m & 15)),
        _ => None,
    };
    if fcadd || fcmla || indexed.is_some() {
        let w = indexed.map_or(8u8 << ((word >> 22) & 3), |v| v.0);
        if w == 8 {
            return None;
        }
        let rotation = if indexed.is_some() {
            (word >> 10) & 3
        } else {
            (word >> 13) & 3
        };
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let pair = e & !1;
            let imaginary = e & 1 != 0;
            let active = if indexed.is_some() {
                c(1, 1)
            } else {
                p(pg, e * (w as u16 / 8))
            };
            let old = lane(d, e, w);
            if fcadd {
                let negative = ((word >> 16) & 1 != 0) == imaginary;
                let input = lane(n, pair + u16::from(!imaginary), w);
                let input = if negative {
                    fp_neg(input, fp.control.clone())
                } else {
                    input
                };
                values.push(fp.step(
                    &mut r,
                    F::Add,
                    w,
                    vec![old.clone(), input],
                    active,
                    old,
                    false,
                ));
            } else {
                let select = (rotation & 1) as u16;
                let source_pair = if let Some((_, index, _)) = indexed {
                    let pairs_per_segment = 128 / (2 * w as u16);
                    (e / 2 / pairs_per_segment * pairs_per_segment + index as u16) * 2
                } else {
                    pair
                };
                let right = lane(
                    indexed.map_or(m, |v| v.2),
                    source_pair + if imaginary { 1 - select } else { select },
                    w,
                );
                let negative = if imaginary {
                    rotation & 2 != 0
                } else {
                    (rotation & 1) != ((rotation >> 1) & 1)
                };
                let right = if negative {
                    fp_neg(right, fp.control.clone())
                } else {
                    right
                };
                values.push(fp.step(
                    &mut r,
                    F::FusedMultiplyAdd {
                        negate_product: false,
                        negate_addend: false,
                    },
                    w,
                    vec![old.clone(), lane(n, pair + select, w), right],
                    active,
                    old,
                    false,
                ));
            }
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    // Top conversions select the odd source half for FCVTLT, or replace only
    // the odd destination half for FCVTNT/BFCVTNT. /Z never clears the even half
    // of a narrowing destination; it only clears inactive odd halves.
    let conversion = match word & 0xffffe000 {
        0x6489a000 => Some((32u8, true, true, false)),
        0x6481a000 => Some((32, true, false, false)),
        0x64cba000 => Some((64, true, true, false)),
        0x64c3a000 => Some((64, true, false, false)),
        0x6488a000 => Some((32, false, true, false)),
        0x6480a000 => Some((32, false, false, false)),
        0x64caa000 => Some((64, false, true, false)),
        0x64c2a000 => Some((64, false, false, false)),
        0x648aa000 => Some((32, false, true, true)),
        0x6482a000 => Some((32, false, false, true)),
        _ => None,
    };
    if let Some((w, widening, merging, bfloat)) = conversion {
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let active = p(pg, e * (w as u16 / 8));
            let src_width = if widening { w / 2 } else { w };
            let dst_width = if widening { w } else { w / 2 };
            let old = lane(d, e, w);
            let inactive = if merging {
                if widening {
                    old.clone()
                } else {
                    Expr::extract(old.clone(), w / 2, w / 2)
                }
            } else {
                c(dst_width, 0)
            };
            let value = fp.step(
                &mut r,
                if bfloat {
                    F::ToBFloat16
                } else {
                    F::Convert {
                        source_width: src_width,
                        round_to_odd: false,
                    }
                },
                dst_width,
                vec![if widening {
                    lane(n, 2 * e + 1, w / 2)
                } else {
                    lane(n, e, w)
                }],
                active,
                inactive,
                !bfloat,
            );
            values.push(if widening {
                value
            } else {
                b(
                    B::Or,
                    Expr::cast(Expr::extract(old, 0, w / 2), w, false),
                    b(B::Shl, Expr::cast(value, w, false), c(w, (w / 2) as u64)),
                )
            });
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    // FPMulAddH keeps binary16 unpack/NaN processing and binary32 fused
    // rounding in one native operation; converting the operands separately
    // would change signaling-NaN and enabled-exception ordering.
    let half_long = word & 0xffe0d800 == 0x64a08000;
    let half_long_index = word & 0xffe0d000 == 0x64a04000;
    if half_long || half_long_index {
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / 32 {
            let source = 2 * e + ((word >> 10) & 1) as u16;
            let source2 = if half_long_index {
                (e / 4) * 8 + (((word >> 19) & 3) * 2 + ((word >> 11) & 1)) as u16
            } else {
                source
            };
            let left = lane(n, source, 16);
            let left = if word & (1 << 13) != 0 {
                fp_neg(left, fp.control.clone())
            } else {
                left
            };
            values.push(fp.step(
                &mut r,
                F::WideningFusedMultiplyAdd { source_width: 16 },
                32,
                vec![
                    lane(d, e, 32),
                    left,
                    lane(if half_long_index { m & 7 } else { m }, source2, 16),
                ],
                c(1, 1),
                c(32, 0),
                false,
            ));
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, 32);
        return Some(r);
    }
    let odd = match word & 0xffffe000 {
        0x650aa000 => Some((false, true)),
        0x641ac000 => Some((false, false)),
        0x640aa000 => Some((true, true)),
        0x6402a000 => Some((true, false)),
        _ => None,
    };
    if let Some((top, merging)) = odd {
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / 64 {
            let active = p(pg, e * 8);
            let old = lane(d, e, 64);
            // Narrowing /M preserves the entire inactive destination element;
            // an active bottom conversion zeroes its high half, whereas top
            // conversion always preserves the incoming low half.
            let converted = fp.step(
                &mut r,
                F::Convert {
                    source_width: 64,
                    round_to_odd: true,
                },
                32,
                vec![lane(n, e, 64)],
                active.clone(),
                if top && merging {
                    Expr::extract(old.clone(), 32, 32)
                } else {
                    c(32, 0)
                },
                true,
            );
            values.push(if top {
                b(
                    B::Or,
                    Expr::cast(Expr::extract(old, 0, 32), 64, false),
                    b(B::Shl, Expr::cast(converted, 64, false), c(64, 32)),
                )
            } else {
                Expr::select(
                    active,
                    Expr::cast(converted, 64, false),
                    if merging { old } else { c(64, 0) },
                )
            });
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, 64);
        return Some(r);
    }
    let dot = word & 0xffe0fc00 == 0x64608000;
    let dot_index = word & 0xffe0fc00 == 0x64604000;
    if dot || dot_index {
        let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
        let mut values = Vec::new();
        for e in 0..vl / 32 {
            let source2 = if dot_index {
                2 * (e / 4 * 4 + ((word >> 19) & 3) as u16)
            } else {
                2 * e
            };
            values.push(r.bind(Expr::float(FloatExpression {
                operation: F::BFloatDotAdd,
                environment: FloatEnvironment::A64,
                width: 32,
                inputs: vec![
                    lane(d, e, 32),
                    lane(n, 2 * e, 16),
                    lane(n, 2 * e + 1, 16),
                    lane(if dot_index { m & 7 } else { m }, source2, 16),
                    lane(if dot_index { m & 7 } else { m }, source2 + 1, 16),
                ],
                control: Box::new(control.clone()),
                status: Box::new(c(32, 0)),
                projection: FloatProjection::Value,
            })));
        }
        write_z(&mut r, d, values, 32);
        return Some(r);
    }
    None
}
fn floating(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if let Some(recipe) = floating_complex_long(word, address, vl) {
        return Some(recipe);
    }
    use FloatOperation as F;
    use FloatRounding as R;
    let w = 8u8 << ((word >> 22) & 3);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    // FRINT32/64X/Z use FPRoundIntN, including its signed range check and
    // indefinite result. Merging and zeroing diagrams put sz/U differently.
    let bounded_merge = word & 0xfff8e000 == 0x6510a000;
    let bounded_zero = word & 0xfffe8000 == 0x641c8000;
    if bounded_merge || bounded_zero {
        let width = 32u8 << ((word >> if bounded_merge { 17 } else { 14 }) & 1);
        let intsize = if word & (1 << if bounded_merge { 18 } else { 16 }) != 0 {
            64
        } else {
            32
        };
        let environment = word & (1 << if bounded_merge { 16 } else { 13 }) != 0;
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / u16::from(width))
            .map(|e| {
                fp.bounded_round(
                    &mut r,
                    lane(n, e, width),
                    intsize,
                    environment,
                    p(pg, e * u16::from(width / 8)),
                    if bounded_merge {
                        lane(d, e, width)
                    } else {
                        c(width, 0)
                    },
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, width);
        return Some(r);
    }
    // June 2026 fscale_z_p_zz and both flogb_z_p_z diagrams. LogB's
    // merging and zeroing encodings put size in different physical fields.
    let scale = word & 0xff3fe000 == 0x65098000;
    let logb_merge = word & 0xfff9e000 == 0x6518a000;
    let logb_zero = word & 0xffff8000 == 0x641e8000;
    if scale || logb_merge || logb_zero {
        let width = if scale {
            w
        } else if logb_merge {
            8u8 << ((word >> 17) & 3)
        } else {
            8u8 << ((word >> 13) & 3)
        };
        if width == 8 {
            return None;
        }
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / width as u16 {
            values.push(fp.scale_logb(
                &mut r,
                width,
                lane(if scale { d } else { n }, e, width),
                if scale { Some(lane(n, e, width)) } else { None },
                p(pg, e * (width as u16 / 8)),
                if logb_zero {
                    c(width, 0)
                } else {
                    lane(d, e, width)
                },
            ));
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, width);
        return Some(r);
    }
    if word & 0xff3ffc00 == 0x0420b800 {
        if w == 8 {
            return None;
        }
        non_streaming(&mut r, true);
        let table = match w {
            16 => EXP16,
            32 => EXP32,
            _ => EXP64,
        };
        let (index_width, exponent_width, fraction_width) = match w {
            16 => (5, 5, 10),
            32 => (6, 8, 23),
            _ => (6, 11, 52),
        };
        let values = (0..vl / w as u16)
            .map(|e| {
                let input = r.bind(lane(n, e, w));
                let index = r.bind(Expr::extract(input.clone(), 0, index_width));
                b(
                    B::Or,
                    coefficient(index, table, w),
                    b(
                        B::Shl,
                        Expr::cast(Expr::extract(input, index_width, exponent_width), w, false),
                        c(w, fraction_width),
                    ),
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if word & 0xff38fc00 == 0x65108000 {
        if w == 8 {
            return None;
        }
        non_streaming(&mut r, false);
        let table = match w {
            16 => TRIG16,
            32 => TRIG32,
            _ => TRIG64,
        };
        let imm = (word >> 16) & 7;
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                let input = r.bind(Expr::select(
                    not(fp.trapped.clone()),
                    lane(n, e, w),
                    c(w, 0),
                ));
                let index = r.bind(b(
                    B::Or,
                    c(4, imm as u64),
                    b(
                        B::Shl,
                        Expr::cast(Expr::extract(input.clone(), w - 1, 1), 4, false),
                        c(4, 3),
                    ),
                ));
                let coeff = coefficient(index, table, w);
                let abs = fp_abs(input, w, fp.control.clone());
                fp.step(
                    &mut r,
                    F::FusedMultiplyAdd {
                        negate_product: false,
                        negate_addend: false,
                    },
                    w,
                    vec![coeff, lane(d, e, w), abs],
                    c(1, 1),
                    c(w, 0),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let binary = word & 0xff3fe000;
    let binary_op = match binary {
        0x65008000 => Some((F::Add, false)),
        0x65018000 => Some((F::Subtract, false)),
        0x65038000 => Some((F::Subtract, true)),
        0x65028000 => Some((F::Multiply, false)),
        0x650d8000 => Some((F::Divide, false)),
        0x650c8000 => Some((F::Divide, true)),
        0x650a8000 => Some((F::MultiplyExtended, false)),
        0x65048000 => Some((
            F::MinMax {
                minimum: false,
                numeric: true,
            },
            false,
        )),
        0x65058000 => Some((
            F::MinMax {
                minimum: true,
                numeric: true,
            },
            false,
        )),
        0x65068000 => Some((
            F::MinMax {
                minimum: false,
                numeric: false,
            },
            false,
        )),
        0x65078000 => Some((
            F::MinMax {
                minimum: true,
                numeric: false,
            },
            false,
        )),
        _ => None,
    };
    if let Some((op, reverse)) = binary_op {
        if w == 8 {
            return None;
        }
        let mut fp = FloatState::new(&mut r);
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let mut inputs = vec![lane(d, e, w), lane(n, e, w)];
            if reverse {
                inputs.reverse();
            }
            values.push(fp.step(
                &mut r,
                op,
                w,
                inputs,
                p(pg, e * (w as u16 / 8)),
                lane(d, e, w),
                false,
            ));
        }
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(
        binary,
        0x64108000 | 0x64148000 | 0x64158000 | 0x64168000 | 0x64178000
    ) {
        if w == 8 {
            return None;
        }
        let op = if binary == 0x64108000 {
            F::Add
        } else {
            F::MinMax {
                minimum: matches!(binary, 0x64158000 | 0x64178000),
                numeric: matches!(binary, 0x64148000 | 0x64158000),
            }
        };
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                let (source, first) = if e % 2 == 0 { (d, e) } else { (n, e - 1) };
                fp.step(
                    &mut r,
                    op,
                    w,
                    vec![lane(source, first, w), lane(source, first + 1, w)],
                    p(pg, e * (w as u16 / 8)),
                    lane(d, e, w),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let plain = word & 0xff20fc00;
    if let Some(op) = match plain {
        0x65000000 => Some(F::Add),
        0x65000400 => Some(F::Subtract),
        0x65000800 => Some(F::Multiply),
        0x65001800 => Some(F::ReciprocalStep),
        0x65001c00 => Some(F::ReciprocalSquareRootStep),
        _ => None,
    } {
        if w == 8 {
            return None;
        }
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                fp.step(
                    &mut r,
                    op,
                    w,
                    vec![lane(n, e, w), lane(m, e, w)],
                    c(1, 1),
                    c(w, 0),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let fused = word & 0xff20e000;
    if matches!(
        fused,
        0x65200000
            | 0x65202000
            | 0x65204000
            | 0x65206000
            | 0x65208000
            | 0x6520a000
            | 0x6520c000
            | 0x6520e000
    ) {
        if w == 8 {
            return None;
        }
        let op = F::FusedMultiplyAdd {
            negate_product: matches!(fused & 0x6000, 0x2000 | 0x4000),
            negate_addend: fused & 0x4000 != 0,
        };
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                fp.step(
                    &mut r,
                    op,
                    w,
                    if fused & 0x8000 == 0 {
                        vec![lane(d, e, w), lane(n, e, w), lane(m, e, w)]
                    } else {
                        vec![lane(n, e, w), lane(d, e, w), lane(m, e, w)]
                    },
                    p(pg, e * (w as u16 / 8)),
                    lane(d, e, w),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let immediate = word & 0xff3fe3c0;
    if matches!(
        immediate,
        0x65188000
            | 0x65198000
            | 0x651a8000
            | 0x651b8000
            | 0x651c8000
            | 0x651d8000
            | 0x651e8000
            | 0x651f8000
    ) {
        if w == 8 {
            return None;
        }
        let large = word & 32 != 0;
        let two = immediate == 0x651a8000;
        let bits = match (w, large, two) {
            (16, false, _) => 0x3800,
            (16, true, false) => 0x3c00,
            (16, true, true) => 0x4000,
            (32, false, _) => 0x3f000000,
            (32, true, false) => 0x3f800000,
            (32, true, true) => 0x40000000,
            (64, false, _) => 0x3fe0000000000000,
            (64, true, false) => 0x3ff0000000000000,
            _ => 0x4000000000000000,
        };
        let minmax = immediate >= 0x651c8000;
        let bits = if minmax && !large { 0 } else { bits };
        let op = if minmax {
            F::MinMax {
                minimum: matches!(immediate, 0x651d8000 | 0x651f8000),
                numeric: matches!(immediate, 0x651c8000 | 0x651d8000),
            }
        } else if immediate == 0x65188000 {
            F::Add
        } else if two {
            F::Multiply
        } else {
            F::Subtract
        };
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                fp.step(
                    &mut r,
                    op,
                    w,
                    if immediate == 0x651b8000 {
                        vec![c(w, bits), lane(d, e, w)]
                    } else {
                        vec![lane(d, e, w), c(w, bits)]
                    },
                    p(pg, e * (w as u16 / 8)),
                    lane(d, e, w),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    // FABS/FNEG are bit transport. Under AH a NaN's sign is unchanged;
    // neither operation raises an FP exception or changes FPSR.
    let unary = word & 0xff3fe000;
    if let Some(op) = match word & 0xff3ffc00 {
        0x650e3000 => Some(F::ReciprocalEstimate),
        0x650f3000 => Some(F::ReciprocalSquareRootEstimate),
        _ => None,
    } {
        if w == 8 {
            return None;
        }
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| fp.step(&mut r, op, w, vec![lane(n, e, w)], c(1, 1), c(w, 0), false))
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(unary, 0x041ca000 | 0x041da000 | 0x040ca000 | 0x040da000) {
        if w == 8 {
            return None;
        }
        let ah = r.bind(Expr::extract(
            Expr::register(register("a64.fpcr", 0, 32, 32)),
            1,
            1,
        ));
        let exponent = match w {
            16 => 0x7c00,
            32 => 0x7f800000,
            _ => 0x7ff0000000000000,
        };
        let fraction = match w {
            16 => 0x3ff,
            32 => 0x7fffff,
            _ => 0xfffffffffffff,
        };
        let merge = unary & 0x00100000 != 0;
        let neg = unary & 0x10000 != 0;
        let values = (0..vl / w as u16)
            .map(|e| {
                let active = p(pg, e * (w as u16 / 8));
                let input = r.bind(Expr::select(active.clone(), lane(n, e, w), c(w, 0)));
                let nan = b(
                    B::And,
                    b(
                        B::Eq,
                        b(B::And, input.clone(), c(w, exponent)),
                        c(w, exponent),
                    ),
                    not(b(B::Eq, b(B::And, input.clone(), c(w, fraction)), c(w, 0))),
                );
                let sign = 1u64 << (w - 1);
                let result = b(
                    if neg { B::Xor } else { B::And },
                    input.clone(),
                    c(w, if neg { sign } else { !sign }),
                );
                Expr::select(
                    active,
                    Expr::select(b(B::And, ah.clone(), nan), input, result),
                    if merge { lane(d, e, w) } else { c(w, 0) },
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let round = match unary {
        0x6506a000 | 0x6419c000 => Some((R::Environment, true)),
        0x6507a000 | 0x6419e000 => Some((R::Environment, false)),
        0x6504a000 | 0x64198000 => Some((R::NearestAway, false)),
        0x6500a000 | 0x64188000 => Some((R::NearestEven, false)),
        0x6503a000 | 0x6418e000 => Some((R::Zero, false)),
        0x6502a000 | 0x6418c000 => Some((R::NegativeInfinity, false)),
        0x6501a000 | 0x6418a000 => Some((R::PositiveInfinity, false)),
        _ => None,
    };
    let unary_op = round
        .map(|(rounding, exact)| F::RoundToIntegral { rounding, exact })
        .or_else(|| match unary {
            0x650da000 | 0x641ba000 => Some(F::SquareRoot),
            0x650ca000 | 0x641b8000 => Some(F::ReciprocalExponent),
            _ => None,
        });
    if let Some(op) = unary_op {
        if w == 8 {
            return None;
        }
        let merge = word & 0xff000000 == 0x65000000;
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                fp.step(
                    &mut r,
                    op,
                    w,
                    vec![lane(n, e, w)],
                    p(pg, e * (w as u16 / 8)),
                    if merge { lane(d, e, w) } else { c(w, 0) },
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    // Mixed-width SVE conversions have predicate/packing stride max(src,dst).
    // Active slots zero-extend, except signed FP-to-integer sign-extends.
    let conversion = word & 0xffffe000;
    let cvt = [
        (0x6589a000, 0x649aa000, 16, 32),
        (0x65c9a000, 0x64daa000, 16, 64),
        (0x6588a000, 0x649a8000, 32, 16),
        (0x65cba000, 0x64dae000, 32, 64),
        (0x65c8a000, 0x64da8000, 64, 16),
        (0x65caa000, 0x64dac000, 64, 32),
    ]
    .into_iter()
    .find_map(|(merge, zero, s, d)| {
        if conversion == merge || conversion == zero {
            Some((s, d, conversion == merge, 0u8, true))
        } else {
            None
        }
    });
    let mut spec = cvt.or_else(|| match conversion {
        0x658aa000 => Some((32, 16, true, 3, true)),
        0x649ac000 => Some((32, 16, false, 3, true)),
        _ => None,
    });
    for (base, zero, s, d) in [
        (0x6552a000, 0x645cc000, 16, 16),
        (0x6554a000, 0x645d8000, 32, 16),
        (0x6594a000, 0x649d8000, 32, 32),
        (0x65d0a000, 0x64dc8000, 32, 64),
        (0x6556a000, 0x645dc000, 64, 16),
        (0x65d4a000, 0x64dd8000, 64, 32),
        (0x65d6a000, 0x64ddc000, 64, 64),
    ] {
        for signed in [true, false] {
            let merge = base + if signed { 0 } else { 0x10000 };
            let zero = zero + if signed { 0 } else { 0x2000 };
            if conversion == merge || conversion == zero {
                spec = Some((s, d, conversion == merge, 1, signed));
            }
        }
    }
    for (base, zero, s, d) in [
        (0x655aa000, 0x645ec000, 16, 16),
        (0x655ca000, 0x645f8000, 16, 32),
        (0x655ea000, 0x645fc000, 16, 64),
        (0x659ca000, 0x649f8000, 32, 32),
        (0x65dca000, 0x64df8000, 32, 64),
        (0x65d8a000, 0x64de8000, 64, 32),
        (0x65dea000, 0x64dfc000, 64, 64),
    ] {
        for signed in [true, false] {
            let merge = base + if signed { 0 } else { 0x10000 };
            let zero = zero + if signed { 0 } else { 0x2000 };
            if conversion == merge || conversion == zero {
                spec = Some((s, d, conversion == merge, 2, signed));
            }
        }
    }
    if let Some((src, dst, merge, kind, signed)) = spec {
        let stride = src.max(dst);
        let op = match kind {
            0 => F::Convert {
                source_width: src,
                round_to_odd: false,
            },
            1 => F::FromInteger {
                source_width: src,
                signed,
                fractional_bits: 0,
            },
            3 => F::ToBFloat16,
            _ => F::ToInteger {
                source_width: src,
                signed,
                fractional_bits: 0,
                rounding: R::Zero,
            },
        };
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / stride as u16)
            .map(|e| {
                let active = p(pg, e * (stride as u16 / 8));
                let value = fp.step(
                    &mut r,
                    op,
                    dst,
                    vec![Expr::extract(lane(n, e, stride), 0, src)],
                    active.clone(),
                    c(dst, 0),
                    kind == 0,
                );
                Expr::select(
                    active,
                    Expr::cast(value, stride, kind == 2 && signed),
                    if merge {
                        lane(d, e, stride)
                    } else {
                        c(stride, 0)
                    },
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, stride);
        return Some(r);
    }
    let vector_compare = word & 0xff20e010;
    let compare = match vector_compare {
        0x65006000 => Some((0, false, false)),
        0x65006010 => Some((1, false, false)),
        0x65004000 => Some((2, true, false)),
        0x65004010 => Some((3, true, false)),
        0x6500c000 => Some((4, false, false)),
        0x6500c010 => Some((7, true, false)),
        0x6500e010 => Some((8, true, false)),
        _ => None,
    };
    let compare = compare.or_else(|| match word & 0xff3fe010 {
        0x65122000 => Some((0, false, true)),
        0x65132000 => Some((1, false, true)),
        0x65102000 => Some((2, true, true)),
        0x65102010 => Some((3, true, true)),
        0x65112000 => Some((5, true, true)),
        0x65112010 => Some((6, true, true)),
        _ => None,
    });
    if let Some((relation, signal_all_nans, zero)) = compare {
        if w == 8 {
            return None;
        }
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                let active = p(pg, e * (w as u16 / 8));
                let mut inputs = vec![lane(n, e, w), if zero { c(w, 0) } else { lane(m, e, w) }];
                if matches!(relation, 5 | 6) {
                    inputs.reverse();
                }
                if matches!(relation, 7 | 8) {
                    // FPAbs cannot raise an exception. The sign of a NaN
                    // has no effect on Compare's NZCV/exception projections.
                    inputs = inputs
                        .into_iter()
                        .map(|v| b(B::And, v, c(w, !(1u64 << (w - 1)))))
                        .collect();
                }
                let code = fp.step(
                    &mut r,
                    F::Compare {
                        source_width: w,
                        signal_all_nans,
                    },
                    4,
                    inputs,
                    active.clone(),
                    c(4, 0),
                    false,
                );
                b(
                    B::And,
                    active,
                    fp_relation(
                        if relation == 5 {
                            3
                        } else if relation == 6 || relation == 7 {
                            2
                        } else if relation == 8 {
                            3
                        } else {
                            relation
                        },
                        code,
                    ),
                )
            })
            .collect::<Vec<_>>();
        fp.finish(&mut r);
        write_p(&mut r, d & 15, &values, w, vl);
        return Some(r);
    }
    let reduce = word & 0xff3fe000;
    if matches!(
        reduce,
        0x65002000 | 0x65182000 | 0x65042000 | 0x65052000 | 0x65062000 | 0x65072000
    ) {
        if w == 8 {
            return None;
        }
        if reduce == 0x65182000 {
            non_streaming(&mut r, false);
        }
        let mut fp = FloatState::new(&mut r);
        let value = if reduce == 0x65182000 {
            let mut value = r.bind(lane(d, 0, w));
            for e in 0..vl / w as u16 {
                value = fp.step(
                    &mut r,
                    F::Add,
                    w,
                    vec![value.clone(), lane(n, e, w)],
                    p(pg, e * (w as u16 / 8)),
                    value,
                    false,
                );
            }
            value
        } else {
            let minimum = matches!(reduce, 0x65052000 | 0x65072000);
            let op = if reduce == 0x65002000 {
                F::Add
            } else {
                F::MinMax {
                    minimum,
                    numeric: matches!(reduce, 0x65042000 | 0x65052000),
                }
            };
            let inf = match w {
                16 => 0x7c00,
                32 => 0x7f800000,
                _ => 0x7ff0000000000000,
            };
            let identity = if matches!(reduce, 0x65042000 | 0x65052000) {
                let quiet = 1u64
                    << match w {
                        16 => 9,
                        32 => 22,
                        _ => 51,
                    };
                b(
                    B::Or,
                    c(w, inf | quiet),
                    b(
                        B::Shl,
                        Expr::cast(Expr::extract(fp.control.clone(), 1, 1), w, false),
                        c(w, (w - 1) as u64),
                    ),
                )
            } else {
                c(
                    w,
                    if reduce == 0x65002000 {
                        0
                    } else {
                        inf | if minimum { 0 } else { 1u64 << (w - 1) }
                    },
                )
            };
            let values = (0..vl / w as u16)
                .map(|e| {
                    r.bind(Expr::select(
                        p(pg, e * (w as u16 / 8)),
                        lane(n, e, w),
                        identity.clone(),
                    ))
                })
                .collect::<Vec<_>>();
            fp_reduce(&mut r, &mut fp, op, &values, w)
        };
        fp.finish(&mut r);
        fp_scalar_write(&mut r, d, value, vl);
        return Some(r);
    }
    // Indexed multipliers are selected independently in every 128-bit segment.
    let indexed = if matches!(word & 0xffa0fc00, 0x64200000 | 0x64200400 | 0x64202000) {
        Some((
            16,
            ((word >> 22) & 1) * 4 + ((word >> 19) & 3),
            (word >> 16) & 7,
            word & 0x2000 != 0,
        ))
    } else if matches!(word & 0xffe0fc00, 0x64a00000 | 0x64a00400 | 0x64a02000) {
        Some((32, (word >> 19) & 3, (word >> 16) & 7, word & 0x2000 != 0))
    } else if matches!(word & 0xffe0fc00, 0x64e00000 | 0x64e00400 | 0x64e02000) {
        Some((64, (word >> 20) & 1, (word >> 16) & 15, word & 0x2000 != 0))
    } else {
        None
    };
    if let Some((w, index, m, multiply)) = indexed {
        let mut fp = FloatState::new(&mut r);
        let values = (0..vl / w as u16)
            .map(|e| {
                let segment = e / (128 / w as u16) * (128 / w as u16);
                let mut inputs = vec![lane(n, e, w), lane(m, segment + index as u16, w)];
                if !multiply {
                    inputs.insert(0, lane(d, e, w));
                }
                fp.step(
                    &mut r,
                    if multiply {
                        F::Multiply
                    } else {
                        F::FusedMultiplyAdd {
                            negate_product: word & 0x400 != 0,
                            negate_addend: false,
                        }
                    },
                    w,
                    inputs,
                    c(1, 1),
                    c(w, 0),
                    false,
                )
            })
            .collect();
        fp.finish(&mut r);
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    None
}
// Integer families use the ordinary SVE lane order and the incoming register
// image. Unlike Advanced SIMD saturating operations, SVE's SatQ call discards
// its indicator and does not update FPSR.QC.
fn integer_minmax(a: Expr, z: Expr, signed: bool, minimum: bool) -> Expr {
    let less = b(if signed { B::Slt } else { B::Ult }, a.clone(), z.clone());
    Expr::select(
        less,
        if minimum { a.clone() } else { z.clone() },
        if minimum { z } else { a },
    )
}
fn integer_saturate(a: Expr, z: Expr, unsigned: bool, subtract: bool) -> Expr {
    let w = a.ty.width;
    let result = b(if subtract { B::Sub } else { B::Add }, a.clone(), z.clone());
    if unsigned {
        let overflow = if subtract {
            b(B::Ult, a, z)
        } else {
            b(B::Ult, result.clone(), a)
        };
        Expr::select(overflow, c(w, if subtract { 0 } else { mask(w) }), result)
    } else {
        let sa = Expr::extract(a, w - 1, 1);
        let sz = Expr::extract(z, w - 1, 1);
        let sr = Expr::extract(result.clone(), w - 1, 1);
        let overflow = b(
            B::And,
            if subtract {
                b(B::Xor, sa.clone(), sz)
            } else {
                not(b(B::Xor, sa.clone(), sz))
            },
            b(B::Xor, sa.clone(), sr),
        );
        Expr::select(
            overflow,
            Expr::select(sa, c(w, 1u64 << (w - 1)), c(w, mask(w - 1))),
            result,
        )
    }
}
fn integer_lookup(index: Expr, values: &[Expr]) -> Expr {
    if values.len() == 1 {
        return values[0].clone();
    }
    let half = values.len() / 2;
    Expr::select(
        Expr::extract(index.clone(), half.trailing_zeros() as u8, 1),
        integer_lookup(index.clone(), &values[half..]),
        integer_lookup(index, &values[..half]),
    )
}
fn integer_table(index: Expr, chunks: &[Expr], w: u8, inactive: Expr) -> Expr {
    let index = Expr::cast(index, 64, false);
    let per = 64 / w;
    let chunk_index = b(B::Lsr, index.clone(), c(64, per.trailing_zeros() as u64));
    let shift = b(
        B::Mul,
        b(B::And, index.clone(), c(64, (per - 1) as u64)),
        c(64, w as u64),
    );
    Expr::select(
        b(B::Ult, index, c(64, chunks.len() as u64 * per as u64)),
        Expr::cast(
            b(B::Lsr, integer_lookup(chunk_index, chunks), shift),
            w,
            false,
        ),
        inactive,
    )
}

fn integer_rounding_mla(r: &mut Recipe, old: Expr, a: Expr, z: Expr, subtract: bool) -> Expr {
    let w = old.ty.width;
    let (product, overflow) = integer_doubling_high(r, a, z, true, subtract);
    Expr::select(
        overflow,
        Expr::select(
            Expr::extract(old.clone(), w - 1, 1),
            b(B::Add, old.clone(), c(w, 1u64 << (w - 1))),
            c(w, mask(w - 1)),
        ),
        integer_saturate(old, product, false, false),
    )
}
fn integer_complex_polynomial(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let size = (word >> 22) & 3;
    let w = 8u8 << size;
    let opcode = word & 0xff20fc00;
    if matches!(opcode, 0x44000800 | 0x44000c00) {
        if w == 8 {
            return None;
        }
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let a = lane(n, e * 2, w / 2);
            let z = lane(m, e * 2 + 1, w / 2);
            let product = b(
                B::Mul,
                Expr::cast(a.clone(), w, true),
                Expr::cast(z.clone(), w, true),
            );
            let product = Expr::select(
                b(
                    B::And,
                    b(B::Eq, a, c(w / 2, 1u64 << (w / 2 - 1))),
                    b(B::Eq, z, c(w / 2, 1u64 << (w / 2 - 1))),
                ),
                c(w, mask(w - 1)),
                b(B::Shl, product, c(w, 1)),
            );
            values.push(integer_saturate(
                lane(d, e, w),
                product,
                false,
                word & (1 << 10) != 0,
            ));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(opcode, 0x45006800 | 0x45006c00) {
        if size == 2 {
            return None;
        }
        let wide = size == 0;
        let width = if wide { 128 } else { w as u16 };
        let h = (width / 2) as u8;
        let top = ((word >> 10) & 1) as u16;
        if wide {
            let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
            let enabled = Expr::select(
                Expr::register(register("a64.ssve_aes", 0, 1, 1)),
                c(1, 1),
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
            );
            r.bind(Expr::require_context(
                Expr::select(sm, enabled, c(1, 1)),
                "SVE PMULL128 streaming requires effective FA64 or SSVE_AES",
            ));
        }
        let out = if wide { 64 } else { w };
        let mut values = Vec::new();
        for e in 0..vl / width {
            let a = r.bind(Expr::cast(lane(n, e * 2 + top, h), out, false));
            let z = r.bind(lane(m, e * 2 + top, h));
            let mut low = c(out, 0);
            let mut high = c(64, 0);
            for bit in 0..h {
                let active = Expr::extract(z.clone(), bit, 1);
                low = r.bind(b(
                    B::Xor,
                    low,
                    Expr::select(
                        active.clone(),
                        b(B::Shl, a.clone(), c(out, bit as u64)),
                        c(out, 0),
                    ),
                ));
                if wide && bit != 0 {
                    high = r.bind(b(
                        B::Xor,
                        high,
                        Expr::select(
                            active,
                            b(B::Lsr, a.clone(), c(64, (64 - bit) as u64)),
                            c(64, 0),
                        ),
                    ));
                }
            }
            values.push(low);
            if wide {
                values.push(high);
            }
        }
        write_z(&mut r, d, values, out);
        return Some(r);
    }
    let plain = word & 0xff20f000;
    let indexed = word & 0xffa0f000;
    let kind = match plain {
        0x44001000 => Some(0),
        0x44002000 => Some(1),
        0x44003000 => Some(2),
        _ => None,
    };
    let indexed_kind = match indexed {
        0x44a04000 => Some(0),
        0x44a06000 => Some(1),
        0x44a07000 => Some(2),
        _ => None,
    };
    if let Some(kind) = kind.or(indexed_kind) {
        let indexed = indexed_kind.is_some();
        let w = if indexed && kind != 0 {
            if size == 2 {
                16
            } else {
                32
            }
        } else {
            w
        };
        if kind == 0 && w < 32 {
            return None;
        }
        let m = if indexed {
            (word >> 16) & if size == 2 { 7 } else { 15 }
        } else {
            m
        };
        let index = if size == 2 {
            (word >> 19) & 3
        } else {
            (word >> 20) & 1
        };
        let rotation = (word >> 10) & 3;
        let a = (rotation & 1) as u16;
        let z = a ^ 1;
        let mut values = Vec::new();
        if kind == 0 {
            let h = w / 4;
            for e in 0..vl / w as u16 {
                let src = if indexed {
                    e / (128 / w as u16) * (128 / w as u16) + index as u16
                } else {
                    e
                };
                let mut value = lane(d, e, w);
                for i in 0..2 {
                    let real = b(
                        B::Mul,
                        Expr::cast(lane(n, e * 4 + i * 2, h), w, true),
                        Expr::cast(lane(m, src * 4 + i * 2 + a, h), w, true),
                    );
                    let imaginary = b(
                        B::Mul,
                        Expr::cast(lane(n, e * 4 + i * 2 + 1, h), w, true),
                        Expr::cast(lane(m, src * 4 + i * 2 + z, h), w, true),
                    );
                    value = b(
                        if (rotation & 1) == (rotation >> 1) {
                            B::Sub
                        } else {
                            B::Add
                        },
                        b(B::Add, value, real),
                        imaginary,
                    );
                }
                values.push(value);
            }
        } else {
            for e in 0..vl / (2 * w as u16) {
                let per = 128 / (2 * w as u16);
                let src = if indexed {
                    e / per * per + index as u16
                } else {
                    e
                };
                let input = lane(n, e * 2 + a, w);
                let real = lane(m, src * 2 + a, w);
                let imaginary = lane(m, src * 2 + z, w);
                let sub_real = (rotation & 1) != (rotation >> 1);
                let sub_imaginary = rotation & 2 != 0;
                for (part, mul, subtract) in [(0, real, sub_real), (1, imaginary, sub_imaginary)] {
                    let old = lane(d, e * 2 + part, w);
                    values.push(if kind == 2 {
                        integer_rounding_mla(&mut r, old, input.clone(), mul, subtract)
                    } else {
                        b(
                            if subtract { B::Sub } else { B::Add },
                            old,
                            b(B::Mul, input.clone(), mul),
                        )
                    });
                }
            }
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    None
}

fn integer_clamp_narrow(a: Expr, h: u8, unsigned_source: bool, unsigned_result: bool) -> Expr {
    let w = a.ty.width;
    let max = if unsigned_result {
        mask(h)
    } else {
        mask(h - 1)
    };
    let min = if unsigned_result {
        0
    } else {
        (!mask(h - 1)) & mask(w)
    };
    Expr::cast(
        integer_minmax(
            integer_minmax(a, c(w, max), !unsigned_source, true),
            c(w, min),
            !unsigned_source,
            false,
        ),
        h,
        false,
    )
}
fn integer_narrow_shift(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    if word & 0xffa0c000 != 0x45200000 {
        return None;
    }
    let tsize = (((word >> 22) & 1) << 2) | ((word >> 19) & 3);
    if tsize == 0 {
        return None;
    }
    let h = 8u8 << (31 - tsize.leading_zeros());
    let w = h * 2;
    let shift = 2 * h as u32 - (tsize * 8 + ((word >> 16) & 7));
    let d = word & 31;
    let n = (word >> 5) & 31;
    let kind = (word >> 12) & 3;
    let rounded = word & (1 << 11) != 0;
    let top = word & (1 << 10) != 0;
    let unsigned = kind == 1 || kind == 3;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let mut values = Vec::new();
    for e in 0..vl / w as u16 {
        let a = lane(n, e, w);
        let a = if rounded {
            integer_round_right(a, c(w, shift as u64), unsigned)
        } else {
            b(
                if unsigned { B::Lsr } else { B::Asr },
                a,
                c(w, shift as u64),
            )
        };
        let value = if kind == 1 {
            Expr::cast(a, h, false)
        } else {
            integer_clamp_narrow(a, h, unsigned, kind != 2)
        };
        values.push(if top {
            lane(d, e * 2, h)
        } else {
            value.clone()
        });
        values.push(if top { value } else { c(h, 0) });
    }
    write_z(&mut r, d, values, h);
    Some(r)
}
// Product-high is expressed in two width-sized limbs, including the 64-bit
// case. RDM subtract negates the full product BEFORE rounding (ties differ).
fn integer_doubling_high(
    r: &mut Recipe,
    a: Expr,
    z: Expr,
    rounded: bool,
    negate: bool,
) -> (Expr, Expr) {
    let w = a.ty.width;
    let positive_overflow = if negate {
        c(1, 0)
    } else {
        b(
            B::And,
            b(B::Eq, a.clone(), c(w, 1u64 << (w - 1))),
            b(B::Eq, z.clone(), c(w, 1u64 << (w - 1))),
        )
    };
    let lo = r.bind(b(B::Mul, a.clone(), z.clone()));
    let hi = r.bind(b(B::SignedMultiplyHigh, a, z));
    let (lo, hi) = if negate {
        (
            r.bind(b(B::Sub, c(w, 0), lo.clone())),
            r.bind(b(
                B::Add,
                not(hi),
                Expr::cast(b(B::Eq, lo, c(w, 0)), w, false),
            )),
        )
    } else {
        (lo, hi)
    };
    let high = b(
        B::Or,
        b(B::Shl, hi, c(w, 1)),
        b(B::Lsr, lo.clone(), c(w, (w - 1) as u64)),
    );
    let value = if rounded {
        b(
            B::Add,
            high,
            Expr::cast(Expr::extract(lo, w - 2, 1), w, false),
        )
    } else {
        high
    };
    (r.bind(value), r.bind(positive_overflow))
}
fn integer_products(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let opcode = word & 0xff20fc00;
    let plain_long = matches!(
        opcode,
        0x45007000
            | 0x45007400
            | 0x45007800
            | 0x45007c00
            | 0x44004000
            | 0x44004400
            | 0x44004800
            | 0x44004c00
            | 0x44005000
            | 0x44005400
            | 0x44005800
            | 0x44005c00
            | 0x45006000
            | 0x45006400
            | 0x44006000
            | 0x44006400
            | 0x44006800
            | 0x44006c00
    );
    let indexed_long = word & 0xffa0f400;
    let indexed_long = matches!(
        indexed_long,
        0x44a08000
            | 0x44a08400
            | 0x44a09000
            | 0x44a09400
            | 0x44a0a000
            | 0x44a0a400
            | 0x44a0b000
            | 0x44a0b400
            | 0x44a0c000
            | 0x44a0c400
            | 0x44a0d000
            | 0x44a0d400
            | 0x44a02000
            | 0x44a02400
            | 0x44a03000
            | 0x44a03400
            | 0x44a0e000
            | 0x44a0e400
    );
    if plain_long || indexed_long {
        let w = 8u8 << ((word >> 22) & 3);
        if w == 8 {
            return None;
        }
        let h = w / 2;
        let top = ((word >> 10) & 1) as u16;
        let m = if indexed_long {
            (word >> 16) & if w == 32 { 7 } else { 15 }
        } else {
            m
        };
        let index = if indexed_long {
            (((word >> 19) & if w == 32 { 3 } else { 2 }) << 1) | ((word >> 11) & 1)
        } else {
            0
        };
        // In the 64-bit-result indexed class, i2h is bit20, not bit19.
        let index = if indexed_long && w == 64 {
            (((word >> 20) & 1) << 1) | ((word >> 11) & 1)
        } else {
            index
        };
        let doubling = if indexed_long {
            word & (1 << 15) == 0 || word & 0xf000 == 0xe000
        } else {
            matches!(
                opcode,
                0x45006000 | 0x45006400 | 0x44006000 | 0x44006400 | 0x44006800 | 0x44006c00
            )
        };
        let unsigned = !doubling && word & (if indexed_long { 1 << 12 } else { 1 << 11 }) != 0;
        let accumulate = if indexed_long {
            if doubling {
                word & (1 << 15) == 0
            } else {
                word & (1 << 14) == 0
            }
        } else {
            word >> 24 == 0x44
        };
        let subtract = accumulate
            && word
                & (if indexed_long {
                    if doubling {
                        1 << 12
                    } else {
                        1 << 13
                    }
                } else {
                    if doubling {
                        1 << 11
                    } else {
                        1 << 12
                    }
                })
                != 0;
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let src = if indexed_long {
                (e / (128 / w as u16)) * (128 / h as u16) + index as u16
            } else {
                e * 2 + top
            };
            let a = lane(n, e * 2 + top, h);
            let z = lane(m, src, h);
            let product = b(
                B::Mul,
                Expr::cast(a.clone(), w, !unsigned),
                Expr::cast(z.clone(), w, !unsigned),
            );
            let product = if doubling {
                Expr::select(
                    b(
                        B::And,
                        b(B::Eq, a, c(h, 1u64 << (h - 1))),
                        b(B::Eq, z, c(h, 1u64 << (h - 1))),
                    ),
                    c(w, mask(w - 1)),
                    b(B::Shl, product, c(w, 1)),
                )
            } else {
                product
            };
            let value = if accumulate {
                if doubling {
                    integer_saturate(lane(d, e, w), product, false, subtract)
                } else {
                    b(
                        if subtract { B::Sub } else { B::Add },
                        lane(d, e, w),
                        product,
                    )
                }
            } else {
                product
            };
            values.push(value);
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let high = matches!(opcode, 0x04207000 | 0x04207400 | 0x44007000 | 0x44007400);
    let indexed16 = matches!(
        word & 0xffa0fc00,
        0x4420f000 | 0x4420f400 | 0x44201000 | 0x44201400
    );
    let indexed32or64 = matches!(
        word & 0xffa0fc00,
        0x44a0f000 | 0x44a0f400 | 0x44a01000 | 0x44a01400
    );
    if high || indexed16 || indexed32or64 {
        let indexed = indexed16 || indexed32or64;
        let w = if indexed16 {
            16
        } else {
            8u8 << ((word >> 22) & 3)
        };
        let m = if indexed {
            (word >> 16) & if w == 64 { 15 } else { 7 }
        } else {
            m
        };
        let index = match w {
            16 => (((word >> 22) & 1) << 2) | ((word >> 19) & 3),
            32 => (word >> 19) & 3,
            _ => (word >> 20) & 1,
        };
        let accumulate = if indexed {
            word & (1 << 15) == 0
        } else {
            word >> 24 == 0x44
        };
        let subtract = accumulate && word & (1 << 10) != 0;
        let rounded = accumulate || word & (1 << 10) != 0;
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let src = if indexed {
                (e / (128 / w as u16)) * (128 / w as u16) + index as u16
            } else {
                e
            };
            let (product, overflow) =
                integer_doubling_high(&mut r, lane(n, e, w), lane(m, src, w), rounded, subtract);
            let value = if accumulate {
                let old = lane(d, e, w);
                let negative = Expr::extract(old.clone(), w - 1, 1);
                Expr::select(
                    overflow,
                    Expr::select(
                        negative,
                        b(B::Add, old.clone(), c(w, 1u64 << (w - 1))),
                        c(w, mask(w - 1)),
                    ),
                    integer_saturate(old, product, false, false),
                )
            } else {
                Expr::select(overflow, c(w, mask(w - 1)), product)
            };
            values.push(value);
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    None
}
fn integer_dot_matrix(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;

    let short_plain = word & 0xffe0fc00;
    let half_plain = matches!(short_plain, 0x44400000 | 0x44400400);
    let word_plain = matches!(short_plain, 0x4400c800 | 0x4400cc00);
    let half_indexed = matches!(word & 0xffa0fc00, 0x44200000 | 0x44200400);
    let word_indexed = matches!(word & 0xffe0fc00, 0x4480c800 | 0x4480cc00);
    if half_plain || word_plain || half_indexed || word_indexed {
        let w = if half_plain || half_indexed { 16 } else { 32 };
        let indexed = half_indexed || word_indexed;
        let unsigned = word & (1 << 10) != 0;
        let m = if indexed { (word >> 16) & 7 } else { m };
        let index = if half_indexed {
            (((word >> 22) & 1) << 2) | ((word >> 19) & 3)
        } else {
            (word >> 19) & 3
        };
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let src = if indexed {
                e / (128 / w as u16) * (128 / w as u16) + index as u16
            } else {
                e
            };
            let mut value = lane(d, e, w);
            for i in 0..2 {
                value = b(
                    B::Add,
                    value,
                    b(
                        B::Mul,
                        Expr::cast(lane(n, e * 2 + i, w / 2), w, !unsigned),
                        Expr::cast(lane(m, src * 2 + i, w / 2), w, !unsigned),
                    ),
                );
            }
            values.push(value);
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let plain = word & 0xffa0fc00;
    let indexed = word & 0xffa0fc00;
    let ordinary = matches!(plain, 0x44800000 | 0x44800400) || word & 0xffe0fc00 == 0x44807800;
    let indexed = matches!(indexed, 0x44a00000 | 0x44a00400)
        || matches!(word & 0xffe0fc00, 0x44a01800 | 0x44a01c00);
    if ordinary || indexed {
        let w = 8u8 << ((word >> 22) & 3);
        let h = w / 4;
        let mixed =
            word & 0xffe0fc00 == 0x44807800 || matches!(word & 0xffe0fc00, 0x44a01800 | 0x44a01c00);
        let unsigned1 = if mixed {
            !indexed || word & (1 << 10) == 0
        } else {
            word & (1 << 10) != 0
        };
        let unsigned2 = if mixed {
            indexed && word & (1 << 10) != 0
        } else {
            word & (1 << 10) != 0
        };
        let m = if indexed {
            (word >> 16) & if w == 64 { 15 } else { 7 }
        } else {
            m
        };
        let index = if w == 64 {
            (word >> 20) & 1
        } else {
            (word >> 19) & 3
        };
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let src = if indexed {
                (e / (128 / w as u16)) * (128 / w as u16) + index as u16
            } else {
                e
            };
            let mut value = lane(d, e, w);
            for i in 0..4 {
                value = b(
                    B::Add,
                    value,
                    b(
                        B::Mul,
                        Expr::cast(lane(n, e * 4 + i, h), w, !unsigned1),
                        Expr::cast(lane(m, src * 4 + i, h), w, !unsigned2),
                    ),
                );
            }
            values.push(value);
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let matrix = word & 0xffe0fc00;
    if matches!(matrix, 0x45009800 | 0x45c09800 | 0x45809800) {
        non_streaming(&mut r, false);
        let unsigned1 = matrix != 0x45009800;
        let unsigned2 = matrix == 0x45c09800;
        let mut values = Vec::new();
        for segment in 0..vl / 128 {
            for i in 0..2 {
                for j in 0..2 {
                    let mut value = lane(d, segment * 4 + i * 2 + j, 32);
                    for k in 0..8 {
                        value = b(
                            B::Add,
                            value,
                            b(
                                B::Mul,
                                Expr::cast(lane(n, segment * 16 + i * 8 + k, 8), 32, !unsigned1),
                                Expr::cast(lane(m, segment * 16 + j * 8 + k, 8), 32, !unsigned2),
                            ),
                        );
                    }
                    values.push(value);
                }
            }
        }
        write_z(&mut r, d, values, 32);
        return Some(r);
    }
    None
}
// Parallel stable bit compaction/expansion. Each stage moves all selected
// fields by a power of two, keeping scalable graphs bounded at maximum VL.
fn integer_bit_permute(r: &mut Recipe, data: Expr, mask: Expr, w: u8, deposit: bool) -> Expr {
    let lane_mask = |shift: u8| {
        let lane = (if w == 64 { u64::MAX } else { (1u64 << w) - 1 }) & !((1u64 << shift) - 1);
        (0..64 / w).fold(0u64, |bits, i| bits | (lane << (i * w)))
    };
    let original = mask.clone();
    let mut selected = mask;
    let mut gaps = r.bind(b(
        B::And,
        b(B::Shl, not(selected.clone()), c(64, 1)),
        c(64, lane_mask(1)),
    ));
    let mut value = if deposit {
        data
    } else {
        r.bind(b(B::And, data, selected.clone()))
    };
    let mut movements = vec![];
    let mut distance = 1u8;
    while distance < w {
        let mut prefix = gaps.clone();
        let mut shift = 1u8;
        while shift < w {
            prefix = r.bind(b(
                B::Xor,
                prefix.clone(),
                b(
                    B::And,
                    b(B::Shl, prefix, c(64, shift as u64)),
                    c(64, lane_mask(shift)),
                ),
            ));
            shift *= 2;
        }
        let movement = r.bind(b(B::And, prefix.clone(), selected.clone()));
        selected = r.bind(b(
            B::Or,
            b(B::Xor, selected, movement.clone()),
            b(B::Lsr, movement.clone(), c(64, distance as u64)),
        ));
        if !deposit {
            let moving = r.bind(b(B::And, value.clone(), movement.clone()));
            value = r.bind(b(
                B::Or,
                b(B::Xor, value, moving.clone()),
                b(B::Lsr, moving, c(64, distance as u64)),
            ));
        }
        movements.push((distance, movement));
        gaps = r.bind(b(B::And, gaps, not(prefix)));
        distance *= 2;
    }
    if deposit {
        for (distance, movement) in movements.into_iter().rev() {
            value = r.bind(b(
                B::Or,
                b(B::And, value.clone(), not(movement.clone())),
                b(B::And, b(B::Shl, value, c(64, distance as u64)), movement),
            ));
        }
        value = r.bind(b(B::And, value, original));
    }
    value
}

fn integer_carry_bitperm(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let carry = word & 0xffa0fc00;
    if matches!(carry, 0x4500d000 | 0x4500d400 | 0x4580d000 | 0x4580d400) {
        let w = 32u8 << ((word >> 22) & 1);
        let top = ((word >> 10) & 1) as u16;
        let subtract = word & (1 << 23) != 0;
        let mut values = Vec::new();
        for e in 0..vl / (2 * w as u16) {
            let a = lane(d, e * 2, w);
            let z = lane(n, e * 2 + top, w);
            let z = if subtract { not(z) } else { z };
            let cin = Expr::cast(Expr::extract(lane(m, e * 2 + 1, w), 0, 1), w, false);
            let sum = r.bind(b(B::Add, a.clone(), z));
            let value = r.bind(b(B::Add, sum.clone(), cin));
            let cout = b(
                B::Or,
                b(B::Ult, sum.clone(), a),
                b(B::Ult, value.clone(), sum),
            );
            values.push(value);
            values.push(Expr::cast(cout, w, false));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let opcode = word & 0xff20fc00;
    let w = 8u8 << ((word >> 22) & 3);
    if matches!(opcode, 0x45009000 | 0x45009400) {
        let sel = ((word >> 10) & 1) as u16;
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            values.push(if e % 2 == sel {
                b(B::Xor, lane(n, e, w), lane(m, e ^ 1, w))
            } else {
                lane(d, e, w)
            });
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(opcode, 0x4500b000 | 0x4500b400 | 0x4500b800) {
        let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
        let allowed = Expr::select(
            Expr::register(register("a64.ssve_bitperm", 0, 1, 1)),
            c(1, 1),
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
        );
        r.bind(Expr::require_context(
            Expr::select(sm, allowed, c(1, 1)),
            "SVE bit permutation streaming requires effective FA64 or SSVE_BitPerm",
        ));
        let mut values = Vec::new();
        for chunk in 0..vl / 64 {
            let data = r.bind(lane(n, chunk, 64));
            let mask = r.bind(lane(m, chunk, 64));
            let selected =
                integer_bit_permute(&mut r, data.clone(), mask.clone(), w, opcode == 0x4500b400);
            values.push(if opcode == 0x4500b800 {
                let unselected = integer_bit_permute(&mut r, data, not(mask.clone()), w, false);
                let mut grouped = c(64, 0);
                for e in 0..64 / w {
                    let count = Expr::unary(
                        UnaryOp::PopulationCount,
                        Expr::extract(mask.clone(), e * w, w),
                    );
                    let low = Expr::extract(selected.clone(), e * w, w);
                    let high = Expr::extract(unselected.clone(), e * w, w);
                    let value = b(B::Or, low, b(B::Shl, high, count));
                    grouped = b(
                        B::Or,
                        grouped,
                        b(B::Shl, Expr::cast(value, 64, false), c(64, (e * w) as u64)),
                    );
                }
                grouped
            } else {
                selected
            });
        }
        write_z(&mut r, d, values, 64);
        return Some(r);
    }
    None
}

fn integer_predicate(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 15;
    let n = (word >> 5) & 15;
    let m = (word >> 16) & 15;
    let pg = (word >> 10) & 15;
    let unary = word & 0xfffffe10;
    if matches!(unary, 0x05304000 | 0x05314000) {
        let half = vl / 16;
        let high = word & (1 << 16) != 0;
        let values = (0..half)
            .map(|e| p(n, e + if high { half } else { 0 }))
            .collect::<Vec<_>>();
        write_p(&mut r, d, &values, 16, vl);
        return Some(r);
    }
    let first = unary == 0x2558c000;
    let next = word & 0xff3ffe10 == 0x2519c400;
    if first || next {
        let w = if first { 8 } else { 8u8 << ((word >> 22) & 3) };
        let elements = vl / w as u16;
        let governing: Vec<_> = (0..elements)
            .map(|e| r.bind(p(n, e * (w as u16 / 8))))
            .collect();
        let mut past = c(16, 0);
        if next {
            for e in 0..elements {
                past = r.bind(Expr::select(
                    p(d, e * (w as u16 / 8)),
                    c(16, (e + 1) as u64),
                    past,
                ));
            }
        }
        let mut found = c(1, 0);
        let mut values = Vec::new();
        for e in 0..elements {
            let active = governing[e as usize].clone();
            let selected = r.bind(b(
                B::And,
                not(found.clone()),
                b(
                    B::And,
                    active,
                    not(b(B::Ult, c(16, e as u64), past.clone())),
                ),
            ));
            found = r.bind(b(B::Or, found, selected.clone()));
            values.push(if first {
                b(B::Or, p(d, e), selected)
            } else {
                selected
            });
        }
        pred_flags(&mut r, &governing, &values);
        write_p(&mut r, d, &values, w, vl);
        return Some(r);
    }
    let ordinary = word & 0xffffc200;
    let flags = word & (1 << 22) != 0;
    let break_ordinary = matches!(ordinary, 0x25104000 | 0x25904000)
        || flags && matches!(word & 0xffffc210, 0x25504000 | 0x25d04000);
    let previous = matches!(word & 0xffb0c210, 0x2500c000 | 0x2500c010);
    let next_break = matches!(word & 0xffffc210, 0x25184000 | 0x25584000);
    if break_ordinary || previous || next_break {
        let elements = vl / 8;
        let governing: Vec<_> = (0..elements).map(|e| r.bind(p(pg, e))).collect();
        let mut last = c(1, 0);
        if previous || next_break {
            for e in 0..elements {
                last = r.bind(Expr::select(governing[e as usize].clone(), p(n, e), last));
            }
        }
        let mut values = Vec::new();
        if next_break {
            for e in 0..elements {
                values.push(b(B::And, last.clone(), p(d, e)));
            }
            if flags {
                pred_flags(&mut r, &vec![c(1, 1); elements as usize], &values);
            }
        } else {
            let before = if previous {
                word & (1 << 4) != 0
            } else {
                word & (1 << 23) != 0
            };
            let merge = !flags && !previous && word & (1 << 4) != 0;
            let mut continuing = if previous { last } else { c(1, 1) };
            for e in 0..elements {
                let active = governing[e as usize].clone();
                let element = p(if previous { m } else { n }, e);
                let after = r.bind(b(
                    B::And,
                    continuing.clone(),
                    not(b(B::And, active.clone(), element)),
                ));
                values.push(Expr::select(
                    active,
                    if before {
                        after.clone()
                    } else {
                        continuing.clone()
                    },
                    if merge { p(d, e) } else { c(1, 0) },
                ));
                continuing = after;
            }
            if flags {
                pred_flags(&mut r, &governing, &values);
            }
        }
        write_p(&mut r, d, &values, 8, vl);
        return Some(r);
    }
    let scalar = word & 0xff20f000 == 0x0420f000;
    let vector = word & 0xff30f000 == 0x0420c000;
    if scalar || vector {
        let w = 8u8 << ((word >> 22) & 3);
        if vector && w == 8 {
            return None;
        }
        let unsigned = word & (1 << 10) != 0;
        let subtract = word & (1 << 11) != 0;
        let width = if scalar {
            if word & (1 << 20) != 0 {
                64
            } else {
                32
            }
        } else {
            w
        };
        let amount = c(
            width,
            count((word >> 5) & 31, vl / w as u16) as u64 * (((word >> 16) & 15) + 1) as u64,
        );
        let d = word & 31;
        if scalar {
            if d != 31 {
                let value = integer_saturate(gp(d, width, false), amount, unsigned, subtract);
                r.write(
                    register("a64.gpr", d as u16, 64, 64),
                    WritePolicy::ZeroUpper,
                    Expr::cast(value, 64, !unsigned),
                );
            }
        } else {
            let values = (0..vl / w as u16)
                .map(|e| integer_saturate(lane(d, e, w), amount.clone(), unsigned, subtract))
                .collect();
            write_z(&mut r, d, values, w);
        }
        return Some(r);
    }
    None
}

fn integer_widen_narrow(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let opcode = word & 0xff20fc00;
    let long = matches!(
        opcode,
        0x45000000
            | 0x45000400
            | 0x45000800
            | 0x45000c00
            | 0x45001000
            | 0x45001400
            | 0x45001800
            | 0x45001c00
    );
    let wide = matches!(
        opcode,
        0x45004000
            | 0x45004400
            | 0x45004800
            | 0x45004c00
            | 0x45005000
            | 0x45005400
            | 0x45005800
            | 0x45005c00
    );
    let narrow = matches!(
        opcode,
        0x45206000
            | 0x45206400
            | 0x45206800
            | 0x45206c00
            | 0x45207000
            | 0x45207400
            | 0x45207800
            | 0x45207c00
    );
    if long || wide || narrow {
        if w == 8 {
            return None;
        }
        let top = (word >> 10) & 1;
        let unsigned = word & (1 << 11) != 0;
        let subtract = word & (1 << 12) != 0;
        if !narrow {
            let values = (0..vl / w as u16)
                .map(|e| {
                    let a = if wide {
                        lane(n, e, w)
                    } else {
                        Expr::cast(lane(n, e * 2 + top as u16, w / 2), w, !unsigned)
                    };
                    let z = Expr::cast(lane(m, e * 2 + top as u16, w / 2), w, !unsigned);
                    b(if subtract { B::Sub } else { B::Add }, a, z)
                })
                .collect();
            write_z(&mut r, d, values, w);
        } else {
            let mut values = Vec::new();
            for e in 0..vl / w as u16 {
                // Only the middle w/2 bits survive: modulo-w add/sub is exact
                // even when the mathematical sum carries beyond w bits.
                let value = b(
                    if subtract { B::Sub } else { B::Add },
                    lane(n, e, w),
                    lane(m, e, w),
                );
                let value = if unsigned {
                    b(B::Add, value, c(w, 1u64 << (w / 2 - 1)))
                } else {
                    value
                };
                let value = Expr::extract(value, w / 2, w / 2);
                values.push(if top == 0 {
                    value.clone()
                } else {
                    lane(d, e * 2, w / 2)
                });
                values.push(if top == 0 { c(w / 2, 0) } else { value });
            }
            write_z(&mut r, d, values, w / 2);
        }
        return Some(r);
    }
    let opcode = word & 0xffa7fc00;
    if matches!(
        opcode,
        0x45204000 | 0x45204400 | 0x45204800 | 0x45204c00 | 0x45205000 | 0x45205400
    ) {
        let tsize = (((word >> 22) & 1) << 2) | ((word >> 19) & 3);
        if !matches!(tsize, 1 | 2 | 4) {
            return None;
        }
        let w = 16u8 << (31 - tsize.leading_zeros());
        let h = w / 2;
        let top = word & (1 << 10) != 0;
        let unsigned = word & (1 << 11) != 0;
        let to_unsigned = word & (1 << 12) != 0;
        let mut values = Vec::new();
        for e in 0..vl / w as u16 {
            let a = lane(n, e, w);
            let max = if unsigned || to_unsigned {
                mask(h)
            } else {
                mask(h - 1)
            };
            let min = if unsigned || to_unsigned {
                0
            } else {
                (!mask(h - 1)) & mask(w)
            };
            let value = Expr::cast(
                integer_minmax(
                    integer_minmax(a, c(w, max), !unsigned, true),
                    c(w, min),
                    !unsigned,
                    false,
                ),
                h,
                false,
            );
            values.push(if top {
                lane(d, e * 2, h)
            } else {
                value.clone()
            });
            values.push(if top { value } else { c(h, 0) });
        }
        write_z(&mut r, d, values, h);
        return Some(r);
    }
    None
}
fn integer_compare_value(a: Expr, z: Expr, unsigned: bool, code: u8) -> Expr {
    match code {
        0 => b(B::Eq, a, z),
        1 => not(b(B::Eq, a, z)),
        2 => not(b(if unsigned { B::Ult } else { B::Slt }, a, z)),
        3 => b(if unsigned { B::Ult } else { B::Slt }, z, a),
        4 => b(if unsigned { B::Ult } else { B::Slt }, a, z),
        _ => not(b(if unsigned { B::Ult } else { B::Slt }, z, a)),
    }
}
fn integer_compare_count(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let elements = vl / w as u16;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let signed_imm = match word & 0xff20e010 {
        0x25008000 => Some(0),
        0x25008010 => Some(1),
        0x25000000 => Some(2),
        0x25000010 => Some(3),
        0x25002000 => Some(4),
        0x25002010 => Some(5),
        _ => None,
    };
    let unsigned_imm = match word & 0xff202010 {
        0x24200000 => Some(2),
        0x24200010 => Some(3),
        0x24202000 => Some(4),
        0x24202010 => Some(5),
        _ => None,
    };
    let wide_compare = match word & 0xff20e010 {
        0x24002000 => Some((false, 0)),
        0x24002010 => Some((false, 1)),
        0x24004000 => Some((false, 2)),
        0x24004010 => Some((false, 3)),
        0x24006000 => Some((false, 4)),
        0x24006010 => Some((false, 5)),
        0x2400c000 => Some((true, 2)),
        0x2400c010 => Some((true, 3)),
        0x2400e000 => Some((true, 4)),
        0x2400e010 => Some((true, 5)),
        _ => None,
    };
    if signed_imm.is_some() || unsigned_imm.is_some() || wide_compare.is_some() {
        if wide_compare.is_some() && w == 64 {
            return None;
        }
        let (unsigned, code) = wide_compare.unwrap_or((
            unsigned_imm.is_some(),
            signed_imm.or(unsigned_imm).unwrap_or(0),
        ));
        let mask: Vec<_> = (0..elements)
            .map(|e| r.bind(p(pg, e * (w as u16 / 8))))
            .collect();
        let values: Vec<_> = (0..elements)
            .map(|e| {
                let a = Expr::cast(lane(n, e, w), 64, !unsigned);
                let z = if wide_compare.is_some() {
                    z(m, e * w as u16 / 64)
                } else if unsigned {
                    c(64, ((word >> 14) & 127) as u64)
                } else {
                    c(64, ((((word >> 16) & 31) as i8) << 3 >> 3) as i64 as u64)
                };
                Expr::select(
                    mask[e as usize].clone(),
                    integer_compare_value(a, z, unsigned, code),
                    c(1, 0),
                )
            })
            .collect();
        pred_flags(&mut r, &mask, &values);
        write_p(&mut r, d & 15, &values, w, vl);
        return Some(r);
    }
    let predicate_opcode = word & 0xff3ffe00;
    let modular = matches!(
        predicate_opcode,
        0x252c8800 | 0x252d8800 | 0x252c8000 | 0x252d8000
    );
    let sat = matches!(
        predicate_opcode,
        0x25288800
            | 0x25288c00
            | 0x25298800
            | 0x25298c00
            | 0x252a8800
            | 0x252a8c00
            | 0x252b8800
            | 0x252b8c00
            | 0x25288000
            | 0x25298000
            | 0x252a8000
            | 0x252b8000
    );
    let pattern_opcode = word & 0xff30fc00;
    let pattern = matches!(
        pattern_opcode,
        0x0430e000 | 0x0430e400 | 0x0430c000 | 0x0430c400
    );
    if modular || sat || pattern {
        let scalar = word & (1 << 11) != 0 && !pattern || pattern && word & (1 << 13) != 0;
        if !scalar && w == 8 {
            return None;
        }
        let subtract = if pattern {
            word & (1 << 10) != 0
        } else if modular {
            word & (1 << 16) != 0
        } else {
            word & (1 << 17) != 0
        };
        let unsigned = sat && word & (1 << 16) != 0;
        let amount = if pattern {
            c(
                64,
                count((word >> 5) & 31, elements) as u64 * (((word >> 16) & 15) + 1) as u64,
            )
        } else {
            let mut sum = c(64, 0);
            for e in 0..elements {
                sum = r.bind(b(
                    B::Add,
                    sum,
                    Expr::cast(p(n & 15, e * (w as u16 / 8)), 64, false),
                ));
            }
            sum
        };
        let scalar_width = if !sat || word & (1 << 10) != 0 {
            64
        } else {
            32
        };
        let width = if scalar { scalar_width } else { w };
        let amount = Expr::cast(amount, width, false);
        let update = |a| {
            if sat {
                integer_saturate(a, amount.clone(), unsigned, subtract)
            } else {
                b(if subtract { B::Sub } else { B::Add }, a, amount.clone())
            }
        };
        if scalar {
            if d != 31 {
                r.write(
                    register("a64.gpr", d as u16, 64, 64),
                    WritePolicy::ZeroUpper,
                    Expr::cast(update(gp(d, width, false)), 64, sat && !unsigned),
                );
            }
        } else {
            let values = (0..elements).map(|e| update(lane(d, e, w))).collect();
            write_z(&mut r, d, values, w);
        }
        return Some(r);
    }
    None
}

// Exact unbounded-integer right rounding, including counts >= element width.
fn integer_round_right(a: Expr, count: Expr, unsigned: bool) -> Expr {
    let w = a.ty.width;
    let base = b(
        if unsigned { B::Lsr } else { B::Asr },
        a.clone(),
        count.clone(),
    );
    let bit = b(
        B::And,
        b(B::Lsr, a.clone(), b(B::Sub, count.clone(), c(w, 1))),
        c(w, 1),
    );
    let ordinary = b(B::Add, base, bit);

    let at_width = if unsigned {
        b(B::Lsr, a.clone(), c(w, (w - 1) as u64))
    } else {
        c(w, 0)
    };
    Expr::select(
        b(B::Eq, count.clone(), c(w, 0)),
        a,
        Expr::select(
            b(B::Ult, count.clone(), c(w, w as u64)),
            ordinary,
            Expr::select(b(B::Eq, count, c(w, w as u64)), at_width, c(w, 0)),
        ),
    )
}
fn integer_sat_left(a: Expr, count: Expr, unsigned: bool, to_unsigned: bool) -> Expr {
    let w = a.ty.width;
    let shifted = b(B::Shl, a.clone(), count.clone());
    let recovered = b(
        if unsigned || to_unsigned {
            B::Lsr
        } else {
            B::Asr
        },
        shifted.clone(),
        count.clone(),
    );
    let negative = Expr::extract(a.clone(), w - 1, 1);
    let saturation = if unsigned || to_unsigned {
        c(w, mask(w))
    } else {
        Expr::select(negative.clone(), c(w, 1u64 << (w - 1)), c(w, mask(w - 1)))
    };
    let result = Expr::select(
        b(B::Eq, a.clone(), c(w, 0)),
        c(w, 0),
        Expr::select(
            b(B::Ult, count, c(w, w as u64)),
            Expr::select(b(B::Eq, recovered, a), shifted, saturation.clone()),
            saturation,
        ),
    );
    if to_unsigned {
        Expr::select(negative, c(w, 0), result)
    } else {
        result
    }
}
fn integer_pair_shift(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let elements = vl / w as u16;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let pg = (word >> 10) & 7;
    let pred = word & 0xff3fe000;
    let half = matches!(
        pred,
        0x44108000
            | 0x44118000
            | 0x44128000
            | 0x44138000
            | 0x44148000
            | 0x44158000
            | 0x44168000
            | 0x44178000
    );
    let pair = matches!(
        pred,
        0x4411a000 | 0x4414a000 | 0x4415a000 | 0x4416a000 | 0x4417a000
    );
    let accumulate = matches!(pred, 0x4404a000 | 0x4405a000);
    let variable = matches!(
        pred,
        0x44028000
            | 0x44038000
            | 0x44068000
            | 0x44078000
            | 0x44088000
            | 0x44098000
            | 0x440a8000
            | 0x440b8000
            | 0x440c8000
            | 0x440d8000
            | 0x440e8000
            | 0x440f8000
    );
    if half || pair || accumulate || variable {
        if accumulate && w == 8 {
            return None;
        }
        let unsigned = word & (1 << 16) != 0;
        let mut values = Vec::new();
        for e in 0..elements {
            let old = lane(d, e, w);
            let value = if half {
                let reversed = word & (1 << 17) != 0 && word & (1 << 18) != 0;
                let (a, z) = if reversed {
                    (lane(n, e, w), old.clone())
                } else {
                    (old.clone(), lane(n, e, w))
                };
                let shift = if unsigned { B::Lsr } else { B::Asr };
                if word & (1 << 17) != 0 {
                    b(
                        B::Sub,
                        b(
                            B::Sub,
                            b(shift, a.clone(), c(w, 1)),
                            b(shift, z.clone(), c(w, 1)),
                        ),
                        Expr::cast(
                            b(B::And, not(Expr::extract(a, 0, 1)), Expr::extract(z, 0, 1)),
                            w,
                            false,
                        ),
                    )
                } else {
                    let xor = b(B::Xor, a.clone(), z.clone());
                    let value = b(B::Add, b(B::And, a, z), b(shift, xor.clone(), c(w, 1)));
                    if word & (1 << 18) != 0 {
                        b(B::Add, value, b(B::And, xor, c(w, 1)))
                    } else {
                        value
                    }
                }
            } else if pair {
                let source = if e % 2 == 0 { d } else { n };
                let a = lane(source, e & !1, w);
                let z = lane(source, (e & !1) + 1, w);
                if pred == 0x4411a000 {
                    b(B::Add, a, z)
                } else {
                    integer_minmax(a, z, !unsigned, word & (1 << 17) != 0)
                }
            } else if accumulate {
                b(
                    B::Add,
                    old.clone(),
                    b(
                        B::Add,
                        Expr::cast(lane(n, e * 2, w / 2), w, !unsigned),
                        Expr::cast(lane(n, e * 2 + 1, w / 2), w, !unsigned),
                    ),
                )
            } else {
                let reversed = word & (1 << 18) != 0;
                let value = if reversed { lane(n, e, w) } else { old.clone() };
                let count = r.bind(if reversed { old.clone() } else { lane(n, e, w) });
                let negative = Expr::extract(count.clone(), w - 1, 1);
                let right = b(B::Sub, c(w, 0), count.clone());
                let rounded = word & (1 << 17) != 0;
                let left = if word & (1 << 19) != 0 {
                    integer_sat_left(value.clone(), count, unsigned, false)
                } else {
                    b(B::Shl, value.clone(), count)
                };
                let right = if rounded {
                    integer_round_right(value.clone(), right, unsigned)
                } else {
                    b(if unsigned { B::Lsr } else { B::Asr }, value, right)
                };
                Expr::select(negative, right, left)
            };
            values.push(Expr::select(p(pg, e * (w as u16 / 8)), value, old));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let immediate = matches!(
        pred,
        0x04068000 | 0x04078000 | 0x040f8000 | 0x040c8000 | 0x040d8000
    );
    let accumulate = matches!(word & 0xff20fc00, 0x4500e800 | 0x4500ec00);
    if immediate || accumulate {
        let tsize = (((word >> 22) & 3) << 2)
            | if accumulate {
                (word >> 19) & 3
            } else {
                (word >> 8) & 3
            };
        if tsize == 0 {
            return None;
        }
        let w = 8u8 << (31 - tsize.leading_zeros());
        let encoded = tsize * 8
            + if accumulate {
                (word >> 16) & 7
            } else {
                (word >> 5) & 7
            };
        let left = matches!(pred, 0x04068000 | 0x04078000 | 0x040f8000) && !accumulate;
        let count = if left {
            encoded - w as u32
        } else {
            2 * w as u32 - encoded
        };
        let unsigned = word & (if accumulate { 1 << 10 } else { 1 << 16 }) != 0;
        let values = (0..vl / w as u16)
            .map(|e| {
                let old = lane(d, e, w);
                let value = if left {
                    integer_sat_left(
                        old.clone(),
                        c(w, count as u64),
                        unsigned && pred != 0x040f8000,
                        pred == 0x040f8000,
                    )
                } else {
                    integer_round_right(
                        if accumulate {
                            lane(n, e, w)
                        } else {
                            old.clone()
                        },
                        c(w, count as u64),
                        unsigned,
                    )
                };
                if accumulate {
                    b(B::Add, old, value)
                } else {
                    Expr::select(p(pg, e * (w as u16 / 8)), value, old)
                }
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    None
}

// DecodeBitMasks(..., immediate=TRUE), with the reserved encodings rejected.
fn integer_logical_mask(imm: u32) -> Option<u64> {
    let imms = imm & 63;
    let combined = ((imm >> 12) << 6) | ((!imms) & 63);
    if combined < 2 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    let levels = (1u32 << len) - 1;
    let size = 1u8 << len;
    let count = (imms & levels) + 1;
    if count == 1u32 << len {
        return None;
    }
    let rotation = (imm >> 6) & levels;
    let ones = mask(count as u8);
    let pattern = if rotation == 0 {
        ones
    } else {
        ((ones >> rotation) | (ones << (u32::from(size) - rotation))) & mask(size)
    };
    let mut value = 0;
    for bit in (0..64).step_by(size as usize) {
        value |= pattern << bit;
    }
    Some(value)
}
fn integer_data(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let elements = vl / w as u16;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let pred = word & 0xff3fe000;
    // Stable active-element compaction. Sorting unique (inactive,index) keys
    // preserves order, and the source arm remains lazy for inactive elements.
    if matches!(word & 0xffbfe000, 0x05218000 | 0x05a18000) {
        let w = if word & (1 << 23) != 0 { 32 } else { 8 } << ((word >> 22) & 1);
        let elements = vl / w as u16;
        let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
        let allowed = Expr::select(
            Expr::register(register("a64.sme2p2", 0, 1, 1)),
            c(1, 1),
            Expr::register(register("a64.sme_fa64", 0, 1, 1)),
        );
        r.bind(Expr::require_context(
            Expr::select(sm, allowed, c(1, 1)),
            "COMPACT streaming mode requires effective FA64 or SME2p2",
        ));
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for e in 0..elements {
            let active = r.bind(p(pg, e * (w as u16 / 8)));
            keys.push(r.bind(b(
                B::Or,
                c(16, e as u64),
                b(B::Shl, Expr::cast(not(active.clone()), 16, false), c(16, 8)),
            )));
            values.push(r.bind(Expr::select(active, lane(n, e, w), c(w, 0))));
        }
        let mut size = 2;
        while size <= elements as usize {
            let mut stride = size / 2;
            while stride != 0 {
                for i in 0..elements as usize {
                    let j = i ^ stride;
                    if j > i {
                        let swap = r.bind(if i & size == 0 {
                            b(B::Ult, keys[j].clone(), keys[i].clone())
                        } else {
                            b(B::Ult, keys[i].clone(), keys[j].clone())
                        });
                        let ki =
                            r.bind(Expr::select(swap.clone(), keys[j].clone(), keys[i].clone()));
                        let kj =
                            r.bind(Expr::select(swap.clone(), keys[i].clone(), keys[j].clone()));
                        let vi = r.bind(Expr::select(
                            swap.clone(),
                            values[j].clone(),
                            values[i].clone(),
                        ));
                        let vj = r.bind(Expr::select(swap, values[i].clone(), values[j].clone()));
                        keys[i] = ki;
                        keys[j] = kj;
                        values[i] = vi;
                        values[j] = vj;
                    }
                }
                stride /= 2;
            }
            size *= 2;
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(pred, 0x052c8000 | 0x052d8000) {
        let (s1, s2) = if pred == 0x052c8000 {
            (d, n)
        } else {
            (n, (n + 1) % 32)
        };
        let mut first = c(16, 0);
        let mut last = c(16, 0);
        let mut any = c(1, 0);
        for e in 0..elements {
            let active = r.bind(p(pg, e * (w as u16 / 8)));
            first = r.bind(Expr::select(
                b(B::And, active.clone(), not(any.clone())),
                c(16, e as u64),
                first,
            ));
            last = r.bind(Expr::select(active.clone(), c(16, e as u64), last));
            any = r.bind(b(B::Or, any, active));
        }
        let count = r.bind(Expr::select(
            any.clone(),
            b(B::Add, b(B::Sub, last, first.clone()), c(16, 1)),
            c(16, 0),
        ));
        let a: Vec<_> = (0..vl / 64)
            .map(|i| r.bind(Expr::select(any.clone(), z(s1, i), c(64, 0))))
            .collect();
        let z: Vec<_> = (0..vl / 64).map(|i| r.bind(z(s2, i))).collect();
        let values = (0..elements)
            .map(|e| {
                Expr::select(
                    b(B::Ult, c(16, e as u64), count.clone()),
                    integer_table(b(B::Add, first.clone(), c(16, e as u64)), &a, w, c(w, 0)),
                    integer_table(b(B::Sub, c(16, e as u64), count.clone()), &z, w, c(w, 0)),
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let last_kind = match pred {
        0x0520a000 | 0x0521a000 => Some((false, 0)),
        0x05228000 | 0x05238000 => Some((false, 1)),
        0x0530a000 | 0x0531a000 => Some((true, 0)),
        0x052a8000 | 0x052b8000 => Some((true, 1)),
        0x05288000 | 0x05298000 => Some((true, 2)),
        _ => None,
    };
    if let Some((conditional, kind)) = last_kind {
        let before = word & (1 << 16) != 0;
        let mut index = c(16, if before { (elements - 1) as u64 } else { 0 });
        let mut any = c(1, 0);
        for e in 0..elements {
            let active = r.bind(p(pg, e * (w as u16 / 8)));
            index = r.bind(Expr::select(
                active.clone(),
                c(
                    16,
                    if before {
                        e as u64
                    } else {
                        ((e + 1) % elements) as u64
                    },
                ),
                index,
            ));
            any = r.bind(b(B::Or, any, active));
        }
        let chunks: Vec<_> = (0..vl / 64).map(|i| r.bind(z(n, i))).collect();
        let selected = r.bind(integer_table(index, &chunks, w, c(w, 0)));
        if kind == 2 {
            let values = (0..elements)
                .map(|e| Expr::select(any.clone(), selected.clone(), lane(d, e, w)))
                .collect();
            write_z(&mut r, d, values, w);
        } else {
            let fallback = if kind == 0 {
                gp(d, w, false)
            } else {
                lane(d, 0, w)
            };
            let value = if conditional {
                Expr::select(any, selected, fallback)
            } else {
                selected
            };
            if kind == 0 {
                if d != 31 {
                    r.write(
                        register("a64.gpr", d as u16, if w < 64 { 32 } else { 64 }, 64),
                        WritePolicy::ZeroUpper,
                        Expr::cast(value, if w < 64 { 32 } else { 64 }, false),
                    );
                }
            } else {
                fp_scalar_write(&mut r, d, value, vl);
            }
        }
        return Some(r);
    }
    let unary = word & 0xff3ffc00;
    if matches!(unary, 0x05243800 | 0x05343800) {
        let first = if unary == 0x05243800 {
            gp(n, w, false)
        } else {
            lane(n, 0, w)
        };
        let values = (0..elements)
            .map(|e| {
                if e == 0 {
                    first.clone()
                } else {
                    lane(d, e - 1, w)
                }
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(unary, 0x05303800 | 0x05313800 | 0x05323800 | 0x05333800) {
        if w == 8 {
            return None;
        }
        let high = word & (1 << 16) != 0;
        let signed = word & (1 << 17) == 0;
        let values = (0..elements)
            .map(|e| {
                Expr::cast(
                    lane(n, e + if high { elements } else { 0 }, w / 2),
                    w,
                    signed,
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let immediate = word & 0xfffc0000;
    if matches!(immediate, 0x05000000 | 0x05400000 | 0x05800000 | 0x05c00000) {
        let imm = integer_logical_mask((word >> 5) & 8191)?;
        let values = (0..vl / 64)
            .map(|i| {
                if immediate == 0x05c00000 {
                    c(64, imm)
                } else {
                    b(
                        match immediate {
                            0x05000000 => B::Or,
                            0x05400000 => B::Xor,
                            _ => B::And,
                        },
                        z(d, i),
                        c(64, imm),
                    )
                }
            })
            .collect();
        write_z(&mut r, d, values, 64);
        return Some(r);
    }
    let ternary = word & 0xffe0fc00;
    if matches!(
        ternary,
        0x04203800 | 0x04603800 | 0x04203c00 | 0x04603c00 | 0x04a03c00 | 0x04e03c00
    ) {
        let values = (0..vl / 64)
            .map(|i| {
                let a = z(d, i);
                let m = z(m, i);
                let k = z(n, i);
                match ternary {
                    0x04203800 => b(B::Xor, b(B::Xor, a, m), k),
                    0x04603800 => b(B::Xor, a, b(B::And, m, not(k))),
                    _ => {
                        let a = if ternary == 0x04603c00 { not(a) } else { a };
                        let m = if ternary == 0x04a03c00 { not(m) } else { m };
                        let value = b(B::Or, b(B::And, a, k.clone()), b(B::And, m, not(k)));
                        if ternary == 0x04e03c00 {
                            not(value)
                        } else {
                            value
                        }
                    }
                }
            })
            .collect();
        write_z(&mut r, d, values, 64);
        return Some(r);
    }
    if word & 0xff20fc00 == 0x04203400 {
        let tsize = (((word >> 22) & 3) << 2) | ((word >> 19) & 3);
        if tsize == 0 {
            return None;
        }
        let w = 8u8 << (31 - tsize.leading_zeros());
        let rotation = 2 * u32::from(w) - (tsize * 8 + ((word >> 16) & 7));
        let values = (0..vl / w as u16)
            .map(|e| {
                b(
                    B::Ror,
                    b(B::Xor, lane(d, e, w), lane(n, e, w)),
                    c(w, rotation as u64),
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    None
}

fn integer_extra(word: u32, address: u64, vl: u16) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let w = 8u8 << ((word >> 22) & 3);
    let elements = vl / w as u16;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let pred = word & 0xff3fe000;
    // All four signed/unsigned and ordinary/reversed division encodings.
    let divide = matches!(pred, 0x04140000 | 0x04150000 | 0x04160000 | 0x04170000);
    let minmax = matches!(pred, 0x04080000 | 0x04090000 | 0x040a0000 | 0x040b0000);
    let difference = matches!(pred, 0x040c0000 | 0x040d0000);
    let high = matches!(pred, 0x04120000 | 0x04130000);
    let saturating = matches!(
        pred,
        0x44188000
            | 0x44198000
            | 0x441a8000
            | 0x441b8000
            | 0x441c8000
            | 0x441d8000
            | 0x441e8000
            | 0x441f8000
    );
    if divide || minmax || difference || high || saturating {
        if divide && w < 32 {
            return None;
        }
        let mut values = Vec::new();
        for e in 0..elements {
            let a = lane(d, e, w);
            let z = lane(n, e, w);
            let value = if divide {
                if pred & 0x20000 != 0 {
                    b(
                        if pred & 0x10000 != 0 {
                            B::Udiv
                        } else {
                            B::Sdiv
                        },
                        z,
                        a.clone(),
                    )
                } else {
                    b(
                        if pred & 0x10000 != 0 {
                            B::Udiv
                        } else {
                            B::Sdiv
                        },
                        a.clone(),
                        z,
                    )
                }
            } else if minmax {
                integer_minmax(a.clone(), z, pred & 0x10000 == 0, pred & 0x20000 != 0)
            } else if difference {
                let less = b(
                    if pred & 0x10000 == 0 { B::Slt } else { B::Ult },
                    a.clone(),
                    z.clone(),
                );
                Expr::select(
                    less,
                    b(B::Sub, z.clone(), a.clone()),
                    b(B::Sub, a.clone(), z),
                )
            } else if high {
                b(
                    if pred & 0x10000 == 0 {
                        B::SignedMultiplyHigh
                    } else {
                        B::UnsignedMultiplyHigh
                    },
                    a.clone(),
                    z,
                )
            } else if pred == 0x441c8000 {
                let limit = b(B::Sub, c(w, mask(w - 1)), a.clone());
                Expr::select(
                    b(B::Ult, limit, z.clone()),
                    c(w, mask(w - 1)),
                    b(B::Add, a.clone(), z),
                )
            } else if pred == 0x441d8000 {
                Expr::select(
                    Expr::extract(z.clone(), w - 1, 1),
                    integer_saturate(a.clone(), b(B::Sub, c(w, 0), z.clone()), true, true),
                    integer_saturate(a.clone(), z, true, false),
                )
            } else if pred & 0x40000 != 0 {
                integer_saturate(z, a.clone(), pred & 0x10000 != 0, true)
            } else {
                integer_saturate(a.clone(), z, pred & 0x10000 != 0, pred & 0x20000 != 0)
            };
            values.push(Expr::select(p(pg, e * (w as u16 / 8)), value, a));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let multiply_add = word & 0xff20e000;
    if matches!(
        multiply_add,
        0x04004000 | 0x04006000 | 0x0400c000 | 0x0400e000
    ) {
        let mut values = Vec::new();
        for e in 0..elements {
            let old = lane(d, e, w);
            let (a, addend) = if multiply_add & 0x8000 != 0 {
                (old.clone(), lane(n, e, w))
            } else {
                (lane(n, e, w), old.clone())
            };
            let result = b(
                if multiply_add & 0x2000 != 0 {
                    B::Sub
                } else {
                    B::Add
                },
                addend,
                b(B::Mul, a, lane(m, e, w)),
            );
            values.push(Expr::select(p(pg, e * (w as u16 / 8)), result, old));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let immediate = word & 0xff3fc000;
    let imm_min = word & 0xff3fe000;
    if matches!(
        immediate,
        0x2520c000 | 0x2521c000 | 0x2523c000 | 0x2524c000 | 0x2525c000 | 0x2526c000 | 0x2527c000
    ) || matches!(
        imm_min,
        0x2528c000 | 0x2529c000 | 0x252ac000 | 0x252bc000 | 0x2530c000
    ) {
        let raw = ((word >> 5) & 255) as u64;
        let mm = matches!(imm_min, 0x2528c000 | 0x2529c000 | 0x252ac000 | 0x252bc000);
        let mul = imm_min == 0x2530c000;
        let shift = !mm && !mul && word & (1 << 13) != 0;
        if shift && w == 8 {
            return None;
        }
        let imm = if mm && imm_min & 0x10000 != 0 {
            raw
        } else if mm || mul {
            raw as u8 as i8 as i64 as u64
        } else if shift {
            raw << 8
        } else {
            raw
        };
        let mut values = Vec::new();
        for e in 0..elements {
            let a = lane(d, e, w);
            let z = c(w, imm);
            let value = if mm {
                integer_minmax(a, z, imm_min & 0x10000 == 0, imm_min & 0x20000 != 0)
            } else if mul {
                b(B::Mul, a, z)
            } else if immediate & 0x40000 != 0 {
                let unsigned = immediate & 0x10000 != 0;
                let sub = immediate & 0x20000 != 0;
                // Signed saturation immediates are positive integers, even
                // when bit7/15 exceeds the signed element range.
                if !unsigned && w < 64 {
                    let wide = b(
                        if sub { B::Sub } else { B::Add },
                        Expr::cast(a, 64, true),
                        c(64, imm),
                    );
                    Expr::cast(
                        integer_minmax(
                            integer_minmax(wide, c(64, mask(w - 1)), true, true),
                            c(64, !mask(w - 1)),
                            true,
                            false,
                        ),
                        w,
                        false,
                    )
                } else {
                    integer_saturate(a, z, unsigned, sub)
                }
            } else if immediate == 0x2523c000 {
                b(B::Sub, z, a)
            } else {
                b(
                    if immediate == 0x2520c000 {
                        B::Add
                    } else {
                        B::Sub
                    },
                    a,
                    z,
                )
            };
            values.push(value);
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let plain = word & 0xff20fc00;
    if matches!(plain, 0x04201000 | 0x04201400 | 0x04201800 | 0x04201c00) {
        let values = (0..elements)
            .map(|e| {
                integer_saturate(
                    lane(n, e, w),
                    lane(m, e, w),
                    plain & 0x400 != 0,
                    plain & 0x800 != 0,
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(pred, 0x4408a000 | 0x4409a000 | 0x440aa000 | 0x440ba000) {
        let mut values = Vec::new();
        for e in 0..elements {
            let a = lane(n, e, w);
            let negative = b(B::Sub, c(w, 0), a.clone());
            let value = Expr::select(
                b(B::Eq, a.clone(), c(w, 1u64 << (w - 1))),
                c(w, mask(w - 1)),
                if pred & 0x10000 != 0 {
                    negative
                } else {
                    Expr::select(Expr::extract(a.clone(), w - 1, 1), negative, a)
                },
            );
            values.push(Expr::select(
                p(pg, e * (w as u16 / 8)),
                value,
                if pred & 0x20000 == 0 {
                    lane(d, e, w)
                } else {
                    c(w, 0)
                },
            ));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let extension = pred & !0x100000;
    if matches!(
        extension,
        0x0400a000 | 0x0401a000 | 0x0402a000 | 0x0403a000 | 0x0404a000 | 0x0405a000
    ) {
        let source_width = 8 << ((extension >> 17) & 3);
        if w <= source_width {
            return None;
        }
        let values = (0..elements)
            .map(|e| {
                Expr::select(
                    p(pg, e * (w as u16 / 8)),
                    Expr::cast(
                        Expr::extract(lane(n, e, w), 0, source_width),
                        w,
                        extension & 0x10000 == 0,
                    ),
                    if pred & 0x100000 != 0 {
                        lane(d, e, w)
                    } else {
                        c(w, 0)
                    },
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    let unary = pred & !0x00100000;
    let arithmetic_unary = matches!(
        unary,
        0x0406a000 | 0x0407a000 | 0x0408a000 | 0x0409a000 | 0x040aa000 | 0x040ea000
    );
    let reverse = matches!(
        pred,
        0x05248000
            | 0x0524a000
            | 0x05258000
            | 0x0525a000
            | 0x05268000
            | 0x0526a000
            | 0x05278000
            | 0x0527a000
    );
    if arithmetic_unary || reverse {
        let merge = if arithmetic_unary {
            pred & 0x100000 != 0
        } else {
            pred & 0x2000 == 0
        };
        let subword = 8u8 << ((pred >> 16) & 3);
        if reverse && pred & 0x30000 != 0x30000 && w <= subword {
            return None;
        }
        let mut values = Vec::new();
        for e in 0..elements {
            let a = lane(n, e, w);
            let value = if arithmetic_unary {
                match unary {
                    0x0406a000 => Expr::select(
                        Expr::extract(a.clone(), w - 1, 1),
                        b(B::Sub, c(w, 0), a.clone()),
                        a,
                    ),
                    0x0407a000 => b(B::Sub, c(w, 0), a),
                    0x0408a000 => b(
                        B::Sub,
                        Expr::unary(
                            UnaryOp::CountLeadingZeros,
                            b(B::Xor, a.clone(), b(B::Asr, a, c(w, (w - 1) as u64))),
                        ),
                        c(w, 1),
                    ),
                    0x0409a000 => Expr::unary(UnaryOp::CountLeadingZeros, a),
                    0x040aa000 => Expr::unary(UnaryOp::PopulationCount, a),
                    _ => not(a),
                }
            } else if pred & 0x30000 == 0x30000 {
                Expr::unary(UnaryOp::ReverseBits, a)
            } else {
                let mut result = c(w, 0);
                for part in 0..w / subword {
                    result = b(
                        B::Or,
                        result,
                        b(
                            B::Shl,
                            Expr::cast(Expr::extract(a.clone(), part * subword, subword), w, false),
                            c(w, (w - subword - part * subword) as u64),
                        ),
                    );
                }
                result
            };
            values.push(Expr::select(
                p(pg, e * (w as u16 / 8)),
                value,
                if merge { lane(d, e, w) } else { c(w, 0) },
            ));
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(
        pred,
        0x04002000
            | 0x04012000
            | 0x04082000
            | 0x04092000
            | 0x040a2000
            | 0x040b2000
            | 0x04182000
            | 0x04192000
            | 0x041a2000
    ) {
        if pred == 0x04002000 && w == 64 {
            return None;
        }
        let sum = matches!(pred, 0x04002000 | 0x04012000);
        let minimum = pred & 0x20000 != 0;
        let unsigned = pred & 0x10000 != 0;
        let minmax = matches!(pred, 0x04082000 | 0x04092000 | 0x040a2000 | 0x040b2000);
        let rw = if sum { 64 } else { w };
        let init = if minmax {
            if minimum {
                if unsigned {
                    mask(w)
                } else {
                    mask(w - 1)
                }
            } else if unsigned {
                0
            } else {
                1u64 << (w - 1)
            }
        } else if pred == 0x041a2000 {
            mask(w)
        } else {
            0
        };
        let mut value = c(rw, init);
        for e in 0..elements {
            let a = Expr::cast(lane(n, e, w), rw, sum && !unsigned);
            let next = if minmax {
                integer_minmax(value.clone(), a, !unsigned, minimum)
            } else {
                b(
                    if sum {
                        B::Add
                    } else {
                        match pred {
                            0x04182000 => B::Or,
                            0x04192000 => B::Xor,
                            _ => B::And,
                        }
                    },
                    value.clone(),
                    a,
                )
            };
            value = r.bind(Expr::select(p(pg, e * (w as u16 / 8)), next, value));
        }
        fp_scalar_write(&mut r, d, value, vl);
        return Some(r);
    }
    // ZIP/UZP/TRN in every ordinary element width plus FEAT_F64MM's
    // 128-bit form. Transfer the two numeric chunks without widening Expr.
    let permute = match plain {
        0x05206000 | 0x05206400 => Some((0, (word >> 10) & 1, w)),
        0x05206800 | 0x05206c00 => Some((1, (word >> 10) & 1, w)),
        0x05207000 | 0x05207400 => Some((2, (word >> 10) & 1, w)),
        _ => match word & 0xffe0fc00 {
            0x05a00000 | 0x05a00400 => Some((0, (word >> 10) & 1, 128)),
            0x05a00800 | 0x05a00c00 => Some((1, (word >> 10) & 1, 128)),
            0x05a01800 | 0x05a01c00 => Some((2, (word >> 10) & 1, 128)),
            _ => None,
        },
    };
    if let Some((op, part, width)) = permute {
        if vl < 2 * width as u16 {
            return None;
        }
        if width == 128 {
            non_streaming(&mut r, false);
        }
        let count = vl / width as u16;
        let pairs = count / 2;
        let mut values = Vec::new();
        for e in 0..count {
            let (source, index) = match op {
                0 => (if e % 2 == 0 { n } else { m }, part as u16 * pairs + e / 2),
                1 => (if e < pairs { n } else { m }, 2 * (e % pairs) + part as u16),
                _ => (if e % 2 == 0 { n } else { m }, 2 * (e / 2) + part as u16),
            };
            if width == 128 {
                values.push(z(source, index * 2));
                values.push(z(source, index * 2 + 1));
            } else {
                values.push(lane(source, index, width));
            }
        }
        write_z(&mut r, d, values, if width == 128 { 64 } else { width });
        return Some(r);
    }
    let pp = word & 0xff30fe10;
    if matches!(
        pp,
        0x05204000 | 0x05204400 | 0x05204800 | 0x05204c00 | 0x05205000 | 0x05205400
    ) || word & 0xff3ffe10 == 0x05344000
    {
        let reverse = word & 0xff3ffe10 == 0x05344000;
        let part = ((word >> 10) & 1) as u16;
        let pairs = elements / 2;
        let group = w as u16 / 8;
        let mut values = Vec::new();
        for bit in 0..vl / 8 {
            let e = bit / group;
            let within = bit % group;
            let (source, index) = if reverse {
                (n & 15, elements - 1 - e)
            } else {
                match pp & !0x400 {
                    0x05204000 => (
                        if e % 2 == 0 { n & 15 } else { m & 15 },
                        part * pairs + e / 2,
                    ),
                    0x05204800 => (
                        if e < pairs { n & 15 } else { m & 15 },
                        2 * (e % pairs) + part,
                    ),
                    _ => (if e % 2 == 0 { n & 15 } else { m & 15 }, 2 * (e / 2) + part),
                }
            };
            values.push(p(source, index * group + within));
        }
        write_p(&mut r, d & 15, &values, 8, vl);
        return Some(r);
    }
    if word & 0xff3ffc00 == 0x05383800 {
        write_z(
            &mut r,
            d,
            (0..elements)
                .map(|e| lane(n, elements - 1 - e, w))
                .collect(),
            w,
        );
        return Some(r);
    }
    let extract = word & 0xffe0e000;
    if extract == 0x05200000 || extract == 0x05600000 {
        let (first, second) = if extract == 0x05200000 {
            (d, n)
        } else {
            (n, (n + 1) % 32)
        };
        let position = (((word >> 16) & 31) * 8 + ((word >> 10) & 7)) as u16;
        let count = vl / 8;
        let position = if position >= count { 0 } else { position };
        let values = (0..count)
            .map(|e| {
                if e + position < count {
                    lane(first, e + position, 8)
                } else {
                    lane(second, e + position - count, 8)
                }
            })
            .collect();
        write_z(&mut r, d, values, 8);
        return Some(r);
    }
    if matches!(plain, 0x05203000 | 0x05202800 | 0x05202c00) {
        let double = plain == 0x05202800;
        let keep = plain == 0x05202c00;
        let mut chunks = Vec::new();
        for source in 0..if double { 2 } else { 1 } {
            for chunk in 0..vl / 64 {
                chunks.push(r.bind(z((n + source) % 32, chunk)));
            }
        }
        let values = (0..elements)
            .map(|e| {
                integer_table(
                    lane(m, e, w),
                    &chunks,
                    w,
                    if keep { lane(d, e, w) } else { c(w, 0) },
                )
            })
            .collect();
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if word & 0xff3ffc00 == 0x05203800 {
        write_z(&mut r, d, vec![gp(n, w, true); elements as usize], w);
        return Some(r);
    }
    if plain == 0x05202000 {
        let tsz = (word >> 16) & 31;
        if tsz == 0 {
            return None;
        }
        let size = tsz.trailing_zeros();
        let width = 8u16 << size;
        let index = ((((word >> 22) & 3) << 5) | tsz) >> (size + 1);
        let value = if index < vl as u32 / width as u32 {
            if width == 128 {
                z(n, index as u16 * 2)
            } else {
                lane(n, index as u16, width as u8)
            }
        } else {
            c(if width == 128 { 64 } else { width as u8 }, 0)
        };
        if width == 128 {
            let high = if index < vl as u32 / 128 {
                z(n, index as u16 * 2 + 1)
            } else {
                c(64, 0)
            };
            write_z(
                &mut r,
                d,
                (0..vl / 64)
                    .map(|i| {
                        if i % 2 == 0 {
                            value.clone()
                        } else {
                            high.clone()
                        }
                    })
                    .collect(),
                64,
            );
        } else {
            write_z(&mut r, d, vec![value; (vl / width) as usize], width as u8);
        }
        return Some(r);
    }
    if word & 0xff3fc000 == 0x2538c000 {
        let shift = word & (1 << 13) != 0;
        if shift && w == 8 {
            return None;
        }
        let imm =
            (((word >> 5) & 255) as u8 as i8 as i64 as u64).wrapping_shl(if shift { 8 } else { 0 });
        write_z(&mut r, d, vec![c(w, imm); elements as usize], w);
        return Some(r);
    }
    None
}

/// Exact bounded SVE families. Predicate chunks use P*4+chunk (FFR=16),
/// vector chunks Z*32+chunk. Unrecognized families have no guessed transition.
pub fn a64(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    if !(128..=2048).contains(&vl) || !vl.is_power_of_two() {
        return None;
    }
    if word & 0xff000000 == 0x64000000 {
        if let Some(recipe) = arm64_bfloat_widening::a64(word, address, vl, vl) {
            return Some(recipe);
        }
    }
    if let Some(recipe) = floating(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_complex_polynomial(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_narrow_shift(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_products(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_dot_matrix(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_carry_bitperm(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_predicate(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_widen_narrow(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_compare_count(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_pair_shift(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_data(word, address, vl) {
        return Some(recipe);
    }
    if let Some(recipe) = integer_extra(word, address, vl) {
        return Some(recipe);
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let size = ((word >> 22) & 3) as u8;
    let w = 8u8 << size;
    let elements = vl / w as u16;
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let pt = word & 0xff3ffc10;
    if pt == 0x2518e000 || pt == 0x2519e000 {
        let n = count((word >> 5) & 31, elements);
        let values: Vec<_> = (0..elements).map(|e| c(1, (e < n) as u64)).collect();
        if pt == 0x2519e000 {
            pred_flags(&mut r, &vec![c(1, 1); elements as usize], &values)
        }
        write_p(&mut r, d & 15, &values, w, vl);
        return Some(r);
    }
    if word & 0xfffffff0 == 0x2518e400 {
        write_p(&mut r, d & 15, &vec![c(1, 0); (vl / 8) as usize], 8, vl);
        return Some(r);
    }
    if word & 0xff30fc00 == 0x0420e000 {
        let value = count((word >> 5) & 31, elements) as u64 * (((word >> 16) & 15) + 1) as u64;
        if d != 31 {
            r.write(
                register("a64.gpr", d as u16, 64, 64),
                WritePolicy::ZeroUpper,
                c(64, value),
            );
        }
        return Some(r);
    }
    // Predicate boolean operations use byte granularity, independently of
    // the size field used by vector arithmetic encodings.
    let predicate = word & 0xffb0c210;
    let predicate_select = word & 0xfff0c210 == 0x25004210;
    if matches!(
        predicate,
        0x25004000 | 0x25004010 | 0x25004200 | 0x25804000 | 0x25804010 | 0x25804200 | 0x25804210
    ) || predicate_select
    {
        let g = (word >> 10) & 15;
        let n = (word >> 5) & 15;
        let m = (word >> 16) & 15;
        let mask: Vec<_> = (0..vl / 8).map(|e| p(g, e)).collect();
        let values: Vec<_> = (0..vl / 8)
            .map(|e| {
                let a = p(n, e);
                let z = p(m, e);
                let value = match predicate {
                    0x25004000 => b(B::And, a, z),
                    0x25004010 => b(B::And, a, not(z)),
                    0x25004200 => b(B::Xor, a, z),
                    0x25804000 => b(B::Or, a, z),
                    0x25804010 => b(B::Or, a, not(z)),
                    0x25804200 => not(b(B::Or, a, z)),
                    0x25804210 => not(b(B::And, a, z)),
                    _ => a,
                };
                if predicate_select {
                    Expr::select(mask[e as usize].clone(), value, p(m, e))
                } else {
                    b(B::And, mask[e as usize].clone(), value)
                }
            })
            .collect();
        if !predicate_select && word & (1 << 22) != 0 {
            pred_flags(&mut r, &mask, &values)
        }
        write_p(&mut r, d & 15, &values, 8, vl);
        return Some(r);
    }
    if word & 0xffffc21f == 0x2550c000 {
        let g = (word >> 10) & 15;
        let n = (word >> 5) & 15;
        let mask: Vec<_> = (0..vl / 8).map(|e| p(g, e)).collect();
        let values: Vec<_> = (0..vl / 8).map(|e| p(n, e)).collect();
        pred_flags(&mut r, &mask, &values);
        return Some(r);
    }
    if word & 0xff3fc200 == 0x25208000 {
        let g = (word >> 10) & 15;
        let n = (word >> 5) & 15;
        let mut value = c(64, 0);
        for e in 0..elements {
            let bit = e * (w as u16 / 8);
            value = b(
                B::Add,
                value,
                Expr::cast(b(B::And, p(g, bit), p(n, bit)), 64, false),
            );
        }
        if d != 31 {
            r.write(
                register("a64.gpr", d as u16, 64, 64),
                WritePolicy::ZeroUpper,
                value,
            );
        }
        return Some(r);
    }
    let wh = word & 0xff20ec10;
    if matches!(
        wh,
        0x25200400
            | 0x25200410
            | 0x25200c00
            | 0x25200c10
            | 0x25200000
            | 0x25200010
            | 0x25200800
            | 0x25200810
    ) {
        let rw = 32u8 << ((word >> 12) & 1);
        let a = gp(n, rw, false);
        let z = gp(m, rw, false);
        let unsigned = word & 0x800 != 0;
        let reverse = word & 0x400 == 0;
        let inclusive = (word & 16 != 0) != reverse;
        let mut last = c(1, 1);
        let mut values = vec![c(1, 0); elements as usize];
        for i in 0..elements {
            let e = if reverse { elements - 1 - i } else { i };
            let v = b(
                if reverse { B::Sub } else { B::Add },
                a.clone(),
                c(rw, i as u64),
            );
            let less = if reverse {
                b(if unsigned { B::Ult } else { B::Slt }, v, z.clone())
            } else {
                b(if unsigned { B::Ult } else { B::Slt }, z.clone(), v)
            };
            let cond = if inclusive {
                not(less)
            } else if reverse {
                b(
                    if unsigned { B::Ult } else { B::Slt },
                    z.clone(),
                    b(B::Sub, a.clone(), c(rw, i as u64)),
                )
            } else {
                b(
                    if unsigned { B::Ult } else { B::Slt },
                    b(B::Add, a.clone(), c(rw, i as u64)),
                    z.clone(),
                )
            };
            last = r.bind(b(B::And, last, cond));
            values[e as usize] = last.clone();
        }
        pred_flags(&mut r, &vec![c(1, 1); elements as usize], &values);
        write_p(&mut r, d & 15, &values, w, vl);
        return Some(r);
    }
    let ix = word & 0xff20fc00;
    if matches!(ix, 0x04204000 | 0x04204400 | 0x04204800 | 0x04204c00) {
        let imm = |x: u32| c(w, ((x as i8) << 3 >> 3) as i64 as u64);
        let start = if ix & 0x400 != 0 {
            gp(n, w, false)
        } else {
            imm(n)
        };
        let step = if ix & 0x800 != 0 {
            gp(m, w, false)
        } else {
            imm(m)
        };
        write_z(
            &mut r,
            d,
            (0..elements)
                .map(|e| {
                    b(
                        B::Add,
                        start.clone(),
                        b(B::Mul, step.clone(), c(w, e as u64)),
                    )
                })
                .collect(),
            w,
        );
        return Some(r);
    }
    let plain = word & 0xff20fc00;
    let pred = word & 0xff3fe000;
    let logical = word & 0xffe0fc00;
    let op = if plain == 0x04200000 {
        Some((B::Add, false, false))
    } else if plain == 0x04200400 {
        Some((B::Sub, false, false))
    } else {
        match pred {
            0x04000000 => Some((B::Add, true, false)),
            0x04010000 => Some((B::Sub, true, false)),
            0x04030000 => Some((B::Sub, true, true)),
            0x04100000 => Some((B::Mul, true, false)),
            0x04180000 => Some((B::Or, true, false)),
            0x04190000 => Some((B::Xor, true, false)),
            0x041a0000 => Some((B::And, true, false)),
            0x041b0000 => Some((B::And, true, true)),
            _ => None,
        }
    };
    if let Some((op, predicated, reverse)) = op {
        let mut values = Vec::new();
        for e in 0..elements {
            let a = lane(if predicated { d } else { n }, e, w);
            let z = lane(if predicated { n } else { m }, e, w);
            let value = if pred == 0x041b0000 {
                b(op, a.clone(), not(z))
            } else if reverse {
                b(op, z, a.clone())
            } else {
                b(op, a.clone(), z)
            };
            values.push(if predicated {
                Expr::select(p(pg, e * (w as u16 / 8)), value, a)
            } else {
                value
            });
        }
        write_z(&mut r, d, values, w);
        return Some(r);
    }
    if matches!(logical, 0x04203000 | 0x04603000 | 0x04a03000 | 0x04e03000) {
        let op = match logical {
            0x04603000 => B::Or,
            0x04a03000 => B::Xor,
            _ => B::And,
        };
        write_z(
            &mut r,
            d,
            (0..vl / 64)
                .map(|e| {
                    b(
                        op,
                        z(n, e),
                        if logical == 0x04e03000 {
                            not(z(m, e))
                        } else {
                            z(m, e)
                        },
                    )
                })
                .collect(),
            64,
        );
        return Some(r);
    }
    if word & 0xff20c000 == 0x0520c000 {
        let pg = (word >> 10) & 15;
        write_z(
            &mut r,
            d,
            (0..elements)
                .map(|e| Expr::select(p(pg, e * (w as u16 / 8)), lane(n, e, w), lane(m, e, w)))
                .collect(),
            w,
        );
        return Some(r);
    }
    let comparison = word & 0xff20e010;
    let code = match comparison {
        0x2400a000 => Some(0),
        0x2400a010 => Some(1),
        0x24008000 => Some(2),
        0x24008010 => Some(3),
        0x24000000 => Some(4),
        0x24000010 => Some(5),
        _ => None,
    };
    if let Some(code) = code {
        let mask: Vec<_> = (0..elements).map(|e| p(pg, e * (w as u16 / 8))).collect();
        let values: Vec<_> = (0..elements)
            .map(|e| {
                b(
                    B::And,
                    mask[e as usize].clone(),
                    cmp(code, lane(n, e, w), lane(m, e, w)),
                )
            })
            .collect();
        pred_flags(&mut r, &mask, &values);
        write_p(&mut r, d & 15, &values, w, vl);
        return Some(r);
    }
    let shift = match plain {
        0x04209000 => Some((B::Asr, false, false)),
        0x04209400 => Some((B::Lsr, false, false)),
        0x04209c00 => Some((B::Shl, false, false)),
        _ => match pred {
            0x04008000 => Some((B::Asr, true, false)),
            0x04018000 => Some((B::Lsr, true, false)),
            0x04038000 => Some((B::Shl, true, false)),
            0x04108000 => Some((B::Asr, true, true)),
            0x04118000 => Some((B::Lsr, true, true)),
            0x04138000 => Some((B::Shl, true, true)),
            _ => None,
        },
    };
    if let Some((op, predicated, reg)) = shift {
        let ts = if predicated {
            (((word >> 22) & 3) << 2) | ((word >> 8) & 3)
        } else {
            (((word >> 22) & 3) << 2) | ((word >> 19) & 3)
        };
        if !reg && ts == 0 {
            return None;
        }
        let width = if reg {
            w
        } else {
            8u8 << (31 - ts.leading_zeros())
        };
        let imm = if predicated {
            (word >> 5) & 7
        } else {
            (word >> 16) & 7
        };
        let encoded = ts * 8 + imm;
        let amount = if reg {
            0
        } else if op == B::Shl {
            encoded - width as u32
        } else {
            2 * width as u32 - encoded
        };
        let values = (0..vl / width as u16)
            .map(|e| {
                let a = lane(if predicated { d } else { n }, e, width);
                let shift = if reg {
                    lane(n, e, width)
                } else {
                    c(width, amount as u64)
                };
                let value = b(op, a.clone(), shift);
                if predicated {
                    Expr::select(p(pg, e * (width as u16 / 8)), value, a)
                } else {
                    value
                }
            })
            .collect();
        write_z(&mut r, d, values, width);
        return Some(r);
    }
    if let Some(recipe) = arm64_sve_ordinary::a64(word, address, endian, vl) {
        return Some(recipe);
    }

    None
}
pub(super) fn memory_shape(word: u32) -> Option<(bool, u8, u8, bool, bool)> {
    let immediate = word & 0xfff0e000;
    let register_offset = word & 0xffe0e000;
    for (load, msize, imm, reg) in [
        (true, 32, 0xa5102000, 0xa5008000),
        (true, 64, 0xa5902000, 0xa5808000),
        (false, 32, 0xe500e000, 0xe5004000),
        (false, 64, 0xe5c0e000, 0xe5c04000),
    ] {
        if immediate == imm {
            return Some((load, msize, 128, false, false));
        }
        if register_offset == reg {
            return Some((load, msize, 128, true, false));
        }
    }
    for (msize, esize, value) in [
        (8, 8, 0xa400a000),
        (8, 16, 0xa420a000),
        (8, 32, 0xa440a000),
        (8, 64, 0xa460a000),
        (16, 16, 0xa4a0a000),
        (16, 32, 0xa4c0a000),
        (16, 64, 0xa4e0a000),
        (32, 32, 0xa540a000),
        (32, 64, 0xa560a000),
        (64, 64, 0xa5e0a000),
    ] {
        if immediate == value {
            return Some((true, msize, esize, false, false));
        }
        if register_offset == value ^ 0xe000 {
            return Some((true, msize, esize, true, false));
        }
    }
    for (msize, esize, value) in [
        (8, 16, 0xa5c0a000),
        (8, 32, 0xa5a0a000),
        (8, 64, 0xa580a000),
        (16, 32, 0xa520a000),
        (16, 64, 0xa500a000),
        (32, 64, 0xa480a000),
    ] {
        if immediate == value {
            return Some((true, msize, esize, false, true));
        }
        if register_offset == value ^ 0xe000 {
            return Some((true, msize, esize, true, true));
        }
    }
    let store_reg = word & 0xff80e000;
    if store_reg == 0xe4004000 || store_reg == 0xe4804000 {
        let msize = if store_reg == 0xe4004000 { 8 } else { 16 };
        let esize = 8 << ((word >> 21) & 3);
        if esize >= msize {
            return Some((false, msize, esize, true, false));
        }
    }
    if word & 0xffc0e000 == 0xe5404000 {
        return Some((false, 32, 32 << ((word >> 21) & 1), true, false));
    }
    // Each store gate includes its memory width and excludes quadword elements.
    let st = word & 0xff90e000;
    if st == 0xe400e000 || st == 0xe480e000 {
        let msize = if st == 0xe400e000 { 8 } else { 16 };
        let esize = 8 << ((word >> 21) & 3);
        if esize >= msize {
            return Some((false, msize, esize, false, false));
        }
    }
    if word & 0xffd0e000 == 0xe540e000 {
        return Some((false, 32, 32 << ((word >> 21) & 1), false, false));
    }
    if immediate == 0xe5e0e000 {
        return Some((false, 64, 64, false, false));
    }
    if register_offset == 0xe5e04000 {
        return Some((false, 64, 64, true, false));
    }
    None
}

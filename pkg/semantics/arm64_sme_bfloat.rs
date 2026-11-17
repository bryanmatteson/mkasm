//! SME2 BF16 dot products accumulating into groups of ZA single-vectors.
//! June 2026 bfdot_za_{zzi,zzv,zzw}: six exact physical classes. Optional
//! features/access permissions and effective FPCR controls belong to admission.
//! ZAvector index is a physical ZA row, not a tile or a contiguous group.
use super::*;
use BinaryOp as B;
fn c(width: u8, value: u64) -> Expr {
    Expr::constant(width, value)
}
fn b(op: B, left: Expr, right: Expr) -> Expr {
    Expr::binary(op, left, right)
}
#[derive(Clone, Copy)]
struct Form {
    nreg: u16,
    n: u32,
    m: u32,
    index: Option<u16>,
    grouped_m: bool,
}
fn form(word: u32) -> Option<Form> {
    let (nreg, indexed, grouped_m) = if word & 0xfff09038 == 0xc1501018 {
        (2, true, false)
    } else if word & 0xfff09078 == 0xc1509018 {
        (4, true, false)
    } else if word & 0xfff09c18 == 0xc1201010 {
        (2, false, false)
    } else if word & 0xfff09c18 == 0xc1301010 {
        (4, false, false)
    } else if word & 0xffe19c38 == 0xc1a01010 {
        (2, false, true)
    } else if word & 0xffe39c78 == 0xc1a11010 {
        (4, false, true)
    } else {
        return None;
    };
    Some(Form {
        nreg,
        n: (word >> 5)
            & if indexed || grouped_m {
                32 - u32::from(nreg)
            } else {
                31
            },
        m: (word >> 16) & if grouped_m { 32 - u32::from(nreg) } else { 15 },
        index: indexed.then_some(((word >> 10) & 3) as u16),
        grouped_m,
    })
}
fn capture(r: &mut Recipe, inputs: &mut Vec<(u32, Vec<Expr>)>, n: u32, svl: u16) {
    if inputs.iter().any(|(reg, _)| *reg == n) {
        return;
    }
    let chunks = (0..svl / 64)
        .map(|chunk| {
            r.bind(Expr::register(register(
                "a64.vector64",
                n as u16 * 32 + chunk,
                64,
                64,
            )))
        })
        .collect();
    inputs.push((n, chunks));
}
fn lane(inputs: &[(u32, Vec<Expr>)], n: u32, e: u16) -> Expr {
    let chunks = &inputs
        .iter()
        .find(|(reg, _)| *reg == n)
        .expect("captured source")
        .1;
    Expr::extract(chunks[(e / 4) as usize].clone(), ((e % 4) * 16) as u8, 16)
}
/// Exact SME2 VGx2/VGx4 BFDOT to ZA single-vectors. The three primary
/// layouts are group-by-vector, group-by-indexed-pair and group-by-group.
/// Uses a64.za64[row*32+chunk], a64.vector64[Z*32+chunk], W8..W11 and SVCR.
/// No subtract encoding exists in these six classes. FPSR/NZCV are untouched.
/// Unrelated words return None; recognized forms with unsupported SVL reject.
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    let f = form(word)?;
    if !(128..=2048).contains(&svl) || !svl.is_power_of_two() {
        return Some(Recipe::unsupported(
            "SME2 BF16 dot requires SVL 128, 256, 512, 1024 or 2048",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
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
        "SME2 BF16 dot requires streaming mode and ZA enabled",
    );
    let stride = svl / 8 / f.nreg;
    // UInt(W)+off3 is mathematical addition before modulo, not a W-width add.
    // ZA groups are stride-separated rows; never align this selector to nreg.
    let base = r.bind(b(
        B::Urem,
        b(
            B::Add,
            Expr::cast(
                Expr::register(register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64)),
                64,
                false,
            ),
            c(64, u64::from(word & 7)),
        ),
        c(64, u64::from(stride)),
    ));
    let control = r.bind(Expr::register(register("a64.fpcr", 0, 32, 32)));
    let mut inputs = Vec::new();
    for member in 0..f.nreg {
        capture(&mut r, &mut inputs, (f.n + u32::from(member)) % 32, svl);
        capture(
            &mut r,
            &mut inputs,
            f.m + if f.grouped_m { u32::from(member) } else { 0 },
            svl,
        );
    }
    // Finite indexed slices select only the affected physical ZA rows. All
    // reads use incoming state; unselected rows and bits above active SVL have
    // no outputs or dependencies. The selector addition precedes the modulo.
    for member in 0..f.nreg {
        let row = r.bind(b(B::Add, base.clone(), c(64, u64::from(member * stride))));
        let n = (f.n + u32::from(member)) % 32;
        let m = f.m + if f.grouped_m { u32::from(member) } else { 0 };
        for chunk in 0..svl / 64 {
            let destination = IndexedRegister {
                bank: "a64.za64",
                base: chunk,
                stride: 32,
                count: svl / 8,
                index: Box::new(row.clone()),
                offset: 0,
                width: 64,
                parent_width: 64,
            };
            let old = r.bind(Expr::indexed_register(destination.clone()));
            let mut updated = c(64, 0);
            for part in 0..2 {
                let e = chunk * 2 + part;
                let right = if let Some(index) = f.index {
                    2 * (e / 4 * 4 + index)
                } else {
                    2 * e
                };
                let value = Expr::float(FloatExpression {
                    operation: FloatOperation::BFloatDotAdd,
                    environment: FloatEnvironment::A64,
                    width: 32,
                    inputs: vec![
                        Expr::extract(old.clone(), (part * 32) as u8, 32),
                        lane(&inputs, n, 2 * e),
                        lane(&inputs, n, 2 * e + 1),
                        lane(&inputs, m, right),
                        lane(&inputs, m, right + 1),
                    ],
                    control: Box::new(control.clone()),
                    status: Box::new(c(32, 0)),
                    projection: FloatProjection::Value,
                });
                updated = if part == 0 {
                    Expr::cast(value, 64, false)
                } else {
                    b(
                        B::Or,
                        updated,
                        b(B::Shl, Expr::cast(value, 64, false), c(64, 32)),
                    )
                };
            }
            r.write_indexed(destination, WritePolicy::ZeroUpper, updated);
        }
    }
    Some(r)
}

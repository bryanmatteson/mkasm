//! Ordinary interleaved SVE LD2/3/4 and ST2/3/4, June 2026 primary ASL.
//! `vl` is effective CurrentVL (SVL while streaming). CheckSVEEnabled forms
//! permit either mode. Feature, translation/tag and ordinary fault policy are
//! consumer admission; exact original-width memory events remain ordered.
//! Predication suppresses inactive accesses. Loads choose SVEZEROUPPER=false
//! beyond CurrentVL. Active misaligned SP requires unrepresented SA/SA0 policy;
//! empty predicates choose the permitted CHECKSPNONEACTIVE=false behavior.
use super::*;
use BinaryOp as B;
#[derive(Clone, Copy)]
struct Shape {
    mask: u32,
    value: u32,
    width: u16,
    count: u16,
    store: bool,
    immediate: bool,
}
const SHAPES: &[Shape] = &[
    Shape {
        mask: 0xfff0e000,
        value: 0xa420e000,
        width: 8,
        count: 2,
        store: false,
        immediate: true,
    }, // ld2b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa420c000,
        width: 8,
        count: 2,
        store: false,
        immediate: false,
    }, // ld2b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa5a0e000,
        width: 64,
        count: 2,
        store: false,
        immediate: true,
    }, // ld2d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa5a0c000,
        width: 64,
        count: 2,
        store: false,
        immediate: false,
    }, // ld2d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa4a0e000,
        width: 16,
        count: 2,
        store: false,
        immediate: true,
    }, // ld2h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa4a0c000,
        width: 16,
        count: 2,
        store: false,
        immediate: false,
    }, // ld2h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa490e000,
        width: 128,
        count: 2,
        store: false,
        immediate: true,
    }, // ld2q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa4a08000,
        width: 128,
        count: 2,
        store: false,
        immediate: false,
    }, // ld2q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa520e000,
        width: 32,
        count: 2,
        store: false,
        immediate: true,
    }, // ld2w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa520c000,
        width: 32,
        count: 2,
        store: false,
        immediate: false,
    }, // ld2w_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa440e000,
        width: 8,
        count: 3,
        store: false,
        immediate: true,
    }, // ld3b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa440c000,
        width: 8,
        count: 3,
        store: false,
        immediate: false,
    }, // ld3b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa5c0e000,
        width: 64,
        count: 3,
        store: false,
        immediate: true,
    }, // ld3d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa5c0c000,
        width: 64,
        count: 3,
        store: false,
        immediate: false,
    }, // ld3d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa4c0e000,
        width: 16,
        count: 3,
        store: false,
        immediate: true,
    }, // ld3h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa4c0c000,
        width: 16,
        count: 3,
        store: false,
        immediate: false,
    }, // ld3h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa510e000,
        width: 128,
        count: 3,
        store: false,
        immediate: true,
    }, // ld3q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa5208000,
        width: 128,
        count: 3,
        store: false,
        immediate: false,
    }, // ld3q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa540e000,
        width: 32,
        count: 3,
        store: false,
        immediate: true,
    }, // ld3w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa540c000,
        width: 32,
        count: 3,
        store: false,
        immediate: false,
    }, // ld3w_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa460e000,
        width: 8,
        count: 4,
        store: false,
        immediate: true,
    }, // ld4b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa460c000,
        width: 8,
        count: 4,
        store: false,
        immediate: false,
    }, // ld4b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa5e0e000,
        width: 64,
        count: 4,
        store: false,
        immediate: true,
    }, // ld4d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa5e0c000,
        width: 64,
        count: 4,
        store: false,
        immediate: false,
    }, // ld4d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa4e0e000,
        width: 16,
        count: 4,
        store: false,
        immediate: true,
    }, // ld4h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa4e0c000,
        width: 16,
        count: 4,
        store: false,
        immediate: false,
    }, // ld4h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa590e000,
        width: 128,
        count: 4,
        store: false,
        immediate: true,
    }, // ld4q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa5a08000,
        width: 128,
        count: 4,
        store: false,
        immediate: false,
    }, // ld4q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xa560e000,
        width: 32,
        count: 4,
        store: false,
        immediate: true,
    }, // ld4w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa560c000,
        width: 32,
        count: 4,
        store: false,
        immediate: false,
    }, // ld4w_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe430e000,
        width: 8,
        count: 2,
        store: true,
        immediate: true,
    }, // st2b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4206000,
        width: 8,
        count: 2,
        store: true,
        immediate: false,
    }, // st2b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe5b0e000,
        width: 64,
        count: 2,
        store: true,
        immediate: true,
    }, // st2d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5a06000,
        width: 64,
        count: 2,
        store: true,
        immediate: false,
    }, // st2d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4b0e000,
        width: 16,
        count: 2,
        store: true,
        immediate: true,
    }, // st2h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4a06000,
        width: 16,
        count: 2,
        store: true,
        immediate: false,
    }, // st2h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4400000,
        width: 128,
        count: 2,
        store: true,
        immediate: true,
    }, // st2q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4600000,
        width: 128,
        count: 2,
        store: true,
        immediate: false,
    }, // st2q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe530e000,
        width: 32,
        count: 2,
        store: true,
        immediate: true,
    }, // st2w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5206000,
        width: 32,
        count: 2,
        store: true,
        immediate: false,
    }, // st2w_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe450e000,
        width: 8,
        count: 3,
        store: true,
        immediate: true,
    }, // st3b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4406000,
        width: 8,
        count: 3,
        store: true,
        immediate: false,
    }, // st3b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe5d0e000,
        width: 64,
        count: 3,
        store: true,
        immediate: true,
    }, // st3d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5c06000,
        width: 64,
        count: 3,
        store: true,
        immediate: false,
    }, // st3d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4d0e000,
        width: 16,
        count: 3,
        store: true,
        immediate: true,
    }, // st3h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4c06000,
        width: 16,
        count: 3,
        store: true,
        immediate: false,
    }, // st3h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4800000,
        width: 128,
        count: 3,
        store: true,
        immediate: true,
    }, // st3q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4a00000,
        width: 128,
        count: 3,
        store: true,
        immediate: false,
    }, // st3q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe550e000,
        width: 32,
        count: 3,
        store: true,
        immediate: true,
    }, // st3w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5406000,
        width: 32,
        count: 3,
        store: true,
        immediate: false,
    }, // st3w_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe470e000,
        width: 8,
        count: 4,
        store: true,
        immediate: true,
    }, // st4b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4606000,
        width: 8,
        count: 4,
        store: true,
        immediate: false,
    }, // st4b_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe5f0e000,
        width: 64,
        count: 4,
        store: true,
        immediate: true,
    }, // st4d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5e06000,
        width: 64,
        count: 4,
        store: true,
        immediate: false,
    }, // st4d_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4f0e000,
        width: 16,
        count: 4,
        store: true,
        immediate: true,
    }, // st4h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4e06000,
        width: 16,
        count: 4,
        store: true,
        immediate: false,
    }, // st4h_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe4c00000,
        width: 128,
        count: 4,
        store: true,
        immediate: true,
    }, // st4q_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4e00000,
        width: 128,
        count: 4,
        store: true,
        immediate: false,
    }, // st4q_z_p_br
    Shape {
        mask: 0xfff0e000,
        value: 0xe570e000,
        width: 32,
        count: 4,
        store: true,
        immediate: true,
    }, // st4w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5606000,
        width: 32,
        count: 4,
        store: true,
        immediate: false,
    }, // st4w_z_p_br
];
fn c(width: u8, value: u64) -> Expr {
    Expr::constant(width, value)
}
fn b(op: B, left: Expr, right: Expr) -> Expr {
    Expr::binary(op, left, right)
}
fn predicate(pg: u32, e: u16, width: u16) -> Expr {
    let bit = e * (width / 8);
    Expr::extract(
        Expr::register(register(
            "a64.predicate64",
            pg as u16 * 4 + bit / 64,
            64,
            64,
        )),
        (bit % 64) as u8,
        1,
    )
}
fn lane(n: u32, e: u16, width: u8) -> Expr {
    let bit = e * u16::from(width);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        width,
    )
}
fn any_active(mut values: Vec<Expr>) -> Expr {
    while values.len() > 1 {
        values = values
            .chunks(2)
            .map(|pair| {
                if pair.len() == 1 {
                    pair[0].clone()
                } else {
                    b(B::Or, pair[0].clone(), pair[1].clone())
                }
            })
            .collect();
    }
    values.pop().unwrap()
}
/// All sixty B/H/W/D/Q scalar-base plus register/signed-immediate classes.
/// Rm=31 is excluded by register-form diagrams; register groups wrap modulo32.
/// Q transfers remain one128-bit event per member, never two scalar accesses.
pub fn a64(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    let s = *SHAPES.iter().find(|s| word & s.mask == s.value)?;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pg = (word >> 10) & 7;
    let first = word & 31;
    if !s.immediate && m == 31 {
        return None;
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "structured SVE CurrentVL must be128,256,512,1024 or2048",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let elements = vl / s.width;
    let active: Vec<_> = (0..elements).map(|e| predicate(pg, e, s.width)).collect();
    let base = Expr::register(register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    ));
    if n == 31 {
        let aligned = b(B::Eq, b(B::And, base.clone(), c(64, 15)), c(64, 0));
        r.guard = Expr::require_context(
            Expr::select(any_active(active.clone()), aligned, c(1, 1)),
            "active misaligned structured SVE SP requires architectural alignment policy",
        );
    }
    let offset = if s.immediate {
        let imm = (((word >> 16) & 15) as i64) << 60 >> 60;
        c(64, (imm * i64::from(s.count) * i64::from(vl / 8)) as u64)
    } else {
        b(
            B::Shl,
            Expr::register(register("a64.gpr", m as u16, 64, 64)),
            c(64, u64::from(s.width.trailing_zeros() - 3)),
        )
    };
    let start = b(B::Add, base, offset);
    let mut values = vec![Vec::<Expr>::new(); s.count as usize];
    for e in 0..elements {
        for member in 0..s.count {
            let addr = b(
                B::Add,
                start.clone(),
                c(64, u64::from((e * s.count + member) * (s.width / 8))),
            );
            let selected = active[e as usize].clone();
            let vector = (first + u32::from(member)) % 32;
            if s.width == 128 {
                let memory = WideMemory {kind: Default::default(), privilege: Default::default(),
                    address: Box::new(addr),
                    width: 128,
                    endian,
                };
                if s.store {
                    r.store_wide_conditional(
                        selected,
                        memory,
                        vec![lane(vector, e * 2, 64), lane(vector, e * 2 + 1, 64)],
                    );
                } else {
                    let chunks = r.load_wide_conditional(selected.clone(), memory);
                    for chunk in chunks {
                        values[member as usize].push(Expr::select(
                            selected.clone(),
                            chunk,
                            c(64, 0),
                        ));
                    }
                }
            } else {
                let width = s.width as u8;
                let memory = Memory {kind: Default::default(), privilege: Default::default(),
                    address: Box::new(addr),
                    width,
                    endian,
                };
                if s.store {
                    r.store_conditional(selected, memory, lane(vector, e, width));
                } else {
                    let value = r
                        .load_ordered_conditional(selected.clone(), memory)
                        .expect("audited scalar width");
                    values[member as usize].push(Expr::select(selected, value, c(width, 0)));
                }
            }
        }
    }
    if !s.store {
        let width = s.width.min(64) as u8;
        for member in 0..s.count {
            let vector = (first + u32::from(member)) % 32;
            for (chunk, lanes) in values[member as usize]
                .chunks(64 / usize::from(width))
                .enumerate()
            {
                let mut value = c(64, 0);
                for (i, lane) in lanes.iter().enumerate() {
                    value = b(
                        B::Or,
                        value,
                        b(
                            B::Shl,
                            Expr::cast(lane.clone(), 64, false),
                            c(64, (i * usize::from(width)) as u64),
                        ),
                    );
                }
                let value = r.bind(value);
                r.write(
                    register("a64.vector64", vector as u16 * 32 + chunk as u16, 64, 64),
                    WritePolicy::ZeroUpper,
                    value,
                );
            }
        }
    }
    Some(r)
}

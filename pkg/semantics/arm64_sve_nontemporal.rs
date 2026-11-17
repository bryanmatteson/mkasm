//! Single-vector SVE/SVE2 non-temporal loads/stores, June 2026 ASL.
//! Each active lane retains its architectural memory width and lane order.
//! Non-temporal is a cache hint: this schema models no cache or timing effect.
//! Feature/access admission belongs to the consumer. `vl` is CurrentVL (SVL
//! when streaming). Gather/scatter needs non-streaming mode or effective FA64;
//! contiguous CheckSVEEnabled forms permit streaming mode. Address arithmetic
//! uses ordinary 64-bit addresses; tagged/MTE access needs consumer admission.
//! Writes preserve backing chunks beyond CurrentVL, the permitted
//! SVEZEROUPPER=false choice, without consuming those incoming chunks.
use super::*;
use BinaryOp as B;
#[derive(Clone, Copy)]
struct Shape {
    mask: u32,
    value: u32,
    element: u8,
    memory: u8,
    store: bool,
    signed: bool,
    mode: u8,
}
const SHAPES: &[Shape] = &[
    Shape {
        mask: 0xffe0e000,
        value: 0x8400a000,
        element: 32,
        memory: 8,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1b_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc400c000,
        element: 64,
        memory: 8,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1b_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xa400e000,
        element: 8,
        memory: 8,
        store: false,
        signed: false,
        mode: 2,
    }, // ldnt1b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa400c000,
        element: 8,
        memory: 8,
        store: false,
        signed: false,
        mode: 1,
    }, // ldnt1b_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0xc580c000,
        element: 64,
        memory: 64,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1d_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xa580e000,
        element: 64,
        memory: 64,
        store: false,
        signed: false,
        mode: 2,
    }, // ldnt1d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa580c000,
        element: 64,
        memory: 64,
        store: false,
        signed: false,
        mode: 1,
    }, // ldnt1d_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0x8480a000,
        element: 32,
        memory: 16,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1h_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc480c000,
        element: 64,
        memory: 16,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1h_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xa480e000,
        element: 16,
        memory: 16,
        store: false,
        signed: false,
        mode: 2,
    }, // ldnt1h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa480c000,
        element: 16,
        memory: 16,
        store: false,
        signed: false,
        mode: 1,
    }, // ldnt1h_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0x84008000,
        element: 32,
        memory: 8,
        store: false,
        signed: true,
        mode: 0,
    }, // ldnt1sb_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc4008000,
        element: 64,
        memory: 8,
        store: false,
        signed: true,
        mode: 0,
    }, // ldnt1sb_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0x84808000,
        element: 32,
        memory: 16,
        store: false,
        signed: true,
        mode: 0,
    }, // ldnt1sh_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc4808000,
        element: 64,
        memory: 16,
        store: false,
        signed: true,
        mode: 0,
    }, // ldnt1sh_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc5008000,
        element: 64,
        memory: 32,
        store: false,
        signed: true,
        mode: 0,
    }, // ldnt1sw_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0x8500a000,
        element: 32,
        memory: 32,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1w_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xc500c000,
        element: 64,
        memory: 32,
        store: false,
        signed: false,
        mode: 0,
    }, // ldnt1w_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xa500e000,
        element: 32,
        memory: 32,
        store: false,
        signed: false,
        mode: 2,
    }, // ldnt1w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xa500c000,
        element: 32,
        memory: 32,
        store: false,
        signed: false,
        mode: 1,
    }, // ldnt1w_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0xe4402000,
        element: 32,
        memory: 8,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1b_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xe4002000,
        element: 64,
        memory: 8,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1b_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xe410e000,
        element: 8,
        memory: 8,
        store: true,
        signed: false,
        mode: 2,
    }, // stnt1b_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4006000,
        element: 8,
        memory: 8,
        store: true,
        signed: false,
        mode: 1,
    }, // stnt1b_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0xe5802000,
        element: 64,
        memory: 64,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1d_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xe590e000,
        element: 64,
        memory: 64,
        store: true,
        signed: false,
        mode: 2,
    }, // stnt1d_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5806000,
        element: 64,
        memory: 64,
        store: true,
        signed: false,
        mode: 1,
    }, // stnt1d_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0xe4c02000,
        element: 32,
        memory: 16,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1h_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xe4802000,
        element: 64,
        memory: 16,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1h_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xe490e000,
        element: 16,
        memory: 16,
        store: true,
        signed: false,
        mode: 2,
    }, // stnt1h_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe4806000,
        element: 16,
        memory: 16,
        store: true,
        signed: false,
        mode: 1,
    }, // stnt1h_z_p_br
    Shape {
        mask: 0xffe0e000,
        value: 0xe5402000,
        element: 32,
        memory: 32,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1w_z_p_ar
    Shape {
        mask: 0xffe0e000,
        value: 0xe5002000,
        element: 64,
        memory: 32,
        store: true,
        signed: false,
        mode: 0,
    }, // stnt1w_z_p_ar
    Shape {
        mask: 0xfff0e000,
        value: 0xe510e000,
        element: 32,
        memory: 32,
        store: true,
        signed: false,
        mode: 2,
    }, // stnt1w_z_p_bi
    Shape {
        mask: 0xffe0e000,
        value: 0xe5006000,
        element: 32,
        memory: 32,
        store: true,
        signed: false,
        mode: 1,
    }, // stnt1w_z_p_br
];
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, l: Expr, r: Expr) -> Expr {
    Expr::binary(op, l, r)
}
fn lane(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w);
    Expr::extract(
        Expr::register(register("a64.vector64", n as u16 * 32 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        w,
    )
}
fn predicate(n: u32, e: u16, w: u8) -> Expr {
    let bit = e * u16::from(w) / 8;
    Expr::extract(
        Expr::register(register("a64.predicate64", n as u16 * 4 + bit / 64, 64, 64)),
        (bit % 64) as u8,
        1,
    )
}
fn x(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, 64, 64))
    }
}
/// LDNT1[BHWD]/LDNT1S[BHW] and STNT1[BHWD], vector-base + X offset or
/// contiguous scalar-base + scaled X / signed VL immediate. Signed loads
/// exist only in vector-base classes. Unrelated/reserved words return None;
/// recognized words with invalid VL return an explicit unsupported recipe.
pub fn a64(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    let s = *SHAPES.iter().find(|s| word & s.mask == s.value)?;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let d = word & 31;
    let pg = (word >> 10) & 7;
    // The contiguous scalar register diagrams explicitly exclude Rm=31.
    // Vector-base classes allow XZR as their unscaled offset (never SP).
    if s.mode == 1 && m == 31 {
        return None;
    }
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        return Some(Recipe::unsupported(
            "SVE CurrentVL must be 128, 256, 512, 1024 or 2048",
            address.wrapping_add(4),
            64,
        ));
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if s.mode == 0 {
        let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
        r.guard = Expr::require_context(
            Expr::select(
                sm,
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
            "non-temporal gather/scatter requires non-streaming mode or effective FA64",
        );
    }
    if s.mode != 0 && n == 31 {
        let mut active: Vec<_> = (0..vl / u16::from(s.element))
            .map(|e| predicate(pg, e, s.element))
            .collect();
        // Keep MAX_VL byte masks within native expression-depth limits.
        while active.len() > 1 {
            active = active
                .chunks(2)
                .map(|p| {
                    if p.len() == 2 {
                        b(B::Or, p[0].clone(), p[1].clone())
                    } else {
                        p[0].clone()
                    }
                })
                .collect();
        }
        let any = active.pop().unwrap();
        let sp = Expr::register(register("a64.sp", 0, 64, 64));
        let aligned = b(B::Eq, b(B::And, sp, c(64, 15)), c(64, 0));
        // CHECKSPNONEACTIVE=false is permitted. Active misaligned SP requires
        // unrepresented SA/SA0 policy; never fabricate a fault or permit access.
        r.guard = Expr::require_context(
            Expr::select(any, aligned, c(1, 1)),
            "active misaligned SVE SP needs target alignment policy",
        );
    }
    let mut values = vec![];
    for e in 0..vl / u16::from(s.element) {
        let active = predicate(pg, e, s.element);
        let addr = if s.mode == 0 {
            b(B::Add, Expr::cast(lane(n, e, s.element), 64, false), x(m))
        } else {
            let base = if n == 31 {
                Expr::register(register("a64.sp", 0, 64, 64))
            } else {
                x(n)
            };
            let offset = if s.mode == 1 {
                b(
                    B::Shl,
                    x(m),
                    c(64, u64::from(s.memory.trailing_zeros() - 3)),
                )
            } else {
                let imm = ((word >> 16) & 15) as i64;
                let imm = (imm << 60) >> 60;
                c(64, (imm * (i64::from(vl) / 8)) as u64)
            };
            b(
                B::Add,
                b(B::Add, base, offset),
                c(64, u64::from(e) * u64::from(s.memory / 8)),
            )
        };
        let memory = Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(addr),
            width: s.memory,
            endian,
        };
        if s.store {
            r.store_conditional(
                active,
                memory,
                Expr::cast(lane(d, e, s.element), s.memory, false),
            );
        } else {
            let value = r
                .load_ordered_conditional(active.clone(), memory)
                .expect("audited SVE scalar widths");
            values.push(Expr::select(
                active,
                Expr::cast(value, s.element, s.signed),
                c(s.element, 0),
            ));
        }
    }
    if !s.store {
        for (chunk, elements) in values.chunks(64 / usize::from(s.element)).enumerate() {
            let value = elements.iter().enumerate().fold(c(64, 0), |a, (i, v)| {
                b(
                    B::Or,
                    a,
                    b(
                        B::Shl,
                        Expr::cast(v.clone(), 64, false),
                        c(64, i as u64 * u64::from(s.element)),
                    ),
                )
            });
            let value = r.bind(value);
            r.write(
                register("a64.vector64", d as u16 * 32 + chunk as u16, 64, 64),
                WritePolicy::ZeroUpper,
                value,
            );
        }
    }
    Some(r)
}

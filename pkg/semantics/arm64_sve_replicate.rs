//! Complete scalar/128-bit/256-bit SVE replicate loads, June2026 primary ASL.
//! Accesses keep their native element width, byte order and predicate order.
//! Scalar broadcast accesses memory once; block broadcast only consults the
//! low block predicate bits and repeats the loaded, zero-masked block.
use super::*;
use BinaryOp as B;
#[derive(Clone, Copy)]
struct Shape {
    mask: u32,
    base: u32,
    width: u8,
    memory: u8,
    block: u16,
    signed: bool,
    immediate: bool,
}
const SHAPES: &[Shape] = &[
    Shape {
        mask: 0xffc0e000,
        base: 0x8440a000,
        width: 16,
        memory: 8,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rb_z_p_bi_u16
    Shape {
        mask: 0xffc0e000,
        base: 0x8440c000,
        width: 32,
        memory: 8,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rb_z_p_bi_u32
    Shape {
        mask: 0xffc0e000,
        base: 0x8440e000,
        width: 64,
        memory: 8,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rb_z_p_bi_u64
    Shape {
        mask: 0xffc0e000,
        base: 0x84408000,
        width: 8,
        memory: 8,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rb_z_p_bi_u8
    Shape {
        mask: 0xffc0e000,
        base: 0x85c0e000,
        width: 64,
        memory: 64,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rd_z_p_bi_u64
    Shape {
        mask: 0xffc0e000,
        base: 0x84c0a000,
        width: 16,
        memory: 16,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rh_z_p_bi_u16
    Shape {
        mask: 0xffc0e000,
        base: 0x84c0c000,
        width: 32,
        memory: 16,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rh_z_p_bi_u32
    Shape {
        mask: 0xffc0e000,
        base: 0x84c0e000,
        width: 64,
        memory: 16,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rh_z_p_bi_u64
    Shape {
        mask: 0xfff0e000,
        base: 0xa4202000,
        width: 8,
        memory: 8,
        block: 256,
        signed: false,
        immediate: true,
    }, // ld1rob_z_p_bi_u8
    Shape {
        mask: 0xffe0e000,
        base: 0xa4200000,
        width: 8,
        memory: 8,
        block: 256,
        signed: false,
        immediate: false,
    }, // ld1rob_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa5a02000,
        width: 64,
        memory: 64,
        block: 256,
        signed: false,
        immediate: true,
    }, // ld1rod_z_p_bi_u64
    Shape {
        mask: 0xffe0e000,
        base: 0xa5a00000,
        width: 64,
        memory: 64,
        block: 256,
        signed: false,
        immediate: false,
    }, // ld1rod_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa4a02000,
        width: 16,
        memory: 16,
        block: 256,
        signed: false,
        immediate: true,
    }, // ld1roh_z_p_bi_u16
    Shape {
        mask: 0xffe0e000,
        base: 0xa4a00000,
        width: 16,
        memory: 16,
        block: 256,
        signed: false,
        immediate: false,
    }, // ld1roh_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa5202000,
        width: 32,
        memory: 32,
        block: 256,
        signed: false,
        immediate: true,
    }, // ld1row_z_p_bi_u32
    Shape {
        mask: 0xffe0e000,
        base: 0xa5200000,
        width: 32,
        memory: 32,
        block: 256,
        signed: false,
        immediate: false,
    }, // ld1row_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa4002000,
        width: 8,
        memory: 8,
        block: 128,
        signed: false,
        immediate: true,
    }, // ld1rqb_z_p_bi_u8
    Shape {
        mask: 0xffe0e000,
        base: 0xa4000000,
        width: 8,
        memory: 8,
        block: 128,
        signed: false,
        immediate: false,
    }, // ld1rqb_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa5802000,
        width: 64,
        memory: 64,
        block: 128,
        signed: false,
        immediate: true,
    }, // ld1rqd_z_p_bi_u64
    Shape {
        mask: 0xffe0e000,
        base: 0xa5800000,
        width: 64,
        memory: 64,
        block: 128,
        signed: false,
        immediate: false,
    }, // ld1rqd_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa4802000,
        width: 16,
        memory: 16,
        block: 128,
        signed: false,
        immediate: true,
    }, // ld1rqh_z_p_bi_u16
    Shape {
        mask: 0xffe0e000,
        base: 0xa4800000,
        width: 16,
        memory: 16,
        block: 128,
        signed: false,
        immediate: false,
    }, // ld1rqh_z_p_br_contiguous
    Shape {
        mask: 0xfff0e000,
        base: 0xa5002000,
        width: 32,
        memory: 32,
        block: 128,
        signed: false,
        immediate: true,
    }, // ld1rqw_z_p_bi_u32
    Shape {
        mask: 0xffe0e000,
        base: 0xa5000000,
        width: 32,
        memory: 32,
        block: 128,
        signed: false,
        immediate: false,
    }, // ld1rqw_z_p_br_contiguous
    Shape {
        mask: 0xffc0e000,
        base: 0x85c0c000,
        width: 16,
        memory: 8,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsb_z_p_bi_s16
    Shape {
        mask: 0xffc0e000,
        base: 0x85c0a000,
        width: 32,
        memory: 8,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsb_z_p_bi_s32
    Shape {
        mask: 0xffc0e000,
        base: 0x85c08000,
        width: 64,
        memory: 8,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsb_z_p_bi_s64
    Shape {
        mask: 0xffc0e000,
        base: 0x8540a000,
        width: 32,
        memory: 16,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsh_z_p_bi_s32
    Shape {
        mask: 0xffc0e000,
        base: 0x85408000,
        width: 64,
        memory: 16,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsh_z_p_bi_s64
    Shape {
        mask: 0xffc0e000,
        base: 0x84c08000,
        width: 64,
        memory: 32,
        block: 0,
        signed: true,
        immediate: true,
    }, // ld1rsw_z_p_bi_s64
    Shape {
        mask: 0xffc0e000,
        base: 0x8540c000,
        width: 32,
        memory: 32,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rw_z_p_bi_u32
    Shape {
        mask: 0xffc0e000,
        base: 0x8540e000,
        width: 64,
        memory: 32,
        block: 0,
        signed: false,
        immediate: true,
    }, // ld1rw_z_p_bi_u64
];
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, x: Expr, y: Expr) -> Expr {
    Expr::binary(op, x, y)
}
fn p(n: u32, e: u16, w: u8) -> Expr {
    let at = e * u16::from(w) / 8;
    Expr::extract(
        Expr::register(register("a64.predicate64", n as u16 * 4 + at / 64, 64, 64)),
        (at % 64) as u8,
        1,
    )
}
fn any(bits: &[Expr]) -> Expr {
    if bits.len() == 1 {
        return bits[0].clone();
    }
    let at = bits.len() / 2;
    b(B::Or, any(&bits[..at]), any(&bits[at..]))
}
pub fn a64(word: u32, address: u64, endian: Endian, vl: u16) -> Option<Recipe> {
    let s = *SHAPES.iter().find(|s| word & s.mask == s.base)?;
    let next = address.wrapping_add(4);
    let m = (word >> 16) & 31;
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) || s.block > vl || !s.immediate && m == 31 {
        return Some(Recipe::unsupported(
            "reserved SVE replicate length or offset register",
            next,
            64,
        ));
    }
    let d = word & 31;
    let n = (word >> 5) & 31;
    let pg = (word >> 10) & 7;
    let mut r = Recipe::new(next, 64);
    if s.block == 256 {
        let sm = Expr::extract(Expr::register(register("a64.svcr", 0, 64, 64)), 0, 1);
        r.guard = Expr::require_context(
            Expr::select(
                sm,
                Expr::register(register("a64.sme_fa64", 0, 1, 1)),
                c(1, 1),
            ),
            "SVE octaword replicate requires non-streaming mode or effective FA64",
        );
    }
    let count = if s.block == 0 { vl } else { s.block } / u16::from(s.width);
    let active: Vec<_> = (0..count)
        .map(|e| {
            r.bind_before_reads(p(pg, e, s.width))
                .expect("audited replicate predicate binding")
        })
        .collect();
    let any = r
        .bind_before_reads(any(&active))
        .expect("audited replicate mask binding");
    let base = Expr::register(register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    ));
    if n == 31 {
        let aligned = b(B::Eq, b(B::And, base.clone(), c(64, 15)), c(64, 0));
        r.bind_before_reads(Expr::require_context(
            Expr::select(any.clone(), aligned, c(1, 1)),
            "active SVE replicate SP alignment requires target SA/SA0 policy",
        ))
        .expect("audited replicate alignment binding");
    }
    let offset = if s.immediate {
        if s.block == 0 {
            c(64, u64::from((word >> 16) & 63) * u64::from(s.memory / 8))
        } else {
            let imm = ((word >> 16) & 15) as i64;
            let imm = if imm & 8 != 0 { imm - 16 } else { imm };
            c(64, (imm * i64::from(s.block / 8)) as u64)
        }
    } else {
        b(
            B::Mul,
            Expr::register(register("a64.gpr", m as u16, 64, 64)),
            c(64, u64::from(s.memory / 8)),
        )
    };
    // No address or offset state is demanded when there is no actual access.
    let base = r
        .bind_before_reads(Expr::select(any.clone(), b(B::Add, base, offset), c(64, 0)))
        .expect("audited replicate address binding");
    let mut lanes = Vec::new();
    if s.block == 0 {
        let value = r
            .load_ordered_conditional(
                any,
                Memory {kind: Default::default(), privilege: Default::default(),
                    address: Box::new(base),
                    width: s.memory,
                    endian,
                },
            )
            .expect("replicate scalar width");
        for active in active {
            lanes.push(Expr::select(
                active,
                Expr::cast(value.clone(), s.width, s.signed),
                c(s.width, 0),
            ));
        }
    } else {
        for (e, active) in active.into_iter().enumerate() {
            let at = b(
                B::Add,
                base.clone(),
                c(64, e as u64 * u64::from(s.memory / 8)),
            );
            let value = r
                .load_ordered_conditional(
                    active.clone(),
                    Memory {kind: Default::default(), privilege: Default::default(),
                        address: Box::new(at),
                        width: s.memory,
                        endian,
                    },
                )
                .expect("replicate block element width");
            lanes.push(Expr::select(active, value, c(s.width, 0)));
        }
    }
    let per_chunk = 64 / usize::from(s.width);
    let chunks: Vec<_> = lanes
        .chunks(per_chunk)
        .map(|elements| {
            elements.iter().enumerate().fold(c(64, 0), |out, (e, v)| {
                b(
                    B::Or,
                    out,
                    b(
                        B::Shl,
                        Expr::cast(v.clone(), 64, false),
                        c(64, e as u64 * u64::from(s.width)),
                    ),
                )
            })
        })
        .map(|v| r.bind(v))
        .collect();
    for output in 0..vl / 64 {
        r.write(
            register("a64.vector64", d as u16 * 32 + output, 64, 64),
            WritePolicy::ZeroUpper,
            chunks[usize::from(output) % chunks.len()].clone(),
        );
    }
    Some(r)
}

//! A64 Advanced SIMD structure transfers from the 2026-06 Arm operation text.
//!
//! LD/ST1-4 multiple structures, single lanes and load-replicate use one
//! `Mem{esize}` access for each element in the architectural loop order. Even
//! LD1 {Vt.16B} therefore has sixteen byte accesses, not a fabricated 128-bit
//! access. All these esizes are at most 64 bits; no wide access is split here.
//! Access permissions, tags and FP/SIMD enablement remain consumer-owned.
use super::*;
use BinaryOp as B;

fn c(width: u8, value: u64) -> Expr {
    Expr::constant(width, value)
}
fn bin(op: B, left: Expr, right: Expr) -> Expr {
    Expr::binary(op, left, right)
}
fn base(number: u32) -> RegisterSlice {
    register(
        if number == 31 { "a64.sp" } else { "a64.gpr" },
        if number == 31 { 0 } else { number as u16 },
        64,
        64,
    )
}
fn vector(number: u32, chunk: u16) -> RegisterSlice {
    register("a64.vector64", number as u16 * 32 + chunk, 64, 64)
}
fn lane(number: u32, index: u8, width: u8) -> RegisterSlice {
    let bit = u16::from(index) * u16::from(width);
    let mut slice = vector(number, bit / 64);
    slice.offset = (bit % 64) as u8;
    slice.width = width;
    slice
}
fn memory(address: &Expr, offset: u64, width: u8, endian: Endian) -> Memory {
    Memory {kind: Default::default(), privilege: Default::default(),
        address: Box::new(bin(B::Add, address.clone(), c(64, offset))),
        width,
        endian,
    }
}
fn insert(value: Expr, element: Expr, offset: u8) -> Expr {
    bin(
        B::Or,
        value,
        bin(
            B::Shl,
            Expr::cast(element, 64, false),
            c(64, u64::from(offset)),
        ),
    )
}
fn reject(address: u64) -> Option<Recipe> {
    Some(Recipe::unsupported(
        "reserved A64 SIMD structure transfer encoding",
        address.wrapping_add(4),
        64,
    ))
}

/// Extract an allocated A64 structure-transfer recipe from its physical word.
/// Unrelated families return None; reserved forms return an unsupported recipe.
pub fn a64(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    let single = match word & 0xbf00_0000 {
        0x0c00_0000 => false,
        0x0d00_0000 => true,
        _ => return None,
    };
    let q = ((word >> 30) & 1) as u8;
    let post = word & (1 << 23) != 0;
    let load = word & (1 << 22) != 0;
    let rm = (word >> 16) & 31;
    let rn = (word >> 5) & 31;
    let rt = word & 31;
    if (!post && rm != 0) || (!single && word & (1 << 21) != 0) {
        return reject(address);
    }
    let datasize = 64u16 << q;
    let size = ((word >> 10) & 3) as u8;
    let (rpt, selem, esize, lane_index, replicate) = if single {
        let opcode = ((word >> 13) & 7) as u8;
        let s = ((word >> 12) & 1) as u8;
        let selem = ((opcode & 1) << 1) + ((word >> 21) & 1) as u8 + 1;
        let (scale, index, replicate) = match opcode >> 1 {
            0 => (0, (q << 3) | (s << 2) | size, false),
            1 if size & 1 == 0 => (1, (q << 2) | (s << 1) | (size >> 1), false),
            2 if size == 0 => (2, (q << 1) | s, false),
            2 if size == 1 && s == 0 => (3, q, false),
            3 if load && s == 0 => (size, 0, true),
            _ => return reject(address),
        };
        (1, selem, 8u8 << scale, index, replicate)
    } else {
        let (rpt, selem) = match (word >> 12) & 15 {
            0 => (1, 4),
            2 => (4, 1),
            4 => (1, 3),
            6 => (3, 1),
            7 => (1, 1),
            8 => (1, 2),
            10 => (2, 1),
            _ => return reject(address),
        };
        if q == 0 && size == 3 && selem != 1 {
            return reject(address);
        }
        (rpt, selem, 8u8 << size, 0, false)
    };
    let mut recipe = Recipe::new(address.wrapping_add(4), 64);
    // A misaligned SP needs SCTLR/PSTATE context. Aligned SP is valid under
    // every alignment-control setting; do not invent an unconditional trap.
    if rn == 31 {
        recipe.guard = Expr::require_context(
            bin(
                B::Eq,
                bin(B::And, Expr::register(base(rn)), c(64, 15)),
                c(64, 0),
            ),
            "A64 SP alignment controls",
        );
    }
    let incoming_base = recipe.bind(Expr::register(base(rn)));
    // Xn may also be Xm: bind both before publishing base writeback.
    let increment = if post && rm != 31 {
        Some(recipe.bind(Expr::register(base(rm))))
    } else {
        None
    };
    let mut offset = 0u64;
    if single {
        for element_register in 0..selem {
            let number = (rt + u32::from(element_register)) & 31;
            let access = memory(&incoming_base, offset, esize, endian);
            if load {
                let value = recipe.bind(Expr::load(access));
                if replicate {
                    let mut chunk = c(64, 0);
                    for index in 0..64 / esize {
                        chunk = insert(chunk, value.clone(), index * esize);
                    }
                    let chunk = recipe.bind(chunk);
                    recipe.write(vector(number, 0), WritePolicy::ZeroUpper, chunk.clone());
                    recipe.write(
                        vector(number, 1),
                        WritePolicy::ZeroUpper,
                        if q != 0 { chunk } else { c(64, 0) },
                    );
                } else {
                    // Only the selected lane changes, including for Q==0.
                    // In contrast to a 64-bit vector load this preserves V[127:64].
                    recipe.write(
                        lane(number, lane_index, esize),
                        WritePolicy::Preserve,
                        value,
                    );
                }
            } else {
                let value = recipe.bind(Expr::register(lane(number, lane_index, esize)));
                recipe.effects.push(Effect::Store {
                    memory: access,
                    value,
                });
            }
            offset += u64::from(esize / 8);
        }
    } else {
        let count = usize::from(rpt * selem);
        let elements = datasize / u16::from(esize);
        let mut chunks = vec![[c(64, 0), c(64, 0)]; count];
        // Arm's operation nests repetition, lane, then structure member. LD1
        // repetitions advance whole registers; LD2/3/4 interleave their lanes.
        for repetition in 0..rpt {
            for index in 0..elements {
                for member in 0..selem {
                    let relative = repetition + member;
                    let number = (rt + u32::from(relative)) & 31;
                    let access = memory(&incoming_base, offset, esize, endian);
                    if load {
                        let value = recipe.bind(Expr::load(access));
                        let bit = index * u16::from(esize);
                        let chunk = &mut chunks[usize::from(relative)][usize::from(bit / 64)];
                        *chunk = insert(chunk.clone(), value, (bit % 64) as u8);
                    } else {
                        let value = recipe.bind(Expr::register(lane(number, index as u8, esize)));
                        recipe.effects.push(Effect::Store {
                            memory: access,
                            value,
                        });
                    }
                    offset += u64::from(esize / 8);
                }
            }
        }
        if load {
            for (relative, values) in chunks.into_iter().enumerate() {
                let number = (rt + relative as u32) & 31;
                for (chunk, value) in values.into_iter().enumerate() {
                    let value = recipe.bind(value);
                    recipe.write(vector(number, chunk as u16), WritePolicy::ZeroUpper, value);
                }
            }
        }
    }
    if post {
        let value = recipe.bind(bin(
            B::Add,
            incoming_base,
            increment.unwrap_or_else(|| c(64, offset)),
        ));
        recipe.write(base(rn), WritePolicy::ZeroUpper, value);
    }
    Some(recipe)
}

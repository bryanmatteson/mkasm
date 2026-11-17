//! SME ZA operations, derived from the Arm 2026-06 operation/accessor text.
//!
//! Fixed-stride, incoming-state banks (all indices are u16, never u8):
//! * a64.za64[row*32+chunk]: 64-bit chunks of 256 physical 2048-bit ZA rows.
//!   Tile T, element width E, row R, column C occupies physical row R*E/8+T
//!   and bit C*E. Active ZA is SVL/8 rows of SVL bits each.
//! * a64.vector64[Z*32+chunk], a64.predicate64[P*4+chunk], FFR is P16.
//! * a64.svcr[0]: two bits, SM at bit 0 and ZA at bit 1.
//! * a64.zt064[0..8]: ZT0's eight 64-bit chunks; a64.fpmr[0]: 64 bits.
//! * a64.fpcr[0], a64.fpsr[0]: 32 bits, using the existing FP contract.
//!
//! SME access permissions and optional instruction features belong to admission.
//! Non-streaming/disabled-ZA operation needs architectural context, never a
//! fabricated matrix transition. ZA writes preserve bits outside active SVL
//! (the permitted SMEZEROUPPER choice). ResetSVEState/ResetSMEState clear MAX_VL
//! storage. ZA disable preserves its prior storage, one permitted ARBITRARY
//! value choice; subsequent re-enable always zeroes all of it.
//!
//! Memory preserves the primary operation's access stream: ZA row and ZT0
//! transfers use individual bytes; slice and vector-group transfers use one
//! access per active element, including native 128-bit LD1Q/ST1Q accesses.
//! No memory form writes back Xn, Xm or the W slice index. Misaligned array/
//! table bases and misaligned SP need the unrepresented alignment-policy
//! context, including CHECKSPNONEACTIVE. Vector groups require streaming
//! mode: a non-streaming SVE2.1 CurrentVL needs a separate VL input.
use super::*;
use BinaryOp as B;

fn c(width: u8, value: u64) -> Expr {
    Expr::constant(width, value)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn not(a: Expr) -> Expr {
    Expr::unary(UnaryOp::Not, a)
}
fn scalar(bank: &'static str, index: u16, width: u8) -> RegisterSlice {
    register(bank, index, width, width)
}
fn za(row: u16, chunk: u16) -> RegisterSlice {
    scalar("a64.za64", row * 32 + chunk, 64)
}
fn z(n: u32, chunk: u16) -> RegisterSlice {
    scalar("a64.vector64", n as u16 * 32 + chunk, 64)
}
fn part(mut slice: RegisterSlice, offset: u8, width: u8) -> Expr {
    slice.offset = offset;
    slice.width = width;
    Expr::register(slice)
}
fn z_lane(n: u32, e: u16, width: u8) -> Expr {
    let bit = e * u16::from(width);
    part(z(n, bit / 64), (bit % 64) as u8, width)
}
fn za_lane(row: u16, e: u16, width: u8) -> Expr {
    let bit = e * u16::from(width);
    part(za(row, bit / 64), (bit % 64) as u8, width)
}
fn predicate(n: u32, byte: u16) -> Expr {
    part(
        scalar("a64.predicate64", n as u16 * 4 + byte / 64, 64),
        (byte % 64) as u8,
        1,
    )
}
fn pack(values: impl Iterator<Item = Expr>, width: u8) -> Expr {
    values.enumerate().fold(c(64, 0), |out, (i, value)| {
        b(
            B::Or,
            out,
            b(
                B::Shl,
                Expr::cast(value, 64, false),
                c(64, i as u64 * u64::from(width)),
            ),
        )
    })
}
fn write(r: &mut Recipe, destination: RegisterSlice, value: Expr) {
    let value = r.bind(value);
    r.write(destination, WritePolicy::ZeroUpper, value);
}
fn context(r: &mut Recipe, bits: u64) {
    r.guard = Expr::require_context(
        b(
            B::Eq,
            b(B::And, Expr::register(scalar("a64.svcr", 0, 2)), c(2, bits)),
            c(2, bits),
        ),
        "SME operation requires the selected streaming and ZA state enabled",
    );
}

// Base SME integer operations. The scalar forms use saved SVL even while
// non-streaming; tile additions require both SM and ZA and never affect NZCV.
fn base_integer(word: u32, r: &mut Recipe, svl: u16, form: u8) {
    if form <= 3 {
        context(r, 3);
        let width = if form & 2 != 0 { 64 } else { 32 };
        let tile = (word & (if width == 64 { 7 } else { 3 })) as u16;
        let n = (word >> 5) & 31;
        let pn = (word >> 10) & 7;
        let pm = (word >> 13) & 7;
        let dim = svl / u16::from(width);
        for row in 0..dim {
            for chunk in 0..svl / 64 {
                let physical_row = row * u16::from(width) / 8 + tile;
                let values = (0..64 / u16::from(width)).map(|i| {
                    let col = chunk * (64 / u16::from(width)) + i;
                    let old = za_lane(physical_row, col, width);
                    let active = b(
                        B::And,
                        predicate(pn, row * u16::from(width) / 8),
                        predicate(pm, col * u16::from(width) / 8),
                    );
                    Expr::select(
                        active,
                        b(
                            B::Add,
                            old.clone(),
                            z_lane(n, if form & 1 == 0 { col } else { row }, width),
                        ),
                        old,
                    )
                });
                write(r, za(physical_row, chunk), pack(values, width));
            }
        }
    } else {
        let imm = (((word >> 5) & 63) as i64) << 58 >> 58;
        let scale = if form == 4 { svl / 64 } else { svl / 8 };
        let offset = c(64, imm.wrapping_mul(i64::from(scale)) as u64);
        let d = (word & 31) as u16;
        if form == 6 {
            if d != 31 {
                write(r, scalar("a64.gpr", d, 64), offset);
            }
        } else {
            let n = ((word >> 16) & 31) as u16;
            let source = if n == 31 {
                scalar("a64.sp", 0, 64)
            } else {
                scalar("a64.gpr", n, 64)
            };
            let destination = if d == 31 {
                scalar("a64.sp", 0, 64)
            } else {
                scalar("a64.gpr", d, 64)
            };
            write(r, destination, b(B::Add, Expr::register(source), offset));
        }
    }
}
fn base_integer_form(word: u32) -> Option<u8> {
    match word & 0xffff_001c {
        0xc0900000 => return Some(0),
        0xc0910000 => return Some(1),
        _ => {}
    }
    match word & 0xffff_0018 {
        0xc0d00000 => return Some(2),
        0xc0d10000 => return Some(3),
        _ => {}
    }
    if word & 0xffff_f800 == 0x04bf5800 {
        return Some(6);
    }
    match word & 0xffe0_f800 {
        0x04605800 => Some(4),
        0x04205800 => Some(5),
        _ => None,
    }
}

fn streaming(word: u32, r: &mut Recipe) {
    let selection = (word >> 8) & 6;
    let start = word & (1 << 8) != 0;
    let state = Expr::register(scalar("a64.svcr", 0, 2));
    r.guard = Expr::require_context(
        b(B::Eq, state.clone(), state.clone()),
        "SME streaming state must be available before changing SVCR",
    );
    let old = r.bind(state);
    let target = c(1, u64::from(start));
    if selection & 2 != 0 {
        let changed = r.bind(not(b(
            B::Eq,
            Expr::extract(old.clone(), 0, 1),
            target.clone(),
        )));
        let mut reset = |destination: RegisterSlice, value: u64| {
            write(
                r,
                destination,
                Expr::select(
                    changed.clone(),
                    c(destination.width, value),
                    Expr::register(destination),
                ),
            );
        };
        for n in 0..32 {
            for chunk in 0..32 {
                reset(z(n, chunk), 0);
            }
        }
        for index in 0..17 * 4 {
            reset(scalar("a64.predicate64", index, 64), 0);
        }
        reset(scalar("a64.fpsr", 0, 32), 0x0800_009f);
        reset(scalar("a64.fpmr", 0, 64), 0);
    }
    if selection & 4 != 0 && start {
        let enabling = r.bind(not(Expr::extract(old.clone(), 1, 1)));
        for row in 0..256 {
            for chunk in 0..32 {
                let destination = za(row, chunk);
                write(
                    r,
                    destination,
                    Expr::select(enabling.clone(), c(64, 0), Expr::register(destination)),
                );
            }
        }
        // The exposed ZT0 bank exists only for SME2-capable consumers. Zero is
        // harmless retained backing storage when that optional feature is off.
        for chunk in 0..8 {
            let destination = scalar("a64.zt064", chunk, 64);
            write(
                r,
                destination,
                Expr::select(enabling.clone(), c(64, 0), Expr::register(destination)),
            );
        }
    }
    let mask = (u64::from(selection) >> 1) & 3;
    let value = if start {
        b(B::Or, old, c(2, mask))
    } else {
        b(B::And, old, c(2, !mask))
    };
    write(r, scalar("a64.svcr", 0, 2), value);
}

fn zero(word: u32, r: &mut Recipe, svl: u16) {
    context(r, 2);
    for row in 0..svl / 8 {
        if word & (1 << (row % 8)) != 0 {
            for chunk in 0..svl / 64 {
                write(r, za(row, chunk), c(64, 0));
            }
        }
    }
}

fn selected_row(
    tile: u16,
    width: u16,
    selected: &Expr,
    bit: u16,
    lane_width: u8,
    svl: u16,
) -> Expr {
    let mut out = c(lane_width, 0);
    for row in (0..svl / width).rev() {
        out = Expr::select(
            b(B::Eq, selected.clone(), c(32, u64::from(row))),
            part(
                za(row * width / 8 + tile, bit / 64),
                (bit % 64) as u8,
                lane_width,
            ),
            out,
        );
    }
    out
}
fn selected_column(row: u16, width: u16, half: u16, selected: &Expr, svl: u16) -> Expr {
    let lane_width = width.min(64) as u8;
    let mut out = c(lane_width, 0);
    for column in (0..svl / width).rev() {
        let bit = column * width + half * 64;
        out = Expr::select(
            b(B::Eq, selected.clone(), c(32, u64::from(column))),
            part(za(row, bit / 64), (bit % 64) as u8, lane_width),
            out,
        );
    }
    out
}

fn mova(word: u32, r: &mut Recipe, svl: u16, extract: bool) {
    context(r, 3);
    let width = if word & (1 << 16) != 0 {
        128
    } else {
        8u16 << ((word >> 22) & 3)
    };
    let low = if extract { (word >> 5) & 15 } else { word & 15 };
    let offset_bits = 4 - (width / 8).trailing_zeros();
    let tile = (low >> offset_bits) as u16;
    let offset = low & ((1 << offset_bits) - 1);
    let s = Expr::register(register(
        "a64.gpr",
        (12 + ((word >> 13) & 3)) as u16,
        32,
        64,
    ));
    // UInt(index)+offset is mathematical addition, not wrapping a W register.
    let selected = r.bind(b(
        B::Urem,
        b(B::Add, Expr::cast(s, 64, false), c(64, u64::from(offset))),
        c(64, u64::from(svl / width)),
    ));
    let selected = r.bind(Expr::cast(selected, 32, false));
    let pg = (word >> 10) & 7;
    let vector = if extract { word & 31 } else { (word >> 5) & 31 };
    let vertical = word & (1 << 15) != 0;
    matrix_moves(
        r,
        svl,
        width,
        tile,
        &[selected],
        vector,
        vertical,
        extract,
        Some(pg),
    );
}

#[allow(clippy::too_many_arguments)]
fn matrix_moves(
    r: &mut Recipe,
    svl: u16,
    width: u16,
    tile: u16,
    selected: &[Expr],
    vector: u32,
    vertical: bool,
    extract: bool,
    pg: Option<u32>,
) {
    let lane_width = width.min(64) as u8;
    let halves = (width / 64).max(1);
    let active = |element| pg.map_or_else(|| c(1, 1), |pg| predicate(pg, element * width / 8));
    if extract {
        for (member, selected) in selected.iter().enumerate() {
            let vector = vector + member as u32;
            for chunk in 0..svl / 64 {
                let values = (0..64 / u16::from(lane_width)).map(|within| {
                    let bit = chunk * 64 + within * u16::from(lane_width);
                    let element = bit / width;
                    let half = (bit % width) / 64;
                    let value = if vertical {
                        selected_column(element * width / 8 + tile, width, half, selected, svl)
                    } else {
                        selected_row(tile, width, selected, bit, lane_width, svl)
                    };
                    Expr::select(
                        active(element),
                        value,
                        z_lane(vector, bit / u16::from(lane_width), lane_width),
                    )
                });
                write(r, z(vector, chunk), pack(values, lane_width));
            }
            // Choose the permitted SVEZEROUPPER behavior for the destination Z.
            for chunk in svl / 64..32 {
                write(r, z(vector, chunk), c(64, 0));
            }
        }
    } else {
        for row in 0..svl / width {
            for chunk in 0..svl / 64 {
                let values = (0..64 / u16::from(lane_width)).map(|within| {
                    let bit = chunk * 64 + within * u16::from(lane_width);
                    let column = bit / width;
                    let half = (bit % width) / 64;
                    let element = if vertical { row } else { column };
                    let mut value = za_lane(
                        row * width / 8 + tile,
                        bit / u16::from(lane_width),
                        lane_width,
                    );
                    // Combine all selected slices before publishing a chunk:
                    // vertical groups can update several lanes of one row.
                    for (member, selected) in selected.iter().enumerate() {
                        let active = b(
                            B::And,
                            active(element),
                            b(
                                B::Eq,
                                selected.clone(),
                                c(32, u64::from(if vertical { column } else { row })),
                            ),
                        );
                        let source =
                            z_lane(vector + member as u32, element * halves + half, lane_width);
                        value = Expr::select(active, source, value);
                    }
                    value
                });
                write(
                    r,
                    za(row * width / 8 + tile, chunk),
                    pack(values, lane_width),
                );
            }
        }
    }
}

// SME2's unpredicated array-vector and two/four tile-slice aliases.
fn multi_mova(word: u32, r: &mut Recipe, svl: u16, nreg: u16, extract: bool, array: bool) {
    context(r, 3);
    let width = if array { 8 } else { 8u16 << ((word >> 22) & 3) };
    if !array && nreg == 4 && width == 64 && svl < 256 {
        r.effects.push(Effect::Trap {
            kind: TrapKind::InvalidInstruction,
            condition: c(1, 1),
        });
        return;
    }
    let low = if extract { (word >> 5) & 15 } else { word & 15 };
    let (tile, offset, dimension, base_register) = if array {
        (0, low & 7, svl / 8 / nreg, 8)
    } else {
        let bits = (4 - (width / 8).trailing_zeros()).saturating_sub(nreg.trailing_zeros());
        (
            (low >> bits) as u16,
            (low & ((1 << bits) - 1)) * u32::from(nreg),
            svl / width,
            12,
        )
    };
    let incoming = Expr::register(register(
        "a64.gpr",
        (base_register + ((word >> 13) & 3)) as u16,
        32,
        64,
    ));
    let mut index = Expr::cast(incoming, 64, false);
    if !array {
        index = b(B::And, index, c(64, !u64::from(nreg - 1)));
    }
    let first = r.bind(b(
        B::Urem,
        b(B::Add, index, c(64, u64::from(offset))),
        c(64, u64::from(dimension)),
    ));
    let selected: Vec<_> = (0..nreg)
        .map(|member| {
            let increment = if array { member * dimension } else { member };
            let value = b(B::Add, first.clone(), c(64, u64::from(increment)));
            r.bind(Expr::cast(value, 32, false))
        })
        .collect();
    let vector = if extract { word & 31 } else { (word >> 5) & 31 };
    matrix_moves(
        r,
        svl,
        width,
        tile,
        &selected,
        vector,
        !array && word & (1 << 15) != 0,
        extract,
        None,
    );
}

fn multi_form(word: u32) -> Option<(u16, bool, bool)> {
    for (nreg, extract, array, mask, values) in [
        (2, true, true, 0xffff9f01, &[0xc0060800][..]),
        (4, true, true, 0xffff9f03, &[0xc0060c00][..]),
        (2, false, true, 0xffff9c38, &[0xc0040800][..]),
        (4, false, true, 0xffff9c78, &[0xc0040c00][..]),
        (
            2,
            true,
            false,
            0xffff1f01,
            &[0xc0060000, 0xc0460000, 0xc0860000, 0xc0c60000][..],
        ),
        (
            4,
            true,
            false,
            0xffff1f83,
            &[0xc0060400, 0xc0460400, 0xc0860400][..],
        ),
        (4, true, false, 0xffff1f03, &[0xc0c60400][..]),
        (
            2,
            false,
            false,
            0xffff1c38,
            &[0xc0040000, 0xc0440000, 0xc0840000, 0xc0c40000][..],
        ),
        (
            4,
            false,
            false,
            0xffff1c7c,
            &[0xc0040400, 0xc0440400, 0xc0840400][..],
        ),
        (4, false, false, 0xffff1c78, &[0xc0c40400][..]),
    ] {
        if values.contains(&(word & mask)) {
            return Some((nreg, extract, array));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum Product {
    Integer {
        parts: u16,
        left_unsigned: bool,
        right_unsigned: bool,
    },
    Bitwise,
}

fn outer(word: u32, r: &mut Recipe, svl: u16, width: u8, product: Product) {
    context(r, 3);
    let dim = svl / u16::from(width);
    let tile = (word & u32::from(width / 8 - 1)) as u16;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let pn = (word >> 10) & 7;
    let pm = (word >> 13) & 7;
    let subtract = word & (1 << 4) != 0;
    for row in 0..dim {
        for chunk in 0..svl / 64 {
            let values = (0..64 / u16::from(width)).map(|within| {
                let col = chunk * 64 / u16::from(width) + within;
                let old = za_lane(row * u16::from(width) / 8 + tile, col, width);
                match product {
                    Product::Bitwise => {
                        let active = b(B::And, predicate(pn, row * 4), predicate(pm, col * 4));
                        let count = Expr::unary(
                            UnaryOp::PopulationCount,
                            not(b(B::Xor, z_lane(n, row, 32), z_lane(m, col, 32))),
                        );
                        Expr::select(
                            active,
                            b(if subtract { B::Sub } else { B::Add }, old.clone(), count),
                            old,
                        )
                    }
                    Product::Integer {
                        parts,
                        left_unsigned,
                        right_unsigned,
                    } => {
                        let input_width = width / parts as u8;
                        let mut sum = old;
                        for k in 0..parts {
                            let a = row * parts + k;
                            let z = col * parts + k;
                            let active = b(
                                B::And,
                                predicate(pn, a * u16::from(input_width) / 8),
                                predicate(pm, z * u16::from(input_width) / 8),
                            );
                            let multiply = b(
                                B::Mul,
                                Expr::cast(z_lane(n, a, input_width), width, !left_unsigned),
                                Expr::cast(z_lane(m, z, input_width), width, !right_unsigned),
                            );
                            sum = Expr::select(
                                active,
                                b(
                                    if subtract { B::Sub } else { B::Add },
                                    sum.clone(),
                                    multiply,
                                ),
                                sum,
                            );
                        }
                        sum
                    }
                }
            });
            write(
                r,
                za(row * u16::from(width) / 8 + tile, chunk),
                pack(values, width),
            );
        }
    }
}

#[derive(Clone, Copy)]
enum MemoryForm {
    Array,
    Table,
    Slice(u16),
    Group,
}
fn memory_form(word: u32) -> Option<MemoryForm> {
    if word & 0xffdf_9c10 == 0xe100_0000 {
        Some(MemoryForm::Array)
    } else if word & 0xffdf_fc1f == 0xe11f_8000 {
        Some(MemoryForm::Table)
    } else {
        match word & 0xffc0_0010 {
            0xe0000000 => Some(MemoryForm::Slice(8)),
            0xe0400000 => Some(MemoryForm::Slice(16)),
            0xe0800000 => Some(MemoryForm::Slice(32)),
            0xe0c00000 => Some(MemoryForm::Slice(64)),
            0xe1c00000 => Some(MemoryForm::Slice(128)),
            _ if word & 0xfe80_0000 == 0xa000_0000
                && !(word & (1 << 22) != 0 && word & (1 << 20) != 0)
                && !(word & (1 << 15) != 0
                    && word & (if word & (1 << 24) == 0 { 2 } else { 4 }) != 0) =>
            {
                Some(MemoryForm::Group)
            }
            _ => None,
        }
    }
}
/// All 128 contiguous/strided grouped LD1/ST1/LDNT1/STNT1 physical classes.
/// `vl` is effective CurrentVL, including when saved SVL differs. Loads select
/// the permitted SVEZEROUPPER behavior. Empty masks suppress SP/address reads.
pub fn a64_group_memory(word: u32, address: u64, vl: u16, endian: Endian) -> Option<Recipe> {
    if !matches!(memory_form(word), Some(MemoryForm::Group)) {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if !matches!(vl, 128 | 256 | 512 | 1024 | 2048) {
        r.guard = Expr::require_context(c(1, 0), "invalid grouped vector CurrentVL");
    } else {
        memory_group(word, &mut r, vl, endian);
    }
    Some(r)
}
fn x_base(n: u32) -> Expr {
    Expr::register(scalar(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
    ))
}
fn x_offset(n: u32) -> Expr {
    if n == 31 {
        c(64, 0)
    } else {
        x_base(n)
    }
}
fn require_memory_context(r: &mut Recipe, legal: Expr, reason: &'static str) {
    r.guard = Expr::select(
        r.guard.clone(),
        Expr::require_context(legal, reason),
        c(1, 0),
    );
}
fn memory_alignment(r: &mut Recipe, base: Expr, required: bool) {
    if required {
        require_memory_context(
            r,
            b(B::Eq, b(B::And, base, c(64, 15)), c(64, 0)),
            "SME unaligned base needs SP/alignment-control context (including inactive-SP policy)",
        );
    }
}
fn memory_read(
    r: &mut Recipe,
    address: Expr,
    width: u16,
    endian: Endian,
    active: Expr,
) -> Vec<Expr> {
    // All original widths share one ordered read stream. Inactive predicates
    // suppress address evaluation and the native memory callback altogether.
    r.load_wide_conditional(
        active,
        WideMemory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(address),
            width,
            endian,
        },
    )
}
fn memory_store(
    r: &mut Recipe,
    address: Expr,
    width: u16,
    endian: Endian,
    active: Expr,
    chunks: Vec<Expr>,
) {
    if width <= 64 {
        r.store_conditional(
            active,
            Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(address),
                width: width as u8,
                endian,
            },
            chunks[0].clone(),
        );
    } else {
        r.store_wide_conditional(
            active,
            WideMemory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(address),
                width,
                endian,
            },
            chunks,
        );
    }
}
fn memory_index(word: u32, offset: u32, dimension: u16) -> Expr {
    let w = Expr::register(register(
        "a64.gpr",
        (12 + ((word >> 13) & 3)) as u16,
        32,
        64,
    ));
    Expr::cast(
        b(
            B::Urem,
            b(B::Add, Expr::cast(w, 64, false), c(64, u64::from(offset))),
            c(64, u64::from(dimension)),
        ),
        32,
        false,
    )
}
fn memory_array(word: u32, r: &mut Recipe, svl: u16, table: bool) {
    context(r, 2);
    let base = x_base((word >> 5) & 31);
    memory_alignment(r, base.clone(), true);
    let offset = if table { 0 } else { word & 15 };
    let bytes = if table { 64 } else { svl / 8 };
    let address = b(B::Add, base, c(64, u64::from(offset) * u64::from(bytes)));
    let selected = memory_index(word, offset, svl / 8);
    if word & (1 << 21) == 0 {
        // LDR ZA and LDR ZT0 explicitly perform byte accesses, even though
        // their result is a complete vector/table. Endian never reverses it.
        let loaded: Vec<_> = (0..bytes)
            .map(|e| {
                memory_read(
                    r,
                    b(B::Add, address.clone(), c(64, u64::from(e))),
                    8,
                    Endian::Little,
                    c(1, 1),
                )[0]
                .clone()
            })
            .collect();
        for row in 0..if table { 1 } else { svl / 8 } {
            for chunk in 0..bytes / 8 {
                let destination = if table {
                    scalar("a64.zt064", chunk, 64)
                } else {
                    za(row, chunk)
                };
                let value = pack(
                    (0..8).map(|e| loaded[usize::from(chunk * 8 + e)].clone()),
                    8,
                );
                let value = if table {
                    value
                } else {
                    Expr::select(
                        b(B::Eq, selected.clone(), c(32, u64::from(row))),
                        value,
                        Expr::register(destination),
                    )
                };
                write(r, destination, value);
            }
        }
    } else {
        for e in 0..bytes {
            let value = if table {
                part(scalar("a64.zt064", e / 8, 64), (e % 8 * 8) as u8, 8)
            } else {
                selected_row(0, 8, &selected, e * 8, 8, svl)
            };
            memory_store(
                r,
                b(B::Add, address.clone(), c(64, u64::from(e))),
                8,
                Endian::Little,
                c(1, 1),
                vec![value],
            );
        }
    }
}
fn memory_slice(word: u32, r: &mut Recipe, svl: u16, width: u16, endian: Endian) {
    context(r, 3);
    let n = (word >> 5) & 31;
    let base = x_base(n);
    memory_alignment(r, base.clone(), n == 31);
    let offset_bits = 4 - (width / 8).trailing_zeros();
    let tile = ((word & 15) >> offset_bits) as u16;
    let offset = word & ((1 << offset_bits) - 1);
    let selected = memory_index(word, offset, svl / width);
    let address = b(
        B::Add,
        base,
        b(
            B::Mul,
            x_offset((word >> 16) & 31),
            c(64, u64::from(width / 8)),
        ),
    );
    let pg = (word >> 10) & 7;
    let vertical = word & (1 << 15) != 0;
    let lane_width = width.min(64) as u8;
    let active = |e| predicate(pg, e * width / 8);
    if word & (1 << 21) == 0 {
        let values: Vec<_> = (0..svl / width)
            .map(|e| {
                memory_read(
                    r,
                    b(B::Add, address.clone(), c(64, u64::from(e * width / 8))),
                    width,
                    endian,
                    active(e),
                )
            })
            .collect();
        for row in 0..svl / width {
            for chunk in 0..svl / 64 {
                let values = (0..64 / u16::from(lane_width)).map(|within| {
                    let bit = chunk * 64 + within * u16::from(lane_width);
                    let column = bit / width;
                    let half = (bit % width) / 64;
                    let element = if vertical { row } else { column };
                    let source = Expr::select(
                        active(element),
                        values[usize::from(element)][usize::from(half)].clone(),
                        c(lane_width, 0),
                    );
                    Expr::select(
                        b(
                            B::Eq,
                            selected.clone(),
                            c(32, u64::from(if vertical { column } else { row })),
                        ),
                        source,
                        part(
                            za(row * width / 8 + tile, chunk),
                            (bit % 64) as u8,
                            lane_width,
                        ),
                    )
                });
                write(
                    r,
                    za(row * width / 8 + tile, chunk),
                    pack(values, lane_width),
                );
            }
        }
    } else {
        for e in 0..svl / width {
            let chunks = (0..(width / 64).max(1))
                .map(|half| {
                    if vertical {
                        selected_column(e * width / 8 + tile, width, half, &selected, svl)
                    } else {
                        selected_row(
                            tile,
                            width,
                            &selected,
                            e * width + half * 64,
                            lane_width,
                            svl,
                        )
                    }
                })
                .collect();
            memory_store(
                r,
                b(B::Add, address.clone(), c(64, u64::from(e * width / 8))),
                width,
                endian,
                active(e),
                chunks,
            );
        }
    }
}
fn memory_group(word: u32, r: &mut Recipe, svl: u16, endian: Endian) {
    let strided = word & (1 << 24) != 0;
    let sm = part(scalar("a64.svcr", 0, 2), 0, 1);
    // Contiguous lists admit ordinary SVE2.1; strided lists remain SME2.
    // The caller supplies effective CurrentVL, independent of its saved SVL.
    let legal = if strided {
        sm
    } else {
        Expr::select(Expr::register(scalar("a64.sve2p1", 0, 1)), c(1, 1), sm)
    };
    require_memory_context(
        r,
        legal,
        "grouped vector memory requires SVE2.1 or streaming SME2",
    );
    let n = (word >> 5) & 31;
    let base = x_base(n);
    let count = if word & (1 << 15) == 0 { 2 } else { 4 };
    let width = 8u16 << ((word >> 13) & 3);
    let elements = svl / width;
    let (first, stride) = if word & (1 << 24) != 0 {
        (
            ((word >> 4) & 1) * 16 + (word & (if count == 2 { 7 } else { 3 })),
            16 / count,
        )
    } else {
        (word & (if count == 2 { 30 } else { 28 }), 1)
    };
    let address = if word & (1 << 22) != 0 {
        let imm = (((word >> 16) & 15) as i64) << 60 >> 60;
        b(
            B::Add,
            base.clone(),
            c(64, imm.wrapping_mul(i64::from(count * svl / 8)) as u64),
        )
    } else {
        b(
            B::Add,
            base.clone(),
            b(
                B::Mul,
                x_offset((word >> 16) & 31),
                c(64, u64::from(width / 8)),
            ),
        )
    };
    let pn = 8 + ((word >> 10) & 7);
    let counter = arm64_sve_counter::Counter::read_before_reads(r, pn as u16, svl);
    let active: Vec<_> = (0..count * elements)
        .map(|index| {
            r.bind_before_reads(counter.bit(index * width / 8))
                .expect("pure counter lane")
        })
        .collect();
    if n == 31 {
        let mut level = active.clone();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 2 {
                        b(B::Or, pair[0].clone(), pair[1].clone())
                    } else {
                        pair[0].clone()
                    }
                })
                .collect();
        }
        let any = level.pop().unwrap();
        let aligned = b(B::Eq, b(B::And, base.clone(), c(64, 15)), c(64, 0));
        r.bind_before_reads(Expr::require_context(
            Expr::select(any, aligned, c(1, 1)),
            "misaligned active grouped vector SP access requires SP-alignment policy",
        ))
        .expect("SP qualification precedes ordered reads");
    }
    for member in 0..count {
        let vector = first + u32::from(member * stride);
        let mut loaded = Vec::new();
        for e in 0..elements {
            let index = member * elements + e;
            let active = active[usize::from(index)].clone();
            let address = b(B::Add, address.clone(), c(64, u64::from(index * width / 8)));
            if word & (1 << 21) == 0 {
                let value = memory_read(r, address, width, endian, active.clone())[0].clone();
                loaded.push(Expr::select(active, value, c(width as u8, 0)));
            } else {
                memory_store(
                    r,
                    address,
                    width,
                    endian,
                    active,
                    vec![z_lane(vector, e, width as u8)],
                );
            }
        }
        if word & (1 << 21) == 0 {
            for chunk in 0..svl / 64 {
                write(
                    r,
                    z(vector, chunk),
                    pack(
                        (0..64 / width)
                            .map(|within| loaded[usize::from(chunk * 64 / width + within)].clone()),
                        width as u8,
                    ),
                );
            }
            for chunk in svl / 64..32 {
                write(r, z(vector, chunk), c(64, 0));
            }
        }
    }
}

// These scalar expressions represent the mathematical, unbounded intermediate
// in the primary operation. No host-width add precedes the rounded right shift.
fn integer_right(a: Expr, shift: u8, rounded: bool, unsigned: bool) -> Expr {
    let w = a.ty.width;
    if shift == w {
        return if unsigned && rounded {
            b(B::Lsr, a, c(w, u64::from(w - 1)))
        } else if unsigned || rounded {
            c(w, 0)
        } else {
            b(B::Asr, a, c(w, u64::from(w)))
        };
    }
    let base = b(
        if unsigned { B::Lsr } else { B::Asr },
        a.clone(),
        c(w, u64::from(shift)),
    );
    if rounded {
        b(
            B::Add,
            base,
            b(B::And, b(B::Lsr, a, c(w, u64::from(shift - 1))), c(w, 1)),
        )
    } else {
        base
    }
}
fn integer_narrow(a: Expr, width: u8, unsigned_source: bool, unsigned_result: bool) -> Expr {
    let w = a.ty.width;
    let max = if unsigned_result {
        (1u64 << width) - 1
    } else {
        (1u64 << (width - 1)) - 1
    };
    let min = if unsigned_result {
        0
    } else {
        0u64.wrapping_sub(1u64 << (width - 1))
    };
    let upper = Expr::select(
        b(
            if unsigned_source { B::Ult } else { B::Slt },
            c(w, max),
            a.clone(),
        ),
        c(w, max),
        a,
    );
    let bounded = if unsigned_source {
        upper
    } else {
        Expr::select(b(B::Slt, upper.clone(), c(w, min)), c(w, min), upper)
    };
    Expr::cast(bounded, width, false)
}
fn integer_multi_mul_form(word: u32) -> Option<(u16, bool)> {
    if word & 0xff30ffe1 == 0xc120a400 {
        Some((2, false))
    } else if word & 0xff30ffe3 == 0xc120ac00 {
        Some((4, false))
    } else if word & 0xff21ffe1 == 0xc120b400 {
        Some((2, true))
    } else if word & 0xff23ffe3 == 0xc120bc00 {
        Some((4, true))
    } else {
        None
    }
}
fn integer_multi_mul(word: u32, r: &mut Recipe, svl: u16, nreg: u16, group: bool) {
    context(r, 1);
    let width = 8u8 << ((word >> 22) & 3);
    let d = word & 31;
    let m = (word >> 16) & if group { 32 - u32::from(nreg) } else { 15 };
    for member in 0..nreg {
        for chunk in 0..svl / 64 {
            let mut values = Vec::new();
            for e in 0..64 / u16::from(width) {
                let e = chunk * 64 / u16::from(width) + e;
                let a = z_lane(d + u32::from(member), e, width);
                let z = z_lane(m + if group { u32::from(member) } else { 0 }, e, width);
                let overflow = b(
                    B::And,
                    b(B::Eq, a.clone(), c(width, 1u64 << (width - 1))),
                    b(B::Eq, z.clone(), c(width, 1u64 << (width - 1))),
                );
                let lo = r.bind(b(B::Mul, a.clone(), z.clone()));
                let hi = r.bind(b(B::SignedMultiplyHigh, a, z));
                let high = b(
                    B::Or,
                    b(B::Shl, hi, c(width, 1)),
                    b(B::Lsr, lo, c(width, u64::from(width - 1))),
                );
                values.push(Expr::select(
                    overflow,
                    c(width, (1u64 << (width - 1)) - 1),
                    high,
                ));
            }
            write(
                r,
                z(d + u32::from(member), chunk),
                pack(values.into_iter(), width),
            );
        }
        for chunk in svl / 64..32 {
            write(r, z(d + u32::from(member), chunk), c(64, 0));
        }
    }
}
fn integer_multi_round_shift_form(word: u32) -> Option<(u16, bool)> {
    if matches!(word & 0xff30ffe1, 0xc120a220 | 0xc120a221) {
        Some((2, false))
    } else if matches!(word & 0xff30ffe3, 0xc120aa20 | 0xc120aa21) {
        Some((4, false))
    } else if matches!(word & 0xff21ffe1, 0xc120b220 | 0xc120b221) {
        Some((2, true))
    } else if matches!(word & 0xff23ffe3, 0xc120ba20 | 0xc120ba21) {
        Some((4, true))
    } else {
        None
    }
}
fn integer_multi_round_shift(word: u32, r: &mut Recipe, svl: u16, nreg: u16, group: bool) {
    context(r, 1);
    let width = 8u8 << ((word >> 22) & 3);
    let d = word & (32 - u32::from(nreg));
    let m = (word >> 16) & if group { 32 - u32::from(nreg) } else { 15 };
    let unsigned = word & 1 != 0;
    for member in 0..nreg {
        for chunk in 0..svl / 64 {
            let mut values = Vec::new();
            for e in 0..64 / u16::from(width) {
                let e = chunk * 64 / u16::from(width) + e;
                let a = z_lane(d + u32::from(member), e, width);
                let count = r.bind(z_lane(
                    m + if group { u32::from(member) } else { 0 },
                    e,
                    width,
                ));
                let negative = b(B::Slt, count.clone(), c(width, 0));
                let magnitude = r.bind(b(B::Sub, c(width, 0), count.clone()));
                // ShiftSat clamps the FULL signed element to
                // [-(esize+1),+(esize+1)]. Exactly -esize rounds the
                // unsigned top bit; more-negative counts produce zero.
                let at_width = if unsigned {
                    Expr::select(
                        b(B::Eq, magnitude.clone(), c(width, u64::from(width))),
                        b(B::Lsr, a.clone(), c(width, u64::from(width - 1))),
                        c(width, 0),
                    )
                } else {
                    c(width, 0)
                };
                let right = Expr::select(
                    b(B::Ult, magnitude.clone(), c(width, u64::from(width))),
                    b(
                        B::Add,
                        b(
                            if unsigned { B::Lsr } else { B::Asr },
                            a.clone(),
                            magnitude.clone(),
                        ),
                        b(
                            B::And,
                            b(B::Lsr, a.clone(), b(B::Sub, magnitude, c(width, 1))),
                            c(width, 1),
                        ),
                    ),
                    at_width,
                );
                let left = Expr::select(
                    b(B::Ult, count.clone(), c(width, u64::from(width))),
                    b(B::Shl, a, count),
                    c(width, 0),
                );
                values.push(Expr::select(negative, right, left));
            }
            write(
                r,
                z(d + u32::from(member), chunk),
                pack(values.into_iter(), width),
            );
        }
        for chunk in svl / 64..32 {
            write(r, z(d + u32::from(member), chunk), c(64, 0));
        }
    }
}

#[derive(Clone, Copy)]
struct IntegerNarrow {
    nreg: u16,
    width: u8,
    shift: u8,
    rounded: bool,
    unsigned: bool,
    to_unsigned: bool,
    interleaved: bool,
    streaming: bool,
}
fn integer_multi_narrow_form(word: u32) -> Option<IntegerNarrow> {
    // Saturating conversions are the zero-shift forms, with distinct
    // concatenating and interleaving layouts and no cumulative-QC update.
    if matches!(
        word & 0xfffffc20,
        0xc123e000 | 0xc123e020 | 0xc163e000 | 0x45314000 | 0x45314800 | 0x45315000
    ) {
        let streaming = word >> 24 == 0xc1;
        let unsigned = if streaming {
            word & (1 << 5) != 0
        } else {
            word & 0x1800 == 0x800
        };
        let to_unsigned = if streaming {
            word & ((1 << 22) | (1 << 5)) != 0
        } else {
            word & 0x1800 != 0
        };
        return Some(IntegerNarrow {
            nreg: 2,
            width: 16,
            shift: 0,
            rounded: false,
            unsigned,
            to_unsigned,
            interleaved: !streaming,
            streaming,
        });
    }
    if matches!(
        word & 0xff7ffc60,
        0xc133e000 | 0xc133e020 | 0xc173e000 | 0xc133e040 | 0xc133e060 | 0xc173e040
    ) {
        return Some(IntegerNarrow {
            nreg: 4,
            width: 8u8 << ((word >> 23) & 1),
            shift: 0,
            rounded: false,
            unsigned: word & (1 << 5) != 0,
            to_unsigned: word & ((1 << 22) | (1 << 5)) != 0,
            interleaved: word & (1 << 6) != 0,
            streaming: true,
        });
    }
    // SVE/SME2.3 two-register, interleaved, non-rounding forms.
    if matches!(word & 0xffe0fc20, 0x45a00000 | 0x45a01000 | 0x45a02000) {
        let tsize = (word >> 19) & 3;
        if tsize == 0 {
            return None;
        }
        let width = 8u8 << (31 - tsize.leading_zeros());
        return Some(IntegerNarrow {
            nreg: 2,
            width,
            shift: (u32::from(width) * 2 - (tsize * 8 + ((word >> 16) & 7))) as u8,
            rounded: false,
            unsigned: word & (1 << 12) != 0,
            to_unsigned: word & 0x3000 != 0,
            interleaved: true,
            streaming: false,
        });
    }
    // Rounded two-register forms have only 8- and 16-bit results.
    let rounded2 = match word & 0xfff8fc20 {
        0x45a80800 | 0x45a82800 | 0x45a83800 => Some(8),
        _ => None,
    }
    .or_else(|| match word & 0xfff0fc20 {
        0x45b00800 | 0x45b02800 | 0x45b03800 => Some(16),
        _ => None,
    });
    if let Some(width) = rounded2 {
        return Some(IntegerNarrow {
            nreg: 2,
            width,
            shift: width - (((word >> 16) & u32::from(width - 1)) as u8),
            rounded: true,
            unsigned: word & (1 << 12) != 0,
            to_unsigned: word & 0x3000 != 0x2000,
            interleaved: true,
            streaming: false,
        });
    }
    // SME concatenating two-register SQRSHR/UQRSHR/SQRSHRU.
    if matches!(word & 0xfff0fc20, 0xc1e0d400 | 0xc1e0d420 | 0xc1f0d400) {
        return Some(IntegerNarrow {
            nreg: 2,
            width: 16,
            shift: 16 - (((word >> 16) & 15) as u8),
            rounded: true,
            unsigned: word & (1 << 5) != 0,
            to_unsigned: word & ((1 << 20) | (1 << 5)) != 0,
            interleaved: false,
            streaming: true,
        });
    }
    // Four-register 4:1 narrowing, concatenating or interleaved. Both tsize
    // encodings 10 and 11 denote 16-bit results and different shift halves.
    if matches!(
        word & 0xff20fc60,
        0xc120d800 | 0xc120d820 | 0xc120d840 | 0xc120dc00 | 0xc120dc20 | 0xc120dc40
    ) {
        let tsize = (word >> 22) & 3;
        if tsize == 0 {
            return None;
        }
        let width = 8u8 << (31 - tsize.leading_zeros());
        return Some(IntegerNarrow {
            nreg: 4,
            width,
            shift: (u32::from(width) * 8 - (tsize * 32 + ((word >> 16) & 31))) as u8,
            rounded: true,
            unsigned: word & (1 << 5) != 0,
            to_unsigned: word & 0x60 != 0,
            interleaved: word & (1 << 10) != 0,
            streaming: true,
        });
    }
    None
}
fn integer_multi_narrow(word: u32, r: &mut Recipe, svl: u16, f: IntegerNarrow) {
    if f.streaming {
        context(r, 1);
    }
    let width = f.width;
    let input = width * f.nreg as u8;
    let n = (word >> 5) & (32 - u32::from(f.nreg));
    let d = word & 31;
    let elements = svl / u16::from(input);
    for chunk in 0..svl / 64 {
        let mut values = Vec::new();
        for e in 0..64 / u16::from(width) {
            let out = chunk * 64 / u16::from(width) + e;
            let (member, element) = if f.interleaved {
                (out % f.nreg, out / f.nreg)
            } else {
                (out / elements, out % elements)
            };
            let a = z_lane(n + u32::from(member), element, input);
            values.push(integer_narrow(
                integer_right(a, f.shift, f.rounded, f.unsigned),
                width,
                f.unsigned,
                f.to_unsigned,
            ));
        }
        write(r, z(d, chunk), pack(values.into_iter(), width));
    }
    for chunk in svl / 64..32 {
        write(r, z(d, chunk), c(64, 0));
    }
}

#[derive(Clone, Copy)]
struct IntegerMatrix {
    width: u8,
    nreg: u16,
    shape: u8,
    mode: u8,
    index: u16,
    offset: u16,
    unsigned_left: bool,
    unsigned_right: bool,
    subtract: bool,
}
fn integer_matrix_form(word: u32) -> Option<IntegerMatrix> {
    for &(mask, value, width, nreg, shape, mode, index_kind, flags) in INTEGER_MATRIX_FORMS {
        if word & mask != value {
            continue;
        }
        let width = if width == 0 {
            32u8 << ((word >> 22) & 1)
        } else {
            width
        };
        let index = match index_kind {
            0 => 0,
            1 => (word >> 10) & 3,
            2 => (word >> 10) & 1,
            3 => (((word >> 15) & 1) << 2) | ((word >> 10) & 3),
            4 => (((word >> 10) & 3) << 1) | ((word >> 2) & 1),
            5 => (((word >> 15) & 1) << 3) | ((word >> 10) & 7),
            6 => (((word >> 15) & 1) << 2) | ((word >> 10) & 3),
            7 => (((word >> 10) & 3) << 2) | ((word >> 1) & 3),
            8 => (((word >> 10) & 1) << 2) | ((word >> 1) & 3),
            _ => unreachable!(),
        } as u16;
        let offset = match shape {
            0 | 1 | 4 => (word & 7) as u16,
            2 => ((word & if nreg == 1 { 7 } else { 3 }) * 2) as u16,
            3 => ((word & if nreg == 1 { 3 } else { 1 }) * 4) as u16,
            _ => unreachable!(),
        };
        return Some(IntegerMatrix {
            width,
            nreg,
            shape,
            mode,
            index,
            offset,
            unsigned_left: flags & 1 != 0,
            unsigned_right: flags & 2 != 0,
            subtract: flags & 4 != 0,
        });
    }
    None
}
fn integer_matrix(word: u32, r: &mut Recipe, svl: u16, f: IntegerMatrix) {
    context(r, 3);
    let width = f.width;
    let (parts, rows) = match f.shape {
        0 => (4, 1),
        1 => (2, 1),
        2 => (1, 2),
        3 => (1, 4),
        4 => (f.nreg, 1),
        _ => unreachable!(),
    };
    let input = width / (parts * rows) as u8;
    let vertical = f.shape == 4;
    let n = (word >> 5)
        & if f.mode == 0 {
            31
        } else {
            32 - u32::from(f.nreg)
        };
    let m = (word >> 16)
        & if f.mode == 2 {
            32 - u32::from(f.nreg)
        } else {
            15
        };
    let stride = svl / 8 / f.nreg;
    // X{32} and the immediate are added as mathematical integers, not a
    // wrapping 32-bit add. ZA vector alignment follows modulo, as in ASL.
    let mut index = register("a64.gpr", 8 + ((word >> 13) & 3) as u16, 32, 64);
    index.offset = 0;
    let base = r.bind(b(
        B::And,
        b(
            B::Urem,
            b(
                B::Add,
                Expr::cast(Expr::register(index), 64, false),
                c(64, u64::from(f.offset)),
            ),
            c(64, u64::from(stride)),
        ),
        c(64, !(u64::from(rows) - 1)),
    ));
    for member in 0..f.nreg {
        for row in 0..rows {
            for chunk in 0..svl / 64 {
                let mut values = Vec::new();
                for e in 0..64 / u16::from(width) {
                    let e = chunk * 64 / u16::from(width) + e;
                    let segment = e - e % (128 / u16::from(width));
                    let mut sum = c(width, 0);
                    for part in 0..parts {
                        let left = if vertical {
                            e * parts + member
                        } else if rows == 1 {
                            e * parts + part
                        } else {
                            e * rows + row
                        };
                        let right = if f.mode == 1 {
                            if rows == 1 {
                                (segment + f.index) * parts + part
                            } else {
                                segment * rows + f.index
                            }
                        } else {
                            left
                        };
                        let a = Expr::cast(
                            z_lane(
                                (n + u32::from(if vertical { part } else { member })) % 32,
                                left,
                                input,
                            ),
                            width,
                            !f.unsigned_left,
                        );
                        let z = Expr::cast(
                            z_lane(
                                m + if f.mode == 2 { u32::from(member) } else { 0 },
                                right,
                                input,
                            ),
                            width,
                            !f.unsigned_right,
                        );
                        sum = b(B::Add, sum, b(B::Mul, a, z));
                    }
                    values.push(sum);
                }
                let delta = r.bind(pack(values.into_iter(), width));
                let destination = IndexedRegister {
                    bank: "a64.za64",
                    base: chunk,
                    stride: 32,
                    count: svl / 8,
                    index: Box::new(b(
                        B::Add,
                        base.clone(),
                        c(64, u64::from(member * stride + row)),
                    )),
                    offset: 0,
                    width: 64,
                    parent_width: 64,
                };
                let old = r.bind(Expr::indexed_register(destination.clone()));
                // Lane arithmetic cannot carry into the adjacent packed lane.
                let updated = pack(
                    (0..64 / width).map(|lane| {
                        b(
                            if f.subtract { B::Sub } else { B::Add },
                            Expr::extract(old.clone(), lane * width, width),
                            Expr::extract(delta.clone(), lane * width, width),
                        )
                    }),
                    width,
                );
                r.write_indexed(destination, WritePolicy::ZeroUpper, updated);
            }
        }
    }
}
// Exact June-2026 ZA dot/widening classes. Each record retains the complete
// physical fixed-bit mask, including group alignment and signedness selectors.
// Tuple: mask, value, result bits (0 => 32<<sz), group size, shape
// (dot4/dot2/long2/long4), source mode (vector/indexed/group), index layout,
// unsigned-left/right and subtract flags. No FP or reserved opcode wildcard.
const INTEGER_MATRIX_FORMS: &[(u32, u32, u8, u16, u8, u8, u8, u8)] = &[
    (0xfff0001c, 0xc1000014, 32, 1, 3, 1, 5, 2), //sumlall_za_zzi_s
    (0xfff09038, 0xc1100030, 32, 2, 3, 1, 7, 2), //sumlall_za_zzi_s2xi
    (0xfff09078, 0xc1108030, 32, 4, 3, 1, 7, 2), //sumlall_za_zzi_s4xi
    (0xfff09c1e, 0xc1200014, 32, 2, 3, 0, 0, 2), //sumlall_za_zzv_s2x1
    (0xfff09c1e, 0xc1300014, 32, 4, 3, 0, 0, 2), //sumlall_za_zzv_s4x1
    (0xfff09078, 0xc1508038, 32, 4, 4, 1, 1, 2), //suvdot_za_zzi_s4xi
    (0xfff09038, 0xc1500020, 32, 2, 4, 1, 1, 0), //svdot_za32_zzi_2xi
    (0xfff09078, 0xc1508020, 32, 4, 4, 1, 1, 0), //svdot_za_zzi_s4xi
    (0xfff09878, 0xc1d08808, 64, 4, 4, 1, 2, 0), //svdot_za_zzi_d4xi
    (0xfff0001c, 0xc1000004, 32, 1, 3, 1, 5, 1), //usmlall_za_zzi_s
    (0xfff09038, 0xc1100020, 32, 2, 3, 1, 7, 1), //usmlall_za_zzi_s2xi
    (0xfff09078, 0xc1108020, 32, 4, 3, 1, 7, 1), //usmlall_za_zzi_s4xi
    (0xfff09c1c, 0xc1200404, 32, 1, 3, 0, 0, 1), //usmlall_za_zzv_s
    (0xfff09c1e, 0xc1200004, 32, 2, 3, 0, 0, 1), //usmlall_za_zzv_s2x1
    (0xfff09c1e, 0xc1300004, 32, 4, 3, 0, 0, 1), //usmlall_za_zzv_s4x1
    (0xffe19c3e, 0xc1a00004, 32, 2, 3, 2, 0, 1), //usmlall_za_zzw_s2x2
    (0xffe39c7e, 0xc1a10004, 32, 4, 3, 2, 0, 1), //usmlall_za_zzw_s4x4
    (0xfff09078, 0xc1508028, 32, 4, 4, 1, 1, 1), //usvdot_za_zzi_s4xi
    (0xfff09038, 0xc1500030, 32, 2, 4, 1, 1, 3), //uvdot_za32_zzi_2xi
    (0xfff09078, 0xc1508030, 32, 4, 4, 1, 1, 3), //uvdot_za_zzi_s4xi
    (0xfff09878, 0xc1d08818, 64, 4, 4, 1, 2, 3), //uvdot_za_zzi_d4xi
    // sdot_za32_zzi: Two ZA single-vectors.
    (0xfff09038, 0xc1501000, 32, 2, 1, 1, 1, 0),
    // sdot_za32_zzi: Four ZA single-vectors.
    (0xfff09078, 0xc1509000, 32, 4, 1, 1, 1, 0),
    // sdot_za32_zzv: Two ZA single-vectors.
    (0xfff09c18, 0xc1601408, 32, 2, 1, 0, 0, 0),
    // sdot_za32_zzv: Four ZA single-vectors.
    (0xfff09c18, 0xc1701408, 32, 4, 1, 0, 0, 0),
    // sdot_za32_zzw: Two ZA single-vectors.
    (0xffe19c38, 0xc1e01408, 32, 2, 1, 2, 0, 0),
    // sdot_za32_zzw: Four ZA single-vectors.
    (0xffe39c78, 0xc1e11408, 32, 4, 1, 2, 0, 0),
    // sdot_za_zzi: Two ZA single-vectors of 32-bit elements.
    (0xfff09038, 0xc1501020, 32, 2, 0, 1, 1, 0),
    // sdot_za_zzi: Two ZA single-vectors of 64-bit elements.
    (0xfff09838, 0xc1d00008, 64, 2, 0, 1, 2, 0),
    // sdot_za_zzi: Four ZA single-vectors of 32-bit elements.
    (0xfff09078, 0xc1509020, 32, 4, 0, 1, 1, 0),
    // sdot_za_zzi: Four ZA single-vectors of 64-bit elements.
    (0xfff09878, 0xc1d08008, 64, 4, 0, 1, 2, 0),
    // sdot_za_zzv: Two ZA single-vectors.
    (0xffb09c18, 0xc1201400, 0, 2, 0, 0, 0, 0),
    // sdot_za_zzv: Four ZA single-vectors.
    (0xffb09c18, 0xc1301400, 0, 4, 0, 0, 0, 0),
    // sdot_za_zzw: Two ZA single-vectors.
    (0xffa19c38, 0xc1a01400, 0, 2, 0, 2, 0, 0),
    // sdot_za_zzw: Four ZA single-vectors.
    (0xffa39c78, 0xc1a11400, 0, 4, 0, 2, 0, 0),
    // smlal_za_zzi: One ZA double-vector.
    (0xfff01018, 0xc1c01000, 32, 1, 2, 1, 3, 0),
    // smlal_za_zzi: Two ZA double-vectors.
    (0xfff09038, 0xc1d01000, 32, 2, 2, 1, 4, 0),
    // smlal_za_zzi: Four ZA double-vectors.
    (0xfff09078, 0xc1d09000, 32, 4, 2, 1, 4, 0),
    // smlal_za_zzv: One ZA double-vector.
    (0xfff09c18, 0xc1600c00, 32, 1, 2, 0, 0, 0),
    // smlal_za_zzv: Two ZA double-vectors.
    (0xfff09c1c, 0xc1600800, 32, 2, 2, 0, 0, 0),
    // smlal_za_zzv: Four ZA double-vectors.
    (0xfff09c1c, 0xc1700800, 32, 4, 2, 0, 0, 0),
    // smlal_za_zzw: Two ZA double-vectors.
    (0xffe19c3c, 0xc1e00800, 32, 2, 2, 2, 0, 0),
    // smlal_za_zzw: Four ZA double-vectors.
    (0xffe39c7c, 0xc1e10800, 32, 4, 2, 2, 0, 0),
    // smlall_za_zzi: One ZA quad-vector of 32-bit elements.
    (0xfff0001c, 0xc1000000, 32, 1, 3, 1, 5, 0),
    // smlall_za_zzi: One ZA quad-vector of 64-bit elements.
    (0xfff0101c, 0xc1800000, 64, 1, 3, 1, 6, 0),
    // smlall_za_zzi: Two ZA quad-vectors of 32-bit elements.
    (0xfff09038, 0xc1100000, 32, 2, 3, 1, 7, 0),
    // smlall_za_zzi: Two ZA quad-vectors of 64-bit elements.
    (0xfff09838, 0xc1900000, 64, 2, 3, 1, 8, 0),
    // smlall_za_zzi: Four ZA quad-vectors of 32-bit elements.
    (0xfff09078, 0xc1108000, 32, 4, 3, 1, 7, 0),
    // smlall_za_zzi: Four ZA quad-vectors of 64-bit elements.
    (0xfff09878, 0xc1908000, 64, 4, 3, 1, 8, 0),
    // smlall_za_zzv: One ZA quad-vector.
    (0xffb09c1c, 0xc1200400, 0, 1, 3, 0, 0, 0),
    // smlall_za_zzv: Two ZA quad-vectors.
    (0xffb09c1e, 0xc1200000, 0, 2, 3, 0, 0, 0),
    // smlall_za_zzv: Four ZA quad-vectors.
    (0xffb09c1e, 0xc1300000, 0, 4, 3, 0, 0, 0),
    // smlall_za_zzw: Two ZA quad-vectors.
    (0xffa19c3e, 0xc1a00000, 0, 2, 3, 2, 0, 0),
    // smlall_za_zzw: Four ZA quad-vectors.
    (0xffa39c7e, 0xc1a10000, 0, 4, 3, 2, 0, 0),
    // smlsl_za_zzi: One ZA double-vector.
    (0xfff01018, 0xc1c01008, 32, 1, 2, 1, 3, 4),
    // smlsl_za_zzi: Two ZA double-vectors.
    (0xfff09038, 0xc1d01008, 32, 2, 2, 1, 4, 4),
    // smlsl_za_zzi: Four ZA double-vectors.
    (0xfff09078, 0xc1d09008, 32, 4, 2, 1, 4, 4),
    // smlsl_za_zzv: One ZA double-vector.
    (0xfff09c18, 0xc1600c08, 32, 1, 2, 0, 0, 4),
    // smlsl_za_zzv: Two ZA double-vectors.
    (0xfff09c1c, 0xc1600808, 32, 2, 2, 0, 0, 4),
    // smlsl_za_zzv: Four ZA double-vectors.
    (0xfff09c1c, 0xc1700808, 32, 4, 2, 0, 0, 4),
    // smlsl_za_zzw: Two ZA double-vectors.
    (0xffe19c3c, 0xc1e00808, 32, 2, 2, 2, 0, 4),
    // smlsl_za_zzw: Four ZA double-vectors.
    (0xffe39c7c, 0xc1e10808, 32, 4, 2, 2, 0, 4),
    // smlsll_za_zzi: One ZA quad-vector of 32-bit elements.
    (0xfff0001c, 0xc1000008, 32, 1, 3, 1, 5, 4),
    // smlsll_za_zzi: One ZA quad-vector of 64-bit elements.
    (0xfff0101c, 0xc1800008, 64, 1, 3, 1, 6, 4),
    // smlsll_za_zzi: Two ZA quad-vectors of 32-bit elements.
    (0xfff09038, 0xc1100008, 32, 2, 3, 1, 7, 4),
    // smlsll_za_zzi: Two ZA quad-vectors of 64-bit elements.
    (0xfff09838, 0xc1900008, 64, 2, 3, 1, 8, 4),
    // smlsll_za_zzi: Four ZA quad-vectors of 32-bit elements.
    (0xfff09078, 0xc1108008, 32, 4, 3, 1, 7, 4),
    // smlsll_za_zzi: Four ZA quad-vectors of 64-bit elements.
    (0xfff09878, 0xc1908008, 64, 4, 3, 1, 8, 4),
    // smlsll_za_zzv: One ZA quad-vector.
    (0xffb09c1c, 0xc1200408, 0, 1, 3, 0, 0, 4),
    // smlsll_za_zzv: Two ZA quad-vectors.
    (0xffb09c1e, 0xc1200008, 0, 2, 3, 0, 0, 4),
    // smlsll_za_zzv: Four ZA quad-vectors.
    (0xffb09c1e, 0xc1300008, 0, 4, 3, 0, 0, 4),
    // smlsll_za_zzw: Two ZA quad-vectors.
    (0xffa19c3e, 0xc1a00008, 0, 2, 3, 2, 0, 4),
    // smlsll_za_zzw: Four ZA quad-vectors.
    (0xffa39c7e, 0xc1a10008, 0, 4, 3, 2, 0, 4),
    // sudot_za_zzi: Two ZA single-vectors.
    (0xfff09038, 0xc1501038, 32, 2, 0, 1, 1, 2),
    // sudot_za_zzi: Four ZA single-vectors.
    (0xfff09078, 0xc1509038, 32, 4, 0, 1, 1, 2),
    // sudot_za_zzv: Two ZA single-vectors.
    (0xfff09c18, 0xc1201418, 32, 2, 0, 0, 0, 2),
    // sudot_za_zzv: Four ZA single-vectors.
    (0xfff09c18, 0xc1301418, 32, 4, 0, 0, 0, 2),
    // udot_za32_zzi: Two ZA single-vectors.
    (0xfff09038, 0xc1501010, 32, 2, 1, 1, 1, 3),
    // udot_za32_zzi: Four ZA single-vectors.
    (0xfff09078, 0xc1509010, 32, 4, 1, 1, 1, 3),
    // udot_za32_zzv: Two ZA single-vectors.
    (0xfff09c18, 0xc1601418, 32, 2, 1, 0, 0, 3),
    // udot_za32_zzv: Four ZA single-vectors.
    (0xfff09c18, 0xc1701418, 32, 4, 1, 0, 0, 3),
    // udot_za32_zzw: Two ZA single-vectors.
    (0xffe19c38, 0xc1e01418, 32, 2, 1, 2, 0, 3),
    // udot_za32_zzw: Four ZA single-vectors.
    (0xffe39c78, 0xc1e11418, 32, 4, 1, 2, 0, 3),
    // udot_za_zzi: Two ZA single-vectors of 32-bit elements.
    (0xfff09038, 0xc1501030, 32, 2, 0, 1, 1, 3),
    // udot_za_zzi: Two ZA single-vectors of 64-bit elements.
    (0xfff09838, 0xc1d00018, 64, 2, 0, 1, 2, 3),
    // udot_za_zzi: Four ZA single-vectors of 32-bit elements.
    (0xfff09078, 0xc1509030, 32, 4, 0, 1, 1, 3),
    // udot_za_zzi: Four ZA single-vectors of 64-bit elements.
    (0xfff09878, 0xc1d08018, 64, 4, 0, 1, 2, 3),
    // udot_za_zzv: Two ZA single-vectors.
    (0xffb09c18, 0xc1201410, 0, 2, 0, 0, 0, 3),
    // udot_za_zzv: Four ZA single-vectors.
    (0xffb09c18, 0xc1301410, 0, 4, 0, 0, 0, 3),
    // udot_za_zzw: Two ZA single-vectors.
    (0xffa19c38, 0xc1a01410, 0, 2, 0, 2, 0, 3),
    // udot_za_zzw: Four ZA single-vectors.
    (0xffa39c78, 0xc1a11410, 0, 4, 0, 2, 0, 3),
    // umlal_za_zzi: One ZA double-vector.
    (0xfff01018, 0xc1c01010, 32, 1, 2, 1, 3, 3),
    // umlal_za_zzi: Two ZA double-vectors.
    (0xfff09038, 0xc1d01010, 32, 2, 2, 1, 4, 3),
    // umlal_za_zzi: Four ZA double-vectors.
    (0xfff09078, 0xc1d09010, 32, 4, 2, 1, 4, 3),
    // umlal_za_zzv: One ZA double-vector.
    (0xfff09c18, 0xc1600c10, 32, 1, 2, 0, 0, 3),
    // umlal_za_zzv: Two ZA double-vectors.
    (0xfff09c1c, 0xc1600810, 32, 2, 2, 0, 0, 3),
    // umlal_za_zzv: Four ZA double-vectors.
    (0xfff09c1c, 0xc1700810, 32, 4, 2, 0, 0, 3),
    // umlal_za_zzw: Two ZA double-vectors.
    (0xffe19c3c, 0xc1e00810, 32, 2, 2, 2, 0, 3),
    // umlal_za_zzw: Four ZA double-vectors.
    (0xffe39c7c, 0xc1e10810, 32, 4, 2, 2, 0, 3),
    // umlall_za_zzi: One ZA quad-vector of 32-bit elements.
    (0xfff0001c, 0xc1000010, 32, 1, 3, 1, 5, 3),
    // umlall_za_zzi: One ZA quad-vector of 64-bit elements.
    (0xfff0101c, 0xc1800010, 64, 1, 3, 1, 6, 3),
    // umlall_za_zzi: Two ZA quad-vectors of 32-bit elements.
    (0xfff09038, 0xc1100010, 32, 2, 3, 1, 7, 3),
    // umlall_za_zzi: Two ZA quad-vectors of 64-bit elements.
    (0xfff09838, 0xc1900010, 64, 2, 3, 1, 8, 3),
    // umlall_za_zzi: Four ZA quad-vectors of 32-bit elements.
    (0xfff09078, 0xc1108010, 32, 4, 3, 1, 7, 3),
    // umlall_za_zzi: Four ZA quad-vectors of 64-bit elements.
    (0xfff09878, 0xc1908010, 64, 4, 3, 1, 8, 3),
    // umlall_za_zzv: One ZA quad-vector.
    (0xffb09c1c, 0xc1200410, 0, 1, 3, 0, 0, 3),
    // umlall_za_zzv: Two ZA quad-vectors.
    (0xffb09c1e, 0xc1200010, 0, 2, 3, 0, 0, 3),
    // umlall_za_zzv: Four ZA quad-vectors.
    (0xffb09c1e, 0xc1300010, 0, 4, 3, 0, 0, 3),
    // umlall_za_zzw: Two ZA quad-vectors.
    (0xffa19c3e, 0xc1a00010, 0, 2, 3, 2, 0, 3),
    // umlall_za_zzw: Four ZA quad-vectors.
    (0xffa39c7e, 0xc1a10010, 0, 4, 3, 2, 0, 3),
    // umlsl_za_zzi: One ZA double-vector.
    (0xfff01018, 0xc1c01018, 32, 1, 2, 1, 3, 7),
    // umlsl_za_zzi: Two ZA double-vectors.
    (0xfff09038, 0xc1d01018, 32, 2, 2, 1, 4, 7),
    // umlsl_za_zzi: Four ZA double-vectors.
    (0xfff09078, 0xc1d09018, 32, 4, 2, 1, 4, 7),
    // umlsl_za_zzv: One ZA double-vector.
    (0xfff09c18, 0xc1600c18, 32, 1, 2, 0, 0, 7),
    // umlsl_za_zzv: Two ZA double-vectors.
    (0xfff09c1c, 0xc1600818, 32, 2, 2, 0, 0, 7),
    // umlsl_za_zzv: Four ZA double-vectors.
    (0xfff09c1c, 0xc1700818, 32, 4, 2, 0, 0, 7),
    // umlsl_za_zzw: Two ZA double-vectors.
    (0xffe19c3c, 0xc1e00818, 32, 2, 2, 2, 0, 7),
    // umlsl_za_zzw: Four ZA double-vectors.
    (0xffe39c7c, 0xc1e10818, 32, 4, 2, 2, 0, 7),
    // umlsll_za_zzi: One ZA quad-vector of 32-bit elements.
    (0xfff0001c, 0xc1000018, 32, 1, 3, 1, 5, 7),
    // umlsll_za_zzi: One ZA quad-vector of 64-bit elements.
    (0xfff0101c, 0xc1800018, 64, 1, 3, 1, 6, 7),
    // umlsll_za_zzi: Two ZA quad-vectors of 32-bit elements.
    (0xfff09038, 0xc1100018, 32, 2, 3, 1, 7, 7),
    // umlsll_za_zzi: Two ZA quad-vectors of 64-bit elements.
    (0xfff09838, 0xc1900018, 64, 2, 3, 1, 8, 7),
    // umlsll_za_zzi: Four ZA quad-vectors of 32-bit elements.
    (0xfff09078, 0xc1108018, 32, 4, 3, 1, 7, 7),
    // umlsll_za_zzi: Four ZA quad-vectors of 64-bit elements.
    (0xfff09878, 0xc1908018, 64, 4, 3, 1, 8, 7),
    // umlsll_za_zzv: One ZA quad-vector.
    (0xffb09c1c, 0xc1200418, 0, 1, 3, 0, 0, 7),
    // umlsll_za_zzv: Two ZA quad-vectors.
    (0xffb09c1e, 0xc1200018, 0, 2, 3, 0, 0, 7),
    // umlsll_za_zzv: Four ZA quad-vectors.
    (0xffb09c1e, 0xc1300018, 0, 4, 3, 0, 0, 7),
    // umlsll_za_zzw: Two ZA quad-vectors.
    (0xffa19c3e, 0xc1a00018, 0, 2, 3, 2, 0, 7),
    // umlsll_za_zzw: Four ZA quad-vectors.
    (0xffa39c7e, 0xc1a10018, 0, 4, 3, 2, 0, 7),
    // usdot_za_zzi: Two ZA single-vectors.
    (0xfff09038, 0xc1501028, 32, 2, 0, 1, 1, 1),
    // usdot_za_zzi: Four ZA single-vectors.
    (0xfff09078, 0xc1509028, 32, 4, 0, 1, 1, 1),
    // usdot_za_zzv: Two ZA single-vectors.
    (0xfff09c18, 0xc1201408, 32, 2, 0, 0, 0, 1),
    // usdot_za_zzv: Four ZA single-vectors.
    (0xfff09c18, 0xc1301408, 32, 4, 0, 0, 0, 1),
    // usdot_za_zzw: Two ZA single-vectors.
    (0xffe19c38, 0xc1a01408, 32, 2, 0, 2, 0, 1),
    // usdot_za_zzw: Four ZA single-vectors.
    (0xffe39c78, 0xc1a11408, 32, 4, 0, 2, 0, 1),
];

/// Exact SME state/matrix families at a physical streaming length in bits.
/// Legal SVLs are 128, 256, 512, 1024 and 2048. Unrelated words return None;
/// recognized instructions with unavailable length context fail explicitly.
pub fn a64(word: u32, address: u64, svl: u16) -> Option<Recipe> {
    a64_with_endian(word, address, svl, Endian::Little)
}
/// Endian-aware SME transfers. ZA array/ZT0 byte transfers ignore data endian;
/// predicated slice and vector-group elements use the supplied data byte order.
/// Group load destinations choose permitted SVEZEROUPPER behavior. Temporal
/// versus non-temporal encodings share architectural data/state transitions;
/// the access descriptor's cache hint is not a memory atomicity guarantee.
pub fn a64_with_endian(word: u32, address: u64, svl: u16, endian: Endian) -> Option<Recipe> {
    if let Some(recipe) = super::arm64_za_outer::a64(word, address, svl) {
        return Some(recipe);
    }
    if let Some(recipe) = a64_group_memory(word, address, svl, endian) {
        return Some(recipe);
    }
    let base_integer_descriptor = base_integer_form(word);
    let integer_shift = integer_multi_round_shift_form(word);
    let integer_mul = integer_multi_mul_form(word);
    let integer_narrow_form = integer_multi_narrow_form(word);
    let integer_matrix_descriptor = integer_matrix_form(word);
    let memory = memory_form(word);
    let streaming_form = word & 0xffff_f8ff == 0xd503_407f && matches!((word >> 8) & 7, 2..=7);
    let zero_form = word & 0xffff_ff00 == 0xc008_0000;
    let mova_extract = matches!(
        word & 0xffff_0200,
        0xc0020000 | 0xc0420000 | 0xc0820000 | 0xc0c20000 | 0xc0c30000
    );
    let mova_insert = matches!(
        word & 0xffff_0010,
        0xc0000000 | 0xc0400000 | 0xc0800000 | 0xc0c00000 | 0xc0c10000
    );
    let product = if word & 0xfe80_0000 == 0xa080_0000 {
        let width = if word & (1 << 22) != 0 { 64 } else { 32 };
        let half = width == 32 && word & (1 << 3) != 0;
        let fixed = if width == 64 {
            word & 0xfec0_0008 == 0xa0c0_0000
        } else if half {
            word & 0xfee0_000c == 0xa080_0008
        } else {
            word & 0xfec0_000c == 0xa080_0000
        };
        fixed.then_some((
            width,
            Product::Integer {
                parts: if half { 2 } else { 4 },
                left_unsigned: word & (1 << 24) != 0,
                right_unsigned: if half {
                    word & (1 << 24) != 0
                } else {
                    word & (1 << 21) != 0
                },
            },
        ))
    } else {
        match word & 0xffe0_001e {
            _ if word & 0xffe0_001c == 0x80800008 || word & 0xffe0_001c == 0x80800018 => {
                Some((32, Product::Bitwise))
            }
            _ => None,
        }
    };
    let multi = multi_form(word);
    if !streaming_form
        && !zero_form
        && !mova_extract
        && !mova_insert
        && product.is_none()
        && multi.is_none()
        && memory.is_none()
        && base_integer_descriptor.is_none()
        && integer_shift.is_none()
        && integer_mul.is_none()
        && integer_narrow_form.is_none()
        && integer_matrix_descriptor.is_none()
    {
        return None;
    }
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    if !matches!(svl, 128 | 256 | 512 | 1024 | 2048) {
        r.guard = Expr::require_context(
            c(1, 0),
            "SME streaming vector length must be an architectural power of two from 128 to 2048 bits",
        );
        return Some(r);
    }
    if let Some(form) = base_integer_descriptor {
        base_integer(word, &mut r, svl, form);
    } else if let Some((nreg, group)) = integer_shift {
        integer_multi_round_shift(word, &mut r, svl, nreg, group);
    } else if let Some((nreg, group)) = integer_mul {
        integer_multi_mul(word, &mut r, svl, nreg, group);
    } else if let Some(form) = integer_narrow_form {
        integer_multi_narrow(word, &mut r, svl, form);
    } else if let Some(form) = integer_matrix_descriptor {
        integer_matrix(word, &mut r, svl, form);
    } else if let Some(memory) = memory {
        match memory {
            MemoryForm::Array => memory_array(word, &mut r, svl, false),
            MemoryForm::Table => memory_array(word, &mut r, svl, true),
            MemoryForm::Slice(width) => memory_slice(word, &mut r, svl, width, endian),
            MemoryForm::Group => memory_group(word, &mut r, svl, endian),
        }
    } else if streaming_form {
        streaming(word, &mut r);
    } else if zero_form {
        zero(word, &mut r, svl);
    } else if mova_extract || mova_insert {
        mova(word, &mut r, svl, mova_extract);
    } else if let Some((nreg, extract, array)) = multi {
        multi_mova(word, &mut r, svl, nreg, extract, array);
    } else if let Some((width, kind)) = product {
        outer(word, &mut r, svl, width, kind);
    }
    Some(r)
}

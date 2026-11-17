use super::*;

// Register contract: a64.nzcv indices 0..3 are the one-bit N/Z/C/V state
// shared with integer recipes. a64.fpcr and a64.fpsr index 0 are their 32-bit
// architectural read images, shared with floating-point recipes (not separate
// shadow copies). a32.nzcv has the same flag layout; a32.q index 0 is the
// one-bit sticky saturation flag, shared with saturating integer operations.
// a32.fpscr index 0 is the 32-bit architectural FPSCR read image shared with
// A32 floating-point recipes; its high flags are distinct from a32.nzcv until
// the architectural VMRS APSR_nzcv transfer explicitly copies them.
// a64.dit and a64.tco index 0 are one-bit PSTATE fields. a64.tpidr_el0
// and a64.tpidrro_el0 index 0 are distinct 64-bit architectural thread IDs.
// a64.dczid_el0 index 0 is the 64-bit target read image, not a guessed CPU
// constant. a64.dc_zva_permitted index 0 is a one-bit execution-context
// qualification, not an architectural register: it certifies admitted access
// and the selected ordinary Normal-memory data-zero/tag model. Device memory,
// unimplemented tag checks or trap routing cannot be admitted by setting it
// true without an exact consumer contract for those behaviors.
// Consumers must bind every bank used by a recipe or reject its lowering.
// These builders describe successful execution after instruction/feature
// validation, consistently with Recipe's ordinary-execution contract. They do
// not authorize EL/FP access or implement exception entry and trap routing.

fn unsupported(mut recipe: Recipe, reason: &'static str) -> Recipe {
    recipe.support = Support::Unsupported(reason);
    recipe
}

fn flag(bank: &'static str, index: u16) -> Expr {
    Expr::register(register(bank, index, 1, 1))
}

fn write_flags(recipe: &mut Recipe, bank: &'static str, value: Expr) {
    for index in 0..4 {
        recipe.write(
            register(bank, index, 1, 1),
            WritePolicy::ZeroUpper,
            Expr::extract(value.clone(), 31 - index as u8, 1),
        );
    }
}

fn a64_register(word: u32) -> Expr {
    if word & 31 == 31 {
        Expr::constant(64, 0)
    } else {
        Expr::register(register("a64.gpr", (word & 31) as u16, 64, 64))
    }
}

fn masked_write(recipe: &mut Recipe, bank: &'static str, value: Expr, writable_mask: u32) {
    masked_write_dynamic(
        recipe,
        bank,
        value,
        Expr::constant(32, u64::from(writable_mask)),
    );
}
fn masked_write_dynamic(recipe: &mut Recipe, bank: &'static str, value: Expr, writable_mask: Expr) {
    let old = Expr::register(register(bank, 0, 32, 32));
    let keep = Expr::binary(
        BinaryOp::And,
        old,
        Expr::unary(UnaryOp::Not, writable_mask.clone()),
    );
    let change = Expr::binary(BinaryOp::And, value, writable_mask);
    recipe.write(
        register(bank, 0, 32, 32),
        WritePolicy::ZeroUpper,
        Expr::binary(BinaryOp::Or, keep, change),
    );
}

fn a64_system_register(word: u32, mut recipe: Recipe) -> Option<Recipe> {
    let read = word & (1 << 21) != 0;
    let encoding = word & !(0x1f | (1 << 21));
    let value = match encoding {
        0xd51b4200 if read => {
            let mut packed = Expr::constant(64, 0);
            for index in 0..4 {
                let bit = Expr::binary(
                    BinaryOp::Shl,
                    Expr::cast(flag("a64.nzcv", index), 64, false),
                    Expr::constant(64, 31 - u64::from(index)),
                );
                packed = Expr::binary(BinaryOp::Or, packed, bit);
            }
            packed
        }
        0xd51b4200 => {
            write_flags(&mut recipe, "a64.nzcv", a64_register(word));
            return Some(recipe);
        }
        0xd51b4400 if read => {
            Expr::cast(Expr::register(register("a64.fpcr", 0, 32, 32)), 64, false)
        }
        0xd51b4400 => {
            let value = Expr::extract(a64_register(word), 0, 32);
            masked_write_dynamic(
                &mut recipe,
                "a64.fpcr",
                value,
                Expr::register(register("a64.fpcr_write_mask", 0, 32, 32)),
            );
            return Some(recipe);
        }
        0xd51b4420 => {
            // FPSR has QC[27], IDC[7], IXC/UFC/OFC/DZC/IOC[4:0]; the remaining
            // bits are RES0. Use the same storage as floating-point recipes.
            let value = Expr::binary(
                BinaryOp::And,
                if read {
                    Expr::register(register("a64.fpsr", 0, 32, 32))
                } else {
                    Expr::extract(a64_register(word), 0, 32)
                },
                Expr::constant(32, 0x0800009f),
            );
            if !read {
                recipe.write(
                    register("a64.fpsr", 0, 32, 32),
                    WritePolicy::ZeroUpper,
                    value,
                );
                return Some(recipe);
            }
            Expr::cast(value, 64, false)
        }
        // DIT/TCO transfer at their PSTATE bit positions, not bit zero.
        0xd51b42a0 | 0xd51b42e0 => {
            let (bank, bit) = if encoding == 0xd51b42a0 {
                ("a64.dit", 24)
            } else {
                ("a64.tco", 25)
            };
            if !read {
                recipe.write(
                    register(bank, 0, 1, 1),
                    WritePolicy::ZeroUpper,
                    Expr::extract(a64_register(word), bit, 1),
                );
                return Some(recipe);
            }
            Expr::binary(
                BinaryOp::Shl,
                Expr::cast(flag(bank, 0), 64, false),
                Expr::constant(64, u64::from(bit)),
            )
        }
        0xd51bd040 => {
            if !read {
                recipe.write(
                    register("a64.tpidr_el0", 0, 64, 64),
                    WritePolicy::ZeroUpper,
                    a64_register(word),
                );
                return Some(recipe);
            }
            Expr::register(register("a64.tpidr_el0", 0, 64, 64))
        }
        0xd51bd060 if read => Expr::register(register("a64.tpidrro_el0", 0, 64, 64)),
        0xd51b00e0 if read => Expr::register(register("a64.dczid_el0", 0, 64, 64)),
        0xd51bd060 | 0xd51b00e0 => {
            return Some(unsupported(
                recipe,
                "EL0 cannot write TPIDRRO_EL0 or DCZID_EL0",
            ))
        }
        0xd51b4220 => {
            return Some(unsupported(
                recipe,
                "DAIF access requires PSTATE interrupt masks and privilege/trap configuration",
            ));
        }
        _ => return None,
    };
    if word & 31 != 31 {
        recipe.write(
            register("a64.gpr", (word & 31) as u16, 64, 64),
            WritePolicy::ZeroUpper,
            value,
        );
    }
    Some(recipe)
}

/// Successful EL0 DC ZVA context. `dczid_el0` is the architectural read
/// image, including effective DZP. `dc_zva_permitted` certifies the selected
/// EL/trap, Normal-memory and allocation-tag context admits this ordinary
/// data-zero access; false rejects context without guessing exception routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct A64El0Context {
    pub dczid_el0: u64,
    pub dc_zva_permitted: bool,
}

fn a64_zero_block(word: u32, mut recipe: Recipe, dczid: Expr, permitted: Expr) -> Recipe {
    let bs = Expr::extract(dczid.clone(), 0, 4);
    let allowed = Expr::binary(
        BinaryOp::And,
        permitted,
        Expr::binary(
            BinaryOp::Eq,
            Expr::extract(dczid, 4, 1),
            Expr::constant(1, 0),
        ),
    );
    // Original-width memory is presently bounded to 256 bytes. Larger legal
    // target blocks require a wider memory contract, never split stores with
    // different permission/fault behavior. Do not evaluate Xt when rejected.
    recipe.guard = Expr::require_context(Expr::binary(BinaryOp::And, allowed,
        Expr::binary(BinaryOp::Ult, bs.clone(), Expr::constant(4, 7))),
        "DC ZVA requires an admitted EL0/tag context, DZP=0 and a representable block size (4..256 bytes)");
    for exponent in 0..=6 {
        let bytes = 4u16 << exponent;
        let address = Expr::binary(
            BinaryOp::And,
            a64_register(word),
            Expr::constant(64, !(u64::from(bytes) - 1)),
        );
        let selected = Expr::binary(BinaryOp::Eq, bs.clone(), Expr::constant(4, exponent));
        if bytes <= 8 {
            recipe.store_conditional(
                selected,
                Memory {kind: Default::default(), privilege: Default::default(),
                    address: Box::new(address),
                    width: (bytes * 8) as u8,
                    endian: Endian::Little,
                },
                Expr::constant((bytes * 8) as u8, 0),
            );
        } else {
            let memory = WideMemory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(address),
                width: bytes * 8,
                endian: Endian::Little,
            };
            let chunks = (0..memory.chunk_count())
                .map(|_| Expr::constant(64, 0))
                .collect();
            recipe.store_wide_conditional(selected, memory, chunks);
        }
    }
    recipe
}

/// Target-qualified DCZID read/DC ZVA pair. Both instructions use this same
/// context so software observes the block it will zero. All other instructions
/// retain `a64` behavior; no FPCR or PSTATE configuration is replaced.
pub fn a64_with_el0_context(word: u32, address: u64, context: A64El0Context) -> Option<Recipe> {
    if word & !31 == 0xd53b00e0 {
        let mut recipe = Recipe::new(address.wrapping_add(4), 64);
        if word & 31 != 31 {
            recipe.write(
                register("a64.gpr", (word & 31) as u16, 64, 64),
                WritePolicy::ZeroUpper,
                Expr::constant(64, context.dczid_el0),
            );
        }
        return Some(recipe);
    }
    if word & !31 == 0xd50b7420 {
        return Some(a64_zero_block(
            word,
            Recipe::new(address.wrapping_add(4), 64),
            Expr::constant(64, context.dczid_el0),
            Expr::constant(1, u64::from(context.dc_zva_permitted)),
        ));
    }
    a64(word, address)
}

/// Target-qualified A64 entry point for an exact FPCR register write. The mask
/// must identify writable FPCR bits on the selected implementation and feature
/// set, including implementation-defined exception-enable writability. The
/// incoming `a64.fpcr` must be its architectural read image (RES0 bits zero).
/// Non-writable bits retain that image. No target-independent mask is assumed by
/// `a64`; its default entry point reads the explicit `a64.fpcr_write_mask` bank.
/// Other instructions use `a64` unchanged.
pub fn a64_with_fpcr_write_mask(word: u32, address: u64, writable_mask: u32) -> Option<Recipe> {
    if word & !31 != 0xd51b4400 {
        return a64(word, address);
    }
    let mut recipe = Recipe::new(address.wrapping_add(4), 64);
    let incoming = Expr::extract(a64_register(word), 0, 32);
    masked_write(&mut recipe, "a64.fpcr", incoming, writable_mask);
    Some(recipe)
}

fn a32_fpscr(word: u32, mut recipe: Recipe) -> Option<Recipe> {
    match word & 0x0fff0fff {
        0x0ef10a10 => {
            let value = Expr::register(register("a32.fpscr", 0, 32, 32));
            let t = ((word >> 12) & 15) as u16;
            if t == 15 {
                write_flags(&mut recipe, "a32.nzcv", value);
            } else {
                recipe.write(
                    register("a32.gpr", t, 32, 32),
                    WritePolicy::ZeroUpper,
                    value,
                );
            }
            Some(recipe)
        }
        0x0ee10a10 => {
            let source = ((word >> 12) & 15) as u16;
            if source == 15 {
                return Some(unsupported(
                    recipe,
                    "FPSCR source PC is constrained unpredictable",
                ));
            }
            masked_write_dynamic(
                &mut recipe,
                "a32.fpscr",
                Expr::register(register("a32.gpr", source, 32, 32)),
                Expr::register(register("a32.fpscr_write_mask", 0, 32, 32)),
            );
            Some(recipe)
        }
        _ => None,
    }
}

/// Target-qualified A32 FPSCR write, using the same writable-mask/read-image
/// contract as `a64_with_fpcr_write_mask`. The caller supplies the architectural
/// predicate and pipeline updates in `recipe`. Rt=PC remains unsupported.
pub fn a32_with_fpscr_write_mask(
    word: u32,
    mut recipe: Recipe,
    writable_mask: u32,
) -> Option<Recipe> {
    if word >> 28 == 15 || word & 0x0fff0fff != 0x0ee10a10 || (word >> 12) & 15 == 15 {
        return a32(word, recipe);
    }
    let value = Expr::register(register("a32.gpr", ((word >> 12) & 15) as u16, 32, 32));
    masked_write(&mut recipe, "a32.fpscr", value, writable_mask);
    Some(recipe)
}

/// Target-qualified Thumb FPSCR write. Wide instruction words use the same
/// halfword order as `thumb`; the supplied recipe retains IT predication and
/// unconditional IT advance. Rt=PC remains unsupported.
pub fn thumb_with_fpscr_write_mask(
    word: u32,
    length: usize,
    mut recipe: Recipe,
    writable_mask: u32,
) -> Option<Recipe> {
    if length != 4 || word & 0xffff0fff != 0xeee10a10 || (word >> 12) & 15 == 15 {
        return thumb(word, length, recipe);
    }
    let value = Expr::register(register("a32.gpr", ((word >> 12) & 15) as u16, 32, 32));
    masked_write(&mut recipe, "a32.fpscr", value, writable_mask);
    Some(recipe)
}

fn a32_status_write(mut recipe: Recipe, value: Expr, spsr: bool, mask: u32) -> Recipe {
    if spsr {
        return unsupported(
            recipe,
            "SPSR access requires current mode, banked SPSR and exception-return state",
        );
    }
    // Only CPSR_f (APSR_nzcvq) is independent of the current privilege level
    // and feature set. CPSR_s also writes SSBS/PAN/DIT, not just GE. CPSR_x/c
    // can change endianness, interrupt masks and mode; none can be dropped.
    if mask != 8 {
        return unsupported(
            recipe,
            "CPSR field write requires privilege, feature and PSTATE transition state",
        );
    }
    write_flags(&mut recipe, "a32.nzcv", value.clone());
    recipe.write(
        register("a32.q", 0, 1, 1),
        WritePolicy::ZeroUpper,
        Expr::extract(value, 27, 1),
    );
    recipe
}

fn trap(mut recipe: Recipe, kind: TrapKind) -> Recipe {
    recipe.effects.push(Effect::Trap {
        kind,
        condition: Expr::constant(1, 1),
    });
    recipe
}

fn barrier(mut recipe: Recipe, kind: BarrierKind, option: u8) -> Recipe {
    // Arm's 2026-06 corpus normalizes all DMB shareability options to SY.
    // DSB *LD/*ST options likewise have LD/ST behavior; only NSH/ISH retain
    // a restricted maintenance scope. OSH and reserved options execute as SY.
    let (scope, access) = if kind == BarrierKind::InstructionSynchronization
        || kind == BarrierKind::Speculation
        || option & 3 == 0
    {
        (BarrierScope::System, BarrierAccess::All)
    } else {
        (
            if kind == BarrierKind::DataSynchronization && option & 3 == 3 {
                match option >> 2 {
                    1 => BarrierScope::NonShareable,
                    2 => BarrierScope::InnerShareable,
                    _ => BarrierScope::System,
                }
            } else {
                BarrierScope::System
            },
            match option & 3 {
                1 => BarrierAccess::Reads,
                2 => BarrierAccess::Writes,
                _ => BarrierAccess::All,
            },
        )
    };
    recipe.effects.push(Effect::Barrier {
        kind,
        scope,
        access,
        condition: None,
    });
    recipe
}

/// A64 standalone barriers, monitor clear, synchronous debug/undefined traps,
/// NZCV/FP/PSTATE transfers, EL0 thread IDs, target-qualified data zero, and
/// typed wait/event boundaries. Supervisor transitions require a separate
/// environment contract. FPCR writes use the target write-mask bank; DC ZVA
/// uses target DCZID and permission banks. Qualified entry points can supply
/// constants instead. Waits/events require the Machine environment capability.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    let mut recipe = Recipe::new(address.wrapping_add(4), 64);
    if word & 0xffffff3f == 0xd503241f { return Some(recipe); }
    if let Some(wait)=super::arm64_timedwait::a64(word,address){return Some(wait);}
    // HINTE excludes the legacy HINT subspace even when invoked without the
    // generated decoder. Its allocated extended immediate values are NOPs.
    if word&0xffd8f000==0xd5002000 && !(word&(1<<21)==0 && (word>>16)&7==3 && word&31==31){return Some(recipe);}
    if let Some(hint) = super::arm64_system_hints::a64(word, address) {
        return Some(hint);
    }
    if let Some(system) = a64_system_register(word, recipe.clone()) {
        return Some(system);
    }
    if word & !31 == 0xd50b7420 {
        return Some(a64_zero_block(
            word,
            recipe,
            Expr::register(register("a64.dczid_el0", 0, 64, 64)),
            flag("a64.dc_zva_permitted", 0),
        ));
    }
    for (encoding, bank) in [(0xd503405f, "a64.dit"), (0xd503409f, "a64.tco")] {
        if word & 0xfffff0ff == encoding {
            recipe.write(
                register(bank, 0, 1, 1),
                WritePolicy::ZeroUpper,
                Expr::constant(1, u64::from((word >> 8) & 1)),
            );
            return Some(recipe);
        }
    }
    match word {
        0xd503203f | 0xd503205f | 0xd503207f => {
            recipe.effects.push(Effect::Wait {
                allow_protection_trap: word == 0xd503207f,
            });
            return Some(recipe);
        }
        0xd503209f | 0xd50320bf => {
            recipe.effects.push(Effect::SendEvent {
                local: word == 0xd50320bf,
            });
            return Some(recipe);
        }
        _ => {}
    }
    if matches!(word & 0xfffff0ff, 0xd50340df | 0xd50340ff) {
        return Some(unsupported(
            recipe,
            "DAIFSet/DAIFClr require PSTATE interrupt masks and privilege/trap configuration",
        ));
    }
    // These PSTATE flag operations share precisely the ordinary NZCV state.
    // The decoder supplies the FlagM/FlagM2 feature legality checks.
    if matches!(word, 0xd500401f | 0xd500403f | 0xd500405f) {
        let z = flag("a64.nzcv", 1);
        let c = flag("a64.nzcv", 2);
        let v = flag("a64.nzcv", 3);
        let inv = |value| Expr::unary(UnaryOp::Not, value);
        let bin = |op, a, b| Expr::binary(op, a, b);
        if word == 0xd500401f {
            recipe.write(
                register("a64.nzcv", 2, 1, 1),
                WritePolicy::ZeroUpper,
                inv(c),
            );
        } else {
            let values = if word == 0xd500405f {
                [
                    Expr::constant(1, 0),
                    bin(BinaryOp::Or, z, v.clone()),
                    bin(BinaryOp::And, c, inv(v)),
                    Expr::constant(1, 0),
                ]
            } else {
                [
                    bin(BinaryOp::And, inv(c.clone()), inv(z.clone())),
                    bin(BinaryOp::And, z.clone(), c.clone()),
                    bin(BinaryOp::Or, c.clone(), z.clone()),
                    bin(BinaryOp::And, inv(c), z),
                ]
            };
            for (index, value) in values.into_iter().enumerate() {
                recipe.write(
                    register("a64.nzcv", index as u16, 1, 1),
                    WritePolicy::ZeroUpper,
                    value,
                );
            }
        }
        return Some(recipe);
    }
    if word & 0xffe0001f == 0xd4200000 {
        return Some(trap(recipe, TrapKind::Breakpoint));
    }
    if word & 0xffff0000 == 0 {
        return Some(trap(recipe, TrapKind::InvalidInstruction));
    }
    if word & 0xfffff0ff == 0xd503305f {
        recipe.effects.push(Effect::ExclusiveMonitorClear);
        return Some(recipe);
    }
    if word == 0xd50330ff {
        return Some(barrier(recipe, BarrierKind::Speculation, 15));
    }
    let kind = match word & 0xfffff0ff {
        0xd50330bf => BarrierKind::DataMemory,
        0xd503309f => BarrierKind::DataSynchronization,
        0xd50330df => BarrierKind::InstructionSynchronization,
        _ => return None,
    };
    Some(barrier(recipe, kind, ((word >> 8) & 15) as u8))
}

/// A32 standalone machine operations, FPSCR reads and APSR_nzcvq writes. The
/// caller supplies the instruction's architectural predicate in `recipe.guard`.
/// FPSCR writes need `a32_with_fpscr_write_mask`. CPSR reads and other CPSR/SPSR
/// byte writes report their missing state contract instead of dropping fields.
pub fn a32(word: u32, mut recipe: Recipe) -> Option<Recipe> {
    if word >> 28 != 15 {
        if let Some(fpscr) = a32_fpscr(word, recipe.clone()) {
            return Some(fpscr);
        }
        if word & 0x0fbf0fff == 0x010f0000 {
            return Some(unsupported(
                recipe,
                "MRS requires CPSR privilege-dependent read image or banked SPSR state",
            ));
        }
        if word & 0x0fb0fff0 == 0x0120f000 && word & 0x000f0000 != 0 {
            if word & 15 == 15 {
                return Some(unsupported(
                    recipe,
                    "MSR source PC is constrained unpredictable",
                ));
            }
            let value = Expr::register(register("a32.gpr", (word & 15) as u16, 32, 32));
            return Some(a32_status_write(
                recipe,
                value,
                word & (1 << 22) != 0,
                (word >> 16) & 15,
            ));
        }
        if word & 0x0fb0f000 == 0x0320f000 && word & 0x000f0000 != 0 {
            let value = (word & 255).rotate_right(((word >> 8) & 15) * 2);
            return Some(a32_status_write(
                recipe,
                Expr::constant(32, u64::from(value)),
                word & (1 << 22) != 0,
                (word >> 16) & 15,
            ));
        }
    }
    if word == 0xf57ff01f {
        recipe.guard = Expr::constant(1, 1);
        recipe.effects.push(Effect::ExclusiveMonitorClear);
        return Some(recipe);
    }
    if word == 0xf57ff070 {
        recipe.guard = Expr::constant(1, 1);
        return Some(barrier(recipe, BarrierKind::Speculation, 15));
    }
    if word & 0x0ff000f0 == 0x07f000f0 && word >> 28 != 15 {
        return Some(trap(recipe, TrapKind::InvalidInstruction));
    }
    // BKPT has AL in the architectural encoding; other conditions must not
    // inherit an ordinary conditional breakpoint recipe.
    if word & 0xfff000f0 == 0xe1200070 {
        recipe.guard = Expr::constant(1, 1);
        return Some(trap(recipe, TrapKind::Breakpoint));
    }
    let kind = match word & 0xfffffff0 {
        0xf57ff040 => BarrierKind::DataSynchronization,
        0xf57ff050 => BarrierKind::DataMemory,
        0xf57ff060 => BarrierKind::InstructionSynchronization,
        _ => return None,
    };
    // These encodings are unconditional A32 instructions (cond=1111).
    recipe.guard = Expr::constant(1, 1);
    Some(barrier(recipe, kind, (word & 15) as u8))
}

/// Thumb standalone machine operations, preserving the caller's IT predicate
/// and explicit pipeline updates. `word` places the first halfword at 31:16
/// for wide encodings, as the generated decoder does.
pub fn thumb(word: u32, length: usize, mut recipe: Recipe) -> Option<Recipe> {
    if length == 2 {
        if word > 0xffff {
            return None;
        }
        return match word & 0xff00 {
            0xde00 => Some(trap(recipe, TrapKind::InvalidInstruction)),
            // BKPT executes irrespective of the IT condition.
            0xbe00 => {
                recipe.guard = Expr::constant(1, 1);
                Some(trap(recipe, TrapKind::Breakpoint))
            }
            _ => None,
        };
    }
    if length != 4 {
        return None;
    }
    if word >> 28 == 14 {
        if let Some(fpscr) = a32_fpscr(word, recipe.clone()) {
            return Some(fpscr);
        }
    }
    if word & 0xffeff0ff == 0xf3ef8000 {
        return Some(unsupported(
            recipe,
            "MRS requires CPSR privilege-dependent read image or banked SPSR state",
        ));
    }
    if word & 0xffe0f0ff == 0xf3808000 {
        let n = (word >> 16) & 15;
        if n == 15 {
            return Some(unsupported(
                recipe,
                "MSR source PC is constrained unpredictable",
            ));
        }
        let value = Expr::register(register("a32.gpr", n as u16, 32, 32));
        return Some(a32_status_write(
            recipe,
            value,
            word & (1 << 20) != 0,
            (word >> 8) & 15,
        ));
    }
    if word & 0xfff0f000 == 0xf7f0a000 {
        return Some(trap(recipe, TrapKind::InvalidInstruction));
    }
    if word == 0xf3bf8f2f {
        recipe.effects.push(Effect::ExclusiveMonitorClear);
        return Some(recipe);
    }
    if word == 0xf3bf8f70 {
        // The decode constraint applies even when the incoming IT predicate
        // would fail. RequireContext distinguishes this unsupported context
        // from an architectural UDF trap or an arbitrary no-op choice.
        let mask = Expr::binary(
            BinaryOp::And,
            Expr::register(register("a32.itstate", 0, 8, 8)),
            Expr::constant(8, 15),
        );
        recipe.guard = Expr::require_context(
            Expr::binary(BinaryOp::Eq, mask, Expr::constant(8, 0)),
            "Thumb SB is constrained unpredictable inside an IT block",
        );
        return Some(barrier(recipe, BarrierKind::Speculation, 15));
    }
    let kind = match word & 0xfffffff0 {
        0xf3bf8f40 => BarrierKind::DataSynchronization,
        0xf3bf8f50 => BarrierKind::DataMemory,
        0xf3bf8f60 => BarrierKind::InstructionSynchronization,
        _ => return None,
    };
    Some(barrier(recipe, kind, (word & 15) as u8))
}

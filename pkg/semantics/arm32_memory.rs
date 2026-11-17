// A32/Thumb Advanced SIMD structured memory. Physical fields, spacing,
// element access sizes and alignment restrictions follow the Arm 2026-06
// VLD/VST{1,2,3,4}_{m,1,a} pseudocode. Admission/access controls belong to
// the caller. Incoming predicate and unconditional IT updates are retained.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn add(a: Expr, n: u32) -> Expr {
    b(B::Add, a, c(32, u64::from(n)))
}
fn gpr(n: u32) -> RegisterSlice {
    register("a32.gpr", n as u16, 32, 32)
}
fn vector(n: u32) -> RegisterSlice {
    register("a32.vector64", n as u16, 64, 64)
}
fn bad(mut r: Recipe) -> Recipe {
    r.support = Support::Unsupported("reserved or constrained A32 SIMD memory operands");
    r
}
#[derive(Clone, Copy)]
enum Form {
    Multiple,
    Lane(u8),
    Replicate,
}
struct Layout {
    form: Form,
    streams: u32,
    groups: u32,
    inc: u32,
    bytes: u8,
    alignment: u32,
}
fn layout(w: u32) -> Option<Layout> {
    let t = (w >> 8) & 15;
    if w & (1 << 23) == 0 {
        let size = (w >> 6) & 3;
        let a = (w >> 4) & 3;
        let (streams, groups, inc, max_align) = match t {
            7 => (1, 1, 1, 1),
            10 => (1, 2, 1, 2),
            6 => (1, 3, 1, 1),
            2 => (1, 4, 1, 3),
            8 => (2, 1, 1, 2),
            9 => (2, 1, 2, 2),
            3 => (2, 2, 2, 3),
            4 => (3, 1, 1, 1),
            5 => (3, 1, 2, 1),
            0 => (4, 1, 1, 3),
            1 => (4, 1, 2, 3),
            _ => return None,
        };
        if a > max_align || (streams != 1 && size == 3) {
            return None;
        }
        return Some(Layout {
            form: Form::Multiple,
            streams,
            groups,
            inc,
            bytes: 1 << size,
            alignment: if a == 0 { 1 } else { 4 << a },
        });
    }
    let streams = ((w >> 8) & 3) + 1;
    let size = (w >> 10) & 3;
    let ia = (w >> 4) & 15;
    if size == 3 {
        if w & (1 << 21) == 0 {
            return None;
        } // no replicate store encoding
        let s = (w >> 6) & 3;
        let a = (w >> 4) & 1;
        let t = (w >> 5) & 1;
        if (streams != 4 && s == 3)
            || (streams == 1 && s == 0 && a != 0)
            || (streams == 3 && a != 0)
            || (streams == 4 && s == 3 && a == 0)
        {
            return None;
        }
        let bytes = if s == 3 { 4 } else { 1 << s };
        let alignment = if streams == 3 || (a == 0 && s != 3) {
            1
        } else if streams == 4 {
            4 << ((s >> 1) + (s & 1))
        } else {
            streams * u32::from(bytes)
        };
        return Some(Layout {
            form: Form::Replicate,
            streams,
            groups: if streams == 1 { t + 1 } else { 1 },
            inc: if streams == 1 { 1 } else { t + 1 },
            bytes,
            alignment,
        });
    }
    let bytes = 1u8 << size;
    let index = (ia >> (size + 1)) as u8;
    let inc = if size == 0 { 1 } else { 1 + ((ia >> size) & 1) };
    let low = ia & ((1 << (size + 1)) - 1);
    let alignment = match (streams, size) {
        (1, 0) if low == 0 => 1,
        (1, 1) if low & 2 == 0 => {
            if low == 0 {
                1
            } else {
                2
            }
        }
        (1, 2) if low == 0 || low == 3 => {
            if low == 0 {
                1
            } else {
                4
            }
        }
        (2, 0) => {
            if ia & 1 == 0 {
                1
            } else {
                2
            }
        }
        (2, 1) => {
            if ia & 1 == 0 {
                1
            } else {
                4
            }
        }
        (2, 2) if ia & 2 == 0 => {
            if ia & 1 == 0 {
                1
            } else {
                8
            }
        }
        (3, 0 | 1) if ia & 1 == 0 => 1,
        (3, 2) if ia & 3 == 0 => 1,
        (4, 0) => {
            if ia & 1 == 0 {
                1
            } else {
                4
            }
        }
        (4, 1) => {
            if ia & 1 == 0 {
                1
            } else {
                8
            }
        }
        (4, 2) if ia & 3 != 3 => {
            if ia & 3 == 0 {
                1
            } else {
                4 << (ia & 3)
            }
        }
        _ => return None,
    };
    Some(Layout {
        form: Form::Lane(index),
        streams,
        groups: 1,
        inc: if streams == 1 { 1 } else { inc },
        bytes,
        alignment,
    })
}
/// A32 unconditional encoding. The caller's recipe still owns admission.
pub fn a32(word: u32, base: Recipe, endian: Endian) -> Option<Recipe> {
    if word & 0xff100000 != 0xf4000000 {
        return None;
    }
    Some(dispatch(word, base, endian))
}
/// Canonical T32 halfword order, exactly four bytes; retains dynamic IT state.
pub fn thumb(word: u32, length: u8, base: Recipe, endian: Endian) -> Option<Recipe> {
    if length != 4 || word & 0xff100000 != 0xf9000000 {
        return None;
    }
    Some(dispatch(word, base, endian))
}
fn dispatch(word: u32, mut r: Recipe, endian: Endian) -> Recipe {
    let p = match layout(word) {
        Some(p) => p,
        None => return bad(r),
    };
    let d = ((word >> 12) & 15) | ((word >> 18) & 16);
    let n = (word >> 16) & 15;
    let m = word & 15;
    if n == 15 || d + (p.streams - 1) * p.inc + p.groups > 32 {
        return bad(r);
    }
    let address = Expr::register(gpr(n));
    let aligned = b(
        B::Eq,
        b(B::And, address.clone(), c(32, u64::from(p.alignment - 1))),
        c(32, 0),
    );
    // The .64 VLD1/VST1 encodings split each element into two original .32
    // accesses. Unaligned .64 additionally depends on SCTLR alignment policy,
    // which is not a represented input: reject that context explicitly.
    if p.bytes == 8 {
        let aligned64 = b(B::Eq, b(B::And, address.clone(), c(32, 7)), c(32, 0));
        // An explicit encoded-alignment fault is determined already, even
        // when the implementation's optional alignment policy is unavailable.
        let context = Expr::select(aligned.clone(), aligned64, c(1, 1));
        r.guard = Expr::select(
            r.guard,
            Expr::require_context(
                context,
                "unaligned A32 SIMD .64 needs AlignmentEnforced context",
            ),
            c(1, 0),
        );
    }

    r.effects.push(Effect::Trap {
        kind: TrapKind::Protection,
        condition: Expr::unary(UnaryOp::Not, aligned.clone()),
    });
    let load = word & (1 << 21) != 0;
    let width = p.bytes * 8;
    let elements = if matches!(p.form, Form::Multiple) {
        8 / p.bytes
    } else {
        1
    };
    let mut offset = 0;
    // Each D register has one immutable incoming source for stores. Rn/Rm
    // always read the incoming GPR snapshot, including Rn == Rm writeback.
    let mut sources = Vec::new();
    if !load {
        for s in 0..p.streams {
            for g in 0..p.groups {
                sources.push((
                    d + s * p.inc + g,
                    r.bind(Expr::register(vector(d + s * p.inc + g))),
                ));
            }
        }
    }
    for g in 0..p.groups {
        for e in 0..elements {
            for s in 0..p.streams {
                let reg = d + s * p.inc + g;
                let lane = match p.form {
                    Form::Lane(i) => i,
                    _ => e,
                };
                let a = add(address.clone(), offset);
                if load {
                    // Replicate VLD1 with T=1 reads a single element for both D regs.
                    if matches!(p.form, Form::Replicate) && p.streams == 1 && g != 0 {
                        continue;
                    }
                    let value = if width == 64 {
                        // VLD1_m's two assignments always read data[31:0]
                        // first. BigEndian therefore reads address+4 before
                        // address; VST1_m separately keeps address order.
                        let (lo_address, hi_address) = if endian == Endian::Little {
                            (a.clone(), add(a, 4))
                        } else {
                            (add(a.clone(), 4), a)
                        };
                        let lo = guarded_load(&mut r, lo_address, 32, endian, aligned.clone());
                        let hi = guarded_load(&mut r, hi_address, 32, endian, aligned.clone());
                        b(
                            B::Or,
                            Expr::cast(lo, 64, false),
                            b(B::Shl, Expr::cast(hi, 64, false), c(64, 32)),
                        )
                    } else {
                        guarded_load(&mut r, a, width, endian, aligned.clone())
                    };
                    if matches!(p.form, Form::Replicate) {
                        let value = r.bind(value);
                        let mut replicated = c(64, 0);
                        for i in 0..64 / width {
                            replicated = b(
                                B::Or,
                                replicated,
                                b(
                                    B::Shl,
                                    Expr::cast(value.clone(), 64, false),
                                    c(64, u64::from(i * width)),
                                ),
                            );
                        }
                        let count = if p.streams == 1 { p.groups } else { 1 };
                        for group in 0..count {
                            r.write(
                                vector(reg + group),
                                WritePolicy::ZeroUpper,
                                replicated.clone(),
                            );
                        }
                    } else {
                        let mut dest = vector(reg);
                        dest.offset = lane * width;
                        dest.width = width;
                        r.write(dest, WritePolicy::Preserve, value);
                    }
                } else {
                    let source = sources
                        .iter()
                        .find(|(index, _)| *index == reg)
                        .unwrap()
                        .1
                        .clone();
                    let value = Expr::extract(source, lane * width, width);
                    if width == 64 {
                        let lo = Expr::extract(value.clone(), 0, 32);
                        let hi = Expr::extract(value, 32, 32);
                        let (first, second) = if endian == Endian::Little {
                            (lo, hi)
                        } else {
                            (hi, lo)
                        };
                        store(&mut r, a.clone(), 32, endian, first);
                        store(&mut r, add(a, 4), 32, endian, second);
                    } else {
                        store(&mut r, a, width, endian, value);
                    }
                }
                offset += u32::from(p.bytes);
            }
        }
    }
    if m != 15 {
        let delta = if m == 13 {
            c(32, u64::from(offset))
        } else {
            Expr::register(gpr(m))
        };
        r.write(gpr(n), WritePolicy::ZeroUpper, b(B::Add, address, delta));
    }
    r
}
fn guarded_load(r: &mut Recipe, address: Expr, width: u8, endian: Endian, aligned: Expr) -> Expr {
    r.bind(Expr::select(
        aligned,
        Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(address),
            width,
            endian,
        }),
        c(width, 0),
    ))
}
fn store(r: &mut Recipe, address: Expr, width: u8, endian: Endian, value: Expr) {
    r.effects.push(Effect::Store {
        memory: Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(address),
            width,
            endian,
        },
        value,
    });
}

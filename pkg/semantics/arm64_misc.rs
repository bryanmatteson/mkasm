// A64 CRC32/CRC32C, FlagM RMIF/SETF and scalar CSSC. Masks and operand
// constraints follow the Arm A-profile June 2026 XML encoding diagrams.
// Feature admission is caller-owned. Register 31 is always ZR here, never SP;
// W writes zero the parent X register. Existing NZCV indices are N/Z/C/V.
use super::*;
use BinaryOp as B;
fn c(w: u8, v: u64) -> Expr {
    Expr::constant(w, v)
}
fn b(op: B, a: Expr, z: Expr) -> Expr {
    Expr::binary(op, a, z)
}
fn input(n: u32, w: u8) -> Expr {
    if n == 31 {
        c(w, 0)
    } else {
        Expr::register(register("a64.gpr", n as u16, w, 64))
    }
}
fn output(r: &mut Recipe, n: u32, w: u8, v: Expr) {
    if n != 31 {
        r.write(
            register("a64.gpr", n as u16, w, 64),
            WritePolicy::ZeroUpper,
            v,
        );
    }
}
fn flag(r: &mut Recipe, index: u16, v: Expr) {
    r.write(register("a64.nzcv", index, 1, 1), WritePolicy::ZeroUpper, v);
}
/// Returns None for unrelated classes; recognized reserved CRC operand widths
/// return Unsupported rather than falling into an ordinary arithmetic decoder.
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let d = word & 31;
    let n = (word >> 5) & 31;
    let m = (word >> 16) & 31;
    let width = if word >> 31 != 0 { 64 } else { 32 };
    // sf and sz jointly encode B/H/W/X; accumulator and output remain W.
    if word & 0x7fe0e000 == 0x1ac04000 {
        let size = 8u8 << ((word >> 10) & 3);
        if (width == 64) != (size == 64) {
            r.support = Support::Unsupported("reserved CRC32 sf/sz combination");
            return Some(r);
        }
        let mut acc = r.bind(input(n, 32));
        let data = r.bind(input(m, size));
        let polynomial = if word & (1 << 12) == 0 {
            0xedb88320
        } else {
            0x82f63b78
        };
        for bit in 0..size {
            let feedback = b(
                B::Xor,
                Expr::extract(acc.clone(), 0, 1),
                Expr::extract(data.clone(), bit, 1),
            );
            acc = r.bind(b(
                B::Xor,
                b(B::Lsr, acc, c(32, 1)),
                Expr::select(feedback, c(32, polynomial), c(32, 0)),
            ));
        }
        output(&mut r, d, 32, acc);
        return Some(r);
    }
    if word & 0xffe07c10 == 0xba000400 {
        let mask = word & 15;
        if mask != 0 {
            let rotated = r.bind(b(B::Ror, input(n, 64), c(64, u64::from((word >> 15) & 63))));
            for i in 0..4 {
                if mask & (1 << (3 - i)) != 0 {
                    flag(
                        &mut r,
                        i as u16,
                        Expr::extract(rotated.clone(), (3 - i) as u8, 1),
                    );
                }
            }
        }
        return Some(r);
    }
    if word & 0xffffbc1f == 0x3a00080d {
        let size = if word & (1 << 14) == 0 { 8 } else { 16 };
        let value = r.bind(input(n, 32));
        let sign = Expr::extract(value.clone(), size - 1, 1);
        flag(&mut r, 0, sign.clone());
        flag(
            &mut r,
            1,
            b(B::Eq, Expr::extract(value.clone(), 0, size), c(size, 0)),
        );
        flag(&mut r, 3, b(B::Xor, Expr::extract(value, size, 1), sign));
        return Some(r);
    }
    let unary = word & 0x7ffffc00;
    if matches!(unary, 0x5ac01800 | 0x5ac01c00 | 0x5ac02000) {
        let a = r.bind(input(n, width));
        let result = match unary {
            0x5ac01800 => Expr::unary(
                UnaryOp::CountLeadingZeros,
                Expr::unary(UnaryOp::ReverseBits, a),
            ),
            0x5ac01c00 => Expr::unary(UnaryOp::PopulationCount, a),
            _ => Expr::select(
                Expr::extract(a.clone(), width - 1, 1),
                Expr::unary(UnaryOp::Neg, a.clone()),
                a,
            ),
        };
        let result = r.bind(result);
        output(&mut r, d, width, result);
        return Some(r);
    }
    let reg = word & 0x7fe0f000 == 0x1ac06000;
    let immediate = word & 0x7ff00000 == 0x11c00000;
    if reg || immediate {
        // Reg opcode[1:0] and immediate opc[1:0] select max/min, signedness.
        let operation = if reg {
            (word >> 10) & 3
        } else {
            (word >> 18) & 15
        };
        if operation > 3 {
            return None;
        }
        let unsigned = operation & 1 != 0;
        let minimum = operation & 2 != 0;
        let a = r.bind(input(n, width));
        let z = if reg {
            input(m, width)
        } else {
            let imm = (word >> 10) & 255;
            c(
                width,
                if unsigned {
                    u64::from(imm)
                } else {
                    (imm as u8 as i8 as i64) as u64
                },
            )
        };
        let z = r.bind(z);
        let less = b(if unsigned { B::Ult } else { B::Slt }, a.clone(), z.clone());
        let result = r.bind(if minimum {
            Expr::select(less, a, z)
        } else {
            Expr::select(less, z, a)
        });
        output(&mut r, d, width, result);
        return Some(r);
    }
    None
}

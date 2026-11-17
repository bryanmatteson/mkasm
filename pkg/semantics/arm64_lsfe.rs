//! All LSFE IEEE/bfloat16 load-update and store aliases, June2026 primary.
use super::*;
use AtomicFloatRmwOp as F;
use BinaryOp as B;
const FORMS: &[(u32, u32, u8, bool, F, bool)] = &[
    (0xffe0fc00, 0x3c200000, 16, true, F::Add, false), //LDBFADD_16
    (0xffe0fc00, 0x3ca00000, 16, true, F::Add, false), //LDBFADDA_16
    (0xffe0fc00, 0x3ce00000, 16, true, F::Add, false), //LDBFADDAL_16
    (0xffe0fc00, 0x3c600000, 16, true, F::Add, false), //LDBFADDL_16
    (0xffe0fc00, 0x3c204000, 16, true, F::Maximum, false), //LDBFMAX_16
    (0xffe0fc00, 0x3ca04000, 16, true, F::Maximum, false), //LDBFMAXA_16
    (0xffe0fc00, 0x3ce04000, 16, true, F::Maximum, false), //LDBFMAXAL_16
    (0xffe0fc00, 0x3c604000, 16, true, F::Maximum, false), //LDBFMAXL_16
    (0xffe0fc00, 0x3c206000, 16, true, F::MaximumNumber, false), //LDBFMAXNM_16
    (0xffe0fc00, 0x3ca06000, 16, true, F::MaximumNumber, false), //LDBFMAXNMA_16
    (0xffe0fc00, 0x3ce06000, 16, true, F::MaximumNumber, false), //LDBFMAXNMAL_16
    (0xffe0fc00, 0x3c606000, 16, true, F::MaximumNumber, false), //LDBFMAXNML_16
    (0xffe0fc00, 0x3c205000, 16, true, F::Minimum, false), //LDBFMIN_16
    (0xffe0fc00, 0x3ca05000, 16, true, F::Minimum, false), //LDBFMINA_16
    (0xffe0fc00, 0x3ce05000, 16, true, F::Minimum, false), //LDBFMINAL_16
    (0xffe0fc00, 0x3c605000, 16, true, F::Minimum, false), //LDBFMINL_16
    (0xffe0fc00, 0x3c207000, 16, true, F::MinimumNumber, false), //LDBFMINNM_16
    (0xffe0fc00, 0x3ca07000, 16, true, F::MinimumNumber, false), //LDBFMINNMA_16
    (0xffe0fc00, 0x3ce07000, 16, true, F::MinimumNumber, false), //LDBFMINNMAL_16
    (0xffe0fc00, 0x3c607000, 16, true, F::MinimumNumber, false), //LDBFMINNML_16
    (0xffe0fc00, 0x7c200000, 16, false, F::Add, false), //LDFADD_16
    (0xffe0fc00, 0x7ca00000, 16, false, F::Add, false), //LDFADDA_16
    (0xffe0fc00, 0x7ce00000, 16, false, F::Add, false), //LDFADDAL_16
    (0xffe0fc00, 0x7c600000, 16, false, F::Add, false), //LDFADDL_16
    (0xffe0fc00, 0xbc200000, 32, false, F::Add, false), //LDFADD_32
    (0xffe0fc00, 0xbca00000, 32, false, F::Add, false), //LDFADDA_32
    (0xffe0fc00, 0xbce00000, 32, false, F::Add, false), //LDFADDAL_32
    (0xffe0fc00, 0xbc600000, 32, false, F::Add, false), //LDFADDL_32
    (0xffe0fc00, 0xfc200000, 64, false, F::Add, false), //LDFADD_64
    (0xffe0fc00, 0xfca00000, 64, false, F::Add, false), //LDFADDA_64
    (0xffe0fc00, 0xfce00000, 64, false, F::Add, false), //LDFADDAL_64
    (0xffe0fc00, 0xfc600000, 64, false, F::Add, false), //LDFADDL_64
    (0xffe0fc00, 0x7c204000, 16, false, F::Maximum, false), //LDFMAX_16
    (0xffe0fc00, 0x7ca04000, 16, false, F::Maximum, false), //LDFMAXA_16
    (0xffe0fc00, 0x7ce04000, 16, false, F::Maximum, false), //LDFMAXAL_16
    (0xffe0fc00, 0x7c604000, 16, false, F::Maximum, false), //LDFMAXL_16
    (0xffe0fc00, 0xbc204000, 32, false, F::Maximum, false), //LDFMAX_32
    (0xffe0fc00, 0xbca04000, 32, false, F::Maximum, false), //LDFMAXA_32
    (0xffe0fc00, 0xbce04000, 32, false, F::Maximum, false), //LDFMAXAL_32
    (0xffe0fc00, 0xbc604000, 32, false, F::Maximum, false), //LDFMAXL_32
    (0xffe0fc00, 0xfc204000, 64, false, F::Maximum, false), //LDFMAX_64
    (0xffe0fc00, 0xfca04000, 64, false, F::Maximum, false), //LDFMAXA_64
    (0xffe0fc00, 0xfce04000, 64, false, F::Maximum, false), //LDFMAXAL_64
    (0xffe0fc00, 0xfc604000, 64, false, F::Maximum, false), //LDFMAXL_64
    (0xffe0fc00, 0x7c206000, 16, false, F::MaximumNumber, false), //LDFMAXNM_16
    (0xffe0fc00, 0x7ca06000, 16, false, F::MaximumNumber, false), //LDFMAXNMA_16
    (0xffe0fc00, 0x7ce06000, 16, false, F::MaximumNumber, false), //LDFMAXNMAL_16
    (0xffe0fc00, 0x7c606000, 16, false, F::MaximumNumber, false), //LDFMAXNML_16
    (0xffe0fc00, 0xbc206000, 32, false, F::MaximumNumber, false), //LDFMAXNM_32
    (0xffe0fc00, 0xbca06000, 32, false, F::MaximumNumber, false), //LDFMAXNMA_32
    (0xffe0fc00, 0xbce06000, 32, false, F::MaximumNumber, false), //LDFMAXNMAL_32
    (0xffe0fc00, 0xbc606000, 32, false, F::MaximumNumber, false), //LDFMAXNML_32
    (0xffe0fc00, 0xfc206000, 64, false, F::MaximumNumber, false), //LDFMAXNM_64
    (0xffe0fc00, 0xfca06000, 64, false, F::MaximumNumber, false), //LDFMAXNMA_64
    (0xffe0fc00, 0xfce06000, 64, false, F::MaximumNumber, false), //LDFMAXNMAL_64
    (0xffe0fc00, 0xfc606000, 64, false, F::MaximumNumber, false), //LDFMAXNML_64
    (0xffe0fc00, 0x7c205000, 16, false, F::Minimum, false), //LDFMIN_16
    (0xffe0fc00, 0x7ca05000, 16, false, F::Minimum, false), //LDFMINA_16
    (0xffe0fc00, 0x7ce05000, 16, false, F::Minimum, false), //LDFMINAL_16
    (0xffe0fc00, 0x7c605000, 16, false, F::Minimum, false), //LDFMINL_16
    (0xffe0fc00, 0xbc205000, 32, false, F::Minimum, false), //LDFMIN_32
    (0xffe0fc00, 0xbca05000, 32, false, F::Minimum, false), //LDFMINA_32
    (0xffe0fc00, 0xbce05000, 32, false, F::Minimum, false), //LDFMINAL_32
    (0xffe0fc00, 0xbc605000, 32, false, F::Minimum, false), //LDFMINL_32
    (0xffe0fc00, 0xfc205000, 64, false, F::Minimum, false), //LDFMIN_64
    (0xffe0fc00, 0xfca05000, 64, false, F::Minimum, false), //LDFMINA_64
    (0xffe0fc00, 0xfce05000, 64, false, F::Minimum, false), //LDFMINAL_64
    (0xffe0fc00, 0xfc605000, 64, false, F::Minimum, false), //LDFMINL_64
    (0xffe0fc00, 0x7c207000, 16, false, F::MinimumNumber, false), //LDFMINNM_16
    (0xffe0fc00, 0x7ca07000, 16, false, F::MinimumNumber, false), //LDFMINNMA_16
    (0xffe0fc00, 0x7ce07000, 16, false, F::MinimumNumber, false), //LDFMINNMAL_16
    (0xffe0fc00, 0x7c607000, 16, false, F::MinimumNumber, false), //LDFMINNML_16
    (0xffe0fc00, 0xbc207000, 32, false, F::MinimumNumber, false), //LDFMINNM_32
    (0xffe0fc00, 0xbca07000, 32, false, F::MinimumNumber, false), //LDFMINNMA_32
    (0xffe0fc00, 0xbce07000, 32, false, F::MinimumNumber, false), //LDFMINNMAL_32
    (0xffe0fc00, 0xbc607000, 32, false, F::MinimumNumber, false), //LDFMINNML_32
    (0xffe0fc00, 0xfc207000, 64, false, F::MinimumNumber, false), //LDFMINNM_64
    (0xffe0fc00, 0xfca07000, 64, false, F::MinimumNumber, false), //LDFMINNMA_64
    (0xffe0fc00, 0xfce07000, 64, false, F::MinimumNumber, false), //LDFMINNMAL_64
    (0xffe0fc00, 0xfc607000, 64, false, F::MinimumNumber, false), //LDFMINNML_64
    (0xffe0fc1f, 0x3c20801f, 16, true, F::Add, true),  //STBFADD_16
    (0xffe0fc1f, 0x3c60801f, 16, true, F::Add, true),  //STBFADDL_16
    (0xffe0fc1f, 0x3c20c01f, 16, true, F::Maximum, true), //STBFMAX_16
    (0xffe0fc1f, 0x3c60c01f, 16, true, F::Maximum, true), //STBFMAXL_16
    (0xffe0fc1f, 0x3c20e01f, 16, true, F::MaximumNumber, true), //STBFMAXNM_16
    (0xffe0fc1f, 0x3c60e01f, 16, true, F::MaximumNumber, true), //STBFMAXNML_16
    (0xffe0fc1f, 0x3c20d01f, 16, true, F::Minimum, true), //STBFMIN_16
    (0xffe0fc1f, 0x3c60d01f, 16, true, F::Minimum, true), //STBFMINL_16
    (0xffe0fc1f, 0x3c20f01f, 16, true, F::MinimumNumber, true), //STBFMINNM_16
    (0xffe0fc1f, 0x3c60f01f, 16, true, F::MinimumNumber, true), //STBFMINNML_16
    (0xffe0fc1f, 0x7c20801f, 16, false, F::Add, true), //STFADD_16
    (0xffe0fc1f, 0x7c60801f, 16, false, F::Add, true), //STFADDL_16
    (0xffe0fc1f, 0xbc20801f, 32, false, F::Add, true), //STFADD_32
    (0xffe0fc1f, 0xbc60801f, 32, false, F::Add, true), //STFADDL_32
    (0xffe0fc1f, 0xfc20801f, 64, false, F::Add, true), //STFADD_64
    (0xffe0fc1f, 0xfc60801f, 64, false, F::Add, true), //STFADDL_64
    (0xffe0fc1f, 0x7c20c01f, 16, false, F::Maximum, true), //STFMAX_16
    (0xffe0fc1f, 0x7c60c01f, 16, false, F::Maximum, true), //STFMAXL_16
    (0xffe0fc1f, 0xbc20c01f, 32, false, F::Maximum, true), //STFMAX_32
    (0xffe0fc1f, 0xbc60c01f, 32, false, F::Maximum, true), //STFMAXL_32
    (0xffe0fc1f, 0xfc20c01f, 64, false, F::Maximum, true), //STFMAX_64
    (0xffe0fc1f, 0xfc60c01f, 64, false, F::Maximum, true), //STFMAXL_64
    (0xffe0fc1f, 0x7c20e01f, 16, false, F::MaximumNumber, true), //STFMAXNM_16
    (0xffe0fc1f, 0x7c60e01f, 16, false, F::MaximumNumber, true), //STFMAXNML_16
    (0xffe0fc1f, 0xbc20e01f, 32, false, F::MaximumNumber, true), //STFMAXNM_32
    (0xffe0fc1f, 0xbc60e01f, 32, false, F::MaximumNumber, true), //STFMAXNML_32
    (0xffe0fc1f, 0xfc20e01f, 64, false, F::MaximumNumber, true), //STFMAXNM_64
    (0xffe0fc1f, 0xfc60e01f, 64, false, F::MaximumNumber, true), //STFMAXNML_64
    (0xffe0fc1f, 0x7c20d01f, 16, false, F::Minimum, true), //STFMIN_16
    (0xffe0fc1f, 0x7c60d01f, 16, false, F::Minimum, true), //STFMINL_16
    (0xffe0fc1f, 0xbc20d01f, 32, false, F::Minimum, true), //STFMIN_32
    (0xffe0fc1f, 0xbc60d01f, 32, false, F::Minimum, true), //STFMINL_32
    (0xffe0fc1f, 0xfc20d01f, 64, false, F::Minimum, true), //STFMIN_64
    (0xffe0fc1f, 0xfc60d01f, 64, false, F::Minimum, true), //STFMINL_64
    (0xffe0fc1f, 0x7c20f01f, 16, false, F::MinimumNumber, true), //STFMINNM_16
    (0xffe0fc1f, 0x7c60f01f, 16, false, F::MinimumNumber, true), //STFMINNML_16
    (0xffe0fc1f, 0xbc20f01f, 32, false, F::MinimumNumber, true), //STFMINNM_32
    (0xffe0fc1f, 0xbc60f01f, 32, false, F::MinimumNumber, true), //STFMINNML_32
    (0xffe0fc1f, 0xfc20f01f, 64, false, F::MinimumNumber, true), //STFMINNM_64
    (0xffe0fc1f, 0xfc60f01f, 64, false, F::MinimumNumber, true), //STFMINNML_64
];
pub fn a64(word: u32, address: u64, endian: Endian) -> Option<Recipe> {
    let &(_, _, width, bfloat, operation, store) = FORMS
        .iter()
        .find(|(mask, value, _, _, _, _)| word & mask == *value)?;
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let (t, n, s) = (word & 31, (word >> 5) & 31, (word >> 16) & 31);
    let acquire = word & (1 << 23) != 0;
    let release = word & (1 << 22) != 0;
    let ordering = match (acquire, release) {
        (false, false) => MemoryOrdering::Monotonic,
        (true, false) => MemoryOrdering::Acquire,
        (false, true) => MemoryOrdering::Release,
        (true, true) => MemoryOrdering::AcquireRelease,
    };
    let base = Expr::register(register(
        if n == 31 { "a64.sp" } else { "a64.gpr" },
        if n == 31 { 0 } else { n as u16 },
        64,
        64,
    ));
    if n == 31 {
        let aligned = Expr::binary(
            B::Eq,
            Expr::binary(B::And, base.clone(), Expr::constant(64, 15)),
            Expr::constant(64, 0),
        );
        r.preflight_traps.push((
            TrapKind::Protection,
            Expr::select(
                aligned,
                Expr::constant(1, 0),
                Expr::register(register("a64.sp_alignment_enforced", 0, 1, 1)),
            ),
        ));
    }
    let result = r.atomic(AtomicOperation {
        memory: Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(base),
            width,
            endian,
        },
        ordering,
        scope: MemoryScope::System,
        kind: AtomicOperationKind::FloatingPointReadModifyWrite {
            operation,
            bfloat,
            value: Expr::register(register("a64.vector64", s as u16 * 32, width, 64)),
            control: Expr::register(register("a64.fpcr", 0, 32, 32)),
        },
    });
    // Unlike integer LSE, V31 is a real destination for every load form.
    // Store encodings have their separate no-return bit set.
    if !store {
        r.write(
            register("a64.vector64", t as u16 * 32, 64, 64),
            WritePolicy::ZeroUpper,
            Expr::cast(result.value?, 64, false),
        );
        for chunk in 1..32 {
            r.write(
                register("a64.vector64", t as u16 * 32 + chunk, 64, 64),
                WritePolicy::ZeroUpper,
                Expr::constant(64, 0),
            );
        }
    }
    Some(r)
}

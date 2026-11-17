//! Non-branch A64 hints and store-bypass/nXS barriers from the June 2026 ISA.
//! Feature mask bits: CLRBHB, DGH, CMH, PCDPHINT, SPE, TRF, CHK, XS.
//! All effective controls are incoming machine inputs; no privileged state is guessed.
use super::*;
fn bit(bank: &'static str) -> Expr {
    Expr::register(register(bank, 0, 1, 1))
}
fn feature(index: u8) -> Expr {
    Expr::extract(
        Expr::register(register("a64.system_hint_features", 0, 8, 8)),
        index,
        1,
    )
}
fn event(
    r: &mut Recipe,
    kind: BarrierKind,
    scope: BarrierScope,
    access: BarrierAccess,
    condition: Option<Expr>,
) {
    r.effects.push(Effect::Barrier {
        kind,
        scope,
        access,
        condition,
    });
}
fn scope(option: u32) -> BarrierScope {
    match option {
        1 => BarrierScope::NonShareable,
        2 => BarrierScope::InnerShareable,
        _ => BarrierScope::System,
    }
}
pub fn a64(word: u32, address: u64) -> Option<Recipe> {
    let mut r = Recipe::new(address.wrapping_add(4), 64);
    let (kind, enabled) = match word {
        0xd503229f => (BarrierKind::ConsumptionSpeculativeData, None),
        0xd50322df => (BarrierKind::ClearBranchHistory, Some(0)),
        0xd50320df => (BarrierKind::DataGatheringHint, Some(1)),
        0xd503269f => (BarrierKind::StoreConcurrentPriorityHint, Some(2)),
        0xd503261f => (BarrierKind::StoreSharedKeepHint, Some(3)),
        0xd503263f => (BarrierKind::StoreSharedStreamHint, Some(3)),
        0xd503265f => (BarrierKind::SharedUpdateHint, Some(2)),
        0xd503267f => (BarrierKind::SharedUpdatePriorityHint, Some(2)),
        0xd503223f => {
            r.preflight_traps
                .push((TrapKind::Protection, bit("a64.psb_trap")));
            (BarrierKind::ProfilingSynchronization, Some(4))
        }
        0xd503225f => {
            r.preflight_traps
                .push((TrapKind::Protection, bit("a64.tsb_trap")));
            (BarrierKind::TraceSynchronization, Some(5))
        }
        0xd503251f => {
            r.guard = feature(6);
            // AArch64_ChkFeat: only bit 0 is assigned (effective GCS enable).
            // Preserve every other input bit, including unassigned selectors.
            let select = Expr::register(register("a64.gpr", 16, 64, 64));
            let enabled = Expr::cast(bit("a64.gcs_enabled"), 64, false);
            r.write(
                register("a64.gpr", 16, 64, 64),
                WritePolicy::ZeroUpper,
                Expr::binary(BinaryOp::And, select, Expr::unary(UnaryOp::Not, enabled)),
            );
            return Some(r);
        }
        0xd503309f => (BarrierKind::StoreBypass, None),
        0xd503349f => (BarrierKind::PhysicalStoreBypass, None),
        _ if word & 0xfffff3ff == 0xd503323f => {
            // Unlike hint-space instructions, an absent XS feature is UNDEFINED.
            r.preflight_traps.push((
                TrapKind::InvalidInstruction,
                Expr::unary(UnaryOp::Not, feature(7)),
            ));
            event(
                &mut r,
                BarrierKind::DataSynchronizationNoXS,
                scope((word >> 10) & 3),
                BarrierAccess::All,
                None,
            );
            return Some(r);
        }
        _ if word & 0xfffff0ff == 0xd503309f => {
            let option = (word >> 8) & 15;
            let access = match option & 3 {
                1 => BarrierAccess::Reads,
                2 => BarrierAccess::Writes,
                _ => BarrierAccess::All,
            };
            let scope = if option & 3 == 3 {
                scope(option >> 2)
            } else {
                BarrierScope::System
            };
            // Effective nXS includes FEAT_XS and the EL/HCRX_EL2.FnXS controls.
            // The environment supplies this already-resolved one-bit input.
            let nxs = bit("a64.dsb_nxs");
            event(
                &mut r,
                BarrierKind::DataSynchronization,
                scope,
                access,
                Some(Expr::unary(UnaryOp::Not, nxs.clone())),
            );
            event(
                &mut r,
                BarrierKind::DataSynchronizationNoXS,
                scope,
                access,
                Some(nxs),
            );
            return Some(r);
        }
        _ => return None,
    };
    if let Some(index) = enabled {
        r.guard = feature(index);
    }
    event(&mut r, kind, BarrierScope::System, BarrierAccess::All, None);
    Some(r)
}

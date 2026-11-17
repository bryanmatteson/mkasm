// Package semantics supplies the architecture-neutral instruction recipe schema used
// by generated Rust codecs. Recipes are explicit, audited instruction families;
// they are not inferred from mnemonics or translated documentation pseudocode.
package semantics

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed runtime.rs
var rustRuntime string

//go:embed arm64_system_hints.rs
var arm64SystemHintsRuntime string

//go:embed system.rs
var systemRuntime string

//go:embed arm64_sve_float_misc.rs
var arm64SVEFloatMiscRuntime string

//go:embed arm64_float_quad_reduce.rs
var arm64FloatQuadReduceRuntime string

//go:embed arm64_group_convert.rs
var arm64GroupConvertRuntime string

//go:embed arm64_sve_bfloat_arithmetic.rs
var arm64SVEBFloatArithmeticRuntime string

//go:embed arm64_group_bfloat.rs
var arm64GroupBFloatRuntime string

//go:embed arm64_group_integer.rs
var arm64GroupIntegerRuntime string

//go:embed arm64_group_float.rs
var arm64GroupFloatRuntime string

//go:embed arm64_za_partial.rs
var arm64ZaPartialRuntime string

//go:embed arm64_za_dot.rs
var arm64ZaDotRuntime string

//go:embed arm64_za_half_widening.rs
var arm64ZaHalfWideningRuntime string

//go:embed arm64_za_outer.rs
var arm64ZaOuterRuntime string

//go:embed arm64_za_fused.rs
var arm64ZaFusedRuntime string

//go:embed arm64_sme_state.rs
var arm64SmeStateRuntime string

//go:embed arm64_za_integer.rs
var arm64ZaIntegerRuntime string

//go:embed arm64_za_addsub.rs
var arm64ZaAddsubRuntime string

//go:embed arm64_float_lane_ops.rs
var arm64FloatLaneOpsRuntime string

//go:embed arm64_sve_float_matrix.rs
var arm64SveFloatMatrixRuntime string

//go:embed arm64_fixed_half_matrix.rs
var arm64FixedHalfMatrixRuntime string

//go:embed arm64_fixed_fp8.rs
var arm64FixedFp8Runtime string

//go:embed arm64_fp8_matrix.rs
var arm64Fp8MatrixRuntime string

//go:embed arm64_fp8_dot.rs
var arm64Fp8DotRuntime string

//go:embed arm64_fp8_widening.rs
var arm64Fp8WideningRuntime string

//go:embed arm64_bfloat_widening.rs
var arm64BfloatWideningRuntime string

//go:embed arm64_fp8.rs
var arm64Fp8Runtime string

//go:embed arm64_gcs_stack.rs
var arm64GcsStackRuntime string

//go:embed arm64_gcs_memory.rs
var arm64GcsMemoryRuntime string

//go:embed arm64_bti.rs
var arm64BtiRuntime string

//go:embed arm64_ordered.rs
var arm64OrderedRuntime string

//go:embed arm64_lsui.rs
var arm64LsuiRuntime string

//go:embed arm64_lsfe.rs
var arm64LsfeRuntime string

//go:embed arm64_timedwait.rs
var arm64TimedWait string

//go:embed arm64_ls64.rs
var arm64Ls64Runtime string

//go:embed arm64_mops.rs
var arm64MopsRuntime string

//go:embed arm64_tags.rs
var arm64TagsRuntime string

//go:embed arm64_rcw.rs
var arm64RcwRuntime string

//go:embed arm64_atomics.rs
var arm64AtomicRuntime string

//go:embed arm32_integer.rs
var arm32IntegerRuntime string

//go:embed arm64_integer.rs
var arm64IntegerRuntime string

//go:embed arm64_sme_bfloat.rs
var arm64SmeBfloatRuntime string

//go:embed arm64_sme.rs
var arm64SmeRuntime string

//go:embed arm64_float_extra.rs
var arm64FloatExtraRuntime string

//go:embed arm64_sve.rs
var arm64SveRuntime string

//go:embed arm64_crypto.rs
var arm64CryptoRuntime string

//go:embed arm64_misc.rs
var arm64MiscRuntime string

//go:embed arm64_sve_crypto.rs
var arm64SveCryptoRuntime string

//go:embed arm64_sve_crypto_group.rs
var arm64SveCryptoGroupRuntime string

//go:embed arm64_float_classic.rs
var arm64FloatClassicRuntime string

//go:embed arm64_sve_structured.rs
var arm64SveStructuredRuntime string

//go:embed arm64_sve_counter.rs
var arm64SveCounterRuntime string

//go:embed arm64_sve_misc.rs
var arm64SveMiscRuntime string

//go:embed arm64_sve_integer_extra.rs
var arm64SveIntegerExtraRuntime string

//go:embed arm64_sve_predicate_extra.rs
var arm64SvePredicateExtraRuntime string

//go:embed arm64_sve_quad_reduce.rs
var arm64SveQuadReduceRuntime string

//go:embed arm64_sve_quad_permute.rs
var arm64SveQuadPermuteRuntime string

//go:embed arm64_sve_pair_arithmetic.rs
var arm64SvePairArithmeticRuntime string

//go:embed arm64_sve_expand.rs
var arm64SveExpandRuntime string

//go:embed arm64_sve_while_extra.rs
var arm64SveWhileExtraRuntime string

//go:embed arm64_sve_integer_estimate.rs
var arm64SveIntegerEstimateRuntime string

//go:embed arm64_sve_indexed_integer.rs
var arm64SveIndexedIntegerRuntime string

//go:embed arm64_sve_replicate.rs
var arm64SveReplicateRuntime string

//go:embed arm64_sve_lookup.rs
var arm64SveLookupRuntime string

//go:embed arm64_sve_transfer.rs
var arm64SveTransferRuntime string

//go:embed arm64_sve_predicate_rearrange.rs
var arm64SvePredicateRearrangeRuntime string

//go:embed arm64_sve_nontemporal.rs
var arm64SveNontemporalRuntime string

//go:embed arm64_sve_final_data.rs
var arm64SveFinalDataRuntime string

//go:embed arm64_sve_ordinary.rs
var arm64SveOrdinaryRuntime string

//go:embed arm64_sve_memory.rs
var arm64SveMemoryRuntime string

//go:embed arm64_sve_fault.rs
var arm64SveFaultRuntime string

//go:embed arm64_pointer.rs
var arm64PointerRuntime string

//go:embed arm64_float_misc.rs
var arm64FloatMiscRuntime string

//go:embed arm64_simd_integer_extra.rs
var arm64SimdIntegerExtraRuntime string

//go:embed arm64_memory.rs
var arm64MemoryRuntime string

//go:embed arm32_crypto.rs
var arm32CryptoRuntime string

//go:embed arm32_memory.rs
var arm32MemoryRuntime string

//go:embed x87.rs
var x87Runtime string

//go:embed x86_float.rs
var x86FloatRuntime string

// RustRuntime includes the shared schema and closed architectural system
// operations. Keeping one generated module also supports standalone consumers.
var RustRuntime = rustRuntime + "\npub mod arm64_gcs_stack {\n" + arm64GcsStackRuntime + "\n}\n" + "\npub mod arm64_gcs_memory {\n" + arm64GcsMemoryRuntime + "\n}\n" + "\npub mod arm64_bti {\n" + arm64BtiRuntime + "\n}\n" + "\npub mod arm64_timedwait {\n" + arm64TimedWait + "\n}\n" + "\npub mod arm64_ls64 {\n" + arm64Ls64Runtime + "\n}\n" + "\npub mod arm64_mops {\n" + arm64MopsRuntime + "\n}\n" + "\npub mod arm64_tags {\n" + arm64TagsRuntime + "\n}\n" + "\npub mod arm64_rcw {\n" + arm64RcwRuntime + "\n}\n" + "\npub mod arm64_lsui {\n" + arm64LsuiRuntime + "\n}\n" + "\npub mod arm64_system_hints {\n" + arm64SystemHintsRuntime + "\n}\n" + "\npub mod system {\n" + systemRuntime + "\n}\n" +
	"\npub mod arm64_sve_bfloat_arithmetic {\n" + arm64SVEBFloatArithmeticRuntime + "\n}\n" +
	"\npub mod arm64_sve_float_misc {\n" + arm64SVEFloatMiscRuntime + "\n}\n" +
	"\npub mod arm64_float_quad_reduce {\n" + arm64FloatQuadReduceRuntime + "\n}\n" +
	"\npub mod arm64_group_convert {\n" + arm64GroupConvertRuntime + "\n}\n" +
	"\npub mod arm64_group_bfloat {\n" + arm64GroupBFloatRuntime + "\n}\n" +
	"\npub mod arm64_group_integer {\n" + arm64GroupIntegerRuntime + "\n}\n" +
	"\npub mod arm64_group_float {\n" + arm64GroupFloatRuntime + "\n}\n" +
	"\npub mod arm64_za_partial {\n" + arm64ZaPartialRuntime + "\n}\n" +
	"\npub mod arm64_za_dot {\n" + arm64ZaDotRuntime + "\n}\n" +
	"\npub mod arm64_za_half_widening {\n" + arm64ZaHalfWideningRuntime + "\n}\n" +
	"\npub mod arm64_za_outer {\n" + arm64ZaOuterRuntime + "\n}\n" +
	"\npub mod arm64_za_fused {\n" + arm64ZaFusedRuntime + "\n}\n" +
	"\npub mod arm64_sme_state {\n" + arm64SmeStateRuntime + "\n}\n" +
	"\npub mod arm64_za_integer {\n" + arm64ZaIntegerRuntime + "\n}\n" +
	"\npub mod arm64_za_addsub {\n" + arm64ZaAddsubRuntime + "\n}\n" +
	"\npub mod arm64_float_lane_ops {\n" + arm64FloatLaneOpsRuntime + "\n}\n" +
	"\npub mod arm64_sve_float_matrix {\n" + arm64SveFloatMatrixRuntime + "\n}\n" +
	"\npub mod arm64_fixed_half_matrix {\n" + arm64FixedHalfMatrixRuntime + "\n}\n" +
	"\npub mod arm64_fixed_fp8 {\n" + arm64FixedFp8Runtime + "\n}\n" +
	"\npub mod arm64_fp8_matrix {\n" + arm64Fp8MatrixRuntime + "\n}\n" +
	"\npub mod arm64_fp8_dot {\n" + arm64Fp8DotRuntime + "\n}\n" +
	"\npub mod arm64_fp8_widening {\n" + arm64Fp8WideningRuntime + "\n}\n" +
	"\npub mod arm64_bfloat_widening {\n" + arm64BfloatWideningRuntime + "\n}\n" +
	"\npub mod arm64_fp8 {\n" + arm64Fp8Runtime + "\n}\n" +
	"\npub mod arm64_ordered {\n" + arm64OrderedRuntime + "\n}\n" +
	"\npub mod arm64_lsfe {\n" + arm64LsfeRuntime + "\n}\n" +
	"\npub mod arm64_atomics {\n" + arm64AtomicRuntime + "\n}\n" +
	"\npub mod arm32_integer {\n" + arm32IntegerRuntime + "\n}\n" +
	"\npub mod arm64_integer {\n" + arm64IntegerRuntime + "\n}\n" +
	"\npub mod arm64_sme {\n" + arm64SmeRuntime + "\n}\n" +
	"\npub mod arm64_sme_bfloat {\n" + arm64SmeBfloatRuntime + "\n}\n" +
	"\npub mod arm64_float_extra {\n" + arm64FloatExtraRuntime + "\n}\n" +
	"\npub mod arm64_sve {\n" + arm64SveRuntime + "\n}\n" +
	"\npub mod arm64_sve_final_data {\n" + arm64SveFinalDataRuntime + "\n}\n" +
	"\npub mod arm64_sve_ordinary {\n" + arm64SveOrdinaryRuntime + "\n}\n" +
	"\npub mod arm64_sve_memory {\n" + arm64SveMemoryRuntime + "\n}\n" +
	"\npub mod arm64_sve_fault {\n" + arm64SveFaultRuntime + "\n}\n" +
	"\npub mod arm64_sve_nontemporal {\n" + arm64SveNontemporalRuntime + "\n}\n" +
	"\npub mod arm64_sve_misc {\n" + arm64SveMiscRuntime + "\n}\n" +
	"\npub mod arm64_sve_integer_extra {\n" + arm64SveIntegerExtraRuntime + "\n}\n" +
	"\npub mod arm64_sve_predicate_extra {\n" + arm64SvePredicateExtraRuntime + "\n}\n" +
	"\npub mod arm64_sve_quad_reduce {\n" + arm64SveQuadReduceRuntime + "\n}\n" +
	"\npub mod arm64_sve_quad_permute {\n" + arm64SveQuadPermuteRuntime + "\n}\n" +
	"\npub mod arm64_sve_pair_arithmetic {\n" + arm64SvePairArithmeticRuntime + "\n}\n" +
	"\npub mod arm64_sve_expand {\n" + arm64SveExpandRuntime + "\n}\n" +
	"\npub mod arm64_sve_while_extra {\n" + arm64SveWhileExtraRuntime + "\n}\n" +
	"\npub mod arm64_sve_integer_estimate {\n" + arm64SveIntegerEstimateRuntime + "\n}\n" +
	"\npub mod arm64_sve_indexed_integer {\n" + arm64SveIndexedIntegerRuntime + "\n}\n" +
	"\npub mod arm64_sve_replicate {\n" + arm64SveReplicateRuntime + "\n}\n" +
	"\npub mod arm64_sve_lookup {\n" + arm64SveLookupRuntime + "\n}\n" +
	"\npub mod arm64_sve_transfer {\n" + arm64SveTransferRuntime + "\n}\n" +
	"\npub mod arm64_sve_predicate_rearrange {\n" + arm64SvePredicateRearrangeRuntime + "\n}\n" +
	"\npub mod arm64_sve_counter {\n" + arm64SveCounterRuntime + "\n}\n" +
	"\npub mod arm64_sve_structured {\n" + arm64SveStructuredRuntime + "\n}\n" +
	"\npub mod arm64_sve_crypto {\n" + arm64SveCryptoRuntime + "\n}\n" +
	"\npub mod arm64_sve_crypto_group {\n" + arm64SveCryptoGroupRuntime + "\n}\n" +
	"\npub mod arm64_float_classic {\n" + arm64FloatClassicRuntime + "\n}\n" +
	"\npub mod arm64_crypto {\n" + arm64CryptoRuntime + "\n}\n" +
	"\npub mod arm64_misc {\n" + arm64MiscRuntime + "\n}\n" +
	"\npub mod arm64_pointer {\n" + arm64PointerRuntime + "\n}\n" +
	"\npub mod arm64_float_misc {\n" + arm64FloatMiscRuntime + "\n}\n" +
	"\npub mod arm64_simd_integer_extra {\n" + arm64SimdIntegerExtraRuntime + "\n}\n" +
	"\npub mod arm64_memory {\n" + arm64MemoryRuntime + "\n}\n" +
	"\npub mod arm32_crypto {\n" + arm32CryptoRuntime + "\n}\n" +
	"\npub mod arm32_memory {\n" + arm32MemoryRuntime + "\n}\n" +
	"\npub mod x87 {\n" + x87Runtime + "\n}\n" +
	"\npub mod x86_float {\n" + x86FloatRuntime + "\n}\n"

// WriteRust installs the identical, dependency-free schema in a generated crate.
func WriteRust(src string) error {
	return os.WriteFile(filepath.Join(src, "semantics.rs"), []byte(RustRuntime), 0644)
}

package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustA64SMEBaseInteger(t *testing.T) {
	runRustRecipeFixture(t, "arm64_sme_base_integer")
}

func TestRustA64ClassicFloat(t *testing.T) {
	runRustRecipeFixture(t, "arm64_float_classic")
}

func TestRustA64SVEReplicate(t *testing.T) {
	runRustRecipeFixture(t, "arm64_sve_replicate")
}

func TestRustA64SMELookup(t *testing.T) {
	runRustRecipeFixture(t, "arm64_sme_lookup")
}

func TestRustA64PackedLookup(t *testing.T) {
	runRustRecipeFixture(t, "arm64_sve_lookup_pointer")
}

func runRustRecipeFixture(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	body, err := os.ReadFile("testdata/" + name + ".rs")
	if err != nil {
		t.Fatal(err)
	}
	if cases, err := os.ReadFile("testdata/" + name + "_cases.rs"); err == nil {
		if err := os.WriteFile(filepath.Join(dir, name+"_cases.rs"), cases, 0644); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"semantics.rs": []byte(RustRuntime), "classic.rs": body} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"--edition=2021", "--test", "classic.rs", "-Copt-level=1", "-Dwarnings", "-o", "classic-tests"}, {"./classic-tests", "--nocapture"}} {
		var cmd *exec.Cmd
		if args[0][0] == '.' {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func TestRustA64LSE128(t *testing.T) {
	runRustRecipeFixture(t, "arm64_lse128")
}

func TestRustA64OrderedMemory(t *testing.T) {
	runRustRecipeFixture(t, "arm64_ordered")
}

func TestRustA64FP8Conversions(t *testing.T) {
	runRustRecipeFixture(t, "arm64_fp8")
}

func TestRustA64FP8ScalableConversions(t *testing.T) { runRustRecipeFixture(t, "arm64_fp8_scalable") }

func TestRustA64BFloatWidening(t *testing.T) { runRustRecipeFixture(t, "arm64_bfloat_widening") }

func TestRustA64FP8Widening(t *testing.T) { runRustRecipeFixture(t, "arm64_fp8_widening") }

func TestRustA64FP8Dot(t *testing.T) { runRustRecipeFixture(t, "arm64_fp8_dot") }

func TestRustA64FP8Matrix(t *testing.T) { runRustRecipeFixture(t, "arm64_fp8_matrix") }

func TestRustA64ZaAddSub(t *testing.T) { runRustRecipeFixture(t, "arm64_za_addsub") }

func TestRustA64ZaFused(t *testing.T) { runRustRecipeFixture(t, "arm64_za_fused") }

func TestRustA64ZaOuter(t *testing.T) { runRustRecipeFixture(t, "arm64_za_outer") }

func TestRustA64ZaHalfWidening(t *testing.T) { runRustRecipeFixture(t, "arm64_za_half_widening") }

func TestRustA64ZaDot(t *testing.T) { runRustRecipeFixture(t, "arm64_za_dot") }

func TestRustA64ZaPartial(t *testing.T) { runRustRecipeFixture(t, "arm64_za_partial") }

func TestRustA64GroupFloat(t *testing.T) { runRustRecipeFixture(t, "arm64_group_float") }

func TestRustA64GroupBFloat(t *testing.T) { runRustRecipeFixture(t, "arm64_group_bfloat") }

func TestRustA64SVEBFloatArithmetic(t *testing.T) {
	runRustRecipeFixture(t, "arm64_sve_bfloat_arithmetic")
}

func TestRustA64GroupConvert(t *testing.T) { runRustRecipeFixture(t, "arm64_group_convert") }

func TestRustA64FloatQuadReduce(t *testing.T) { runRustRecipeFixture(t, "arm64_float_quad_reduce") }

func TestRustA64SVEFloatMisc(t *testing.T) { runRustRecipeFixture(t, "arm64_sve_float_misc") }

func TestRustA64FixedFp8(t *testing.T) { runRustRecipeFixture(t, "arm64_fixed_fp8") }

func TestRustA64FixedHalfMatrix(t *testing.T) { runRustRecipeFixture(t, "arm64_fixed_half_matrix") }

func TestRustA64SVEFloatMatrix(t *testing.T) { runRustRecipeFixture(t, "arm64_sve_float_matrix") }

func TestRustA64FloatLaneOps(t *testing.T) { runRustRecipeFixture(t, "arm64_float_lane_ops") }

func TestRustA64GroupInteger(t *testing.T) { runRustRecipeFixture(t, "arm64_group_integer") }

func TestRustA64ZaInteger(t *testing.T) { runRustRecipeFixture(t, "arm64_za_integer") }

func TestRustA64ZaIntegerMultiply(t *testing.T) { runRustRecipeFixture(t, "arm64_za_integer_multiply") }

func TestRustA64SMEState(t *testing.T) { runRustRecipeFixture(t, "arm64_sme_state") }

func TestRustA64SVEOrdinary(t *testing.T) { runRustRecipeFixture(t, "arm64_sve_ordinary") }

func TestRustA64SVEFinalData(t *testing.T) { runRustRecipeFixture(t, "arm64_sve_final_data") }

func TestRustA64LSFE(t *testing.T) { runRustRecipeFixture(t, "arm64_lsfe") }

func TestRustA64SystemHints(t *testing.T) { runRustRecipeFixture(t, "arm64_system_hints") }

func TestRustA64LSUI(t *testing.T) { runRustRecipeFixture(t, "arm64_lsui") }

func TestRustA64LOR(t *testing.T) { runRustRecipeFixture(t, "arm64_lor") }

func TestRustA64RCW(t *testing.T) { runRustRecipeFixture(t, "arm64_rcw") }

func TestRustA64MOPSTags(t *testing.T) { runRustRecipeFixture(t, "arm64_mops_tags") }

func TestRustA64LS64(t *testing.T) { runRustRecipeFixture(t, "arm64_ls64") }

func TestRustA64TimedWait(t *testing.T) { runRustRecipeFixture(t, "arm64_timedwait") }

func TestRustA64ExclusivePairs(t *testing.T) { runRustRecipeFixture(t, "arm64_exclusive") }

func TestRustA64BranchTargetPipeline(t *testing.T) { runRustRecipeFixture(t, "arm64_bti") }

func TestRustA64GCSMemory(t *testing.T) { runRustRecipeFixture(t, "arm64_gcs_memory") }

func TestRustA64GCSStack(t *testing.T) { runRustRecipeFixture(t, "arm64_gcs_stack") }

func TestRustA32ScalarDSPCompletion(t *testing.T) { runRustRecipeFixture(t, "arm32_scalar_dsp") }

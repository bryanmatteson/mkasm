#!/usr/bin/env python3
"""Run the production backends against installed independent implementations.

Tool paths and source inputs are explicit JSON configuration, never downloaded.
Every selected test must actually pass: a missing test, a skipped test, a build
failure, or an unavailable reference is a failure. Reports distinguish each
test's reference and scope; passing is not a claim of exhaustive ISA semantics.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]


def jobs():
    result = []

    def add(name, targets, package, tests, reference, scope, required=(), environment=None):
        result.append(dict(name=name, architectures=targets.split(), package="./" + package,
                           tests=tests.split(), reference=reference, scope=scope,
                           required=list(required), environment=environment or {}))

    add("avr", "avr", "pkg/avr", "TestLLVMByteParity", "LLVM MC", "all imported forms, classic and tiny register profiles", ["MKASM_LLVM_MC"])
    add("ebpf", "bpfel bpfeb", "pkg/ebpf", "TestLLVMParity", "LLVM MC", "physical forms; relocation-bearing calls covered separately")
    add("loongarch", "loongarch32 loongarch64", "pkg/loongarch", "TestFullLLVMCorpus", "LLVM MC", "all imported forms", ["MKASM_LOONGARCH_JSON", "LLVM_MC"])
    add("riscv", "riscv32 riscv64", "pkg/riscv", "TestLLVMParity TestUpstreamUnassignedBitsOracle TestIndependentUpstreamCorpus", "LLVM MC and upstream Python parser", "every imported record and native physical boundary patterns through Go and fresh Rust; LLVM extension vectors", ["RISCV_OPCODES_DIR", "LLVM_MC"])
    add("powerpc", "powerpc32 powerpc32le powerpc64 powerpc64le", "pkg/powerpc", "TestLLVMWholeCorpusParity", "LLVM MC", "two samples per imported form", ["LLVM_MC", "MKASM_POWERPC_TABLEGEN_JSON"])
    add("sparc", "sparc32 sparc32le sparc64", "pkg/sparc", "TestFullCorpus", "LLVM MC and GNU assembler", "all imported samples; GNU covers LLVM32 vocabulary gaps, LE uses the native physical word", ["SPARC_TABLEGEN_JSON", "LLVM_MC", "MKASM_SPARC_AS"], {"SPARC_LLVM_PARITY": "1"})
    add("systemz", "systemz", "pkg/systemz", "TestLLVMOracle", "LLVM MC", "all imported physical forms")
    add("amdgpu", "amdgpu", "pkg/amdgpu", "TestFullLLVMCorpus", "LLVM MC assembler/disassembler/code emitter", "all assemblable source representatives and physical alternate forms", ["MKASM_AMDGPU_TABLEGEN"])
    for name, targets in [("arc-classic", "arc32 arc32be arc600 arc600be arc700 arc700be arcem arcembe"), ("arc-v3", "arc64 arc64be arcv3-32 arcv3-32be"), ("arc-nps", "arcnps400 arcnps400be")]:
        add(name, targets, "pkg/arc", "TestGNUFullCorpus", "compiled GNU binutils operand insertion routines", "three samples per imported form", ["ARC_GNU_SOURCE", "ARC_NATIVE_ORACLE"], {"ARC_MODES": targets.replace(" ", ",")})
    add("hexagon", "hexagon", "pkg/hexagon", "TestCompleteLLVMCorpus TestLLVMCombineParserLowering", "LLVM MC", "complete physical corpus, packets, parser lowering and object fixups", ["HEXAGON_SOURCE", "MKASM_LLVM_MC"], {"HEXAGON_FULL_CORPUS": "1"})
    for arch in ["msp430", "msp430x"]:
        add(arch, arch, "pkg/msp430", "TestIndependentGNUCorpus", "GNU assembler and linker", "all imported physical forms", ["MSP430_AS", "MSP430_LD"], {"MKASM_MSP430_AUDIT_ARCH": arch})
    for arch in ["mips32", "mips32el", "mips64", "mips64el", "micromips32", "micromips32el"]:
        micro = arch.startswith("micro")
        add(arch, arch, "pkg/mips", "TestLLVMWholeCorpus", "LLVM MC and GNU DSP assembler" if micro else "LLVM MC", "all source forms; five incorrect LLVM DSP layouts use GNU; derived spellings separate" if micro else "all source forms", ["MKASM_MIPS_TABLEGEN_JSON", "LLVM_MC"] + (["MKASM_MIPS_AS"] if micro else []), {"MKASM_MIPS_VALIDATE_ALL": "1", "MKASM_MIPS_AUDIT_ARCH": arch})
    for arch in ["micromips64", "micromips64el"]:
        add(arch, arch, "pkg/mips", "TestIndependentMicroMIPS64Corpus TestGNUMicro64MachineRows TestGNUMicro64BitfieldBoundaries TestIndependentGNUMicro64OperandBoundaries TestIndependentGNUMicro64RejectedBitfields", "LLVM microMIPS32 physical ISA and GNU ELF64 assembler/linker/decoder", "956 forms including 85 GNU64-only rows; native linked r5 corpus and native operand boundaries through Go and fresh Rust; r6 uses physical ISA reference", ["MKASM_MIPS_TABLEGEN_JSON", "LLVM_MC", "MKASM_MIPS_AS", "MIPS64_LD", "MKASM_REFERENCE_CLI", "MKASM_MICRO64_EXPORTER", "MKASM_MICRO64_ORACLE"], {"MKASM_MIPS_AUDIT_ARCH": arch})
    add("micro-dsp", "", "pkg/mips", "TestIndependentMicroDSPConsumers", "GNU assembler", "five corrected LLVM layouts, 60 native boundary vectors through Go, CLI generation and four fresh Rust crates", ["MKASM_MIPS_TABLEGEN_JSON", "MKASM_MIPS_AS", "MKASM_REFERENCE_CLI"])
    add("mips16", "mips16 mips16el mips16-64 mips16-64el", "pkg/mips", "TestGNU16EveryMachineRow TestGNU16ActualAssemblerCorpus TestMIPS16ExecutionContext TestMIPS16AddressWidths", "GNU assembler and compiled GNU disassembler", "all machine rows, six upstream corpora and execution-context boundaries", ["MKASM_MIPS_AS", "MKASM_MIPS16_DISASSEMBLER"])
    add("m68k", "m68k coldfire", "pkg/m68k", "TestGNUCorpus TestGNUAssemblerVectors", "GNU assembler and disassembler", "all source template lengths plus independent assembler operand vectors", ["MKASM_M68K_BINUTILS"])
    add("tricore", "tricore tricore-pcp", "pkg/tricore", "TestIndependentGhidra", "Ghidra SLEIGH compiler/assembler/disassembler", "all physical source forms and PCP mode", ["MKASM_GHIDRA_HOME"], {"MKASM_TRICORE_GHIDRA": "1"})
    add("pic", "pic12 pic16c5x pic14 pic14-enhanced pic16 pic17 pic18 pic24 pic24e pic24f pic24h dspic dspic30f dspic33f dspic33e dspic33c", "pkg/pic", "TestIndependentGhidraAllProfiles", "Ghidra assembler/disassembler/solver and gputils assembler", "all union forms and public selectors; native solver validates alternatives and gputils covers seven corrected/unsupported samples", ["MKASM_GHIDRA_HOME", "MKASM_GPASM"])
    add("v850", "v850", "pkg/v850", "TestGNUOracle TestGNUBoundaryOracle", "GNU assembler", "complete physical corpus and operand boundaries", ["MKASM_V850_AS"])
    add("mos6502", "mos6502", "pkg/mos6502", "TestCC65Oracle", "cc65 assembler and linker", "documented profile forms supported by ca65", ["MKASM_MOS6502_CC65"])
    add("w65c816", "w65c816", "pkg/w65c816", "TestCC65FullCorpusOracle", "cc65 assembler and linker", "all 256 opcode slots in four M/X states; WDM escape is raw data", ["MKASM_MOS6502_CC65"])
    add("z80", "z80 z180", "pkg/z80", "TestIndependentGNU", "GNU assembler", "all source forms; alias choices compared against complete candidate set", ["MKASM_Z80_AS"])
    add("z80-variants", "ez80 ez80-adl z80n r800 gbz80", "pkg/z80", "TestVariantGNUOracle", "GNU assembler", "all source forms; alias choices compared against complete candidate set", ["MKASM_Z80_AS"])
    add("mcs51", "mcs51 mcs80390", "pkg/mcs51", "TestIndependentSDCCAllOpcodes", "SDCC assemblers and linker", "all 255 defined opcodes and three operand patterns per target")
    add("xtensa", "xtensa xtensaeb", "pkg/xtensa", "TestIndependentAssemblerCorpus", "GNU/LLVM assemblers, Ghidra and native vendor BE fields", "all physical samples in both byte orders through Go and fresh CLI Rust; optional BE formats use native physical field composition", ["MKASM_XTENSA_GNU_AS", "MKASM_XTENSA_LLVM_MC", "MKASM_GHIDRA_HOME", "MKASM_XTENSA_LE_CONFIG", "MKASM_XTENSA_BE_CONFIG", "MKASM_XTENSA_NATIVE_FIELDS", "MKASM_REFERENCE_CLI"])
    add("jvm", "jvm", "pkg/jvm", "TestIndependentASMAllOpcodes TestJavacJavapClassWorkflow", "OpenJDK ASM, javac, javap and JVM", "all legal opcode/wide forms and boundaries; executable compiled methods")
    add("cil", "cil", "pkg/cil", "TestIndependentRuntimeEmission", ".NET Reflection.Emit and PEReader", "all 218 opcode encodings/descriptors and compiled methods with EH")
    add("dotnet", "", "pkg/dotnet", "TestCompiledEnumReferences TestCompiledNetmoduleReferences TestRewrittenAssemblyExecutes", "Roslyn, System.Reflection, PEReader and CLR", "live reference assemblies, forwarding, escaped enums, three netmodules and execution of rewritten CIL")
    add("dotnet-cli", "", "cmd/mkasm", "TestIndependentManagedCLIReference", "live Microsoft PEReader, PortablePDB reader and CLR", "actual CLI and fresh managed Rust: four images, three Portable PDBs, method/EH bytes and executable rewrite", ["MKASM_REFERENCE_CLI"])
    add("dex", "dex", "pkg/dex", "TestDexlibOracle TestSmaliWorkflow", "smali and dexlib2", "all non-reserved opcodes and payload widths; actual DEX workflow", ["MKASM_SMALI_JAR", "MKASM_BAKSMALI_JAR"])
    add("wasm", "wasm32 wasm64", "pkg/wasm", "TestIndependentWasmTools TestIndependentWATModules", "wasmparser, wasm-encoder, wat and Validator", "all 626 opcode forms per target and valid memory/SIMD/GC/memory64 modules", ["WASM_ORACLE"])
    add("spirv", "spirv", "pkg/spirv", "TestIndependentFullGrammar TestIndependentTools TestIndependentWideModule", "SPIRV-Tools", "all grammar instructions plus validated complete compute modules", ["MKASM_SPIRV_TOOLS"])
    add("ptx", "ptx", "pkg/ptx", "TestIndependentNVIDIAAssembler TestIndependentLLVMNVIDIACorpus TestIndependentUpstreamNVIDIARuns", "LLVM llc and NVIDIA ptxas", "all 594 native RUN cases, including generated matrices/textures and an explicit native ABI rejection, plus 37 compiler programs through Go and fresh CLI Rust; legacy 32-bit, SM20 through modern targets, PTX9.5 and negatives", ["MKASM_PTX_VALIDATOR", "MKASM_PTX_LEGACY_VALIDATOR", "MKASM_PTX_32_VALIDATOR", "MKASM_PTX_FERMI_VALIDATOR", "MKASM_LLC", "MKASM_LLVM_SOURCE", "MKASM_REFERENCE_CLI"])
    add("arm32", "arm32", "pkg/arm", "TestIndependentARM32LLVM", "LLVM MC", "upstream basic/NEON A32/Thumb16/Thumb32 native bytes and formatted output, both byte orders, fresh CLI Rust and structured analysis", ["MKASM_REFERENCE_ARM32_CORPUS", "MKASM_LLVM_MC", "MKASM_LLVM_SOURCE", "MKASM_REFERENCE_CLI"])
    add("aarch64", "aarch64", "tests/conformance", "TestGoAssemblerLLVMConformance TestRustAssemblerLLVMConformance", "LLVM MC and Clang", "complete exact-encoder Go/Rust corpus and all extended hints; reserved allocations rejected", ["MKASM_CORPUS", "MKASM_LLVM_MC"], {"MKASM_GO_LLVM_CONFORMANCE": "1", "MKASM_RUST_LLVM_CONFORMANCE": "1", "MKASM_LLVM_REQUIRE_ALL": "1"})
    add("x86", "x86_32 x86_64", "pkg/x86", "TestGenerateRustExecutionModes TestIndependentLLVMCorpus", "LLVM MC", "upstream scalar/AVX/AVX512 native vectors in 16/32/64 modes through Go and fresh full-corpus Rust", ["MKASM_X86_OPCODESDB", "MKASM_LLVM_SOURCE", "MKASM_LLVM_MC"])
    return result


def evaluate_events(events, tests, returncode):
    passed, skipped, failures = set(), [], []
    for event in events:
        test = event.get("Test", "")
        if event.get("Action") == "pass": passed.add(test)
        if event.get("Action") == "skip": skipped.append(test or "package")
        if event.get("Action") == "fail": failures.append(test or event.get("Package", "package"))
    missing = sorted(set(tests) - passed)
    return dict(passed=returncode == 0 and not skipped and not failures and not missing,
                returncode=returncode, skipped=skipped, failed=failures, missing_tests=missing)


def run_job(job, config, output):
    environment = os.environ | config.get("environment", {}) | job["environment"] | config.get("job_environment", {}).get(job["name"], {}) | {"MKASM_REFERENCE_STRICT": "1"}
    missing = [name for name in job["required"] if not environment.get(name)]
    record = {k: job[k] for k in ["name", "architectures", "reference", "scope", "tests"]}
    if missing:
        return record | dict(passed=False, error="missing environment: " + ", ".join(missing))
    expression = "^(" + "|".join(map(re.escape, job["tests"])) + ")$"
    command = ["go", "test", "-json", job["package"], "-run", expression, "-count=1", "-timeout=30m"]
    start = time.monotonic()
    path = output / (job["name"] + ".jsonl")
    print("Running " + job["name"] + " against " + job["reference"], flush=True)
    with path.open("w") as log:
        result = subprocess.run(command, cwd=REPO, env=environment, stdout=log, stderr=subprocess.STDOUT)
    events, evidence = [], []
    for line in path.read_text().splitlines():
        try: event = json.loads(line)
        except json.JSONDecodeError: continue
        events.append(event)
        text = event.get("Output", "").strip()
        if text and not text.startswith(("===", "---", "PASS", "ok ")): evidence.append(text)
    record |= evaluate_events(events, job["tests"], result.returncode)
    record |= dict(seconds=round(time.monotonic() - start, 3), command=command, log=str(path), evidence=evidence)
    print(("PASS " if record["passed"] else "FAIL ") + job["name"], flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="JSON environment and optional job_environment dictionaries")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True, help="current mkasm executable; its target list must match the suite")
    parser.add_argument("--only", help="comma-separated job names for a focused rerun")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    config.setdefault("environment", {})["MKASM_REFERENCE_CLI"] = str(args.cli.resolve())
    registered = subprocess.check_output([str(args.cli.resolve()), "--list-architectures"], text=True).split()
    suite = jobs()
    covered = [arch for job in suite for arch in job["architectures"]]
    if len(covered) != len(set(covered)) or set(covered) != set(registered):
        parser.error(f"target coverage differs from CLI: missing={sorted(set(registered)-set(covered))} extra={sorted(set(covered)-set(registered))}")
    if args.jobs < 1: parser.error("--jobs must be positive")
    if args.only:
        selected = set(args.only.split(","))
        if selected - {job["name"] for job in suite}: parser.error("unknown --only job")
        suite = [job for job in suite if job["name"] in selected]
    args.output.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(lambda job: run_job(job, config, args.output), suite))
    report = dict(registered_targets=len(registered), selected_targets=sum(len(r["architectures"]) for r in results),
                  passed=all(r["passed"] for r in results), results=results)
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Reference checks: {sum(r['passed'] for r in results)}/{len(results)} jobs passed; {report['selected_targets']} targets selected", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

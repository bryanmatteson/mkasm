#!/usr/bin/env python3
"""Export a resolved upstream LLVM instruction corpus for mkasm.

The source checkout and llvm-tblgen must come from the same LLVM release. This
does not synthesize instructions, extract examples, or discard target records.
"""

import argparse
import pathlib
import shutil
import subprocess


TARGETS = {
    "avr": "AVR", "ebpf": "BPF", "loongarch": "LoongArch",
    "mips": "Mips", "powerpc": "PowerPC", "msp430": "MSP430",
    "sparc": "Sparc", "systemz": "SystemZ", "m68k": "M68k",
    "xtensa": "Xtensa", "arc": "ARC", "hexagon": "Hexagon",
    "amdgpu": "AMDGPU", "nvptx": "NVPTX",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=pathlib.Path,
                        help="llvm-project checkout, or its llvm/ subdirectory")
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-tblgen", default=shutil.which("llvm-tblgen"))
    args = parser.parse_args()
    if not args.llvm_tblgen:
        parser.error("llvm-tblgen is required; supply --llvm-tblgen")
    source = args.source.resolve()
    if (source / "llvm" / "include").is_dir():
        source /= "llvm"
    target = TARGETS[args.target]
    directory = source / "lib" / "Target" / target
    definition = directory / (target + ".td")
    if not definition.is_file():
        parser.error(f"missing upstream target description: {definition}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        args.llvm_tblgen, "--dump-json", "-I", str(source / "include"),
        "-I", str(directory), str(definition), "-o", str(args.output),
    ], check=True)


if __name__ == "__main__":
    main()

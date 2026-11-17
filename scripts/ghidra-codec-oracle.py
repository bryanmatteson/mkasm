#!/usr/bin/env python3
"""Run an optional independent Ghidra assembly/disassembly oracle over JSONL.

Requires an existing Ghidra installation and its supported Java development kit.
Example request: {"language":"6502:LE:16:default","bytes":"a92a"}
Ghidra diagnostics go to stderr; stdout contains only JSON responses. Each
request may supply assembly, bytes, address (decimal/0x string), and context.
language_definitions may point to a separate .ldefs and compiled SLA files for
an independently built source revision without modifying the Ghidra install.
Compiled helper files are stored beneath the caller's artifact directory.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", type=Path, default=Path.home() / "Ghidra")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    home = args.ghidra.expanduser().resolve(strict=True)
    if not (home / "support/analyzeHeadless").is_file():
        parser.error("--ghidra must point at an installed Ghidra distribution")
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("ghidra-codec-oracle") / "CodecOracle.java"
    jars = sorted((home / "Ghidra").rglob("*.jar"))
    classpath = os.pathsep.join(map(str, jars))
    compiled = output / "CodecOracle.class"
    if not compiled.is_file() or compiled.stat().st_mtime < source.stat().st_mtime:
        subprocess.run(["javac", "-proc:none", "-cp", classpath, "-d", str(output), str(source)], check=True)
    command = ["java", "-Djava.awt.headless=true", "-cp", str(output) + os.pathsep + classpath,
               "CodecOracle", str(home)]
    os.execvp(command[0], command)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Ghidra oracle failed: {error}", file=sys.stderr)
        sys.exit(1)

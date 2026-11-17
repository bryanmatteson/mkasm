#!/usr/bin/env python3
"""Read LLVM's positive NVIDIA-verified RUN cases without invoking a shell.

The LLVM source selects compiler features and native assembler options. FileCheck
comments and expected PTX strings never supply the comparison output.
"""
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys


def commands(source):
    joined = []
    marker = ";" if source.suffix == ".ll" else "#"
    for line in source.read_text().splitlines():
        match = re.match(r"\s*" + marker + r" RUN:\s*(.*)", line)
        if not match:
            continue
        command = match[1].strip()
        if joined and joined[-1].endswith("\\"):
            joined[-1] = joined[-1][:-1] + command
        else:
            joined.append(command)
    return joined


def generate(source, joined, output):
    """Run the upstream generator's exact argv, with task-owned output paths."""
    if output is None:
        raise ValueError(f"{source.name}: generated native corpus needs an output directory")
    directory = (output / source.stem).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    prefix = str(directory / "generated")
    generated = {}
    for command in joined:
        if not command.startswith("%python %s "):
            continue
        argv = shlex.split(command)
        if len(argv) < 4 or argv[-2] != ">" or any(c in command for c in "|$`;&"):
            raise ValueError(f"{source.name}: unsupported generator command {command}")
        destination = argv[-1]
        if not destination.startswith("%t"):
            raise ValueError(f"{source.name}: generator output is not task-owned")
        argv = [str(source) if a == "%s" else a.replace("%t", prefix) for a in argv[1:-2]]
        if any("%" in a for a in argv):
            raise ValueError(f"{source.name}: unresolved generator argument")
        path = Path(destination.replace("%t", prefix))
        with path.open("wb") as stream:
            subprocess.run([sys.executable, *argv], cwd=source.parent, stdout=stream,
                           stderr=subprocess.PIPE, check=True, timeout=60,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if not path.stat().st_size:
            raise ValueError(f"{source.name}: empty native generator output")
        generated[destination] = path
    if not generated:
        raise ValueError(f"{source.name}: no supported primary generator")
    return generated


def read_runs(root, generated_output=None):
    result = []
    corpus = root / "llvm/test/CodeGen/NVPTX"
    for source in sorted([*corpus.glob("*.ll"), *corpus.glob("*.py")]):
        joined = commands(source)
        if not any("%ptxas-verify" in c for c in joined):
            continue
        inputs = {"%s": source} if source.suffix == ".ll" else generate(source, joined, generated_output)
        ordinal = 0
        for command in joined:
            if "%ptxas-verify" not in command:
                continue
            ordinal += 1
            start = command.find("llc")
            if start < 0 or "not llc" in command:
                raise ValueError(f"{source.name}: unsupported native RUN: {command}")
            compiler, rest = command[start + 3:].split("|", 1)
            arguments = shlex.split(compiler)
            cleaned = []
            input_path = None
            while arguments:
                arg = arguments.pop(0)
                if arg == "<":
                    if not arguments or arguments[0] not in inputs:
                        raise ValueError(f"{source.name}: unsupported compiler input")
                    if input_path is not None:
                        raise ValueError(f"{source.name}: repeated compiler input")
                    input_path = inputs[arguments.pop(0)]
                elif arg in inputs:
                    if input_path is not None:
                        raise ValueError(f"{source.name}: repeated compiler input")
                    input_path = inputs[arg]
                elif arg.startswith("-") and not any(c in arg for c in "$`%"):
                    cleaned.append(arg)
                else:
                    raise ValueError(f"{source.name}: unsupported compiler argument {arg!r}")
            if input_path is None:
                raise ValueError(f"{source.name}: no primary IR input")
            native = shlex.split(rest.split("%ptxas-verify", 1)[1].strip().removesuffix("%}").strip())
            options = iter(native)
            for arg in options:
                if arg in {"-arch", "--gpu-name"}:
                    if not re.fullmatch(r"sm_[0-9]+[af]?", next(options, "")):
                        raise ValueError(f"{source.name}: unsupported native architecture")
                elif arg.startswith(("-arch=", "--gpu-name=")):
                    if not re.fullmatch(r"sm_[0-9]+[af]?", arg.split("=", 1)[1]):
                        raise ValueError(f"{source.name}: unsupported native architecture")
                elif arg not in {"-m32", "-m64"}:
                    raise ValueError(f"{source.name}: unsupported native argument {arg!r}")
            result.append(dict(name=f"{source.stem}-{ordinal}", source=str(input_path),
                               llc=cleaned, ptxas=native))
    if not result:
        raise ValueError("no native NVIDIA RUN cases found")
    return result


if __name__ == "__main__":
    json.dump(read_runs(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) > 2 else None), sys.stdout)
    print()

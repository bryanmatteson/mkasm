#!/usr/bin/env python3
"""Expand all NPS400 vendor macros from GNU binutils 2.44 into an ARC archive.

The source table and license are retained alongside the resolved table. No C
compiler or assembler is needed when importing the resulting archive.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="GNU binutils source directory")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("arc_export", Path(__file__).with_name("export-arc64.py"))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    opcodes = args.source / "opcodes"
    files = {name: (opcodes / name).read_bytes() for name in ("arc-tbl.h", "arc-opc.c", "arc-fxi.h")}
    for name, expected in (("arc-nps400-tbl.h", 352), ("arc-ext-tbl.h", 58)):
        source = opcodes / name
        header = re.sub(r"(?m)^#include[^\n]*", "", (args.source / "include/opcode/arc.h").read_text())
        with tempfile.TemporaryDirectory(prefix="mkasm-nps-export-") as temporary:
            unit = Path(temporary) / "table.c"
            unit.write_text(header + "\n" + source.read_text())
            text = subprocess.check_output(["cc", "-E", "-P", "-x", "c", str(unit)], text=True)
        while re.search(r'"([^"\n]*)"\s*"([^"\n]*)"', text):
            text = re.sub(r'"([^"\n]*)"\s*"([^"\n]*)"', lambda m: '"' + m[1] + m[2] + '"', text)
        row = re.compile(r'\{\s*"([^"]+)",\s*(.*?),\s*(.*?),\s*([^,]+),\s*(\w+),\s*(\w+),\s*\{([^}]+)\},\s*\{([^}]+)\}\s*\}', re.S)
        rows = []
        for match in row.finditer(text):
            mnemonic, value, mask, cpu, kind, feature, operands, flags = match.groups()
            operands = operands.strip().rstrip(",")
            rows.append(f'{{ "{mnemonic}", 0x{helper.integer(value):x}, 0x{helper.integer(mask):x}, {helper.integer(cpu):#x}, {kind}, {feature}, {{ {operands} }}, {{ {flags} }} }},')
        if len(rows) != expected:
            raise ValueError(f"expected all {expected} GNU 2.44 {name} rows, got {len(rows)}")
        files[name] = ("\n".join(rows) + "\n").encode()
        files["UPSTREAM-" + name] = source.read_bytes()
        print(f"{len(rows)} resolved {name} rows")
    files.update({"COPYING3": (args.source / "COPYING3").read_bytes(),
                  "SOURCE-PIN": b"GNU binutils 2.44; scripts/export-arc-nps400.py\n"})
    helper.write_archive(args.output, files)


if __name__ == "__main__":
    main()

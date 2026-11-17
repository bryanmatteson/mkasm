#!/usr/bin/env python3
"""Resolve the pinned GNU ARCv3 macro tables into a source archive for mkasm.

Uses only the C preprocessor for macro expansion. Integer expressions are
evaluated with a restricted AST interpreter; symbolic operands and flags remain
source names, so changing a GNU enum cannot silently change the imported ISA.
"""
import argparse
import ast
import gzip
import io
import operator
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

PIN = "e3f952f340d16cbee94277d023273a42b47b6648"
OPS = {ast.Add:operator.add, ast.Sub:operator.sub, ast.Mult:operator.mul,
       ast.LShift:operator.lshift, ast.RShift:operator.rshift,
       ast.BitOr:operator.or_, ast.BitAnd:operator.and_, ast.BitXor:operator.xor}

def integer(text):
    text = re.sub(r"(?i)\b(0x[0-9a-f]+|\d+)[ul]+\b", r"\1", text)
    def visit(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int): return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in OPS: return OPS[type(n.op)](visit(n.left), visit(n.right))
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Invert): return ~visit(n.operand)
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub): return -visit(n.operand)
        raise ValueError(f"unresolved GNU integer expression {text}")
    return visit(ast.parse(text.strip(), mode="eval").body) & ((1<<64)-1)

def definitions(path, macro):
    text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.S)
    for m in re.finditer(r"\b"+macro+r"\((.*?)\)", text, re.S):
        yield [v.strip() for v in m[1].split(",")]

def write_archive(output, contents):
    """Keep both tar member headers and the gzip header reproducible."""
    with output.open("wb") as stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in contents.items():
                    raw = data.encode() if isinstance(data, str) else data
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime = len(raw), 0
                    archive.addfile(info, io.BytesIO(raw))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="pinned upstream binutils source directory")
    p.add_argument("output", type=Path)
    a = p.parse_args(); src = a.source/"opcodes"
    header = (a.source/"include/opcode/arc.h").read_text()
    macros = re.sub(r"(?m)^#include[^\n]*", "", header)
    text = macros+"\n"+(src/"arc64-opc.c").read_text().replace('#include "arcxx-opc.inc"', "")
    with tempfile.TemporaryDirectory(prefix="mkasm-arc-export-") as t:
        f = Path(t)/"arc64.c"; f.write_text(text)
        text = subprocess.check_output(["cc", "-E", "-P", "-I", str(src), str(f)], text=True)
    # Adjacent C string literals produced by token-pasting macros are one name.
    while re.search(r'"([^"\n]*)"\s*"([^"\n]*)"', text):
        text = re.sub(r'"([^"\n]*)"\s*"([^"\n]*)"', lambda m: '"'+m[1]+m[2]+'"', text)
    row = re.compile(r'\{\s*"([^"]+)",\s*(.*?),\s*(.*?),\s*([^,]+),\s*(\w+),\s*(\w+),\s*\{([^}]+)\},\s*\{([^}]+)\}\s*\}', re.S)
    rows = []
    for m in row.finditer(text):
        name,value,mask,cpu,kind,feature,operands,flags = m.groups()
        rows.append(f'{{ "{name}", 0x{integer(value):x}, 0x{integer(mask):x}, {integer(cpu):#x}, {kind}, {feature}, {{ {operands} }}, {{ {flags} }} }},')
    if len(rows) != 4289:
        raise ValueError(f"expected all 4289 ARCv3 source rows at {PIN}, got {len(rows)}")
    metadata = ['const struct arc_operand arc_operands[] = {']
    for name,*values in definitions(src/"arc-operands.def", "ARC_OPERAND"):
        metadata += [f'#define {name}', '{ '+', '.join(values)+' },']
    metadata += ['};', 'const struct arc_flag_operand arc_flag_operands[] = {']
    for name,*values in definitions(src/"arc-flag.def", "FLAG"):
        metadata += [f'#define F_{name}', '{ '+', '.join(values)+' },']
    metadata += ['};', 'const struct arc_flag_class arc_flag_classes[] = {']
    for name,kind,a0,a1,*values in definitions(src/"arc-flag-classes.def", "FLAG_CLASS"):
        metadata += [f'#define C_{name}', '{ '+kind+', '+a0+', '+a1+', { '+', '.join(values)+' } },']
    metadata += ['};']
    contents = {'arc-tbl.h':'\n'.join(rows)+'\n',
                'arc-opc.c':'\n'.join(metadata)+'\n',
                'arc-fxi.h':(src/"arcxx-opc.inc").read_text()+'\n'+(src/"arc-fxi.h").read_text(),
                'COPYING3':(a.source/"COPYING3").read_text(),
                'SOURCE-PIN':PIN+'\nGenerated with scripts/export-arc64.py from the complete macro-expanded ARCv3 table.\n'}
    # Preserve the original macro inputs too, including their source notices.
    # The importer selects only the resolved C tables above.
    for name in ("arc64-opc.c", "arc64-tbl.h", "arc-operands.def", "arc-flag.def", "arc-flag-classes.def"):
        contents['UPSTREAM-'+name] = (src/name).read_bytes()
    contents['UPSTREAM-arc.h'] = (a.source/"include/opcode/arc.h").read_bytes()
    write_archive(a.output, contents)
    print(f"{len(rows)} resolved source opcode rows")

if __name__ == '__main__': main()

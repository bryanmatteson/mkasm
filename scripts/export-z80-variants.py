#!/usr/bin/env python3
"""Resolve GNU binutils 2.44's variant tables into mkasm's physical model.

The primary decoder runs unchanged behind a small BFD I/O adapter. Each operand
bit is independently varied to recover its printed numeric field. The exporter
rejects nonlinear or unaccounted-for fields instead of inventing encodings.
No C compiler or BFD dependency is needed by the resulting Go or Rust libraries.
"""
import argparse
import base64
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile

ADAPTER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#define ATTRIBUTE_UNUSED __attribute__((unused))
typedef uint64_t bfd_vma;
typedef int (*fprintf_ftype)(void *, const char *, ...);
typedef struct disassemble_info disassemble_info;
struct disassemble_info {
  int bytes_per_line; unsigned long mach; void *stream;
  fprintf_ftype fprintf_func;
  int (*read_memory_func)(bfd_vma, unsigned char *, unsigned, disassemble_info *);
  void (*memory_error_func)(int, bfd_vma, disassemble_info *);
};
#define bfd_mach_z80strict 1
#define bfd_mach_z180 2
#define bfd_mach_z80 3
#define bfd_mach_ez80_z80 4
#define bfd_mach_ez80_adl 5
#define bfd_mach_z80n 6
#define bfd_mach_z80full 7
#define bfd_mach_gbz80 8
#define bfd_mach_r800 11
static unsigned char input[32]; static uint64_t pc;
static int readmem(bfd_vma p,unsigned char *b,unsigned n,disassemble_info *i ATTRIBUTE_UNUSED){
  if(p<pc || p-pc+n>sizeof(input)) return 1;
  memcpy(b,input+p-pc,n); return 0;
}
static void memerr(int e ATTRIBUTE_UNUSED,bfd_vma p ATTRIBUTE_UNUSED,disassemble_info *i ATTRIBUTE_UNUSED){}
static int output(void *p,const char *f,...){
  char *s=p; va_list a; va_start(a,f); int n=vsnprintf(s+strlen(s),512-strlen(s),f,a); va_end(a); return n;
}
'''
MAIN = r'''
int main(void){
  char hex[65], result[512]; unsigned long mach;
  while(scanf("%lu %llu %64s",&mach,(unsigned long long *)&pc,hex)==3){
    memset(input,0,sizeof(input)); result[0]=0;
    for(unsigned i=0;i<strlen(hex)/2;i++){unsigned n;sscanf(hex+2*i,"%2x",&n);input[i]=n;}
    disassemble_info info={0}; info.mach=mach;info.stream=result;info.fprintf_func=output;
    info.read_memory_func=readmem;info.memory_error_func=memerr;
    int n=print_insn_z80(pc,&info);printf("%d\t%s\n",n,result);fflush(stdout);
  }
  return 0;
}
'''
NUMBER = re.compile(r"(?<![a-zA-Z0-9_])(-?0x[0-9a-fA-F]+|-?\d+)(?![a-zA-Z0-9_])")
TARGETS = {"ez80": 4, "ez80-adl": 5, "z80n": 6, "gbz80": 8, "r800": 11}


def normalized(s):
    # A stable '+' separates index registers from their signed displacement.
    return re.sub(r"\b(ix|iy)([+-])(\d+)", lambda m: m[1]+"+"+("-" if m[2]=="-" else "")+m[3], s)


def tokenize(s):
    s = normalized(s)
    matches = list(NUMBER.finditer(s))
    return s, matches, [int(m[0], 0) if "x" in m[0] else int(m[0]) for m in matches]


def export(exe, source, arch):
    process = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    def decode(b):
        process.stdin.write(f"{TARGETS[arch]} 8192 {b.hex()}\n")
        process.stdin.flush()
        n, text = process.stdout.readline().rstrip("\n").split("\t", 1)
        return int(n), text
    encodings = []
    suffixes = [b""]
    if arch.startswith("ez80"):
        suffixes += [bytes([p]) for p in (0x40, 0x49, 0x52, 0x5b)]
    families = ("", "cb") if arch == "gbz80" else ("", "cb", "ed", "dd", "fd", "ddcb", "fdcb")
    for suffix in suffixes:
        for family in families:
            for op in range(256):
                if not family and op in (0xcb, 0xdd, 0xed, 0xfd):
                    continue
                if arch.startswith("ez80") and not family and op in (0x40, 0x49, 0x52, 0x5b):
                    continue
                if family in ("dd", "fd") and op == 0xcb:
                    continue
                prefix = bytes.fromhex(family)
                if family in ("ddcb", "fdcb"):
                    physical = suffix+prefix+b"\0"+bytes([op])
                    opcode_positions = set(range(len(suffix)+2)) | {len(suffix)+3}
                else:
                    physical = suffix+prefix+bytes([op])
                    opcode_positions = set(range(len(physical)))
                b = bytearray(physical+b"\0"*10)
                n, text = decode(b)
                if n < len(physical) or "????" in text or ".db" in text or text.startswith("defb") or not re.match(r"[a-z]", text):
                    continue
                b = b[:n]
                text, numbers, baseline = tokenize(text)
                # The upstream decoder has a mnemonic typo for Next ED 2C.
                if arch == "z80n" and text.startswith("bslc "):
                    text = text.replace("bslc ", "brlc ", 1)
                    text, numbers, baseline = tokenize(text)
                fields = {}
                for i in range(n):
                    if i in opcode_positions:
                        continue
                    for bit in range(8):
                        probe = bytearray(b); probe[i] ^= 1 << bit
                        pn, pt = decode(probe)
                        pt, pm, values = tokenize(pt)
                        if pn != n or len(values) != len(baseline):
                            raise ValueError((arch, b.hex(), text, pt, "field shape"))
                        changed = [j for j, (a, v) in enumerate(zip(baseline, values)) if a != v]
                        if len(changed) != 1:
                            raise ValueError((arch, b.hex(), text, pt, "unmodeled bit", i, bit))
                        j = changed[0]; delta = values[j]-baseline[j]
                        power = abs(delta)
                        if power & (power-1):
                            raise ValueError((arch, b.hex(), "nonlinear field", delta))
                        vb = power.bit_length()-1
                        f = fields.setdefault(j, {"bits": [], "signed": False})
                        f["bits"].append({"instruction_bit": i*8+bit, "value_bit": vb, "width": 1})
                        f["signed"] |= delta < 0
                syntax, cursor, operands = "", 0, []
                mnemonic = text.split()[0]
                relative = mnemonic.split(".")[0] in ("jr", "djnz")
                for j, m in enumerate(numbers):
                    if j not in fields:
                        continue
                    name = f"op{len(operands)}"
                    syntax += text[cursor:m.start()]+"{"+name+"}"
                    cursor = m.end()
                    f = fields[j]
                    operand = {"name": name, "kind": "immediate", "bits": f["bits"]}
                    if f["signed"]:
                        operand["signed"] = True
                        operand["kind"] = "displacement"
                    if relative:
                        wrap = 24 if arch == "ez80-adl" else 16
                        if suffix:
                            wrap = 24 if suffix[0] in (0x49, 0x5b) else 16
                        operand.update(kind="address", relative=True, pc_bias=n, pc_wrap_bits=wrap)
                    operands.append(operand)
                syntax += text[cursor:]
                if arch == "gbz80" and op == 0x10 and not family:
                    # GNU's disassembler omits STOP's required padding byte;
                    # gas and the LR35902 instruction specification emit 10 00.
                    b.append(0)
                mask = bytearray([255]*len(b))
                for operand in operands:
                    for bit in operand["bits"]:
                        mask[bit["instruction_bit"]//8] &= ~(1 << (bit["instruction_bit"]%8))
                flow = "next"
                root = mnemonic.split(".")[0]
                if root in ("call", "rst"):
                    flow = "call"
                elif root in ("ret", "reti", "retn"):
                    flow = "return"
                elif root in ("jp", "jr", "djnz"):
                    flow = "indirect-branch" if "(" in text else "branch"
                elif root in ("halt", "stop"):
                    flow = "halt"
                if root in ("call", "ret", "jp", "jr") and ("," in text or root == "ret" and len(text.split()) > 1):
                    flow = {"call":"conditional_call", "ret":"conditional_return", "jp":"conditional_branch", "jr":"conditional_branch"}[root]
                if root in ("djnz", "ldir", "lddr", "cpir", "cpdr", "inir", "indr", "otir", "otdr", "ldirx", "lddrx", "ldpirx", "ldirsx", "otirx", "inimr", "indmr", "otimr", "otdmr"):
                    flow = "conditional_branch"
                e = dict(id=f"gnu/{suffix.hex()}/{family}/{op:02x}", mnemonic=mnemonic,
                         syntax=syntax, mask=base64.b64encode(mask).decode(), value=base64.b64encode(b).decode(),
                         operands=operands, flow_control=flow, features=[arch])
                if root == "rst":
                    e["fixed_target"] = baseline[0]
                encodings.append(e)
    process.stdin.close(); process.wait()
    return dict(schema="mkasm.codec.v1", architecture=arch,
                source=f"GNU binutils 2.44 opcodes/z80-dis.c sha256:{hashlib.sha256(source).hexdigest()}",
                source_license_id="GPL-3.0-or-later", feature_sets={"default": [arch], arch: [arch]}, encodings=encodings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("pkg/z80/data/z80-dis.c"))
    parser.add_argument("--output", type=Path, default=Path("pkg/z80/data/variants.json.gz"))
    args = parser.parse_args()
    source = args.source.read_bytes()
    csource = re.sub(r"(?m)^#include.*$", "", source.decode())
    with tempfile.TemporaryDirectory(prefix="mkasm-z80-export-") as temp:
        path = Path(temp)
        (path/"export.c").write_text(ADAPTER+csource+MAIN)
        subprocess.run(["cc", "-O2", str(path/"export.c"), "-o", str(path/"export")], check=True)
        result = {arch: export(str(path/"export"), source, arch) for arch in TARGETS}
    data = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
    args.output.write_bytes(gzip.compress(data, mtime=0))
    print(json.dumps({arch: len(c["encodings"]) for arch, c in result.items()}, sort_keys=True))


if __name__ == "__main__":
    main()

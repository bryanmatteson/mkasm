#!/usr/bin/env python3
"""Build native references from explicit unmodified GNU/QEMU source inputs.

QEMU's BE core has no floating-point option. For those optional instructions the
supplemental reference combines native LLVM/GNU LE opcode selection with the
vendor-generated BE format field functions. This is a physical layout reference,
not a claim that the BE core implements a floating-point extension.
"""
import argparse
from pathlib import Path
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binutils-source',type=Path,required=True)
p.add_argument('--qemu-be-core',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
repo=Path(__file__).resolve().parents[1]
include=a.binutils_source/'include'
be=a.qemu_be_core/'xtensa-modules.c.inc'
le=a.binutils_source/'bfd/xtensa-modules.c'
for source in (be,le,a.qemu_be_core/'core-isa.h',include/'xtensa-isa-internal.h'):
 if not source.is_file():p.error(f'missing native source: {source}')
common=['clang','-O2','-fPIC','-DATTRIBUTE_UNUSED=__attribute__((unused))','-I'+str(include),'-I'+str(a.qemu_be_core)]
config=a.output/'config.c'
config.write_text('#include "core-isa.h"\n#define XSHAL_USE_ABSOLUTE_LITERALS 0\n#define XCHAL_HAVE_MMU XCHAL_HAVE_PTP_MMU\n#define XSHAL_ABI XTHAL_ABI_WINDOWED\n#define XTENSA_CONFIG_DEFINITION\n#include "xtensa-dynconfig.h"\nXTENSA_CONFIG_INSTANCE_LIST;\n')
shared=['-dynamiclib'] if sys.platform=='darwin' else ['-shared']
suffix='.dylib' if sys.platform=='darwin' else '.so'
subprocess.run(common+shared+['-x','c',str(be),str(config),'-o',str(a.output/('qemu-be'+suffix))],check=True)
leconfig=a.output/'config-le.c'
leconfig.write_text('#include "xtensa-config.h"\n#undef XCHAL_HAVE_BE\n#define XCHAL_HAVE_BE 0\n#define XTENSA_CONFIG_DEFINITION\n#include "xtensa-dynconfig.h"\nXTENSA_CONFIG_INSTANCE_LIST;\n')
subprocess.run(common+shared+['-x','c',str(le),str(leconfig),'-o',str(a.output/('gnu-le'+suffix))],check=True)
adapter=repo/'pkg/xtensa/testdata/native-fields.c'
objects=[]
for name,module,function,decode in [('le',le,'reference_le_fields',True),('be',be,'reference_be_fields',False)]:
 obj=a.output/(name+'-fields.o');objects.append(str(obj))
 args=common+['-DXTENSA_MODULES="'+str(module)+'"','-DMODULE_SYMBOL=reference_'+name+'_module','-DFUNCTION_NAME='+function]
 if decode:args+=['-DREFERENCE_DECODE']
 subprocess.run(args+['-c',str(adapter),'-o',str(obj)],check=True)
subprocess.run(['clang']+shared+objects+['-o',str(a.output/('native-fields'+suffix))],check=True)
print(a.output/('qemu-be'+suffix));print(a.output/('gnu-le'+suffix));print(a.output/('native-fields'+suffix))

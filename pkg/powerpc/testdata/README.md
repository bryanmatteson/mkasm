The compressed fixture contains all Instruction, InstAlias, DAGOperand, RegisterClass,
Register, and RegClassByHwMode records from LLVM llvmorg-22.1.8 PPC.td resolved by
llvm-tblgen 22.1.8 --dump-json. It preserves real source bits and metadata; the
adapter performs the architecture-specific normalization under test.

Source: https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/PowerPC
LLVM source license: Apache-2.0 WITH LLVM-exception.

Regenerate the uncompressed dump with:

    llvm-tblgen --dump-json -I llvm/include -I llvm/lib/Target/PowerPC \
      llvm/lib/Target/PowerPC/PPC.td -o powerpc.json

MKASM_POWERPC_TABLEGEN_JSON selects a fresh full dump instead of this fixture.
LLVM_MC selects the independent llvm-mc executable for the whole-corpus parity
check. The parity report records every rejected source form and diagnostic when
MKASM_POWERPC_PARITY_DIR is set.

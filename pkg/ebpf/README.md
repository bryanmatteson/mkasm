# eBPF TableGen importer

`Parse(reader, "bpfel")` and `Parse(reader, "bpfeb")` consume LLVM's actual
`llvm-tblgen --dump-json BPF.td` output. `ebpf` and `bpf` select little endian.
The output uses `pkg/codec` for Go encoding, decoding, text assembly, JSON, and
Rust generation.

BPF byte order is applied separately to the opcode, register nibbles, signed
16-bit offset, and 32-bit immediate. Wide immediate instructions have a second
8-byte slot. Its first four bytes are reserved zero and its high immediate word
uses target byte order. Registers use r0..r10 or w0..w10. Tied TableGen operands
share one field and must have identical text values.

Branch operand values in the codec API are **byte displacements**. Encoded
16-bit/32-bit branch offsets and local calls count 8-byte instruction slots;
`Scale=8`, `PCBias=8` implement that conversion. Formatting resolves branches to
absolute addresses. For example, a branch at 0x100 with encoded offset 3 formats
its target as 0x120. This makes the text assembler independent of instruction
slot arithmetic. Helper calls retain numeric helper IDs; `call_rel` names a
local target address and `call_kfunc` names a Linux BTF function ID.

LLVM's generic `LD_pseudo` record expands into seven concrete source subtypes,
`LD_pseudo_0` through `LD_pseudo_6`. These retain `ld_pseudo rN, subtype, value`
syntax. Types 2 and 6 use a packed 64-bit value whose upper word is the map-value
offset; types 1, 3, 4, and 5 reserve that upper word as zero. The map/BTF/function
references are numeric encoding fields; object relocation and map resolution
belong to the object loader.

The LLVM 22.1.8 corpus contains 201 BPF instruction records. Thirteen are marked
compiler pseudo instructions, and four CO-RE operations have no standalone
machine encoding and appear in `Catalog.Unsupported`. The remaining 184 machine
records yield 192 forms after source-subtype and Linux call-tag specialization.
The importer preserves available source feature predicates. Feature metadata
describes those imported conditions, rather than asserting a kernel verifier or
CPU release compatibility guarantee.

`go test ./pkg/ebpf` tests the retained real corpus, round trips every form in both
byte orders, checks wide framing and reserved fields, and compares 190 forms per
byte order with LLVM MC when it is installed. Fixed independent LLVM vectors run
without that executable. To test a fresh unmodified dump instead, set
`MKASM_BPF_TABLEGEN_JSON=/path/to/bpf.json`.

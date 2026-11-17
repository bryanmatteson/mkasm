#!/bin/sh
# GNU binutils 2.44: compile its real operand tables and disassembler.
# The generated source data and upstream oracle are GPL-3.0-or-later.
set -eu
: "${GNU_SOURCE:?set GNU_SOURCE to the extracted binutils-2.44 directory}"
: "${GNU_BUILD:?set GNU_BUILD to the configured/built MIPS binutils directory}"
: "${GNU_OUTPUT:?set GNU_OUTPUT to a task artifact directory}"
mkdir -p "$GNU_OUTPUT"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc -std=c11 -I"$GNU_BUILD/opcodes" -I"$GNU_BUILD/bfd" \
 -I"$GNU_SOURCE/opcodes" -I"$GNU_SOURCE/include" \
 "$script_dir/export-gnu.c" -o "$GNU_OUTPUT/export-gnu"
"$GNU_OUTPUT/export-gnu" > "$GNU_OUTPUT/gnu-mips16.json"
cc -std=c11 -I"$GNU_BUILD/opcodes" -I"$GNU_BUILD/bfd" \
 -I"$GNU_SOURCE/opcodes" -I"$GNU_SOURCE/include" \
 "$script_dir/export-micro64.c" -o "$GNU_OUTPUT/export-micro64"
"$GNU_OUTPUT/export-micro64" > "$GNU_OUTPUT/gnu-micromips64.json"
cc -std=c11 -I"$GNU_BUILD/opcodes" -I"$GNU_BUILD/bfd" \
 -I"$GNU_SOURCE/bfd" -I"$GNU_SOURCE/opcodes" -I"$GNU_SOURCE/include" \
 "$script_dir/gnu-disassemble.c" "$GNU_BUILD/opcodes/.libs/libopcodes.a" \
 "$GNU_BUILD/bfd/.libs/libbfd.a" "$GNU_BUILD/libsframe/.libs/libsframe.a" \
 "$GNU_BUILD/libiberty/libiberty.a" -L/opt/homebrew/lib -lz -lzstd \
 -o "$GNU_OUTPUT/gnu-disassemble"
cc -std=c11 -I"$GNU_BUILD/opcodes" -I"$GNU_BUILD/bfd" \
 -I"$GNU_SOURCE/bfd" -I"$GNU_SOURCE/opcodes" -I"$GNU_SOURCE/include" \
 "$script_dir/gnu-micro64-oracle.c" "$GNU_BUILD/opcodes/.libs/libopcodes.a" \
 "$GNU_BUILD/bfd/.libs/libbfd.a" "$GNU_BUILD/libsframe/.libs/libsframe.a" \
 "$GNU_BUILD/libiberty/libiberty.a" -L/opt/homebrew/lib -lz -lzstd \
 -o "$GNU_OUTPUT/gnu-micro64-oracle"
printf '%s\n' "GNU export: $GNU_OUTPUT/gnu-mips16.json" "GNU decoder: $GNU_OUTPUT/gnu-disassemble"

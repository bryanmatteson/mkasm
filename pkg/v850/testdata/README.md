# Sources and oracle fixtures

`v850-opc.c`, `v850.h`, and `tc-v850.c` are unmodified GNU binutils 2.44
sources. They are respectively from `opcodes/`, `include/opcode/`, and
`gas/config/`. Their copyright and GPL-3.0-or-later notices are preserved;
`COPYING3` is the matching license. Source archive:
https://ftp.gnu.org/gnu/binutils/binutils-2.44.tar.xz

SHA-256:

```text
441c4c107eb8580acebc177c8accbf985248db75344db57379533f6a35958abb  v850-opc.c
1a8c6fa6c1cfae18b349187e2e3af79a477dffab8f05e816a5893e585ae054f9  v850.h
6aa0719506e660ba9ccae386ff4bd7ef45a57b451013218989b4e60d7c4cf075  tc-v850.c
```

`gnu-vectors.json` contains one exact independent GNU assembler result for
each of the 403 source rows, in source order. `gnu-boundaries.json` contains
619 additional independent cases, including the 528 legal `bins` ranges.
`program.s` is an original routine; `program.bin` is its `.text` section
assembled by the same GNU 2.44 `v850-elf` assembler with
`-mv850e3v5 -mextension`. Tests can regenerate these cases through real ELF
objects and compare section bytes.

`ghidra-vectors.json` contains the 308 cases where installed Ghidra 12.1.2
both decoded the GNU bytes and reassembled its own text to exactly those
bytes. It includes the original GNU assembly and Ghidra's own spelling.
The executable was Ghidra 12.1.2 PUBLIC, built 2026-06-05, using language
`V850:LE:32:default`. Installed language hashes:

```text
cc4e2755d2b9d7763e05700c05649712d1eb3a2062655dc9532d368958194dda  V850.slaspec
7f4c0e6a509c17e89d2869ad2f1aadc4273d46f002408e00c1edb156f134274f  V850.sla
```

No Ghidra source is redistributed in this package. The Ghidra comparison is
independent and intentionally reports the older installed language's E3
coverage limits; see the package README. Complete oracle outputs, actual
ELF objects, build logs, and the generated Rust consumer are retained under
`~/Documents/Developer/go-mkasm/architecture-expansion/v850/`.

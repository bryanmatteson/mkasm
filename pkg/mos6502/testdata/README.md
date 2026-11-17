# Pinned source and independent fixtures

`opcodes.c` concatenates the complete, unmodified `src/da65/opc6502.c`,
`opc6502x.c`, `opc65sc02.c`, and `opc65c02.c` from cc65 tag **V2.19**.
Each original copyright and Zlib notice is retained. `CC65-LICENSE` is the
matching upstream license. The source archive and this bundle have SHA-256:

```text
157b8051aed7f534e5093471e734e7a95e509c577324099c3c81324ed9d0de77  cc65-V2.19.tar.gz
b465cdc12565ea2628d78ac4e02b956a3fd9fc1589241eebed345dfefcf98aab  opcodes.c
```

Archive: https://github.com/cc65/cc65/archive/refs/tags/V2.19.tar.gz
Some tools built from this tag identify themselves as V2.18; the actual input
is the pinned V2.19 archive above, not an inferred version from that banner.

The official WDC **February 16, 2024** W65C02S datasheet is the primary source
for reserved-NOP frame lengths and the BRK signature byte:
https://www.westerndesigncenter.com/documentation/w65c02s.pdf

```text
4fb4a2c1055e319c6d8df5a6f7b348d9cffa958fdabc982a494bda54e5e17195  w65c02s-2024-02-16.pdf
```

The copyrighted datasheet is retained as an external task artifact and is not
redistributed in this package. Only encoding and framing facts from its tables
4-1 and 7-1 are represented in the importer.

`cc65-vectors.json` records all 361 imported forms. For 317 non-reserved forms
it records actual ca65/ld65 bytes and da65 text. The assembler chooses canonical
bytes for 35 redundant undocumented encodings; both the requested and actual
bytes are recorded, and their distinction is tested. The 44 reserved WDC NOPs
are explicitly tagged `reserved-nop` and are covered by the complete primary
datasheet framing groups, not claimed as independently accepted assembler
instructions.

`ghidra-results.json` records all 212 documented form requests against installed
Ghidra 12.1.2 PUBLIC, built June 5, 2026. Of these, 209 have identical assembled
bytes and decoded lengths; BRK has its known display-length difference and
WAI/STP are unsupported. Installed SLA hashes:

```text
6e9528e7f417b815f7dfdaaec357a5ebd975525e31c4d7c456694c1e99743d92  6502.sla
6995ea3f14fc851009924d69ab06d47fee611dca50614c7e6761f555d8fc5ac1  65c02.sla
```

No Ghidra source is redistributed in this package. Its installed languages match
the checked-out definitions used to understand the oracle syntax.

`program.s` and `link.cfg` are original consumer inputs. `program.bin` is the
actual ca65/ld65 output loaded at address `0x1000`. The integration test
regenerates it, adds the documented sim65 image header, and executes it through
the independent simulator. No simulator or assembler is required for normal
offline tests or the generated Rust crate.

Sources, tool builds, object files, simulator input, complete oracle output,
fuzz results and generated Rust are retained in
`~/Documents/Developer/go-mkasm/architecture-expansion/mos6502/`.
